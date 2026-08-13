package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	tclient "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

const (
	e2ePassword = "labpass1!"
	e2eSecret   = "LabSecret-16chars!"
	e2eToken    = "lab-bootstrap-token-32-bytes!!!"
)

func TestVerticalSkeletonE2E(t *testing.T) {
	dir := t.TempDir()
	phc, err := credentials.DeriveArgon2id([]byte(e2ePassword), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	login := filepath.Join(dir, "login")
	sec := filepath.Join(dir, "shared")
	tok := filepath.Join(dir, "token")
	for _, f := range []struct {
		path string
		data []byte
	}{
		{login, phc},
		{sec, []byte(e2eSecret)},
		{tok, []byte(e2eToken)},
	} {
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "lab.yaml")
	src := `
schema_version: 1
server:
  shutdown_grace: 2s
listeners:
  legacy_tacacs:
    enabled: true
    bind: 127.0.0.1:0
    single_connect: {enabled: true, max_lifetime: 1m, idle_timeout: 5s}
  secure_tacacs: {enabled: false}
  http:
    enabled: true
    bind: 127.0.0.1:0
    write_timeout: 2s
observability:
  metrics: {enabled: false}
api:
  bootstrap_tokens:
    - id: lab
      token: {file: ` + tok + `}
      scopes: [state:read, policy:test, events:read]
clients:
  - id: lab-switches
    priority: 10
    match: {source_cidrs: ["127.0.0.0/8", "::1/128"], transports: [legacy]}
    legacy: {shared_secret: {file: ` + sec + `}}
    authentication: {allowed_methods: [ascii]}
groups:
  - id: administrators
    priority: 10
    services:
      - service: shell
        action: permit
        reply_attributes:
          - {name: priv-lvl, separator: "=", value: "15"}
    command_rules:
      - id: permit-configure
        priority: 10
        action: permit
        command: {exact: configure}
        arguments: {pattern: ".*"}
    default_command_action: deny
  - id: readonly
    priority: 100
    services:
      - service: shell
        action: permit
        reply_attributes:
          - {name: priv-lvl, separator: "=", value: "1"}
    command_rules:
      - id: show
        priority: 10
        action: permit
        command: {exact: show}
        arguments: {pattern: ".*"}
      - id: deny-everything-else
        priority: 10000
        action: deny
        command: {pattern: ".*"}
        arguments: {pattern: ".*"}
    default_command_action: deny
users:
  - id: lab-admin
    group_ids: [administrators]
    credentials:
      login: {verifier: {file: ` + login + `}}
  - id: lab-readonly
    group_ids: [readonly]
    credentials:
      login: {verifier: {file: ` + login + `}}
`
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuf
	errc := make(chan int, 1)
	go func() { errc <- serve(ctx, []string{"--config", cfg}, &stdout, &stderr) }()

	legacyAddr := waitServeAddr(t, &stdout, &stderr)
	httpAddr := waitHTTPAddr(t, &stdout, &stderr)

	c, err := tclient.Dial(legacyAddr, []byte(e2eSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// ASCII LOGIN
	body, err := tcodec.WriteStart(tcodec.Start{
		Action: tcodec.ActionLogin, AType: tcodec.TypeASCII, Service: tcodec.SvcLogin,
		User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 1}, body); err != nil {
		t.Fatal(err)
	}
	_, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tcodec.ReadReply(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.StatusGetPass {
		t.Fatalf("ascii start status=%#x stderr=%s", rep.Status, stderr.String())
	}
	cbody, err := tcodec.WriteCont(tcodec.Cont{Msg: []byte(e2ePassword)})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 3, Flags: tcodec.FlagSingleConnect, SessionID: 1}, cbody); err != nil {
		t.Fatal(err)
	}
	_, rbody, err = c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	rep, err = tcodec.ReadReply(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.StatusPass {
		t.Fatalf("ascii pass status=%#x", rep.Status)
	}

	// Session authorization (empty cmd) vs command authorization.
	sessionBody, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		Pairs: []tcodec.Pair{{Key: "service", Sep: tcodec.SepEq, Val: "shell"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 2}, sessionBody); err != nil {
		t.Fatal(err)
	}
	_, rbody, err = c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	arep, err := tcodec.ReadAuthorRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if arep.Status != tcodec.AuthorPassAdd {
		t.Fatalf("session author=%#x", arep.Status)
	}
	if len(arep.Pairs) != 1 || arep.Pairs[0].Key != "priv-lvl" || arep.Pairs[0].Val != "15" {
		t.Fatalf("session PASS_ADD args=%+v", arep.Pairs)
	}

	cmdBody, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		Pairs: []tcodec.Pair{
			{Key: "service", Sep: tcodec.SepEq, Val: "shell"},
			{Key: "cmd", Sep: tcodec.SepEq, Val: "configure"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 3}, cmdBody); err != nil {
		t.Fatal(err)
	}
	_, rbody, err = c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	arep, err = tcodec.ReadAuthorRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if arep.Status != tcodec.AuthorPassAdd {
		t.Fatalf("configure author=%#x", arep.Status)
	}
	if len(arep.Pairs) != 0 {
		t.Fatalf("configure PASS_ADD must return zero args, got %+v", arep.Pairs)
	}

	denyBody, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		Pairs: []tcodec.Pair{
			{Key: "service", Sep: tcodec.SepEq, Val: "shell"},
			{Key: "cmd", Sep: tcodec.SepEq, Val: "reload"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 4}, denyBody); err != nil {
		t.Fatal(err)
	}
	_, rbody, err = c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	arep, err = tcodec.ReadAuthorRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if arep.Status != tcodec.AuthorFail {
		t.Fatalf("reload should deny, got %#x", arep.Status)
	}

	roBody, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("lab-readonly"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		Pairs: []tcodec.Pair{
			{Key: "service", Sep: tcodec.SepEq, Val: "shell"},
			{Key: "cmd", Sep: tcodec.SepEq, Val: "configure"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 6}, roBody); err != nil {
		t.Fatal(err)
	}
	_, rbody, err = c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	arep, err = tcodec.ReadAuthorRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if arep.Status != tcodec.AuthorFail {
		t.Fatalf("readonly configure should deny, got %#x", arep.Status)
	}

	// Accounting START.
	acctBody, err := tcodec.WriteAcctReq(tcodec.AcctReq{
		Flags: tcodec.AcctStart, Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAcct, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 5}, acctBody); err != nil {
		t.Fatal(err)
	}
	_, rbody, err = c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	acct, err := tcodec.ReadAcctRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if acct.Status != tcodec.AcctOK {
		t.Fatalf("acct=%#x", acct.Status)
	}

	stopBody, err := tcodec.WriteAcctReq(tcodec.AcctReq{
		Flags: tcodec.AcctStop, Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		Pairs: []tcodec.Pair{
			{Key: "task_id", Sep: tcodec.SepEq, Val: "sess-e2e"},
			{Key: "service", Sep: tcodec.SepEq, Val: "shell"},
			{Key: "cmd", Sep: tcodec.SepEq, Val: "configure"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAcct, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 7}, stopBody); err != nil {
		t.Fatal(err)
	}
	_, rbody, err = c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	acct, err = tcodec.ReadAcctRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if acct.Status != tcodec.AcctOK {
		t.Fatalf("acct stop=%#x", acct.Status)
	}

	badBody, err := tcodec.WriteAcctReq(tcodec.AcctReq{
		Flags: tcodec.AcctStart | tcodec.AcctStop, Method: tcodec.MethTACACS,
		User: []byte("lab-admin"),
	})
	if err == nil {
		if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAcct, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 8}, badBody); err != nil {
			t.Fatal(err)
		}
		_, rbody, err = c.ReadPacket()
		if err != nil {
			t.Fatal(err)
		}
		acct, err = tcodec.ReadAcctRep(rbody)
		if err != nil {
			t.Fatal(err)
		}
		if acct.Status != tcodec.AcctErr && acct.Status != 0x02 {
			t.Fatalf("invalid flags status=%#x", acct.Status)
		}
	}

	// REST status + evaluate (same operations as MCP).
	base := "http://" + httpAddr
	st := restGET(t, base+"/api/v1/status", e2eToken)
	if st.Users < 1 {
		t.Fatalf("status users=%d", st.Users)
	}
	evs := restListEvents(t, base+"/api/v1/events?category=acct&limit=20", e2eToken)
	if len(evs.Items) < 2 {
		t.Fatalf("acct events=%d", len(evs.Items))
	}
	live, err := http.Get(base + "/health/live")
	if err != nil {
		t.Fatal(err)
	}
	if live.StatusCode != http.StatusOK {
		t.Fatalf("live=%d", live.StatusCode)
	}
	_ = live.Body.Close()

	restTrace := restEvaluate(t, base, e2eToken, operations.EvaluatePolicyRequest{
		UserID: "lab-admin", ClientID: "lab-switches", Service: "shell", Cmd: "configure",
	})
	if restTrace.Evaluator != "command" || restTrace.Decision != "permit_add" {
		t.Fatalf("rest evaluate=%+v", restTrace)
	}
	restSess := restEvaluate(t, base, e2eToken, operations.EvaluatePolicyRequest{
		UserID: "lab-admin", ClientID: "lab-switches", Service: "shell",
	})
	if restSess.Evaluator != "service" {
		t.Fatalf("rest session evaluator=%s", restSess.Evaluator)
	}

	// MCP tools call the same registry.
	mcpTrace := mcpEvaluate(t, base, e2eToken, operations.EvaluatePolicyRequest{
		UserID: "lab-admin", ClientID: "lab-switches", Service: "shell", Cmd: "configure",
	})
	if mcpTrace.Decision != restTrace.Decision || mcpTrace.Evaluator != restTrace.Evaluator {
		t.Fatalf("parity rest=%+v mcp=%+v", restTrace, mcpTrace)
	}

	roREST := restEvaluate(t, base, e2eToken, operations.EvaluatePolicyRequest{
		UserID: "lab-readonly", ClientID: "lab-switches", Service: "shell", Cmd: "configure",
	})
	if roREST.Evaluator != "command" || roREST.Decision != "deny" {
		t.Fatalf("readonly rest=%+v", roREST)
	}
	for _, st := range roREST.Steps {
		if st.Kind == "service" {
			t.Fatalf("readonly configure hit service rule: %+v", st)
		}
	}
	roMCP := mcpEvaluate(t, base, e2eToken, operations.EvaluatePolicyRequest{
		UserID: "lab-readonly", ClientID: "lab-switches", Service: "shell", Cmd: "configure",
	})
	if roMCP.Decision != roREST.Decision || roMCP.Evaluator != roREST.Evaluator {
		t.Fatalf("readonly parity rest=%+v mcp=%+v", roREST, roMCP)
	}

	cancel()
	select {
	case code := <-errc:
		if code != 0 {
			t.Fatalf("exit %d stderr=%s", code, stderr.String())
		}
	case <-time.After(4 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

func waitHTTPAddr(t *testing.T, stdout, stderr *syncBuf) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		out := stdout.String()
		if strings.Contains(out, "ready") {
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, "listening http ") {
					return strings.TrimPrefix(line, "listening http ")
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("http not ready: stdout=%q stderr=%q", stdout.String(), stderr.String())
	return ""
}

func restGET(t *testing.T, url, token string) operations.Status {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s -> %d %s", url, resp.StatusCode, b)
	}
	var env struct {
		Data operations.Status `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	return env.Data
}

func restListEvents(t *testing.T, url, token string) operations.EventList {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s -> %d %s", url, resp.StatusCode, b)
	}
	var env struct {
		Data operations.EventList `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	return env.Data
}

func restEvaluate(t *testing.T, base, token string, req operations.EvaluatePolicyRequest) operations.PolicyTrace {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, base+"/api/v1/policy/evaluate", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("evaluate %d %s", resp.StatusCode, b)
	}
	var env struct {
		Data operations.PolicyTrace `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	return env.Data
}

func mcpEvaluate(t *testing.T, base, token string, req operations.EvaluatePolicyRequest) operations.PolicyTrace {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "taclab.policy.evaluate",
			"arguments": req,
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
				"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "taclab-e2e", "version": "test"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, base+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("MCP-Protocol-Version", "2026-07-28")
	httpReq.Header.Set("Mcp-Method", "tools/call")
	httpReq.Header.Set("Mcp-Name", "taclab.policy.evaluate")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("mcp %d %s", resp.StatusCode, b)
	}
	var parsed struct {
		Result struct {
			Structured operations.PolicyTrace `json:"structuredContent"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Error != nil {
		t.Fatalf("mcp error=%+v", parsed.Error)
	}
	return parsed.Result.Structured
}
