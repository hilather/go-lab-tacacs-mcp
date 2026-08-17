package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	tclient "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

func defaultScenarios(h *harness) []scenario {
	return []scenario{
		{ID: "LAB-HEALTH", Fn: h.labHealth},
		{ID: "LAB-UI", Fn: h.labUI},
		{ID: "LAB-LEGACY-001", Fn: h.labLegacyLifecycle},
		{ID: "LAB-AUTH-001", Fn: h.labASCIISuccess},
		{ID: "LAB-AUTH-002", Fn: h.labASCIIFail},
		{ID: "LAB-AUTH-003", Fn: h.labPAP},
		{ID: "LAB-AUTH-004", Fn: h.labCHAP},
		{ID: "LAB-AUTH-007", Fn: h.labEnable},
		{ID: "LAB-AUTHZ-001", Fn: h.labAuthorShell},
		{ID: "LAB-AUTHZ-002", Fn: h.labAuthorReadonlyShow},
		{ID: "LAB-AUTHZ-003", Fn: h.labAuthorReadonlyConfigure},
		{ID: "LAB-ACCT-001", Fn: h.labAcctStartStop},
		{ID: "LAB-ACCT-003", Fn: h.labAcctInvalidFlags},
		{ID: "LAB-TLS-001", Fn: h.labTLSSuccess},
		{ID: "LAB-TLS-002", Fn: h.labTLSUnauth},
		{ID: "LAB-TLS-003", Fn: h.labTLSPlaintext},
		{ID: "LAB-API-001", Fn: h.labAPIparity},
		{ID: "LAB-API-002", Fn: h.labAPICreate},
		{ID: "LAB-STATE-002", Fn: h.labReset},
		{ID: "LAB-STATE-003", Fn: h.labReload},
		{ID: "LAB-SSE-001", Fn: h.labSubscriberSurvivesWriteTimeout},
		{ID: "LAB-SOURCE-001", Fn: h.labSourceIP},
		{ID: "LAB-NEG-001", Fn: h.labUnauth},
		{ID: "LAB-TACACS-ONLY", Fn: h.labTACACSOnlyReady},
	}
}

func combinedScenarios(h *harness) []scenario {
	return []scenario{
		{ID: "LAB-HEALTH", Fn: h.labHealth},
		{ID: "LAB-RADIUS-001", Fn: h.labRADIUSReady},
		{ID: "LAB-RADIUS-002", Fn: h.labRADIUSAccessTest},
		{ID: "LAB-RADIUS-DYNAUTH", Fn: h.labRADIUSDynAuth},
		{ID: "LAB-RADIUS-RADSEC", Fn: h.labRADIUSRadSec},
		{ID: "LAB-AUTH-001", Fn: h.labASCIISuccess},
		{ID: "LAB-NEG-001", Fn: h.labUnauth},
	}
}

func radiusOnlyScenarios(h *harness) []scenario {
	return []scenario{
		{ID: "LAB-HEALTH", Fn: h.labHealth},
		{ID: "LAB-RADIUS-001", Fn: h.labRADIUSReady},
		{ID: "LAB-RADIUS-002", Fn: h.labRADIUSAccessTest},
		{ID: "LAB-RADIUS-ONLY", Fn: h.labRADIUSOnlyProfile},
		{ID: "LAB-RADIUS-DYNAUTH", Fn: h.labRADIUSDynAuth},
		{ID: "LAB-RADIUS-RADSEC", Fn: h.labRADIUSRadSec},
		{ID: "LAB-NEG-001", Fn: h.labUnauth},
	}
}

func (h *harness) labHealth() error {
	code, raw, err := h.restJSON(http.MethodGet, "/health/ready", nil, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("ready=%d %s", code, raw)
	}
	code, raw, err = h.restJSON(http.MethodGet, "/health/live", nil, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("live=%d %s", code, raw)
	}
	return nil
}

func (h *harness) labUI() error {
	req, err := http.NewRequest(http.MethodGet, h.HTTP+"/", nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ui=%d", resp.StatusCode)
	}
	if !bytes.Contains(b, []byte("<html")) && !bytes.Contains(b, []byte("<!DOCTYPE")) && !bytes.Contains(b, []byte("<div")) {
		return fmt.Errorf("ui body is not HTML")
	}
	return h.rejectCanary(b)
}

func (h *harness) labLegacyLifecycle() error {
	code, raw, err := h.restJSON(http.MethodGet, "/api/v1/clients/lab-switches", nil, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, raw); err != nil {
		return err
	}
	if err := mustContain(raw, "lab-switches"); err != nil {
		return err
	}
	if bytes.Contains(raw, h.Secret) {
		return fmt.Errorf("shared secret in client GET")
	}
	lower := bytes.ToLower(raw)
	if !bytes.Contains(lower, []byte("current")) && !bytes.Contains(lower, []byte("lifecycle")) && !bytes.Contains(raw, []byte("shared_secret")) {
		// Lifecycle is exposed as status text, not the secret.
		if !bytes.Contains(raw, []byte("lab-switches")) {
			return fmt.Errorf("client view missing identity")
		}
	}
	return nil
}

func (h *harness) labASCIISuccess() error {
	return h.withLegacy(func(c *tclient.Conn) error {
		st, err := h.asciiLogin(c, 1, "lab-admin", h.pw("lab-admin"))
		if err != nil {
			return err
		}
		if st != tcodec.StatusPass {
			return fmt.Errorf("ascii status=%#x", st)
		}
		return nil
	})
}

func (h *harness) labASCIIFail() error {
	return h.withLegacy(func(c *tclient.Conn) error {
		st, err := h.asciiLogin(c, 2, "lab-admin", "wrong-password-!!!!")
		if err != nil {
			return err
		}
		// Wrong password is FAIL or a uniform GETPASS retry (bounded rounds). Never PASS.
		if st == tcodec.StatusPass {
			return fmt.Errorf("wrong password passed")
		}
		if st != tcodec.StatusFail && st != tcodec.StatusGetPass {
			return fmt.Errorf("want FAIL or retry GETPASS got %#x", st)
		}
		return nil
	})
}

func (h *harness) labPAP() error {
	return h.withLegacy(func(c *tclient.Conn) error {
		body, err := tcodec.WriteStart(tcodec.Start{
			Action: tcodec.ActionLogin, AType: tcodec.TypePAP, Service: tcodec.SvcLogin,
			User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
			Data: []byte(h.pw("lab-admin")),
		})
		if err != nil {
			return err
		}
		if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(1), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 3}, body); err != nil {
			return err
		}
		st, err := readAuthen(c)
		if err != nil {
			return err
		}
		if st != tcodec.StatusPass {
			return fmt.Errorf("pap=%#x", st)
		}
		return nil
	})
}

func (h *harness) labCHAP() error {
	chalSecret := []byte(h.pw("lab-admin-challenge"))
	return h.withLegacy(func(c *tclient.Conn) error {
		id := byte(0x42)
		chal := []byte("12345678")
		resp := credentials.CHAPResponse(id, chalSecret, chal)
		data, err := tcodec.PackChap(tcodec.Chap{ID: id, Chal: chal, Resp: resp})
		if err != nil {
			return err
		}
		body, err := tcodec.WriteStart(tcodec.Start{
			Action: tcodec.ActionLogin, AType: tcodec.TypeCHAP, Service: tcodec.SvcPPP,
			User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
			Data: data,
		})
		if err != nil {
			return err
		}
		if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(1), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 4}, body); err != nil {
			return err
		}
		st, err := readAuthen(c)
		if err != nil {
			return err
		}
		if st != tcodec.StatusPass {
			return fmt.Errorf("chap=%#x", st)
		}
		return nil
	})
}

func (h *harness) labEnable() error {
	return h.withLegacy(func(c *tclient.Conn) error {
		body, err := tcodec.WriteStart(tcodec.Start{
			Action: tcodec.ActionLogin, AType: tcodec.TypeASCII, Service: tcodec.SvcEnable,
			User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		})
		if err != nil {
			return err
		}
		if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 5}, body); err != nil {
			return err
		}
		st, err := readAuthen(c)
		if err != nil {
			return err
		}
		if st != tcodec.StatusGetPass && st != tcodec.StatusGetData {
			return fmt.Errorf("enable start=%#x", st)
		}
		cbody, err := tcodec.WriteCont(tcodec.Cont{Msg: []byte(h.pw("lab-admin-enable"))})
		if err != nil {
			return err
		}
		if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 3, Flags: tcodec.FlagSingleConnect, SessionID: 5}, cbody); err != nil {
			return err
		}
		st, err = readAuthen(c)
		if err != nil {
			return err
		}
		if st != tcodec.StatusPass {
			return fmt.Errorf("enable=%#x", st)
		}
		return nil
	})
}

func (h *harness) labAuthorShell() error {
	return h.withLegacy(func(c *tclient.Conn) error {
		st, err := h.author(c, 10, "lab-admin", "", nil)
		if err != nil {
			return err
		}
		if st != tcodec.AuthorPassAdd && st != tcodec.AuthorPassRepl {
			return fmt.Errorf("shell author=%#x", st)
		}
		return nil
	})
}

func (h *harness) labAuthorReadonlyShow() error {
	return h.withLegacy(func(c *tclient.Conn) error {
		st, err := h.author(c, 11, "lab-readonly", "show", []string{"running-config"})
		if err != nil {
			return err
		}
		if st != tcodec.AuthorPassAdd && st != tcodec.AuthorPassRepl {
			return fmt.Errorf("show author=%#x", st)
		}
		return nil
	})
}

func (h *harness) labAuthorReadonlyConfigure() error {
	return h.withLegacy(func(c *tclient.Conn) error {
		st, err := h.author(c, 12, "lab-readonly", "configure", nil)
		if err != nil {
			return err
		}
		if st != tcodec.AuthorFail {
			return fmt.Errorf("configure want FAIL got %#x", st)
		}
		return nil
	})
}

func (h *harness) labAcctStartStop() error {
	return h.withLegacy(func(c *tclient.Conn) error {
		if err := h.acct(c, 20, tcodec.AcctStart); err != nil {
			return err
		}
		return h.acct(c, 21, tcodec.AcctStop)
	})
}

func (h *harness) labAcctInvalidFlags() error {
	return h.withLegacy(func(c *tclient.Conn) error {
		// Client codec refuses invalid flags; send a raw START|STOP body.
		user, port, rem := []byte("lab-admin"), []byte("tty0"), []byte("127.0.0.1")
		body := []byte{tcodec.AcctStart | tcodec.AcctStop, tcodec.MethTACACS, 0, 0, tcodec.SvcLogin, byte(len(user)), byte(len(port)), byte(len(rem)), 0}
		body = append(body, user...)
		body = append(body, port...)
		body = append(body, rem...)
		if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAcct, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 22}, body); err != nil {
			return err
		}
		_, rbody, err := c.ReadPacket()
		if err != nil {
			return err
		}
		rep, err := tcodec.ReadAcctRep(rbody)
		if err != nil {
			return err
		}
		if rep.Status != tcodec.AcctErr && rep.Status != 0x02 {
			return fmt.Errorf("invalid flags status=%#x", rep.Status)
		}
		return nil
	})
}

func (h *harness) labTLSSuccess() error {
	if h.PKI == "" {
		return fmt.Errorf("pki directory required")
	}
	cert, roots, err := loadTLSMaterial(h.PKI)
	if err != nil {
		return err
	}
	c, err := tclient.DialTLS(h.TLS, tclient.TLSOptions{
		ServerName:   h.ServerName,
		Kind:         tclient.IdentityDNS,
		Identity:     h.ServerName,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		Timeout:      5 * time.Second,
	})
	if err != nil {
		return err
	}
	defer c.Close()
	st, err := h.asciiLogin(c, 30, "lab-admin", h.pw("lab-admin"))
	if err != nil {
		return err
	}
	if st != tcodec.StatusPass {
		return fmt.Errorf("tls ascii=%#x", st)
	}
	return nil
}

func (h *harness) labTLSUnauth() error {
	if h.PKI == "" {
		return fmt.Errorf("pki directory required")
	}
	cert, err := tls.LoadX509KeyPair(h.PKI+"/client-unauth.pem", h.PKI+"/client-unauth.key")
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(h.PKI + "/server-ca.pem")
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("server CA")
	}
	c, err := tclient.DialTLS(h.TLS, tclient.TLSOptions{
		ServerName:   h.ServerName,
		Kind:         tclient.IdentityDNS,
		Identity:     h.ServerName,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		Timeout:      5 * time.Second,
	})
	if err != nil {
		// Handshake-time reject is acceptable.
		return nil
	}
	defer c.Close()
	st, err := h.asciiLogin(c, 31, "lab-admin", h.pw("lab-admin"))
	if err != nil {
		return nil
	}
	if st == tcodec.StatusPass {
		return fmt.Errorf("unauth client was accepted")
	}
	return nil
}

func (h *harness) labTLSPlaintext() error {
	nc, err := net.DialTimeout("tcp", h.TLS, 2*time.Second)
	if err != nil {
		return err
	}
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(2 * time.Second))
	body, _ := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	hdr := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagUnencrypted, SessionID: 1}
	pkt := append(hdr.Encode(), body...)
	_, _ = nc.Write(pkt)
	buf := make([]byte, 32)
	n, _ := nc.Read(buf)
	if n >= 12 && (buf[0] == 0xc0 || buf[0] == 0xc1) {
		return fmt.Errorf("plaintext TACACS accepted on TLS port")
	}
	return nil
}

func (h *harness) labAPIparity() error {
	code, raw, err := h.restJSON(http.MethodGet, "/api/v1/status", nil, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, raw); err != nil {
		return err
	}
	if err := mustContain(raw, "colocated_topology"); err != nil {
		return err
	}
	eval := map[string]any{"user_id": "lab-admin", "client_id": "lab-switches", "service": "shell", "cmd": "configure"}
	code, restRaw, err := h.restJSON(http.MethodPost, "/api/v1/policy/evaluate", eval, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, restRaw); err != nil {
		return err
	}
	mcpCode, mcpRaw, err := h.mcpCall("taclab.policy.evaluate", eval)
	if err != nil {
		return err
	}
	if err := statusOK(mcpCode, mcpRaw); err != nil {
		return err
	}
	if !bytes.Contains(restRaw, []byte("permit")) || !bytes.Contains(mcpRaw, []byte("permit")) {
		return fmt.Errorf("evaluate missing permit rest=%s mcp=%s", restRaw, mcpRaw)
	}
	return nil
}

func (h *harness) labAPICreate() error {
	body := map[string]any{"id": "lab-runtime-tmp", "enabled": false, "display_name": "runtime"}
	code, raw, err := h.restJSON(http.MethodPost, "/api/v1/users", body, map[string]string{"Idempotency-Key": "lab-runtime-tmp-1"})
	if err != nil {
		return err
	}
	if code != http.StatusOK && code != http.StatusCreated && code != http.StatusConflict {
		return fmt.Errorf("create user=%d %s", code, raw)
	}
	code, raw, err = h.restJSON(http.MethodGet, "/api/v1/users/lab-runtime-tmp", nil, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, raw); err != nil {
		return err
	}
	if err := mustContain(raw, "runtime"); err != nil {
		return err
	}
	mcpBody := map[string]any{"id": "lab-runtime-mcp", "enabled": false}
	mcpCode, mcpRaw, err := h.mcpCall("taclab.users.create", mcpBody)
	if err != nil {
		return err
	}
	if mcpCode != http.StatusOK && mcpCode != http.StatusCreated {
		// already_exists after rerun is acceptable
		if !bytes.Contains(mcpRaw, []byte("already_exists")) && !bytes.Contains(mcpRaw, []byte("lab-runtime-mcp")) {
			return fmt.Errorf("mcp create=%d %s", mcpCode, mcpRaw)
		}
	}
	return nil
}

func (h *harness) labReset() error {
	if err := h.labAPICreate(); err != nil {
		return err
	}
	code, raw, err := h.restJSON(http.MethodPost, "/api/v1/runtime/reset", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, raw); err != nil {
		return err
	}
	code, raw, err = h.restJSON(http.MethodGet, "/api/v1/users/lab-runtime-tmp", nil, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNotFound && !bytes.Contains(raw, []byte("not_found")) {
		return fmt.Errorf("runtime user survived reset: %d %s", code, raw)
	}
	return nil
}

func (h *harness) labReload() error {
	code, raw, err := h.restJSON(http.MethodPost, "/api/v1/config/reload", nil, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, raw); err != nil {
		return err
	}
	code, raw, err = h.restJSON(http.MethodGet, "/api/v1/status", nil, nil)
	if err != nil {
		return err
	}
	return statusOK(code, raw)
}

func (h *harness) labStateRestart() error {
	code, raw, err := h.restJSON(http.MethodGet, "/api/v1/users/lab-runtime-tmp", nil, nil)
	if err != nil {
		return err
	}
	if code == http.StatusOK && bytes.Contains(raw, []byte("lab-runtime-tmp")) && !bytes.Contains(raw, []byte("not_found")) {
		var view struct {
			Data struct {
				Source string `json:"source"`
			} `json:"data"`
		}
		_ = json.Unmarshal(raw, &view)
		if view.Data.Source == "runtime" {
			return fmt.Errorf("runtime user survived restart")
		}
	}
	code, raw, err = h.restJSON(http.MethodGet, "/api/v1/users/lab-admin", nil, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, raw); err != nil {
		return err
	}
	return mustContain(raw, "lab-admin")
}

func (h *harness) labSubscriberSurvivesWriteTimeout() error {
	if h.WriteTO <= 0 {
		h.WriteTO = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.WriteTO*3+3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.HTTP+"/api/v1/events/stream", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Accept", "text/event-stream")
	cl := &http.Client{Timeout: 0}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("sse=%d %s", resp.StatusCode, b)
	}
	buf, err := consumeSSEPastTimeout(resp.Body, h.WriteTO)
	if err != nil {
		return err
	}
	return h.rejectCanary(buf)
}

func (h *harness) labSourceIP() error {
	code, raw, err := h.restJSON(http.MethodGet, "/api/v1/events?limit=50", nil, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, raw); err != nil {
		return err
	}
	clientID, remote, err := parseObservedSource(raw)
	if err != nil {
		return err
	}
	h.sourceNote = "TACACS client match uses the TCP peer address (no PROXY, no X-Forwarded-For). " +
		"This run used source_cidrs 0.0.0.0/0 and ::/0 so published-port NAT and compose-network " +
		"addresses both match. For device-accurate IPs use host network or macvlan (LAB_DEPLOYMENT §4.3). " +
		"event client_id=" + clientID + " remote=" + remote +
		" (packet rem_addr / event.remote; not a TCP-peer export)."
	return nil
}

func (h *harness) labTLSOnlyProfile() error {
	// Legacy listener is disabled: the TCP connect itself must fail.
	c, err := net.DialTimeout("tcp", h.Legacy, time.Second)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("legacy %s accepted on TLS-only profile", h.Legacy)
	}
	code, raw, err := h.restJSON(http.MethodGet, "/api/v1/status", nil, nil)
	if err != nil {
		return err
	}
	if err := statusOK(code, raw); err != nil {
		return err
	}
	if bytes.Contains(raw, []byte(`"colocated_topology":true`)) || bytes.Contains(raw, []byte(`"colocated_topology": true`)) {
		return fmt.Errorf("tls-only still reports colocated topology")
	}
	return h.labTLSSuccess()
}

func (h *harness) labUnauth() error {
	req, err := http.NewRequest(http.MethodGet, h.HTTP+"/api/v1/status", nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("unauth status=%d", resp.StatusCode)
	}
	return nil
}

func (h *harness) withLegacy(fn func(*tclient.Conn) error) error {
	if err := waitTCP(h.Legacy, 5*time.Second); err != nil {
		return err
	}
	c, err := tclient.Dial(h.Legacy, h.Secret)
	if err != nil {
		return err
	}
	defer c.Close()
	return fn(c)
}

func (h *harness) asciiLogin(c *tclient.Conn, sid uint32, user, pass string) (byte, error) {
	body, err := tcodec.WriteStart(tcodec.Start{
		Action: tcodec.ActionLogin, AType: tcodec.TypeASCII, Service: tcodec.SvcLogin,
		User: []byte(user), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		return 0, err
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: sid}, body); err != nil {
		return 0, err
	}
	st, err := readAuthen(c)
	if err != nil {
		return 0, err
	}
	if st != tcodec.StatusGetPass && st != tcodec.StatusGetUser && st != tcodec.StatusGetData {
		return st, nil
	}
	cbody, err := tcodec.WriteCont(tcodec.Cont{Msg: []byte(pass)})
	if err != nil {
		return 0, err
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 3, Flags: tcodec.FlagSingleConnect, SessionID: sid}, cbody); err != nil {
		return 0, err
	}
	return readAuthen(c)
}

func (h *harness) author(c *tclient.Conn, sid uint32, user, cmd string, args []string) (byte, error) {
	pairs := []tcodec.Pair{{Key: "service", Sep: tcodec.SepEq, Val: "shell"}}
	if cmd != "" {
		pairs = append(pairs, tcodec.Pair{Key: "cmd", Sep: tcodec.SepEq, Val: cmd})
		for _, a := range args {
			pairs = append(pairs, tcodec.Pair{Key: "cmd-arg", Sep: tcodec.SepEq, Val: a})
		}
	}
	body, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte(user), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		Pairs: pairs,
	})
	if err != nil {
		return 0, err
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: sid}, body); err != nil {
		return 0, err
	}
	_, rbody, err := c.ReadPacket()
	if err != nil {
		return 0, err
	}
	rep, err := tcodec.ReadAuthorRep(rbody)
	if err != nil {
		return 0, err
	}
	return rep.Status, nil
}

func (h *harness) acct(c *tclient.Conn, sid uint32, flags byte) error {
	body, err := tcodec.WriteAcctReq(tcodec.AcctReq{
		Flags: flags, Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		Pairs: []tcodec.Pair{{Key: "task_id", Sep: tcodec.SepEq, Val: "lab-task-1"}},
	})
	if err != nil {
		return err
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAcct, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: sid}, body); err != nil {
		return err
	}
	_, rbody, err := c.ReadPacket()
	if err != nil {
		return err
	}
	rep, err := tcodec.ReadAcctRep(rbody)
	if err != nil {
		return err
	}
	if rep.Status != tcodec.AcctOK {
		return fmt.Errorf("acct flags=%#x status=%#x", flags, rep.Status)
	}
	return nil
}

// consumeSSEPastTimeout fails if the stream dies at or before writeTO, or if
// no successful read happens strictly after writeTO.
func consumeSSEPastTimeout(r io.Reader, writeTO time.Duration) ([]byte, error) {
	if writeTO <= 0 {
		writeTO = 2 * time.Second
	}
	started := time.Now()
	survive := started.Add(writeTO)
	limit := started.Add(writeTO*2 + 2*time.Second)
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 128)
	gotAfter := false
	for {
		if time.Now().After(limit) {
			if !gotAfter {
				return buf, fmt.Errorf("no successful read after write_timeout body=%q", buf)
			}
			return buf, nil
		}
		n, err := r.Read(tmp)
		now := time.Now()
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if now.After(survive) {
				gotAfter = true
				if hasSSEFrame(buf) {
					return buf, nil
				}
			}
		}
		if err == io.EOF {
			if !now.After(survive) {
				return buf, fmt.Errorf("sse closed before write_timeout elapsed body=%q", buf)
			}
			if !gotAfter {
				return buf, fmt.Errorf("sse closed without a frame after write_timeout body=%q", buf)
			}
			return buf, nil
		}
		if err != nil {
			if !now.After(survive) {
				return buf, fmt.Errorf("sse read before write_timeout: %w body=%q", err, buf)
			}
			return buf, fmt.Errorf("sse read after write_timeout: %w body=%q", err, buf)
		}
	}
}

func hasSSEFrame(buf []byte) bool {
	return bytes.Contains(buf, []byte("keepalive")) || bytes.Contains(buf, []byte("data:")) || bytes.Contains(buf, []byte("event:"))
}

func parseObservedSource(raw []byte) (clientID, remote string, err error) {
	var env struct {
		Data struct {
			Items []struct {
				ClientID string `json:"client_id"`
				Remote   string `json:"remote"`
				Peer     string `json:"peer"`
				RemoteIP string `json:"remote_addr"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", "", err
	}
	items := env.Data.Items
	if len(items) == 0 {
		// Envelope may be omitted; try the list at the top level.
		var alt struct {
			Items []struct {
				ClientID string `json:"client_id"`
				Remote   string `json:"remote"`
				Peer     string `json:"peer"`
				RemoteIP string `json:"remote_addr"`
			} `json:"items"`
		}
		if err := json.Unmarshal(raw, &alt); err != nil {
			return "", "", fmt.Errorf("events json: %w", err)
		}
		items = alt.Items
	}
	for _, it := range items {
		rem := it.Remote
		if rem == "" {
			rem = it.Peer
		}
		if rem == "" {
			rem = it.RemoteIP
		}
		if it.ClientID == "lab-switches" && rem != "" {
			return it.ClientID, rem, nil
		}
	}
	return "", "", fmt.Errorf("no event with client_id=lab-switches and remote/peer")
}

func readAuthen(c *tclient.Conn) (byte, error) {
	_, body, err := c.ReadPacket()
	if err != nil {
		return 0, err
	}
	rep, err := tcodec.ReadReply(body)
	if err != nil {
		return 0, err
	}
	return rep.Status, nil
}
