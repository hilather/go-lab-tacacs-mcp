package operations

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestStatusReadsPublishedSnapshot(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	m := mustMgr(t, smallYAML)
	snap := m.Snapshot()
	res, err := reg.Invoke(context.Background(), IDSystemStatusGet, snap, Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != snap.Revision || res.Revision != 1 {
		t.Fatalf("revision=%d snap=%d", res.Revision, snap.Revision)
	}
	st, ok := res.Data.(Status)
	if !ok {
		t.Fatalf("data=%T", res.Data)
	}
	if st.Revision != snap.Revision || st.BaselineHash != snap.BaselineHash || st.OverlayHash != snap.OverlayHash {
		t.Fatalf("status hashes/rev mismatch: %+v", st)
	}
	if st.CompiledAt != snap.CompiledAt {
		t.Fatalf("compiled_at=%v want %v", st.CompiledAt, snap.CompiledAt)
	}
	if st.InstanceID != "lab-legacy" {
		t.Fatalf("instance=%q", st.InstanceID)
	}
	if st.Users != 1 || st.Groups != 1 || st.Clients != 1 {
		t.Fatalf("counts users=%d groups=%d clients=%d", st.Users, st.Groups, st.Clients)
	}
	if st.ColocatedTopology || st.TopologyWarning != "" {
		t.Fatalf("legacy-only must not warn: %+v", st)
	}
	if len(st.Listeners) != 3 {
		t.Fatalf("listeners=%d", len(st.Listeners))
	}
	if st.Listeners[0].ID != ListenerLegacy || !st.Listeners[0].Enabled || st.Listeners[0].Transport != string(domain.TransportLegacy) {
		t.Fatalf("legacy=%+v", st.Listeners[0])
	}
	if st.Listeners[1].ID != ListenerSecure || st.Listeners[1].Enabled {
		t.Fatalf("secure=%+v", st.Listeners[1])
	}
	if st.Listeners[2].ID != ListenerHTTP || !st.Listeners[2].Enabled || st.Listeners[2].Transport != TransportHTTP {
		t.Fatalf("http=%+v", st.Listeners[2])
	}
	if st.Listeners[0].Bind == "" || st.Listeners[2].Bind == "" {
		t.Fatal("bind addresses required")
	}
}

func TestStatusColocatedWarning(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	snap := mustSnap(t, colocatedYAML)
	res, err := reg.Invoke(context.Background(), IDSystemStatusGet, snap, Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	st := res.Data.(Status)
	if !st.ColocatedTopology || st.TopologyWarning != ColocatedTopologyWarning {
		t.Fatalf("expected colocated warning, got %+v", st)
	}
	if st.Listeners[0].Enabled != true || st.Listeners[1].Enabled != true {
		t.Fatalf("both TACACS listeners should be enabled: %+v", st.Listeners)
	}
}

func TestStatusTracksOverlayRevision(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	m := mustMgr(t, smallYAML)
	first := m.Snapshot()
	rev := first.Revision
	name := "Alice Overlay"
	if _, err := m.UpdateUser("alice", state.UpdateUser{DisplayName: &name}, &rev); err != nil {
		t.Fatal(err)
	}
	second := m.Snapshot()
	if second.Revision != first.Revision+1 {
		t.Fatalf("rev %d -> %d", first.Revision, second.Revision)
	}
	res, err := reg.Invoke(context.Background(), IDSystemStatusGet, second, Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	st := res.Data.(Status)
	if st.Revision != second.Revision || st.OverlayHash == first.OverlayHash {
		t.Fatalf("status did not follow overlay publish: %+v", st)
	}
	if st.Users != 1 {
		t.Fatalf("users=%d", st.Users)
	}
}

func TestStatusOmitsSecretMaterial(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	res, err := reg.Invoke(context.Background(), IDSystemStatusGet, mustSnap(t, smallYAML), Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%+v", res.Data)
	for _, needle := range []string{"/run/secrets", "alice-login", "shared_secret", "verifier"} {
		if strings.Contains(dump, needle) {
			t.Fatalf("status leaked %q: %s", needle, dump)
		}
	}
}

func TestBuildReadsSnapshotAndMeta(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	snap := mustSnap(t, smallYAML)
	res, err := reg.Invoke(context.Background(), IDSystemBuildGet, snap, Input{Actor: reader, Request: GetBuildRequest{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != snap.Revision {
		t.Fatalf("revision=%d", res.Revision)
	}
	info, ok := res.Data.(BuildInfo)
	if !ok {
		t.Fatalf("data=%T", res.Data)
	}
	if info.Version != "test" || info.Commit != "abc" || info.BuildTime != "2026-08-12T00:00:00Z" || info.UIVersion != "ui-test" {
		t.Fatalf("meta=%+v", info)
	}
	if info.GoVersion != runtime.Version() {
		t.Fatalf("go=%q", info.GoVersion)
	}
	if info.SchemaVersion != config.SchemaVersion || info.SchemaVersion != snap.Settings().SchemaVersion {
		t.Fatalf("schema=%d", info.SchemaVersion)
	}
	if info.MCPSpecification != MCPSpecification || info.TACACSConformance != TACACSConformance {
		t.Fatalf("specs=%+v", info)
	}
}

func TestBuildDefaultsEmptyMeta(t *testing.T) {
	t.Parallel()
	reg, err := New(mustSpec(t), Deps{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := reg.Invoke(context.Background(), IDSystemBuildGet, mustSnap(t, smallYAML), Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	info := res.Data.(BuildInfo)
	if info.Version != "dev" || info.Commit != "unknown" || info.BuildTime != "unknown" {
		t.Fatalf("defaults=%+v", info)
	}
	if info.UIVersion != "" {
		t.Fatalf("ui=%q", info.UIVersion)
	}
}

func TestBuildOmitsPaths(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	res, err := reg.Invoke(context.Background(), IDSystemBuildGet, mustSnap(t, smallYAML), Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%+v", res.Data)
	if strings.Contains(dump, "/run/secrets") || strings.Contains(dump, "/etc/") {
		t.Fatalf("build leaked path: %s", dump)
	}
}

func TestEvaluatePolicyServiceVsCommand(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	snap := mustSnap(t, smallYAML)
	tester := Actor{ID: "tester", Scopes: []string{"policy:test"}}

	sess, err := reg.Invoke(context.Background(), IDPolicyEvaluate, snap, Input{
		Actor:   tester,
		Request: EvaluatePolicyRequest{UserID: "alice", ClientID: "sw", Service: "shell"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tr := sess.Data.(PolicyTrace)
	if tr.Evaluator != string(domain.RuleKindService) || tr.Decision != "deny" {
		t.Fatalf("session trace=%+v", tr)
	}

	cmd, err := reg.Invoke(context.Background(), IDPolicyEvaluate, snap, Input{
		Actor:   tester,
		Request: EvaluatePolicyRequest{UserID: "alice", ClientID: "sw", Service: "shell", Cmd: "show", CmdArgs: []string{"ver"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctr := cmd.Data.(PolicyTrace)
	if ctr.Evaluator != string(domain.RuleKindCommand) || ctr.Decision != "permit_add" {
		t.Fatalf("command trace=%+v", ctr)
	}
	for _, st := range ctr.Steps {
		if st.Kind == string(domain.RuleKindService) {
			t.Fatalf("command walk hit service rule: %+v", st)
		}
	}
}

func TestEvaluatePolicyRequiresUserAndScope(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	snap := mustSnap(t, smallYAML)
	_, err := reg.Invoke(context.Background(), IDPolicyEvaluate, snap, Input{Actor: reader, Request: EvaluatePolicyRequest{UserID: "alice"}})
	if !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("scope err=%v", err)
	}
	tester := Actor{ID: "tester", Scopes: []string{"policy:test"}}
	_, err = reg.Invoke(context.Background(), IDPolicyEvaluate, snap, Input{Actor: tester, Request: EvaluatePolicyRequest{}})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("user err=%v", err)
	}
}

func TestInvokeConcurrentReads(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	snap := mustSnap(t, colocatedYAML)
	var wg sync.WaitGroup
	errc := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := reg.Invoke(context.Background(), IDSystemStatusGet, snap, Input{Actor: reader})
			if err != nil {
				errc <- err
			}
		}()
		go func() {
			defer wg.Done()
			_, err := reg.Invoke(context.Background(), IDSystemBuildGet, snap, Input{Actor: reader})
			if err != nil {
				errc <- err
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

func mustMgr(t *testing.T, src string) *state.Manager {
	t.Helper()
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	m, err := state.New(doc, state.Options{Clock: fixedClock{t: time.Date(2026, 8, 12, 15, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

const smallYAML = `
schema_version: 1
server:
  instance_id: lab-legacy
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: sw
    display_name: Switches
    priority: 100
    match:
      source_cidrs: ["10.20.0.0/16", "2001:db8:20::/48"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/sw}
    authorization:
      default_group_ids: [ops]
groups:
  - id: ops
    display_name: Operators
    priority: 10
    command_rules:
      - id: show
        priority: 10
        action: permit
        command: {exact: show}
        arguments: {pattern: ".*"}
users:
  - id: alice
    display_name: Alice
    group_ids: [ops]
    credentials:
      login:
        verifier: {file: /run/secrets/alice-login}
      challenge:
        secret: {file: /run/secrets/alice-chal}
      enable:
        verifier: {file: /run/secrets/alice-enable}
`

const colocatedYAML = `
schema_version: 1
server:
  instance_id: lab-both
listeners:
  secure_tacacs:
    enabled: true
    tls:
      identities:
        profiles:
          - id: default
            certificate_chain: {file: /etc/taclab/tls/server.pem}
            private_key: {file: /run/secrets/tls-key}
      client_ca_bundle: {file: /etc/taclab/tls/ca.pem}
      revocation:
        crl_bundle: {file: /etc/taclab/tls/crl.pem}
clients:
  - id: sw
    display_name: Switches
    priority: 100
    match:
      source_cidrs: ["10.20.0.0/16"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/sw}
`
