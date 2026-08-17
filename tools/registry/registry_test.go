package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := FindRoot(wd)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCheckedInRegistriesValid(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Valid() {
		for _, issue := range rep.Issues {
			t.Errorf("%s", issue)
		}
	}
	if got := len(rep.Operations.Operations); got != expectedOperationCount {
		t.Fatalf("operations: got %d, want %d", got, expectedOperationCount)
	}
	have := map[string]struct{}{}
	for _, op := range rep.Operations.Operations {
		have[op.ID] = struct{}{}
	}
	for _, id := range protocolOnlyOperationIDs {
		if _, ok := have[id]; !ok {
			t.Errorf("missing protocol-only operation %s", id)
		}
	}
	if got := len(rep.RFC8907.Rows); got != 171 {
		t.Fatalf("RFC 8907 rows: got %d, want 171", got)
	}
	if got := len(rep.RFC9887.Rows); got != 51 {
		t.Fatalf("RFC 9887 rows: got %d, want 51", got)
	}
	if got := len(rep.RFC2865.Rows); got != 13 {
		t.Fatalf("RFC 2865 rows: got %d, want 13", got)
	}
	if got := len(rep.RFC2866.Rows); got != 3 {
		t.Fatalf("RFC 2866 rows: got %d, want 3", got)
	}
	if got := len(rep.RFC2869.Rows); got != 3 {
		t.Fatalf("RFC 2869 rows: got %d, want 3", got)
	}
	if got := len(rep.RFC3579.Rows); got != 1 {
		t.Fatalf("RFC 3579 rows: got %d, want 1", got)
	}
	if got := len(rep.RFC5080.Rows); got != 1 {
		t.Fatalf("RFC 5080 rows: got %d, want 1", got)
	}
	if got := len(rep.ProjectRADIUS.Rows); got != 19 {
		t.Fatalf("project-radius rows: got %d, want 19", got)
	}
}

func TestConformanceIDsUniqueAndRequired(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, ConformanceDocPath))
	if err != nil {
		t.Fatal(err)
	}
	radiusDoc, err := os.ReadFile(filepath.Join(root, RadiusConformanceDocPath))
	if err != nil {
		t.Fatal(err)
	}
	tacacsIDs := ExtractConformanceIDs(doc)
	if len(tacacsIDs) != 222 {
		t.Fatalf("TACACS contract IDs: got %d, want 222", len(tacacsIDs))
	}
	radiusIDs := ExtractConformanceIDs(radiusDoc)
	if len(radiusIDs) != 40 {
		t.Fatalf("RADIUS contract IDs: got %d, want 40", len(radiusIDs))
	}
	want := append(append([]string{}, tacacsIDs...), radiusIDs...)
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]struct{}{}
	for _, table := range rep.ConformanceTables() {
		for _, row := range table.Rows {
			if _, ok := seen[row.ID]; ok {
				t.Errorf("duplicate id %s", row.ID)
			}
			seen[row.ID] = struct{}{}
			if row.Level == "" || row.Requirement == "" || row.Status == "" {
				t.Errorf("%s: missing level/requirement/status", row.ID)
			}
			if row.Status == StatusNotStarted && len(row.Evidence) != 0 {
				t.Errorf("%s: NOT_STARTED evidence must be empty", row.ID)
			}
			if statusRequiresEvidence(row.Status) && len(row.Evidence) == 0 {
				t.Errorf("%s: status %s requires evidence", row.ID, row.Status)
			}
		}
	}
	for _, id := range want {
		if _, ok := seen[id]; !ok {
			t.Errorf("missing contract id %s", id)
		}
	}
	for id := range seen {
		if strings.HasPrefix(id, "T") {
			continue
		}
		found := false
		for _, wantID := range radiusIDs {
			if wantID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("registry id %s is missing from %s", id, RadiusConformanceDocPath)
		}
	}
}

func TestOperationsUniqueAndBindingsPresent(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(root, ParityDocPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ExtractOperationIDs(doc) {
		found := false
		for _, op := range rep.Operations.Operations {
			if op.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing contract operation %s", id)
		}
	}
	ids := map[string]struct{}{}
	for _, op := range rep.Operations.Operations {
		if _, ok := ids[op.ID]; ok {
			t.Errorf("duplicate operation %s", op.ID)
		}
		ids[op.ID] = struct{}{}
		needREST, needMCP := requiredBindings(op.Parity)
		if needREST && op.REST.Empty() {
			t.Errorf("%s missing REST binding", op.ID)
		}
		if needMCP && op.MCP.Empty() {
			t.Errorf("%s missing MCP binding", op.ID)
		}
	}
}

func TestEventsSubscribeDifferentBinding(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	var sub *Operation
	for i := range rep.Operations.Operations {
		if rep.Operations.Operations[i].ID == "events.subscribe" {
			sub = &rep.Operations.Operations[i]
			break
		}
	}
	if sub == nil {
		t.Fatal("events.subscribe missing")
	}
	if sub.Parity != ParityDifferentBinding {
		t.Fatalf("parity %s, want %s", sub.Parity, ParityDifferentBinding)
	}
	if sub.REST.Method != "GET" || sub.REST.Path != "/api/v1/events/stream" {
		t.Fatalf("REST binding %#v", sub.REST)
	}
	if sub.MCP.Kind != "listen" || sub.MCP.Resource != "taclab://events/recent" {
		t.Fatalf("MCP binding %#v", sub.MCP)
	}
	if sub.MCP.PullOperation != "events.list" {
		t.Fatalf("pull_operation %q, want events.list", sub.MCP.PullOperation)
	}
	if strings.Contains(sub.MCP.Name, "taclab.events.subscribe") {
		t.Fatal("must not invent an MCP event firehose tool")
	}
}

func TestInvalidOperationFixturesFail(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file    string
		wantSub string
	}{
		{"operations-missing-rest.yaml", "missing REST binding"},
		{"operations-missing-mcp.yaml", "missing MCP binding"},
		{"operations-duplicate-id.yaml", "duplicate operation id"},
		{"subscribe-missing-mcp.yaml", "missing MCP binding"},
		{"operations-exempt-missing-adr.yaml", "EXEMPT_BY_ADR requires adr"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			doc, err := LoadOperations(filepath.Join("testdata", "invalid", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			rep := &Report{}
			validateOperations(rep, tc.file, doc)
			if rep.Valid() {
				t.Fatal("expected validation failure")
			}
			if !containsIssue(rep, tc.wantSub) {
				t.Fatalf("issues %#v, want substring %q", rep.Issues, tc.wantSub)
			}
		})
	}
}

func TestUnknownYAMLFieldFailsLoad(t *testing.T) {
	t.Parallel()
	_, err := LoadOperations(filepath.Join("testdata", "invalid", "operations-unknown-field.yaml"))
	if err == nil {
		t.Fatal("expected unknown field to fail decode")
	}
	if !strings.Contains(err.Error(), "pull_opertion") {
		t.Fatalf("error %v, want pull_opertion", err)
	}
}

func TestMandatoryLevels(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]ConformanceRow{}
	for _, table := range []*ConformanceRegistry{rep.RFC8907, rep.RFC9887} {
		for _, row := range table.Rows {
			rows[row.ID] = row
		}
	}
	cases := []struct {
		id   string
		want bool
	}{
		{"T89-H-003", true},
		{"T89-L-004", true},
		{"T89-AU-017", true},
		{"T89-AC-014", true},
		{"T89-AS-013", true},
		{"T98-CERT-004", true},
		{"T98-RES-005", true},
		{"T89-SEC-014", false},
		{"T89-SEC-015", false},
		{"T98-ROLE-001", false},
		{"T98-OPT-002", false},
		{"T98-OPT-003", false},
		{"T98-TLS-008", false},
	}
	for _, tc := range cases {
		row, ok := rows[tc.id]
		if !ok {
			t.Fatalf("missing row %s", tc.id)
		}
		if got := row.Mandatory(); got != tc.want {
			t.Errorf("%s level %q Mandatory()=%v, want %v", tc.id, row.Level, got, tc.want)
		}
	}
}

func TestInvalidConformanceFixturesFail(t *testing.T) {
	t.Parallel()
	doc, err := LoadConformance(filepath.Join("testdata", "invalid", "conformance-duplicate-id.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rep := &Report{}
	validateConformance(rep, "conformance-duplicate-id.yaml", "8907", doc)
	if !containsIssue(rep, "duplicate conformance id") {
		t.Fatalf("issues %#v", rep.Issues)
	}
}

func TestUnreferencedMandatoryRowFailsCoverage(t *testing.T) {
	t.Parallel()
	doc, err := LoadConformance(filepath.Join("testdata", "invalid", "conformance-missing-mandatory.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rep := &Report{}
	checkConformanceContractCoverage(rep, []string{"T89-H-001", "T89-H-003"}, doc)
	if !containsIssue(rep, "unreferenced mandatory conformance row") {
		t.Fatalf("issues %#v", rep.Issues)
	}
	if !issueHasID(rep, "T89-H-003") {
		t.Fatalf("expected T89-H-003 missing, issues %#v", rep.Issues)
	}
}

func TestReleaseValidationRejectsNotStartedMUST(t *testing.T) {
	t.Parallel()
	doc := &ConformanceRegistry{
		SchemaVersion: 1,
		RFC:           "8907",
		Rows: []ConformanceRow{
			{ID: "T89-H-003", Level: "MUST", Status: StatusNotStarted},
			{ID: "T89-AU-017", Level: "SHOULD/PROJECT MUST", Status: StatusNotStarted},
			{ID: "T98-CERT-004", Level: "MUST/Policy", Status: StatusNotStarted},
			{ID: "T89-SEC-014", Level: "OPERATOR SHOULD", Status: StatusNotStarted},
		},
	}
	issues := CheckReleaseStatuses(doc)
	if len(issues) == 0 {
		t.Fatal("expected release validation to fail while rows are NOT_STARTED")
	}
	wantIDs := []string{"T89-H-003", "T89-AU-017", "T98-CERT-004"}
	have := map[string]struct{}{}
	for _, issue := range issues {
		have[issue.ID] = struct{}{}
	}
	for _, id := range wantIDs {
		if _, ok := have[id]; !ok {
			t.Fatalf("expected %s in release issues (compound MUST rows must be gated)", id)
		}
	}
	if _, ok := have["T89-SEC-014"]; ok {
		t.Fatal("OPERATOR SHOULD must not be a release-blocking MUST")
	}
}

func TestReleaseValidationPassesQualifiedRegistries(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if issues := CheckReleaseStatuses(rep.TACACSTables()...); len(issues) != 0 {
		t.Fatalf("qualified MUST rows still open: %v", issues)
	}
	if issues := CheckSHOULDDispositions(rep.TACACSTables()...); len(issues) != 0 {
		t.Fatalf("SHOULD rows missing disposition: %v", issues)
	}
}

func TestReleaseGateExcludesRADIUSSkeletons(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range ReleaseConformanceTables(rep) {
		if table == nil {
			continue
		}
		switch table.RFC {
		case "8907", "9887":
		default:
			t.Errorf("check-registries -release must not include rfc %q", table.RFC)
		}
	}
	radiusIssues := CheckReleaseStatuses(rep.RADIUSTables()...)
	if len(radiusIssues) == 0 {
		t.Fatal("R65-ACCESS-004 DEFERRED_MAY must fail CheckReleaseStatuses")
	}
	have := map[string]struct{}{}
	for _, issue := range radiusIssues {
		have[issue.ID] = struct{}{}
	}
	if _, ok := have["R65-ACCESS-004"]; !ok {
		t.Error("expected R65-ACCESS-004 (DEFERRED_MAY) in RADIUS CheckReleaseStatuses issues")
	}
	for _, id := range []string{"R65-PKT-001", "PRJ-SEC-001"} {
		if _, ok := have[id]; ok {
			t.Errorf("%s is evidenced PASS and must not fail CheckReleaseStatuses", id)
		}
	}
	if issues := CheckReleaseStatuses(ReleaseConformanceTables(rep)...); len(issues) != 0 {
		t.Fatalf("-release tables must stay clean: %v", issues)
	}
}

func TestListenPullMustNameARegisteredOperation(t *testing.T) {
	t.Parallel()
	doc := &OperationRegistry{
		SchemaVersion: 1,
		Operations: []Operation{{
			ID:           "events.subscribe",
			Description:  "Live events",
			Parity:       ParityDifferentBinding,
			Idempotent:   "false",
			Scopes:       []string{"events:read"},
			RequestType:  "SubscribeEventsRequest",
			ResponseType: "EventStream",
			REST:         RESTBinding{Method: "GET", Path: "/api/v1/events/stream"},
			MCP: MCPBinding{
				Kind:          "listen",
				Name:          "subscriptions/listen",
				Resource:      "taclab://events/recent",
				PullOperation: "events.list",
			},
			Status: StatusNotStarted,
		}},
	}
	rep := &Report{}
	validateOperations(rep, "mem", doc)
	if !containsIssue(rep, `pull_operation "events.list" is not a registered operation`) {
		t.Fatalf("issues %#v", rep.Issues)
	}
}

func TestGenerateDocs(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := GenerateDocs(out, rep.Operations, rep.ConformanceTables()...); err != nil {
		t.Fatal(err)
	}
	parity, err := os.ReadFile(filepath.Join(out, GeneratedParity))
	if err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(filepath.Join(out, GeneratedConformance))
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"events.subscribe", ParityDifferentBinding, "GET /api/v1/events/stream", "subscriptions/listen"} {
		if !strings.Contains(string(parity), needle) {
			t.Errorf("api-parity.md missing %q", needle)
		}
	}
	for _, needle := range []string{
		"T89-H-001",
		"T98-TLS-001",
		StatusPass,
		"T89-AV-003",
		"cmd",
		"unit:internal/tacacs/codec.TestDecodeEncodeRoundTrip",
		"Qualification summary",
		"mandatory rows `PASS`",
		"Generated TACACS+ and RADIUS conformance inventory",
		"R65-PKT-001",
		"R79-MA-001",
		"R80-DUP-001",
		"PRJ-SEC-001",
		"RADIUS qualification summary",
		"Do not claim complete RADIUS",
		"External radclient / Cisco IOL",
	} {
		if !strings.Contains(string(conf), needle) {
			t.Errorf("conformance.md missing %q", needle)
		}
	}
}

const expectedOperationCount = 44

var protocolOnlyOperationIDs = []string{
	"health.live",
	"health.ready",
	"openapi.get",
	"session.create",
	"session.delete",
	"mcp.discover",
	"mcp.tools.list",
	"mcp.resources.list",
	"mcp.notifications.list_changed",
}

func containsIssue(rep *Report, sub string) bool {
	for _, issue := range rep.Issues {
		if strings.Contains(issue.String(), sub) {
			return true
		}
	}
	return false
}

func issueHasID(rep *Report, id string) bool {
	for _, issue := range rep.Issues {
		if issue.ID == id {
			return true
		}
	}
	return false
}

func TestRADIUSRowPrefixesAndDeferredEvidence(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Valid() {
		for _, issue := range rep.Issues {
			t.Errorf("%s", issue)
		}
	}
	wantPrefix := map[string]string{
		"2865":    "R65-",
		"2866":    "R66-",
		"2869":    "R69-",
		"3579":    "R79-",
		"5080":    "R80-",
		"PROJECT": "PRJ-",
	}
	for _, table := range rep.RADIUSTables() {
		prefix := wantPrefix[table.RFC]
		if prefix == "" {
			t.Fatalf("unexpected RADIUS rfc %q", table.RFC)
		}
		for _, row := range table.Rows {
			if !strings.HasPrefix(row.ID, prefix) {
				t.Errorf("%s: id %s must start with %s", table.RFC, row.ID, prefix)
			}
			if strings.HasPrefix(row.ID, "R3579-") || strings.HasPrefix(row.ID, "R5080-") {
				t.Errorf("invented row id %s is forbidden", row.ID)
			}
		}
	}
	var challenge *ConformanceRow
	for _, row := range rep.RFC2865.Rows {
		if row.ID == "R65-ACCESS-004" {
			row := row
			challenge = &row
			break
		}
	}
	if challenge == nil {
		t.Fatal("missing R65-ACCESS-004")
	}
	if challenge.Status != StatusDeferredMAY {
		t.Fatalf("R65-ACCESS-004 status %s, want %s", challenge.Status, StatusDeferredMAY)
	}
	if len(challenge.Evidence) != 1 || challenge.Evidence[0] != "adr:docs/decisions/0016-radius-udp-security-retransmission-and-scope.md" {
		t.Fatalf("R65-ACCESS-004 evidence %#v", challenge.Evidence)
	}
}

func TestInvalidRADIUSPrefixRejected(t *testing.T) {
	t.Parallel()
	doc := &ConformanceRegistry{
		SchemaVersion: 1,
		RFC:           "3579",
		Rows: []ConformanceRow{{
			ID:          "R3579-MA-001",
			Section:     "ma",
			Level:       "MUST",
			Requirement: "invented prefix",
			Status:      StatusNotStarted,
		}},
	}
	rep := &Report{}
	validateConformance(rep, RFC3579Path, "3579", doc)
	if !containsIssue(rep, "id must match R79-* form") {
		t.Fatalf("issues %#v", rep.Issues)
	}
}

func TestConformanceIDRegex(t *testing.T) {
	t.Parallel()
	markdown := []byte("see T89-H-001 and R65-PKT-001 R79-MA-001 R80-DUP-001 PRJ-SEC-001 but not R3579-MA-001 or R5080-IMP-001")
	got := ExtractConformanceIDs(markdown)
	want := []string{"T89-H-001", "R65-PKT-001", "R79-MA-001", "R80-DUP-001", "PRJ-SEC-001"}
	if len(got) != len(want) {
		t.Fatalf("ids %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids %#v, want %#v", got, want)
		}
	}
}

func TestEvidenceTestSymbol(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"internal/aaa.TestInvalidServiceFails", "TestInvalidServiceFails"},
		{"cmd/taclabd.TestVerticalSkeletonE2E", "TestVerticalSkeletonE2E"},
		{"internal/tacacs/codec.FuzzSequence", "FuzzSequence"},
		{"internal/tacacs/codec.BenchmarkHeaderDecode", "BenchmarkHeaderDecode"},
		{"internal/tacacs/testclient/codec (independent encode/decode)", ""},
		{"tools/labgen generates >=32-char unique secrets", ""},
		{"testdata/protocol/bodies/", ""},
		{"internal/tacacs/testclient + cmd/taclabd.TestRemainingAuthFlowsE2E", "TestRemainingAuthFlowsE2E"},
	}
	for _, tc := range cases {
		if got := evidenceTestSymbol(tc.in); got != tc.want {
			t.Errorf("evidenceTestSymbol(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestCheckEvidenceRejectsUnknownPrefixAndSymbol(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	symbols, err := collectTestSymbols(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := symbols["TestInvalidServiceFails"]; !ok {
		t.Fatal("expected to index TestInvalidServiceFails")
	}
	rep := &Report{}
	checkOneEvidence(rep, root, RFC8907Path, "T89-AS-011", "note:not-a-prefix", symbols)
	if !containsIssue(rep, "known prefix") {
		t.Fatalf("prefix: %#v", rep.Issues)
	}
	rep = &Report{}
	checkOneEvidence(rep, root, RFC8907Path, "T89-AS-011", "unit:internal/aaa.TestDoesNotExistAnywhere", symbols)
	if !containsIssue(rep, "unknown test symbol") {
		t.Fatalf("symbol: %#v", rep.Issues)
	}
	rep = &Report{}
	checkOneEvidence(rep, root, RFC8907Path, "T89-AS-011", "unit:internal/aaa.TestInvalidServiceFails", symbols)
	if !rep.Valid() {
		t.Fatalf("valid unit: %#v", rep.Issues)
	}
	rep = &Report{}
	checkOneEvidence(rep, root, RFC8907Path, "T98-CERT-010", "adr:docs/decisions/does-not-exist.md", symbols)
	if !containsIssue(rep, "path") {
		t.Fatalf("missing adr: %#v", rep.Issues)
	}
}
