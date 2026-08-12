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
	if got := len(rep.Operations.Operations); got < 29 {
		t.Fatalf("operations: got %d, want at least the API_PARITY matrix", got)
	}
	if got := len(rep.RFC8907.Rows); got != 168 {
		t.Fatalf("RFC 8907 rows: got %d, want 168", got)
	}
	if got := len(rep.RFC9887.Rows); got != 51 {
		t.Fatalf("RFC 9887 rows: got %d, want 51", got)
	}
}

func TestConformanceIDsUniqueAndRequired(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, ConformanceDocPath))
	if err != nil {
		t.Fatal(err)
	}
	want := ExtractConformanceIDs(doc)
	if len(want) != 219 {
		t.Fatalf("contract IDs: got %d, want 219", len(want))
	}
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]struct{}{}
	for _, table := range []*ConformanceRegistry{rep.RFC8907, rep.RFC9887} {
		for _, row := range table.Rows {
			if _, ok := seen[row.ID]; ok {
				t.Errorf("duplicate id %s", row.ID)
			}
			seen[row.ID] = struct{}{}
			if row.Level == "" || row.Requirement == "" || row.Status != StatusNotStarted {
				t.Errorf("%s: level/requirement/status not in the empty NOT_STARTED form", row.ID)
			}
			if len(row.Evidence) != 0 {
				t.Errorf("%s: evidence must start empty", row.ID)
			}
		}
	}
	for _, id := range want {
		if _, ok := seen[id]; !ok {
			t.Errorf("missing contract id %s", id)
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
	root := testRoot(t)
	rep, err := ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	issues := CheckReleaseStatuses(rep.RFC8907, rep.RFC9887)
	if len(issues) == 0 {
		t.Fatal("expected release validation to fail while rows are NOT_STARTED")
	}
	found := false
	for _, issue := range issues {
		if issue.ID == "T89-H-003" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected T89-H-003 in release issues, first=%s", issues[0])
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
	if err := GenerateDocs(out, rep.Operations, rep.RFC8907, rep.RFC9887); err != nil {
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
	for _, needle := range []string{"T89-H-001", "T98-TLS-001", StatusNotStarted} {
		if !strings.Contains(string(conf), needle) {
			t.Errorf("conformance.md missing %q", needle)
		}
	}
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
