package rest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

type keyedResult struct {
	Status   int
	Code     string
	Revision uint64
	Data     json.RawMessage
	Raw      string
}

func decodeKeyed(t *testing.T, status int, raw []byte) keyedResult {
	t.Helper()
	out := keyedResult{Status: status, Raw: string(raw)}
	if status == http.StatusOK {
		var env struct {
			Revision uint64          `json:"revision"`
			Data     json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode envelope: %v %s", err, raw)
		}
		out.Revision, out.Data = env.Revision, env.Data
		return out
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(raw, &problem); err != nil {
		t.Fatalf("decode problem: %v %s", err, raw)
	}
	out.Code = problem.Code
	return out
}

func createUserBody(t *testing.T, id string) []byte {
	t.Helper()
	disabled := false
	body, err := json.Marshal(operations.CreateUserRequest{ID: id, Enabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// postUserSocket sends POST /api/v1/users through a real HTTP connection.
func postUserSocket(t *testing.T, h *harness, id, key string) keyedResult {
	t.Helper()
	resp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/users", h.Token, createUserBody(t, id), map[string]string{headerIdempotency: key})
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return decodeKeyed(t, resp.StatusCode, raw)
}

// postUserAdapter drives the REST handler directly with the header value set
// verbatim, bypassing HTTP wire parsing, to pin what the adapter itself does.
func postUserAdapter(t *testing.T, h *harness, id, key string) keyedResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(createUserBody(t, id)))
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header[headerIdempotency] = []string{key}
	rec := httptest.NewRecorder()
	h.Server.Handler().ServeHTTP(rec, req)
	return decodeKeyed(t, rec.Code, rec.Body.Bytes())
}

// postUserRaw writes a hand-built HTTP/1.1 request so the exact header line
// bytes (including trailing whitespace) reach the server's parser.
func postUserRaw(t *testing.T, h *harness, id, keyLine string) keyedResult {
	t.Helper()
	body := createUserBody(t, id)
	conn, err := net.DialTimeout("tcp", h.HTTP.Listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var b strings.Builder
	fmt.Fprintf(&b, "POST /api/v1/users HTTP/1.1\r\nHost: taclab.test\r\n")
	fmt.Fprintf(&b, "Authorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n", h.Token, len(body))
	fmt.Fprintf(&b, "Idempotency-Key: %s\r\nConnection: close\r\n\r\n", keyLine)
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return decodeKeyed(t, resp.StatusCode, raw)
}

func requireCreated(t *testing.T, label string, r keyedResult) {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("%s: status=%d %s", label, r.Status, r.Raw)
	}
}

func requireReplay(t *testing.T, label string, first, second keyedResult) {
	t.Helper()
	if second.Status != http.StatusOK || second.Revision != first.Revision || !bytes.Equal(second.Data, first.Data) {
		t.Fatalf("%s: want replay of first=%s got status=%d %s", label, first.Raw, second.Status, second.Raw)
	}
}

// requireDistinct asserts the second request re-executed the create (so the
// key was not treated as the first key): the user already exists, the error is
// not an idempotency conflict, and no further mutation happened.
func requireDistinct(t *testing.T, label string, h *harness, before uint64, second keyedResult) {
	t.Helper()
	if second.Status != http.StatusConflict || second.Code != string(domain.CodeAlreadyExists) {
		t.Fatalf("%s: want 409 %s (re-executed, not replayed) got status=%d %s", label, domain.CodeAlreadyExists, second.Status, second.Raw)
	}
	if got := uint64(h.Mgr.Revision()); got != before {
		t.Fatalf("%s: revision moved %d -> %d", label, before, got)
	}
}

func TestRESTIdempotencyKeyExactReplay(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	start := uint64(h.Mgr.Revision())
	first := postUserSocket(t, h, "idem-exact", "create-1")
	requireCreated(t, "first", first)
	second := postUserSocket(t, h, "idem-exact", "create-1")
	requireReplay(t, "exact key", first, second)
	if got := uint64(h.Mgr.Revision()); got != start+1 {
		t.Fatalf("revision=%d want %d (retry repeated mutation)", got, start+1)
	}
}

func TestRESTIdempotencyKeyTrailingSpaceIsDistinctAtAdapter(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	first := postUserAdapter(t, h, "idem-space", "create-1")
	requireCreated(t, "first", first)
	before := uint64(h.Mgr.Revision())
	requireDistinct(t, "create-1 vs \"create-1 \"", h, before, postUserAdapter(t, h, "idem-space", "create-1 "))
	requireReplay(t, "exact key after distinct", first, postUserAdapter(t, h, "idem-space", "create-1"))
}

func TestRESTIdempotencyKeyUnicodeWhitespaceIsDistinctOverHTTP(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	first := postUserSocket(t, h, "idem-nbsp", "create-1")
	requireCreated(t, "first", first)
	before := uint64(h.Mgr.Revision())
	requireDistinct(t, "create-1 vs create-1+U+00A0", h, before, postUserSocket(t, h, "idem-nbsp", "create-1\u00a0"))
	requireDistinct(t, "create-1 vs U+3000+create-1", h, before, postUserSocket(t, h, "idem-nbsp", "\u3000create-1"))
}

func TestRESTIdempotencyKeyOpaqueBytesOverHTTP(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	ff, fe := string([]byte{0xff}), string([]byte{0xfe})
	first := postUserSocket(t, h, "idem-opaque", ff)
	requireCreated(t, "first", first)
	requireReplay(t, "0xff replay", first, postUserSocket(t, h, "idem-opaque", ff))
	before := uint64(h.Mgr.Revision())
	requireDistinct(t, "0xff vs 0xfe", h, before, postUserSocket(t, h, "idem-opaque", fe))
}

// HTTP field parsing removes leading/trailing SP/HTAB (RFC 9110 §5.5) before
// the adapter runs, so such whitespace on the wire is not part of the key. This
// pins net/http behavior the ADR 0033 wording relies on.
func TestRESTIdempotencyKeyWireOWSIsNotPartOfKey(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	first := postUserRaw(t, h, "idem-ows", "create-1")
	requireCreated(t, "first", first)
	for _, line := range []string{"create-1 ", "create-1\t", " create-1"} {
		requireReplay(t, fmt.Sprintf("wire %q", line), first, postUserRaw(t, h, "idem-ows", line))
	}
}
