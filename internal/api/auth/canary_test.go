package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestAuthCanaries(t *testing.T) {
	t.Parallel()
	const tokenCanary = "unit-test-auth-bearer-canary-zz99"
	m, value, clock := mustTokenMgr(t, []string{"state:read"}, nil)
	svc := New(Options{Clock: clock})
	snap := m.Snapshot()

	_, verr := svc.VerifyBearer([]byte(tokenCanary), snap)
	if verr == nil {
		t.Fatal("canary must not authenticate")
	}
	sess, err := svc.Create(operations.Actor{ID: "rt", Scopes: []string{"state:read"}}, snap)
	if err != nil {
		t.Fatal(err)
	}
	cookie := string(sess.Cookie.Bytes())
	_, cerr := svc.VerifyCookie("not-the-cookie", "", true, snap)

	dumps := []string{
		fmt.Sprintf("%v %#v %s", verr, verr, verr.Error()),
		fmt.Sprintf("%v", cerr),
		fmt.Sprintf("%+v", sess),
	}
	raw, err := json.Marshal(sess)
	if err != nil {
		t.Fatal(err)
	}
	dumps = append(dumps, string(raw))
	for _, d := range dumps {
		if strings.Contains(d, tokenCanary) || strings.Contains(d, cookie) || strings.Contains(d, value) {
			t.Fatalf("secret leaked: %q", d)
		}
	}
	if !strings.Contains(string(raw), sess.CSRFToken) {
		t.Fatal("CSRF missing from create JSON")
	}

	// Digest of the presented canary must not appear in errors.
	sum := fmt.Sprintf("%x", credentials.DigestToken(credentials.NewTokenMaterial([]byte(tokenCanary))).Bytes())
	if strings.Contains(verr.Error(), sum) {
		t.Fatal("digest leaked")
	}
	if de, ok := domain.AsError(verr); ok && de.Message == "" {
		t.Fatal("empty message")
	}
}
