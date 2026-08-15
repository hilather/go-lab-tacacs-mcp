package udp

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExternalRadclientAccessAndAccounting is the Q-010 FreeRADIUS peer.
// A skip is not RADIUS PASS. The required software peer is the in-tree
// testclient (TestIndependentTestclientPAPAndAccountingOnUDP).
func TestExternalRadclientAccessAndAccounting(t *testing.T) {
	bin, err := exec.LookPath("radclient")
	if err != nil {
		t.Skip("radclient not on PATH; FreeRADIUS 3.2.5+ radclient is the required external peer (PAP/CHAP/acct with Message-Authenticator, validate response MA). Skip is not RADIUS PASS. See docs/INTEROP.md")
	}

	secret := []byte(labSecret)
	access, _ := startAccessPolicy(t)
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, radiusYAML(sec, "127.0.0.0/8", "127.0.0.1:0"))
	acct, _, ring := startAccounting(t, doc)

	papFile := filepath.Join(dir, "pap.txt")
	if err := os.WriteFile(papFile, []byte("User-Name = lab-admin\nUser-Password = "+accessTestPassword+"\nMessage-Authenticator = 0x00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runRadclient(t, bin, papFile, access.Addr().String(), "auth", string(secret))
	if err != nil {
		t.Fatalf("radclient auth: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Access-Accept") {
		t.Fatalf("expected Access-Accept:\n%s", out)
	}

	acctFile := filepath.Join(dir, "acct.txt")
	if err := os.WriteFile(acctFile, []byte("Acct-Status-Type = Start\nAcct-Session-Id = radclient-1\nUser-Name = lab-admin\nMessage-Authenticator = 0x00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runRadclient(t, bin, acctFile, acct.Addr().String(), "acct", string(secret))
	if err != nil {
		t.Fatalf("radclient acct: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Accounting-Response") && !strings.Contains(out, "Received response") {
		t.Fatalf("expected Accounting-Response:\n%s", out)
	}
	if ring.Len() != 1 {
		t.Fatalf("recorded=%d\n%s", ring.Len(), out)
	}
}

func runRadclient(t *testing.T, bin, input, addr, kind, secret string) (string, error) {
	t.Helper()
	ctx := t.Context()
	cmd := exec.CommandContext(ctx, bin, "-t", "2", "-r", "1", "-f", input, addr, kind, secret)
	cmd.Env = append(os.Environ(), "LANG=C")
	done := time.AfterFunc(5*time.Second, func() { _ = cmd.Process.Kill() })
	defer done.Stop()
	raw, err := cmd.CombinedOutput()
	return string(raw), err
}
