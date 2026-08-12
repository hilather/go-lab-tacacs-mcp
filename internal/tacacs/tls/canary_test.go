package tls

import (
	"os"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestHandshakeErrorsOmitPrivateKey(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	yaml := labYAML(pki, "127.0.0.1:0", "", "")
	yaml = strings.Replace(yaml, pki.ServerKey, pki.ServerChain, 1)
	doc, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }
	_, err = Listen(Options{
		Bind:     "127.0.0.1:0",
		Settings: doc.Listeners.SecureTACACS,
		Snapshot: func() *state.Snapshot { return nil },
		Secrets:  lookup,
	})
	if err == nil {
		t.Fatal("expected key load error")
	}
	if strings.Contains(err.Error(), "-----BEGIN") {
		t.Fatalf("error leaked key material: %v", err)
	}
}
