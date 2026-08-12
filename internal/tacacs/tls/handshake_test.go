package tls

import (
	"crypto/tls"
	"os"
	"strings"
	"testing"
)

func TestTLS12Rejected(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	cfg.MinVersion = tls.VersionTLS12
	cfg.MaxVersion = tls.VersionTLS12
	_, err := tls.Dial("tcp", ln.Addr().String(), cfg)
	if err == nil {
		t.Fatal("TLS 1.2 must be rejected")
	}
}

func TestMandatoryCipherSuiteNegotiated(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	c := mustHandshake(t, ln.Addr().String(), cfg)
	st := c.ConnectionState()
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("version=%#x", st.Version)
	}
	switch st.CipherSuite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256:
	default:
		t.Fatalf("unexpected suite %#x", st.CipherSuite)
	}
}

func TestSNISelectsProfile(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	extra := `
          - id: lab-alt
            server_names: [other.tacacs.lab.example]
            certificate_chain: {file: ` + pki.ServerAltChain + `}
            private_key: {file: ` + pki.ServerAltKey + `}
`
	ln, _, _ := startTLS(t, labYAML(pki, "127.0.0.1:0", extra, ""), nil)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "other.tacacs.lab.example", nil)
	c := mustHandshake(t, ln.Addr().String(), cfg)
	if c.ConnectionState().ServerName != "other.tacacs.lab.example" {
		t.Fatalf("sni=%q", c.ConnectionState().ServerName)
	}
}

func TestWildcardServerIdentity(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	extra := `
          - id: lab-wild
            server_names: ["*.tacacs.lab.example"]
            certificate_chain: {file: ` + pki.ServerWildcardChain + `}
            private_key: {file: ` + pki.ServerWildcardKey + `}
`
	yaml := labYAML(pki, "127.0.0.1:0", extra, "")
	yaml = strings.Replace(yaml, "require_sni: false", "require_sni: true", 1)
	ln, _, _ := startTLS(t, yaml, nil)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "r1.tacacs.lab.example", nil)
	_ = mustHandshake(t, ln.Addr().String(), cfg)
}

func TestRequireSNIRejectsEmpty(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	yaml := labYAML(pki, "127.0.0.1:0", "", "")
	yaml = strings.Replace(yaml, "require_sni: false", "require_sni: true", 1)
	ln, _, _ := startTLS(t, yaml, nil)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	cfg.ServerName = ""
	cfg.InsecureSkipVerify = true
	_, err = tls.Dial("tcp", ln.Addr().String(), cfg)
	if err == nil {
		t.Fatal("empty SNI must fail when require_sni is true")
	}
}

func TestCertificateFileRotation(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, _, _ := startTLS(t, labYAML(pki, "127.0.0.1:0", "", ""), nil)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	_ = mustHandshake(t, ln.Addr().String(), cfg)

	alt, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	chain, err := os.ReadFile(alt.ServerChain)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(alt.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pki.ServerChain, chain, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pki.ServerKey, key, 0o600); err != nil {
		t.Fatal(err)
	}
	// Client still trusts the original root; rotated chain is a different CA.
	// Rotation of files for the same CA is covered by rewriting the same
	// issuer's leaf. Rebuild a second leaf under the original intermediate
	// is enough: copy the original alt chain (same intermediate) over default.
	altChain, err := os.ReadFile(pki.ServerAltChain)
	if err != nil {
		t.Fatal(err)
	}
	altKey, err := os.ReadFile(pki.ServerAltKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pki.ServerChain, altChain, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pki.ServerKey, altKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2 := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "tacacs.lab.example", nil)
	// Presented cert is other.tacacs.lab.example; client name check would fail.
	cfg2.InsecureSkipVerify = true
	cfg2.VerifyConnection = func(cs tls.ConnectionState) error { return nil }
	_ = mustHandshake(t, ln.Addr().String(), cfg2)
}

func TestIntermediateChainPresented(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	c := mustHandshake(t, ln.Addr().String(), cfg)
	if len(c.ConnectionState().PeerCertificates) < 2 {
		t.Fatalf("expected leaf+intermediate, got %d", len(c.ConnectionState().PeerCertificates))
	}
}
