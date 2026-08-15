// Command labtest runs LAB-* container acceptance against a live taclabd.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("labtest", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	httpBase := fs.String("http", envOr("TACLAB_HTTP", "http://127.0.0.1:8080"), "admin HTTP base URL")
	legacy := fs.String("legacy", envOr("TACLAB_LEGACY", "127.0.0.1:4949"), "legacy TACACS host:port")
	tlsAddr := fs.String("tls", envOr("TACLAB_TLS", "127.0.0.1:4300"), "secure TACACS host:port")
	radiusAccess := fs.String("radius-access", envOr("TACLAB_RADIUS_ACCESS", "127.0.0.1:1812"), "RADIUS access host:port")
	radiusAcct := fs.String("radius-acct", envOr("TACLAB_RADIUS_ACCT", "127.0.0.1:1813"), "RADIUS accounting host:port")
	tokenFile := fs.String("token-file", envOr("TACLAB_TOKEN_FILE", ""), "bootstrap bearer file")
	secretFile := fs.String("secret-file", envOr("TACLAB_SHARED_SECRET_FILE", ""), "legacy shared-secret file")
	radiusSecretFile := fs.String("radius-secret-file", envOr("TACLAB_RADIUS_SECRET_FILE", ""), "RADIUS shared-secret file")
	pkiDir := fs.String("pki", envOr("TACLAB_PKI", ""), "GenerateLabPKI directory")
	pwFile := fs.String("passwords", envOr("TACLAB_PASSWORDS", ""), "labgen PASSWORDS.txt")
	writeTO := fs.Duration("write-timeout", 2*time.Second, "configured listeners.http.write_timeout")
	reportPath := fs.String("report", envOr("TACLAB_REPORT", "lab-test-report.json"), "machine-readable report")
	phase := fs.String("phase", "all", "all | after-restart")
	serverName := fs.String("server-name", "tacacs.lab.example", "TLS server DNS-ID")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := harness{
		HTTP:         strings.TrimRight(*httpBase, "/"),
		Legacy:       *legacy,
		TLS:          *tlsAddr,
		RadiusAccess: *radiusAccess,
		RadiusAcct:   *radiusAcct,
		PKI:          *pkiDir,
		WriteTO:      *writeTO,
		Phase:        *phase,
		ServerName:   *serverName,
		Started:      time.Now().UTC(),
	}
	var err error
	if *tokenFile != "" {
		cfg.Token, err = readTrim(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "labtest: token: %v\n", err)
			return 2
		}
		cfg.canaries = append(cfg.canaries, cfg.Token)
	}
	if *secretFile != "" {
		cfg.Secret, err = os.ReadFile(*secretFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "labtest: secret: %v\n", err)
			return 2
		}
		cfg.Secret = trimNL(cfg.Secret)
		cfg.canaries = append(cfg.canaries, string(cfg.Secret))
	}
	if *radiusSecretFile != "" {
		cfg.RadiusSecret, err = os.ReadFile(*radiusSecretFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "labtest: radius secret: %v\n", err)
			return 2
		}
		cfg.RadiusSecret = trimNL(cfg.RadiusSecret)
		cfg.canaries = append(cfg.canaries, string(cfg.RadiusSecret))
	}
	if *pwFile != "" {
		cfg.Passwords, err = parsePasswords(*pwFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "labtest: passwords: %v\n", err)
			return 2
		}
		for _, v := range cfg.Passwords {
			cfg.canaries = append(cfg.canaries, v)
		}
	}
	if cfg.PKI != "" {
		if key, err := os.ReadFile(filepath.Join(cfg.PKI, "server.key")); err == nil {
			cfg.canaries = append(cfg.canaries, string(trimNL(key)))
		}
	}

	var scenarios []scenario
	switch cfg.Phase {
	case "after-restart":
		scenarios = []scenario{{ID: "LAB-STATE-001", Fn: cfg.labStateRestart}}
	case "mutate":
		scenarios = []scenario{{ID: "LAB-STATE-001-SETUP", Fn: cfg.labAPICreate}}
	case "tls-only":
		scenarios = []scenario{{ID: "LAB-TLS-ONLY", Fn: cfg.labTLSOnlyProfile}}
	case "combined":
		scenarios = combinedScenarios(&cfg)
	case "radius-only":
		scenarios = radiusOnlyScenarios(&cfg)
	default:
		scenarios = defaultScenarios(&cfg)
	}

	rep := Report{
		StartedAt: cfg.Started,
		Phase:     cfg.Phase,
		HTTP:      cfg.HTTP,
		Legacy:    cfg.Legacy,
		TLS:       cfg.TLS,
	}
	ok := true
	for _, sc := range scenarios {
		start := time.Now()
		err := sc.Fn()
		item := ScenarioResult{ID: sc.ID, DurationMS: time.Since(start).Milliseconds()}
		if err != nil {
			ok = false
			item.OK = false
			item.Error = err.Error()
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", sc.ID, err)
		} else {
			item.OK = true
			fmt.Fprintf(os.Stderr, "PASS %s\n", sc.ID)
		}
		rep.Scenarios = append(rep.Scenarios, item)
	}
	rep.SourceIP = cfg.sourceNote
	rep.OK = ok
	rep.FinishedAt = time.Now().UTC()

	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "labtest: report: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(*reportPath), 0o755); err != nil && filepath.Dir(*reportPath) != "." {
		fmt.Fprintf(os.Stderr, "labtest: report dir: %v\n", err)
	}
	if err := os.WriteFile(*reportPath, append(body, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "labtest: write report: %v\n", err)
		return 1
	}
	if !ok {
		return 1
	}
	return 0
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(trimNL(b)), nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func parsePasswords(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = v
	}
	return out, nil
}

func loadTLSMaterial(pki string) (tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(pki, "client-ok.pem"), filepath.Join(pki, "client-ok.key"))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pem, err := os.ReadFile(filepath.Join(pki, "server-ca.pem"))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return tls.Certificate{}, nil, fmt.Errorf("no server CA in %s", filepath.Join(pki, "server-ca.pem"))
	}
	return cert, roots, nil
}

func waitTCP(addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	return last
}
