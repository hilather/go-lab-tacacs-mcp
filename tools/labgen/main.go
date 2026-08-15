// Command labgen materializes an ephemeral TacLab directory: PKI, secrets,
// and compose-oriented YAML. Secret values are never printed.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	tacacstls "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/tls"
)

const (
	sharedSecretBytes = 40
	passwordBytes     = 18
)

// Options control Generate. Tests inject cheap Argon2 params and entropy.
type Options struct {
	Dir          string
	Force        bool
	InstanceID   string
	WriteTimeout string
	IdleTimeout  string
	Params       credentials.Argon2Params
	Now          time.Time
	Entropy      io.Reader
	Stdout       io.Writer
	Stderr       io.Writer
}

// Manifest is the non-secret description of a generated lab directory.
type Manifest struct {
	GeneratedAt             time.Time `json:"generated_at"`
	InstanceID              string    `json:"instance_id"`
	SharedSecretLength      int       `json:"shared_secret_length"`
	SharedSecretLastRotated time.Time `json:"shared_secret_last_rotated_at"`
	RotationInterval        string    `json:"rotation_interval"`
	TokenEncoding           string    `json:"token_encoding"`
	PKI                     string    `json:"pki"`
	HTTPWriteTimeout        string    `json:"http_write_timeout"`
	PasswordsFile           string    `json:"passwords_file"`
	FileWatchReload         bool      `json:"file_watch_reload"`
	SourceCIDRs             []string  `json:"source_cidrs"`
	SourceIPNote            string    `json:"source_ip_note"`
	SecureClientDNS         string    `json:"secure_client_dns"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("labgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	force := fs.Bool("force", false, "overwrite an existing lab directory")
	instance := fs.String("instance-id", "taclab-01", "server.instance_id")
	writeTO := fs.String("http-write-timeout", "30s", "listeners.http.write_timeout")
	idleTO := fs.String("http-idle-timeout", "60s", "listeners.http.idle_timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir := "deployments/compose"
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	res, err := Generate(Options{
		Dir:          dir,
		Force:        *force,
		InstanceID:   *instance,
		WriteTimeout: *writeTO,
		IdleTimeout:  *idleTO,
		Stdout:       stdout,
		Stderr:       stderr,
	})
	if err != nil {
		fmt.Fprintf(stderr, "labgen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote lab directory %s\n", res.Dir)
	fmt.Fprintf(stdout, "  config:      %s\n", filepath.Join(res.Dir, "config", "taclab.yaml"))
	fmt.Fprintf(stdout, "  tls-only:    %s\n", filepath.Join(res.Dir, "config", "taclab.tls-only.yaml"))
	fmt.Fprintf(stdout, "  combined:    %s\n", filepath.Join(res.Dir, "config", "taclab.combined.yaml"))
	fmt.Fprintf(stdout, "  radius-only: %s\n", filepath.Join(res.Dir, "config", "taclab.radius-only.yaml"))
	fmt.Fprintf(stdout, "  secrets:     %s\n", filepath.Join(res.Dir, "secrets"))
	fmt.Fprintf(stdout, "  certs:       %s\n", filepath.Join(res.Dir, "certs-public"))
	fmt.Fprintf(stdout, "  manifest:    %s\n", filepath.Join(res.Dir, "manifest.json"))
	fmt.Fprintf(stdout, "plaintext passwords: %s (not logged)\n", filepath.Join(res.Dir, "secrets", "PASSWORDS.txt"))
	return 0
}

// Result is the generated tree. Secret material is not included.
type Result struct {
	Dir      string
	Manifest Manifest
}

// Generate writes a complete lab directory.
func Generate(opts Options) (*Result, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("directory is required")
	}
	if opts.Entropy == nil {
		opts.Entropy = rand.Reader
	}
	if opts.Params == (credentials.Argon2Params{}) {
		opts.Params = credentials.DefaultParams
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.InstanceID == "" {
		opts.InstanceID = "taclab-01"
	}
	if opts.WriteTimeout == "" {
		opts.WriteTimeout = "30s"
	}
	if opts.IdleTimeout == "" {
		opts.IdleTimeout = "60s"
	}
	dir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, err
	}
	if err := prepareDir(dir, opts.Force); err != nil {
		return nil, err
	}

	pkiDir := filepath.Join(dir, "pki")
	pki, err := tacacstls.GenerateLabPKI(pkiDir)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}

	secretsDir := filepath.Join(dir, "secrets")
	certsDir := filepath.Join(dir, "certs-public")
	cfgDir := filepath.Join(dir, "config")
	evDir := filepath.Join(dir, "evidence")
	for _, d := range []string{secretsDir, certsDir, cfgDir, evDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}

	token, digest, err := credentials.IssueBearer(opts.Entropy)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	digest.Wipe()
	shared, err := randomSharedSecret(opts.Entropy, sharedSecretBytes)
	if err != nil {
		return nil, fmt.Errorf("shared secret: %w", err)
	}
	radiusShared, err := distinctSharedSecret(opts.Entropy, shared, sharedSecretBytes)
	if err != nil {
		return nil, fmt.Errorf("radius shared secret: %w", err)
	}
	adminPW, err := randomPassword(opts.Entropy, "Adm")
	if err != nil {
		return nil, err
	}
	enablePW, err := randomPassword(opts.Entropy, "En")
	if err != nil {
		return nil, err
	}
	roPW, err := randomPassword(opts.Entropy, "Ro")
	if err != nil {
		return nil, err
	}
	disPW, err := randomPassword(opts.Entropy, "Dis")
	if err != nil {
		return nil, err
	}
	chal, err := randomPassword(opts.Entropy, "Ch")
	if err != nil {
		return nil, err
	}

	adminPHC, err := credentials.DeriveArgon2id([]byte(adminPW), opts.Params, opts.Entropy)
	if err != nil {
		return nil, fmt.Errorf("admin verifier: %w", err)
	}
	enablePHC, err := credentials.DeriveArgon2id([]byte(enablePW), opts.Params, opts.Entropy)
	if err != nil {
		return nil, fmt.Errorf("enable verifier: %w", err)
	}
	roPHC, err := credentials.DeriveArgon2id([]byte(roPW), opts.Params, opts.Entropy)
	if err != nil {
		return nil, fmt.Errorf("readonly verifier: %w", err)
	}
	disPHC, err := credentials.DeriveArgon2id([]byte(disPW), opts.Params, opts.Entropy)
	if err != nil {
		return nil, fmt.Errorf("disabled verifier: %w", err)
	}

	// Compose file secrets keep host mode and are read as UID 10001. 0444 is
	// not world-writable (strict_secret_files) and matches Docker secret mounts.
	const secretMode os.FileMode = 0o444
	writes := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{filepath.Join(secretsDir, "api_admin_token"), []byte(token), secretMode},
		{filepath.Join(secretsDir, "lab_switches_tacacs_secret"), shared, secretMode},
		{filepath.Join(secretsDir, "lab_switches_radius_secret"), radiusShared, secretMode},
		{filepath.Join(secretsDir, "lab_admin_argon2id"), adminPHC, secretMode},
		{filepath.Join(secretsDir, "lab_admin_enable_argon2id"), enablePHC, secretMode},
		{filepath.Join(secretsDir, "lab_readonly_argon2id"), roPHC, secretMode},
		{filepath.Join(secretsDir, "lab_disabled_argon2id"), disPHC, secretMode},
		{filepath.Join(secretsDir, "lab_admin_challenge_secret"), []byte(chal), secretMode},
	}
	for _, w := range writes {
		if err := os.WriteFile(w.path, w.data, w.mode); err != nil {
			return nil, err
		}
		_ = os.Chmod(w.path, w.mode)
	}

	serverKey, err := os.ReadFile(pki.ServerKey)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(secretsDir, "tacacs_server_key.pem"), serverKey, secretMode); err != nil {
		return nil, err
	}
	_ = os.Chmod(filepath.Join(secretsDir, "tacacs_server_key.pem"), secretMode)

	pwPath := filepath.Join(secretsDir, "PASSWORDS.txt")
	pwBody := strings.Join([]string{
		"# Lab-only plaintext. Mode 0600. Do not commit. labgen never logs these values.",
		"lab-admin=" + adminPW,
		"lab-admin-enable=" + enablePW,
		"lab-readonly=" + roPW,
		"lab-disabled=" + disPW,
		"lab-admin-challenge=" + chal,
		"",
	}, "\n")
	if err := os.WriteFile(pwPath, []byte(pwBody), 0o600); err != nil {
		return nil, err
	}
	_ = os.Chmod(pwPath, 0o600)

	publicCopies := []struct{ src, dest string }{
		{pki.ServerChain, "server-chain.pem"},
		{pki.ServerCACert, "server-ca.pem"},
		{pki.ClientCACert, "client-ca.pem"},
		{pki.CRLEmpty, "client-crl.pem"},
		{pki.CRLRevoked, "client-crl-revoked.pem"},
		{pki.ClientOKCert, "client-ok.pem"},
		{pki.ClientUnauthCert, "client-unauth.pem"},
	}
	for _, c := range publicCopies {
		b, err := os.ReadFile(c.src)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(certsDir, c.dest), b, 0o644); err != nil {
			return nil, err
		}
	}

	rotated := opts.Now.UTC().Truncate(time.Second)
	dual := renderConfig(opts.InstanceID, opts.WriteTimeout, opts.IdleTimeout, rotated, true)
	tlsOnly := renderConfig(opts.InstanceID, opts.WriteTimeout, opts.IdleTimeout, rotated, false)
	combined := renderCombinedConfig(opts.InstanceID, opts.WriteTimeout, opts.IdleTimeout, rotated)
	radiusOnly := renderRadiusOnlyConfig(opts.InstanceID, opts.WriteTimeout, opts.IdleTimeout, rotated)
	writesCfg := []struct {
		name string
		body string
	}{
		{"taclab.yaml", dual},
		{"taclab.tls-only.yaml", tlsOnly},
		{"taclab.combined.yaml", combined},
		{"taclab.radius-only.yaml", radiusOnly},
	}
	for _, w := range writesCfg {
		if err := os.WriteFile(filepath.Join(cfgDir, w.name), []byte(w.body), 0o644); err != nil {
			return nil, err
		}
	}

	man := Manifest{
		GeneratedAt:             rotated,
		InstanceID:              opts.InstanceID,
		SharedSecretLength:      len(shared),
		SharedSecretLastRotated: rotated,
		RotationInterval:        "90d",
		TokenEncoding:           "unpadded-base64url",
		PKI:                     "internal/tacacs/tls.GenerateLabPKI",
		HTTPWriteTimeout:        opts.WriteTimeout,
		PasswordsFile:           "secrets/PASSWORDS.txt",
		FileWatchReload:         false,
		SourceCIDRs:             []string{"0.0.0.0/0", "::/0"},
		SourceIPNote:            "Compose published ports may NAT the TACACS or RADIUS peer. Use host network or macvlan before claiming device-accurate client match (LAB_DEPLOYMENT §4.3). Match key is the TCP/UDP peer, never X-Forwarded-For.",
		SecureClientDNS:         "nas.lab.example",
	}
	mb, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(mb, '\n'), 0o644); err != nil {
		return nil, err
	}

	readme := labREADME()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644); err != nil {
		return nil, err
	}

	if err := validateGenerated(dir); err != nil {
		return nil, fmt.Errorf("generated config is invalid: %w", err)
	}
	return &Result{Dir: dir, Manifest: man}, nil
}

func prepareDir(dir string, force bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	marker := filepath.Join(dir, "manifest.json")
	secrets := filepath.Join(dir, "secrets")
	if !force {
		if _, err := os.Stat(marker); err == nil {
			return fmt.Errorf("%s already exists (pass -force to regenerate)", dir)
		}
		if entries, err := os.ReadDir(secrets); err == nil && len(entries) > 0 {
			return fmt.Errorf("%s is not empty (pass -force to regenerate)", secrets)
		}
	}
	for _, rel := range []string{
		"secrets", "certs-public", "pki",
		"config/taclab.yaml", "config/taclab.tls-only.yaml",
		"config/taclab.combined.yaml", "config/taclab.radius-only.yaml",
		"manifest.json",
	} {
		_ = os.RemoveAll(filepath.Join(dir, rel))
	}
	return nil
}

func validateGenerated(dir string) error {
	for _, name := range []string{"taclab.yaml", "taclab.tls-only.yaml", "taclab.combined.yaml", "taclab.radius-only.yaml"} {
		path := filepath.Join(dir, "config", name)
		doc, err := config.Load(path)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := config.Validate(doc); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func distinctSharedSecret(r io.Reader, other []byte, n int) ([]byte, error) {
	for i := 0; i < 8; i++ {
		next, err := randomSharedSecret(r, n)
		if err != nil {
			return nil, err
		}
		if string(next) != string(other) {
			return next, nil
		}
	}
	return nil, fmt.Errorf("could not generate a distinct RADIUS shared secret")
}

func randomSharedSecret(r io.Reader, n int) ([]byte, error) {
	// Four character classes, length >= 32, not a known-weak value.
	const (
		lower = "abcdefghijkmnopqrstuvwxyz"
		upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		digit = "23456789"
		other = "#%+-=@_"
	)
	classes := []string{lower, upper, digit, other}
	out := make([]byte, n)
	for i, cls := range classes {
		b, err := randByte(r, cls)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	all := lower + upper + digit + other
	for i := len(classes); i < n; i++ {
		b, err := randByte(r, all)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	// Shuffle so the first four bytes are not a predictable class prefix.
	for i := n - 1; i > 0; i-- {
		jbuf := make([]byte, 1)
		if _, err := io.ReadFull(r, jbuf); err != nil {
			return nil, err
		}
		j := int(jbuf[0]) % (i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func randomPassword(r io.Reader, prefix string) (string, error) {
	raw := make([]byte, passwordBytes)
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw) + "!", nil
}

func randByte(r io.Reader, alphabet string) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return alphabet[int(b[0])%len(alphabet)], nil
}

func renderConfig(instance, writeTO, idleTO string, rotated time.Time, dual bool) string {
	legacyEnabled := "true"
	if !dual {
		legacyEnabled = "false"
	}
	return fmt.Sprintf(configTemplate, instance, legacyEnabled, writeTO, idleTO, rotated.Format(time.RFC3339))
}

func renderCombinedConfig(instance, writeTO, idleTO string, rotated time.Time) string {
	return fmt.Sprintf(combinedConfigTemplate, instance, writeTO, idleTO, rotated.Format(time.RFC3339))
}

func renderRadiusOnlyConfig(instance, writeTO, idleTO string, rotated time.Time) string {
	return fmt.Sprintf(radiusOnlyConfigTemplate, instance, writeTO, idleTO, rotated.Format(time.RFC3339))
}

func labREADME() string {
	return `# Generated TacLab directory

Secrets and private keys in ` + "`secrets/`" + ` and ` + "`pki/`" + ` are lab-only.
They are not committed. Regenerate with:

` + "```bash" + `
go run ./tools/labgen -force <this-directory>
` + "```" + `

TACACS-only (host 49 / 300 / 8080; RADIUS ports mapped but disabled in v1 YAML):

` + "```bash" + `
docker compose -f deployments/compose/compose.yaml --project-directory <this-directory> up -d --build
` + "```" + `

Combined TACACS + RADIUS/UDP (host 49 / 300 / 8080 / 1812 / 1813):

` + "```bash" + `
docker compose -f deployments/compose/compose.yaml -f deployments/compose/compose.combined.yaml --project-directory <this-directory> up -d --build
` + "```" + `

RADIUS-only (host 1812 / 1813 / 8080; no 49 / 300):

` + "```bash" + `
docker compose -f deployments/compose/compose.yaml -f deployments/compose/compose.radius-only.yaml --project-directory <this-directory> up -d --build
` + "```" + `

TLS-only TACACS profile (no legacy port 49):

` + "```bash" + `
docker compose -f deployments/compose/compose.yaml -f deployments/compose/compose.tls-only.yaml --project-directory <this-directory> up -d --build
` + "```" + `

RADIUS/UDP is a lab profile, not complete RADIUS. Keep 1812/1813 off the public internet.

Reload is explicit (` + "`SIGHUP`" + ` or ` + "`POST /api/v1/config/reload`" + `). File-watch reload is off.

Source-IP: published ports may NAT the TACACS or RADIUS peer. See
https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md#43-source-address-fidelity
`
}

const configTemplate = `# Generated by tools/labgen. Secrets are file references only.
# Reload is explicit (SIGHUP or config.reload). File-watch reload is off.
# source_cidrs are 0.0.0.0/0 and ::/0 so Compose published-port NAT still
# matches. Device-accurate topologies need host network or macvlan (LAB §4.3).
schema_version: 1

metadata:
  name: compose-lab
  description: Generated dual/TLS-only Compose lab baseline
  labels:
    environment: lab
    owner: labgen

server:
  instance_id: %s
  shutdown_grace: 15s
  startup_failure_mode: fail_closed
  log_level: info

runtime:
  persistence: memory
  allow_shadowing: true
  delete_baseline_behavior: tombstone
  reload_overlay_behavior: rebase
  reset_requires_scope: runtime:reset
  max_objects:
    users: 10000
    groups: 1000
    clients: 2000
    api_tokens: 1000

security:
  allow_environment_secrets: false
  strict_secret_files: true
  legacy_shared_secrets:
    minimum_length_characters: 16
    minimum_character_classes: 3
    reject_known_weak_values: true
    warn_on_reuse: true
    default_rotation_interval: 90d
    rotation_warning_before: 14d

listeners:
  legacy_tacacs:
    enabled: %s
    bind: 0.0.0.0:4949
    advertised_port: 49
    read_timeout: 15s
    write_timeout: 15s
    idle_timeout: 60s
    handshake_timeout: 10s
    max_connections: 4096
    max_sessions_per_connection: 1024
    max_packet_body_bytes: 65536
    single_connect:
      enabled: true
      max_lifetime: 10m
      idle_timeout: 60s

  secure_tacacs:
    enabled: true
    bind: 0.0.0.0:4300
    advertised_port: 300
    read_timeout: 15s
    write_timeout: 15s
    idle_timeout: 60s
    handshake_timeout: 10s
    max_connections: 4096
    max_sessions_per_connection: 1024
    max_packet_body_bytes: 65536
    single_connect:
      enabled: true
      max_lifetime: 10m
      idle_timeout: 60s
    tls:
      minimum_version: TLS1.3
      identities:
        default_id: lab-default
        require_sni: false
        profiles:
          - id: lab-default
            server_names:
              - tacacs.lab.example
            certificate_chain:
              file: /etc/taclab/certs-public/server-chain.pem
            private_key:
              file: /run/secrets/tacacs_server_key
      client_authentication: require_and_verify_certificate
      client_ca_bundle:
        file: /etc/taclab/certs-public/client-ca.pem
      revocation:
        mode: configured_crl
        crl_bundle:
          file: /etc/taclab/certs-public/client-crl.pem
      session_resumption:
        enabled: true
        ticket_lifetime: 168h
        recheck_client_revocation: true
      reject_early_data: true

  http:
    enabled: true
    bind: 0.0.0.0:8080
    read_header_timeout: 5s
    read_timeout: 30s
    write_timeout: %s
    idle_timeout: %s
    max_request_body_bytes: 2097152
    trusted_proxy_cidrs: []
    tls:
      enabled: false

api:
  mode: lab_static_bearer
  ui_session:
    enabled: true
    lifetime: 30m
    idle_timeout: 10m
    cookie_secure: false
    cookie_same_site: strict
  mcp:
    allowed_origins: []
    require_origin: false
  bootstrap_tokens:
    - id: lab-admin
      token:
        file: /run/secrets/api_admin_token
      scopes:
        - state:read
        - state:write
        - config:reload
        - config:export
        - policy:test
        - events:read
        - tokens:manage
        - runtime:reset
      expires_at: null
  rate_limits:
    enabled: true
    per_token_requests_per_second: 50
    per_token_burst: 100
    unauthenticated_requests_per_second: 5
    unauthenticated_burst: 10

limits:
  max_username_bytes: 253
  max_port_bytes: 253
  max_remote_address_bytes: 253
  max_authentication_rounds: 16
  max_authorization_arguments: 256
  max_argument_bytes: 65535
  max_command_bytes: 65535
  max_policy_trace_steps: 1000
  max_event_payload_bytes: 65536

clients:
  - id: lab-switches
    display_name: Lab switches
    priority: 100
    enabled: true
    match:
      mode: address_and_certificate
      source_cidrs:
        - 0.0.0.0/0
        - ::/0
      transports:
        - legacy
    legacy:
      shared_secret:
        file: /run/secrets/lab_switches_tacacs_secret
      shared_secret_lifecycle:
        last_rotated_at: %s
        rotation_interval: 90d
    authentication:
      allowed_methods:
        - ascii
        - pap
        - chap
        - mschapv1
        - mschapv2
        - enable
        - ascii_chpass
      default_service: login
    authorization:
      default_group_ids:
        - readonly
    accounting:
      enabled: true
      accept_start: true
      accept_stop: true
      accept_watchdog: true

  - id: secure-routers
    display_name: TLS lab routers
    priority: 50
    enabled: true
    match:
      mode: address_and_certificate
      source_cidrs:
        - 0.0.0.0/0
        - ::/0
      transports:
        - tls
      certificate:
        dns_sans:
          - nas.lab.example
        ip_sans:
          - 127.0.0.1
    authentication:
      allowed_methods:
        - ascii
        - pap
        - chap
        - mschapv1
        - mschapv2
        - enable
        - ascii_chpass
    authorization:
      default_group_ids:
        - readonly
    accounting:
      enabled: true

groups:
  - id: administrators
    display_name: Full administrators
    priority: 10
    enabled: true
    services:
      - service: shell
        protocol: null
        action: permit
        reply_attributes:
          - name: priv-lvl
            separator: "="
            value: "15"
    command_rules:
      - id: permit-all
        priority: 10
        action: permit
        command:
          pattern: ".*"
        arguments:
          pattern: ".*"
        reason: Full lab administration
    default_command_action: deny

  - id: readonly
    display_name: Read-only operators
    priority: 100
    enabled: true
    services:
      - service: shell
        protocol: null
        action: permit
        reply_attributes:
          - name: priv-lvl
            separator: "="
            value: "1"
    command_rules:
      - id: show
        priority: 10
        action: permit
        command:
          exact: show
        arguments:
          pattern: ".*"
        reason: Permit operational show commands
      - id: ping
        priority: 20
        action: permit
        command:
          exact: ping
        arguments:
          pattern: ".*"
      - id: traceroute
        priority: 30
        action: permit
        command:
          pattern: "^(traceroute|traceroute6)$"
        arguments:
          pattern: ".*"
      - id: deny-everything-else
        priority: 10000
        action: deny
        command:
          pattern: ".*"
        arguments:
          pattern: ".*"
        reason: Default deny
    default_command_action: deny

users:
  - id: lab-admin
    display_name: Lab Administrator
    enabled: true
    group_ids:
      - administrators
    rules:
      services: []
      command_rules: []
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_admin_argon2id
      challenge:
        secret:
          file: /run/secrets/lab_admin_challenge_secret
      enable:
        verifier:
          file: /run/secrets/lab_admin_enable_argon2id
    restrictions:
      client_ids: []
      valid_after: null
      valid_before: null

  - id: lab-readonly
    display_name: Read-only Lab User
    enabled: true
    group_ids:
      - readonly
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_readonly_argon2id
    restrictions:
      client_ids:
        - lab-switches
        - secure-routers

  - id: lab-disabled
    display_name: Disabled Lab User
    enabled: false
    group_ids:
      - readonly
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_disabled_argon2id

fallback_rules:
  services: []
  command_rules: []

events:
  ring_buffer_capacity: 10000
  include_successful_authentication: true
  include_failed_authentication: true
  include_authorization: true
  include_accounting: true
  redact_user_input: true
  stdout:
    enabled: true
    format: json

observability:
  metrics:
    enabled: true
    bind: 127.0.0.1:9090
    path: /metrics
    expose_on_admin: false
  tracing:
    enabled: false
  profiling:
    enabled: false
`

const combinedConfigTemplate = `# Generated by tools/labgen (combined TACACS + RADIUS/UDP). Secrets are file refs.
# RADIUS/UDP is a lab profile, not complete RADIUS. File-watch reload is off.
schema_version: 2

metadata:
  name: compose-lab-combined
  description: Generated combined TACACS and RADIUS Compose lab baseline
  labels:
    environment: lab
    owner: labgen

server:
  instance_id: %s
  shutdown_grace: 15s
  startup_failure_mode: fail_closed
  admin_only: false
  log_level: info

runtime:
  persistence: memory
  allow_shadowing: true
  delete_baseline_behavior: tombstone
  reload_overlay_behavior: rebase
  reset_requires_scope: runtime:reset
  max_objects:
    users: 10000
    groups: 1000
    clients: 2000
    api_tokens: 1000

security:
  allow_environment_secrets: false
  strict_secret_files: true
  legacy_shared_secrets:
    minimum_length_characters: 16
    minimum_character_classes: 3
    reject_known_weak_values: true
    warn_on_reuse: true
    default_rotation_interval: 90d
    rotation_warning_before: 14d
  radius_shared_secrets:
    minimum_length_characters: 16
    minimum_character_classes: 3
    reject_known_weak_values: true
    warn_on_reuse: true
    default_rotation_interval: 90d
    rotation_warning_before: 14d

listeners:
  tacacs:
    legacy:
      enabled: true
      bind: 0.0.0.0:4949
      advertised_port: 49
      read_timeout: 15s
      write_timeout: 15s
      idle_timeout: 60s
      handshake_timeout: 10s
      max_connections: 4096
      max_sessions_per_connection: 1024
      max_packet_body_bytes: 65536
      single_connect:
        enabled: true
        max_lifetime: 10m
        idle_timeout: 60s
    tls:
      enabled: true
      bind: 0.0.0.0:4300
      advertised_port: 300
      read_timeout: 15s
      write_timeout: 15s
      idle_timeout: 60s
      handshake_timeout: 10s
      max_connections: 4096
      max_sessions_per_connection: 1024
      max_packet_body_bytes: 65536
      single_connect:
        enabled: true
        max_lifetime: 10m
        idle_timeout: 60s
      tls:
        minimum_version: TLS1.3
        identities:
          default_id: lab-default
          require_sni: false
          profiles:
            - id: lab-default
              server_names:
                - tacacs.lab.example
              certificate_chain:
                file: /etc/taclab/certs-public/server-chain.pem
              private_key:
                file: /run/secrets/tacacs_server_key
        client_authentication: require_and_verify_certificate
        client_ca_bundle:
          file: /etc/taclab/certs-public/client-ca.pem
        revocation:
          mode: configured_crl
          crl_bundle:
            file: /etc/taclab/certs-public/client-crl.pem
        session_resumption:
          enabled: true
          ticket_lifetime: 168h
          recheck_client_revocation: true
        reject_early_data: true
  radius:
    access:
      enabled: true
      required: true
      bind: 0.0.0.0:1812
      transport: udp
      message_authenticator: required
      limit_proxy_state: true
    accounting:
      enabled: true
      required: false
      bind: 0.0.0.0:1813
      transport: udp
  http:
    enabled: true
    bind: 0.0.0.0:8080
    read_header_timeout: 5s
    read_timeout: 30s
    write_timeout: %s
    idle_timeout: %s
    max_request_body_bytes: 2097152
    trusted_proxy_cidrs: []
    tls:
      enabled: false

api:
  mode: lab_static_bearer
  ui_session:
    enabled: true
    lifetime: 30m
    idle_timeout: 10m
    cookie_secure: false
    cookie_same_site: strict
  mcp:
    allowed_origins: []
    require_origin: false
  bootstrap_tokens:
    - id: lab-admin
      token:
        file: /run/secrets/api_admin_token
      scopes:
        - state:read
        - state:write
        - config:reload
        - config:export
        - policy:test
        - events:read
        - tokens:manage
        - runtime:reset
      expires_at: null
  rate_limits:
    enabled: true
    per_token_requests_per_second: 50
    per_token_burst: 100
    unauthenticated_requests_per_second: 5
    unauthenticated_burst: 10

limits:
  max_username_bytes: 253
  max_port_bytes: 253
  max_remote_address_bytes: 253
  max_authentication_rounds: 16
  max_authorization_arguments: 256
  max_argument_bytes: 65535
  max_command_bytes: 65535
  max_policy_trace_steps: 1000
  max_event_payload_bytes: 65536

clients:
  - id: lab-switches
    display_name: Lab switches
    priority: 100
    enabled: true
    match:
      mode: address_and_certificate
      source_cidrs:
        - 0.0.0.0/0
        - ::/0
    endpoints:
      - id: tacacs-legacy
        protocol: tacacs
        transport: tcp
        roles: [authentication, authorization, accounting]
        tacacs:
          shared_secret:
            file: /run/secrets/lab_switches_tacacs_secret
          shared_secret_lifecycle:
            last_rotated_at: %s
            rotation_interval: 90d
          allowed_methods:
            - ascii
            - pap
            - chap
            - mschapv1
            - mschapv2
            - enable
            - ascii_chpass
          default_service: login
          default_group_ids:
            - readonly
          accounting:
            enabled: true
            accept_start: true
            accept_stop: true
            accept_watchdog: true
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access, accounting]
        radius:
          shared_secret:
            file: /run/secrets/lab_switches_radius_secret
          require_message_authenticator: true
          limit_proxy_state: true
          allowed_authentication_methods: [pap, chap]
          access_policy_id: default-radius-access
          accounting:
            accept_status_types: [start, stop, interim_update, accounting_on, accounting_off]

  - id: secure-routers
    display_name: TLS lab routers
    priority: 50
    enabled: true
    match:
      mode: address_and_certificate
      source_cidrs:
        - 0.0.0.0/0
        - ::/0
      transports:
        - tls
      certificate:
        dns_sans:
          - nas.lab.example
        ip_sans:
          - 127.0.0.1
    authentication:
      allowed_methods:
        - ascii
        - pap
        - chap
        - mschapv1
        - mschapv2
        - enable
        - ascii_chpass
    authorization:
      default_group_ids:
        - readonly
    accounting:
      enabled: true

groups:
  - id: administrators
    display_name: Full administrators
    priority: 10
    enabled: true
    services:
      - service: shell
        protocol: null
        action: permit
        reply_attributes:
          - name: priv-lvl
            separator: "="
            value: "15"
    command_rules:
      - id: permit-all
        priority: 10
        action: permit
        command:
          pattern: ".*"
        arguments:
          pattern: ".*"
        reason: Full lab administration
    default_command_action: deny

  - id: readonly
    display_name: Read-only operators
    priority: 100
    enabled: true
    services:
      - service: shell
        protocol: null
        action: permit
        reply_attributes:
          - name: priv-lvl
            separator: "="
            value: "1"
    command_rules:
      - id: show
        priority: 10
        action: permit
        command:
          exact: show
        arguments:
          pattern: ".*"
        reason: Permit operational show commands
      - id: ping
        priority: 20
        action: permit
        command:
          exact: ping
        arguments:
          pattern: ".*"
      - id: traceroute
        priority: 30
        action: permit
        command:
          pattern: "^(traceroute|traceroute6)$"
        arguments:
          pattern: ".*"
      - id: deny-everything-else
        priority: 10000
        action: deny
        command:
          pattern: ".*"
        arguments:
          pattern: ".*"
        reason: Default deny
    default_command_action: deny

users:
  - id: lab-admin
    display_name: Lab Administrator
    enabled: true
    group_ids:
      - administrators
    rules:
      services: []
      command_rules: []
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_admin_argon2id
      challenge:
        secret:
          file: /run/secrets/lab_admin_challenge_secret
      enable:
        verifier:
          file: /run/secrets/lab_admin_enable_argon2id
    restrictions:
      client_ids: []
      valid_after: null
      valid_before: null

  - id: lab-readonly
    display_name: Read-only Lab User
    enabled: true
    group_ids:
      - readonly
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_readonly_argon2id
    restrictions:
      client_ids:
        - lab-switches
        - secure-routers

  - id: lab-disabled
    display_name: Disabled Lab User
    enabled: false
    group_ids:
      - readonly
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_disabled_argon2id

radius_reply_profiles:
  - id: lab-accept
    attributes:
      - name: Session-Timeout
        value: "600"

radius_policies:
  - id: default-radius-access
    rules:
      - id: permit-administrators
        match:
          groups_any: [administrators]
        effect: permit
        reply_profiles: [lab-accept]
      - id: deny-rest
        effect: deny

fallback_rules:
  services: []
  command_rules: []

events:
  ring_buffer_capacity: 10000
  include_successful_authentication: true
  include_failed_authentication: true
  include_authorization: true
  include_accounting: true
  redact_user_input: true
  stdout:
    enabled: true
    format: json

observability:
  metrics:
    enabled: true
    bind: 127.0.0.1:9090
    path: /metrics
    expose_on_admin: false
  tracing:
    enabled: false
  profiling:
    enabled: false
`

const radiusOnlyConfigTemplate = `# Generated by tools/labgen (RADIUS-only). Secrets are file refs.
# RADIUS/UDP is a lab profile, not complete RADIUS. File-watch reload is off.
schema_version: 2

metadata:
  name: compose-lab-radius-only
  description: Generated RADIUS-only Compose lab baseline
  labels:
    environment: lab
    owner: labgen

server:
  instance_id: %s
  shutdown_grace: 15s
  startup_failure_mode: fail_closed
  admin_only: false
  log_level: info

runtime:
  persistence: memory
  allow_shadowing: true
  delete_baseline_behavior: tombstone
  reload_overlay_behavior: rebase
  reset_requires_scope: runtime:reset
  max_objects:
    users: 10000
    groups: 1000
    clients: 2000
    api_tokens: 1000

security:
  allow_environment_secrets: false
  strict_secret_files: true
  legacy_shared_secrets:
    minimum_length_characters: 16
    minimum_character_classes: 3
    reject_known_weak_values: true
    warn_on_reuse: true
    default_rotation_interval: 90d
    rotation_warning_before: 14d
  radius_shared_secrets:
    minimum_length_characters: 16
    minimum_character_classes: 3
    reject_known_weak_values: true
    warn_on_reuse: true
    default_rotation_interval: 90d
    rotation_warning_before: 14d

listeners:
  tacacs:
    legacy:
      enabled: false
    tls:
      enabled: false
  radius:
    access:
      enabled: true
      required: true
      bind: 0.0.0.0:1812
      transport: udp
      message_authenticator: required
      limit_proxy_state: true
    accounting:
      enabled: true
      required: false
      bind: 0.0.0.0:1813
      transport: udp
  http:
    enabled: true
    bind: 0.0.0.0:8080
    read_header_timeout: 5s
    read_timeout: 30s
    write_timeout: %s
    idle_timeout: %s
    max_request_body_bytes: 2097152
    trusted_proxy_cidrs: []
    tls:
      enabled: false

api:
  mode: lab_static_bearer
  ui_session:
    enabled: true
    lifetime: 30m
    idle_timeout: 10m
    cookie_secure: false
    cookie_same_site: strict
  mcp:
    allowed_origins: []
    require_origin: false
  bootstrap_tokens:
    - id: lab-admin
      token:
        file: /run/secrets/api_admin_token
      scopes:
        - state:read
        - state:write
        - config:reload
        - config:export
        - policy:test
        - events:read
        - tokens:manage
        - runtime:reset
      expires_at: null
  rate_limits:
    enabled: true
    per_token_requests_per_second: 50
    per_token_burst: 100
    unauthenticated_requests_per_second: 5
    unauthenticated_burst: 10

limits:
  max_username_bytes: 253
  max_port_bytes: 253
  max_remote_address_bytes: 253
  max_authentication_rounds: 16
  max_authorization_arguments: 256
  max_argument_bytes: 65535
  max_command_bytes: 65535
  max_policy_trace_steps: 1000
  max_event_payload_bytes: 65536

clients:
  - id: lab-switches
    display_name: Lab switches
    priority: 100
    enabled: true
    match:
      mode: address_and_certificate
      source_cidrs:
        - 0.0.0.0/0
        - ::/0
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access, accounting]
        radius:
          shared_secret:
            file: /run/secrets/lab_switches_radius_secret
          shared_secret_lifecycle:
            last_rotated_at: %s
            rotation_interval: 90d
          require_message_authenticator: true
          limit_proxy_state: true
          allowed_authentication_methods: [pap, chap]
          access_policy_id: default-radius-access
          accounting:
            accept_status_types: [start, stop, interim_update, accounting_on, accounting_off]

groups:
  - id: administrators
    display_name: Full administrators
    priority: 10
    enabled: true
    services:
      - service: shell
        protocol: null
        action: permit
        reply_attributes:
          - name: priv-lvl
            separator: "="
            value: "15"
    command_rules:
      - id: permit-all
        priority: 10
        action: permit
        command:
          pattern: ".*"
        arguments:
          pattern: ".*"
        reason: Full lab administration
    default_command_action: deny

  - id: readonly
    display_name: Read-only operators
    priority: 100
    enabled: true
    services:
      - service: shell
        protocol: null
        action: permit
        reply_attributes:
          - name: priv-lvl
            separator: "="
            value: "1"
    command_rules:
      - id: show
        priority: 10
        action: permit
        command:
          exact: show
        arguments:
          pattern: ".*"
      - id: deny-everything-else
        priority: 10000
        action: deny
        command:
          pattern: ".*"
        arguments:
          pattern: ".*"
        reason: Default deny
    default_command_action: deny

users:
  - id: lab-admin
    display_name: Lab Administrator
    enabled: true
    group_ids:
      - administrators
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_admin_argon2id
      challenge:
        secret:
          file: /run/secrets/lab_admin_challenge_secret
      enable:
        verifier:
          file: /run/secrets/lab_admin_enable_argon2id
    restrictions:
      client_ids: []
      valid_after: null
      valid_before: null

  - id: lab-readonly
    display_name: Read-only Lab User
    enabled: true
    group_ids:
      - readonly
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_readonly_argon2id
    restrictions:
      client_ids:
        - lab-switches

  - id: lab-disabled
    display_name: Disabled Lab User
    enabled: false
    group_ids:
      - readonly
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_disabled_argon2id

radius_reply_profiles:
  - id: lab-accept
    attributes:
      - name: Session-Timeout
        value: "600"

radius_policies:
  - id: default-radius-access
    rules:
      - id: permit-administrators
        match:
          groups_any: [administrators]
        effect: permit
        reply_profiles: [lab-accept]
      - id: deny-rest
        effect: deny

fallback_rules:
  services: []
  command_rules: []

events:
  ring_buffer_capacity: 10000
  include_successful_authentication: true
  include_failed_authentication: true
  include_authorization: true
  include_accounting: true
  redact_user_input: true
  stdout:
    enabled: true
    format: json

observability:
  metrics:
    enabled: true
    bind: 127.0.0.1:9090
    path: /metrics
    expose_on_admin: false
  tracing:
    enabled: false
  profiling:
    enabled: false
`
