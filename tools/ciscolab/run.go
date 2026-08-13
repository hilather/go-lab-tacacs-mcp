package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// RunOptions control the shipped cisco-lab entry point.
type RunOptions struct {
	RepoRoot     string
	WorkDir      string
	EvidencePath string
	Lookups      Lookups
	Stdout       io.Writer
	Stderr       io.Writer
	SkipDeploy   bool
	Keep         bool
	Now          func() time.Time
	Command      func(ctx context.Context, name string, args ...string) *exec.Cmd
	HTTPGet      func(ctx context.Context, url, token string) (int, []byte, error)
	DialSSH      func(ctx context.Context, addr, user, password string) (sshSession, error)
}

type sshSession interface {
	CombinedOutput(cmd string) ([]byte, error)
	Close() error
}

// Run is the shipped entry point: detect, skip or deploy+exercise, write evidence.
func Run(opts RunOptions) (Evidence, int) {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.Lookups.Getenv == nil && opts.Lookups.LookPath == nil && opts.Lookups.ImageExists == nil {
		opts.Lookups = OSLookups()
	}
	started := opts.Now()
	evPath := opts.EvidencePath
	if evPath == "" {
		if v := opts.Lookups.Getenv; v != nil {
			evPath = v(EnvEvidence)
		}
		if evPath == "" {
			evPath = filepath.Join(opts.RepoRoot, "dist", "cisco-lab-evidence.json")
		}
	}

	hits, err := ForbiddenArtifacts(opts.RepoRoot)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "cisco-lab: tree scan: %v\n", err)
		return Evidence{Status: "error", Reason: err.Error()}, 1
	}
	if len(hits) > 0 {
		fmt.Fprintf(opts.Stderr, "cisco-lab: forbidden Cisco artifacts in tree: %s\n", strings.Join(hits, ", "))
		return Evidence{Status: "error", Reason: "forbidden Cisco artifacts present"}, 1
	}

	d := Detect(opts.Lookups)
	ev := decisionEvidence(d)
	ev.StartedAt = started
	if d.Status == StatusSkip {
		fmt.Fprintln(opts.Stdout, d.Reason)
		fmt.Fprintln(opts.Stdout, "cisco-lab: skip is not Cisco PASS and is not device-family completeness")
		ev.FinishedAt = opts.Now()
		_ = writeEvidence(evPath, ev)
		return ev, 0
	}

	if opts.SkipDeploy {
		fmt.Fprintln(opts.Stdout, "cisco-lab: ready (deploy skipped)")
		ev.FinishedAt = opts.Now()
		_ = writeEvidence(evPath, ev)
		return ev, 0
	}

	code := runLive(opts, &ev)
	ev.FinishedAt = opts.Now()
	if err := writeEvidence(evPath, ev); err != nil {
		fmt.Fprintf(opts.Stderr, "cisco-lab: write evidence: %v\n", err)
	}
	return ev, code
}

func runLive(opts RunOptions, ev *Evidence) int {
	work := opts.WorkDir
	if work == "" {
		var err error
		work, err = os.MkdirTemp("", "taclab-cisco-iol-")
		if err != nil {
			ev.Status = "error"
			ev.Reason = err.Error()
			return 1
		}
	}
	keep := opts.Keep
	if !keep && opts.Lookups.Getenv != nil && opts.Lookups.Getenv(EnvKeep) == "1" {
		keep = true
	}
	if !keep {
		defer func() {
			_ = destroyLab(opts, work)
			_ = os.RemoveAll(work)
		}()
	}

	p := DefaultRenderParams(opts.Lookups.Getenv)
	p.IOLImage = ev.IOLImageRef
	labDir := filepath.Join(work, "lab")
	fmt.Fprintf(opts.Stdout, "cisco-lab: generate TacLab secrets in %s\n", labDir)
	if err := runLabgen(opts, labDir); err != nil {
		ev.Status = "error"
		ev.Reason = "labgen: " + err.Error()
		fmt.Fprintln(opts.Stderr, ev.Reason)
		return 1
	}
	secret, err := os.ReadFile(filepath.Join(labDir, "secrets", "lab_switches_tacacs_secret"))
	if err != nil {
		ev.Status = "error"
		ev.Reason = err.Error()
		return 1
	}
	p.SharedSecret = string(bytes.TrimSpace(secret))
	p.LabDir = labDir
	gen, err := WriteGenerated(opts.RepoRoot, work, p)
	if err != nil {
		ev.Status = "error"
		ev.Reason = err.Error()
		return 1
	}

	if err := ensureTacLabImage(opts, p.TacLabImage); err != nil {
		ev.Status = "error"
		ev.Reason = err.Error()
		return 1
	}

	fmt.Fprintln(opts.Stdout, "cisco-lab: containerlab deploy")
	if err := clabDeploy(opts, gen.TopoPath); err != nil {
		ev.Status = "error"
		ev.Reason = SanitizeEvidenceText(err.Error(), p.SharedSecret)
		fmt.Fprintln(opts.Stderr, ev.Reason)
		return 1
	}

	httpBase := fmt.Sprintf("http://127.0.0.1:%d", p.HTTPHostPort)
	if err := waitHTTP(opts, httpBase+"/health/ready", 2*time.Minute); err != nil {
		ev.Status = "error"
		ev.Reason = "taclab ready: " + err.Error()
		return 1
	}

	iolAddr := net.JoinHostPort(p.IOLIPv4, "22")
	if err := waitTCP(opts, iolAddr, 5*time.Minute); err != nil {
		ev.Status = "error"
		ev.Reason = "IOL SSH: " + err.Error()
		ev.CapabilityNotes = append(ev.CapabilityNotes, "IOL did not open SSH; check image boot")
		return 1
	}

	pwBody, err := os.ReadFile(filepath.Join(labDir, "secrets", "PASSWORDS.txt"))
	if err != nil {
		ev.Status = "error"
		ev.Reason = err.Error()
		return 1
	}
	pws := parsePasswordsFile(string(pwBody))
	loginPW := pws["lab-admin"]
	enablePW := pws["lab-admin-enable"]
	tokenB, _ := os.ReadFile(filepath.Join(labDir, "secrets", "api_admin_token"))
	token := string(bytes.TrimSpace(tokenB))

	login, enable, authz, notes, err := exerciseDevice(opts, iolAddr, "lab-admin", loginPW, enablePW)
	ev.Login = login
	ev.Enable = enable
	ev.Authorization = authz
	ev.CapabilityNotes = append(ev.CapabilityNotes, notes...)
	if err != nil {
		ev.Status = "fail"
		ev.Reason = SanitizeEvidenceText(err.Error(), loginPW, enablePW, p.SharedSecret, token)
		fmt.Fprintln(opts.Stderr, ev.Reason)
		return 1
	}

	acct, acctNote := readAccounting(opts, httpBase, token)
	ev.Accounting = acct
	if acctNote != "" {
		ev.CapabilityNotes = append(ev.CapabilityNotes, acctNote)
	}

	ev.Status = "pass"
	ev.CiscoPass = login == "ok" && (enable == "ok" || enable == "already-privileged")
	ev.Reason = "IOL login against TacLab succeeded"
	fmt.Fprintln(opts.Stdout, "cisco-lab: login="+login+" enable="+enable+" authz="+authz+" acct="+acct)
	return 0
}

func runLabgen(opts RunOptions, dest string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := command(opts, ctx, "go", "run", "./tools/labgen", "-force", "-instance-id", "cisco-iol", dest)
	cmd.Dir = opts.RepoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, SanitizeEvidenceText(string(out)))
	}
	return nil
}

func ensureTacLabImage(opts RunOptions, image string) error {
	ok, err := dockerImageInspectOnly(image)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	fmt.Fprintf(opts.Stdout, "cisco-lab: building TacLab image %s\n", image)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cmd := command(opts, ctx, "docker", "build", "--target", "runtime", "-t", image, opts.RepoRoot)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker build: %w: %s", err, SanitizeEvidenceText(string(out)))
	}
	return nil
}

func clabDeploy(opts RunOptions, topo string) error {
	clab := "containerlab"
	if opts.Lookups.LookPath != nil {
		if p, err := findContainerlab(opts.Lookups.LookPath); err == nil {
			clab = p
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := command(opts, ctx, clab, "deploy", "-t", topo)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("containerlab deploy: %w: %s", err, string(out))
	}
	return nil
}

func destroyLab(opts RunOptions, work string) error {
	topo := filepath.Join(work, "topo.clab.yaml")
	if _, err := os.Stat(topo); err != nil {
		return nil
	}
	clab := "containerlab"
	if opts.Lookups.LookPath != nil {
		if p, err := findContainerlab(opts.Lookups.LookPath); err == nil {
			clab = p
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := command(opts, ctx, clab, "destroy", "-t", topo, "--cleanup")
	_ = cmd.Run()
	return nil
}

func waitHTTP(opts RunOptions, url string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		code, _, err := httpGet(opts, ctx, url, "")
		cancel()
		if err == nil && code >= 200 && code < 300 {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for %s", url)
}

func waitTCP(opts RunOptions, addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

func exerciseDevice(opts RunOptions, addr, user, loginPW, enablePW string) (login, enable, authz string, notes []string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sess, err := dialSSH(opts, ctx, addr, user, loginPW)
	if err != nil {
		return "fail", "not-run", "not-run", notes, fmt.Errorf("SSH login as %s: %w", user, err)
	}
	defer sess.Close()
	login = "ok"

	out, eerr := sess.CombinedOutput("show privilege")
	text := strings.ToLower(string(out))
	if eerr == nil && strings.Contains(text, "15") {
		enable = "already-privileged"
	} else {
		enOut, enErr := sess.CombinedOutput("enable\n" + enablePW + "\nshow privilege")
		enText := strings.ToLower(string(enOut))
		if enErr == nil && (strings.Contains(enText, "15") || strings.Contains(enText, "privilege")) {
			enable = "ok"
		} else if enErr != nil && (strings.Contains(enText, "unknown") || strings.Contains(enText, "invalid")) {
			enable = "unsupported"
			notes = append(notes, "ENABLE not offered or rejected by this IOL image; recorded as device capability, not a TacLab PASS")
		} else {
			enable = "fail"
			return login, enable, "not-run", notes, fmt.Errorf("ENABLE: %v %s", enErr, SanitizeEvidenceText(string(enOut), enablePW))
		}
	}

	sh, shErr := sess.CombinedOutput("show version")
	if shErr != nil {
		notes = append(notes, "exec/command authorization not confirmed: show version failed")
		authz = "unavailable"
		return login, enable, authz, notes, nil
	}
	if len(bytes.TrimSpace(sh)) == 0 {
		authz = "unavailable"
		notes = append(notes, "exec/command authorization not confirmed on this IOL image")
		return login, enable, authz, notes, nil
	}
	authz = "ok"
	return login, enable, authz, notes, nil
}

func readAccounting(opts RunOptions, httpBase, token string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	code, body, err := httpGet(opts, ctx, httpBase+"/api/v1/events?limit=50", token)
	if err != nil || code >= 300 {
		return "unavailable", "accounting events not read (device capability or API error)"
	}
	low := strings.ToLower(string(body))
	if strings.Contains(low, "account") || strings.Contains(low, "acct") {
		return "ok", ""
	}
	return "not-seen", "no accounting events yet; IOL may not send acct on this image"
}

func command(opts RunOptions, ctx context.Context, name string, args ...string) *exec.Cmd {
	if opts.Command != nil {
		return opts.Command(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...)
}

func httpGet(opts RunOptions, ctx context.Context, url, token string) (int, []byte, error) {
	if opts.HTTPGet != nil {
		return opts.HTTPGet(ctx, url, token)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b, nil
}

func dialSSH(opts RunOptions, ctx context.Context, addr, user, password string) (sshSession, error) {
	if opts.DialSSH != nil {
		return opts.DialSSH(ctx, addr, user, password)
	}
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i, q := range questions {
					if strings.Contains(strings.ToLower(q), "password") {
						ans[i] = password
					}
				}
				return ans, nil
			}),
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // lab-only IOL
		Timeout:         20 * time.Second,
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &realSSH{client: ssh.NewClient(c, chans, reqs)}, nil
}

type realSSH struct {
	client *ssh.Client
}

func (r *realSSH) CombinedOutput(cmd string) ([]byte, error) {
	sess, err := r.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	_ = sess.RequestPty("vt100", 80, 24, ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	})
	return sess.CombinedOutput(cmd)
}

func (r *realSSH) Close() error {
	return r.client.Close()
}
