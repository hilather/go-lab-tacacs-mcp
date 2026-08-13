package main

import (
	"errors"
	"strings"
	"testing"
)

func TestDetectUnsetImageSkipsWithoutPull(t *testing.T) {
	t.Setenv(EnvIOLImage, "")
	var pulled bool
	d := Detect(Lookups{
		Getenv: func(k string) string {
			if k == EnvIOLImage {
				return ""
			}
			return ""
		},
		LookPath: func(string) (string, error) { return "/usr/bin/containerlab", nil },
		ImageExists: func(string) (bool, error) {
			pulled = true
			return false, errors.New("must not inspect when unset")
		},
	})
	if d.Status != StatusSkip {
		t.Fatalf("status=%s want skip", d.Status)
	}
	if !strings.Contains(d.Reason, "SKIP") || !strings.Contains(strings.ToLower(d.Reason), "equipment") {
		t.Fatalf("reason not an explicit equipment skip: %s", d.Reason)
	}
	if !strings.Contains(d.Reason, EnvIOLImage) {
		t.Fatalf("reason should mention unset image env: %s", d.Reason)
	}
	if pulled {
		t.Fatal("Detect must not inspect or pull when image env is unset")
	}
	if d.WouldPull {
		t.Fatal("WouldPull must be false")
	}
	if ClaimCiscoPass(d) || d.CiscoPass || d.DeviceFamilyClaim || d.ConformanceClaim != "none" {
		t.Fatalf("skip treated as PASS: %+v", d)
	}
}

func TestDetectMissingLocalImageSkipsNoPull(t *testing.T) {
	d := Detect(Lookups{
		Getenv:   func(string) string { return "vrnetlab/cisco_iol:does-not-exist" },
		LookPath: func(name string) (string, error) { return "/bin/" + name, nil },
		ImageExists: func(name string) (bool, error) {
			if name == "vrnetlab/cisco_iol:does-not-exist" {
				return false, nil
			}
			t.Fatalf("unexpected inspect %q", name)
			return false, nil
		},
	})
	if d.Status != StatusSkip {
		t.Fatalf("status=%s", d.Status)
	}
	if !strings.Contains(d.Reason, "will not pull") {
		t.Fatalf("missing no-pull wording: %s", d.Reason)
	}
	if ClaimCiscoPass(d) {
		t.Fatal("missing image skip must not be Cisco PASS")
	}
}

func TestDetectNoContainerlabSkips(t *testing.T) {
	d := Detect(Lookups{
		Getenv: func(string) string { return "vrnetlab/cisco_iol:lab" },
		LookPath: func(name string) (string, error) {
			if name == "docker" {
				return "/usr/bin/docker", nil
			}
			return "", errors.New("not found")
		},
		ImageExists: func(string) (bool, error) { return true, nil },
	})
	if d.Status != StatusSkip || !strings.Contains(d.Reason, "containerlab") {
		t.Fatalf("got %+v", d)
	}
}

func TestDetectReadyWhenImageAndClabPresent(t *testing.T) {
	d := Detect(Lookups{
		Getenv: func(string) string { return "vrnetlab/cisco_iol:17.12.01" },
		LookPath: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
		ImageExists: func(name string) (bool, error) {
			return name == "vrnetlab/cisco_iol:17.12.01", nil
		},
	})
	if d.Status != StatusReady {
		t.Fatalf("status=%s reason=%s", d.Status, d.Reason)
	}
	if d.WouldPull || ClaimCiscoPass(d) {
		t.Fatalf("ready is not yet a Cisco PASS: %+v", d)
	}
}

func TestRunSkipWritesEvidenceNotPass(t *testing.T) {
	dir := t.TempDir()
	evPath := dir + "/evidence.json"
	ev, code := Run(RunOptions{
		RepoRoot:     repoRoot(t),
		EvidencePath: evPath,
		Stdout:       &strings.Builder{},
		Stderr:       &strings.Builder{},
		Lookups: Lookups{
			Getenv:      func(string) string { return "" },
			LookPath:    func(string) (string, error) { return "", errors.New("no") },
			ImageExists: func(string) (bool, error) { t.Fatal("inspect"); return false, nil },
		},
	})
	if code != 0 {
		t.Fatalf("skip must exit 0, got %d", code)
	}
	if ev.Status != StatusSkip || ev.CiscoPass {
		t.Fatalf("evidence %+v", ev)
	}
	body := mustRead(t, evPath)
	if strings.Contains(strings.ToLower(body), `"cisco_pass": true`) {
		t.Fatal("evidence claimed cisco_pass")
	}
	if !strings.Contains(body, `"status": "skip"`) {
		t.Fatalf("evidence missing skip: %s", body)
	}
}
