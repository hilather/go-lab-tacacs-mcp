package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpExitsZero(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{nil, {"-h"}, {"--help"}, {"help"}, {"serve", "-h"}} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("run(%v) exit %d, stderr=%q", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "taclabd serve") {
			t.Fatalf("run(%v) missing usage, stdout=%q", args, stdout.String())
		}
	}
}

func TestVersionExitsZero(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"version"}, {"--version"}, {"-version"}} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("run(%v) exit %d, stderr=%q", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "taclabd") {
			t.Fatalf("run(%v) missing version, stdout=%q", args, stdout.String())
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run([]string{"not-a-command"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestServeRequiresConfig(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run([]string{"serve"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
