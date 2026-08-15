package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestValidateExampleConfig(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := validateCmd([]string{"--config", filepath.Join("..", "..", "configs", "lab.example.yaml")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "ok\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestValidateExampleV2Config(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := validateCmd([]string{"--config", filepath.Join("..", "..", "configs", "lab.example.v2.yaml")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "ok\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestValidateRequiresConfig(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := validateCmd(nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
}
