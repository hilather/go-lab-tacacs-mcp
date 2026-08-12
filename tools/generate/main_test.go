package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateWritesToolchainRecord(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := generate(root); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "docs", "generated", "toolchain.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != toolchainMarkdown {
		t.Fatalf("generated toolchain.md drifted from the stub generator")
	}
}
