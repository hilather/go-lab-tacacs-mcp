package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkParseSmall(b *testing.B) {
	data, err := os.ReadFile("testdata/parse/minimal.yaml")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseLabExample(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "lab.example.yaml"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseLarge(b *testing.B) {
	data := largeBaseline()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(data); err != nil {
			b.Fatal(err)
		}
	}
}

func largeBaseline() []byte {
	var b strings.Builder
	b.WriteString("schema_version: 1\nclients:\n")
	for i := 0; i < 200; i++ {
		b.WriteString("  - id: client-")
		b.WriteString(itoa(i))
		b.WriteString("\n    match:\n      source_cidrs: [\"10.")
		b.WriteString(itoa(i / 256))
		b.WriteString(".")
		b.WriteString(itoa(i % 256))
		b.WriteString(".0/24\"]\n      transports: [legacy]\n    legacy:\n      shared_secret:\n        file: /run/secrets/c")
		b.WriteString(itoa(i))
		b.WriteString("\n")
	}
	b.WriteString("groups:\n")
	for i := 0; i < 50; i++ {
		b.WriteString("  - id: group-")
		b.WriteString(itoa(i))
		b.WriteString("\n    services:\n      - service: shell\n        action: permit\n    command_rules:\n      - id: all\n        action: deny\n        command: {pattern: \".*\"}\n        arguments: {pattern: \".*\"}\n")
	}
	b.WriteString("users:\n")
	for i := 0; i < 200; i++ {
		b.WriteString("  - id: user-")
		b.WriteString(itoa(i))
		b.WriteString("\n    group_ids: [group-0]\n    credentials:\n      login:\n        verifier:\n          file: /run/secrets/u")
		b.WriteString(itoa(i))
		b.WriteString("\n")
	}
	return []byte(b.String())
}
