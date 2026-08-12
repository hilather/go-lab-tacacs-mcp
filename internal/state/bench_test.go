package state

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func benchDocument(clients, users, groups int) *config.Document {
	var b strings.Builder
	b.WriteString("schema_version: 1\nlisteners:\n  secure_tacacs: {enabled: false}\ngroups:\n")
	for i := 0; i < groups; i++ {
		fmt.Fprintf(&b, "  - id: group-%d\n    command_rules:\n      - id: all\n        action: deny\n        command: {pattern: \".*\"}\n        arguments: {pattern: \".*\"}\n", i)
	}
	b.WriteString("clients:\n")
	for i := 0; i < clients; i++ {
		fmt.Fprintf(&b, "  - id: client-%d\n    priority: %d\n    match:\n      source_cidrs: [\"10.%d.%d.0/24\", \"2001:db8:%d::/48\"]\n      transports: [legacy]\n    legacy:\n      shared_secret: {file: /run/secrets/c%d}\n", i, i, i/256, i%256, i, i)
	}
	b.WriteString("users:\n")
	for i := 0; i < users; i++ {
		fmt.Fprintf(&b, "  - id: user-%d\n    group_ids: [group-0]\n    credentials:\n      login:\n        verifier: {file: /run/secrets/u%d}\n", i, i)
	}
	doc, err := config.Parse([]byte(b.String()))
	if err != nil {
		panic(err)
	}
	return doc
}

func BenchmarkParseCompile_Small(b *testing.B) {
	src := []byte(smallYAML)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		doc, err := config.Parse(src)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := New(doc, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseCompile_Medium(b *testing.B) {
	src := benchYAML(50, 200, 20)
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		doc, err := config.Parse(src)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := New(doc, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSnapshotPublish_Medium(b *testing.B) {
	doc := benchDocument(50, 200, 20)
	m, err := New(doc, Options{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rev := m.Revision()
		if _, err := m.UpdateUser("user-0", UpdateUser{DisplayName: strPtr("n")}, &rev); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClientLookup_IPv4(b *testing.B) {
	m, err := New(benchDocument(50, 20, 5), Options{})
	if err != nil {
		b.Fatal(err)
	}
	s := m.Snapshot()
	ip := net.ParseIP("10.0.3.9")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.MatchClient(domain.TransportLegacy, ip, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClientLookup_IPv6(b *testing.B) {
	m, err := New(benchDocument(50, 20, 5), Options{})
	if err != nil {
		b.Fatal(err)
	}
	s := m.Snapshot()
	ip := net.ParseIP("2001:db8:3::1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.MatchClient(domain.TransportLegacy, ip, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func benchYAML(clients, users, groups int) []byte {
	var b strings.Builder
	b.WriteString("schema_version: 1\nlisteners:\n  secure_tacacs: {enabled: false}\ngroups:\n")
	for i := 0; i < groups; i++ {
		fmt.Fprintf(&b, "  - id: group-%d\n    command_rules:\n      - id: all\n        action: deny\n        command: {pattern: \".*\"}\n        arguments: {pattern: \".*\"}\n", i)
	}
	b.WriteString("clients:\n")
	for i := 0; i < clients; i++ {
		fmt.Fprintf(&b, "  - id: client-%d\n    priority: %d\n    match:\n      source_cidrs: [\"10.%d.%d.0/24\", \"2001:db8:%d::/48\"]\n      transports: [legacy]\n    legacy:\n      shared_secret: {file: /run/secrets/c%d}\n", i, i, i/256, i%256, i, i)
	}
	b.WriteString("users:\n")
	for i := 0; i < users; i++ {
		fmt.Fprintf(&b, "  - id: user-%d\n    group_ids: [group-0]\n    credentials:\n      login:\n        verifier: {file: /run/secrets/u%d}\n", i, i)
	}
	return []byte(b.String())
}
