package legacy

import (
	"net"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func BenchmarkMatchIPv4(b *testing.B) {
	idx := mustIndex(b, []config.Client{
		client("a", 100, []string{"10.0.0.0/8"}, domain.TransportLegacy),
		client("b", 50, []string{"10.1.0.0/16"}, domain.TransportLegacy),
		client("c", 10, []string{"192.168.0.0/16"}, domain.TransportLegacy),
	})
	ip := net.ParseIP("10.1.2.3")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id, err := idx.Match(domain.TransportLegacy, ip, nil)
		if err != nil || id != "b" {
			b.Fatalf("id=%s err=%v", id, err)
		}
	}
}

func BenchmarkMatchIPv6(b *testing.B) {
	idx := mustIndex(b, []config.Client{
		client("v6", 10, []string{"2001:db8::/32"}, domain.TransportLegacy),
		client("v6n", 5, []string{"2001:db8:1::/48"}, domain.TransportLegacy),
	})
	ip := net.ParseIP("2001:db8:1::5")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id, err := idx.Match(domain.TransportLegacy, ip, nil)
		if err != nil || id != "v6n" {
			b.Fatalf("id=%s err=%v", id, err)
		}
	}
}

func client(id string, pri int, cidrs []string, tr domain.Transport) config.Client {
	return config.Client{
		ID:       id,
		Priority: pri,
		Enabled:  true,
		Match:    config.ClientMatch{SourceCIDRs: cidrs, Transports: []domain.Transport{tr}, Mode: domain.MatchAddressAndCertificate},
	}
}

func mustIndex(b *testing.B, clients []config.Client) *config.ClientIndex {
	b.Helper()
	idx, err := config.CompileClientIndex(clients)
	if err != nil {
		b.Fatal(err)
	}
	return idx
}
