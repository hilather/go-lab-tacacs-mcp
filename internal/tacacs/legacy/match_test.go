package legacy

import (
	"net"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestMatchIPv4LongestPrefix(t *testing.T) {
	t.Parallel()
	idx, err := config.CompileClientIndex([]config.Client{
		client("wide", 10, []string{"10.0.0.0/8"}, domain.TransportLegacy),
		client("narrow", 20, []string{"10.1.0.0/16"}, domain.TransportLegacy),
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := idx.Match(domain.TransportLegacy, net.ParseIP("10.1.2.3"), nil)
	if err != nil || id != "narrow" {
		t.Fatalf("id=%s err=%v", id, err)
	}
}

func TestMatchIPv6LongestPrefix(t *testing.T) {
	t.Parallel()
	idx, err := config.CompileClientIndex([]config.Client{
		client("wide", 10, []string{"2001:db8::/32"}, domain.TransportLegacy),
		client("narrow", 20, []string{"2001:db8:1::/48"}, domain.TransportLegacy),
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := idx.Match(domain.TransportLegacy, net.ParseIP("2001:db8:1::9"), nil)
	if err != nil || id != "narrow" {
		t.Fatalf("id=%s err=%v", id, err)
	}
}

func TestMatchUnknown(t *testing.T) {
	t.Parallel()
	idx, err := config.CompileClientIndex([]config.Client{
		client("lab", 10, []string{"10.0.0.0/8"}, domain.TransportLegacy),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idx.Match(domain.TransportLegacy, net.ParseIP("192.0.2.1"), nil); err == nil {
		t.Fatal("expected unknown client")
	}
}

func TestMatchIgnoresTLSOnly(t *testing.T) {
	t.Parallel()
	idx, err := config.CompileClientIndex([]config.Client{
		client("tls", 10, []string{"127.0.0.0/8"}, domain.TransportTLS),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idx.Match(domain.TransportLegacy, net.ParseIP("127.0.0.1"), nil); err == nil {
		t.Fatal("tls-only client must not match legacy")
	}
}

// client is defined in bench_test.go.
