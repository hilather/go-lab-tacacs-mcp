package peap

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"
)

func TestPEAPFragmentStorageIsBounded(t *testing.T) {
	tun := &Tunnel{}
	for i := 0; i < 100; i++ {
		tun.BufferFragment(Payload{LengthIncluded: i == 0, TLSMessageLen: 64 << 10, MoreFragments: true, TLSData: bytes.Repeat([]byte{1}, 1024)})
	}
	if tun.FragmentError() == nil {
		t.Fatal("overflow was not terminal")
	}
	if len(tun.frag) > 64<<10 {
		t.Fatalf("fragment storage grew to %d bytes", len(tun.frag))
	}
}

func TestPEAPPipeStorageIsBounded(t *testing.T) {
	p := newBytePipe()
	if _, err := p.Write(bytes.Repeat([]byte{1}, (64<<10)+1)); err == nil {
		t.Fatal("oversized TLS pipe write accepted")
	}
	if p.peekLen() > 64<<10 {
		t.Fatal("TLS pipe exceeded buffer bound")
	}
}

func TestPEAPRejectsUnsupportedVersion(t *testing.T) {
	if _, err := Parse([]byte{1}); err == nil {
		t.Fatal("PEAPv1 accepted by PEAPv0-only server")
	}
}

func TestPEAPRegistryCapacityIsBounded(t *testing.T) {
	r := NewRegistry()
	t.Cleanup(r.Reset)
	for i := 0; i < 5; i++ {
		r.Put(string(rune('a'+i)), &Tunnel{closed: true})
	}
	if len(r.items) > 4 {
		t.Fatalf("default tunnel byte budget exceeded: %d tunnels", len(r.items))
	}
}

func TestPEAPRegistryAdmitsOneTunnelBelowReservation(t *testing.T) {
	for _, tc := range []struct{ entries, bytes, want int }{
		{16, 64 << 10, 1},
		{16, (256 << 10) - 1, 1},
		{16, 256 << 10, 1}, // exactly one reservation: fits without the floor
		{16, 1 << 20, 4},
		{2, 8 << 20, 2},
	} {
		if got := tunnelCapacity(tc.entries, tc.bytes); got != tc.want {
			t.Errorf("tunnelCapacity(%d, %d)=%d want %d", tc.entries, tc.bytes, got, tc.want)
		}
	}
	r := NewRegistryWithLimits(16, 64<<10, time.Minute, nil)
	t.Cleanup(r.Reset)
	if !r.Put("first", &Tunnel{closed: true}) {
		t.Fatal("minimum challenge_bytes admitted no PEAP tunnel")
	}
	if r.Put("second", &Tunnel{closed: true}) {
		t.Fatal("sub-reservation budget admitted more than one tunnel")
	}
}

func TestPEAPRegistryExpiresAndClosesAbandonedTunnel(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	var ticks atomic.Int64
	ticks.Store(now.UnixNano())
	r := NewRegistryWithLimits(1, 4*MaxTLSFlightBytes, time.Second, func() time.Time { return time.Unix(0, ticks.Load()) })
	t.Cleanup(r.Reset)
	srv, err := NewServer(mustPEAPCert(t))
	if err != nil {
		t.Fatal(err)
	}
	tun, err := srv.NewTunnel()
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if !r.Put("abandoned", tun) {
		t.Fatal("initial admission failed")
	}
	if r.Put("overflow", &Tunnel{closed: true}) {
		t.Fatal("live tunnel evicted")
	}
	ticks.Add(int64(time.Second))
	if r.Get("abandoned") != nil {
		t.Fatal("expired tunnel remained available")
	}
	if !tun.closed {
		t.Fatal("expired tunnel not closed")
	}
	if !r.Put("replacement", &Tunnel{closed: true}) {
		t.Fatal("expired capacity not recovered")
	}
}

func TestPEAPDeclaredFragmentLength(t *testing.T) {
	for _, p := range []Payload{
		{LengthIncluded: true, TLSMessageLen: 2, TLSData: []byte{1}},
		{LengthIncluded: true, TLSMessageLen: 1, TLSData: []byte{1, 2}},
		{LengthIncluded: true, TLSMessageLen: MaxTLSFlightBytes + 1},
		{MoreFragments: true, TLSData: []byte{1}},
	} {
		tun := &Tunnel{}
		tun.BufferFragment(p)
		if tun.FragmentError() == nil {
			t.Fatalf("invalid fragment accepted: %+v", p)
		}
	}
}

func BenchmarkPEAPReassemble(b *testing.B) {
	data := bytes.Repeat([]byte{1}, 1024)
	tun := &Tunnel{}
	b.ReportAllocs()
	for b.Loop() {
		tun.BufferFragment(Payload{LengthIncluded: true, MoreFragments: true, TLSMessageLen: 2048, TLSData: data})
		tun.BufferFragment(Payload{TLSData: data})
	}
}

func TestPEAPRepeatedLengthFlagRejected(t *testing.T) {
	tnl := &Tunnel{}
	tnl.BufferFragment(Payload{LengthIncluded: true, MoreFragments: true, TLSMessageLen: 10})
	tnl.BufferFragment(Payload{LengthIncluded: true, MoreFragments: true, TLSMessageLen: 10})
	if tnl.FragmentError() == nil {
		t.Fatal("repeated L flag accepted")
	}
}

func TestPEAPRegistryExpiresWithoutTraffic(t *testing.T) {
	r := NewRegistryWithLimits(1, tunnelReservationBytes, 20*time.Millisecond, nil)
	t.Cleanup(r.Reset)
	srv, err := NewServer(mustPEAPCert(t))
	if err != nil {
		t.Fatal(err)
	}
	tun, err := srv.NewTunnel()
	if err != nil {
		t.Fatal(err)
	}
	if !r.Put("idle", tun) {
		t.Fatal("admission failed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		tun.mu.Lock()
		closed := tun.closed
		tun.mu.Unlock()
		if closed {
			r.mu.Lock()
			n := len(r.items)
			r.mu.Unlock()
			if n != 0 {
				t.Fatal("expired entry retained")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("idle tunnel was not closed by expiry timer")
}

func FuzzPEAPBoundedFragments(f *testing.F) {
	for _, seed := range [][]byte{{1}, {0x80, 0, 1, 0, 1}, {0xc0, 0, 0, 0, 0}, {0x40, 1}, {0x80, 0, 0, 0, 2, 1}, {0x38}, {0x98, 0, 0, 0, 1, 1}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Parse(raw)
		if err != nil {
			return
		}
		tun := &Tunnel{}
		tun.BufferFragment(p)
		if len(tun.frag) > MaxTLSFlightBytes {
			t.Fatal("fragment bound exceeded")
		}
	})
}
