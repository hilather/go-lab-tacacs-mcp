package tls

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
	tctls "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/tls"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// RadSec counterparts of TestUDPAdmissionSnapshotSurvivesReloadBeforeAAA:
// each packet on an open connection is admitted and authenticated against
// the snapshot published when it is read, not the handshake snapshot.

func dialRadSec(t *testing.T, ln *radSecLab) *tctls.Conn {
	t.Helper()
	c, err := tctls.Dial(ln.Addr().String(), clientTLS(t, ln.pki))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// radSecPAP sends one PAP Access-Request with a unique Identifier and
// authenticator so the per-connection response cache cannot replay.
func radSecPAP(t *testing.T, c *tctls.Conn, id byte, password string) tcodec.Code {
	t.Helper()
	secret := []byte(labSecret)
	var ra [16]byte
	if _, err := rand.Read(ra[:]); err != nil {
		t.Fatal(err)
	}
	pap, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    id,
		Authenticator: ra,
		UserName:      "lab-admin",
		Password:      []byte(password),
		IncludeMA:     true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(pap); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReadPacket()
	if err != nil {
		t.Fatalf("id %d: %v", id, err)
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatalf("id %d: independent client rejected reply: %v", id, err)
	}
	return reply.Code
}

func radSecAccounting(t *testing.T, c *tctls.Conn, id byte) ([]byte, [16]byte, error) {
	t.Helper()
	secret := []byte(labSecret)
	acct, err := testclient.EncodeAccountingRequest(secret, testclient.AccountingRequest{
		Identifier: id,
		StatusType: testclient.AcctStart,
		SessionID:  "radsec-reload-" + string(rune('a'+id%26)),
		IncludeMA:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := tcodec.Decode(acct)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(acct); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReadPacket()
	return got, pkt.Authenticator, err
}

func TestRadSecDisabledUserRejectedOnOpenConnection(t *testing.T) {
	t.Parallel()
	ln, mgr := startRadSecPolicy(t)
	c := dialRadSec(t, ln)
	if code := radSecPAP(t, c, 1, accessTestPassword); code != tcodec.AccessAccept {
		t.Fatalf("before disable: %s", code)
	}
	disabled := false
	if _, err := mgr.UpdateUser("lab-admin", state.UpdateUser{Enabled: &disabled}, nil); err != nil {
		t.Fatal(err)
	}
	if code := radSecPAP(t, c, 2, accessTestPassword); code != tcodec.AccessReject {
		t.Fatalf("disabled user on open connection: %s", code)
	}
	got, ra, err := radSecAccounting(t, c, 3)
	if err != nil {
		t.Fatalf("accounting after reload: %v", err)
	}
	if _, err := testclient.DecodeAccountingResponse([]byte(labSecret), ra, got); err != nil {
		t.Fatalf("accounting after reload: %v", err)
	}
}

func TestRadSecPasswordChangeVisibleOnOpenConnection(t *testing.T) {
	t.Parallel()
	ln, mgr := startRadSecPolicy(t)
	c := dialRadSec(t, ln)
	if code := radSecPAP(t, c, 1, accessTestPassword); code != tcodec.AccessAccept {
		t.Fatalf("before change: %s", code)
	}
	const changed = "changed-pass-2!"
	phc, err := credentials.DeriveArgon2id([]byte(changed), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.OverrideLoginVerifier("lab-admin", phc, nil); err != nil {
		t.Fatal(err)
	}
	if code := radSecPAP(t, c, 2, accessTestPassword); code != tcodec.AccessReject {
		t.Fatalf("old password after change: %s", code)
	}
	if code := radSecPAP(t, c, 3, changed); code != tcodec.AccessAccept {
		t.Fatalf("new password after change: %s", code)
	}
}

func TestRadSecDeletedClientClosesOpenConnection(t *testing.T) {
	t.Parallel()
	ln, mgr := startRadSecPolicy(t)
	c := dialRadSec(t, ln)
	if code := radSecPAP(t, c, 1, accessTestPassword); code != tcodec.AccessAccept {
		t.Fatalf("before delete: %s", code)
	}
	if _, err := mgr.DeleteClient("radsec", state.DeleteOptions{Tombstone: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := mgr.Snapshot().Client("radsec"); ok {
		t.Fatal("client still published after delete")
	}
	secret := []byte(labSecret)
	var ra [16]byte
	ra[0] = 0xd1
	pap, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier: 2, Authenticator: ra, UserName: "lab-admin", Password: []byte(accessTestPassword), IncludeMA: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(pap); err != nil {
		t.Fatal(err)
	}
	_, err = c.ReadPacket()
	if err == nil {
		t.Fatal("deleted client received a RADIUS reply on its open connection")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("connection left open after client delete: %v", err)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Logf("connection closed with %v", err)
	}
}

func TestRadSecEndpointPolicyChangeVisibleOnOpenConnection(t *testing.T) {
	t.Parallel()
	ln, mgr := startRadSecPolicy(t)
	c := dialRadSec(t, ln)
	if got, ra, err := radSecAccounting(t, c, 1); err != nil {
		t.Fatalf("accounting before change: %v", err)
	} else if _, err := testclient.DecodeAccountingResponse([]byte(labSecret), ra, got); err != nil {
		t.Fatal(err)
	}
	cur, ok := mgr.Snapshot().Client("radsec")
	if !ok {
		t.Fatal("radsec client missing")
	}
	eps := append([]config.ClientEndpoint(nil), cur.Client.Endpoints...)
	found := false
	for i := range eps {
		if eps[i].ID == "radius-tls" {
			eps[i].Roles = []domain.ListenerRole{domain.RoleAccess}
			found = true
		}
	}
	if !found {
		t.Fatal("radius-tls endpoint missing")
	}
	if _, err := mgr.UpdateClient("radsec", state.UpdateClient{Endpoints: &eps}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := radSecAccounting(t, c, 2); err == nil {
		t.Fatal("accounting answered after the endpoint dropped the accounting role")
	}
}

// BenchmarkRadSecAccountingOnOpenConnection measures one accounting
// round trip on an established RadSec connection, which now includes the
// per-packet snapshot load and client re-admission.
func BenchmarkRadSecAccountingOnOpenConnection(b *testing.B) {
	ln, _ := startRadSecPolicy(b)
	c, err := tctls.Dial(ln.Addr().String(), clientTLS(b, ln.pki))
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	secret := []byte(labSecret)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		req, err := testclient.EncodeAccountingRequest(secret, testclient.AccountingRequest{
			Identifier: byte(i),
			StatusType: testclient.AcctInterimUpdate,
			SessionID:  "bench-" + strconv.Itoa(i),
			IncludeMA:  true,
		})
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if err := c.WritePacket(req); err != nil {
			b.Fatal(err)
		}
		if _, err := c.ReadPacket(); err != nil {
			b.Fatal(err)
		}
	}
}
