package legacy

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	tclient "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

func TestLegacyRoundTripAndMatch(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	ln, _ := startListener(t, testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`), nil)

	c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	body, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 1}
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	rh, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if rh.Flags&tcodec.FlagSingleConnect == 0 {
		t.Fatal("missing single-connect")
	}
	rep, err := tcodec.ReadAuthorRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.AuthorFail {
		t.Fatalf("status=%#x", rep.Status)
	}
}

func TestUnknownClientClosed(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	ln, _ := startListener(t, testYAML(sec, "127.0.0.1:0", `"10.0.0.0/8"`), nil)

	c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadlines(500 * time.Millisecond)
	_, _, err = c.ReadPacket()
	if err == nil {
		t.Fatal("unknown client should not receive a packet")
	}
}

func TestUnencryptedRejected(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	ln, _ := startListener(t, testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`), nil)

	c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	body, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagUnencrypted, SessionID: 1}
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	_, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tcodec.ReadAuthorRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.AuthorError {
		t.Fatalf("status=%#x want ERROR", rep.Status)
	}
}

func TestWrongSecretError(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	ln, _ := startListener(t, testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`), nil)

	c, err := tclient.Dial(ln.Addr().String(), []byte("WrongSecret-16ch!"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	body, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 3}
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	_, rbody, err := c.ReadPacket()
	if err != nil {
		// connection may close without a decodable reply if pad is garbage
		return
	}
	rep, err := tcodec.ReadAuthorRep(rbody)
	if err != nil {
		return
	}
	if rep.Status != tcodec.AuthorError {
		t.Fatalf("status=%#x want ERROR", rep.Status)
	}
}

func TestDistinctClientSecrets(t *testing.T) {
	dir := t.TempDir()
	secA := writeSecret(t, dir, "a", testSecret)
	secB := writeSecret(t, dir, "b", "OtherSecret-16ch!")
	yaml := `
schema_version: 1
listeners:
  legacy_tacacs:
    enabled: true
    bind: 127.0.0.1:0
    single_connect: {enabled: true, max_lifetime: 1m, idle_timeout: 2s}
  secure_tacacs: {enabled: false}
  http: {enabled: false}
clients:
  - id: loop
    priority: 10
    match: {source_cidrs: ["127.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: ` + secA + `}}
  - id: other
    priority: 20
    match: {source_cidrs: ["10.9.8.0/24"], transports: [legacy]}
    legacy: {shared_secret: {file: ` + secB + `}}
`
	ln, _ := startListener(t, yaml, nil)
	c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body, err := tcodec.WriteAcctReq(tcodec.AcctReq{
		Flags: tcodec.AcctStart, Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAcct, SeqNo: 1, SessionID: 4}
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	_, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tcodec.ReadAcctRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.AcctOK {
		t.Fatalf("status=%#x", rep.Status)
	}
}

func TestTLSClientHelloNotRouted(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	ln, _ := startListener(t, testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`), nil)

	nc, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	hello := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	_ = nc.SetDeadline(time.Now().Add(time.Second))
	if _, err := nc.Write(hello); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := nc.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("unexpected reply %x", buf[:n])
	}
}

func TestSecretCanaryNotOnWire(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	ln, _ := startListener(t, testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`), nil)
	c, err := tclient.Dial(ln.Addr().String(), []byte("WrongSecret-16ch!"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body, _ := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	_ = c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 1}, body)
	_, rbody, err := c.ReadPacket()
	if err != nil {
		if strings.Contains(err.Error(), testSecret) {
			t.Fatal("shared secret leaked in error text")
		}
		return
	}
	if strings.Contains(string(rbody), testSecret) {
		t.Fatal("shared secret leaked on the wire after wrong-secret decode")
	}
}

func TestIPv6Match(t *testing.T) {
	ln6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback not available")
	}
	_ = ln6.Close()

	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	ln, _ := startListener(t, testYAML(sec, "[::1]:0", `"::1/128"`), nil)

	c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("::1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 6}
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}
}

func TestSecondSessionWaitsForFirstReply(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	ln, _ := startListener(t, testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`), nil)
	c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	first := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 1}
	second := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 2}
	if err := c.WritePacket(first, body); err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(second, body); err != nil {
		t.Fatal(err)
	}
	rh1, _, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if rh1.Flags&tcodec.FlagSingleConnect == 0 {
		t.Fatal("first reply must complete single-connect")
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}
}

func TestBindFailure(t *testing.T) {
	t.Parallel()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	_, err = Listen(Options{
		Bind:     occupied.Addr().String(),
		Snapshot: func() *state.Snapshot { return nil },
		Secrets:  func(config.SecretRef) ([]byte, error) { return nil, io.EOF },
	})
	if err == nil {
		t.Fatal("expected bind failure")
	}
}
