package legacy

import (
	"runtime"
	"testing"
	"time"

	tclient "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

func TestStartStopNoLeak(t *testing.T) {
	runtime.GC()
	base := runtime.NumGoroutine()
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	for i := 0; i < 8; i++ {
		ln, _ := startListener(t, testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`), nil)
		c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
		if err != nil {
			t.Fatal(err)
		}
		body, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
			Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
			User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		})
		if err != nil {
			t.Fatal(err)
		}
		h := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 1}
		if err := c.WritePacket(h, body); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.ReadPacket(); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	var n int
	for time.Now().Before(deadline) {
		runtime.GC()
		n = runtime.NumGoroutine()
		if n <= base+16 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines leaked: have %d baseline %d", n, base)
}
