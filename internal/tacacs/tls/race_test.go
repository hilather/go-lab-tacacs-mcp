package tls

import (
	"sync"
	"testing"
)

func TestConcurrentHandshakes(t *testing.T) {
	ln, pki := startDefault(t)
	const n = 8
	var wg sync.WaitGroup
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
			c := dialAuth(t, ln.Addr().String(), cfg)
			h, body := authorPacket()
			if err := c.WritePacket(h, body); err != nil {
				errc <- err
				return
			}
			if _, _, err := c.ReadPacket(); err != nil {
				errc <- err
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}
