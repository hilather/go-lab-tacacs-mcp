package state

import (
	"net"
	"sync"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestConcurrentReadMutateReload(t *testing.T) {
	m := mustMgr(t, smallYAML)
	var readers sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s := m.Snapshot()
					if s == nil || s.Revision == 0 {
						t.Error("nil snapshot")
						return
					}
					_, _ = s.User("alice")
					_, _ = s.MatchClient(domain.TransportLegacy, net.ParseIP("10.20.1.1"), nil)
					_, _, _ = s.MatchRADIUS(domain.RoleAccess, domain.CarrierRADIUSUDP, net.ParseIP("10.20.1.1"))
					_ = s.DictionaryVersion()
					_ = s.Users()
					_ = s.Warnings()
				}
			}
		}()
	}
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := 0; i < 40; i++ {
			rev := m.Revision()
			name := "Alice"
			if i%2 == 0 {
				name = "Alice-odd"
			}
			_, _ = m.UpdateUser("alice", UpdateUser{DisplayName: strPtr(name)}, &rev)
			rev = m.Revision()
			_, _ = m.Reload(mustParse(t, smallYAML), &rev)
		}
	}()
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := 0; i < 20; i++ {
			rev := m.Revision()
			_, _ = m.CreateUser(CreateUser{ID: "tmp", DisplayName: strPtr("t")}, &rev)
			rev = m.Revision()
			_, _ = m.DeleteUser("tmp", DeleteOptions{}, &rev)
		}
	}()
	writers.Wait()
	close(stop)
	readers.Wait()
	if m.Snapshot() == nil {
		t.Fatal("lost snapshot")
	}
}
