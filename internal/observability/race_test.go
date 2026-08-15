package observability

import (
	"bytes"
	"sync"
	"testing"
)

func TestRegistryRace(t *testing.T) {
	reg := NewRegistry()
	rec := NewRecorder(reg)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				rec.Authen(TransportLegacy, "ascii", "pass")
				rec.Author(TransportTLS, "deny")
				rec.API("system.status.get", ResultSuccess, "none", 0.001)
				rec.ProtocolDiscard(ProtocolRADIUS, TransportUDP, RoleAccess, "discard_unknown_client")
				rec.RADIUSRetransmission(RoleAccess, RetransmitMiss)
				rec.SetRevision(uint64(j))
				rec.SetSecretLifecycle(map[string]int{StatusCurrent: j % 3})
				rec.SetEventSubscribers(j % 5)
				var buf bytes.Buffer
				_ = reg.WritePrometheus(&buf)
			}
		}()
	}
	wg.Wait()
}
