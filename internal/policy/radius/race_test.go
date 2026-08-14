package radius

import (
	"sync"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestEvaluateConcurrent(t *testing.T) {
	t.Parallel()
	eng := personaEngine(t)
	req := Request{
		UserID:     "lab-admin",
		ClientID:   "lab-switches",
		EndpointID: "radius-udp",
		Method:     domain.AuthMethodPassword,
		Groups:     []string{"lab-admins"},
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				res := eng.Evaluate(req)
				if res.Effect != domain.EffectPermit {
					t.Errorf("effect=%s", res.Effect)
					return
				}
			}
		}()
	}
	wg.Wait()
}
