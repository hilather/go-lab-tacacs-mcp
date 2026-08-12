package policy

import (
	"sync"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestAuthorizeConcurrentRace(t *testing.T) {
	eng := mustCompileFile(t, "policies", "personas.yaml")
	reqs := []Request{
		sessionReq("lab-admin", "lab-switches"),
		cmdReq("lab-admin", "lab-switches", "configure"),
		sessionReq("lab-readonly", "lab-switches"),
		cmdReq("lab-readonly", "lab-switches", "configure"),
	}
	var wg sync.WaitGroup
	errc := make(chan string, 32)
	for i := 0; i < 32; i++ {
		for _, req := range reqs {
			req := req
			wg.Add(1)
			go func() {
				defer wg.Done()
				res := eng.Authorize(req)
				if res.Status == domain.AuthorStatusError {
					errc <- res.Trace.Error
				}
			}()
		}
	}
	wg.Wait()
	close(errc)
	for msg := range errc {
		t.Fatal(msg)
	}
}
