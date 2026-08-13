package parity

import (
	"strconv"
	"sync"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
)

func TestRaceRESTAndMCPReads(t *testing.T) {
	w := newWorld(t, "rest", allScopes, "both")
	w.Name = "rest"
	mcpW := *w
	mcpW.Name = "mcp"

	var wg sync.WaitGroup
	errc := make(chan error, 32)
	for i := 0; i < 8; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			out := invoke(t, w, operations.IDSystemStatusGet, operations.GetStatusRequest{}, callOpts{})
			if out.Code != "" {
				errc <- errStr("rest status " + out.Code)
			}
		}()
		go func() {
			defer wg.Done()
			out := invoke(t, &mcpW, operations.IDSystemStatusGet, operations.GetStatusRequest{}, callOpts{})
			if out.Code != "" {
				errc <- errStr("mcp status " + out.Code)
			}
		}()
		go func() {
			defer wg.Done()
			out := invoke(t, w, operations.IDPolicyEvaluate, operations.EvaluatePolicyRequest{
				UserID: "alice", ClientID: "sw", Service: "shell", Cmd: "show",
			}, callOpts{})
			if out.Code != "" {
				errc <- errStr("rest evaluate " + out.Code)
			}
		}()
		go func() {
			defer wg.Done()
			out := invoke(t, &mcpW, operations.IDEventsList, operations.ListEventsRequest{Limit: 5}, callOpts{})
			if out.Code != "" {
				errc <- errStr("mcp events " + out.Code)
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

func TestRaceMixedMutationsIsolated(t *testing.T) {
	var wg sync.WaitGroup
	errc := make(chan error, 16)
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			w := newWorld(t, "rest", allScopes, "rest")
			out := invoke(t, w, operations.IDUsersCreate, operations.CreateUserRequest{
				ID: "r" + strconv.Itoa(i), Enabled: boolPtr(false),
			}, callOpts{})
			if out.Code != "" {
				errc <- errStr("rest create " + out.Code)
			}
		}()
		go func() {
			defer wg.Done()
			w := newWorld(t, "mcp", allScopes, "mcp")
			out := invoke(t, w, operations.IDUsersCreate, operations.CreateUserRequest{
				ID: "m" + strconv.Itoa(i), Enabled: boolPtr(false),
			}, callOpts{})
			if out.Code != "" {
				errc <- errStr("mcp create " + out.Code)
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }
