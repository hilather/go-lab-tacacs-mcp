package mcp

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
)

func TestRaceDiscoverToolsCall(t *testing.T) {
	h := mcpHarness(t)
	var wg sync.WaitGroup
	errc := make(chan error, 24)
	for i := 0; i < 8; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			got := mcpRPC(t, h.HTTP, h.Token, "server/discover", nil, nil)
			if got.StatusCode != 200 {
				errc <- errStatus(got.StatusCode)
			}
		}()
		go func() {
			defer wg.Done()
			got := mcpRPC(t, h.HTTP, h.Token, "tools/list", nil, nil)
			if got.StatusCode != 200 {
				errc <- errStatus(got.StatusCode)
			}
		}()
		go func() {
			defer wg.Done()
			got := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
				"name":      "taclab.system.status.get",
				"arguments": map[string]any{},
			}, nil)
			if got.StatusCode != 200 || got.Err != nil {
				errc <- errStatus(got.StatusCode)
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

func errStatus(code int) error {
	return fmt.Errorf("status %s", http.StatusText(code))
}
