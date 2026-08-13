package rest

import (
	"net/http"
	"sync"
	"testing"
)

func TestRaceStatusEvaluateEvents(t *testing.T) {
	h := restHarness(t)
	var wg sync.WaitGroup
	errc := make(chan error, 24)
	for i := 0; i < 8; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/status", h.Token, nil, nil)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errc <- errStatus(resp.StatusCode)
			}
		}()
		go func() {
			defer wg.Done()
			resp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/policy/evaluate", h.Token, []byte(`{"user_id":"alice","service":"shell","cmd":"show"}`), nil)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errc <- errStatus(resp.StatusCode)
			}
		}()
		go func() {
			defer wg.Done()
			resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/events", h.Token, nil, nil)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errc <- errStatus(resp.StatusCode)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/users", h.Token, nil, nil)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errc <- errStatus(resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

type statusErr int

func (e statusErr) Error() string { return http.StatusText(int(e)) }

func errStatus(code int) error { return statusErr(code) }
