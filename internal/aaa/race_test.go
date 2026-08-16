package aaa

import (
	"context"
	"sync"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestConcurrentPAPAndCHAP(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	id := byte(1)
	chal := []byte("12345678")
	resp := credentials.CHAPResponse(id, []byte(testChallenge), chal)
	chap := append([]byte{id}, append(chal, resp...)...)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(n uint32) {
			defer wg.Done()
			_, _ = svc.BeginAuthentication(ctx, AuthenticationStart{
				ConnKey: uint64(n), SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
				Data: []byte(testPassword),
			})
		}(uint32(i + 1))
		go func(n uint32) {
			defer wg.Done()
			_, _ = svc.BeginAuthentication(ctx, AuthenticationStart{
				ConnKey: uint64(100 + n), SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
				Data: chap,
			})
		}(uint32(i + 1))
	}
	wg.Wait()
}

func TestMustChangeLoginConcurrentUpdate(t *testing.T) {
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(n uint32) {
			defer wg.Done()
			_, _ = svc.BeginAuthentication(ctx, AuthenticationStart{
				ConnKey: uint64(200 + n), SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
			})
			_, _ = svc.ContinueAuthentication(ctx, AuthenticationContinue{
				ConnKey: uint64(200 + n), SessionID: 1, UserMsg: []byte(testPassword), ClientID: "lab-switches",
			})
		}(uint32(i + 1))
		go func() {
			defer wg.Done()
			rev := mgr.Revision()
			name := "race"
			_, _ = mgr.UpdateUser("lab-admin", state.UpdateUser{DisplayName: &name}, &rev)
		}()
	}
	wg.Wait()
}

func TestRecordRADIUSAccountingRace(t *testing.T) {
	svc, _, _ := testService(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errc := make(chan error, 64)
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := svc.RecordRADIUSAccounting(ctx, RADIUSAccountingRecord{
				Kind:      AccountingStart,
				UserID:    "lab-admin",
				SessionID: "race-sess",
			})
			if err != nil {
				errc <- err
			}
		}()
		go func(n uint32) {
			defer wg.Done()
			_, err := svc.RecordAccounting(ctx, AccountingRecord{
				Flags:     AcctFlagStart,
				ClientID:  "lab-switches",
				UserID:    "lab-admin",
				SessionID: n + 1,
			})
			if err != nil {
				errc <- err
			}
		}(uint32(i))
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

func TestAuthorizeExplainRace(t *testing.T) {
	svc, _, _ := testService(t)
	ctx := context.Background()
	reqs := []AuthorizationRequest{
		{UserID: "lab-admin", ClientID: "lab-switches", Arguments: domain.AVPairs{av("service", '=', "shell")}},
		{UserID: "lab-admin", ClientID: "lab-switches", Arguments: domain.AVPairs{av("service", '=', "shell"), av("cmd", '=', "configure")}},
		{UserID: "lab-readonly", ClientID: "lab-switches", Arguments: domain.AVPairs{av("service", '=', "shell"), av("cmd", '=', "configure")}},
	}
	var wg sync.WaitGroup
	errc := make(chan error, 64)
	for i := 0; i < 16; i++ {
		for _, req := range reqs {
			req := req
			wg.Add(2)
			go func() {
				defer wg.Done()
				if _, err := svc.Authorize(ctx, req); err != nil {
					errc <- err
				}
			}()
			go func() {
				defer wg.Done()
				if _, err := svc.ExplainAuthorization(ctx, req); err != nil {
					errc <- err
				}
			}()
		}
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}
