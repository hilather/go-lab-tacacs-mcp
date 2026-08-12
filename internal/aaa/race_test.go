package aaa

import (
	"context"
	"sync"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
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
