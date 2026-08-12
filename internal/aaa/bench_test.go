package aaa

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func BenchmarkCHAPLogin(b *testing.B) {
	svc, _, _ := testService(b)
	id := byte(0x42)
	chal := []byte("12345678")
	resp := credentials.CHAPResponse(id, []byte(testChallenge), chal)
	data := append([]byte{id}, append(chal, resp...)...)
	start := AuthenticationStart{
		ConnKey: 1, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
		Data: data,
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start.SessionID = uint32(i + 1)
		if _, err := svc.BeginAuthentication(ctx, start); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecordAccounting(b *testing.B) {
	svc, _, _ := testService(b)
	rec := AccountingRecord{
		Flags:    AcctFlagStart,
		UserID:   "lab-admin",
		ClientID: "lab-switches",
		Arguments: domain.AVPairs{
			{Name: "task_id", Separator: '=', Value: "bench"},
			{Name: "service", Separator: '=', Value: "shell"},
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.RecordAccounting(ctx, rec); err != nil {
			b.Fatal(err)
		}
	}
}
