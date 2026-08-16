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

func BenchmarkASCIILoginMustChangeStart(b *testing.B) {
	svc, mgr, _ := testService(b)
	setMustChangeLogin(b, mgr, "lab-admin", true)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sid := uint32(i + 1)
		if _, err := svc.BeginAuthentication(ctx, AuthenticationStart{
			ConnKey: 90, SessionID: sid, UserID: "lab-admin", ClientID: "lab-switches",
			Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
		}); err != nil {
			b.Fatal(err)
		}
		step, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
			ConnKey: 90, SessionID: sid, UserMsg: []byte(testPassword), ClientID: "lab-switches",
		})
		if err != nil {
			b.Fatal(err)
		}
		if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptNewPass {
			b.Fatalf("want extra GETPASS, got %+v", step)
		}
	}
}

func BenchmarkRecordRADIUSAccounting(b *testing.B) {
	svc, _, _ := testService(b)
	rec := RADIUSAccountingRecord{
		Kind:      AccountingStart,
		UserID:    "lab-admin",
		SessionID: "bench-sess",
		SafeAttributes: []SafeAttributeSummary{
			{Name: "NAS-IP-Address"},
			{Name: "User-Name"},
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.RecordRADIUSAccounting(ctx, rec); err != nil {
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
