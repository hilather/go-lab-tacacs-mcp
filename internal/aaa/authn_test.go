package aaa

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestVerifyCredentialsMatchesOneShotStatuses(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()

	chapID := byte(0x42)
	chapChal := []byte("12345678")
	chapOK := credentials.CHAPResponse(chapID, []byte(testChallenge), chapChal)
	chapWrong := bytes.Repeat([]byte{0}, credentials.CHAPResponseLen)
	chapData := func(id byte, chal, resp []byte) []byte {
		return append([]byte{id}, append(chal, resp...)...)
	}

	type tc struct {
		name        string
		user        string
		ev          CredentialEvidence
		start       AuthenticationStart
		wantOutcome domain.AuthOutcome
		wantStatus  domain.AuthenStatus
	}
	cases := []tc{
		{
			name: "pap-pass",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword([]byte(testPassword)),
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
				UserID: "lab-admin", Data: []byte(testPassword),
			},
			wantOutcome: domain.AuthPass,
			wantStatus:  domain.AuthenStatusPass,
		},
		{
			name: "pap-wrong-password",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword([]byte("wrong-password")),
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
				UserID: "lab-admin", Data: []byte("wrong-password"),
			},
			wantOutcome: domain.AuthReject,
			wantStatus:  domain.AuthenStatusFail,
		},
		{
			name: "pap-unknown-user",
			user: "no-such-user",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword([]byte(testPassword)),
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
				UserID: "no-such-user", Data: []byte(testPassword),
			},
			wantOutcome: domain.AuthReject,
			wantStatus:  domain.AuthenStatusFail,
		},
		{
			name: "pap-missing-user",
			user: "",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword([]byte(testPassword)),
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
				Data: []byte(testPassword),
			},
			wantOutcome: domain.AuthReject,
			wantStatus:  domain.AuthenStatusFail,
		},
		{
			name: "pap-missing-data",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword(nil),
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
				UserID: "lab-admin",
			},
			wantOutcome: domain.AuthReject,
			wantStatus:  domain.AuthenStatusFail,
		},
		{
			name: "chap-pass",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    chapID,
				Challenge: chapChal,
				Response:  chapOK,
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
				UserID: "lab-admin", Data: chapData(chapID, chapChal, chapOK),
			},
			wantOutcome: domain.AuthPass,
			wantStatus:  domain.AuthenStatusPass,
		},
		{
			name: "chap-wrong-response",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    chapID,
				Challenge: chapChal,
				Response:  chapWrong,
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
				UserID: "lab-admin", Data: chapData(chapID, chapChal, chapWrong),
			},
			wantOutcome: domain.AuthReject,
			wantStatus:  domain.AuthenStatusFail,
		},
		{
			name: "chap-no-challenge-secret",
			user: "lab-readonly",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    1,
				Challenge: []byte("12345678"),
				Response:  credentials.CHAPResponse(1, []byte(testPassword), []byte("12345678")),
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
				UserID: "lab-readonly",
				Data:   chapData(1, []byte("12345678"), credentials.CHAPResponse(1, []byte(testPassword), []byte("12345678"))),
			},
			wantOutcome: domain.AuthReject,
			wantStatus:  domain.AuthenStatusFail,
		},
		{
			name: "chap-malformed-short",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    1,
				Challenge: []byte{2, 3},
				Response:  []byte{1},
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
				UserID: "lab-admin", Data: []byte{1, 2, 3},
			},
			wantOutcome: domain.AuthError,
			wantStatus:  domain.AuthenStatusError,
		},
		{
			name: "chap-below-min-challenge",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    1,
				Challenge: []byte("1234567"),
				Response:  credentials.CHAPResponse(1, []byte(testChallenge), []byte("1234567")),
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
				UserID: "lab-admin",
				Data:   chapData(1, []byte("1234567"), credentials.CHAPResponse(1, []byte(testChallenge), []byte("1234567"))),
			},
			wantOutcome: domain.AuthError,
			wantStatus:  domain.AuthenStatusError,
		},
		{
			name: "chap-empty-user",
			user: "",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    chapID,
				Challenge: chapChal,
				Response:  chapOK,
			},
			start: AuthenticationStart{
				Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
				Data: chapData(chapID, chapChal, chapOK),
			},
			wantOutcome: domain.AuthReject,
			wantStatus:  domain.AuthenStatusFail,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.VerifyCredentials(ctx, tc.user, "lab-switches", tc.ev)
			if err != nil {
				t.Fatalf("VerifyCredentials: %v", err)
			}
			if got != tc.wantOutcome {
				t.Fatalf("outcome=%s want %s", got, tc.wantOutcome)
			}
			if tacacsStatus(got) != tc.wantStatus {
				t.Fatalf("mapped status=%s want %s", tacacsStatus(got), tc.wantStatus)
			}
			start := tc.start
			start.ConnKey = 100
			start.SessionID = uint32(i + 1)
			start.ClientID = "lab-switches"
			step, err := svc.BeginAuthentication(ctx, start)
			if err != nil {
				t.Fatalf("BeginAuthentication: %v", err)
			}
			if step.Status != tc.wantStatus {
				t.Fatalf("tacacs status=%s want %s", step.Status, tc.wantStatus)
			}
		})
	}
}

func TestVerifyCredentialsRejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	got, err := svc.VerifyCredentials(context.Background(), "lab-admin", "lab-switches", CredentialEvidence{
		Method: domain.AuthMethod("peap"),
	})
	if got != domain.AuthError {
		t.Fatalf("outcome=%s", got)
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeInvalidArgument {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyCredentialsCancelledContext(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := svc.VerifyCredentials(ctx, "lab-admin", "lab-switches", CredentialEvidence{
		Method:   domain.AuthMethodPassword,
		Password: credentials.NewPassword([]byte(testPassword)),
	})
	if got != domain.AuthError || err == nil {
		t.Fatalf("cancelled ctx outcome=%s err=%v", got, err)
	}
}

func TestVerifyCredentialsNilService(t *testing.T) {
	t.Parallel()
	var svc *Service
	got, err := svc.VerifyCredentials(context.Background(), "lab-admin", "lab-switches", CredentialEvidence{
		Method:   domain.AuthMethodPassword,
		Password: credentials.NewPassword([]byte(testPassword)),
	})
	if got != domain.AuthError {
		t.Fatalf("outcome=%s", got)
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeInternal {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyCredentialsWipesPasswordAndDoesNotLogIt(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	pw := credentials.NewPassword([]byte(testPassword))
	ev := CredentialEvidence{Method: domain.AuthMethodPassword, Password: pw}
	if strings.Contains(fmt.Sprintf("%v", ev), testPassword) || strings.Contains(ev.Password.String(), testPassword) {
		t.Fatal("password leaked from CredentialEvidence formatting")
	}
	got, err := svc.VerifyCredentials(context.Background(), "lab-admin", "lab-switches", ev)
	if err != nil {
		t.Fatal(err)
	}
	if got != domain.AuthPass {
		t.Fatalf("outcome=%s", got)
	}
	for _, b := range pw.Bytes() {
		if b != 0 {
			t.Fatal("password holder backing bytes were not wiped")
		}
	}
}

func tacacsStatus(o domain.AuthOutcome) domain.AuthenStatus {
	switch o {
	case domain.AuthPass:
		return domain.AuthenStatusPass
	case domain.AuthError:
		return domain.AuthenStatusError
	default:
		return domain.AuthenStatusFail
	}
}
