package aaa

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestAuthenticateAccessDefaultDenyAndRejects(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	chapID := byte(0x42)
	chapChal := []byte("12345678")
	chapOK := credentials.CHAPResponse(chapID, []byte(testChallenge), chapChal)

	type tc struct {
		name   string
		user   string
		ev     CredentialEvidence
		want   RadiusAccessOutcome
		reason string
	}
	cases := []tc{
		{
			name: "pap-pass-default-deny",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword([]byte(testPassword)),
			},
			want:   RadiusAccessReject,
			reason: AccessReasonPolicy,
		},
		{
			name: "pap-wrong-password",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword([]byte("wrong-password")),
			},
			want:   RadiusAccessReject,
			reason: AccessReasonBadCredentials,
		},
		{
			name: "pap-unknown-user",
			user: "no-such-user",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword([]byte(testPassword)),
			},
			want:   RadiusAccessReject,
			reason: AccessReasonBadCredentials,
		},
		{
			name: "chap-pass-default-deny",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    chapID,
				Challenge: chapChal,
				Response:  chapOK,
			},
			want:   RadiusAccessReject,
			reason: AccessReasonPolicy,
		},
		{
			name: "chap-wrong-response",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    chapID,
				Challenge: chapChal,
				Response:  make([]byte, credentials.CHAPResponseLen),
			},
			want:   RadiusAccessReject,
			reason: AccessReasonBadCredentials,
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
			want:   RadiusAccessReject,
			reason: AccessReasonBadCredentials,
		},
		{
			name:   "unsupported-method",
			user:   "lab-admin",
			ev:     CredentialEvidence{Method: domain.AuthMethod("mschapv1")},
			want:   RadiusAccessReject,
			reason: AccessReasonUnsupportedMethod,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.AuthenticateAccess(ctx, RadiusAccessAttempt{
				Context:  domain.RequestContext{Protocol: domain.ProtocolRADIUS, ClientID: "lab-switches"},
				UserID:   tc.user,
				Evidence: tc.ev,
			})
			if err != nil {
				t.Fatalf("AuthenticateAccess: %v", err)
			}
			if got.Outcome != tc.want || got.ReasonCode != tc.reason {
				t.Fatalf("got %+v want outcome=%s reason=%s", got, tc.want, tc.reason)
			}
			if got.Outcome == RadiusAccessAccept {
				t.Fatal("AuthenticateAccess must not accept")
			}
		})
	}
}

func TestAuthenticateAccessWipesPassword(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	pw := credentials.NewPassword([]byte(testPassword))
	in := RadiusAccessAttempt{
		Context:  domain.RequestContext{Protocol: domain.ProtocolRADIUS, ClientID: "lab-switches"},
		UserID:   "lab-admin",
		Evidence: CredentialEvidence{Method: domain.AuthMethodPassword, Password: pw},
	}
	if strings.Contains(fmt.Sprintf("%v", in), testPassword) {
		t.Fatal("password leaked from RadiusAccessAttempt formatting")
	}
	got, err := svc.AuthenticateAccess(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != RadiusAccessReject || got.ReasonCode != AccessReasonPolicy {
		t.Fatalf("got %+v", got)
	}
	for _, b := range pw.Bytes() {
		if b != 0 {
			t.Fatal("password holder backing bytes were not wiped")
		}
	}
}

func TestAuthenticateAccessCancelledContext(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := svc.AuthenticateAccess(ctx, RadiusAccessAttempt{
		Context:  domain.RequestContext{Protocol: domain.ProtocolRADIUS, ClientID: "lab-switches"},
		UserID:   "lab-admin",
		Evidence: CredentialEvidence{Method: domain.AuthMethodPassword, Password: credentials.NewPassword([]byte(testPassword))},
	})
	if err == nil || got.Outcome != RadiusAccessReject {
		t.Fatalf("cancelled ctx outcome=%s err=%v", got.Outcome, err)
	}
}

func TestAuthenticateAccessNilService(t *testing.T) {
	t.Parallel()
	var svc *Service
	got, err := svc.AuthenticateAccess(context.Background(), RadiusAccessAttempt{
		UserID:   "lab-admin",
		Evidence: CredentialEvidence{Method: domain.AuthMethodPassword},
	})
	if got.Outcome != RadiusAccessReject || got.ReasonCode != AccessReasonInternal {
		t.Fatalf("got %+v", got)
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeInternal {
		t.Fatalf("err=%v", err)
	}
}
