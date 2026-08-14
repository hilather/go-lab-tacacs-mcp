package aaa

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// CredentialEvidence is protocol-neutral proof for VerifyCredentials.
// Password is PAP/password material (credentials.Password, not a raw slice).
// CHAP uses CHAPID + Challenge + Response. AuthenticateAccess is not exported
// yet (RAD-DOM-003).
type CredentialEvidence struct {
	Method    domain.AuthMethod
	Password  credentials.Password
	CHAPID    byte
	Challenge []byte
	Response  []byte
}

// VerifyCredentials checks password or CHAP evidence against the current
// snapshot. It does not record TACACS events or apply client allowed-methods.
// AuthPass / AuthReject / AuthError are the only outcomes; AuthChallenge is
// reserved. An already-cancelled ctx returns AuthError. A cancel during the
// credential check maps to AuthReject so TACACS one-shot PAP/CHAP stay FAIL.
func (s *Service) VerifyCredentials(ctx context.Context, userID string, clientID string, ev CredentialEvidence) (domain.AuthOutcome, error) {
	if s == nil {
		return domain.AuthError, domain.NewError(domain.CodeInternal, "aaa service is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return domain.AuthError, err
	}
	if !ev.Method.Valid() {
		return domain.AuthError, domain.NewError(domain.CodeInvalidArgument, "authentication method must be password or chap")
	}
	snap := s.snap()
	if snap == nil {
		return domain.AuthError, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	return s.verifyAgainst(ctx, snap, userID, clientID, ev), nil
}

func (s *Service) verifyAgainst(ctx context.Context, snap *state.Snapshot, userID string, clientID string, ev CredentialEvidence) domain.AuthOutcome {
	if s == nil || snap == nil {
		return domain.AuthError
	}
	creds := s.boundCreds(snap, clientID)
	var err error
	switch ev.Method {
	case domain.AuthMethodPassword:
		pw := ev.Password.Bytes()
		err = creds.VerifyASCIIOrPAP(ctx, userID, pw)
		wipe(pw)
		ev.Password.Wipe()
	case domain.AuthMethodCHAP:
		err = creds.VerifyCHAP(ctx, userID, ev.CHAPID, ev.Challenge, ev.Response)
	default:
		return domain.AuthError
	}
	return outcomeFromCreds(err)
}

func outcomeFromCreds(err error) domain.AuthOutcome {
	if err == nil {
		return domain.AuthPass
	}
	if protoError(err) {
		return domain.AuthError
	}
	return domain.AuthReject
}
