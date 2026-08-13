package operations

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func handleAuthenticationTest(deps Deps) handleFunc {
	return func(ctx context.Context, snap *state.Snapshot, in Input) (any, error) {
		if snap == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
		}
		req, _ := in.Request.(TestAuthenticationRequest)
		if req.UserID == "" {
			return nil, domain.NewError(domain.CodeInvalidArgument, "user_id is required").WithPath("user_id")
		}
		method := config.AuthMethod(req.Method)
		switch method {
		case config.AuthMethodASCII, config.AuthMethodPAP, config.AuthMethodCHAP, config.AuthMethodMSCHAPv1, config.AuthMethodMSCHAPv2, config.AuthMethodEnable:
		default:
			return nil, domain.NewError(domain.CodeInvalidArgument, "method must be ascii, pap, chap, mschapv1, mschapv2, or enable").WithPath("method")
		}

		out := AuthenticationTestResult{Method: req.Method, UserID: req.UserID, ClientID: req.ClientID, Status: "fail"}
		if u, ok := snap.User(req.UserID); ok {
			out.ASCIIPapConfigured = u.Capabilities.Login
			out.ChallengeConfigured = u.Capabilities.Challenge
			out.EnableConfigured = u.Capabilities.Enable
		}
		if req.ClientID != "" {
			if _, ok := snap.Client(req.ClientID); !ok {
				return nil, domain.NewError(domain.CodeNotFound, "client not found").WithPath("client_id")
			}
			if !clientMethodAllowed(snap, req.ClientID, method) {
				out.Status = "restart"
				audit(deps, "api.authentication.tested", "restart", snap.Revision)
				return out, nil
			}
		}

		status := runAuthTest(ctx, deps, snap, req, method)
		out.Status = status
		wipeString(&req.Password)
		if len(req.Data) > 0 {
			for i := range req.Data {
				req.Data[i] = 0
			}
		}
		audit(deps, "api.authentication.tested", status, snap.Revision)
		return out, nil
	}
}

func runAuthTest(ctx context.Context, deps Deps, snap *state.Snapshot, req TestAuthenticationRequest, method config.AuthMethod) string {
	creds := deps.Creds
	if creds == nil {
		// No verifier configured: still fail closed without enumerating users.
		return "fail"
	}
	bound := creds.WithStore(authTestStore{snap: snap, secrets: deps.Secrets, clientID: req.ClientID})
	var err error
	switch method {
	case config.AuthMethodASCII, config.AuthMethodPAP:
		if req.Password == "" && len(req.Data) == 0 {
			return "fail"
		}
		pw := []byte(req.Password)
		if len(req.Data) > 0 {
			pw = append([]byte(nil), req.Data...)
		}
		err = bound.VerifyASCIIOrPAP(ctx, req.UserID, pw)
		wipeBytes(pw)
	case config.AuthMethodEnable:
		if req.Password == "" {
			return "fail"
		}
		pw := []byte(req.Password)
		err = bound.VerifyEnable(ctx, req.UserID, pw)
		wipeBytes(pw)
	case config.AuthMethodCHAP:
		id, chal, resp, splitErr := credentials.SplitCHAPData(req.Data, credentials.DefaultMinCHAPChallenge)
		if splitErr != nil {
			return "error"
		}
		err = bound.VerifyCHAP(ctx, req.UserID, id, chal, resp)
	case config.AuthMethodMSCHAPv1:
		id, chal, resp, splitErr := credentials.SplitMSCHAPv1Data(req.Data)
		if splitErr != nil {
			return "error"
		}
		err = bound.VerifyMSCHAPv1(ctx, req.UserID, id, chal, resp)
	case config.AuthMethodMSCHAPv2:
		id, chal, resp, splitErr := credentials.SplitMSCHAPv2Data(req.Data)
		if splitErr != nil {
			return "error"
		}
		err = bound.VerifyMSCHAPv2(ctx, req.UserID, id, chal, resp)
	}
	if err == nil {
		return "pass"
	}
	return "fail"
}

func clientMethodAllowed(snap *state.Snapshot, clientID string, method config.AuthMethod) bool {
	c, ok := snap.Client(clientID)
	if !ok || !c.Client.Enabled {
		return false
	}
	methods := c.Client.Authentication.AllowedMethods
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

type authTestStore struct {
	snap     *state.Snapshot
	secrets  config.SecretLookup
	clientID string
}

func (s authTestStore) Lookup(userID string) (credentials.Record, bool) {
	if s.snap == nil {
		return credentials.Record{}, false
	}
	u, ok := s.snap.User(userID)
	if !ok {
		return credentials.Record{}, false
	}
	rec := credentials.Record{ID: u.User.ID, Enabled: u.User.Enabled}
	if len(u.User.Restrictions.ClientIDs) > 0 && s.clientID != "" {
		allowed := false
		for _, id := range u.User.Restrictions.ClientIDs {
			if id == s.clientID {
				allowed = true
				break
			}
		}
		rec.Restricted = !allowed
	}
	rec.ValidAfter = u.User.Restrictions.ValidAfter
	rec.ValidBefore = u.User.Restrictions.ValidBefore
	if ref := u.User.Credentials.Login.Verifier; ref.Set() {
		if b, ok := resolveAuthSecret(s.snap, s.secrets, ref); ok {
			rec.Login = credentials.NewLoginVerifier(b)
			wipeBytes(b)
		}
	}
	if ref := u.User.Credentials.Challenge.Secret; ref.Set() {
		if b, ok := resolveAuthSecret(s.snap, s.secrets, ref); ok {
			rec.Challenge = credentials.NewChallengeSecret(b)
			wipeBytes(b)
		}
	}
	if ref := u.User.Credentials.Enable.Verifier; ref.Set() {
		if b, ok := resolveAuthSecret(s.snap, s.secrets, ref); ok {
			rec.Enable = credentials.NewEnableVerifier(b)
			wipeBytes(b)
		}
	}
	return rec, true
}

func resolveAuthSecret(snap *state.Snapshot, lookup config.SecretLookup, ref config.SecretRef) ([]byte, bool) {
	if ref.MemoryID != "" && snap != nil {
		if b, ok := snap.RuntimeSecret(ref.MemoryID); ok {
			return b, true
		}
	}
	if lookup == nil || !ref.Set() || ref.MemoryID != "" {
		return nil, false
	}
	b, err := lookup(ref)
	if err != nil {
		return nil, false
	}
	return b, true
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func wipeString(s *string) {
	if s == nil || *s == "" {
		return
	}
	b := []byte(*s)
	wipeBytes(b)
	*s = ""
}
