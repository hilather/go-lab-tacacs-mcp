package aaa

import (
	"context"
	"errors"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// BeginAuthentication starts an authentication conversation.
func (s *Service) BeginAuthentication(ctx context.Context, start AuthenticationStart) (AuthenticationStep, error) {
	if s == nil {
		return errorStep(), domain.NewError(domain.CodeInternal, "aaa service is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return errorStep(), err
	}
	key := sessionKey{conn: start.ConnKey, sess: start.SessionID}
	s.dropSession(key)

	snap := s.snap()
	if snap == nil {
		return errorStep(), nil
	}

	// ENABLE ignores type at the codec. AAA still treats ENABLE as unimplemented
	// in this skeleton (PR-11). ASCII LOGIN is the only implemented flow.
	if start.Action != domain.AuthenActionLogin || start.Service == domain.AuthenServiceEnable {
		s.recordAuth(snap, start.ClientID, start.UserID, start.SessionID, start.Transport, start.Revision, "error")
		return errorStep(), nil
	}
	if start.Type != domain.AuthenTypeASCII {
		s.recordAuth(snap, start.ClientID, start.UserID, start.SessionID, start.Transport, start.Revision, "error")
		return errorStep(), nil
	}
	if !asciiAllowed(snap, start.ClientID) {
		s.recordAuth(snap, start.ClientID, start.UserID, start.SessionID, start.Transport, start.Revision, "restart")
		return AuthenticationStep{Status: domain.AuthenStatusRestart}, nil
	}

	user := start.UserID
	if user != "" {
		if canon, err := credentials.CanonicalUsername(user); err == nil {
			user = canon
		}
	}
	sess := &asciiSession{user: user, clientID: start.ClientID, needUser: user == "", needPass: true}
	s.putSession(key, sess)
	if sess.needUser {
		return AuthenticationStep{Status: domain.AuthenStatusGetUser}, nil
	}
	return AuthenticationStep{Status: domain.AuthenStatusGetPass, NoEcho: true}, nil
}

// ContinueAuthentication advances an ASCII LOGIN conversation.
func (s *Service) ContinueAuthentication(ctx context.Context, cont AuthenticationContinue) (AuthenticationStep, error) {
	if s == nil {
		return errorStep(), domain.NewError(domain.CodeInternal, "aaa service is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return errorStep(), err
	}
	key := sessionKey{conn: cont.ConnKey, sess: cont.SessionID}
	sess := s.getSession(key)
	if sess == nil {
		return errorStep(), nil
	}
	if cont.Abort {
		s.dropSession(key)
		snap := s.snap()
		s.recordAuth(snap, cont.ClientID, sess.user, cont.SessionID, cont.Transport, cont.Revision, "abort")
		return AuthenticationStep{Status: domain.AuthenStatusFail}, nil
	}
	snap := s.snap()
	if sess.needUser {
		user := string(cont.UserMsg)
		if canon, err := credentials.CanonicalUsername(user); err == nil {
			user = canon
		}
		sess.user = user
		sess.needUser = false
		sess.needPass = true
		s.putSession(key, sess)
		return AuthenticationStep{Status: domain.AuthenStatusGetPass, NoEcho: true}, nil
	}
	if !sess.needPass {
		s.dropSession(key)
		return errorStep(), nil
	}

	pw := append([]byte(nil), cont.UserMsg...)
	err := s.creds.VerifyASCIIOrPAP(ctx, sess.user, pw)
	wipe(pw)
	if err == nil {
		s.dropSession(key)
		s.recordAuth(snap, sess.clientID, sess.user, cont.SessionID, cont.Transport, cont.Revision, "pass")
		return AuthenticationStep{Status: domain.AuthenStatusPass}, nil
	}
	// Malformed material is protocol ERROR; every other credential result is FAIL.
	var ae credentials.AuthError
	if errors.As(err, &ae) && (ae.Kind == credentials.KindMalformed || ae.Kind == credentials.KindInvalid) {
		s.dropSession(key)
		s.recordAuth(snap, sess.clientID, sess.user, cont.SessionID, cont.Transport, cont.Revision, "error")
		return errorStep(), nil
	}
	sess.fails++
	if sess.fails >= maxRounds(snap) {
		s.dropSession(key)
		s.recordAuth(snap, sess.clientID, sess.user, cont.SessionID, cont.Transport, cont.Revision, "fail")
		return AuthenticationStep{Status: domain.AuthenStatusFail}, nil
	}
	s.putSession(key, sess)
	return AuthenticationStep{Status: domain.AuthenStatusGetPass, NoEcho: true}, nil
}

// AbortAuthentication records a redacted abort and drops conversation state.
func (s *Service) AbortAuthentication(_ context.Context, abort AuthenticationAbort) error {
	if s == nil {
		return nil
	}
	key := sessionKey{conn: abort.ConnKey, sess: abort.SessionID}
	sess := s.getSession(key)
	s.dropSession(key)
	user := ""
	if sess != nil {
		user = sess.user
	}
	s.recordAuth(s.snap(), abort.ClientID, user, abort.SessionID, "", abort.Revision, "abort")
	return nil
}

func errorStep() AuthenticationStep {
	return AuthenticationStep{Status: domain.AuthenStatusError}
}

func asciiAllowed(snap *state.Snapshot, clientID string) bool {
	if snap == nil || clientID == "" {
		return true
	}
	c, ok := snap.Client(clientID)
	if !ok || !c.Client.Enabled {
		return false
	}
	methods := c.Client.Authentication.AllowedMethods
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if m == config.AuthMethodASCII {
			return true
		}
	}
	return false
}

func (s *Service) recordAuth(snap *state.Snapshot, clientID, user string, sessionID uint32, transport domain.Transport, rev domain.Revision, result string) {
	s.record(events.Event{
		Category:  "authen",
		Type:      "ascii_login",
		Result:    result,
		Transport: string(transport),
		ClientID:  clientID,
		SessionID: sessionID,
		Revision:  rev,
		UserID:    user,
	}, redactUserInput(snap))
}
