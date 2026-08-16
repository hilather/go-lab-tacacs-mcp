package aaa

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	promptUser    = "Username: "
	promptPass    = "Password: "
	promptNewPass = "New Password: "
	promptConfirm = "Retype New Password: "

	serverMsgPasswordChangeRequired = "Password change required"
	reasonPasswordChanged           = "password_changed"
	reasonPasswordChangeRequired    = "password_change_required"
	reasonEnablePasswordChanged     = "enable_password_changed"
)

// BeginAuthentication starts an authentication conversation.
func (s *Service) BeginAuthentication(ctx context.Context, start AuthenticationStart) (AuthenticationStep, error) {
	if s == nil {
		return errorStep(), domain.NewError(domain.CodeInternal, "aaa service is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return errorStep(), err
	}
	if err := checkAuthenFields(s, start.UserID, start.Port, start.Remote); err != nil {
		return errorStep(), err
	}
	key := sessionKey{conn: start.ConnKey, sess: start.SessionID}
	s.dropSession(key)

	snap := s.snap()
	if snap == nil {
		return errorStep(), nil
	}

	flow, term := classifyStart(start)
	if term != 0 {
		s.recordAuth(snap, start, "", eventType(flow, start), term.String())
		return AuthenticationStep{Status: term}, nil
	}
	method := methodForFlow(flow)
	if !methodAllowed(snap, start.ClientID, method) {
		s.recordAuth(snap, start, canonUser(start.UserID), eventType(flow, start), "restart")
		return AuthenticationStep{Status: domain.AuthenStatusRestart}, nil
	}

	switch flow {
	case flowPAP:
		return s.oneShotPAP(ctx, snap, start)
	case flowCHAP:
		return s.oneShotCHAP(ctx, snap, start)
	case flowMSCHAPv1:
		return s.oneShotMSCHAP(ctx, snap, start, false)
	case flowMSCHAPv2:
		return s.oneShotMSCHAP(ctx, snap, start, true)
	case flowASCII, flowEnable, flowCHPASS:
		return s.beginInteractive(start, snap, flow)
	default:
		s.recordAuth(snap, start, canonUser(start.UserID), "unsupported", "error")
		return errorStep(), nil
	}
}

// ContinueAuthentication advances an interactive conversation.
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
		kind := eventType(sess.flow, AuthenticationStart{})
		s.dropSession(key)
		s.recordAuth(sess.snap, AuthenticationStart{
			ClientID:  cont.ClientID,
			SessionID: cont.SessionID,
			Transport: cont.Transport,
			Revision:  cont.Revision,
		}, sess.user, kind, "abort")
		return failStep(), nil
	}
	switch sess.flow {
	case flowASCII:
		return s.continueASCII(ctx, key, sess, cont)
	case flowEnable:
		return s.continueEnable(ctx, key, sess, cont)
	case flowCHPASS:
		return s.continueCHPASS(ctx, key, sess, cont)
	default:
		s.dropSession(key)
		return errorStep(), nil
	}
}

// AbortAuthentication records a redacted abort and drops conversation state.
func (s *Service) AbortAuthentication(_ context.Context, abort AuthenticationAbort) error {
	if s == nil {
		return nil
	}
	key := sessionKey{conn: abort.ConnKey, sess: abort.SessionID}
	sess := s.getSession(key)
	if sess == nil {
		return nil
	}
	kind := eventType(sess.flow, AuthenticationStart{})
	user := sess.user
	snap := sess.snap
	s.dropSession(key)
	s.recordAuth(snap, AuthenticationStart{
		ClientID:  abort.ClientID,
		SessionID: abort.SessionID,
		Revision:  abort.Revision,
	}, user, kind, "abort")
	return nil
}

func (s *Service) beginInteractive(start AuthenticationStart, snap *state.Snapshot, flow authFlow) (AuthenticationStep, error) {
	if flow == flowEnable && start.PrivLvl > uint8(domain.PrivilegeMax) {
		s.recordAuth(snap, start, canonUser(start.UserID), "enable", "fail")
		return failStep(), nil
	}
	user := canonUser(start.UserID)
	bound := snap
	sess := &authSession{
		flow:      flow,
		user:      user,
		clientID:  start.ClientID,
		needUser:  user == "",
		needOld:   flow == flowCHPASS,
		needNew:   flow == flowCHPASS,
		snap:      bound,
		creds:     s.creds.WithStore(snapshotStore{snapshot: func() *state.Snapshot { return bound }, secrets: s.secrets, clientID: start.ClientID}),
		maxRounds: maxRounds(bound),
		rev:       bound.Revision,
	}
	s.putSession(sessionKey{conn: start.ConnKey, sess: start.SessionID}, sess)
	if sess.needUser {
		return userPrompt(), nil
	}
	if flow == flowCHPASS {
		return dataPrompt(), nil
	}
	return passPrompt(), nil
}

func (s *Service) continueASCII(ctx context.Context, key sessionKey, sess *authSession, cont AuthenticationContinue) (AuthenticationStep, error) {
	if sess.needUser {
		sess.user = canonUser(string(cont.UserMsg))
		sess.needUser = false
		s.putSession(key, sess)
		return passPrompt(), nil
	}
	if sess.needNew || sess.needConfirm {
		return s.continueNewConfirm(ctx, key, sess, cont, "ascii_login", s.publishLogin)
	}
	return s.finishPassword(ctx, key, sess, cont, false)
}

func (s *Service) continueEnable(ctx context.Context, key sessionKey, sess *authSession, cont AuthenticationContinue) (AuthenticationStep, error) {
	if sess.needUser {
		sess.user = canonUser(string(cont.UserMsg))
		sess.needUser = false
		s.putSession(key, sess)
		return passPrompt(), nil
	}
	if sess.needNew || sess.needConfirm {
		return s.continueNewConfirm(ctx, key, sess, cont, "enable", s.publishEnable)
	}
	return s.finishPassword(ctx, key, sess, cont, true)
}

func (s *Service) finishPassword(ctx context.Context, key sessionKey, sess *authSession, cont AuthenticationContinue, enable bool) (AuthenticationStep, error) {
	pw := append([]byte(nil), cont.UserMsg...)
	verifier := sess.creds
	if verifier == nil {
		verifier = s.creds
	}
	var err error
	if enable {
		err = verifier.VerifyEnable(ctx, sess.user, pw)
	} else {
		err = verifier.VerifyASCIIOrPAP(ctx, sess.user, pw)
	}
	wipe(pw)
	kind := "ascii_login"
	if enable {
		kind = "enable"
	}
	if err == nil {
		if !enable && userMustChangeLogin(sess.snap, sess.user) {
			if !asciiChpassAllowed(sess.snap, sess.clientID) {
				s.dropSession(key)
				s.recordAuthReason(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, kind, "fail", reasonPasswordChangeRequired)
				return failStepMsg(serverMsgPasswordChangeRequired), nil
			}
			sess.needNew = true
			sess.fails = 0
			s.putSession(key, sess)
			return newPassPrompt(), nil
		}
		if enable && userMustChangeEnable(sess.snap, sess.user) {
			sess.needNew = true
			sess.fails = 0
			s.putSession(key, sess)
			return newPassPrompt(), nil
		}
		s.dropSession(key)
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, kind, "pass")
		return passStep(), nil
	}
	if protoError(err) {
		s.dropSession(key)
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, kind, "error")
		return errorStep(), nil
	}
	return s.retryOrFail(key, sess, cont, kind, passPrompt())
}

func (s *Service) continueCHPASS(ctx context.Context, key sessionKey, sess *authSession, cont AuthenticationContinue) (AuthenticationStep, error) {
	if sess.needUser {
		sess.user = canonUser(string(cont.UserMsg))
		sess.needUser = false
		s.putSession(key, sess)
		return dataPrompt(), nil
	}
	if sess.needOld {
		old := append([]byte(nil), cont.UserMsg...)
		err := sess.creds.VerifyASCIIOrPAP(ctx, sess.user, old)
		if protoError(err) {
			wipe(old)
			s.dropSession(key)
			s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, "ascii_chpass", "error")
			return errorStep(), nil
		}
		if err != nil {
			wipe(old)
			return s.retryOrFail(key, sess, cont, "ascii_chpass", dataPrompt())
		}
		wipe(old)
		sess.needOld = false
		sess.fails = 0
		s.putSession(key, sess)
		return passPrompt(), nil
	}
	if sess.needNew {
		if len(cont.UserMsg) == 0 {
			s.dropSession(key)
			s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, "ascii_chpass", "fail")
			return failStep(), nil
		}
		wipe(sess.newPass)
		sess.newPass = append([]byte(nil), cont.UserMsg...)
		sess.needNew = false
		sess.needConfirm = true
		s.putSession(key, sess)
		return passPrompt(), nil
	}
	if !sess.needConfirm {
		s.dropSession(key)
		return errorStep(), nil
	}
	if subtle.ConstantTimeCompare(sess.newPass, cont.UserMsg) != 1 {
		s.dropSession(key)
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, "ascii_chpass", "fail")
		return failStep(), nil
	}
	derived, err := sess.creds.DeriveLoginVerifier(ctx, sess.newPass)
	wipe(sess.newPass)
	sess.newPass = nil
	if err != nil {
		s.dropSession(key)
		if protoError(err) {
			s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, "ascii_chpass", "error")
			return errorStep(), nil
		}
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, "ascii_chpass", "fail")
		return failStep(), nil
	}
	phc := derived.Bytes()
	step := s.publishLogin(sess, cont, phc, "ascii_chpass")
	wipe(phc)
	return step, nil
}

func (s *Service) continueNewConfirm(ctx context.Context, key sessionKey, sess *authSession, cont AuthenticationContinue, eventType string, publish func(*authSession, AuthenticationContinue, []byte, string) AuthenticationStep) (AuthenticationStep, error) {
	if sess.needNew {
		if len(cont.UserMsg) == 0 {
			s.dropSession(key)
			s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "fail")
			return failStep(), nil
		}
		wipe(sess.newPass)
		sess.newPass = append([]byte(nil), cont.UserMsg...)
		sess.needNew = false
		sess.needConfirm = true
		s.putSession(key, sess)
		return confirmPassPrompt(), nil
	}
	if !sess.needConfirm {
		s.dropSession(key)
		return errorStep(), nil
	}
	if subtle.ConstantTimeCompare(sess.newPass, cont.UserMsg) != 1 {
		s.dropSession(key)
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "fail")
		return failStep(), nil
	}
	phc, err := deriveChangePHC(ctx, sess.creds, sess.newPass, eventType == "enable")
	wipe(sess.newPass)
	sess.newPass = nil
	if err != nil {
		s.dropSession(key)
		if protoError(err) {
			s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "error")
			return errorStep(), nil
		}
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "fail")
		return failStep(), nil
	}
	step := publish(sess, cont, phc, eventType)
	wipe(phc)
	return step, nil
}

func deriveChangePHC(ctx context.Context, creds *credentials.Service, password []byte, enable bool) ([]byte, error) {
	if enable {
		derived, err := creds.DeriveEnableVerifier(ctx, password)
		if err != nil {
			return nil, err
		}
		return derived.Bytes(), nil
	}
	derived, err := creds.DeriveLoginVerifier(ctx, password)
	if err != nil {
		return nil, err
	}
	return derived.Bytes(), nil
}

func (s *Service) publishLogin(sess *authSession, cont AuthenticationContinue, phc []byte, eventType string) AuthenticationStep {
	if eventType == "" {
		eventType = "ascii_chpass"
	}
	if s.mgr == nil {
		s.dropSession(sessionKey{conn: cont.ConnKey, sess: cont.SessionID})
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "error")
		return errorStep()
	}
	expected := sess.rev
	_, err := s.mgr.OverrideLoginVerifier(sess.user, phc, &expected)
	s.dropSession(sessionKey{conn: cont.ConnKey, sess: cont.SessionID})
	if err != nil {
		if de, ok := domain.AsError(err); ok && (de.Code == domain.CodeConflict || de.Code == domain.CodeNotFound) {
			s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "fail")
			return failStep()
		}
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "error")
		return errorStep()
	}
	s.recordAuthReason(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "pass", reasonPasswordChanged)
	return passStep()
}

func (s *Service) publishEnable(sess *authSession, cont AuthenticationContinue, phc []byte, eventType string) AuthenticationStep {
	if eventType == "" {
		eventType = "enable"
	}
	if s.mgr == nil {
		s.dropSession(sessionKey{conn: cont.ConnKey, sess: cont.SessionID})
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "error")
		return errorStep()
	}
	expected := sess.rev
	_, err := s.mgr.OverrideEnableVerifier(sess.user, phc, &expected)
	s.dropSession(sessionKey{conn: cont.ConnKey, sess: cont.SessionID})
	if err != nil {
		if de, ok := domain.AsError(err); ok && (de.Code == domain.CodeConflict || de.Code == domain.CodeNotFound) {
			s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "fail")
			return failStep()
		}
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "error")
		return errorStep()
	}
	s.recordAuthReason(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, eventType, "pass", reasonEnablePasswordChanged)
	return passStep()
}

func (s *Service) retryOrFail(key sessionKey, sess *authSession, cont AuthenticationContinue, kind string, retry AuthenticationStep) (AuthenticationStep, error) {
	sess.fails++
	limit := sess.maxRounds
	if limit <= 0 {
		limit = maxRounds(sess.snap)
	}
	if sess.fails >= limit {
		s.dropSession(key)
		s.recordAuth(sess.snap, AuthenticationStart{ClientID: sess.clientID, SessionID: cont.SessionID, Transport: cont.Transport, Revision: cont.Revision}, sess.user, kind, "fail")
		return failStep(), nil
	}
	s.putSession(key, sess)
	return retry, nil
}

func (s *Service) oneShotPAP(ctx context.Context, snap *state.Snapshot, start AuthenticationStart) (AuthenticationStep, error) {
	user := canonUser(start.UserID)
	if user == "" || len(start.Data) == 0 {
		s.recordAuth(snap, start, user, "pap_login", "fail")
		return failStep(), nil
	}
	pw := credentials.NewPassword(start.Data)
	outcome := s.verifyAgainst(ctx, snap, user, start.ClientID, CredentialEvidence{
		Method:   domain.AuthMethodPassword,
		Password: pw,
	})
	pw.Wipe()
	return s.finishOneShotOutcome(snap, start, user, "pap_login", outcome), nil
}

func (s *Service) oneShotCHAP(ctx context.Context, snap *state.Snapshot, start AuthenticationStart) (AuthenticationStep, error) {
	user := canonUser(start.UserID)
	min := credentials.DefaultMinCHAPChallenge
	id, chal, resp, err := credentials.SplitCHAPData(start.Data, min)
	if err != nil {
		s.recordAuth(snap, start, user, "chap_login", "error")
		return errorStep(), nil
	}
	if user == "" {
		s.recordAuth(snap, start, user, "chap_login", "fail")
		return failStep(), nil
	}
	outcome := s.verifyAgainst(ctx, snap, user, start.ClientID, CredentialEvidence{
		Method:    domain.AuthMethodCHAP,
		CHAPID:    id,
		Challenge: chal,
		Response:  resp,
	})
	return s.finishOneShotOutcome(snap, start, user, "chap_login", outcome), nil
}

func (s *Service) oneShotMSCHAP(ctx context.Context, snap *state.Snapshot, start AuthenticationStart, v2 bool) (AuthenticationStep, error) {
	user := canonUser(start.UserID)
	kind := "mschapv1_login"
	var (
		id   byte
		chal []byte
		resp []byte
		err  error
	)
	if v2 {
		kind = "mschapv2_login"
		id, chal, resp, err = credentials.SplitMSCHAPv2Data(start.Data)
	} else {
		id, chal, resp, err = credentials.SplitMSCHAPv1Data(start.Data)
	}
	if err != nil {
		s.recordAuth(snap, start, user, kind, "error")
		return errorStep(), nil
	}
	// Verify before empty-user FAIL so reserved/flags shape is ERROR for every identity.
	creds := s.boundCreds(snap, start.ClientID)
	var ver error
	if v2 {
		ver = creds.VerifyMSCHAPv2(ctx, user, id, chal, resp)
	} else {
		ver = creds.VerifyMSCHAPv1(ctx, user, id, chal, resp)
	}
	if protoError(ver) {
		return s.finishOneShot(snap, start, user, kind, ver), nil
	}
	if user == "" {
		s.recordAuth(snap, start, user, kind, "fail")
		return failStep(), nil
	}
	return s.finishOneShot(snap, start, user, kind, ver), nil
}

func (s *Service) finishOneShot(snap *state.Snapshot, start AuthenticationStart, user, kind string, err error) AuthenticationStep {
	return s.finishOneShotOutcome(snap, start, user, kind, outcomeFromCreds(err))
}

func (s *Service) finishOneShotOutcome(snap *state.Snapshot, start AuthenticationStart, user, kind string, outcome domain.AuthOutcome) AuthenticationStep {
	switch outcome {
	case domain.AuthPass:
		if userMustChangeLogin(snap, user) {
			s.recordAuthReason(snap, start, user, kind, "fail", reasonPasswordChangeRequired)
			return failStepMsg(serverMsgPasswordChangeRequired)
		}
		s.recordAuth(snap, start, user, kind, "pass")
		return passStep()
	case domain.AuthError:
		s.recordAuth(snap, start, user, kind, "error")
		return errorStep()
	default:
		s.recordAuth(snap, start, user, kind, "fail")
		return failStep()
	}
}

func (s *Service) boundCreds(snap *state.Snapshot, clientID string) *credentials.Service {
	bound := snap
	return s.creds.WithStore(snapshotStore{
		snapshot: func() *state.Snapshot { return bound },
		secrets:  s.secrets,
		clientID: clientID,
	})
}

func classifyStart(start AuthenticationStart) (authFlow, domain.AuthenStatus) {
	switch start.Action {
	case domain.AuthenActionSendAuth, domain.AuthenActionSendPass:
		return flowNone, domain.AuthenStatusError
	case domain.AuthenActionCHPASS:
		if start.Service == domain.AuthenServiceEnable {
			return flowNone, domain.AuthenStatusFail
		}
		if start.Type != domain.AuthenTypeASCII {
			return flowNone, domain.AuthenStatusError
		}
		if start.Service == domain.AuthenServiceNone || !start.Service.Valid() {
			return flowNone, domain.AuthenStatusFail
		}
		return flowCHPASS, 0
	case domain.AuthenActionLogin:
		if start.Service == domain.AuthenServiceEnable {
			return flowEnable, 0
		}
		if start.Service == domain.AuthenServiceNone || !start.Service.Valid() {
			return flowNone, domain.AuthenStatusFail
		}
		switch start.Type {
		case domain.AuthenTypeASCII:
			return flowASCII, 0
		case domain.AuthenTypePAP:
			return flowPAP, 0
		case domain.AuthenTypeCHAP:
			return flowCHAP, 0
		case domain.AuthenTypeMSCHAP:
			return flowMSCHAPv1, 0
		case domain.AuthenTypeMSCHAPV2:
			return flowMSCHAPv2, 0
		default:
			return flowNone, domain.AuthenStatusError
		}
	default:
		return flowNone, domain.AuthenStatusError
	}
}

const (
	flowNone     authFlow = 255
	flowPAP      authFlow = 10
	flowCHAP     authFlow = 11
	flowMSCHAPv1 authFlow = 12
	flowMSCHAPv2 authFlow = 13
)

func methodForFlow(flow authFlow) config.AuthMethod {
	switch flow {
	case flowASCII:
		return config.AuthMethodASCII
	case flowPAP:
		return config.AuthMethodPAP
	case flowCHAP:
		return config.AuthMethodCHAP
	case flowMSCHAPv1:
		return config.AuthMethodMSCHAPv1
	case flowMSCHAPv2:
		return config.AuthMethodMSCHAPv2
	case flowEnable:
		return config.AuthMethodEnable
	case flowCHPASS:
		return config.AuthMethodASCIIChpass
	default:
		return ""
	}
}

func methodAllowed(snap *state.Snapshot, clientID string, method config.AuthMethod) bool {
	if snap == nil || clientID == "" || method == "" {
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
		if m == method {
			return true
		}
	}
	return false
}

func eventType(flow authFlow, start AuthenticationStart) string {
	switch flow {
	case flowASCII:
		return "ascii_login"
	case flowPAP:
		return "pap_login"
	case flowCHAP:
		return "chap_login"
	case flowMSCHAPv1:
		return "mschapv1_login"
	case flowMSCHAPv2:
		return "mschapv2_login"
	case flowEnable:
		return "enable"
	case flowCHPASS:
		return "ascii_chpass"
	default:
		if start.Action == domain.AuthenActionSendAuth {
			return "sendauth"
		}
		if start.Action == domain.AuthenActionSendPass {
			return "sendpass"
		}
		return "authen"
	}
}

func (s *Service) recordAuth(snap *state.Snapshot, start AuthenticationStart, user, kind, result string) {
	s.recordAuthReason(snap, start, user, kind, result, "")
}

func (s *Service) recordAuthReason(snap *state.Snapshot, start AuthenticationStart, user, kind, result, reason string) {
	s.metrics.Authen(string(start.Transport), kind, result)
	if snap != nil && snap.Settings() != nil {
		ev := snap.Settings().Events
		ok := ev.IncludeFailedAuthentication
		if result == "pass" {
			ok = ev.IncludeSuccessfulAuthentication
		}
		if !ok {
			return
		}
	}
	s.record(events.Event{
		Category:   events.CategoryAuthen,
		Type:       kind,
		Result:     result,
		Transport:  string(start.Transport),
		ClientID:   start.ClientID,
		SessionID:  start.SessionID,
		Revision:   start.Revision,
		UserID:     user,
		ReasonCode: reason,
	}, false)
}

func userMustChangeLogin(snap *state.Snapshot, userID string) bool {
	if snap == nil || userID == "" {
		return false
	}
	u, ok := snap.User(userID)
	return ok && u.User.MustChangeLogin
}

func userMustChangeEnable(snap *state.Snapshot, userID string) bool {
	if snap == nil || userID == "" {
		return false
	}
	u, ok := snap.User(userID)
	return ok && u.User.MustChangeEnable
}

func asciiChpassAllowed(snap *state.Snapshot, clientID string) bool {
	return methodAllowed(snap, clientID, config.AuthMethodASCIIChpass)
}

func protoError(err error) bool {
	var ae credentials.AuthError
	return errors.As(err, &ae) && (ae.Kind == credentials.KindMalformed || ae.Kind == credentials.KindInvalid)
}

func canonUser(user string) string {
	if user == "" {
		return ""
	}
	if canon, err := credentials.CanonicalUsername(user); err == nil {
		return canon
	}
	return user
}

func errorStep() AuthenticationStep {
	return AuthenticationStep{Status: domain.AuthenStatusError}
}

func checkAuthenFields(s *Service, user, port, remote string) error {
	maxUser, maxPort, maxRemote := 253, 253, 253
	if snap := s.snap(); snap != nil && snap.Settings() != nil {
		lim := snap.Settings().Limits
		if lim.MaxUsernameBytes > 0 {
			maxUser = lim.MaxUsernameBytes
		}
		if lim.MaxPortBytes > 0 {
			maxPort = lim.MaxPortBytes
		}
		if lim.MaxRemoteAddressBytes > 0 {
			maxRemote = lim.MaxRemoteAddressBytes
		}
	}
	if err := observability.CheckBytes("user", []byte(user), maxUser); err != nil {
		return err
	}
	if err := observability.CheckBytes("port", []byte(port), maxPort); err != nil {
		return err
	}
	return observability.CheckBytes("rem_addr", []byte(remote), maxRemote)
}

func failStep() AuthenticationStep {
	return AuthenticationStep{Status: domain.AuthenStatusFail}
}

func failStepMsg(msg string) AuthenticationStep {
	return AuthenticationStep{Status: domain.AuthenStatusFail, ServerMsg: msg}
}

func passStep() AuthenticationStep {
	return AuthenticationStep{Status: domain.AuthenStatusPass}
}

func userPrompt() AuthenticationStep {
	return AuthenticationStep{Status: domain.AuthenStatusGetUser, ServerMsg: promptUser}
}

func passPrompt() AuthenticationStep {
	return AuthenticationStep{Status: domain.AuthenStatusGetPass, NoEcho: true, ServerMsg: promptPass}
}

func dataPrompt() AuthenticationStep {
	return AuthenticationStep{Status: domain.AuthenStatusGetData, NoEcho: true, ServerMsg: promptPass}
}

func newPassPrompt() AuthenticationStep {
	return AuthenticationStep{Status: domain.AuthenStatusGetPass, NoEcho: true, ServerMsg: promptNewPass}
}

func confirmPassPrompt() AuthenticationStep {
	return AuthenticationStep{Status: domain.AuthenStatusGetPass, NoEcho: true, ServerMsg: promptConfirm}
}
