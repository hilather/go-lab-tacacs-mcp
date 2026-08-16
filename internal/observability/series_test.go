package observability_test

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
)

func TestKnownReasonCodeCoversServerAndAccessReasons(t *testing.T) {
	t.Parallel()
	// Every Reason* / AccessReason* value must stay in the §5.7 metrics
	// allowlist so boundReasonCode does not collapse a new reject to
	// internal_error.
	codes := []string{
		server.ReasonUnknownClient,
		server.ReasonAmbiguousClient,
		server.ReasonMalformedHeader,
		server.ReasonInvalidLength,
		server.ReasonInvalidCode,
		server.ReasonInvalidAcctAuth,
		server.ReasonInvalidMA,
		server.ReasonMissingMA,
		server.ReasonEAPWithoutMA,
		server.ReasonProxyStateWithoutMA,
		server.ReasonUnknownAcctStatus,
		server.ReasonAmbiguousIdentity,
		server.ReasonOverload,
		server.ReasonMissingUsername,
		server.ReasonConflictingAuth,
		server.ReasonCHAPPasswordLength,
		server.ReasonUnsupportedMethod,
		server.ReasonBadCredentials,
		server.ReasonPasswordChangeRequired,
		server.ReasonPolicy,
		server.ReasonInternal,
		server.ReasonOK,
		aaa.AccessReasonOK,
		aaa.AccessReasonBadCredentials,
		aaa.AccessReasonPolicy,
		aaa.AccessReasonUnsupportedMethod,
		aaa.AccessReasonInternal,
		aaa.AccessReasonPasswordChangeRequired,
		server.ReasonInvalidState,
		server.ReasonChallengeExpired,
		server.ReasonChallengeBinding,
		server.ReasonChallengeCapacity,
		server.ReasonChallenge,
		server.ReasonUnsupportedEAPMethod,
		server.ReasonEAPTooLong,
		aaa.AccessReasonInvalidState,
		aaa.AccessReasonChallengeExpired,
		aaa.AccessReasonChallengeBinding,
		aaa.AccessReasonChallengeCapacity,
		aaa.AccessReasonChallenge,
		aaa.AccessReasonUnsupportedEAPMethod,
		aaa.AccessReasonEAPTooLong,
		server.ReasonSessionNotFound,
		server.ReasonUnsupportedAttribute,
		server.ReasonMultipleSessions,
	}
	for _, code := range codes {
		reg := observability.NewRegistry()
		reg.Inc(observability.MetricProtocolDiscards, observability.Labels{
			observability.LabelProtocol:   observability.ProtocolRADIUS,
			observability.LabelTransport:  observability.TransportUDP,
			observability.LabelRole:       observability.RoleAccess,
			observability.LabelReasonCode: code,
		}, 1)
		if reg.DroppedLabels() != 0 {
			t.Errorf("knownReasonCode missing %q", code)
		}
	}
}

func TestInboundDASMetricsLabelsAreAllowed(t *testing.T) {
	t.Parallel()
	reg := observability.NewRegistry()
	rec := observability.NewRecorder(reg)
	rec.ProtocolRequest(
		observability.ProtocolRADIUS,
		observability.TransportUDP,
		observability.RoleDynamicAuthorization,
		observability.CodeCoARequest,
		observability.OutcomeACK,
		0.001,
	)
	rec.ProtocolRequest(
		observability.ProtocolRADIUS,
		observability.TransportUDP,
		observability.RoleDynamicAuthorization,
		observability.CodeDisconnectRequest,
		observability.OutcomeNAK,
		0.001,
	)
	rec.RADIUSDynAuth(observability.DirectionIn, observability.CodeCoARequest, observability.OutcomeACK)
	rec.RADIUSDynAuth(observability.DirectionIn, observability.CodeDisconnectRequest, observability.OutcomeNAK)
	rec.RADIUSDynAuth(observability.DirectionOut, observability.CodeCoARequest, observability.OutcomeTimeout)
	if reg.DroppedLabels() != 0 {
		t.Fatalf("inbound DAS metrics dropped labels: %d", reg.DroppedLabels())
	}
}
