package observability

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestCanaryMatrixObservabilitySurfaces(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	rec := NewRecorder(reg)

	// Attempt to plant canaries as labels — must drop.
	rec.SetSecretLifecycle(map[string]int{StatusCurrent: 1})
	reg.Set(MetricSecretLifecycle, Labels{LabelStatus: StatusCurrent, LabelClientID: CanaryLegacyShared}, 1)
	reg.Inc(MetricAuthenTotal, Labels{LabelTransport: TransportLegacy, LabelAuthenType: "ascii", "username": CanaryPassword}, 1)
	reg.Inc(MetricAPIRequests, Labels{LabelOperationID: "tokens.create", LabelResultClass: ResultSuccess, "token": CanaryToken}, 1)
	reg.Inc(MetricSecretWarnings, Labels{LabelStatus: StatusOverdue, "fingerprint": CanaryLegacyShared}, 1)
	reg.Inc(MetricProtocolDiscards, Labels{
		LabelProtocol: ProtocolRADIUS, LabelTransport: TransportUDP, LabelRole: RoleAccess,
		LabelReasonCode: "discard_unknown_client", LabelClientID: CanaryRADIUSShared,
	}, 1)
	reg.Inc(MetricProtocolRequests, Labels{
		LabelProtocol: ProtocolRADIUS, LabelTransport: TransportUDP, LabelRole: RoleAccess,
		LabelPacketCode: CodeAccessRequest, LabelOutcome: OutcomeAccessReject,
		"user_password": CanaryUserPassword,
		"mschap":        CanaryMSCHAP,
	}, 1)
	rec.ProtocolDiscard(ProtocolRADIUS, TransportUDP, RoleAccess, "discard_unknown_client")

	var metrics bytes.Buffer
	if err := reg.WritePrometheus(&metrics); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	lg := NewJSONLogger(&logs, slog.LevelInfo)
	lg.Info("reload", slog.String("result", "error"), slog.String("listener", ListenerLegacy))
	lg.Error("panic recover", slog.String("err", "panic"))

	tr := NewTracer(true)
	_, sp := tr.Start(context.Background(), "authen",
		Attr{Key: "password", Value: CanaryPassword},
		Attr{Key: "secret", Value: CanaryChallenge},
		Attr{Key: "token", Value: CanaryToken},
		Attr{Key: "packet_body", Value: CanaryLegacyShared},
		Attr{Key: "user_password", Value: CanaryUserPassword},
		Attr{Key: "mschap", Value: CanaryMSCHAP},
		Attr{Key: "radius_secret", Value: CanaryRADIUSShared},
		Attr{Key: "transport", Value: TransportLegacy},
	)
	sp.RecordError(fmt.Errorf("verify failed"))
	sp.End()
	var traces bytes.Buffer
	for _, s := range tr.FinishedSpans() {
		fmt.Fprintf(&traces, "%s %s %s\n", s.Name, s.Err, formatAttrs(s.Attrs))
	}

	panicText := recoverCanary(t)

	surfaces := []struct {
		name string
		blob string
	}{
		{"metrics", metrics.String()},
		{"logs", logs.String()},
		{"traces", traces.String()},
		{"panic", panicText},
	}
	for _, s := range surfaces {
		if hits := ScanCanaries(s.blob); len(hits) > 0 {
			t.Error(FormatHits(s.name, hits) + "\n" + s.blob)
		}
	}
}

func formatAttrs(attrs []Attr) string {
	var b strings.Builder
	for _, a := range attrs {
		fmt.Fprintf(&b, "%s=%s;", a.Key, a.Value)
	}
	return b.String()
}

func recoverCanary(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	lg := NewJSONLogger(&buf, slog.LevelError)
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				lg.Error("recovered", slog.String("err", "panic"))
			}
		}()
		panic(CanaryPassword)
	}()
	// Recovery must not stringify the panic value into logs.
	return buf.String()
}

func TestScanCanariesAllowlist(t *testing.T) {
	t.Parallel()
	blob := "issued " + CanaryToken
	if hits := ScanCanaries(blob, CanaryToken); len(hits) != 0 {
		t.Fatalf("allowlist failed: %v", hits)
	}
	if hits := ScanCanaries(blob); len(hits) != 1 {
		t.Fatalf("expected one hit, got %v", hits)
	}
}
