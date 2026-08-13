package observability

import (
	"bytes"
	"strings"
	"testing"
)

func TestRequiredSeriesPresent(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	var buf bytes.Buffer
	if err := reg.WritePrometheus(&buf); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	required := []string{
		MetricConnectionsActive, MetricConnectionsAccepted, MetricConnectionsRejected,
		MetricSessionsActive, MetricAuthenTotal, MetricAuthorTotal, MetricAcctTotal,
		MetricProtocolErrors, MetricAPIRequests, MetricAPIDuration, MetricMCPTools,
		MetricMCPDuration, MetricStateRevision, MetricReloadTotal,
		MetricSecretLifecycle, MetricSecretWarnings, MetricEventSubscribers,
		MetricEventOverwritten, MetricEventSubscriberResets,
		MetricGoGoroutines, MetricGoMemAllocBytes,
	}
	for _, name := range required {
		if !strings.Contains(text, name) {
			t.Errorf("missing series %s", name)
		}
	}
	for _, st := range SecretLifecycleStatuses {
		want := `taclab_secret_lifecycle{status="` + st + `"}`
		if !strings.Contains(text, want) {
			t.Errorf("missing lifecycle gauge %s", want)
		}
	}
}

func TestLifecycleRejectsClientID(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Set(MetricSecretLifecycle, Labels{LabelStatus: StatusOverdue, LabelClientID: "lab-switches"}, 9)
	reg.Inc(MetricSecretWarnings, Labels{LabelStatus: StatusOverdue, LabelClientID: "lab-switches"}, 1)
	reg.Inc(MetricSecretWarnings, Labels{LabelStatus: StatusOverdue, "fingerprint": "deadbeef"}, 1)
	if reg.DroppedLabels() < 3 {
		t.Fatalf("expected dropped lifecycle labels, got %d", reg.DroppedLabels())
	}
	var buf bytes.Buffer
	if err := reg.WritePrometheus(&buf); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	if strings.Contains(text, "client_id") {
		t.Fatalf("client_id leaked onto scrape:\n%s", text)
	}
	if strings.Contains(text, "fingerprint") || strings.Contains(text, "lab-switches") {
		t.Fatalf("forbidden label leaked:\n%s", text)
	}
	if !strings.Contains(text, `taclab_secret_lifecycle{status="overdue"} 0`) {
		t.Fatalf("overdue gauge should stay 0 after rejected write:\n%s", text)
	}
}

func TestForbiddenLabelsDropped(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Inc(MetricAuthenTotal, Labels{LabelTransport: TransportLegacy, LabelAuthenType: "ascii", "username": "alice"}, 1)
	reg.Inc(MetricAPIRequests, Labels{LabelOperationID: "users.list", LabelResultClass: ResultSuccess, "token_id": "tok"}, 1)
	reg.Inc(MetricProtocolErrors, Labels{LabelListener: ListenerLegacy, LabelTransport: TransportLegacy, "command": "show run"}, 1)
	if reg.DroppedLabels() < 3 {
		t.Fatalf("dropped=%d", reg.DroppedLabels())
	}
	var buf bytes.Buffer
	_ = reg.WritePrometheus(&buf)
	if strings.Contains(buf.String(), "alice") || strings.Contains(buf.String(), "show run") || strings.Contains(buf.String(), "tok") {
		t.Fatalf("unbounded label leaked:\n%s", buf.String())
	}
}

func TestRecorderEmitsBoundedLabels(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	rec := NewRecorder(reg)
	rec.ConnectionAccepted(ListenerLegacy, TransportLegacy)
	rec.Authen(TransportLegacy, "ascii_login", "pass")
	rec.Author(TransportTLS, "permit_add")
	rec.Acct(TransportLegacy, "success")
	rec.API("system.status.get", ResultSuccess, "none", 0.002)
	rec.MCP("users.list", ResultSuccess, "none", 0.01)
	rec.SetRevision(4)
	rec.Reload(true)
	rec.SetSecretLifecycle(map[string]int{StatusCurrent: 2, StatusOverdue: 1})
	rec.SecretWarning(StatusOverdue)
	rec.SetEventSubscribers(3)
	rec.EventOverwritten(5)
	rec.EventSubscriberReset()
	rec.ConnectionClosed(ListenerLegacy, TransportLegacy)

	var buf bytes.Buffer
	if err := reg.WritePrometheus(&buf); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	for _, want := range []string{
		`taclab_connections_accepted_total{listener="legacy_tacacs",transport="legacy"} 1`,
		`taclab_authen_total{authen_type="ascii",result_class="success",transport="legacy"} 1`,
		`taclab_author_total{result_class="permit_add",transport="tls"} 1`,
		`taclab_acct_total{result_class="success",transport="legacy"} 1`,
		`taclab_state_revision 4`,
		`taclab_reload_total{result_class="success"} 1`,
		`taclab_secret_lifecycle{status="current"} 2`,
		`taclab_secret_lifecycle{status="overdue"} 1`,
		`taclab_secret_warnings_total{status="overdue"} 1`,
		`taclab_event_subscribers 3`,
		`taclab_event_overwritten_total 5`,
		`taclab_event_subscriber_reset_total 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s\n%s", want, text)
		}
	}
}

func TestNilRecorderIsSafe(t *testing.T) {
	t.Parallel()
	var rec *Recorder
	rec.ConnectionAccepted(ListenerLegacy, TransportLegacy)
	rec.Authen(TransportLegacy, "ascii", "pass")
	rec.SetRevision(1)
	rec.SetSecretLifecycle(nil)
}

func TestClientIDBound(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.maxClientIDs = 2
	reg.Inc(MetricConnectionsAccepted, Labels{LabelListener: ListenerLegacy, LabelTransport: TransportLegacy, LabelClientID: "a"}, 1)
	reg.Inc(MetricConnectionsAccepted, Labels{LabelListener: ListenerLegacy, LabelTransport: TransportLegacy, LabelClientID: "b"}, 1)
	reg.Inc(MetricConnectionsAccepted, Labels{LabelListener: ListenerLegacy, LabelTransport: TransportLegacy, LabelClientID: "c"}, 1)
	var buf bytes.Buffer
	_ = reg.WritePrometheus(&buf)
	if !strings.Contains(buf.String(), `client_id="other"`) {
		t.Fatalf("expected overflow client_id=other:\n%s", buf.String())
	}
}
