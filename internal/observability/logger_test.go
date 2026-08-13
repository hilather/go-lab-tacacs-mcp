package observability

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestJSONLoggerOmitsSecretsWhenNotPassed(t *testing.T) {
	t.Parallel()
	const canary = "unit-test-log-secret-canary-zz07"
	var buf bytes.Buffer
	lg := NewJSONLogger(&buf, slog.LevelInfo)
	lg.Info("authen", slog.String("listener", ListenerLegacy), slog.String("result", "fail"))
	if strings.Contains(buf.String(), canary) {
		t.Fatal("canary in log")
	}
	if !strings.Contains(buf.String(), `"listener":"legacy_tacacs"`) {
		t.Fatalf("structured fields missing: %s", buf.String())
	}
}

func TestParseLogLevel(t *testing.T) {
	t.Parallel()
	if ParseLogLevel("debug") != slog.LevelDebug {
		t.Fatal("debug")
	}
	if ParseLogLevel("info") != slog.LevelInfo {
		t.Fatal("info")
	}
}
