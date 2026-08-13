package observability

import (
	"io"
	"log/slog"
	"os"
)

// NewJSONLogger writes structured JSON logs. Username and command fields
// must not be added by callers unless events.redact_user_input is false.
func NewJSONLogger(w io.Writer, level slog.Level) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// ParseLogLevel maps configuration log_level strings.
func ParseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
