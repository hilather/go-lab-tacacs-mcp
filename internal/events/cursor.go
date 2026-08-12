package events

import (
	"strconv"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const cursorPrefix = "evt_"

// EncodeCursor returns an opaque cursor for the exclusive after-ID.
// afterID 0 is the start of the retained window and encodes as empty.
func EncodeCursor(afterID uint64) string {
	if afterID == 0 {
		return ""
	}
	return cursorPrefix + strconv.FormatUint(afterID, 10)
}

// DecodeCursor parses an opaque cursor. Empty means the oldest retained event.
func DecodeCursor(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	if !strings.HasPrefix(s, cursorPrefix) {
		return 0, domain.NewError(domain.CodeInvalidArgument, "invalid event cursor")
	}
	n, err := strconv.ParseUint(s[len(cursorPrefix):], 10, 64)
	if err != nil {
		return 0, domain.NewError(domain.CodeInvalidArgument, "invalid event cursor")
	}
	return n, nil
}
