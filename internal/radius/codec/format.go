package codec

import (
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// String reports code, identifier, and attribute count. Authenticators and
// attribute values are omitted.
func (p Packet) String() string {
	return "radius.packet{code=" + p.Code.String() + " id=" + strconv.Itoa(int(p.Identifier)) + " attrs=" + strconv.Itoa(p.Attributes.Len()) + "}"
}

// GoString is the %#v form.
func (p Packet) GoString() string { return p.String() }

// Format never writes authenticators or attribute values.
func (p Packet) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, p.String())
}

// LogValue is a redacted slog view.
func (p Packet) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("code", p.Code.String()),
		slog.Int("id", int(p.Identifier)),
		slog.Int("attrs", p.Attributes.Len()),
	)
}
