package codec

import (
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// String reports code, identifier, and attribute count. Authenticators
// and attribute values are omitted.
func (p Packet) String() string {
	return "radius.testclient.packet{code=" + p.Code.String() + " id=" + strconv.Itoa(int(p.Identifier)) + " attrs=" + strconv.Itoa(len(p.Attrs)) + "}"
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
		slog.Int("attrs", len(p.Attrs)),
	)
}

// String reports type and value length only.
func (a Attr) String() string {
	return "radius.testclient.attr{type=" + strconv.Itoa(int(a.Type)) + " len=" + strconv.Itoa(len(a.Value)) + "}"
}

// GoString is the %#v form and never includes Value bytes.
func (a Attr) GoString() string { return a.String() }

// Format never writes Value.
func (a Attr) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, a.String())
}

// String reports vendor and payload length only.
func (v VSA) String() string {
	return "radius.testclient.vsa{vendor=" + strconv.FormatUint(uint64(v.Vendor), 10) + " payload_len=" + strconv.Itoa(len(v.Payload)) + "}"
}

// GoString is the %#v form and never includes payload bytes.
func (v VSA) GoString() string { return v.String() }

// Format never writes the VSA payload.
func (v VSA) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, v.String())
}
