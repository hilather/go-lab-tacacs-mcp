package attribute

import (
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// String reports type and value length only. Values are never printed.
func (r Raw) String() string {
	return "radius.attr{type=" + strconv.Itoa(int(r.Type)) + " len=" + strconv.Itoa(len(r.Value)) + "}"
}

// GoString is the %#v form and never includes Value bytes.
func (r Raw) GoString() string { return r.String() }

// Format never writes Value, including for User-Password / CHAP / MA.
func (r Raw) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, r.String())
}

// LogValue is a redacted slog view.
func (r Raw) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("type", int(r.Type)),
		slog.Int("len", len(r.Value)),
	)
}

// String reports count only.
func (s RawSet) String() string {
	return "radius.attrs{count=" + strconv.Itoa(len(s)) + "}"
}

// GoString is the %#v form.
func (s RawSet) GoString() string { return s.String() }

// Format never walks attribute values.
func (s RawSet) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, s.String())
}

// String reports vendor and payload length only.
func (v VSA) String() string {
	return "radius.vsa{vendor=" + strconv.FormatUint(uint64(v.Vendor), 10) + " payload_len=" + strconv.Itoa(len(v.Payload)) + "}"
}

// GoString is the %#v form and never includes payload bytes.
func (v VSA) GoString() string { return v.String() }

// Format never writes the VSA payload.
func (v VSA) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, v.String())
}
