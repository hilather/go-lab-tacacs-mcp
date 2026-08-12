package codec

import "fmt"

// PrintableASCII reports whether every byte is US-ASCII 0x20–0x7E.
// RFC 20 §5.2 control characters (0x00–0x1F and 0x7F) are rejected.
// Empty input is treated as absent and is accepted.
func PrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func requirePrintable(field string, b []byte) error {
	if PrintableASCII(b) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrNonPrintable, field)
}
