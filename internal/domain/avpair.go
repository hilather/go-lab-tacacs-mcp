package domain

import "strings"

// AV pair encoded length on the TACACS+ wire (name + one separator + value).
const (
	AVPairMinEncodedLen = 2
	AVPairMaxEncodedLen = 255
)

// Separator kinds from RFC 8907: mandatory "=" and optional "*".
const (
	AVSepMandatory byte = '='
	AVSepOptional  byte = '*'
)

// AVPair is one authorization/accounting attribute-value pair.
type AVPair struct {
	Name      string
	Separator byte
	Value     string
}

// AVPairs is an ordered list. Encode and Parse keep order and duplicates.
type AVPairs []AVPair

// EncodedLen is the wire length in bytes: name + separator + value.
func (p AVPair) EncodedLen() int {
	return len(p.Name) + 1 + len(p.Value)
}

// Mandatory reports whether the pair uses the "=" separator.
func (p AVPair) Mandatory() bool { return p.Separator == AVSepMandatory }

// Validate reports whether p can be encoded on the wire.
func (p AVPair) Validate() error {
	if p.Name == "" {
		return NewError(CodeInvalidArgument, "AV pair name is required")
	}
	if containsSeparator(p.Name) {
		return NewError(CodeInvalidArgument, "AV pair name must not contain = or *")
	}
	switch p.Separator {
	case AVSepMandatory, AVSepOptional:
	default:
		return NewError(CodeInvalidArgument, "AV pair separator must be = or *")
	}
	n := p.EncodedLen()
	if n < AVPairMinEncodedLen || n > AVPairMaxEncodedLen {
		return NewError(CodeInvalidArgument, "AV pair encoded length must be 2-255 bytes")
	}
	return nil
}

// Encode writes name, one separator, and value. Length must be 2-255 bytes.
func (p AVPair) Encode() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	out := make([]byte, 0, p.EncodedLen())
	out = append(out, p.Name...)
	out = append(out, p.Separator)
	out = append(out, p.Value...)
	return string(out), nil
}

// ParseAVPair splits s on the first "=" or "*".
// An empty string is a zero-length protocol field and is treated as absent
// (present=false, err=nil).
func ParseAVPair(s string) (p AVPair, present bool, err error) {
	if s == "" {
		return AVPair{}, false, nil
	}
	if len(s) < AVPairMinEncodedLen || len(s) > AVPairMaxEncodedLen {
		return AVPair{}, false, NewError(CodeInvalidArgument, "AV pair encoded length must be 2-255 bytes")
	}
	i, sep, ok := firstSeparator(s)
	if !ok {
		return AVPair{}, false, NewError(CodeInvalidArgument, "AV pair must contain = or *")
	}
	name := s[:i]
	if name == "" {
		return AVPair{}, false, NewError(CodeInvalidArgument, "AV pair name is required")
	}
	return AVPair{Name: name, Separator: sep, Value: s[i+1:]}, true, nil
}

// ParseAVPairs parses each encoded pair. Empty entries are skipped as absent.
func ParseAVPairs(raw []string) (AVPairs, error) {
	out := make(AVPairs, 0, len(raw))
	for _, s := range raw {
		p, present, err := ParseAVPair(s)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// Encode encodes each pair in order.
func (ps AVPairs) Encode() ([]string, error) {
	out := make([]string, len(ps))
	for i, p := range ps {
		s, err := p.Encode()
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

// Clone returns a shallow copy of the list (pairs themselves are values).
func (ps AVPairs) Clone() AVPairs {
	if ps == nil {
		return nil
	}
	out := make(AVPairs, len(ps))
	copy(out, ps)
	return out
}

// Equal reports whether ps and other have the same pairs in the same order.
func (ps AVPairs) Equal(other AVPairs) bool {
	if len(ps) != len(other) {
		return false
	}
	for i := range ps {
		if ps[i] != other[i] {
			return false
		}
	}
	return true
}

func firstSeparator(s string) (int, byte, bool) {
	eq := strings.IndexByte(s, AVSepMandatory)
	st := strings.IndexByte(s, AVSepOptional)
	switch {
	case eq < 0 && st < 0:
		return -1, 0, false
	case eq < 0:
		return st, AVSepOptional, true
	case st < 0:
		return eq, AVSepMandatory, true
	case eq < st:
		return eq, AVSepMandatory, true
	default:
		return st, AVSepOptional, true
	}
}

func containsSeparator(s string) bool {
	return strings.ContainsAny(s, "=*")
}
