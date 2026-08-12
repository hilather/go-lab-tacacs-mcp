package codec

import "fmt"

// Argument is one authorization or accounting AV pair (RFC 8907 §6.1 / §8).
// Zero-length wire fields are absent and are not stored.
type Argument struct {
	Name      string
	Separator byte
	Value     string
}

// Encode writes name, one '=' or '*', and value. Encoded length is 2–255.
func (a Argument) Encode() ([]byte, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("%w: empty name", ErrArgument)
	}
	if containsArgSep(a.Name) {
		return nil, fmt.Errorf("%w: name contains separator", ErrArgument)
	}
	switch a.Separator {
	case ArgSepMandatory, ArgSepOptional:
	default:
		return nil, fmt.Errorf("%w: separator", ErrArgument)
	}
	n := len(a.Name) + 1 + len(a.Value)
	if n < 2 || n > 255 {
		return nil, ErrFieldTooLong
	}
	out := make([]byte, 0, n)
	out = append(out, a.Name...)
	out = append(out, a.Separator)
	out = append(out, a.Value...)
	if err := requirePrintable("argument", out); err != nil {
		return nil, err
	}
	return out, nil
}

// ParseArgument splits raw on the first '=' or '*'.
// An empty field is absent (ok=false).
func ParseArgument(raw []byte) (Argument, bool, error) {
	if len(raw) == 0 {
		return Argument{}, false, nil
	}
	if err := requirePrintable("argument", raw); err != nil {
		return Argument{}, false, err
	}
	sep := -1
	var kind byte
	for i, c := range raw {
		if c == ArgSepMandatory || c == ArgSepOptional {
			sep = i
			kind = c
			break
		}
	}
	if sep <= 0 {
		return Argument{}, false, ErrArgument
	}
	return Argument{
		Name:      string(raw[:sep]),
		Separator: kind,
		Value:     string(raw[sep+1:]),
	}, true, nil
}

func encodeArgList(args []Argument) (lens, payload []byte, err error) {
	if len(args) > 255 {
		return nil, nil, ErrTooManyArgs
	}
	lens = make([]byte, 0, len(args))
	payload = make([]byte, 0)
	for _, a := range args {
		raw, err := a.Encode()
		if err != nil {
			return nil, nil, err
		}
		lens = append(lens, byte(len(raw)))
		payload = append(payload, raw...)
	}
	return lens, payload, nil
}

func readArgLens(c *cursor, n int) ([]byte, error) {
	if n < 0 || n > 255 {
		return nil, ErrTooManyArgs
	}
	if c.remain() < n {
		return nil, ErrLengthMismatch
	}
	lens := make([]byte, n)
	for i := 0; i < n; i++ {
		v, err := c.u8()
		if err != nil {
			return nil, err
		}
		lens[i] = v
	}
	return lens, nil
}

func readArgs(c *cursor, lens []byte) ([]Argument, error) {
	out := make([]Argument, 0, len(lens))
	for i, ln := range lens {
		raw, err := c.bytes(int(ln))
		if err != nil {
			return nil, fmt.Errorf("%w: arg %d", err, i)
		}
		a, present, err := ParseArgument(raw)
		if err != nil {
			return nil, err
		}
		if present {
			out = append(out, a)
		}
	}
	return out, nil
}

func containsArgSep(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ArgSepMandatory || s[i] == ArgSepOptional {
			return true
		}
	}
	return false
}
