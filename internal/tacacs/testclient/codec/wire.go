package codec

import (
	"errors"
	"fmt"
)

const (
	ActionLogin    = 0x01
	ActionCHPASS   = 0x02
	ActionSendPass = 0x03
	ActionSendAuth = 0x04

	TypeASCII    = 0x01
	TypePAP      = 0x02
	TypeCHAP     = 0x03
	TypeARAP     = 0x04
	TypeMSCHAP   = 0x05
	TypeMSCHAPV2 = 0x06

	SvcNone    = 0x00
	SvcLogin   = 0x01
	SvcEnable  = 0x02
	SvcPPP     = 0x03
	SvcARAP    = 0x04 // removed; not in RFC 8907 §5.1
	SvcPT      = 0x05
	SvcRCMD    = 0x06
	SvcX25     = 0x07
	SvcNASI    = 0x08
	SvcFWProxy = 0x09

	StatusPass    = 0x01
	StatusFail    = 0x02
	StatusGetData = 0x03
	StatusGetUser = 0x04
	StatusGetPass = 0x05
	StatusRestart = 0x06
	StatusError   = 0x07
	StatusFollow  = 0x21

	FlagAbort  = 0x01
	FlagNoEcho = 0x01

	AuthorPassAdd  = 0x01
	AuthorPassRepl = 0x02
	AuthorFail     = 0x10
	AuthorError    = 0x11
	AuthorFollow   = 0x21

	AcctStart          = 0x02
	AcctStop           = 0x04
	AcctWatchdog       = 0x08
	AcctWatchdogUpdate = 0x0a

	AcctOK   = 0x01
	AcctErr  = 0x02
	AcctFoll = 0x21

	MethTACACS = 0x06

	CHAPRespLen   = 16
	MSCHAPRespLen = 49
	MSCHAPv1Chal  = 8
	MSCHAPv2Chal  = 16
	CHAPMinChal   = 8

	SepEq = '='
	SepSt = '*'
)

var (
	ErrLen      = errors.New("body length fields do not match")
	ErrASCII    = errors.New("text field is not printable US-ASCII")
	ErrLong     = errors.New("field exceeds width")
	ErrArg      = errors.New("argument is not name plus = or *")
	ErrCHAP     = errors.New("CHAP data length is invalid")
	ErrMSCHAP   = errors.New("MS-CHAP data length is invalid")
	ErrFlags    = errors.New("accounting flags are invalid")
	ErrFollow   = errors.New("FOLLOW must not be written")
	ErrOrder    = errors.New("sequence is not next")
	ErrParity   = errors.New("sequence parity is wrong")
	ErrClosed   = errors.New("session is closed")
	ErrMismatch = errors.New("session id or type mismatch")
	ErrEarly    = errors.New("packet before single-connect negotiation")
	ErrRounds   = errors.New("too many authentication continues")
	ErrRand     = errors.New("session id entropy failed")
	ErrArgs     = errors.New("more than 255 arguments")
)

func isPrintable(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] < 0x20 || b[i] > 0x7e {
			return false
		}
	}
	return true
}

func mustPrint(name string, b []byte) error {
	if isPrintable(b) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrASCII, name)
}

func clone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func put16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

type slice struct {
	p []byte
}

func (s *slice) left() int { return len(s.p) }

func (s *slice) take(n int) ([]byte, error) {
	if n < 0 || len(s.p) < n {
		return nil, ErrLen
	}
	out := s.p[:n]
	s.p = s.p[n:]
	return out, nil
}

func (s *slice) octet() (byte, error) {
	b, err := s.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (s *slice) word() (uint16, error) {
	b, err := s.take(2)
	if err != nil {
		return 0, err
	}
	return be16(b), nil
}

func (s *slice) empty() error {
	if len(s.p) != 0 {
		return fmt.Errorf("%w: leftover %d", ErrLen, len(s.p))
	}
	return nil
}

func fit8(b []byte) (byte, error) {
	if len(b) > 255 {
		return 0, ErrLong
	}
	return byte(len(b)), nil
}

func fit16(b []byte) (uint16, error) {
	if len(b) > 65535 {
		return 0, ErrLong
	}
	return uint16(len(b)), nil
}

func capBody(n int) error {
	if n < 0 || n > MaxBodyBytes {
		return ErrBodyTooLarge
	}
	return nil
}
