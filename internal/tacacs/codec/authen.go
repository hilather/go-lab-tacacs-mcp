package codec

import (
	"encoding/binary"
	"fmt"
)

// AuthenStart is the TACACS+ authentication START body (RFC 8907 §5.1).
type AuthenStart struct {
	Action  byte
	PrivLvl byte
	Type    byte
	Service byte
	User    []byte
	Port    []byte
	RemAddr []byte
	Data    []byte
}

// DecodeAuthenStart parses a START body. Component lengths must consume p exactly.
// User and Data are not printable-ASCII; Port and RemAddr are.
func DecodeAuthenStart(p []byte) (AuthenStart, error) {
	var z AuthenStart
	c := cursor{b: p}
	var err error
	if z.Action, err = c.u8(); err != nil {
		return AuthenStart{}, err
	}
	if z.PrivLvl, err = c.u8(); err != nil {
		return AuthenStart{}, err
	}
	if z.Type, err = c.u8(); err != nil {
		return AuthenStart{}, err
	}
	if z.Service, err = c.u8(); err != nil {
		return AuthenStart{}, err
	}
	userLen, err := c.u8()
	if err != nil {
		return AuthenStart{}, err
	}
	portLen, err := c.u8()
	if err != nil {
		return AuthenStart{}, err
	}
	remLen, err := c.u8()
	if err != nil {
		return AuthenStart{}, err
	}
	dataLen, err := c.u8()
	if err != nil {
		return AuthenStart{}, err
	}
	need := int(userLen) + int(portLen) + int(remLen) + int(dataLen)
	if c.remain() != need {
		return AuthenStart{}, fmt.Errorf("%w: remain=%d need=%d", ErrLengthMismatch, c.remain(), need)
	}
	if z.User, err = c.bytes(int(userLen)); err != nil {
		return AuthenStart{}, err
	}
	if z.Port, err = c.bytes(int(portLen)); err != nil {
		return AuthenStart{}, err
	}
	if z.RemAddr, err = c.bytes(int(remLen)); err != nil {
		return AuthenStart{}, err
	}
	if z.Data, err = c.bytes(int(dataLen)); err != nil {
		return AuthenStart{}, err
	}
	if err := c.done(); err != nil {
		return AuthenStart{}, err
	}
	if err := requirePrintable("port", z.Port); err != nil {
		return AuthenStart{}, err
	}
	if err := requirePrintable("rem_addr", z.RemAddr); err != nil {
		return AuthenStart{}, err
	}
	return z, nil
}

// Encode writes the START body. User and Data may hold arbitrary bytes.
func (s AuthenStart) Encode() ([]byte, error) {
	if err := requirePrintable("port", s.Port); err != nil {
		return nil, err
	}
	if err := requirePrintable("rem_addr", s.RemAddr); err != nil {
		return nil, err
	}
	ul, err := u8len(s.User)
	if err != nil {
		return nil, err
	}
	pl, err := u8len(s.Port)
	if err != nil {
		return nil, err
	}
	rl, err := u8len(s.RemAddr)
	if err != nil {
		return nil, err
	}
	dl, err := u8len(s.Data)
	if err != nil {
		return nil, err
	}
	n := 8 + int(ul) + int(pl) + int(rl) + int(dl)
	if err := checkBodyCap(n); err != nil {
		return nil, err
	}
	out := make([]byte, 0, n)
	out = append(out, s.Action, s.PrivLvl, s.Type, s.Service, ul, pl, rl, dl)
	out = append(out, s.User...)
	out = append(out, s.Port...)
	out = append(out, s.RemAddr...)
	out = append(out, s.Data...)
	return out, nil
}

// AuthenContinue is the authentication CONTINUE body (RFC 8907 §5.3).
type AuthenContinue struct {
	Flags   byte
	UserMsg []byte
	Data    []byte
}

// Abort reports TAC_PLUS_CONTINUE_FLAG_ABORT.
func (c AuthenContinue) Abort() bool { return c.Flags&ContinueFlagAbort != 0 }

// DecodeAuthenContinue parses a CONTINUE body.
func DecodeAuthenContinue(p []byte) (AuthenContinue, error) {
	var z AuthenContinue
	c := cursor{b: p}
	umLen, err := c.u16()
	if err != nil {
		return AuthenContinue{}, err
	}
	dataLen, err := c.u16()
	if err != nil {
		return AuthenContinue{}, err
	}
	if z.Flags, err = c.u8(); err != nil {
		return AuthenContinue{}, err
	}
	need := int(umLen) + int(dataLen)
	if c.remain() != need {
		return AuthenContinue{}, fmt.Errorf("%w: remain=%d need=%d", ErrLengthMismatch, c.remain(), need)
	}
	if z.UserMsg, err = c.bytes(int(umLen)); err != nil {
		return AuthenContinue{}, err
	}
	if z.Data, err = c.bytes(int(dataLen)); err != nil {
		return AuthenContinue{}, err
	}
	if err := c.done(); err != nil {
		return AuthenContinue{}, err
	}
	if err := requirePrintable("user_msg", z.UserMsg); err != nil {
		return AuthenContinue{}, err
	}
	return z, nil
}

// Encode writes the CONTINUE body. Unknown flag bits are cleared.
func (c AuthenContinue) Encode() ([]byte, error) {
	if err := requirePrintable("user_msg", c.UserMsg); err != nil {
		return nil, err
	}
	ul, err := u16len(c.UserMsg)
	if err != nil {
		return nil, err
	}
	dl, err := u16len(c.Data)
	if err != nil {
		return nil, err
	}
	n := 5 + int(ul) + int(dl)
	if err := checkBodyCap(n); err != nil {
		return nil, err
	}
	out := make([]byte, 5, n)
	binary.BigEndian.PutUint16(out[0:2], ul)
	binary.BigEndian.PutUint16(out[2:4], dl)
	out[4] = c.Flags & ContinueFlagKnownMask
	out = append(out, c.UserMsg...)
	out = append(out, c.Data...)
	return out, nil
}

// AuthenReply is the authentication REPLY body (RFC 8907 §5.2).
type AuthenReply struct {
	Status    byte
	Flags     byte
	ServerMsg []byte
	Data      []byte
}

// DecodeAuthenReply parses a REPLY body. FOLLOW is accepted on the wire.
func DecodeAuthenReply(p []byte) (AuthenReply, error) {
	var z AuthenReply
	c := cursor{b: p}
	var err error
	if z.Status, err = c.u8(); err != nil {
		return AuthenReply{}, err
	}
	if z.Flags, err = c.u8(); err != nil {
		return AuthenReply{}, err
	}
	smLen, err := c.u16()
	if err != nil {
		return AuthenReply{}, err
	}
	dataLen, err := c.u16()
	if err != nil {
		return AuthenReply{}, err
	}
	need := int(smLen) + int(dataLen)
	if c.remain() != need {
		return AuthenReply{}, fmt.Errorf("%w: remain=%d need=%d", ErrLengthMismatch, c.remain(), need)
	}
	if z.ServerMsg, err = c.bytes(int(smLen)); err != nil {
		return AuthenReply{}, err
	}
	if z.Data, err = c.bytes(int(dataLen)); err != nil {
		return AuthenReply{}, err
	}
	if err := c.done(); err != nil {
		return AuthenReply{}, err
	}
	if err := requirePrintable("server_msg", z.ServerMsg); err != nil {
		return AuthenReply{}, err
	}
	return z, nil
}

// Encode writes the REPLY body. FOLLOW is refused. Unknown flag bits are cleared.
func (r AuthenReply) Encode() ([]byte, error) {
	if r.Status == AuthenStatusFollow {
		return nil, ErrFollow
	}
	if err := requirePrintable("server_msg", r.ServerMsg); err != nil {
		return nil, err
	}
	sl, err := u16len(r.ServerMsg)
	if err != nil {
		return nil, err
	}
	dl, err := u16len(r.Data)
	if err != nil {
		return nil, err
	}
	n := 6 + int(sl) + int(dl)
	if err := checkBodyCap(n); err != nil {
		return nil, err
	}
	out := make([]byte, 6, n)
	out[0] = r.Status
	out[1] = r.Flags & ReplyFlagKnownMask
	binary.BigEndian.PutUint16(out[2:4], sl)
	binary.BigEndian.PutUint16(out[4:6], dl)
	out = append(out, r.ServerMsg...)
	out = append(out, r.Data...)
	return out, nil
}

// NormalizeAuthenStatus maps a received FOLLOW to FAIL. Other statuses pass through.
func NormalizeAuthenStatus(status byte) byte {
	if status == AuthenStatusFollow {
		return AuthenStatusFail
	}
	return status
}
