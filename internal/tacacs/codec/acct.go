package codec

import (
	"encoding/binary"
	"fmt"
)

// AcctRequest is the accounting REQUEST body (RFC 8907 §7.1).
type AcctRequest struct {
	Flags        byte
	AuthenMethod byte
	PrivLvl      byte
	AuthenType   byte
	Service      byte
	User         []byte
	Port         []byte
	RemAddr      []byte
	Args         []Argument
}

// UseArguments reports whether arguments are meaningful for these flags.
// WATCHDOG without update must ignore arguments (RFC 8907 §7.1).
func (r AcctRequest) UseArguments() bool {
	return r.Flags != AcctFlagWatchdog
}

// ValidAcctFlags reports whether flags are a defined accounting combination.
func ValidAcctFlags(flags byte) bool {
	switch flags {
	case AcctFlagStart, AcctFlagStop, AcctFlagWatchdog, AcctFlagWatchdogUpdate:
		return true
	default:
		return false
	}
}

// DecodeAcctRequest parses a REQUEST body. Invalid flag combinations return
// the decoded fields and ErrAcctFlags so the caller can reply ERROR.
func DecodeAcctRequest(p []byte) (AcctRequest, error) {
	var z AcctRequest
	c := cursor{b: p}
	var err error
	if z.Flags, err = c.u8(); err != nil {
		return AcctRequest{}, err
	}
	if z.AuthenMethod, err = c.u8(); err != nil {
		return AcctRequest{}, err
	}
	if z.PrivLvl, err = c.u8(); err != nil {
		return AcctRequest{}, err
	}
	if z.AuthenType, err = c.u8(); err != nil {
		return AcctRequest{}, err
	}
	if z.Service, err = c.u8(); err != nil {
		return AcctRequest{}, err
	}
	userLen, err := c.u8()
	if err != nil {
		return AcctRequest{}, err
	}
	portLen, err := c.u8()
	if err != nil {
		return AcctRequest{}, err
	}
	remLen, err := c.u8()
	if err != nil {
		return AcctRequest{}, err
	}
	argCnt, err := c.u8()
	if err != nil {
		return AcctRequest{}, err
	}
	lens, err := readArgLens(&c, int(argCnt))
	if err != nil {
		return AcctRequest{}, err
	}
	if z.User, err = c.bytes(int(userLen)); err != nil {
		return AcctRequest{}, err
	}
	if z.Port, err = c.bytes(int(portLen)); err != nil {
		return AcctRequest{}, err
	}
	if z.RemAddr, err = c.bytes(int(remLen)); err != nil {
		return AcctRequest{}, err
	}
	if z.Args, err = readArgs(&c, lens); err != nil {
		return AcctRequest{}, err
	}
	if err := c.done(); err != nil {
		return AcctRequest{}, err
	}
	if err := requirePrintable("port", z.Port); err != nil {
		return AcctRequest{}, err
	}
	if err := requirePrintable("rem_addr", z.RemAddr); err != nil {
		return AcctRequest{}, err
	}
	if !ValidAcctFlags(z.Flags) {
		return z, fmt.Errorf("%w: flags=%#x", ErrAcctFlags, z.Flags)
	}
	return z, nil
}

// Encode writes the REQUEST body. Invalid flag combinations are rejected.
func (r AcctRequest) Encode() ([]byte, error) {
	if !ValidAcctFlags(r.Flags) {
		return nil, fmt.Errorf("%w: flags=%#x", ErrAcctFlags, r.Flags)
	}
	if err := requirePrintable("port", r.Port); err != nil {
		return nil, err
	}
	if err := requirePrintable("rem_addr", r.RemAddr); err != nil {
		return nil, err
	}
	ul, err := u8len(r.User)
	if err != nil {
		return nil, err
	}
	pl, err := u8len(r.Port)
	if err != nil {
		return nil, err
	}
	rl, err := u8len(r.RemAddr)
	if err != nil {
		return nil, err
	}
	args := r.Args
	if !r.UseArguments() {
		args = nil
	}
	lens, payload, err := encodeArgList(args)
	if err != nil {
		return nil, err
	}
	n := 9 + len(lens) + int(ul) + int(pl) + int(rl) + len(payload)
	if err := checkBodyCap(n); err != nil {
		return nil, err
	}
	out := make([]byte, 0, n)
	out = append(out, r.Flags, r.AuthenMethod, r.PrivLvl, r.AuthenType, r.Service, ul, pl, rl, byte(len(lens)))
	out = append(out, lens...)
	out = append(out, r.User...)
	out = append(out, r.Port...)
	out = append(out, r.RemAddr...)
	out = append(out, payload...)
	return out, nil
}

// AcctReply is the accounting REPLY body (RFC 8907 §7.2).
type AcctReply struct {
	Status    byte
	ServerMsg []byte
	Data      []byte
}

// DecodeAcctReply parses a REPLY body (RFC 8907 §7.2):
// server_msg_len(2) || data_len(2) || status(1) || server_msg || data.
// FOLLOW is accepted on the wire. server_msg and data are printable text.
func DecodeAcctReply(p []byte) (AcctReply, error) {
	var z AcctReply
	c := cursor{b: p}
	smLen, err := c.u16()
	if err != nil {
		return AcctReply{}, err
	}
	dataLen, err := c.u16()
	if err != nil {
		return AcctReply{}, err
	}
	if z.Status, err = c.u8(); err != nil {
		return AcctReply{}, err
	}
	need := int(smLen) + int(dataLen)
	if c.remain() != need {
		return AcctReply{}, fmt.Errorf("%w: remain=%d need=%d", ErrLengthMismatch, c.remain(), need)
	}
	if z.ServerMsg, err = c.bytes(int(smLen)); err != nil {
		return AcctReply{}, err
	}
	if z.Data, err = c.bytes(int(dataLen)); err != nil {
		return AcctReply{}, err
	}
	if err := c.done(); err != nil {
		return AcctReply{}, err
	}
	if err := requirePrintable("server_msg", z.ServerMsg); err != nil {
		return AcctReply{}, err
	}
	if err := requirePrintable("data", z.Data); err != nil {
		return AcctReply{}, err
	}
	return z, nil
}

// Encode writes the REPLY body. FOLLOW is refused.
func (r AcctReply) Encode() ([]byte, error) {
	if r.Status == AcctStatusFollow {
		return nil, ErrFollow
	}
	if err := requirePrintable("server_msg", r.ServerMsg); err != nil {
		return nil, err
	}
	if err := requirePrintable("data", r.Data); err != nil {
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
	n := 5 + int(sl) + int(dl)
	if err := checkBodyCap(n); err != nil {
		return nil, err
	}
	out := make([]byte, 5, n)
	binary.BigEndian.PutUint16(out[0:2], sl)
	binary.BigEndian.PutUint16(out[2:4], dl)
	out[4] = r.Status
	out = append(out, r.ServerMsg...)
	out = append(out, r.Data...)
	return out, nil
}

// ClassifyAcctMinor returns DispositionError when minor is not 0.
func ClassifyAcctMinor(minor byte) Disposition {
	if minor != 0 {
		return DispositionError
	}
	return DispositionAccept
}
