package codec

import "encoding/binary"

// AuthorRequest is the authorization REQUEST body (RFC 8907 §6.1).
type AuthorRequest struct {
	AuthenMethod byte
	PrivLvl      byte
	AuthenType   byte
	Service      byte
	User         []byte
	Port         []byte
	RemAddr      []byte
	Args         []Argument
}

// DecodeAuthorRequest parses a REQUEST body. Argument order is preserved.
func DecodeAuthorRequest(p []byte) (AuthorRequest, error) {
	var z AuthorRequest
	c := cursor{b: p}
	var err error
	if z.AuthenMethod, err = c.u8(); err != nil {
		return AuthorRequest{}, err
	}
	if z.PrivLvl, err = c.u8(); err != nil {
		return AuthorRequest{}, err
	}
	if z.AuthenType, err = c.u8(); err != nil {
		return AuthorRequest{}, err
	}
	if z.Service, err = c.u8(); err != nil {
		return AuthorRequest{}, err
	}
	userLen, err := c.u8()
	if err != nil {
		return AuthorRequest{}, err
	}
	portLen, err := c.u8()
	if err != nil {
		return AuthorRequest{}, err
	}
	remLen, err := c.u8()
	if err != nil {
		return AuthorRequest{}, err
	}
	argCnt, err := c.u8()
	if err != nil {
		return AuthorRequest{}, err
	}
	lens, err := readArgLens(&c, int(argCnt))
	if err != nil {
		return AuthorRequest{}, err
	}
	if z.User, err = c.bytes(int(userLen)); err != nil {
		return AuthorRequest{}, err
	}
	if z.Port, err = c.bytes(int(portLen)); err != nil {
		return AuthorRequest{}, err
	}
	if z.RemAddr, err = c.bytes(int(remLen)); err != nil {
		return AuthorRequest{}, err
	}
	if z.Args, err = readArgs(&c, lens); err != nil {
		return AuthorRequest{}, err
	}
	if err := c.done(); err != nil {
		return AuthorRequest{}, err
	}
	if err := requirePrintable("port", z.Port); err != nil {
		return AuthorRequest{}, err
	}
	if err := requirePrintable("rem_addr", z.RemAddr); err != nil {
		return AuthorRequest{}, err
	}
	return z, nil
}

// Encode writes the REQUEST body.
func (r AuthorRequest) Encode() ([]byte, error) {
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
	lens, payload, err := encodeArgList(r.Args)
	if err != nil {
		return nil, err
	}
	n := 8 + len(lens) + int(ul) + int(pl) + int(rl) + len(payload)
	if err := checkBodyCap(n); err != nil {
		return nil, err
	}
	out := make([]byte, 0, n)
	out = append(out, r.AuthenMethod, r.PrivLvl, r.AuthenType, r.Service, ul, pl, rl, byte(len(lens)))
	out = append(out, lens...)
	out = append(out, r.User...)
	out = append(out, r.Port...)
	out = append(out, r.RemAddr...)
	out = append(out, payload...)
	return out, nil
}

// AuthorResponse is the authorization RESPONSE body (RFC 8907 §6.2).
type AuthorResponse struct {
	Status    byte
	ServerMsg []byte
	Data      []byte
	Args      []Argument
}

// DecodeAuthorResponse parses a RESPONSE body. FOLLOW is accepted on the wire.
func DecodeAuthorResponse(p []byte) (AuthorResponse, error) {
	var z AuthorResponse
	c := cursor{b: p}
	var err error
	if z.Status, err = c.u8(); err != nil {
		return AuthorResponse{}, err
	}
	argCnt, err := c.u8()
	if err != nil {
		return AuthorResponse{}, err
	}
	smLen, err := c.u16()
	if err != nil {
		return AuthorResponse{}, err
	}
	dataLen, err := c.u16()
	if err != nil {
		return AuthorResponse{}, err
	}
	lens, err := readArgLens(&c, int(argCnt))
	if err != nil {
		return AuthorResponse{}, err
	}
	if z.ServerMsg, err = c.bytes(int(smLen)); err != nil {
		return AuthorResponse{}, err
	}
	if z.Data, err = c.bytes(int(dataLen)); err != nil {
		return AuthorResponse{}, err
	}
	if z.Args, err = readArgs(&c, lens); err != nil {
		return AuthorResponse{}, err
	}
	if err := c.done(); err != nil {
		return AuthorResponse{}, err
	}
	if err := requirePrintable("server_msg", z.ServerMsg); err != nil {
		return AuthorResponse{}, err
	}
	return z, nil
}

// Encode writes the RESPONSE body. FOLLOW is refused.
func (r AuthorResponse) Encode() ([]byte, error) {
	if r.Status == AuthorStatusFollow {
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
	lens, payload, err := encodeArgList(r.Args)
	if err != nil {
		return nil, err
	}
	n := 6 + len(lens) + int(sl) + int(dl) + len(payload)
	if err := checkBodyCap(n); err != nil {
		return nil, err
	}
	out := make([]byte, 6, n)
	out[0] = r.Status
	out[1] = byte(len(lens))
	binary.BigEndian.PutUint16(out[2:4], sl)
	binary.BigEndian.PutUint16(out[4:6], dl)
	out = append(out, lens...)
	out = append(out, r.ServerMsg...)
	out = append(out, r.Data...)
	out = append(out, payload...)
	return out, nil
}

// KnownAuthorStatus reports whether status is a defined authorization reply.
func KnownAuthorStatus(status byte) bool {
	switch status {
	case AuthorStatusPassAdd, AuthorStatusPassRepl, AuthorStatusFail, AuthorStatusError, AuthorStatusFollow:
		return true
	default:
		return false
	}
}

// ClassifyAuthorMinor returns DispositionError when minor is not 0.
func ClassifyAuthorMinor(minor byte) Disposition {
	if minor != 0 {
		return DispositionError
	}
	return DispositionAccept
}
