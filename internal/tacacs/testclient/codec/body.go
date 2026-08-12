package codec

import "fmt"

// Start is an authentication START body.
type Start struct {
	Action  byte
	Priv    byte
	AType   byte
	Service byte
	User    []byte
	Port    []byte
	RemAddr []byte
	Data    []byte
}

func ReadStart(p []byte) (Start, error) {
	s := slice{p: p}
	var z Start
	var err error
	if z.Action, err = s.octet(); err != nil {
		return Start{}, err
	}
	if z.Priv, err = s.octet(); err != nil {
		return Start{}, err
	}
	if z.AType, err = s.octet(); err != nil {
		return Start{}, err
	}
	if z.Service, err = s.octet(); err != nil {
		return Start{}, err
	}
	ul, err := s.octet()
	if err != nil {
		return Start{}, err
	}
	pl, err := s.octet()
	if err != nil {
		return Start{}, err
	}
	rl, err := s.octet()
	if err != nil {
		return Start{}, err
	}
	dl, err := s.octet()
	if err != nil {
		return Start{}, err
	}
	if s.left() != int(ul)+int(pl)+int(rl)+int(dl) {
		return Start{}, fmt.Errorf("%w: start remain", ErrLen)
	}
	u, err := s.take(int(ul))
	if err != nil {
		return Start{}, err
	}
	po, err := s.take(int(pl))
	if err != nil {
		return Start{}, err
	}
	rm, err := s.take(int(rl))
	if err != nil {
		return Start{}, err
	}
	d, err := s.take(int(dl))
	if err != nil {
		return Start{}, err
	}
	if err := s.empty(); err != nil {
		return Start{}, err
	}
	z.User, z.Port, z.RemAddr, z.Data = clone(u), clone(po), clone(rm), clone(d)
	if err := mustPrint("port", z.Port); err != nil {
		return Start{}, err
	}
	if err := mustPrint("rem_addr", z.RemAddr); err != nil {
		return Start{}, err
	}
	return z, nil
}

func WriteStart(z Start) ([]byte, error) {
	if err := mustPrint("port", z.Port); err != nil {
		return nil, err
	}
	if err := mustPrint("rem_addr", z.RemAddr); err != nil {
		return nil, err
	}
	ul, err := fit8(z.User)
	if err != nil {
		return nil, err
	}
	pl, err := fit8(z.Port)
	if err != nil {
		return nil, err
	}
	rl, err := fit8(z.RemAddr)
	if err != nil {
		return nil, err
	}
	dl, err := fit8(z.Data)
	if err != nil {
		return nil, err
	}
	n := 8 + int(ul) + int(pl) + int(rl) + int(dl)
	if err := capBody(n); err != nil {
		return nil, err
	}
	out := make([]byte, 0, n)
	out = append(out, z.Action, z.Priv, z.AType, z.Service, ul, pl, rl, dl)
	out = append(out, z.User...)
	out = append(out, z.Port...)
	out = append(out, z.RemAddr...)
	out = append(out, z.Data...)
	return out, nil
}

// Cont is an authentication CONTINUE body.
type Cont struct {
	Flags byte
	Msg   []byte
	Data  []byte
}

func (c Cont) Aborted() bool { return c.Flags&FlagAbort != 0 }

func ReadCont(p []byte) (Cont, error) {
	s := slice{p: p}
	ml, err := s.word()
	if err != nil {
		return Cont{}, err
	}
	dl, err := s.word()
	if err != nil {
		return Cont{}, err
	}
	fl, err := s.octet()
	if err != nil {
		return Cont{}, err
	}
	if s.left() != int(ml)+int(dl) {
		return Cont{}, ErrLen
	}
	msg, err := s.take(int(ml))
	if err != nil {
		return Cont{}, err
	}
	data, err := s.take(int(dl))
	if err != nil {
		return Cont{}, err
	}
	if err := s.empty(); err != nil {
		return Cont{}, err
	}
	if err := mustPrint("user_msg", msg); err != nil {
		return Cont{}, err
	}
	return Cont{Flags: fl, Msg: clone(msg), Data: clone(data)}, nil
}

func WriteCont(c Cont) ([]byte, error) {
	if err := mustPrint("user_msg", c.Msg); err != nil {
		return nil, err
	}
	ml, err := fit16(c.Msg)
	if err != nil {
		return nil, err
	}
	dl, err := fit16(c.Data)
	if err != nil {
		return nil, err
	}
	n := 5 + int(ml) + int(dl)
	if err := capBody(n); err != nil {
		return nil, err
	}
	out := make([]byte, 5, n)
	put16(out[0:2], ml)
	put16(out[2:4], dl)
	out[4] = c.Flags & FlagAbort
	out = append(out, c.Msg...)
	out = append(out, c.Data...)
	return out, nil
}

// Reply is an authentication REPLY body.
type Reply struct {
	Status byte
	Flags  byte
	Msg    []byte
	Data   []byte
}

func ReadReply(p []byte) (Reply, error) {
	s := slice{p: p}
	st, err := s.octet()
	if err != nil {
		return Reply{}, err
	}
	fl, err := s.octet()
	if err != nil {
		return Reply{}, err
	}
	ml, err := s.word()
	if err != nil {
		return Reply{}, err
	}
	dl, err := s.word()
	if err != nil {
		return Reply{}, err
	}
	if s.left() != int(ml)+int(dl) {
		return Reply{}, ErrLen
	}
	msg, err := s.take(int(ml))
	if err != nil {
		return Reply{}, err
	}
	data, err := s.take(int(dl))
	if err != nil {
		return Reply{}, err
	}
	if err := s.empty(); err != nil {
		return Reply{}, err
	}
	if err := mustPrint("server_msg", msg); err != nil {
		return Reply{}, err
	}
	return Reply{Status: st, Flags: fl, Msg: clone(msg), Data: clone(data)}, nil
}

func WriteReply(r Reply) ([]byte, error) {
	if r.Status == StatusFollow {
		return nil, ErrFollow
	}
	if err := mustPrint("server_msg", r.Msg); err != nil {
		return nil, err
	}
	ml, err := fit16(r.Msg)
	if err != nil {
		return nil, err
	}
	dl, err := fit16(r.Data)
	if err != nil {
		return nil, err
	}
	n := 6 + int(ml) + int(dl)
	if err := capBody(n); err != nil {
		return nil, err
	}
	out := make([]byte, 6, n)
	out[0] = r.Status
	out[1] = r.Flags & FlagNoEcho
	put16(out[2:4], ml)
	put16(out[4:6], dl)
	out = append(out, r.Msg...)
	out = append(out, r.Data...)
	return out, nil
}

func CollapseFollow(status byte) byte {
	if status == StatusFollow {
		return StatusFail
	}
	return status
}
