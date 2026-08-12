package codec

// AuthorReq is an authorization REQUEST body.
type AuthorReq struct {
	Method  byte
	Priv    byte
	AType   byte
	Service byte
	User    []byte
	Port    []byte
	RemAddr []byte
	Pairs   []Pair
}

func ReadAuthorReq(p []byte) (AuthorReq, error) {
	s := slice{p: p}
	var z AuthorReq
	var err error
	if z.Method, err = s.octet(); err != nil {
		return AuthorReq{}, err
	}
	if z.Priv, err = s.octet(); err != nil {
		return AuthorReq{}, err
	}
	if z.AType, err = s.octet(); err != nil {
		return AuthorReq{}, err
	}
	if z.Service, err = s.octet(); err != nil {
		return AuthorReq{}, err
	}
	ul, err := s.octet()
	if err != nil {
		return AuthorReq{}, err
	}
	pl, err := s.octet()
	if err != nil {
		return AuthorReq{}, err
	}
	rl, err := s.octet()
	if err != nil {
		return AuthorReq{}, err
	}
	n, err := s.octet()
	if err != nil {
		return AuthorReq{}, err
	}
	lens, err := takeLens(&s, int(n))
	if err != nil {
		return AuthorReq{}, err
	}
	u, err := s.take(int(ul))
	if err != nil {
		return AuthorReq{}, err
	}
	po, err := s.take(int(pl))
	if err != nil {
		return AuthorReq{}, err
	}
	rm, err := s.take(int(rl))
	if err != nil {
		return AuthorReq{}, err
	}
	pairs, err := takePairs(&s, lens)
	if err != nil {
		return AuthorReq{}, err
	}
	if err := s.empty(); err != nil {
		return AuthorReq{}, err
	}
	if err := mustPrint("port", po); err != nil {
		return AuthorReq{}, err
	}
	if err := mustPrint("rem_addr", rm); err != nil {
		return AuthorReq{}, err
	}
	z.User, z.Port, z.RemAddr, z.Pairs = clone(u), clone(po), clone(rm), pairs
	return z, nil
}

func WriteAuthorReq(z AuthorReq) ([]byte, error) {
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
	lens, pay, err := packPairs(z.Pairs)
	if err != nil {
		return nil, err
	}
	n := 8 + len(lens) + int(ul) + int(pl) + int(rl) + len(pay)
	if err := capBody(n); err != nil {
		return nil, err
	}
	out := make([]byte, 0, n)
	out = append(out, z.Method, z.Priv, z.AType, z.Service, ul, pl, rl, byte(len(lens)))
	out = append(out, lens...)
	out = append(out, z.User...)
	out = append(out, z.Port...)
	out = append(out, z.RemAddr...)
	out = append(out, pay...)
	return out, nil
}

// AuthorRep is an authorization RESPONSE body.
type AuthorRep struct {
	Status byte
	Msg    []byte
	Data   []byte
	Pairs  []Pair
}

func ReadAuthorRep(p []byte) (AuthorRep, error) {
	s := slice{p: p}
	st, err := s.octet()
	if err != nil {
		return AuthorRep{}, err
	}
	n, err := s.octet()
	if err != nil {
		return AuthorRep{}, err
	}
	ml, err := s.word()
	if err != nil {
		return AuthorRep{}, err
	}
	dl, err := s.word()
	if err != nil {
		return AuthorRep{}, err
	}
	lens, err := takeLens(&s, int(n))
	if err != nil {
		return AuthorRep{}, err
	}
	msg, err := s.take(int(ml))
	if err != nil {
		return AuthorRep{}, err
	}
	data, err := s.take(int(dl))
	if err != nil {
		return AuthorRep{}, err
	}
	pairs, err := takePairs(&s, lens)
	if err != nil {
		return AuthorRep{}, err
	}
	if err := s.empty(); err != nil {
		return AuthorRep{}, err
	}
	if err := mustPrint("server_msg", msg); err != nil {
		return AuthorRep{}, err
	}
	return AuthorRep{Status: st, Msg: clone(msg), Data: clone(data), Pairs: pairs}, nil
}

func WriteAuthorRep(z AuthorRep) ([]byte, error) {
	if z.Status == AuthorFollow {
		return nil, ErrFollow
	}
	if err := mustPrint("server_msg", z.Msg); err != nil {
		return nil, err
	}
	ml, err := fit16(z.Msg)
	if err != nil {
		return nil, err
	}
	dl, err := fit16(z.Data)
	if err != nil {
		return nil, err
	}
	lens, pay, err := packPairs(z.Pairs)
	if err != nil {
		return nil, err
	}
	n := 6 + len(lens) + int(ml) + int(dl) + len(pay)
	if err := capBody(n); err != nil {
		return nil, err
	}
	out := make([]byte, 6, n)
	out[0] = z.Status
	out[1] = byte(len(lens))
	put16(out[2:4], ml)
	put16(out[4:6], dl)
	out = append(out, lens...)
	out = append(out, z.Msg...)
	out = append(out, z.Data...)
	out = append(out, pay...)
	return out, nil
}

func AuthorMinorOK(minor byte) bool { return minor == 0 }

// AcctReq is an accounting REQUEST body.
type AcctReq struct {
	Flags   byte
	Method  byte
	Priv    byte
	AType   byte
	Service byte
	User    []byte
	Port    []byte
	RemAddr []byte
	Pairs   []Pair
}

func AcctFlagsOK(f byte) bool {
	return f == AcctStart || f == AcctStop || f == AcctWatchdog || f == AcctWatchdogUpdate
}

func (r AcctReq) KeepPairs() bool { return r.Flags != AcctWatchdog }

func ReadAcctReq(p []byte) (AcctReq, error) {
	s := slice{p: p}
	var z AcctReq
	var err error
	if z.Flags, err = s.octet(); err != nil {
		return AcctReq{}, err
	}
	if z.Method, err = s.octet(); err != nil {
		return AcctReq{}, err
	}
	if z.Priv, err = s.octet(); err != nil {
		return AcctReq{}, err
	}
	if z.AType, err = s.octet(); err != nil {
		return AcctReq{}, err
	}
	if z.Service, err = s.octet(); err != nil {
		return AcctReq{}, err
	}
	ul, err := s.octet()
	if err != nil {
		return AcctReq{}, err
	}
	pl, err := s.octet()
	if err != nil {
		return AcctReq{}, err
	}
	rl, err := s.octet()
	if err != nil {
		return AcctReq{}, err
	}
	n, err := s.octet()
	if err != nil {
		return AcctReq{}, err
	}
	lens, err := takeLens(&s, int(n))
	if err != nil {
		return AcctReq{}, err
	}
	u, err := s.take(int(ul))
	if err != nil {
		return AcctReq{}, err
	}
	po, err := s.take(int(pl))
	if err != nil {
		return AcctReq{}, err
	}
	rm, err := s.take(int(rl))
	if err != nil {
		return AcctReq{}, err
	}
	pairs, err := takePairs(&s, lens)
	if err != nil {
		return AcctReq{}, err
	}
	if err := s.empty(); err != nil {
		return AcctReq{}, err
	}
	if err := mustPrint("port", po); err != nil {
		return AcctReq{}, err
	}
	if err := mustPrint("rem_addr", rm); err != nil {
		return AcctReq{}, err
	}
	z.User, z.Port, z.RemAddr, z.Pairs = clone(u), clone(po), clone(rm), pairs
	if !AcctFlagsOK(z.Flags) {
		return z, ErrFlags
	}
	return z, nil
}

func WriteAcctReq(z AcctReq) ([]byte, error) {
	if !AcctFlagsOK(z.Flags) {
		return nil, ErrFlags
	}
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
	pairs := z.Pairs
	if !z.KeepPairs() {
		pairs = nil
	}
	lens, pay, err := packPairs(pairs)
	if err != nil {
		return nil, err
	}
	n := 9 + len(lens) + int(ul) + int(pl) + int(rl) + len(pay)
	if err := capBody(n); err != nil {
		return nil, err
	}
	out := make([]byte, 0, n)
	out = append(out, z.Flags, z.Method, z.Priv, z.AType, z.Service, ul, pl, rl, byte(len(lens)))
	out = append(out, lens...)
	out = append(out, z.User...)
	out = append(out, z.Port...)
	out = append(out, z.RemAddr...)
	out = append(out, pay...)
	return out, nil
}

// AcctRep is an accounting REPLY body.
type AcctRep struct {
	Status byte
	Msg    []byte
	Data   []byte
}

func ReadAcctRep(p []byte) (AcctRep, error) {
	s := slice{p: p}
	st, err := s.octet()
	if err != nil {
		return AcctRep{}, err
	}
	ml, err := s.word()
	if err != nil {
		return AcctRep{}, err
	}
	dl, err := s.word()
	if err != nil {
		return AcctRep{}, err
	}
	if s.left() != int(ml)+int(dl) {
		return AcctRep{}, ErrLen
	}
	msg, err := s.take(int(ml))
	if err != nil {
		return AcctRep{}, err
	}
	data, err := s.take(int(dl))
	if err != nil {
		return AcctRep{}, err
	}
	if err := s.empty(); err != nil {
		return AcctRep{}, err
	}
	if err := mustPrint("server_msg", msg); err != nil {
		return AcctRep{}, err
	}
	return AcctRep{Status: st, Msg: clone(msg), Data: clone(data)}, nil
}

func WriteAcctRep(z AcctRep) ([]byte, error) {
	if z.Status == AcctFoll {
		return nil, ErrFollow
	}
	if err := mustPrint("server_msg", z.Msg); err != nil {
		return nil, err
	}
	ml, err := fit16(z.Msg)
	if err != nil {
		return nil, err
	}
	dl, err := fit16(z.Data)
	if err != nil {
		return nil, err
	}
	n := 5 + int(ml) + int(dl)
	if err := capBody(n); err != nil {
		return nil, err
	}
	out := make([]byte, 5, n)
	out[0] = z.Status
	put16(out[1:3], ml)
	put16(out[3:5], dl)
	out = append(out, z.Msg...)
	out = append(out, z.Data...)
	return out, nil
}

func AcctMinorOK(minor byte) bool { return minor == 0 }
