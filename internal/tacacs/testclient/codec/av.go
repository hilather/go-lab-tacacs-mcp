package codec

// Pair is one AV argument. Empty wire values are dropped.
type Pair struct {
	Key string
	Sep byte
	Val string
}

func (p Pair) Bytes() ([]byte, error) {
	if p.Key == "" {
		return nil, ErrArg
	}
	for i := 0; i < len(p.Key); i++ {
		if p.Key[i] == SepEq || p.Key[i] == SepSt {
			return nil, ErrArg
		}
	}
	if p.Sep != SepEq && p.Sep != SepSt {
		return nil, ErrArg
	}
	n := len(p.Key) + 1 + len(p.Val)
	if n < 2 || n > 255 {
		return nil, ErrLong
	}
	out := make([]byte, 0, n)
	out = append(out, p.Key...)
	out = append(out, p.Sep)
	out = append(out, p.Val...)
	if err := mustPrint("argument", out); err != nil {
		return nil, err
	}
	return out, nil
}

func SplitPair(raw []byte) (Pair, bool, error) {
	if len(raw) == 0 {
		return Pair{}, false, nil
	}
	if err := mustPrint("argument", raw); err != nil {
		return Pair{}, false, err
	}
	idx := -1
	var sep byte
	for i, c := range raw {
		if c == SepEq || c == SepSt {
			idx = i
			sep = c
			break
		}
	}
	if idx <= 0 {
		return Pair{}, false, ErrArg
	}
	return Pair{Key: string(raw[:idx]), Sep: sep, Val: string(raw[idx+1:])}, true, nil
}

func packPairs(in []Pair) (lens, body []byte, err error) {
	if len(in) > 255 {
		return nil, nil, ErrArgs
	}
	for _, p := range in {
		raw, err := p.Bytes()
		if err != nil {
			return nil, nil, err
		}
		lens = append(lens, byte(len(raw)))
		body = append(body, raw...)
	}
	return lens, body, nil
}

func takeLens(s *slice, n int) ([]byte, error) {
	if n < 0 || n > 255 {
		return nil, ErrArgs
	}
	return s.take(n)
}

func takePairs(s *slice, lens []byte) ([]Pair, error) {
	out := make([]Pair, 0, len(lens))
	for _, n := range lens {
		raw, err := s.take(int(n))
		if err != nil {
			return nil, err
		}
		p, ok, err := SplitPair(raw)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, p)
		}
	}
	return out, nil
}
