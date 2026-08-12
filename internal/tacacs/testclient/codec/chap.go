package codec

// Chap is id || challenge || 16-byte response.
type Chap struct {
	ID   byte
	Chal []byte
	Resp []byte
}

func UnpackChap(data []byte, min int) (Chap, error) {
	if min <= 0 {
		min = CHAPMinChal
	}
	if min < 5 {
		min = 5
	}
	if len(data) < 1+min+CHAPRespLen {
		return Chap{}, ErrCHAP
	}
	n := len(data) - 1 - CHAPRespLen
	return Chap{ID: data[0], Chal: clone(data[1 : 1+n]), Resp: clone(data[1+n:])}, nil
}

func PackChap(c Chap) ([]byte, error) {
	if len(c.Resp) != CHAPRespLen {
		return nil, ErrCHAP
	}
	out := make([]byte, 0, 1+len(c.Chal)+CHAPRespLen)
	out = append(out, c.ID)
	out = append(out, c.Chal...)
	out = append(out, c.Resp...)
	return out, nil
}

// MSChap is id || challenge(8|16) || response(49).
type MSChap struct {
	ID   byte
	Chal []byte
	Resp []byte
}

func UnpackMSChap(data []byte, v2 bool) (MSChap, error) {
	wantCh := MSCHAPv1Chal
	if v2 {
		wantCh = MSCHAPv2Chal
	}
	if len(data) != 1+wantCh+MSCHAPRespLen {
		return MSChap{}, ErrMSCHAP
	}
	return MSChap{
		ID:   data[0],
		Chal: clone(data[1 : 1+wantCh]),
		Resp: clone(data[1+wantCh:]),
	}, nil
}

func PackMSChap(m MSChap) ([]byte, error) {
	if len(m.Resp) != MSCHAPRespLen {
		return nil, ErrMSCHAP
	}
	if len(m.Chal) != MSCHAPv1Chal && len(m.Chal) != MSCHAPv2Chal {
		return nil, ErrMSCHAP
	}
	out := make([]byte, 0, 1+len(m.Chal)+MSCHAPRespLen)
	out = append(out, m.ID)
	out = append(out, m.Chal...)
	out = append(out, m.Resp...)
	return out, nil
}
