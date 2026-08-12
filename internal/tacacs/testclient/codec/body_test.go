package codec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestStartContReplyRoundTrip(t *testing.T) {
	t.Parallel()
	st := Start{Action: ActionLogin, Priv: 1, AType: TypeASCII, Service: SvcLogin, User: []byte("admin"), Port: []byte("con"), Data: []byte{0, 1, 0x7f}}
	raw, err := WriteStart(st)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadStart(raw)
	if err != nil || !bytes.Equal(got.Data, st.Data) || string(got.User) != "admin" {
		t.Fatalf("%#v %v", got, err)
	}
	cw, err := WriteCont(Cont{Flags: FlagAbort, Msg: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ReadCont(cw)
	if err != nil || !c.Aborted() {
		t.Fatalf("%#v %v", c, err)
	}
	rw, err := WriteReply(Reply{Status: StatusGetPass, Flags: FlagNoEcho, Msg: []byte("Password:")})
	if err != nil {
		t.Fatal(err)
	}
	r, err := ReadReply(rw)
	if err != nil || r.Status != StatusGetPass {
		t.Fatalf("%#v %v", r, err)
	}
}

func TestClientCatalogAndNegatives(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "bodies", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		Bodies []struct {
			Name     string `json:"name"`
			Family   string `json:"family"`
			RawHex   string `json:"raw_hex"`
			Classify *struct {
				Flow        string `json:"flow"`
				Disposition string `json:"disposition"`
			} `json:"classify"`
		} `json:"bodies"`
		Negatives []struct {
			Family string `json:"family"`
			RawHex string `json:"raw_hex"`
			Reason string `json:"reason"`
			Name   string `json:"name"`
		} `json:"negatives"`
	}
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	for _, b := range cat.Bodies {
		wire, err := hex.DecodeString(b.RawHex)
		if err != nil {
			t.Fatal(err)
		}
		if err := readFam(b.Family, wire); err != nil {
			t.Fatalf("%s: %v", b.Name, err)
		}
		if b.Family == "authen_start" && b.Classify != nil {
			st, err := ReadStart(wire)
			if err != nil {
				t.Fatal(err)
			}
			minor := byte(0)
			switch b.Classify.Flow {
			case "pap_login", "chap_login", "mschapv1", "mschapv2":
				minor = 1
			}
			k, v := ScoreStart(minor, st)
			if kindName(k) != b.Classify.Flow || verdName(v) != b.Classify.Disposition {
				t.Fatalf("%s got %s/%s", b.Name, kindName(k), verdName(v))
			}
		}
	}
	for _, n := range cat.Negatives {
		wire, _ := hex.DecodeString(n.RawHex)
		err := readFam(n.Family, wire)
		switch n.Reason {
		case "non_printable":
			if !errors.Is(err, ErrASCII) {
				t.Fatalf("%s: %v", n.Name, err)
			}
		case "length_mismatch":
			if !errors.Is(err, ErrLen) {
				t.Fatalf("%s: %v", n.Name, err)
			}
		case "acct_flags":
			if !errors.Is(err, ErrFlags) {
				t.Fatalf("%s: %v", n.Name, err)
			}
		}
	}
}

func readFam(fam string, p []byte) error {
	switch fam {
	case "authen_start":
		_, err := ReadStart(p)
		return err
	case "authen_continue":
		_, err := ReadCont(p)
		return err
	case "authen_reply":
		_, err := ReadReply(p)
		return err
	case "author_request":
		_, err := ReadAuthorReq(p)
		return err
	case "author_response":
		_, err := ReadAuthorRep(p)
		return err
	case "acct_request":
		_, err := ReadAcctReq(p)
		return err
	case "acct_reply":
		_, err := ReadAcctRep(p)
		return err
	default:
		return errors.New("family")
	}
}

func kindName(k Kind) string {
	switch k {
	case KindASCII:
		return "ascii_login"
	case KindPAP:
		return "pap_login"
	case KindCHAP:
		return "chap_login"
	case KindMS1:
		return "mschapv1"
	case KindMS2:
		return "mschapv2"
	case KindEnable:
		return "enable"
	case KindChpass:
		return "ascii_chpass"
	default:
		return "none"
	}
}

func verdName(v Verdict) string {
	switch v {
	case Fail:
		return "fail"
	case Error:
		return "error"
	default:
		return "accept"
	}
}

func TestEnableIgnoresAuthenType(t *testing.T) {
	t.Parallel()
	for _, typ := range []byte{TypeASCII, TypePAP, TypeCHAP, 0x99} {
		k, v := ScoreStart(0, Start{Action: ActionLogin, AType: typ, Service: SvcEnable})
		if k != KindEnable || v != OK {
			t.Fatalf("type=%#x k=%d v=%d", typ, k, v)
		}
	}
	k, v := ScoreStart(1, Start{Action: ActionLogin, AType: TypePAP, Service: SvcEnable})
	if k != KindEnable || v != Fail {
		t.Fatalf("enable minor1 k=%d v=%d", k, v)
	}
}

func TestClientMSCHAPAndFlags(t *testing.T) {
	t.Parallel()
	v1 := append(append([]byte{9}, bytes.Repeat([]byte{1}, 8)...), bytes.Repeat([]byte{2}, 49)...)
	m, err := UnpackMSChap(v1, false)
	if err != nil || m.ID != 9 || len(m.Chal) != 8 {
		t.Fatalf("%#v %v", m, err)
	}
	v2 := append(append([]byte{9}, bytes.Repeat([]byte{1}, 16)...), bytes.Repeat([]byte{2}, 49)...)
	m2, err := UnpackMSChap(v2, true)
	if err != nil || len(m2.Chal) != 16 {
		t.Fatalf("%#v %v", m2, err)
	}
	if !AcctFlagsOK(AcctStart) || AcctFlagsOK(0) || AcctFlagsOK(AcctStart|AcctStop) {
		t.Fatal("acct flags")
	}
}

func TestWalkAndMux(t *testing.T) {
	t.Parallel()
	w := NewWalk(7, TypeAuthen)
	h, err := w.Out(FlagSingleConnect)
	if err != nil || h.SeqNo != 1 {
		t.Fatalf("%#v %v", h, err)
	}
	if err := w.In(Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 2, SessionID: 7}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Out(0); err != nil {
		t.Fatal(err)
	}

	var m Mux
	m.Offer(FlagSingleConnect)
	if err := m.Guard(); !errors.Is(err, ErrEarly) {
		t.Fatalf("guard: %v", err)
	}
	if !m.Answer(FlagSingleConnect) {
		t.Fatal("mux")
	}
	id, err := GenerateSessionID(bytes.NewReader([]byte{0, 0, 0, 9}))
	if err != nil || id != 9 {
		t.Fatalf("id=%d %v", id, err)
	}
}

func TestMatrixTable(t *testing.T) {
	t.Parallel()
	if k, v := ScoreStart(1, Start{Action: ActionLogin, AType: TypePAP, Service: SvcPPP}); k != KindPAP || v != OK {
		t.Fatal("pap")
	}
	if _, v := ScoreStart(0, Start{Action: ActionLogin, AType: TypePAP, Service: SvcPPP}); v != Fail {
		t.Fatal("pap minor0")
	}
	if _, v := ScoreStart(0, Start{Action: ActionSendAuth, AType: TypeASCII, Service: SvcLogin}); v != Error {
		t.Fatal("sendauth")
	}
	if FamilyMinor(TypeAuthor, 1) != Error || FamilyMinor(TypeAcct, 0) != OK {
		t.Fatal("family minor")
	}
	if k, v := ScoreStart(0, Start{Action: ActionLogin, AType: TypeASCII, Service: SvcARAP}); k != KindASCII || v != Fail {
		t.Fatalf("arap service k=%d v=%d", k, v)
	}
}

func TestAcctRepRFC8907Order(t *testing.T) {
	t.Parallel()
	empty, err := WriteAcctRep(AcctRep{Status: AcctOK})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 5 || empty[4] != AcctOK || empty[0] != 0 || empty[1] != 0 || empty[2] != 0 || empty[3] != 0 {
		t.Fatalf("empty SUCCESS %x", empty)
	}
	raw, err := WriteAcctRep(AcctRep{Status: AcctErr, Msg: []byte("no"), Data: []byte("log")})
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] != 0 || raw[1] != 2 || raw[2] != 0 || raw[3] != 3 || raw[4] != AcctErr {
		t.Fatalf("prefix %x", raw[:5])
	}
	got, err := ReadAcctRep(raw)
	if err != nil || string(got.Msg) != "no" || string(got.Data) != "log" {
		t.Fatalf("%#v %v", got, err)
	}
	if _, err := WriteAcctRep(AcctRep{Status: AcctOK, Data: []byte{0x01}}); !errors.Is(err, ErrASCII) {
		t.Fatalf("data: %v", err)
	}
}

func TestAuthorAcctPairs(t *testing.T) {
	t.Parallel()
	req := AuthorReq{
		Method: MethTACACS, AType: TypeASCII, Service: SvcLogin, User: []byte("u"),
		Pairs: []Pair{{Key: "service", Sep: SepEq, Val: "shell"}, {Key: "cmd", Sep: SepSt, Val: "show"}},
	}
	raw, err := WriteAuthorReq(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadAuthorReq(raw)
	if err != nil || len(got.Pairs) != 2 || got.Pairs[1].Sep != SepSt {
		t.Fatalf("%#v %v", got, err)
	}
	ar, err := WriteAcctReq(AcctReq{Flags: AcctWatchdog, Method: MethTACACS, User: []byte("u"), Pairs: req.Pairs})
	if err != nil {
		t.Fatal(err)
	}
	ag, err := ReadAcctReq(ar)
	if err != nil || ag.KeepPairs() || len(ag.Pairs) != 0 {
		t.Fatalf("%#v %v", ag, err)
	}
}
