package codec

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestBodyCatalog(t *testing.T) {
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
				AcctFlags   string `json:"acct_flags"`
			} `json:"classify"`
		} `json:"bodies"`
		Negatives []struct {
			Name   string `json:"name"`
			Family string `json:"family"`
			RawHex string `json:"raw_hex"`
			Reason string `json:"reason"`
		} `json:"negatives"`
	}
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	if len(cat.Bodies) < 20 || len(cat.Negatives) < 5 {
		t.Fatalf("catalog bodies=%d negatives=%d", len(cat.Bodies), len(cat.Negatives))
	}
	for _, b := range cat.Bodies {
		wire, err := hex.DecodeString(b.RawHex)
		if err != nil {
			t.Fatalf("%s: %v", b.Name, err)
		}
		if err := decodeFamily(b.Family, wire); err != nil {
			t.Fatalf("%s: %v", b.Name, err)
		}
		if b.Family == "authen_start" && b.Classify != nil {
			st, err := DecodeAuthenStart(wire)
			if err != nil {
				t.Fatal(err)
			}
			minor := byte(0)
			switch b.Classify.Flow {
			case "pap_login", "chap_login", "mschapv1", "mschapv2":
				minor = 1
			}
			flow, disp := ClassifyAuthenStart(minor, st)
			if flowName(flow) != b.Classify.Flow || dispName(disp) != b.Classify.Disposition {
				t.Fatalf("%s classify flow=%s disp=%s want %s/%s", b.Name, flowName(flow), dispName(disp), b.Classify.Flow, b.Classify.Disposition)
			}
		}
	}
	for _, n := range cat.Negatives {
		wire, err := hex.DecodeString(n.RawHex)
		if err != nil {
			t.Fatalf("%s: %v", n.Name, err)
		}
		err = decodeFamily(n.Family, wire)
		switch n.Reason {
		case "non_printable":
			if !errors.Is(err, ErrNonPrintable) {
				t.Fatalf("%s: %v", n.Name, err)
			}
		case "length_mismatch":
			if !errors.Is(err, ErrLengthMismatch) {
				t.Fatalf("%s: %v", n.Name, err)
			}
		case "acct_flags":
			if !errors.Is(err, ErrAcctFlags) {
				t.Fatalf("%s: %v", n.Name, err)
			}
		default:
			t.Fatalf("%s unknown reason %s", n.Name, n.Reason)
		}
	}
}

func decodeFamily(family string, wire []byte) error {
	switch family {
	case "authen_start":
		_, err := DecodeAuthenStart(wire)
		return err
	case "authen_continue":
		_, err := DecodeAuthenContinue(wire)
		return err
	case "authen_reply":
		_, err := DecodeAuthenReply(wire)
		return err
	case "author_request":
		_, err := DecodeAuthorRequest(wire)
		return err
	case "author_response":
		_, err := DecodeAuthorResponse(wire)
		return err
	case "acct_request":
		_, err := DecodeAcctRequest(wire)
		return err
	case "acct_reply":
		_, err := DecodeAcctReply(wire)
		return err
	default:
		return errors.New("unknown family")
	}
}

func flowName(f Flow) string {
	switch f {
	case FlowASCIILogin:
		return "ascii_login"
	case FlowPAPLogin:
		return "pap_login"
	case FlowCHAPLogin:
		return "chap_login"
	case FlowMSCHAPv1:
		return "mschapv1"
	case FlowMSCHAPv2:
		return "mschapv2"
	case FlowEnable:
		return "enable"
	case FlowASCIIChpass:
		return "ascii_chpass"
	default:
		return "none"
	}
}

func dispName(d Disposition) string {
	switch d {
	case DispositionFail:
		return "fail"
	case DispositionError:
		return "error"
	default:
		return "accept"
	}
}

func TestEnableGoldensIgnoreType(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"authen-start-enable-ascii.bin", "authen-start-enable-pap.bin"} {
		raw, err := os.ReadFile(protocolFile(t, "bodies", name))
		if err != nil {
			t.Fatal(err)
		}
		st, err := DecodeAuthenStart(raw)
		if err != nil {
			t.Fatal(err)
		}
		flow, disp := ClassifyAuthenStart(0, st)
		if flow != FlowEnable || disp != DispositionAccept {
			t.Fatalf("%s flow=%d disp=%d", name, flow, disp)
		}
	}
}

func TestMSCHAPGoldenLengths(t *testing.T) {
	t.Parallel()
	v1raw, err := os.ReadFile(protocolFile(t, "bodies", "authen-start-mschapv1.bin"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := DecodeAuthenStart(v1raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeMSCHAPv1Data(st.Data)
	if err != nil || d.ID != 1 || len(d.Challenge) != 8 || len(d.Response) != 49 {
		t.Fatalf("v1 %#v %v", d, err)
	}
	v2raw, err := os.ReadFile(protocolFile(t, "bodies", "authen-start-mschapv2.bin"))
	if err != nil {
		t.Fatal(err)
	}
	st2, err := DecodeAuthenStart(v2raw)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := DecodeMSCHAPv2Data(st2.Data)
	if err != nil || d2.ID != 2 || len(d2.Challenge) != 16 || len(d2.Response) != 49 {
		t.Fatalf("v2 %#v %v", d2, err)
	}
}
