package testclient

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

type radiusMSCHAPv1Vector struct {
	Password           string `json:"password"`
	Username           string `json:"username"`
	ID                 byte   `json:"id"`
	ChallengeHex       string `json:"challenge_hex"`
	MSCHAPChallengeHex string `json:"ms_chap_challenge_hex"`
	MSCHAPResponseHex  string `json:"ms_chap_response_hex"`
	Expected           string `json:"expected"`
}

type radiusMSCHAPv2Vector struct {
	Password              string `json:"password"`
	Username              string `json:"username"`
	ID                    byte   `json:"id"`
	ChallengeHex          string `json:"challenge_hex"`
	PeerChallengeHex      string `json:"peer_challenge_hex"`
	MSCHAPChallengeHex    string `json:"ms_chap_challenge_hex"`
	MSCHAP2ResponseHex    string `json:"ms_chap2_response_hex"`
	MSCHAP2SuccessHex     string `json:"ms_chap2_success_hex"`
	AuthenticatorResponse string `json:"authenticator_response"`
	Expected              string `json:"expected"`
}

func loadMSCHAPv1(t *testing.T) radiusMSCHAPv1Vector {
	t.Helper()
	return loadJSON[radiusMSCHAPv1Vector](t, "radius", "mschap", "rfc2433-v1-radius.json")
}

func loadMSCHAPv2(t *testing.T) radiusMSCHAPv2Vector {
	t.Helper()
	return loadJSON[radiusMSCHAPv2Vector](t, "radius", "mschap", "rfc2759-v2-radius.json")
}

func loadJSON[T any](t *testing.T, elem ...string) T {
	t.Helper()
	raw, err := os.ReadFile(protocolFile(t, elem...))
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestIndependentMSCHAPVSAsRoundTrip(t *testing.T) {
	t.Parallel()
	v1 := loadMSCHAPv1(t)
	resp, err := hex.DecodeString(v1.MSCHAPResponseHex)
	if err != nil {
		t.Fatal(err)
	}
	chal, err := hex.DecodeString(v1.MSCHAPChallengeHex)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := EncodeAccessRequest([]byte("lab-secret-16chars!"), AccessRequest{
		Identifier:      9,
		UserName:        v1.Username,
		MSCHAPChallenge: chal,
		MSCHAPResponse:  resp,
		IncludeMA:       true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := codec.Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	var sawChal, sawResp bool
	for _, a := range dec.Attrs {
		vsa, err := codec.ParseVSA(a)
		if err != nil || vsa.Vendor != codec.VendorMicrosoft {
			continue
		}
		tlvs, err := codec.ParseVendorTLVs(vsa.Payload)
		if err != nil {
			t.Fatal(err)
		}
		for _, tl := range tlvs {
			switch tl.Type {
			case codec.VendorTypeMSCHAPChallenge:
				sawChal = true
				if hex.EncodeToString(tl.Value) != v1.MSCHAPChallengeHex {
					t.Fatalf("challenge %x", tl.Value)
				}
			case codec.VendorTypeMSCHAPResponse:
				sawResp = true
				if hex.EncodeToString(tl.Value) != v1.MSCHAPResponseHex {
					t.Fatalf("response %x", tl.Value)
				}
				if tl.Value[0] != v1.ID {
					t.Fatalf("ident=%d", tl.Value[0])
				}
			}
		}
	}
	if !sawChal || !sawResp {
		t.Fatal("missing Microsoft TLVs")
	}
}

func TestIndependentMSCHAPv2SuccessShape(t *testing.T) {
	t.Parallel()
	v2 := loadMSCHAPv2(t)
	success, err := hex.DecodeString(v2.MSCHAP2SuccessHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(success) != 43 || success[0] != v2.ID {
		t.Fatalf("len=%d id=%d", len(success), success[0])
	}
	if string(success[1:]) != v2.AuthenticatorResponse {
		t.Fatalf("success=%q want %q", success[1:], v2.AuthenticatorResponse)
	}
	attr, err := codec.MicrosoftVSA(codec.VendorTypeMSCHAP2Success, success)
	if err != nil {
		t.Fatal(err)
	}
	vsa, err := codec.ParseVSA(attr)
	if err != nil {
		t.Fatal(err)
	}
	tlvs, err := codec.ParseVendorTLVs(vsa.Payload)
	if err != nil || len(tlvs) != 1 || tlvs[0].Type != codec.VendorTypeMSCHAP2Success {
		t.Fatalf("tlvs=%+v err=%v", tlvs, err)
	}
}

func TestIndependentMSCHAPNotTACACSStartData(t *testing.T) {
	t.Parallel()
	v1 := loadMSCHAPv1(t)
	resp, _ := hex.DecodeString(v1.MSCHAPResponseHex)
	chal, _ := hex.DecodeString(v1.ChallengeHex)
	// TACACS START data is PPP_id || challenge || 49-octet response (58 bytes for v1).
	if len(resp) == 1+len(chal)+49 {
		t.Fatal("RADIUS MS-CHAP-Response must not be TACACS START data")
	}
	if len(resp) != 50 {
		t.Fatalf("RADIUS v1 response len=%d", len(resp))
	}
}

func TestEncodeAccessRequestMSCHAPConflicts(t *testing.T) {
	t.Parallel()
	_, err := EncodeAccessRequest([]byte("secret-16-chars!!"), AccessRequest{
		UserName:       "User",
		Password:       []byte("x"),
		MSCHAPResponse: make([]byte, 50),
	}, nil)
	if err != ErrConflictingAuth {
		t.Fatalf("pap+mschap: %v", err)
	}
	_, err = EncodeAccessRequest([]byte("secret-16-chars!!"), AccessRequest{
		UserName:        "User",
		MSCHAPResponse:  make([]byte, 50),
		MSCHAP2Response: make([]byte, 50),
	}, nil)
	if err != ErrConflictingAuth {
		t.Fatalf("v1+v2: %v", err)
	}
}
