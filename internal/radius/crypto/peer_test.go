package crypto_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

func protocolFile(t testing.TB, elem ...string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		cand := filepath.Join(append([]string{dir, "testdata", "protocol"}, elem...)...)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("testdata/protocol/%s not found", filepath.Join(elem...))
	return ""
}

func TestPeerUserPasswordHideBytes(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "radius", "crypto", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		RFCSecretHex string `json:"rfc_secret_hex"`
		LabSecretHex string `json:"lab_secret_hex"`
		UserPassword []struct {
			Name        string `json:"name"`
			Secret      string `json:"secret"`
			PasswordHex string `json:"password_hex"`
			RequestAuth string `json:"request_authenticator_hex"`
			HiddenHex   string `json:"hidden_hex"`
		} `json:"user_password"`
	}
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	rfc, err := hex.DecodeString(cat.RFCSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	lab, err := hex.DecodeString(cat.LabSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range cat.UserPassword {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			secret := rfc
			if v.Secret == "lab" {
				secret = lab
			}
			raB, err := hex.DecodeString(v.RequestAuth)
			if err != nil {
				t.Fatal(err)
			}
			var ra [16]byte
			copy(ra[:], raB)
			password, err := hex.DecodeString(v.PasswordHex)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(v.HiddenHex)
			if err != nil {
				t.Fatal(err)
			}
			prod, err := crypto.HideUserPassword(secret, ra, password)
			if err != nil {
				t.Fatal(err)
			}
			indep, err := tcodec.HideUserPassword(secret, ra, password)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(prod, want) || !bytes.Equal(indep, want) || !bytes.Equal(prod, indep) {
				t.Fatal("hide bytes differ")
			}
			prodPlain, err := crypto.UnhideUserPassword(secret, ra, prod)
			if err != nil {
				t.Fatal(err)
			}
			indepPlain, err := tcodec.UnhideUserPassword(secret, ra, indep)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(prodPlain, password) || !bytes.Equal(indepPlain, password) {
				t.Fatal("unhide mismatch")
			}
			crypto.Wipe(prodPlain)
			tcodec.Wipe(indepPlain)
		})
	}
}

func TestPeerResponseAuthenticatorBytes(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "radius", "crypto", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		RFCSecretHex          string `json:"rfc_secret_hex"`
		LabSecretHex          string `json:"lab_secret_hex"`
		ResponseAuthenticator []struct {
			Name          string `json:"name"`
			Secret        string `json:"secret"`
			Code          uint8  `json:"code"`
			ID            uint8  `json:"id"`
			Length        uint16 `json:"length"`
			RequestAuth   string `json:"request_authenticator_hex"`
			AttributesHex string `json:"attributes_hex"`
			ResponseAuth  string `json:"response_authenticator_hex"`
		} `json:"response_authenticator"`
	}
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	rfc, err := hex.DecodeString(cat.RFCSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	lab, err := hex.DecodeString(cat.LabSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range cat.ResponseAuthenticator {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			secret := rfc
			if v.Secret == "lab" {
				secret = lab
			}
			raB, err := hex.DecodeString(v.RequestAuth)
			if err != nil {
				t.Fatal(err)
			}
			var ra [16]byte
			copy(ra[:], raB)
			attrBytes, err := hex.DecodeString(v.AttributesHex)
			if err != nil {
				t.Fatal(err)
			}
			prodAttrs, err := attribute.Decode(attrBytes, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			indepPkt, err := tcodec.Decode(append(minHdr(v.Code, v.ID, ra, len(attrBytes)), attrBytes...))
			if err != nil {
				t.Fatal(err)
			}
			prod, err := crypto.ResponseAuthenticator(secret, codec.Code(v.Code), v.ID, v.Length, ra, prodAttrs)
			if err != nil {
				t.Fatal(err)
			}
			indep, err := tcodec.ResponseAuthenticator(secret, tcodec.Code(v.Code), v.ID, ra, indepPkt.Attrs)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(v.ResponseAuth)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(prod[:], want) || !bytes.Equal(indep[:], want) || !bytes.Equal(prod[:], indep[:]) {
				t.Fatal("response authenticator bytes differ")
			}
		})
	}
}

func TestPeerMessageAuthenticatorBytes(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "radius", "crypto", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		RFCSecretHex         string `json:"rfc_secret_hex"`
		LabSecretHex         string `json:"lab_secret_hex"`
		MessageAuthenticator []struct {
			Name      string `json:"name"`
			Secret    string `json:"secret"`
			PacketHex string `json:"packet_hex"`
			MAHex     string `json:"message_authenticator_hex"`
		} `json:"message_authenticator"`
	}
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	rfc, err := hex.DecodeString(cat.RFCSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	lab, err := hex.DecodeString(cat.LabSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range cat.MessageAuthenticator {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			secret := rfc
			if v.Secret == "lab" {
				secret = lab
			}
			pkt, err := hex.DecodeString(v.PacketHex)
			if err != nil {
				t.Fatal(err)
			}
			prod, err := crypto.MessageAuthenticator(secret, pkt)
			if err != nil {
				t.Fatal(err)
			}
			indep, err := tcodec.MessageAuthenticator(secret, pkt)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(v.MAHex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(prod[:], want) || !bytes.Equal(indep[:], want) || !bytes.Equal(prod[:], indep[:]) {
				t.Fatal("message authenticator bytes differ")
			}
		})
	}
}

func TestPeerAccountingRequestAuthenticatorBytes(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "radius", "crypto", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		RFCSecretHex                   string `json:"rfc_secret_hex"`
		LabSecretHex                   string `json:"lab_secret_hex"`
		AccountingRequestAuthenticator []struct {
			Name             string `json:"name"`
			Secret           string `json:"secret"`
			PacketHex        string `json:"packet_hex"`
			AuthenticatorHex string `json:"authenticator_hex"`
		} `json:"accounting_request_authenticator"`
	}
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	rfc, err := hex.DecodeString(cat.RFCSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	lab, err := hex.DecodeString(cat.LabSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range cat.AccountingRequestAuthenticator {
		secret := rfc
		if v.Secret == "lab" {
			secret = lab
		}
		pkt, err := hex.DecodeString(v.PacketHex)
		if err != nil {
			t.Fatal(err)
		}
		prod, err := crypto.AccountingRequestAuthenticator(secret, pkt)
		if err != nil {
			t.Fatal(err)
		}
		indep, err := tcodec.AccountingRequestAuthenticator(secret, pkt)
		if err != nil {
			t.Fatal(err)
		}
		want, err := hex.DecodeString(v.AuthenticatorHex)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(prod[:], want) || !bytes.Equal(indep[:], want) || !bytes.Equal(prod[:], indep[:]) {
			t.Fatal("accounting authenticator bytes differ")
		}
	}
}

func minHdr(code, id uint8, ra [16]byte, attrLen int) []byte {
	n := 20 + attrLen
	out := make([]byte, 20)
	out[0] = code
	out[1] = id
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	copy(out[4:], ra[:])
	return out
}
