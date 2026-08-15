package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

type cryptoCatalog struct {
	RFCSecretHex string `json:"rfc_secret_hex"`
	LabSecretHex string `json:"lab_secret_hex"`
	UserPassword []struct {
		Name        string `json:"name"`
		Secret      string `json:"secret"`
		PasswordHex string `json:"password_hex"`
		RequestAuth string `json:"request_authenticator_hex"`
		HiddenHex   string `json:"hidden_hex"`
	} `json:"user_password"`
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
	AccountingRequestAuthenticator []struct {
		Name             string `json:"name"`
		Secret           string `json:"secret"`
		PacketHex        string `json:"packet_hex"`
		AuthenticatorHex string `json:"authenticator_hex"`
	} `json:"accounting_request_authenticator"`
	MessageAuthenticator []struct {
		Name      string `json:"name"`
		Secret    string `json:"secret"`
		PacketHex string `json:"packet_hex"`
		MAHex     string `json:"message_authenticator_hex"`
	} `json:"message_authenticator"`
}

func loadCatalog(t *testing.T) (cryptoCatalog, []byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile(protocolFile(t, "radius", "crypto", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat cryptoCatalog
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
	if len(cat.UserPassword) < 6 || len(cat.ResponseAuthenticator) < 3 ||
		len(cat.AccountingRequestAuthenticator) < 1 || len(cat.MessageAuthenticator) < 3 {
		t.Fatalf("catalog incomplete")
	}
	return cat, rfc, lab
}

func catalogSecret(t *testing.T, which string, rfc, lab []byte) []byte {
	t.Helper()
	switch which {
	case "rfc":
		return rfc
	case "lab":
		return lab
	default:
		t.Fatalf("unknown secret %q", which)
		return nil
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustAuth(t *testing.T, s string) [16]byte {
	t.Helper()
	b := mustHex(t, s)
	if len(b) != 16 {
		t.Fatalf("authenticator len %d", len(b))
	}
	var a [16]byte
	copy(a[:], b)
	return a
}

func TestUserPasswordVectors(t *testing.T) {
	t.Parallel()
	cat, rfc, lab := loadCatalog(t)
	for _, v := range cat.UserPassword {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			secret := catalogSecret(t, v.Secret, rfc, lab)
			ra := mustAuth(t, v.RequestAuth)
			password := mustHex(t, v.PasswordHex)
			want := mustHex(t, v.HiddenHex)
			got, err := HideUserPassword(secret, ra, password)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("hide mismatch")
			}
			plain, err := UnhideUserPassword(secret, ra, want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plain, password) {
				t.Fatalf("unhide mismatch")
			}
			Wipe(plain)
		})
	}
}

func TestResponseAuthenticatorVectors(t *testing.T) {
	t.Parallel()
	cat, rfc, lab := loadCatalog(t)
	for _, v := range cat.ResponseAuthenticator {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			secret := catalogSecret(t, v.Secret, rfc, lab)
			ra := mustAuth(t, v.RequestAuth)
			attrBytes := mustHex(t, v.AttributesHex)
			attrs, err := attribute.Decode(attrBytes, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ResponseAuthenticator(secret, codec.Code(v.Code), v.ID, v.Length, ra, attrs)
			if err != nil {
				t.Fatal(err)
			}
			want := mustAuth(t, v.ResponseAuth)
			if !equal16(got, want) {
				t.Fatalf("response authenticator mismatch")
			}
			pkt := make([]byte, int(v.Length))
			pkt[0] = v.Code
			pkt[1] = v.ID
			pkt[2] = byte(v.Length >> 8)
			pkt[3] = byte(v.Length)
			copy(pkt[4:20], got[:])
			copy(pkt[20:], attrBytes)
			if err := ValidateResponseAuthenticator(secret, pkt, ra); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAccountingRequestAuthenticatorVectors(t *testing.T) {
	t.Parallel()
	cat, rfc, lab := loadCatalog(t)
	for _, v := range cat.AccountingRequestAuthenticator {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			secret := catalogSecret(t, v.Secret, rfc, lab)
			pkt := mustHex(t, v.PacketHex)
			got, err := AccountingRequestAuthenticator(secret, pkt)
			if err != nil {
				t.Fatal(err)
			}
			want := mustAuth(t, v.AuthenticatorHex)
			if !equal16(got, want) {
				t.Fatalf("accounting authenticator mismatch")
			}
			signed := append([]byte(nil), pkt...)
			copy(signed[4:20], got[:])
			if err := ValidateAccountingRequestAuthenticator(secret, signed); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMessageAuthenticatorVectors(t *testing.T) {
	t.Parallel()
	cat, rfc, lab := loadCatalog(t)
	for _, v := range cat.MessageAuthenticator {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			secret := catalogSecret(t, v.Secret, rfc, lab)
			pkt := mustHex(t, v.PacketHex)
			got, err := MessageAuthenticator(secret, pkt)
			if err != nil {
				t.Fatal(err)
			}
			want := mustAuth(t, v.MAHex)
			if !equal16(got, want) {
				t.Fatalf("message authenticator mismatch")
			}
			filled := append([]byte(nil), pkt...)
			// write computed MA into the first type-80 value
			off := 20
			for off+2 <= len(filled) {
				alen := int(filled[off+1])
				if filled[off] == attribute.TypeMessageAuthenticator {
					copy(filled[off+2:off+18], got[:])
					break
				}
				off += alen
			}
			if err := ValidateMessageAuthenticator(secret, filled); err != nil {
				t.Fatal(err)
			}
		})
	}
}
