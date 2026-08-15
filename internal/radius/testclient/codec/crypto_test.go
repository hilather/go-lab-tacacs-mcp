package codec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
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

func loadCryptoCatalog(t *testing.T) (cryptoCatalog, []byte, []byte) {
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

func TestIndependentUserPasswordVectors(t *testing.T) {
	t.Parallel()
	cat, rfc, lab := loadCryptoCatalog(t)
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

func TestIndependentResponseAuthenticatorVectors(t *testing.T) {
	t.Parallel()
	cat, rfc, lab := loadCryptoCatalog(t)
	for _, v := range cat.ResponseAuthenticator {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			secret := catalogSecret(t, v.Secret, rfc, lab)
			ra := mustAuth(t, v.RequestAuth)
			attrBytes := mustHex(t, v.AttributesHex)
			attrs, err := decodeAttrs(attrBytes, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ResponseAuthenticator(secret, Code(v.Code), v.ID, ra, attrs)
			if err != nil {
				t.Fatal(err)
			}
			want := mustAuth(t, v.ResponseAuth)
			if !equal16(got, want) {
				t.Fatalf("response authenticator mismatch")
			}
			pkt, err := Encode(Packet{Code: Code(v.Code), Identifier: v.ID, Authenticator: got, Attrs: attrs})
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateResponseAuthenticator(secret, pkt, ra); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIndependentAccountingRequestAuthenticatorVectors(t *testing.T) {
	t.Parallel()
	cat, rfc, lab := loadCryptoCatalog(t)
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

func TestIndependentMessageAuthenticatorVectors(t *testing.T) {
	t.Parallel()
	cat, rfc, lab := loadCryptoCatalog(t)
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
			if err := PutMessageAuthenticator(filled, got); err != nil {
				t.Fatal(err)
			}
			if err := ValidateMessageAuthenticator(secret, filled); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNewRequestAuthenticatorIsNonce(t *testing.T) {
	t.Parallel()
	fixed := bytes.Repeat([]byte{0x5a}, 16)
	got, err := NewRequestAuthenticator(bytes.NewReader(fixed))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], fixed) {
		t.Fatal("nonce is not the raw random bytes")
	}
}

func TestEmptySecretRejected(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	if _, err := HideUserPassword(nil, ra, []byte("x")); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("hide: %v", err)
	}
	if _, err := ResponseAuthenticator(nil, AccessAccept, 1, ra, nil); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("response: %v", err)
	}
}

func TestCanaryUnhiddenPasswordNeverInErrors(t *testing.T) {
	t.Parallel()
	const canaryPassword = "CANARY-UNHIDE-PASSWORD-zz99"
	const canarySecret = "CANARY-RADIUS-SECRET-aa11"
	var ra [16]byte
	for i := range ra {
		ra[i] = byte(i)
	}
	secret := []byte(canarySecret)
	password := []byte(canaryPassword)
	hidden, err := HideUserPassword(secret, ra, password)
	if err != nil {
		t.Fatal(err)
	}
	errs := []error{
		func() error { _, e := HideUserPassword(nil, ra, password); return e }(),
		func() error { _, e := UnhideUserPassword(secret, ra, hidden[:15]); return e }(),
		func() error { _, e := ResponseAuthenticator(nil, AccessAccept, 1, ra, nil); return e }(),
		func() error { return ValidateMessageAuthenticator(secret, make([]byte, 20)) }(),
	}
	canaries := []string{canaryPassword, canarySecret, string(hidden)}
	for i, e := range errs {
		if e == nil {
			t.Fatalf("case %d: expected error", i)
		}
		blob := fmt.Sprintf("%v %#v %s", e, e, e.Error())
		for _, c := range canaries {
			if c != "" && bytes.Contains([]byte(blob), []byte(c)) {
				t.Fatalf("case %d leaked canary through error fmt", i)
			}
		}
	}
	plain, err := UnhideUserPassword(secret, ra, hidden)
	if err != nil {
		t.Fatal(err)
	}
	Wipe(plain)
	if bytes.Contains(plain, password) {
		t.Fatal("wipe left canary in plaintext buffer")
	}
}
