package testclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

func TestAccessRequestPAPVectorBytes(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "radius", "crypto", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		RFCSecretHex string `json:"rfc_secret_hex"`
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
	secret, err := hex.DecodeString(cat.RFCSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		PasswordHex string
		RequestAuth string
		HiddenHex   string
	}
	for _, row := range cat.UserPassword {
		if row.Name == "rfc2865-7.1-arctangent" {
			v.PasswordHex = row.PasswordHex
			v.RequestAuth = row.RequestAuth
			v.HiddenHex = row.HiddenHex
			break
		}
	}
	if v.HiddenHex == "" {
		t.Fatal("missing rfc2865-7.1-arctangent")
	}
	raBytes, err := hex.DecodeString(v.RequestAuth)
	if err != nil {
		t.Fatal(err)
	}
	var ra [16]byte
	copy(ra[:], raBytes)
	password, err := hex.DecodeString(v.PasswordHex)
	if err != nil {
		t.Fatal(err)
	}
	wantHidden, err := hex.DecodeString(v.HiddenHex)
	if err != nil {
		t.Fatal(err)
	}

	wire, err := EncodeAccessRequest(secret, AccessRequest{
		Identifier:    0,
		Authenticator: ra,
		UserName:      "flopsy",
		Password:      password,
		IncludeMA:     false,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	up, ok := codec.First(got.Attrs, codec.TypeUserPassword)
	if !ok {
		t.Fatal("missing User-Password")
	}
	if !bytes.Equal(up.Value, wantHidden) {
		t.Fatal("encoded User-Password bytes do not match RFC vector")
	}
	codec.Wipe(password)
}

func TestAccessReplyRejectsBadResponseAuthenticator(t *testing.T) {
	t.Parallel()
	secret := []byte("lab-radius-test-secret-32octets!!")
	var ra [16]byte
	for i := range ra {
		ra[i] = byte(i + 1)
	}
	macZero := codec.Attr{Type: codec.TypeMessageAuthenticator, Value: make([]byte, 16)}
	pkt, err := codec.Encode(codec.Packet{
		Code:          codec.AccessReject,
		Identifier:    3,
		Authenticator: ra, // not a real Response Authenticator
		Attrs:         []codec.Attr{macZero},
	})
	if err != nil {
		t.Fatal(err)
	}
	mac, err := codec.MessageAuthenticator(secret, pkt)
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.PutMessageAuthenticator(pkt, mac); err != nil {
		t.Fatal(err)
	}
	_, err = DecodeAccessReply(secret, ra, pkt)
	if err != ErrInvalidResponseAuthenticator {
		t.Fatalf("err=%v", err)
	}
}

func TestAccessReplyRequiresMessageAuthenticator(t *testing.T) {
	t.Parallel()
	secret := []byte("lab-radius-test-secret-32octets!!")
	var ra [16]byte
	auth, err := codec.ResponseAuthenticator(secret, codec.AccessAccept, 1, ra, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := codec.Encode(codec.Packet{
		Code:          codec.AccessAccept,
		Identifier:    1,
		Authenticator: auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeAccessReply(secret, ra, pkt)
	if err != ErrInvalidMessageAuthenticator {
		t.Fatalf("err=%v", err)
	}
}

func TestAccountingRequestAuthenticatorOnWire(t *testing.T) {
	t.Parallel()
	secret := []byte("lab-radius-test-secret-32octets!!")
	wire, err := EncodeAccountingRequest(secret, AccountingRequest{
		Identifier: 7,
		StatusType: AcctStart,
		SessionID:  "sess-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.ValidateAccountingRequestAuthenticator(secret, wire); err != nil {
		t.Fatal(err)
	}
	got, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != codec.AccountingRequest || got.Identifier != 7 {
		t.Fatalf("got %s id=%d", got.Code, got.Identifier)
	}
	st, ok := codec.First(got.Attrs, codec.TypeAcctStatusType)
	if !ok || len(st.Value) != 4 || st.Value[3] != 1 {
		t.Fatalf("status-type %x", st.Value)
	}
}

func TestAccountingResponseRequiresMA(t *testing.T) {
	t.Parallel()
	secret := []byte("lab-radius-test-secret-32octets!!")
	var ra [16]byte
	auth, err := codec.ResponseAuthenticator(secret, codec.AccountingResponse, 4, ra, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := codec.Encode(codec.Packet{
		Code:          codec.AccountingResponse,
		Identifier:    4,
		Authenticator: auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeAccountingResponse(secret, ra, pkt)
	if err != ErrInvalidMessageAuthenticator {
		t.Fatalf("err=%v", err)
	}
}

func TestAccessRequestWithMAValidates(t *testing.T) {
	t.Parallel()
	secret := []byte("lab-radius-test-secret-32octets!!")
	var ra [16]byte
	for i := range ra {
		ra[i] = byte(0xa0 + i)
	}
	wire, err := EncodeAccessRequest(secret, AccessRequest{
		Identifier:    9,
		Authenticator: ra,
		UserName:      "lab",
		Password:      []byte("pw"),
		IncludeMA:     true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.ValidateMessageAuthenticator(secret, wire); err != nil {
		t.Fatal(err)
	}
	got, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	ma, ok := codec.First(got.Attrs, codec.TypeMessageAuthenticator)
	if !ok || len(ma.Value) != 16 || bytes.Equal(ma.Value, make([]byte, 16)) {
		t.Fatal("MA missing or still zero")
	}
}

func TestAccountingRequestWithMAValidates(t *testing.T) {
	t.Parallel()
	secret := []byte("lab-radius-test-secret-32octets!!")
	wire, err := EncodeAccountingRequest(secret, AccountingRequest{
		Identifier: 4,
		StatusType: AcctStop,
		SessionID:  "sess-2",
		IncludeMA:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.ValidateMessageAuthenticator(secret, wire); err != nil {
		t.Fatal(err)
	}
	// Accounting-Request Authenticator is MD5 over attributes with MA zeroed.
	zeroed, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	for i := range zeroed.Attrs {
		if zeroed.Attrs[i].Type == codec.TypeMessageAuthenticator {
			zeroed.Attrs[i].Value = make([]byte, 16)
		}
	}
	check, err := codec.Encode(zeroed)
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.ValidateAccountingRequestAuthenticator(secret, check); err != nil {
		t.Fatal(err)
	}
}

func TestEncodeAccessRequestRejectsConflict(t *testing.T) {
	t.Parallel()
	_, err := EncodeAccessRequest([]byte("lab-radius-test-secret-32octets!!"), AccessRequest{
		UserName:     "lab",
		Password:     []byte("x"),
		CHAPPassword: make([]byte, 17),
	}, nil)
	if err != ErrConflictingAuth {
		t.Fatalf("err=%v", err)
	}
}
