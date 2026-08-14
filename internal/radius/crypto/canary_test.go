package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

const (
	canaryPassword = "CANARY-UNHIDE-PASSWORD-zz99"
	canarySecret   = "CANARY-RADIUS-SECRET-aa11"
)

func TestCanaryUnhiddenPasswordNeverInErrors(t *testing.T) {
	t.Parallel()
	ra := testRA(t)
	secret := []byte(canarySecret)
	password := []byte(canaryPassword)

	hidden, err := HideUserPassword(secret, ra, password)
	if err != nil {
		t.Fatal(err)
	}

	errs := []error{
		mustErr(t, func() error {
			_, e := HideUserPassword(nil, ra, password)
			return e
		}),
		mustErr(t, func() error {
			_, e := HideUserPassword(secret, ra, bytes.Repeat(password, 20))
			return e
		}),
		mustErr(t, func() error {
			_, e := UnhideUserPassword(nil, ra, hidden)
			return e
		}),
		mustErr(t, func() error {
			_, e := UnhideUserPassword(secret, ra, hidden[:15])
			return e
		}),
		mustErr(t, func() error {
			_, e := UnhideUserPassword(secret, ra, append(hidden, 1))
			return e
		}),
		mustErr(t, func() error {
			_, e := ResponseAuthenticator(nil, codec.CodeAccessAccept, 1, 0, ra, nil)
			return e
		}),
		mustErr(t, func() error {
			_, e := AccountingRequestAuthenticator(secret, make([]byte, 19))
			return e
		}),
		mustErr(t, func() error {
			return ValidateAccountingRequestAuthenticator(secret, make([]byte, 20))
		}),
		mustErr(t, func() error {
			return ValidateMessageAuthenticator(secret, make([]byte, 20))
		}),
		mustErr(t, func() error {
			pkt := make([]byte, 20)
			pkt[0] = byte(codec.CodeAccessAccept)
			pkt[3] = 20
			return ValidateResponseAuthenticator(secret, pkt, ra)
		}),
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
		raw, jerr := json.Marshal(struct{ E string }{E: e.Error()})
		if jerr != nil {
			t.Fatal(jerr)
		}
		for _, c := range canaries {
			if c != "" && bytes.Contains(raw, []byte(c)) {
				t.Fatalf("case %d leaked canary through json", i)
			}
		}
	}

	plain, err := UnhideUserPassword(secret, ra, hidden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, password) {
		t.Fatal("unhide failed")
	}
	// Successful unhide returns the password to the caller; wipe it here so
	// leftover test buffers do not retain the canary.
	Wipe(plain)
	if bytes.Contains(plain, password) {
		t.Fatal("wipe left canary in plaintext buffer")
	}
}

func mustErr(t *testing.T, fn func() error) error {
	t.Helper()
	return fn()
}
