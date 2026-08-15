package crypto

import (
	"strings"
	"testing"
)

func FuzzUnhideUserPassword(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(bytes16(0x11), bytes16(0x22))
	f.Add([]byte("lab-radius-test-secret-32octets!!"), bytes16(0x33))
	f.Fuzz(func(t *testing.T, secret, hidden []byte) {
		plain, err := UnhideUserPassword(secret, [16]byte{1}, hidden)
		if err != nil {
			msg := err.Error()
			if len(secret) > 0 && strings.Contains(msg, string(secret)) {
				t.Fatalf("secret leaked in error")
			}
			if len(hidden) >= 8 && strings.Contains(msg, string(hidden)) {
				t.Fatalf("hidden leaked in error")
			}
			return
		}
		Wipe(plain)
	})
}

func FuzzValidateMessageAuthenticator(f *testing.F) {
	f.Add([]byte("lab-radius-test-secret-32octets!!"), make([]byte, 20))
	f.Add([]byte("lab-radius-test-secret-32octets!!"), append(
		[]byte{1, 1, 0, 38}, append(make([]byte, 16), 80, 18)...))
	f.Fuzz(func(t *testing.T, secret, packet []byte) {
		err := ValidateMessageAuthenticator(secret, packet)
		if err == nil {
			return
		}
		msg := err.Error()
		if len(secret) > 4 && strings.Contains(msg, string(secret)) {
			t.Fatalf("secret leaked in error")
		}
	})
}

func FuzzAccountingRequestAuthenticator(f *testing.F) {
	f.Add([]byte("lab-radius-test-secret-32octets!!"), make([]byte, 20))
	f.Fuzz(func(t *testing.T, secret, packet []byte) {
		_, err := AccountingRequestAuthenticator(secret, packet)
		if err == nil {
			return
		}
		if len(secret) > 4 && strings.Contains(err.Error(), string(secret)) {
			t.Fatalf("secret leaked in error")
		}
	})
}

func bytes16(v byte) []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = v
	}
	return b
}
