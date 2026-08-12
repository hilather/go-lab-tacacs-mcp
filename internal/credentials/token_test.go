package credentials

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
)

type seqReader byte

func (s *seqReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*s)
		*s++
	}
	return len(p), nil
}

func TestGenerateAndDigestToken(t *testing.T) {
	t.Parallel()
	var r seqReader
	tok, err := GenerateToken(&r)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Len() != TokenByteLength {
		t.Fatalf("len=%d", tok.Len())
	}
	raw := tok.Bytes()
	if bytes.Equal(raw, make([]byte, TokenByteLength)) {
		t.Fatal("all-zero token")
	}
	sum := sha256.Sum256(raw)
	d := DigestToken(tok)
	if !bytes.Equal(d.Bytes(), sum[:]) {
		t.Fatal("digest mismatch")
	}
	if !EqualDigest(d, NewTokenDigest(sum[:])) {
		t.Fatal("EqualDigest")
	}
	other := DigestToken(NewTokenMaterial(append(raw[1:], raw[0])))
	if EqualDigest(d, other) {
		t.Fatal("different material")
	}
	idx := DigestIndex(d)
	if !bytes.Equal(idx[:], sum[:]) {
		t.Fatal("index")
	}
}

func TestZeroTokenDigestDoesNotAuthenticate(t *testing.T) {
	t.Parallel()
	var a, b TokenDigest
	if a.Equal(b) || EqualDigest(a, b) {
		t.Fatal("empty digests must not compare equal")
	}
	short := NewTokenDigest([]byte("short"))
	if short.Equal(NewTokenDigest([]byte("short"))) {
		t.Fatal("non-32-byte digest must not authenticate")
	}
}

func TestGenerateTokenEntropyFailure(t *testing.T) {
	t.Parallel()
	_, err := GenerateToken(io.LimitReader(bytes.NewReader([]byte{1, 2, 3}), 3))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenDigestRedacted(t *testing.T) {
	t.Parallel()
	canary := "unit-test-token-digest-canary-99"
	d := DigestToken(NewTokenMaterial([]byte(canary)))
	hexCanary := fmt.Sprintf("%x", sha256.Sum256([]byte(canary)))
	for _, out := range []string{
		fmt.Sprintf("%s", d),
		fmt.Sprintf("%v", d),
		fmt.Sprintf("%#v", d),
		fmt.Errorf("digest %v", d).Error(),
	} {
		assertNoCanary(t, "digest fmt", out, canary)
		if bytes.Contains([]byte(out), []byte(hexCanary)) {
			t.Fatalf("digest hex leaked in %q", out)
		}
	}
	_, err := json.Marshal(d)
	if err == nil {
		t.Fatal("json must fail")
	}
	assertNoCanary(t, "digest json err", err.Error(), canary)
	if !errors.Is(err, errNotSerializable) && err.Error() == "" {
		t.Fatal("json error")
	}
}
