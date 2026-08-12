package credentials

import (
	"bytes"
	"crypto/des"
	"crypto/sha1"
	"encoding/hex"
	"testing"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// Independent RFC 2433 DES transcription used only in tests.
func testDESKey(key7 []byte) []byte {
	key := make([]byte, 8)
	key[0] = key7[0]
	key[1] = (key7[0] << 7) | (key7[1] >> 1)
	key[2] = (key7[1] << 6) | (key7[2] >> 2)
	key[3] = (key7[2] << 5) | (key7[3] >> 3)
	key[4] = (key7[3] << 4) | (key7[4] >> 4)
	key[5] = (key7[4] << 3) | (key7[5] >> 5)
	key[6] = (key7[5] << 2) | (key7[6] >> 6)
	key[7] = key7[6] << 1
	return key
}

func testDESEncrypt(key7, data []byte) []byte {
	c, err := des.NewCipher(testDESKey(key7))
	if err != nil {
		panic(err)
	}
	out := make([]byte, 8)
	c.Encrypt(out, data)
	return out
}

func testChallengeResponse(challenge, hash []byte) []byte {
	z := make([]byte, 21)
	copy(z, hash)
	var out []byte
	out = append(out, testDESEncrypt(z[0:7], challenge)...)
	out = append(out, testDESEncrypt(z[7:14], challenge)...)
	out = append(out, testDESEncrypt(z[14:21], challenge)...)
	return out
}

func testNtHash(password []byte) []byte {
	u := utf16.Encode([]rune(string(password)))
	raw := make([]byte, len(u)*2)
	for i, c := range u {
		raw[i*2] = byte(c)
		raw[i*2+1] = byte(c >> 8)
	}
	h := md4.New()
	_, _ = h.Write(raw)
	return h.Sum(nil)
}

func TestMSCHAPv1IndependentVectorIncludesPPPId(t *testing.T) {
	t.Parallel()
	v := loadVectors(t)
	pw := []byte(v.MSCHAPv1.Password)
	chal := mustHex(t, v.MSCHAPv1.ChallengeHex)
	wantNT := mustHex(t, v.MSCHAPv1.NTPasswordHashHex)
	gotNT := testNtHash(pw)
	if hex.EncodeToString(gotNT) != v.MSCHAPv1.NTPasswordHashHex {
		t.Fatalf("NT hash %x want %s (RFC 3079)", gotNT, v.MSCHAPv1.NTPasswordHashHex)
	}
	if !bytes.Equal(NtPasswordHash(pw), wantNT) {
		t.Fatal("production NtPasswordHash != RFC 3079")
	}
	wantResp := testChallengeResponse(chal, wantNT)
	got := ChallengeResponse(chal, NtPasswordHash(pw))
	if !bytes.Equal(got, wantResp) {
		t.Fatalf("NT-response %x want %x", got, wantResp)
	}
	full := MSCHAPv1Response(pw, chal, true)
	if len(full) != MSCHAPResponseLen {
		t.Fatalf("len=%d", len(full))
	}
	if !bytes.Equal(full[24:48], wantResp) || full[48] != 1 {
		t.Fatal("v1 response layout")
	}
	if err := verifyMSCHAPv1(pw, chal, full); err != nil {
		t.Fatal(err)
	}
	// Wire form used by RFC 8907: PPP_id || challenge(8) || response(49).
	wire := append([]byte{v.MSCHAPv1.ID}, append(chal, full...)...)
	if len(wire) != 1+8+49 || wire[0] != v.MSCHAPv1.ID {
		t.Fatalf("wire len=%d id=%d", len(wire), wire[0])
	}
	// PPP id is not mixed into the DES response (generation ignores id).
	if !bytes.Equal(full, MSCHAPv1Response(pw, chal, true)) {
		t.Fatal("v1 response must be deterministic")
	}
	wrong := bytes.Clone(full)
	wrong[30] ^= 0xff
	if err := verifyMSCHAPv1(pw, chal, wrong); err == nil {
		t.Fatal("wrong NT-response must fail")
	}
	if err := verifyMSCHAPv1(pw, chal[:7], full); err == nil || !isMalformed(err) {
		t.Fatalf("short challenge: %v", err)
	}
}

func TestMSCHAPv1LMFlag(t *testing.T) {
	t.Parallel()
	pw := []byte("clientPass")
	chal := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	full := MSCHAPv1Response(pw, chal, false)
	if full[48] != 0 {
		t.Fatal("flags")
	}
	if err := verifyMSCHAPv1(pw, chal, full); err != nil {
		t.Fatal(err)
	}
	full[0] ^= 0xff
	if err := verifyMSCHAPv1(pw, chal, full); err == nil {
		t.Fatal("wrong LM-response must fail")
	}
}

func TestMSCHAPv2RFC2759VectorIncludesPPPId(t *testing.T) {
	t.Parallel()
	v := loadVectors(t)
	pw := []byte(v.MSCHAPv2.Password)
	user := []byte(v.MSCHAPv2.Username)
	auth := mustHex(t, v.MSCHAPv2.ChallengeHex)
	peer := mustHex(t, v.MSCHAPv2.PeerChallengeHex)
	if hex.EncodeToString(NtPasswordHash(pw)) != v.MSCHAPv2.NTPasswordHashHex {
		t.Fatalf("NT hash %x", NtPasswordHash(pw))
	}
	// Independent SHA1(peer||auth||user)[:8]
	h := sha1.New()
	_, _ = h.Write(peer)
	_, _ = h.Write(auth)
	_, _ = h.Write(user)
	ch := h.Sum(nil)[:8]
	if hex.EncodeToString(ch) != v.MSCHAPv2.ChallengeHashHex {
		t.Fatalf("challenge hash %x want %s", ch, v.MSCHAPv2.ChallengeHashHex)
	}
	nt := testChallengeResponse(ch, testNtHash(pw))
	if hex.EncodeToString(nt) != v.MSCHAPv2.NTResponseHex {
		t.Fatalf("NT-response %x want %s", nt, v.MSCHAPv2.NTResponseHex)
	}
	resp := MSCHAPv2Response(pw, user, auth, peer)
	if hex.EncodeToString(resp[24:48]) != v.MSCHAPv2.NTResponseHex {
		t.Fatal("production NT-response")
	}
	if err := verifyMSCHAPv2(pw, user, auth, resp); err != nil {
		t.Fatal(err)
	}
	wire := append([]byte{v.MSCHAPv2.ID}, append(auth, resp...)...)
	if len(wire) != 1+16+49 || wire[0] != v.MSCHAPv2.ID {
		t.Fatalf("wire len=%d id=%d", len(wire), wire[0])
	}
	if err := verifyMSCHAPv2(pw, []byte("user"), auth, resp); err == nil {
		t.Fatal("username case must affect v2")
	}
	resp[20] = 1
	if err := verifyMSCHAPv2(pw, user, auth, resp); err == nil || !isMalformed(err) {
		t.Fatalf("nonzero reserved: %v", err)
	}
	resp[20] = 0
	resp[48] = 1
	if err := verifyMSCHAPv2(pw, user, auth, resp); err == nil || !isMalformed(err) {
		t.Fatalf("nonzero flags: %v", err)
	}
}

func TestMSCHAPv2WrongLengths(t *testing.T) {
	t.Parallel()
	if err := verifyMSCHAPv2([]byte("p"), []byte("u"), make([]byte, 8), make([]byte, 49)); err == nil || !isMalformed(err) {
		t.Fatalf("got %v", err)
	}
}
