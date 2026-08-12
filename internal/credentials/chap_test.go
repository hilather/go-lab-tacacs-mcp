package credentials

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vectorFile struct {
	CHAP []struct {
		Name         string `json:"name"`
		ID           byte   `json:"id"`
		Secret       string `json:"secret"`
		ChallengeHex string `json:"challenge_hex"`
		ResponseHex  string `json:"response_hex"`
	} `json:"chap"`
	MSCHAPv2 struct {
		ID                byte   `json:"id"`
		Username          string `json:"username"`
		Password          string `json:"password"`
		ChallengeHex      string `json:"challenge_hex"`
		PeerChallengeHex  string `json:"peer_challenge_hex"`
		ChallengeHashHex  string `json:"challenge_hash_hex"`
		NTResponseHex     string `json:"nt_response_hex"`
		NTPasswordHashHex string `json:"nt_password_hash_hex"`
	} `json:"mschapv2_rfc2759"`
	MSCHAPv1 struct {
		ID                byte   `json:"id"`
		Password          string `json:"password"`
		ChallengeHex      string `json:"challenge_hex"`
		NTPasswordHashHex string `json:"nt_password_hash_hex"`
	} `json:"mschapv1"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCHAPIndependentVectorsIncludePPPId(t *testing.T) {
	t.Parallel()
	v := loadVectors(t)
	if len(v.CHAP) < 2 {
		t.Fatal("need at least two CHAP vectors")
	}
	for _, c := range v.CHAP {
		chal := mustHex(t, c.ChallengeHex)
		want := mustHex(t, c.ResponseHex)
		// Independent of CHAPResponse: hashlib-equivalent MD5(id||secret||challenge).
		h := md5.New()
		_, _ = h.Write([]byte{c.ID})
		_, _ = h.Write([]byte(c.Secret))
		_, _ = h.Write(chal)
		got := h.Sum(nil)
		if hex.EncodeToString(got) != c.ResponseHex {
			t.Fatalf("%s: independent MD5=%x want %s", c.Name, got, c.ResponseHex)
		}
		if err := verifyCHAP(c.ID, []byte(c.Secret), chal, want, 8); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		wire := append([]byte{c.ID}, append(chal, want...)...)
		if wire[0] != c.ID {
			t.Fatal("wire must start with PPP id")
		}
	}
	if v.CHAP[0].ChallengeHex == v.CHAP[1].ChallengeHex && v.CHAP[0].Secret == v.CHAP[1].Secret {
		if v.CHAP[0].ResponseHex == v.CHAP[1].ResponseHex {
			t.Fatal("different PPP ids must produce different CHAP responses")
		}
	}
}

func TestCHAPRejectsShortChallenge(t *testing.T) {
	t.Parallel()
	err := verifyCHAP(1, []byte("s"), []byte("short"), make([]byte, 16), 8)
	if err == nil || !isMalformed(err) {
		t.Fatalf("got %v", err)
	}
}

func isMalformed(err error) bool {
	var ae AuthError
	return errorAsAuth(err, &ae) && ae.Kind == KindMalformed
}

func errorAsAuth(err error, dest *AuthError) bool {
	if dest == nil {
		return false
	}
	ae, ok := err.(AuthError)
	if !ok {
		return false
	}
	*dest = ae
	return true
}
