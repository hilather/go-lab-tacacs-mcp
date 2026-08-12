package credentials

import (
	"golang.org/x/text/secure/precis"
)

// CanonicalUsername applies RFC 8265 UsernameCasePreserved (PRECIS).
// The result is the TACACS user id used for lookup and for MS-CHAP v2
// ChallengeHash. It is not a lowercase fold.
func CanonicalUsername(raw string) (string, error) {
	out, err := precis.UsernameCasePreserved.String(raw)
	if err != nil || out == "" {
		return "", invalidMaterial()
	}
	return out, nil
}
