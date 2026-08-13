package observability

import (
	"fmt"
	"strings"
)

// Secret class canaries used by the full redaction matrix. Each value is
// unique so a leak names the class.
const (
	CanaryLegacyShared = "unit-test-obs-legacy-shared-canary-aa01"
	CanaryLogin        = "unit-test-obs-login-verifier-canary-aa02"
	CanaryChallenge    = "unit-test-obs-challenge-secret-canary-aa03"
	CanaryEnable       = "unit-test-obs-enable-verifier-canary-aa04"
	CanaryToken        = "unit-test-obs-bearer-token-canary-aa05"
	CanaryTLSKey       = "unit-test-obs-tls-private-key-canary-aa06"
	CanaryCookie       = "unit-test-obs-session-cookie-canary-aa07"
	CanaryPassword     = "unit-test-obs-password-plain-canary-aa08"
)

// AllCanaries is every secret class planted in the matrix.
func AllCanaries() []string {
	return []string{
		CanaryLegacyShared, CanaryLogin, CanaryChallenge, CanaryEnable,
		CanaryToken, CanaryTLSKey, CanaryCookie, CanaryPassword,
	}
}

// ScanCanaries reports every canary found in blob. allow is the one-time
// token create exception (may be empty).
func ScanCanaries(blob string, allow ...string) []string {
	allowed := map[string]struct{}{}
	for _, a := range allow {
		if a != "" {
			allowed[a] = struct{}{}
		}
	}
	var hits []string
	for _, c := range AllCanaries() {
		if _, ok := allowed[c]; ok {
			continue
		}
		if strings.Contains(blob, c) {
			hits = append(hits, c)
		}
	}
	return hits
}

// FormatHits is a test helper.
func FormatHits(surface string, hits []string) string {
	return fmt.Sprintf("%s leaked canaries: %s", surface, strings.Join(hits, ", "))
}
