package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// SecretWarning is a non-fatal compile diagnostic. It must never include
// secret bytes or fingerprints.
type SecretWarning struct {
	Code    domain.Code
	Message string
	Path    string
}

// SecretLookup resolves a typed secret reference to bytes. Callers wipe the
// returned buffer.
type SecretLookup func(ref SecretRef) ([]byte, error)

// CheckSharedSecret enforces length, character-class, and known-weak policy.
// Values of 32 or more bytes are accepted without truncation.
func CheckSharedSecret(policy SharedSecretPolicy, secret credentials.SharedSecret, path string) error {
	raw := secret.Bytes()
	defer wipeBytes(raw)
	return checkSharedSecretBytes(policy, raw, path, "legacy shared secret")
}

// CheckRADIUSSharedSecret enforces RADIUS secret policy. Values of 32 or more
// bytes are accepted without truncation.
func CheckRADIUSSharedSecret(policy SharedSecretPolicy, secret credentials.RADIUSSharedSecret, path string) error {
	raw := secret.Bytes()
	defer wipeBytes(raw)
	return checkSharedSecretBytes(policy, raw, path, "RADIUS shared secret")
}

func checkSharedSecretBytes(policy SharedSecretPolicy, raw []byte, path, noun string) error {
	if policy.MinimumLengthCharacters > 0 && len(raw) < policy.MinimumLengthCharacters {
		return domain.NewError(domain.CodeSharedSecretPolicyViolation, noun+" is shorter than the configured minimum").WithPath(path)
	}
	if policy.MinimumCharacterClasses > 0 && characterClasses(raw) < policy.MinimumCharacterClasses {
		return domain.NewError(domain.CodeSharedSecretPolicyViolation, noun+" does not meet the character-class policy").WithPath(path)
	}
	if policy.RejectKnownWeakValues && isKnownWeakSecret(raw) {
		return domain.NewError(domain.CodeSharedSecretPolicyViolation, noun+" is a known-weak value").WithPath(path)
	}
	return nil
}

func characterClasses(b []byte) int {
	var lower, upper, digit, other bool
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			other = true
			b = b[1:]
			continue
		}
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
		b = b[size:]
	}
	n := 0
	if lower {
		n++
	}
	if upper {
		n++
	}
	if digit {
		n++
	}
	if other {
		n++
	}
	return n
}

func isKnownWeakSecret(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	s := stringsToLowerASCII(b)
	switch s {
	case "password", "secret", "changeme", "tacacs", "tacacs+", "admin",
		"test", "testing", "lab", "default", "cisco", "public", "private",
		"123456", "12345678", "qwerty":
		return true
	default:
		return false
	}
}

func stringsToLowerASCII(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + ('a' - 'A')
		} else {
			out[i] = c
		}
	}
	return string(out)
}

// SecretLifecycleStatus compiles non-secret rotation health.
func SecretLifecycleStatus(meta SecretLifecycleMeta, policy SharedSecretPolicy, now time.Time) domain.SecretLifecycle {
	if meta.LastRotatedAt == nil {
		return domain.LifecycleUnknown
	}
	interval := meta.RotationInterval
	if interval <= 0 {
		interval = policy.DefaultRotationInterval
	}
	if interval <= 0 {
		return domain.LifecycleUnknown
	}
	due := meta.LastRotatedAt.Add(interval)
	if !now.Before(due) {
		return domain.LifecycleOverdue
	}
	if policy.RotationWarningBefore > 0 && !now.Before(due.Add(-policy.RotationWarningBefore)) {
		return domain.LifecycleDueSoon
	}
	return domain.LifecycleCurrent
}

// reuseTracker groups clients that share a secret using a process-local HMAC.
// The key and fingerprints never leave this type.
type reuseTracker struct {
	key  []byte
	seen map[string][]string
}

func newReuseTracker(key []byte) *reuseTracker {
	cp := make([]byte, len(key))
	copy(cp, key)
	return &reuseTracker{key: cp, seen: map[string][]string{}}
}

func (t *reuseTracker) add(id string, secret []byte) {
	if t == nil || len(t.key) == 0 || len(secret) == 0 {
		return
	}
	mac := hmac.New(sha256.New, t.key)
	_, _ = mac.Write(secret)
	sum := hex.EncodeToString(mac.Sum(nil))
	t.seen[sum] = append(t.seen[sum], id)
}

func (t *reuseTracker) warnings() []SecretWarning {
	if t == nil {
		return nil
	}
	var out []SecretWarning
	for _, ids := range t.seen {
		if len(ids) < 2 {
			continue
		}
		sort.Strings(ids)
		out = append(out, SecretWarning{
			Code:    domain.CodeSharedSecretPolicyViolation,
			Message: "shared secret is reused by clients " + strings.Join(ids, ", "),
			Path:    "clients",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Message < out[j].Message })
	return out
}

// EvaluateSecrets applies shared-secret policy and optional reuse detection.
// Missing files surface as SECRET_FILE_UNREADABLE. Overdue rotation is a
// warning unless the caller treats CodeSharedSecretRotationOverdue as fatal.
// RADIUS endpoint secrets use Security.RADIUSSharedSecrets and purpose
// radius_shared_secret. Cross-purpose reuse is warned when the HMAC key is set.
func EvaluateSecrets(doc *Document, lookup SecretLookup, now time.Time, hmacKey []byte) (lifecycles map[string]domain.SecretLifecycle, warnings []SecretWarning, err error) {
	if doc == nil || lookup == nil {
		return nil, nil, nil
	}
	lifecycles = make(map[string]domain.SecretLifecycle, len(doc.Clients))
	policy := doc.Security.LegacySharedSecrets
	radiusPolicy := doc.Security.RADIUSSharedSecrets
	warnReuse := (policy.WarnOnReuse || radiusPolicy.WarnOnReuse) && len(hmacKey) > 0
	var reuse *reuseTracker
	if warnReuse {
		reuse = newReuseTracker(hmacKey)
	}
	for i, c := range doc.Clients {
		// TLS-only (or any client without a legacy secret) is omitted.
		// unknown is reserved for a present secret with missing rotation metadata.
		if c.Legacy.SharedSecret.Set() {
			path := indexPath("clients", i) + ".legacy.shared_secret"
			raw, rerr := lookup(c.Legacy.SharedSecret)
			if rerr != nil {
				return nil, nil, mapSecretLookupErr(rerr, path)
			}
			if err := checkSharedSecretBytes(policy, raw, path, "legacy shared secret"); err != nil {
				wipeBytes(raw)
				return nil, nil, err
			}
			if reuse != nil {
				reuse.add(c.ID, raw)
			}
			wipeBytes(raw)
			st := SecretLifecycleStatus(c.Legacy.SharedSecretLifecycle, policy, now)
			lifecycles[c.ID] = st
			if st == domain.LifecycleOverdue {
				warnings = append(warnings, SecretWarning{
					Code:    domain.CodeSharedSecretRotationOverdue,
					Message: "legacy shared secret rotation is overdue",
					Path:    path,
				})
			}
		}
		for j, ep := range c.Endpoints {
			if ep.RADIUS == nil || !ep.RADIUS.SharedSecret.Set() {
				continue
			}
			path := indexPath(indexPath("clients", i)+".endpoints", j) + ".radius.shared_secret"
			raw, rerr := lookup(ep.RADIUS.SharedSecret)
			if rerr != nil {
				return nil, nil, mapSecretLookupErr(rerr, path)
			}
			if err := checkSharedSecretBytes(radiusPolicy, raw, path, "RADIUS shared secret"); err != nil {
				wipeBytes(raw)
				return nil, nil, err
			}
			if reuse != nil {
				reuse.add(c.ID+" (radius)", raw)
			}
			wipeBytes(raw)
			st := SecretLifecycleStatus(ep.RADIUS.SharedSecretLifecycle, radiusPolicy, now)
			lifecycles[c.ID+"/"+ep.ID] = st
			if st == domain.LifecycleOverdue {
				warnings = append(warnings, SecretWarning{
					Code:    domain.CodeSharedSecretRotationOverdue,
					Message: "RADIUS shared secret rotation is overdue",
					Path:    path,
				})
			}
		}
	}
	if reuse != nil {
		warnings = append(warnings, reuse.warnings()...)
	}
	return lifecycles, warnings, nil
}

func mapSecretLookupErr(err error, path string) error {
	if err == nil {
		return nil
	}
	if de, ok := domain.AsError(err); ok {
		if de.Path == "" {
			return de.WithPath(path)
		}
		return de
	}
	return secretFileError(path, "secret file is not readable")
}
