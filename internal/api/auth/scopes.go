package auth

import "github.com/hilather/go-lab-tacacs-mcp/internal/config"

// Scopes is the exact-match administrative matrix. There is no hierarchy:
// state:write does not grant tokens:manage, runtime:reset, or config:reload.
func Scopes() []string { return config.Scopes() }

// ValidScope reports whether s is a known administrative scope.
func ValidScope(s string) bool { return config.ValidScope(s) }

// Satisfies reports whether have contains every required scope.
func Satisfies(have, need []string) bool {
	return len(Missing(have, need)) == 0
}

// Missing returns required scopes that have does not include, in need order.
func Missing(have, need []string) []string {
	if len(need) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	var missing []string
	for _, s := range need {
		if _, ok := set[s]; !ok {
			missing = append(missing, s)
		}
	}
	return missing
}

// Has reports whether have contains scope.
func Has(have []string, scope string) bool {
	for _, s := range have {
		if s == scope {
			return true
		}
	}
	return false
}
