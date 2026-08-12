package config

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

var quotedLiteral = regexp.MustCompile("`[^`]*`|" + `"[^"]*"` + "|" + `'[^']*'`)

func yamlError(message string) domain.Error {
	return domain.NewError(domain.CodeConfigYAMLInvalid, message)
}

func yamlErrorAt(path, message string) domain.Error {
	return domain.NewError(domain.CodeConfigYAMLInvalid, message).WithPath(path)
}

func unknownField(path, field string, known []string) domain.Error {
	msg := "unknown field"
	if sug := suggestField(field, known); sug != "" {
		msg = "unknown field; did you mean " + sug + "?"
	}
	full := field
	if path != "" {
		full = path + "." + field
	}
	return domain.NewError(domain.CodeConfigUnknownField, msg).WithPath(full)
}

func secretFileError(path, message string) domain.Error {
	return domain.NewError(domain.CodeSecretFileUnreadable, message).WithPath(path)
}

func mapYAMLError(err error) error {
	if err == nil {
		return nil
	}
	if de, ok := domain.AsError(err); ok {
		return de
	}
	msg := sanitizeYAMLErr(err.Error())
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "not found in type") || strings.Contains(lower, "unknown field") {
		field := extractUnknownField(err.Error())
		path := field
		return domain.NewError(domain.CodeConfigUnknownField, "unknown field").WithPath(path)
	}
	return yamlError(msg)
}

func sanitizeYAMLErr(s string) string {
	return quotedLiteral.ReplaceAllString(s, "<redacted>")
}

func extractUnknownField(s string) string {
	// yaml.v3: "line N: field NAME not found in type ..."
	const mid = "field "
	const end = " not found"
	i := strings.Index(s, mid)
	if i < 0 {
		return ""
	}
	rest := s[i+len(mid):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	name := rest[:j]
	if name == "" || strings.ContainsAny(name, " \t\n") || !utf8.ValidString(name) {
		return ""
	}
	return name
}

func suggestField(unknown string, known []string) string {
	if unknown == "" || len(known) == 0 {
		return ""
	}
	u := strings.ToLower(unknown)
	best := ""
	bestD := 3
	for _, k := range known {
		d := levenshtein(u, strings.ToLower(k))
		if d < bestD || (d == bestD && best != "" && k < best) || (d == bestD && best == "") {
			if d <= 2 || (len(u) > 4 && d <= 3) {
				bestD = d
				best = k
			}
		}
	}
	return best
}

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	ra := []rune(a)
	rb := []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := cur[j-1] + 1
			sub := prev[j-1] + cost
			cur[j] = min3(del, ins, sub)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	if key == "" {
		return parent
	}
	return parent + "." + key
}

func indexPath(parent string, i int) string {
	return parent + "[" + itoa(i) + "]"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}
