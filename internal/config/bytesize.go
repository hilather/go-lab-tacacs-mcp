package config

import (
	"strconv"
	"strings"
	"unicode"
)

func parseByteSize(s, path string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 || n > int64(^uint(0)>>1) {
			return 0, yamlErrorAt(path, "invalid byte size")
		}
		return int(n), nil
	}
	compact := strings.ToLower(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s))
	type suffix struct {
		tok string
		mul int64
	}
	// Longest suffix first.
	for _, suf := range []suffix{
		{"gib", 1 << 30},
		{"mib", 1 << 20},
		{"kib", 1 << 10},
		{"gb", 1_000_000_000},
		{"mb", 1_000_000},
		{"kb", 1_000},
		{"b", 1},
	} {
		if !strings.HasSuffix(compact, suf.tok) {
			continue
		}
		num := strings.TrimSpace(compact[:len(compact)-len(suf.tok)])
		if num == "" {
			return 0, yamlErrorAt(path, "invalid byte size")
		}
		f, err := strconv.ParseFloat(num, 64)
		if err != nil || f < 0 {
			return 0, yamlErrorAt(path, "invalid byte size")
		}
		n := int64(f * float64(suf.mul))
		if n < 0 || n > int64(^uint(0)>>1) {
			return 0, yamlErrorAt(path, "invalid byte size")
		}
		return int(n), nil
	}
	return 0, yamlErrorAt(path, "invalid byte size")
}

func parseByteSizeOr(s, path string, def int) (int, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	return parseByteSize(s, path)
}
