package config

import (
	"strconv"
	"strings"
	"time"
	"unicode"
)

func parseDuration(s, path string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if n, ok, err := parseDayDuration(s); err != nil {
		return 0, yamlErrorAt(path, "invalid duration")
	} else if ok {
		return n, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, yamlErrorAt(path, "invalid duration")
	}
	return d, nil
}

func parseDurationOr(s, path string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	return parseDuration(s, path)
}

func parseDayDuration(s string) (time.Duration, bool, error) {
	if !strings.HasSuffix(s, "d") {
		return 0, false, nil
	}
	num := strings.TrimSpace(s[:len(s)-1])
	if num == "" {
		return 0, false, strconv.ErrSyntax
	}
	for _, r := range num {
		if r != '.' && r != '-' && !unicode.IsDigit(r) {
			return 0, false, strconv.ErrSyntax
		}
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, true, err
	}
	return time.Duration(f * 24 * float64(time.Hour)), true, nil
}
