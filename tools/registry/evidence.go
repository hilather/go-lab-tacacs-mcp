package registry

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	evidencePrefixRe = regexp.MustCompile(`^(unit|golden|fuzz|race|bench|lab|adr|docs|interop|cmd):(.+)$`)
	testSymbolNameRe = regexp.MustCompile(`^(?:Test|Fuzz|Benchmark)[A-Za-z0-9_]+$`)
	funcSymbolRe     = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark)[A-Za-z0-9_]+)\(`)
)

var pathEvidenceKinds = map[string]struct{}{
	"golden": {},
	"adr":    {},
	"docs":   {},
}

func checkEvidenceIDs(rep *Report, root string, tables ...*ConformanceRegistry) {
	symbols, err := collectTestSymbols(root)
	if err != nil {
		rep.add("", "", "scan test symbols: %v", err)
		return
	}
	for _, table := range tables {
		if table == nil {
			continue
		}
		file := RFC8907Path
		if table.RFC == "9887" {
			file = RFC9887Path
		}
		for _, row := range table.Rows {
			if !statusRequiresEvidence(row.Status) {
				continue
			}
			for _, ev := range row.Evidence {
				checkOneEvidence(rep, root, file, row.ID, ev, symbols)
			}
		}
	}
}

func checkOneEvidence(rep *Report, root, file, id, ev string, symbols map[string]struct{}) {
	m := evidencePrefixRe.FindStringSubmatch(strings.TrimSpace(ev))
	if m == nil {
		rep.add(file, id, "evidence %q must start with a known prefix (unit|golden|fuzz|race|bench|lab|adr|docs|interop|cmd):", ev)
		return
	}
	kind, payload := m[1], strings.TrimSpace(m[2])
	if sym := evidenceTestSymbol(payload); sym != "" {
		if _, ok := symbols[sym]; !ok {
			rep.add(file, id, "evidence %q names unknown test symbol %s", ev, sym)
		}
	}
	if _, ok := pathEvidenceKinds[kind]; !ok {
		return
	}
	path := firstPathToken(payload)
	if path == "" || !looksLikeRepoPath(path) {
		return
	}
	if _, err := os.Stat(filepath.Join(root, path)); err != nil {
		rep.add(file, id, "evidence %q path %s is missing", ev, path)
	}
}

func evidenceTestSymbol(payload string) string {
	// Take the last dotted identifier if it is a Test/Fuzz/Benchmark name.
	// "internal/aaa.TestInvalidServiceFails" → TestInvalidServiceFails
	// "codec (independent encode/decode)" → not a symbol
	dot := strings.LastIndex(payload, ".")
	if dot < 0 || dot+1 >= len(payload) {
		return ""
	}
	rest := payload[dot+1:]
	if i := strings.IndexAny(rest, " \t("); i >= 0 {
		rest = rest[:i]
	}
	if !testSymbolNameRe.MatchString(rest) {
		return ""
	}
	return rest
}

func firstPathToken(payload string) string {
	fields := strings.Fields(payload)
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimRight(fields[0], ",")
}

func looksLikeRepoPath(p string) bool {
	if strings.Contains(p, "..") {
		return false
	}
	return strings.Contains(p, "/") || strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".json")
}

func collectTestSymbols(root string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	for _, dir := range []string{"cmd", "internal", "tools"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				name := info.Name()
				if name == "node_modules" || name == "testdata" || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range funcSymbolRe.FindAllSubmatch(raw, -1) {
				out[string(m[1])] = struct{}{}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
