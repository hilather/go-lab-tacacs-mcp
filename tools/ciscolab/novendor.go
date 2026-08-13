package main

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// ForbiddenArtifacts lists paths that must never be committed (Cisco binaries).
func ForbiddenArtifacts(root string) ([]string, error) {
	var hits []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		base := strings.ToLower(d.Name())
		relLower := strings.ToLower(rel)
		if d.IsDir() {
			switch base {
			case ".git", "node_modules", "web/node_modules":
				return filepath.SkipDir
			}
			if base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if isForbiddenName(base, relLower) {
			hits = append(hits, rel)
		}
		return nil
	})
	return hits, err
}

func isForbiddenName(base, rel string) bool {
	if strings.Contains(base, "refplat") && strings.HasSuffix(base, ".iso") {
		return true
	}
	if strings.HasPrefix(base, "cisco_iol") && (strings.HasSuffix(base, ".bin") ||
		strings.HasSuffix(base, ".tar") || strings.HasSuffix(base, ".tar.gz") ||
		strings.HasSuffix(base, ".tgz")) {
		return true
	}
	if strings.Contains(base, "adventerprisek9") {
		return true
	}
	if strings.HasPrefix(base, "ioll2") && (strings.HasSuffix(base, ".bin") || strings.HasSuffix(base, ".image")) {
		return true
	}
	if strings.Contains(rel, "iol-xe-") && strings.HasSuffix(base, ".bin") {
		return true
	}
	return false
}
