package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
)

func normalizeRADIUSDictionaries(raw []rawRADIUSDictionary) ([]RADIUSDictionary, error) {
	out := make([]RADIUSDictionary, 0, len(raw))
	seen := map[string]struct{}{}
	if len(raw) > attribute.MaxOperatorDictionaryFiles {
		return nil, yamlErrorAt("radius_dictionaries", "at most 8 radius_dictionaries entries are allowed")
	}
	for i, d := range raw {
		path := indexPath("radius_dictionaries", i)
		id := strings.TrimSpace(d.ID)
		if id == "" {
			return nil, yamlErrorAt(path+".id", "id is required")
		}
		if _, ok := seen[id]; ok {
			return nil, yamlErrorAt(path+".id", "duplicate radius dictionary id")
		}
		seen[id] = struct{}{}
		file := strings.TrimSpace(d.File)
		if err := validateRADIUSDictionaryPath(file, path+".file"); err != nil {
			return nil, err
		}
		out = append(out, RADIUSDictionary{
			ID:      id,
			File:    file,
			Enabled: boolOr(d.Enabled, true),
		})
	}
	return out, nil
}

func validateRADIUSDictionaries(doc *Document) error {
	if doc == nil {
		return nil
	}
	if len(doc.RADIUSDictionaries) > attribute.MaxOperatorDictionaryFiles {
		return yamlErrorAt("radius_dictionaries", "at most 8 radius_dictionaries entries are allowed")
	}
	seen := map[string]struct{}{}
	for i, d := range doc.RADIUSDictionaries {
		path := indexPath("radius_dictionaries", i)
		if strings.TrimSpace(d.ID) == "" {
			return yamlErrorAt(path+".id", "id is required")
		}
		if _, ok := seen[d.ID]; ok {
			return yamlErrorAt(path+".id", "duplicate radius dictionary id")
		}
		seen[d.ID] = struct{}{}
		if err := validateRADIUSDictionaryPath(d.File, path+".file"); err != nil {
			return err
		}
	}
	return nil
}

func validateRADIUSDictionaryPath(file, field string) error {
	if file == "" {
		return yamlErrorAt(field, "file is required")
	}
	if strings.Contains(file, "$INCLUDE") {
		return yamlErrorAt(field, "FreeRADIUS $INCLUDE is not allowed")
	}
	lower := strings.ToLower(file)
	if strings.Contains(file, "://") || strings.HasPrefix(lower, "http:") || strings.HasPrefix(lower, "https:") || strings.HasPrefix(lower, "s3:") {
		return yamlErrorAt(field, "dictionary file must be a local path")
	}
	if !filepath.IsAbs(file) {
		return yamlErrorAt(field, "dictionary file must be an absolute path")
	}
	return nil
}

// CompileRADIUSDictionary reads enabled operator files and merges them onto
// the built-in IETF MVP dictionary. An empty or all-disabled list returns
// Builtin with Version exactly builtin-mvp-1.
func CompileRADIUSDictionary(doc *Document) (attribute.Dictionary, error) {
	if doc == nil || len(doc.RADIUSDictionaries) == 0 {
		return attribute.Builtin(), nil
	}
	var srcs []attribute.OperatorSource
	for i, d := range doc.RADIUSDictionaries {
		if !d.Enabled {
			continue
		}
		path := indexPath("radius_dictionaries", i)
		data, err := readDictionaryFile(d.File, doc.Security.StrictSecretFiles, path+".file")
		if err != nil {
			return attribute.Dictionary{}, err
		}
		srcs = append(srcs, attribute.OperatorSource{ID: d.ID, Data: data})
	}
	return attribute.MergeOperator(attribute.Builtin(), srcs)
}

func readDictionaryFile(path string, strict bool, field string) ([]byte, error) {
	lstat := os.Lstat
	info, err := lstat(path)
	if err != nil {
		return nil, yamlErrorAt(field, "dictionary file is not readable")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if strict {
			return nil, yamlErrorAt(field, "dictionary path is a symlink")
		}
		info, err = os.Stat(path)
		if err != nil {
			return nil, yamlErrorAt(field, "dictionary file is not readable")
		}
	}
	if info.IsDir() {
		return nil, yamlErrorAt(field, "dictionary path is a directory")
	}
	if info.Mode().Perm()&0o002 != 0 {
		return nil, yamlErrorAt(field, "dictionary file is world-writable")
	}
	if info.Size() > attribute.MaxOperatorDictionaryBytes {
		return nil, yamlErrorAt(field, "dictionary file exceeds maximum size")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, yamlErrorAt(field, "dictionary file is not readable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, attribute.MaxOperatorDictionaryBytes+1))
	if err != nil {
		return nil, yamlErrorAt(field, "dictionary file is not readable")
	}
	if len(data) > attribute.MaxOperatorDictionaryBytes {
		return nil, yamlErrorAt(field, "dictionary file exceeds maximum size")
	}
	return data, nil
}
