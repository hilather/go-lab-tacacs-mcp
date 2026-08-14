package config

import (
	"bytes"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Parse decodes and normalizes a baseline YAML document.
func Parse(data []byte) (*Document, error) {
	return ParseWithOptions(data, Options{})
}

// ParseWithOptions decodes and normalizes a baseline YAML document.
func ParseWithOptions(data []byte, opts Options) (*Document, error) {
	max := opts.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if int64(len(data)) > max {
		return nil, yamlError("input exceeds maximum size")
	}
	if !utf8.Valid(data) {
		return nil, yamlError("input is not valid UTF-8")
	}

	nodeDec := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := nodeDec.Decode(&root); err != nil {
		if err == io.EOF {
			return nil, yamlError("YAML document is empty")
		}
		return nil, mapYAMLError(err)
	}
	var extra yaml.Node
	switch err := nodeDec.Decode(&extra); err {
	case io.EOF:
		// single document
	case nil:
		return nil, yamlError("multiple YAML documents are not allowed")
	default:
		return nil, mapYAMLError(err)
	}

	schema, err := peekSchemaVersion(&root)
	if err != nil {
		return nil, err
	}
	if err := rejectMixedSchemaKeys(&root, schema); err != nil {
		return nil, err
	}

	switch schema {
	case SchemaVersionV1:
		if err := inspectNode(&root, reflect.TypeOf(rawFileV1{}), ""); err != nil {
			return nil, err
		}
		typed := newStrictDecoder(bytes.NewReader(data))
		var raw rawFileV1
		if err := typed.Decode(&raw); err != nil {
			return nil, mapYAMLError(err)
		}
		return normalizeV1(&raw)
	case SchemaVersionV2:
		if err := inspectNode(&root, reflect.TypeOf(rawFileV2{}), ""); err != nil {
			return nil, err
		}
		typed := newStrictDecoder(bytes.NewReader(data))
		var raw rawFileV2
		if err := typed.Decode(&raw); err != nil {
			return nil, mapYAMLError(err)
		}
		return normalizeV2(&raw)
	default:
		return nil, yamlErrorAt("schema_version", "unsupported schema version")
	}
}

func peekSchemaVersion(root *yaml.Node) (int, error) {
	m := rootMapping(root)
	if m == nil {
		if root != nil && root.Kind == yaml.DocumentNode && len(root.Content) == 0 {
			return 0, yamlError("YAML document is empty")
		}
		return 0, yamlError("root must be a mapping")
	}
	node := mappingValue(m, "schema_version")
	if node == nil || node.Kind != yaml.ScalarNode || isYAMLNull(node) {
		return 0, yamlErrorAt("schema_version", "schema_version is required")
	}
	var v int
	if err := node.Decode(&v); err != nil {
		return 0, yamlErrorAt("schema_version", "unsupported schema version")
	}
	switch v {
	case SchemaVersionV1, SchemaVersionV2:
		return v, nil
	default:
		return 0, yamlErrorAt("schema_version", "unsupported schema version")
	}
}

func rejectMixedSchemaKeys(root *yaml.Node, schema int) error {
	m := rootMapping(root)
	listeners := mappingValue(m, "listeners")
	if listeners != nil && listeners.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(listeners.Content); i += 2 {
			key := listeners.Content[i].Value
			path := joinPath("listeners", key)
			switch schema {
			case SchemaVersionV1:
				switch key {
				case "radius":
					return yamlErrorAt(path, "RADIUS listeners require schema_version: 2; remove listeners.radius or set schema_version: 2")
				case "tacacs":
					return yamlErrorAt(path, "v2 listener key is not allowed in schema_version 1; use schema_version: 2")
				}
			case SchemaVersionV2:
				switch key {
				case "legacy_tacacs":
					return yamlErrorAt(path, "v1 listener key is not allowed in schema_version 2; use listeners.tacacs.legacy")
				case "secure_tacacs":
					return yamlErrorAt(path, "v1 listener key is not allowed in schema_version 2; use listeners.tacacs.tls")
				}
			}
		}
	}
	if schema == SchemaVersionV1 {
		if mappingValue(mappingValue(m, "security"), "radius_shared_secrets") != nil {
			return yamlErrorAt("security.radius_shared_secrets", "RADIUS shared-secret policy requires schema_version: 2")
		}
		if mappingValue(mappingValue(m, "server"), "admin_only") != nil {
			return yamlErrorAt("server.admin_only", "server.admin_only requires schema_version: 2")
		}
	}
	return nil
}

func rootMapping(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return rootMapping(n.Content[0])
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	return n
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// Load reads path and parses it as a baseline.
func Load(path string) (*Document, error) {
	return LoadWithOptions(path, Options{})
}

// LoadWithOptions reads path and parses it as a baseline.
func LoadWithOptions(path string, opts Options) (*Document, error) {
	max := opts.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, yamlErrorAt(path, "cannot read configuration file")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, yamlErrorAt(path, "cannot read configuration file")
	}
	return ParseWithOptions(data, Options{MaxBytes: max})
}

func inspectNode(n *yaml.Node, t reflect.Type, path string) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return yamlError("YAML document is empty")
		}
		if len(n.Content) > 1 {
			return yamlError("multiple YAML documents are not allowed")
		}
		return inspectNode(n.Content[0], t, path)
	}
	if err := rejectYAMLRef(n, path); err != nil {
		return err
	}
	t = derefType(t)
	if t == nil {
		return nil
	}
	switch n.Kind {
	case yaml.MappingNode:
		return inspectMapping(n, t, path)
	case yaml.SequenceNode:
		return inspectSequence(n, t, path)
	default:
		return nil
	}
}

func inspectMapping(n *yaml.Node, t reflect.Type, path string) error {
	if t.Kind() == reflect.Map {
		seen := make(map[string]struct{}, len(n.Content)/2)
		elem := t.Elem()
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			if err := rejectYAMLRef(key, path); err != nil {
				return err
			}
			if err := rejectYAMLRef(val, joinPath(path, key.Value)); err != nil {
				return err
			}
			if key.Value == "<<" {
				return yamlErrorAt(orRoot(path), "YAML merge keys are not allowed")
			}
			if _, ok := seen[key.Value]; ok {
				return yamlErrorAt(joinPath(path, key.Value), "duplicate mapping key")
			}
			seen[key.Value] = struct{}{}
			if err := inspectNode(val, elem, joinPath(path, key.Value)); err != nil {
				return err
			}
		}
		return nil
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	fields, order := yamlFields(t)
	seen := make(map[string]struct{}, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		if err := rejectYAMLRef(key, path); err != nil {
			return err
		}
		name := key.Value
		if name == "<<" {
			return yamlErrorAt(orRoot(path), "YAML merge keys are not allowed")
		}
		if _, ok := seen[name]; ok {
			return yamlErrorAt(joinPath(path, name), "duplicate mapping key")
		}
		seen[name] = struct{}{}
		ft, ok := fields[name]
		if !ok {
			return unknownField(path, name, order)
		}
		child := joinPath(path, name)
		if err := rejectYAMLRef(val, child); err != nil {
			return err
		}
		if err := inspectNode(val, ft, child); err != nil {
			return err
		}
	}
	return nil
}

func inspectSequence(n *yaml.Node, t reflect.Type, path string) error {
	if t.Kind() != reflect.Slice && t.Kind() != reflect.Array {
		return nil
	}
	elem := t.Elem()
	base := path
	if base == "" {
		base = "$"
	}
	for i, c := range n.Content {
		child := indexPath(base, i)
		if err := rejectYAMLRef(c, child); err != nil {
			return err
		}
		if err := inspectNode(c, elem, child); err != nil {
			return err
		}
	}
	return nil
}

func rejectYAMLRef(n *yaml.Node, path string) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.AliasNode {
		return yamlErrorAt(orRoot(path), "YAML aliases are not allowed")
	}
	if n.Anchor != "" {
		return yamlErrorAt(orRoot(path), "YAML anchors are not allowed")
	}
	return nil
}

func orRoot(path string) string {
	if path == "" {
		return "$"
	}
	return path
}

func derefType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func yamlFields(t reflect.Type) (map[string]reflect.Type, []string) {
	t = derefType(t)
	if t == nil || t.Kind() != reflect.Struct {
		return nil, nil
	}
	out := make(map[string]reflect.Type)
	var order []string
	var walk func(reflect.Type)
	walk = func(st reflect.Type) {
		st = derefType(st)
		if st == nil || st.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < st.NumField(); i++ {
			f := st.Field(i)
			if f.PkgPath != "" && !f.Anonymous {
				continue
			}
			tag := f.Tag.Get("yaml")
			if tag == "-" {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if strings.Contains(opts, "inline") || (name == "" && f.Anonymous) {
				walk(f.Type)
				continue
			}
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			if _, exists := out[name]; exists {
				continue
			}
			out[name] = f.Type
			order = append(order, name)
		}
	}
	walk(t)
	sort.Strings(order)
	return out, order
}

func newStrictDecoder(r io.Reader) *yaml.Decoder {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	return dec
}
