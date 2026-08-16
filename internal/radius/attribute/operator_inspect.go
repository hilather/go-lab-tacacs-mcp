package attribute

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"gopkg.in/yaml.v3"
)

var operatorRootFields = []string{"schema_version", "vendor", "attributes"}
var operatorVendorFields = []string{"id", "name"}
var operatorAttrFields = []string{"name", "vendor_type", "kind", "cardinality", "sensitivity", "allowed_in"}

func inspectOperatorNode(n *yaml.Node, path string) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return yamlOpError(path, "dictionary YAML document is empty")
		}
		if len(n.Content) > 1 {
			return yamlOpError(path, "multiple YAML documents are not allowed")
		}
		return inspectOperatorNode(n.Content[0], path)
	}
	if n.Kind == yaml.AliasNode {
		return yamlOpError(orOpRoot(path), "YAML aliases are not allowed")
	}
	if n.Kind != yaml.MappingNode {
		return yamlOpError(orOpRoot(path), "dictionary root must be a mapping")
	}
	return inspectOperatorMapping(n, path, operatorRootFields, inspectOperatorRootValue)
}

func inspectOperatorRootValue(key string, val *yaml.Node, path string) error {
	child := joinOpPath(path, key)
	switch key {
	case "vendor":
		if val.Kind != yaml.MappingNode {
			return yamlOpError(child, "vendor must be a mapping")
		}
		return inspectOperatorMapping(val, child, operatorVendorFields, nil)
	case "attributes":
		if val.Kind != yaml.SequenceNode {
			return yamlOpError(child, "attributes must be a list")
		}
		for i, item := range val.Content {
			ip := child + "[" + itoaOp(i) + "]"
			if item.Kind == yaml.AliasNode {
				return yamlOpError(ip, "YAML aliases are not allowed")
			}
			if item.Kind != yaml.MappingNode {
				return yamlOpError(ip, "attribute must be a mapping")
			}
			if err := inspectOperatorMapping(item, ip, operatorAttrFields, inspectOperatorAttrValue); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

func inspectOperatorAttrValue(key string, val *yaml.Node, path string) error {
	if key != "allowed_in" {
		return nil
	}
	child := joinOpPath(path, key)
	if val.Kind == yaml.AliasNode {
		return yamlOpError(child, "YAML aliases are not allowed")
	}
	if val.Kind != yaml.SequenceNode {
		return yamlOpError(child, "allowed_in must be a list")
	}
	return nil
}

func inspectOperatorMapping(n *yaml.Node, path string, known []string, child func(string, *yaml.Node, string) error) error {
	if n.Kind == yaml.AliasNode {
		return yamlOpError(orOpRoot(path), "YAML aliases are not allowed")
	}
	if n.Kind != yaml.MappingNode {
		return yamlOpError(orOpRoot(path), "mapping required")
	}
	allow := make(map[string]struct{}, len(known))
	for _, k := range known {
		allow[k] = struct{}{}
	}
	seen := make(map[string]struct{}, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		if key.Kind == yaml.AliasNode || val.Kind == yaml.AliasNode {
			return yamlOpError(orOpRoot(path), "YAML aliases are not allowed")
		}
		name := key.Value
		if name == "<<" {
			return yamlOpError(orOpRoot(path), "YAML merge keys are not allowed")
		}
		if _, ok := seen[name]; ok {
			return yamlOpError(joinOpPath(path, name), "duplicate mapping key")
		}
		seen[name] = struct{}{}
		if _, ok := allow[name]; !ok {
			return unknownOpField(path, name, known)
		}
		if child != nil {
			if err := child(name, val, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func unknownOpField(path, field string, known []string) domain.Error {
	msg := "unknown field"
	full := field
	if path != "" {
		full = path + "." + field
	}
	_ = known
	return domain.NewError(domain.CodeConfigUnknownField, msg).WithPath(full)
}

func joinOpPath(parent, key string) string {
	if parent == "" {
		return key
	}
	if key == "" {
		return parent
	}
	return parent + "." + key
}

func orOpRoot(path string) string {
	if path == "" {
		return "radius_dictionaries"
	}
	return path
}

func itoaOp(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[n:])
}
