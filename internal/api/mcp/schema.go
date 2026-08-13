package mcp

import (
	"reflect"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func schemaFor(typ reflect.Type, mutating bool) map[string]any {
	if typ == nil {
		return map[string]any{"type": "object", "additionalProperties": false}
	}
	s := schemaOf(typ, map[reflect.Type]bool{})
	if mutating {
		if props, ok := s["properties"].(map[string]any); ok {
			if _, exists := props["expected_revision"]; !exists {
				props["expected_revision"] = map[string]any{"type": "integer", "minimum": 0}
			}
			if _, exists := props["idempotency_key"]; !exists {
				props["idempotency_key"] = map[string]any{"type": "string"}
			}
			s["properties"] = props
		}
	}
	return s
}

func schemaOf(t reflect.Type, seen map[reflect.Type]bool) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t {
	case reflect.TypeOf(time.Time{}):
		return map[string]any{"type": "string", "format": "date-time"}
	case reflect.TypeOf(operations.OptionalSecret{}):
		return map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties": map[string]any{
				"file":        map[string]any{"type": "string"},
				"environment": map[string]any{"type": "string"},
			},
		}
	}
	if t == reflect.TypeOf(domain.Revision(0)) {
		return map[string]any{"type": "integer", "minimum": 0}
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 && t.Kind() == reflect.Slice {
			return map[string]any{"type": "string", "contentEncoding": "base64"}
		}
		return map[string]any{"type": "array", "items": schemaOf(t.Elem(), seen)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaOf(t.Elem(), seen)}
	case reflect.Struct:
		if seen[t] {
			return map[string]any{"type": "object"}
		}
		seen[t] = true
		props := map[string]any{}
		var required []string
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			name, omit, skip := jsonField(f)
			if skip {
				continue
			}
			// encoding/json promotes anonymous structs with no json tag.
			if f.Anonymous && (f.Tag.Get("json") == "") && f.Type.Kind() == reflect.Struct {
				emb := schemaOf(f.Type, seen)
				if ep, ok := emb["properties"].(map[string]any); ok {
					for k, v := range ep {
						props[k] = v
					}
				}
				if req, ok := emb["required"].([]string); ok {
					required = append(required, req...)
				}
				continue
			}
			if name == "" {
				continue
			}
			props[name] = schemaOf(f.Type, seen)
			if !omit && f.Type.Kind() != reflect.Pointer && f.Type.Kind() != reflect.Slice && f.Type.Kind() != reflect.Map {
				required = append(required, name)
			}
		}
		out := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(required) > 0 {
			out["required"] = required
		}
		return out
	default:
		return map[string]any{}
	}
}

func jsonField(f reflect.StructField) (name string, omitempty, skip bool) {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", false, true
	}
	if tag == "" {
		return f.Name, false, false
	}
	parts := strings.Split(tag, ",")
	name = parts[0]
	if name == "" {
		name = f.Name
	}
	for _, p := range parts[1:] {
		if p == "omitempty" {
			omitempty = true
		}
	}
	return name, omitempty, false
}
