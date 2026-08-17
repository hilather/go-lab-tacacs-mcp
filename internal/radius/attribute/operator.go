package attribute

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"gopkg.in/yaml.v3"
)

// Operator dictionary compile limits (ADR 0026).
const (
	MaxOperatorDictionaryFiles = 8
	MaxOperatorDictionaryBytes = 64 << 10
	MaxOperatorAttributes      = 256
	MaxOperatorVendors         = 32
	MaxOperatorNameLength      = 64
)

// Reserved vendor IDs. Collision is a compile error even before named
// Cisco / Microsoft builtins ship (KD-R26).
const (
	ReservedVendorIETF      uint32 = 0
	ReservedVendorCisco     uint32 = 9
	ReservedVendorMicrosoft uint32 = 311
)

// Dictionary source tokens returned by radius.attributes.list.
const (
	SourceBuiltin        = "builtin"
	sourceOperatorPrefix = "operator:"
	reservedNameCisco    = "Cisco-AVPair"
	reservedNameMSCHAP   = "MS-CHAP"
)

// OperatorSource is one compiled operator dictionary file.
type OperatorSource struct {
	ID   string
	Data []byte
}

// SourceOperator is the attributes.list source for an operator file id.
func SourceOperator(id string) string { return sourceOperatorPrefix + id }

// MergeOperator adds operator definitions onto a copy of base. An empty
// source list returns base unchanged, including Version exactly
// DictionaryVersion when base is Builtin.
func MergeOperator(base Dictionary, files []OperatorSource) (Dictionary, error) {
	if len(files) == 0 {
		return base, nil
	}
	out := cloneDictionary(base)
	seenVendorID := map[uint32]string{}
	seenVendorName := map[string]uint32{}
	addedAttrs := 0
	var compiled []compiledOperatorFile
	for _, f := range files {
		if f.ID == "" {
			return Dictionary{}, yamlOpError("radius_dictionaries", "id is required")
		}
		if len(f.Data) > MaxOperatorDictionaryBytes {
			return Dictionary{}, yamlOpError("radius_dictionaries."+f.ID, "dictionary file exceeds maximum size")
		}
		if bytes.Contains(f.Data, []byte("$INCLUDE")) {
			return Dictionary{}, yamlOpError("radius_dictionaries."+f.ID, "FreeRADIUS $INCLUDE is not allowed")
		}
		parsed, err := parseOperatorFile(f.ID, f.Data)
		if err != nil {
			return Dictionary{}, err
		}
		if err := reserveOperatorVendor(parsed.vendorID, parsed.vendorName, f.ID); err != nil {
			return Dictionary{}, err
		}
		if prev, ok := seenVendorID[parsed.vendorID]; ok && prev != parsed.vendorName {
			return Dictionary{}, yamlOpError("radius_dictionaries."+f.ID+".vendor.id", "vendor id is already defined as "+prev)
		}
		if prev, ok := seenVendorName[parsed.vendorName]; ok && prev != parsed.vendorID {
			return Dictionary{}, yamlOpError("radius_dictionaries."+f.ID+".vendor.name", "vendor name is already defined with a different id")
		}
		if _, ok := seenVendorID[parsed.vendorID]; !ok {
			if len(seenVendorID)+1 > MaxOperatorVendors {
				return Dictionary{}, yamlOpError("radius_dictionaries."+f.ID+".vendor.id", "operator vendor count exceeds maximum")
			}
			seenVendorID[parsed.vendorID] = parsed.vendorName
			seenVendorName[parsed.vendorName] = parsed.vendorID
		}
		var defs []Definition
		for i, raw := range parsed.attrs {
			path := fmt.Sprintf("radius_dictionaries.%s.attributes[%d]", f.ID, i)
			def, err := compileOperatorAttr(out, parsed.vendorID, f.ID, raw, path)
			if err != nil {
				return Dictionary{}, err
			}
			if addedAttrs+1 > MaxOperatorAttributes {
				return Dictionary{}, yamlOpError(path, "operator attribute count exceeds maximum")
			}
			if _, ok := out.byName[def.Name]; ok {
				return Dictionary{}, yamlOpError(path+".name", "duplicate attribute name")
			}
			if _, ok := out.byKey[def.Key()]; ok {
				return Dictionary{}, yamlOpError(path, "duplicate attribute vendor and type")
			}
			out.byName[def.Name] = def
			out.byKey[def.Key()] = def
			out.order = append(out.order, def)
			defs = append(defs, def)
			addedAttrs++
		}
		compiled = append(compiled, compiledOperatorFile{id: f.ID, defs: defs, vend: parsed.vendorID, vname: parsed.vendorName})
	}
	out.version = operatorVersion(compiled)
	return out, nil
}

type parsedOperatorFile struct {
	vendorID   uint32
	vendorName string
	attrs      []rawOperatorAttr
}

type rawOperatorFile struct {
	SchemaVersion *int              `yaml:"schema_version"`
	Vendor        rawOperatorVendor `yaml:"vendor"`
	Attributes    []rawOperatorAttr `yaml:"attributes"`
}

type rawOperatorVendor struct {
	ID   *uint32 `yaml:"id"`
	Name string  `yaml:"name"`
}

type rawOperatorAttr struct {
	Name        string   `yaml:"name"`
	VendorType  *int     `yaml:"vendor_type"`
	Kind        string   `yaml:"kind"`
	Cardinality string   `yaml:"cardinality"`
	Sensitivity string   `yaml:"sensitivity"`
	AllowedIn   []string `yaml:"allowed_in"`
}

type compiledOperatorFile struct {
	id    string
	defs  []Definition
	vend  uint32
	vname string
}

func parseOperatorFile(id string, data []byte) (parsedOperatorFile, error) {
	path := "radius_dictionaries." + id
	if !utf8.Valid(data) {
		return parsedOperatorFile{}, yamlOpError(path, "dictionary file is not valid UTF-8")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if err == io.EOF {
			return parsedOperatorFile{}, yamlOpError(path, "dictionary YAML document is empty")
		}
		return parsedOperatorFile{}, yamlOpError(path, "dictionary YAML is invalid")
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); err {
	case io.EOF:
	case nil:
		return parsedOperatorFile{}, yamlOpError(path, "multiple YAML documents are not allowed")
	default:
		return parsedOperatorFile{}, yamlOpError(path, "dictionary YAML is invalid")
	}
	if err := inspectOperatorNode(&root, path); err != nil {
		return parsedOperatorFile{}, err
	}
	var raw rawOperatorFile
	if err := root.Decode(&raw); err != nil {
		return parsedOperatorFile{}, yamlOpError(path, "dictionary YAML is invalid")
	}
	if raw.SchemaVersion == nil || *raw.SchemaVersion != 1 {
		return parsedOperatorFile{}, yamlOpError(path+".schema_version", "schema_version must be 1")
	}
	if raw.Vendor.ID == nil {
		return parsedOperatorFile{}, yamlOpError(path+".vendor.id", "vendor.id is required")
	}
	name := strings.TrimSpace(raw.Vendor.Name)
	if name == "" {
		return parsedOperatorFile{}, yamlOpError(path+".vendor.name", "vendor.name is required")
	}
	if len(name) > MaxOperatorNameLength {
		return parsedOperatorFile{}, yamlOpError(path+".vendor.name", "vendor name exceeds maximum length")
	}
	if len(raw.Attributes) == 0 {
		return parsedOperatorFile{}, yamlOpError(path+".attributes", "at least one attribute is required")
	}
	return parsedOperatorFile{vendorID: *raw.Vendor.ID, vendorName: name, attrs: raw.Attributes}, nil
}

func compileOperatorAttr(base Dictionary, vendor uint32, fileID string, raw rawOperatorAttr, path string) (Definition, error) {
	name := strings.TrimSpace(raw.Name)
	if name == "" {
		return Definition{}, yamlOpError(path+".name", "name is required")
	}
	if len(name) > MaxOperatorNameLength {
		return Definition{}, yamlOpError(path+".name", "name exceeds maximum length")
	}
	if reservedOperatorName(name) {
		return Definition{}, yamlOpError(path+".name", "attribute name is reserved")
	}
	if def, ok := base.LookupName(name); ok {
		if def.Sensitivity == SensitivitySecret && parseOperatorSensitivity(raw.Sensitivity) == SensitivityPublic {
			return Definition{}, yamlOpError(path+".sensitivity", "cannot set public on a built-in secret attribute")
		}
		if def.Source == SourceBuiltin || def.Source == "" {
			return Definition{}, yamlOpError(path+".name", "cannot redefine a built-in attribute")
		}
		return Definition{}, yamlOpError(path+".name", "duplicate attribute name")
	}
	if raw.VendorType == nil || *raw.VendorType < 1 || *raw.VendorType > 255 {
		return Definition{}, yamlOpError(path+".vendor_type", "vendor_type must be 1-255")
	}
	kind, err := parseOperatorKind(raw.Kind)
	if err != nil {
		return Definition{}, yamlOpError(path+".kind", err.Error())
	}
	card := CardinalitySingle
	if raw.Cardinality != "" {
		switch raw.Cardinality {
		case string(CardinalitySingle), string(CardinalityMulti):
			card = Cardinality(raw.Cardinality)
		default:
			return Definition{}, yamlOpError(path+".cardinality", "cardinality must be single or multi")
		}
	}
	sens := SensitivityRestricted
	if raw.Sensitivity != "" {
		s := parseOperatorSensitivity(raw.Sensitivity)
		if s == "" {
			return Definition{}, yamlOpError(path+".sensitivity", "sensitivity must be public, restricted, or secret")
		}
		sens = s
	}
	if builtin, ok := base.LookupName(name); ok && builtin.Sensitivity == SensitivitySecret && sens == SensitivityPublic {
		return Definition{}, yamlOpError(path+".sensitivity", "cannot set public on a built-in secret attribute")
	}
	allow, err := parseOperatorAllowed(raw.AllowedIn)
	if err != nil {
		return Definition{}, yamlOpError(path+".allowed_in", err.Error())
	}
	def := Definition{
		Name:        name,
		Vendor:      vendor,
		Code:        uint8(*raw.VendorType),
		Kind:        kind,
		Cardinality: card,
		Sensitivity: sens,
		Source:      SourceOperator(fileID),
		allowed:     allow,
		MaxOctets:   MaxValueLength,
	}
	switch kind {
	case KindInteger, KindIPv4, KindTime:
		def.MinOctets, def.MaxOctets = 4, 4
	case KindIPv6:
		def.MinOctets, def.MaxOctets = 16, 16
	}
	return def, nil
}

func reserveOperatorVendor(id uint32, name, fileID string) error {
	switch id {
	case ReservedVendorIETF, ReservedVendorCisco, ReservedVendorMicrosoft:
		return yamlOpError("radius_dictionaries."+fileID+".vendor.id", "reserved vendor id")
	}
	_ = name
	return nil
}

func reservedOperatorName(name string) bool {
	if name == reservedNameCisco || strings.HasPrefix(name, reservedNameMSCHAP) {
		return true
	}
	if _, ok := Builtin().LookupName(name); ok {
		return true
	}
	return false
}

func parseOperatorKind(raw string) (ValueKind, error) {
	switch raw {
	case string(KindText), string(KindString), string(KindInteger), string(KindIPv4), string(KindIPv6), string(KindTime), string(KindOctets):
		return ValueKind(raw), nil
	case "":
		return "", fmt.Errorf("kind is required")
	default:
		return "", fmt.Errorf("kind must be text, string, integer, ipaddr, ipv6addr, time, or octets")
	}
}

func parseOperatorSensitivity(raw string) Sensitivity {
	switch raw {
	case string(SensitivityPublic), string(SensitivityRestricted), string(SensitivitySecret):
		return Sensitivity(raw)
	default:
		return ""
	}
}

func parseOperatorAllowed(tokens []string) (packetMask, error) {
	if len(tokens) == 0 {
		return 0, fmt.Errorf("allowed_in is required")
	}
	var m packetMask
	for _, tok := range tokens {
		code, ok := operatorPacketToken[tok]
		if !ok {
			return 0, fmt.Errorf("allowed_in token is not a known packet role")
		}
		m |= mustPacketBit(code)
	}
	return m, nil
}

var operatorPacketToken = map[string]uint8{
	"access_request":      PacketAccessRequest,
	"access_accept":       PacketAccessAccept,
	"access_reject":       PacketAccessReject,
	"access_challenge":    PacketAccessChallenge,
	"accounting_request":  PacketAccountingRequest,
	"accounting_response": PacketAccountingResponse,
}

func mustPacketBit(code uint8) packetMask {
	b, ok := packetBit(code)
	if !ok {
		panic("radius operator dictionary: unknown packet")
	}
	return b
}

func operatorVersion(files []compiledOperatorFile) string {
	ids := make([]string, len(files))
	byID := make(map[string]compiledOperatorFile, len(files))
	for i, f := range files {
		ids[i] = f.id
		byID[f.id] = f
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		f := byID[id]
		b.WriteString(id)
		b.WriteByte('\t')
		b.WriteString(fmt.Sprintf("%d\t%s\n", f.vend, f.vname))
		names := make([]string, 0, len(f.defs))
		defs := make(map[string]Definition, len(f.defs))
		for _, d := range f.defs {
			names = append(names, d.Name)
			defs[d.Name] = d
		}
		sort.Strings(names)
		for _, name := range names {
			d := defs[name]
			b.WriteString(name)
			b.WriteByte('\t')
			b.WriteString(fmt.Sprintf("%d\t%s\t%s\t%s", d.Code, d.Kind, d.Cardinality, d.Sensitivity))
			for _, pkt := range d.AllowedPackets() {
				b.WriteByte('\t')
				b.WriteString(operatorPacketName(pkt))
			}
			b.WriteByte('\n')
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return DictionaryVersion + "+op:" + strings.Join(ids, ",") + ":" + hex.EncodeToString(sum[:])
}

func operatorPacketName(code uint8) string {
	for tok, c := range operatorPacketToken {
		if c == code {
			return tok
		}
	}
	return packetName(code)
}

func cloneDictionary(d Dictionary) Dictionary {
	out := Dictionary{
		version: d.version,
		byName:  make(map[string]Definition, len(d.byName)+8),
		byKey:   make(map[Key]Definition, len(d.byKey)+8),
		order:   make([]Definition, 0, len(d.order)+8),
	}
	for _, def := range d.order {
		if def.Source == "" {
			def.Source = SourceBuiltin
		}
		out.order = append(out.order, def)
		out.byName[def.Name] = def
		out.byKey[def.Key()] = def
	}
	return out
}

func yamlOpError(path, message string) domain.Error {
	return domain.NewError(domain.CodeConfigYAMLInvalid, message).WithPath(path)
}
