package attribute

import (
	"fmt"
	"strconv"
)

// DictionaryVersion is the built-in view identifier. Snapshot version stays
// exactly this string when no operator file is compiled (KD-R28).
const DictionaryVersion = "builtin-mvp-1"

// Dictionary is an immutable name/code/role view. Lookups are race-free.
type Dictionary struct {
	version string
	byName  map[string]Definition
	byKey   map[Key]Definition
	order   []Definition
}

var builtin = mustBuiltin()

// Builtin is the compiled IETF MVP dictionary (no operator files).
func Builtin() Dictionary { return builtin }

func mustBuiltin() Dictionary {
	defs := mvpDefinitions()
	d := Dictionary{
		version: DictionaryVersion,
		byName:  make(map[string]Definition, len(defs)),
		byKey:   make(map[Key]Definition, len(defs)),
		order:   defs,
	}
	for i, def := range defs {
		if def.Name == "" {
			panic("radius dictionary: empty name")
		}
		if _, ok := d.byName[def.Name]; ok {
			panic("radius dictionary: duplicate name " + def.Name)
		}
		k := def.Key()
		if _, ok := d.byKey[k]; ok {
			panic("radius dictionary: duplicate key " + def.Name)
		}
		if def.Source == "" {
			def.Source = SourceBuiltin
		}
		d.byName[def.Name] = def
		d.byKey[k] = def
		d.order[i] = def
	}
	return d
}

// Version is the snapshot dictionary identifier.
func (d Dictionary) Version() string { return d.version }

// LookupName is a case-sensitive IETF name lookup.
func (d Dictionary) LookupName(name string) (Definition, bool) {
	def, ok := d.byName[name]
	return def, ok
}

// LookupIETF looks up vendor-0 type code.
func (d Dictionary) LookupIETF(code uint8) (Definition, bool) {
	return d.LookupKey(IETFKey(code))
}

// LookupKey looks up a vendor/code/space identity, including named VSAs.
func (d Dictionary) LookupKey(k Key) (Definition, bool) {
	def, ok := d.byKey[k]
	return def, ok
}

// All returns definitions in declared table order.
func (d Dictionary) All() []Definition {
	out := make([]Definition, len(d.order))
	copy(out, d.order)
	return out
}

// AllowedIn is true for a known attribute that may appear in packet, or
// for an unknown IETF type on a request (raw preservation). Unknown types
// are not legal on responses.
func (d Dictionary) AllowedIn(code, packet uint8) bool {
	if def, ok := d.LookupIETF(code); ok {
		return def.AllowedIn(packet)
	}
	return requestPacket(packet) && knownPacket(packet)
}

// RequiredFirst reports the attribute that must occupy index 0, if any.
func (d Dictionary) RequiredFirst(packet uint8) (Definition, bool) {
	for _, def := range d.order {
		if def.MustBeFirst(packet) {
			return def, true
		}
	}
	return Definition{}, false
}

// Summary is a value-free view of one raw attribute.
type Summary struct {
	Type        uint8
	Vendor      uint32
	Length      int
	Name        string
	Sensitivity Sensitivity
	Known       bool
}

// String never includes attribute values.
func (s Summary) String() string {
	name := s.Name
	if name == "" {
		name = "unknown"
	}
	return "radius.attrsum{type=" + strconv.Itoa(int(s.Type)) +
		" vendor=" + strconv.FormatUint(uint64(s.Vendor), 10) +
		" len=" + strconv.Itoa(s.Length) +
		" name=" + name +
		" sensitivity=" + string(s.Sensitivity) + "}"
}

func namedVSASummary(d Dictionary, v VSA) (Definition, bool) {
	tlvs, err := ParseVendorTLVs(v.Payload)
	if err != nil || len(tlvs) != 1 {
		return Definition{}, false
	}
	return d.LookupKey(Key{Vendor: v.Vendor, Code: uint32(tlvs[0].Type), Space: SpaceVSA})
}

// Summarize classifies a raw TLV without copying or exposing Value.
func (d Dictionary) Summarize(r Raw) Summary {
	s := Summary{Type: r.Type, Length: len(r.Value), Sensitivity: SensitivityUnknown}
	if r.Type == TypeVendorSpecific {
		s.Name = "Vendor-Specific"
		s.Known = true
		s.Sensitivity = SensitivityRestricted
		if v, err := ParseVSA(r); err == nil {
			s.Vendor = v.Vendor
			if named, ok := namedVSASummary(d, v); ok {
				s.Name = named.Name
				s.Sensitivity = named.Sensitivity
			}
		}
		return s
	}
	if def, ok := d.LookupIETF(r.Type); ok {
		s.Name = def.Name
		s.Known = true
		s.Sensitivity = def.Sensitivity
		return s
	}
	return s
}

// CheckSet validates packet-role legality, cardinality, required
// attributes, Message-Authenticator-first on responses, and known value
// lengths. Unknown types stay legal on requests and are rejected on
// responses. HMAC validation is not performed here.
func (d Dictionary) CheckSet(set RawSet, packet uint8) error {
	if !knownPacket(packet) {
		return fmt.Errorf("%w: packet %d", ErrUnknownPacket, packet)
	}
	counts := make(map[Key]int, 8)
	for i, raw := range set {
		def, known := d.LookupIETF(raw.Type)
		if !known {
			if !requestPacket(packet) {
				return fmt.Errorf("%w: type %d packet %s", ErrIllegalRole, raw.Type, packetName(packet))
			}
			continue
		}
		if !def.AllowedIn(packet) {
			return fmt.Errorf("%w: %s packet %s", ErrIllegalRole, def.Name, packetName(packet))
		}
		if def.MustBeFirst(packet) && i != 0 {
			return fmt.Errorf("%w: %s packet %s", ErrNotFirst, def.Name, packetName(packet))
		}
		if err := checkOctets(def, raw); err != nil {
			return err
		}
		k := def.Key()
		counts[k]++
		if def.Cardinality == CardinalitySingle && counts[k] > 1 {
			return fmt.Errorf("%w: %s", ErrCardinality, def.Name)
		}
	}
	for _, def := range d.order {
		if !def.RequiredIn(packet) {
			continue
		}
		if counts[def.Key()] > 0 {
			if def.MustBeFirst(packet) && (len(set) == 0 || set[0].Type != def.Code) {
				return fmt.Errorf("%w: %s packet %s", ErrNotFirst, def.Name, packetName(packet))
			}
			continue
		}
		return fmt.Errorf("%w: %s packet %s", ErrMissingRequired, def.Name, packetName(packet))
	}
	return nil
}

func checkOctets(def Definition, raw Raw) error {
	n := len(raw.Value)
	if def.MinOctets > 0 && n < def.MinOctets {
		return fmt.Errorf("%w: %s have %d min %d", ErrValueLength, def.Name, n, def.MinOctets)
	}
	if def.MaxOctets > 0 && n > def.MaxOctets {
		return fmt.Errorf("%w: %s have %d max %d", ErrValueLength, def.Name, n, def.MaxOctets)
	}
	return nil
}

// String is version and count only.
func (d Dictionary) String() string {
	return "radius.dict{version=" + d.version + " n=" + strconv.Itoa(len(d.order)) + "}"
}
