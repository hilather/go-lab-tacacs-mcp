package radius

// Local MVP dictionary for compile-time name/code/role/kind checks.
// Packet-role bits match the built-in IETF table plus named Cisco-AVPair.

// ValueKind is the RFC 2865 / RFC 3162 / RFC 2869 encoding used at compile.
type ValueKind string

const (
	KindText    ValueKind = "text"
	KindString  ValueKind = "string"
	KindInteger ValueKind = "integer"
	KindIPv4    ValueKind = "ipaddr"
	KindIPv6    ValueKind = "ipv6addr"
	KindTime    ValueKind = "time"
	KindVSA     ValueKind = "vsa"
)

// Cardinality is how many instances of one key may appear in a reply merge.
type Cardinality string

const (
	CardinalitySingle Cardinality = "single"
	CardinalityMulti  Cardinality = "multi"
)

const (
	packetAccessAccept = 2
	packetAccessReject = 3
)

// attrDef is immutable metadata. It never carries a value.
type attrDef struct {
	Name        string
	Vendor      uint32
	Code        uint8
	Kind        ValueKind
	Cardinality Cardinality
	Secret      bool // never a match key or policy-emitted reply
	ServerOwned bool // MA / Proxy-State — server reply path only
	allowReq    bool
	allowAccept bool
	allowReject bool
}

func (d attrDef) key() AttrKey {
	return AttrKey{Vendor: d.Vendor, Code: d.Code, Name: d.Name}
}

type dictionary struct {
	byName map[string]attrDef
	byCode map[uint8]attrDef
}

var builtinDict = mustBuiltin()

func mustBuiltin() dictionary {
	defs := []attrDef{
		{Name: "User-Name", Code: 1, Kind: KindText, Cardinality: CardinalitySingle, allowReq: true, allowAccept: true},
		{Name: "User-Password", Code: 2, Kind: KindString, Cardinality: CardinalitySingle, Secret: true, allowReq: true},
		{Name: "CHAP-Password", Code: 3, Kind: KindString, Cardinality: CardinalitySingle, Secret: true, allowReq: true},
		{Name: "NAS-IP-Address", Code: 4, Kind: KindIPv4, Cardinality: CardinalitySingle, allowReq: true},
		{Name: "NAS-Port", Code: 5, Kind: KindInteger, Cardinality: CardinalitySingle, allowReq: true},
		{Name: "Service-Type", Code: 6, Kind: KindInteger, Cardinality: CardinalitySingle, allowReq: true, allowAccept: true},
		{Name: "Framed-Protocol", Code: 7, Kind: KindInteger, Cardinality: CardinalitySingle, allowReq: true, allowAccept: true},
		{Name: "Framed-IP-Address", Code: 8, Kind: KindIPv4, Cardinality: CardinalitySingle, allowReq: true, allowAccept: true},
		{Name: "Filter-Id", Code: 11, Kind: KindText, Cardinality: CardinalityMulti, allowAccept: true},
		{Name: "Framed-MTU", Code: 12, Kind: KindInteger, Cardinality: CardinalitySingle, allowReq: true, allowAccept: true},
		{Name: "Reply-Message", Code: 18, Kind: KindText, Cardinality: CardinalityMulti, allowAccept: true, allowReject: true},
		{Name: "State", Code: 24, Kind: KindString, Cardinality: CardinalitySingle, Secret: true, ServerOwned: true, allowReq: true, allowAccept: true},
		{Name: "Class", Code: 25, Kind: KindString, Cardinality: CardinalityMulti, allowAccept: true},
		{Name: "Vendor-Specific", Code: 26, Kind: KindVSA, Cardinality: CardinalityMulti, allowReq: true, allowAccept: true},
		{Name: "Session-Timeout", Code: 27, Kind: KindInteger, Cardinality: CardinalitySingle, allowAccept: true},
		{Name: "Idle-Timeout", Code: 28, Kind: KindInteger, Cardinality: CardinalitySingle, allowAccept: true},
		{Name: "Called-Station-Id", Code: 30, Kind: KindText, Cardinality: CardinalitySingle, allowReq: true},
		{Name: "Calling-Station-Id", Code: 31, Kind: KindText, Cardinality: CardinalitySingle, allowReq: true},
		{Name: "NAS-Identifier", Code: 32, Kind: KindText, Cardinality: CardinalitySingle, allowReq: true},
		{Name: "Proxy-State", Code: 33, Kind: KindString, Cardinality: CardinalityMulti, ServerOwned: true, allowReq: true, allowAccept: true, allowReject: true},
		{Name: "Event-Timestamp", Code: 55, Kind: KindTime, Cardinality: CardinalitySingle, allowReq: true, allowAccept: true},
		{Name: "CHAP-Challenge", Code: 60, Kind: KindString, Cardinality: CardinalitySingle, allowReq: true},
		{Name: "NAS-Port-Type", Code: 61, Kind: KindInteger, Cardinality: CardinalitySingle, allowReq: true},
		{Name: "Message-Authenticator", Code: 80, Kind: KindString, Cardinality: CardinalitySingle, Secret: true, ServerOwned: true, allowReq: true, allowAccept: true, allowReject: true},
		{Name: "Acct-Interim-Interval", Code: 85, Kind: KindInteger, Cardinality: CardinalitySingle, allowAccept: true},
		{Name: "NAS-IPv6-Address", Code: 95, Kind: KindIPv6, Cardinality: CardinalitySingle, allowReq: true},
		{Name: "Cisco-AVPair", Vendor: 9, Code: 1, Kind: KindText, Cardinality: CardinalityMulti, allowReq: true, allowAccept: true, allowReject: true},
	}
	d := dictionary{
		byName: make(map[string]attrDef, len(defs)),
		byCode: make(map[uint8]attrDef, len(defs)),
	}
	for _, def := range defs {
		if _, ok := d.byName[def.Name]; ok {
			panic("radius policy dictionary: duplicate name " + def.Name)
		}
		if def.Vendor == 0 {
			if _, ok := d.byCode[def.Code]; ok {
				panic("radius policy dictionary: duplicate code")
			}
			d.byCode[def.Code] = def
		}
		d.byName[def.Name] = def
	}
	return d
}

func (d dictionary) lookupVSA(vendor uint32, code uint8) (attrDef, bool) {
	for _, def := range d.byName {
		if def.Vendor == vendor && def.Code == code {
			return def, true
		}
	}
	return attrDef{}, false
}

func (d dictionary) lookupName(name string) (attrDef, bool) {
	def, ok := d.byName[name]
	return def, ok
}

func (d dictionary) lookupCode(code uint8) (attrDef, bool) {
	def, ok := d.byCode[code]
	return def, ok
}
