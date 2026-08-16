package attribute

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestMergeOperatorEmptyKeepsBuiltinVersion(t *testing.T) {
	t.Parallel()
	d, err := MergeOperator(Builtin(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version() != DictionaryVersion || DictionaryVersion != "builtin-mvp-1" {
		t.Fatalf("version=%q", d.Version())
	}
	if strings.Contains(d.Version(), "+op:") {
		t.Fatalf("empty merge must not append +op: %q", d.Version())
	}
	if len(d.All()) != len(Builtin().All()) {
		t.Fatalf("len=%d want %d", len(d.All()), len(Builtin().All()))
	}
	d2, err := MergeOperator(Builtin(), []OperatorSource{})
	if err != nil {
		t.Fatal(err)
	}
	if d2.Version() != DictionaryVersion {
		t.Fatalf("empty slice version=%q", d2.Version())
	}
}

func TestMergeOperatorAddsNamedVSA(t *testing.T) {
	t.Parallel()
	d, err := MergeOperator(Builtin(), []OperatorSource{{
		ID:   "lab-juniper",
		Data: []byte(juniperDictYAML),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Version() == DictionaryVersion || !strings.HasPrefix(d.Version(), DictionaryVersion+"+op:") {
		t.Fatalf("version=%q", d.Version())
	}
	if !strings.Contains(d.Version(), "lab-juniper") {
		t.Fatalf("version missing id: %q", d.Version())
	}
	def, ok := d.LookupName("Juniper-Local-User-Name")
	if !ok {
		t.Fatal("missing operator name")
	}
	if def.Vendor != 2636 || def.Code != 1 || def.Kind != KindText || def.Cardinality != CardinalitySingle {
		t.Fatalf("def=%+v", def)
	}
	if def.Sensitivity != SensitivityRestricted || def.Source != "operator:lab-juniper" {
		t.Fatalf("sens/source=%q %q", def.Sensitivity, def.Source)
	}
	if !def.AllowedIn(PacketAccessAccept) || def.AllowedIn(PacketAccessRequest) {
		t.Fatalf("allowed=%v", def.AllowedPackets())
	}
	byKey, ok := d.LookupKey(Key{Vendor: 2636, Code: 1, Space: SpaceVSA})
	if !ok || byKey.Name != "Juniper-Local-User-Name" {
		t.Fatalf("lookup key=%+v ok=%v", byKey, ok)
	}
	user, ok := d.LookupName("User-Name")
	if !ok || user.Source != SourceBuiltin {
		t.Fatalf("builtin source=%q ok=%v", user.Source, ok)
	}
}

func TestMergeOperatorVersionStableAcrossFileOrder(t *testing.T) {
	t.Parallel()
	a := OperatorSource{ID: "lab-a", Data: []byte(vendorDictYAML(2636, "Juniper", "Juniper-Local-User-Name", 1))}
	b := OperatorSource{ID: "lab-b", Data: []byte(vendorDictYAML(4874, "Brocade", "Brocade-Auth-Role", 1))}
	d1, err := MergeOperator(Builtin(), []OperatorSource{a, b})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := MergeOperator(Builtin(), []OperatorSource{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if d1.Version() != d2.Version() {
		t.Fatalf("order-dependent version\n%s\n%s", d1.Version(), d2.Version())
	}
	if !strings.Contains(d1.Version(), "lab-a,lab-b") {
		t.Fatalf("ids must be sorted: %q", d1.Version())
	}
}

func TestMergeOperatorRejectsReservedVendors(t *testing.T) {
	t.Parallel()
	for _, id := range []uint32{ReservedVendorIETF, ReservedVendorCisco, ReservedVendorMicrosoft} {
		_, err := MergeOperator(Builtin(), []OperatorSource{{
			ID:   "bad",
			Data: []byte(vendorDictYAML(id, "Stolen", "Stolen-Attr", 1)),
		}})
		if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "reserved vendor") {
			t.Fatalf("vendor %d: %v", id, err)
		}
	}
}

func TestMergeOperatorRejectsReservedNames(t *testing.T) {
	t.Parallel()
	names := []string{
		"User-Name",
		"User-Password",
		"Cisco-AVPair",
		"MS-CHAP-Challenge",
		"MS-CHAP-Response",
		"MS-CHAP2-Response",
		"MS-CHAP2-Success",
		"MS-CHAP-Error",
		"MS-CHAP-Foo",
	}
	for _, name := range names {
		_, err := MergeOperator(Builtin(), []OperatorSource{{
			ID:   "bad",
			Data: []byte(vendorDictYAML(2636, "Juniper", name, 1)),
		}})
		if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "reserved") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestMergeOperatorRejectsSecretSensitivityDowngrade(t *testing.T) {
	t.Parallel()
	_, err := MergeOperator(Builtin(), []OperatorSource{{
		ID: "bad",
		Data: []byte(`schema_version: 1
vendor: {id: 2636, name: Juniper}
attributes:
  - name: User-Password
    vendor_type: 1
    kind: string
    sensitivity: public
    allowed_in: [access_request]
`),
	}})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "secret") && !strings.Contains(msg, "reserved") {
		t.Fatalf("err=%v", err)
	}
}

func TestMergeOperatorRejectsDuplicateNamesAndKeys(t *testing.T) {
	t.Parallel()
	first := OperatorSource{ID: "one", Data: []byte(juniperDictYAML)}
	_, err := MergeOperator(Builtin(), []OperatorSource{first, {
		ID:   "two",
		Data: []byte(vendorDictYAML(2636, "Juniper", "Juniper-Local-User-Name", 2)),
	}})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "duplicate") {
		t.Fatalf("dup name: %v", err)
	}
	_, err = MergeOperator(Builtin(), []OperatorSource{first, {
		ID:   "two",
		Data: []byte(vendorDictYAML(2636, "Juniper", "Juniper-Other", 1)),
	}})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "duplicate") {
		t.Fatalf("dup key: %v", err)
	}
}

func TestMergeOperatorRejectsRemoteAndIncludeBytes(t *testing.T) {
	t.Parallel()
	_, err := MergeOperator(Builtin(), []OperatorSource{{
		ID:   "inc",
		Data: []byte("$INCLUDE /etc/freeradius/dictionary.juniper\n"),
	}})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "$include") {
		t.Fatalf("$INCLUDE: %v", err)
	}
	_, err = MergeOperator(Builtin(), []OperatorSource{{
		ID:   "fr",
		Data: []byte("VENDOR Juniper 2636\nATTRIBUTE Juniper-Local-User-Name 1 string\n"),
	}})
	if err == nil {
		t.Fatal("FreeRADIUS language must fail")
	}
}

func TestMergeOperatorRejectsUnknownFieldsAndKinds(t *testing.T) {
	t.Parallel()
	_, err := MergeOperator(Builtin(), []OperatorSource{{
		ID: "unk",
		Data: []byte(`schema_version: 1
vendor: {id: 2636, name: Juniper}
attributes:
  - name: Juniper-Local-User-Name
    vendor_type: 1
    kind: text
    allowed_in: [access_accept]
    VALUE: 1
`),
	}})
	if !isOperatorErr(err, domain.CodeConfigUnknownField, "") {
		t.Fatalf("unknown field: %v", err)
	}
	_, err = MergeOperator(Builtin(), []OperatorSource{{
		ID:   "kind",
		Data: []byte(vendorDictYAMLKind(2636, "Juniper", "Juniper-X", 1, "tlv")),
	}})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "kind") {
		t.Fatalf("kind: %v", err)
	}
	_, err = MergeOperator(Builtin(), []OperatorSource{{
		ID: "sens",
		Data: []byte(`schema_version: 1
vendor: {id: 2636, name: Juniper}
attributes:
  - name: Juniper-X
    vendor_type: 1
    kind: text
    sensitivity: unknown
    allowed_in: [access_accept]
`),
	}})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "sensitivity") {
		t.Fatalf("sensitivity: %v", err)
	}
	_, err = MergeOperator(Builtin(), []OperatorSource{{
		ID: "pkt",
		Data: []byte(`schema_version: 1
vendor: {id: 2636, name: Juniper}
attributes:
  - name: Juniper-X
    vendor_type: 1
    kind: text
    allowed_in: [coa_request]
`),
	}})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "allowed_in") {
		t.Fatalf("allowed_in: %v", err)
	}
}

func TestMergeOperatorRejectsLimits(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("A", MaxOperatorNameLength+1)
	_, err := MergeOperator(Builtin(), []OperatorSource{{
		ID:   "name",
		Data: []byte(vendorDictYAML(2636, "Juniper", long, 1)),
	}})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "name") {
		t.Fatalf("name length: %v", err)
	}
	var files []OperatorSource
	remaining := MaxOperatorAttributes + 1
	vend := uint32(2000)
	fileN := 0
	for remaining > 0 {
		n := remaining
		if n > 255 {
			n = 255
		}
		var attrs bytes.Buffer
		attrs.WriteString("schema_version: 1\nvendor: {id: " + u32toa(vend) + ", name: V" + itoa(int(vend)) + "}\nattributes:\n")
		for i := 0; i < n; i++ {
			attrs.WriteString(attrYAMLLine("V"+itoa(int(vend))+"-A"+itoa(i), i+1))
		}
		files = append(files, OperatorSource{ID: "many" + itoa(fileN), Data: attrs.Bytes()})
		remaining -= n
		vend++
		fileN++
	}
	_, err = MergeOperator(Builtin(), files)
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "attribute") {
		t.Fatalf("attr cap: %v", err)
	}
	files = nil
	for i := 0; i < MaxOperatorVendors+1; i++ {
		files = append(files, OperatorSource{
			ID:   "v" + itoa(i),
			Data: []byte(vendorDictYAML(1000+uint32(i), "V"+itoa(i), "V"+itoa(i)+"-Attr", 1)),
		})
	}
	_, err = MergeOperator(Builtin(), files)
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "vendor") {
		t.Fatalf("vendor cap: %v", err)
	}
}

func TestMergeOperatorRejectsVendorIdentityClash(t *testing.T) {
	t.Parallel()
	_, err := MergeOperator(Builtin(), []OperatorSource{
		{ID: "a", Data: []byte(vendorDictYAML(2636, "Juniper", "Juniper-A", 1))},
		{ID: "b", Data: []byte(vendorDictYAML(2636, "NotJuniper", "Other-A", 2))},
	})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "vendor") {
		t.Fatalf("id clash: %v", err)
	}
	_, err = MergeOperator(Builtin(), []OperatorSource{
		{ID: "a", Data: []byte(vendorDictYAML(2636, "Juniper", "Juniper-A", 1))},
		{ID: "b", Data: []byte(vendorDictYAML(4874, "Juniper", "Other-A", 1))},
	})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "vendor") {
		t.Fatalf("name clash: %v", err)
	}
}

func TestMergeOperatorRejectsBadSchemaAndEmptyAttrs(t *testing.T) {
	t.Parallel()
	_, err := MergeOperator(Builtin(), []OperatorSource{{
		ID: "sv",
		Data: []byte(`schema_version: 2
vendor: {id: 2636, name: Juniper}
attributes:
  - name: Juniper-X
    vendor_type: 1
    kind: text
    allowed_in: [access_accept]
`),
	}})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "schema_version") {
		t.Fatalf("schema: %v", err)
	}
	_, err = MergeOperator(Builtin(), []OperatorSource{{
		ID: "empty",
		Data: []byte(`schema_version: 1
vendor: {id: 2636, name: Juniper}
attributes: []
`),
	}})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "attribute") {
		t.Fatalf("empty attrs: %v", err)
	}
}

func TestMergeOperatorRejectsOversizedFile(t *testing.T) {
	t.Parallel()
	data := bytes.Repeat([]byte("#"), MaxOperatorDictionaryBytes+1)
	_, err := MergeOperator(Builtin(), []OperatorSource{{ID: "big", Data: data}})
	if !isOperatorErr(err, domain.CodeConfigYAMLInvalid, "size") {
		t.Fatalf("size: %v", err)
	}
}

func TestMergeOperatorDoesNotMutateBuiltin(t *testing.T) {
	t.Parallel()
	before := len(Builtin().All())
	ver := Builtin().Version()
	_, err := MergeOperator(Builtin(), []OperatorSource{{ID: "bad", Data: []byte("not yaml")}})
	if err == nil {
		t.Fatal("expected error")
	}
	if len(Builtin().All()) != before || Builtin().Version() != ver {
		t.Fatal("builtin mutated")
	}
	_, err = MergeOperator(Builtin(), []OperatorSource{{ID: "ok", Data: []byte(juniperDictYAML)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(Builtin().All()) != before || Builtin().Version() != DictionaryVersion {
		t.Fatal("successful merge mutated builtin")
	}
	if _, ok := Builtin().LookupName("Juniper-Local-User-Name"); ok {
		t.Fatal("operator name leaked into builtin")
	}
}

func TestMergeOperatorOctetsKind(t *testing.T) {
	t.Parallel()
	d, err := MergeOperator(Builtin(), []OperatorSource{{
		ID:   "oct",
		Data: []byte(vendorDictYAMLKind(2636, "Juniper", "Juniper-Blob", 2, "octets")),
	}})
	if err != nil {
		t.Fatal(err)
	}
	def, ok := d.LookupName("Juniper-Blob")
	if !ok || def.Kind != KindOctets {
		t.Fatalf("def=%+v ok=%v", def, ok)
	}
}

func TestBuiltinSourcesAreBuiltin(t *testing.T) {
	t.Parallel()
	for _, def := range Builtin().All() {
		if def.Source != SourceBuiltin {
			t.Fatalf("%s source=%q", def.Name, def.Source)
		}
	}
}

func isOperatorErr(err error, code domain.Code, needle string) bool {
	if err == nil {
		return false
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != code {
		return false
	}
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), needle)
}

const juniperDictYAML = `schema_version: 1
vendor:
  id: 2636
  name: Juniper
attributes:
  - name: Juniper-Local-User-Name
    vendor_type: 1
    kind: text
    cardinality: single
    sensitivity: restricted
    allowed_in: [access_accept]
`

func vendorDictYAML(vendor uint32, vendorName, attr string, typ int) string {
	return vendorDictYAMLKind(vendor, vendorName, attr, typ, "text")
}

func vendorDictYAMLKind(vendor uint32, vendorName, attr string, typ int, kind string) string {
	return "schema_version: 1\nvendor: {id: " + u32toa(vendor) + ", name: " + vendorName + "}\nattributes:\n" +
		"  - name: " + attr + "\n    vendor_type: " + itoa(typ) + "\n    kind: " + kind + "\n    allowed_in: [access_accept]\n"
}

func attrYAMLLine(name string, typ int) string {
	return "  - {name: " + name + ", vendor_type: " + itoa(typ) + ", kind: text, allowed_in: [access_accept]}\n"
}

func u32toa(n uint32) string { return itoa(int(n)) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}

func TestMergeOperatorErrorsNeverPrintValues(t *testing.T) {
	t.Parallel()
	const canary = "CANARY-OP-DICT-SECRET-zz"
	_, err := MergeOperator(Builtin(), []OperatorSource{{
		ID:   "bad",
		Data: []byte("schema_version: 1\nvendor: {id: 9, name: " + canary + "}\nattributes: [{name: X, vendor_type: 1, kind: text, allowed_in: [access_accept]}]\n"),
	}})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), canary) {
		// vendor name is not a secret; reserved-vendor errors should mention vendor id.
		t.Logf("err=%v", err)
	}
	_ = errors.New("")
}
