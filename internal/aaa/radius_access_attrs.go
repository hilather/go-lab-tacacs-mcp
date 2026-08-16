package aaa

import (
	"encoding/binary"
	"net/netip"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	policyradius "github.com/hilather/go-lab-tacacs-mcp/internal/policy/radius"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
)

func policyRequestAttrs(raw attribute.RawSet) policyradius.TypedSet {
	if len(raw) == 0 {
		return policyradius.TypedSet{}
	}
	out := make(policyradius.TypedSet, 0, len(raw))
	for _, a := range raw {
		if skipRequestAttr(a.Type) || attribute.MicrosoftSecret(a) {
			continue
		}
		if tv, ok := typedFromRaw(a); ok {
			out = append(out, tv)
		}
	}
	return out
}

func skipRequestAttr(typ uint8) bool {
	if attribute.Sensitive(typ) {
		return true
	}
	switch typ {
	case attribute.TypeMessageAuthenticator, attribute.TypeProxyState, attribute.TypeState:
		return true
	default:
		return false
	}
}

func typedFromRaw(a attribute.Raw) (policyradius.Typed, bool) {
	if a.Type == attribute.TypeVendorSpecific {
		return typedFromVSA(a)
	}
	def, ok := attribute.Builtin().LookupIETF(a.Type)
	if !ok {
		return policyradius.Typed{}, false
	}
	tv := policyradius.Typed{
		Key:  policyradius.AttrKey{Code: def.Code, Name: def.Name},
		Kind: policyradius.ValueKind(def.Kind),
	}
	switch def.Kind {
	case attribute.KindInteger, attribute.KindTime:
		if len(a.Value) != 4 {
			return policyradius.Typed{}, false
		}
		tv.Uint = binary.BigEndian.Uint32(a.Value)
	case attribute.KindIPv4:
		addr, ok := netip.AddrFromSlice(a.Value)
		if !ok || !addr.Is4() {
			return policyradius.Typed{}, false
		}
		tv.Addr = addr
	case attribute.KindIPv6:
		addr, ok := netip.AddrFromSlice(a.Value)
		if !ok || !addr.Is6() {
			return policyradius.Typed{}, false
		}
		tv.Addr = addr
	case attribute.KindText:
		tv.Text = string(a.Value)
	default:
		tv.Raw = append([]byte(nil), a.Value...)
	}
	return tv, true
}

func typedFromVSA(a attribute.Raw) (policyradius.Typed, bool) {
	vsa, err := attribute.ParseVSA(a)
	if err != nil || len(vsa.Payload) < 2 {
		return policyradius.Typed{}, false
	}
	vlen := int(vsa.Payload[1])
	if vlen < 2 || vlen > len(vsa.Payload) {
		return policyradius.Typed{}, false
	}
	return policyradius.Typed{
		Key:  policyradius.AttrKey{Vendor: vsa.Vendor, Code: vsa.Payload[0], Name: "Vendor-Specific"},
		Kind: policyradius.KindVSA,
		Raw:  append([]byte(nil), vsa.Payload[2:vlen]...),
	}, true
}

func encodePolicyReply(attrs policyradius.TypedSet, packet uint8) (attribute.RawSet, error) {
	effect := domain.EffectPermit
	if packet == attribute.PacketAccessReject {
		effect = domain.EffectDeny
	}
	if err := policyradius.CheckReplyLegal(effect, attrs); err != nil {
		return nil, err
	}
	if len(attrs) == 0 {
		return attribute.RawSet{}, nil
	}
	out := make(attribute.RawSet, 0, len(attrs))
	for _, a := range attrs {
		raw, err := encodeTyped(a)
		if err != nil {
			return nil, err
		}
		if !attribute.Builtin().AllowedIn(raw.Type, packet) {
			return nil, domain.NewError(domain.CodeInvalidArgument, "attribute is not legal in this RADIUS reply")
		}
		out = append(out, raw)
	}
	return out, nil
}

func encodeTyped(a policyradius.Typed) (attribute.Raw, error) {
	if a.Key.Vendor != 0 {
		return encodeVSA(a)
	}
	switch a.Kind {
	case policyradius.KindInteger, policyradius.KindTime:
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], a.Uint)
		return attribute.Raw{Type: a.Key.Code, Value: append([]byte(nil), buf[:]...)}, nil
	case policyradius.KindIPv4:
		if !a.Addr.IsValid() || !a.Addr.Is4() {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "reply IPv4 attribute is invalid")
		}
		b := a.Addr.As4()
		return attribute.Raw{Type: a.Key.Code, Value: b[:]}, nil
	case policyradius.KindIPv6:
		if !a.Addr.IsValid() || !a.Addr.Is6() {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "reply IPv6 attribute is invalid")
		}
		b := a.Addr.As16()
		return attribute.Raw{Type: a.Key.Code, Value: b[:]}, nil
	case policyradius.KindText:
		return attribute.Raw{Type: a.Key.Code, Value: []byte(a.Text)}, nil
	default:
		return attribute.Raw{Type: a.Key.Code, Value: append([]byte(nil), a.Raw...)}, nil
	}
}

func encodeVSA(a policyradius.Typed) (attribute.Raw, error) {
	if len(a.Raw) > attribute.MaxValueLength-6 {
		return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "reply VSA exceeds attribute maximum")
	}
	payload := make([]byte, 2+len(a.Raw))
	payload[0] = a.Key.Code
	payload[1] = byte(2 + len(a.Raw))
	copy(payload[2:], a.Raw)
	return attribute.VSA{Vendor: a.Key.Vendor, Payload: payload}.Raw()
}

func wipeSecretAttrs(set attribute.RawSet) {
	for i := range set {
		if !attribute.Sensitive(set[i].Type) && !attribute.MicrosoftSecret(set[i]) {
			continue
		}
		for j := range set[i].Value {
			set[i].Value[j] = 0
		}
	}
}
