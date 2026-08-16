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
		if a.Type == attribute.TypeVendorSpecific {
			out = append(out, typedFromVSAAll(a)...)
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

func typedFromVSAAll(a attribute.Raw) []policyradius.Typed {
	vsa, err := attribute.ParseVSA(a)
	if err != nil {
		return nil
	}
	tlvs, err := attribute.ParseVendorTLVs(vsa.Payload)
	if err != nil {
		return nil
	}
	out := make([]policyradius.Typed, 0, len(tlvs))
	for _, tlv := range tlvs {
		name := "Vendor-Specific"
		kind := policyradius.KindVSA
		text := ""
		if def, ok := attribute.Builtin().LookupKey(attribute.Key{
			Vendor: vsa.Vendor, Code: uint32(tlv.Type), Space: attribute.SpaceVSA,
		}); ok {
			name = def.Name
			kind = policyradius.ValueKind(def.Kind)
			if def.Kind == attribute.KindText {
				text = string(tlv.Value)
			}
		}
		out = append(out, policyradius.Typed{
			Key:  policyradius.AttrKey{Vendor: vsa.Vendor, Code: tlv.Type, Name: name},
			Kind: kind,
			Text: text,
			Raw:  append([]byte(nil), tlv.Value...),
		})
	}
	return out
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
	inner := a.Raw
	if len(inner) == 0 && a.Text != "" {
		inner = []byte(a.Text)
	}
	if len(inner) > attribute.MaxVendorTLVValue {
		return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "reply VSA exceeds attribute maximum")
	}
	payload, err := attribute.EncodeVendorTLVs([]attribute.VendorTLV{{Type: a.Key.Code, Value: inner}})
	if err != nil {
		return attribute.Raw{}, err
	}
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
