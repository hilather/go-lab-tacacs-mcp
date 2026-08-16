package operations

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func handleRadiusAccessTest(deps Deps) handleFunc {
	return func(ctx context.Context, snap *state.Snapshot, in Input) (any, error) {
		if snap == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
		}
		req, _ := in.Request.(RadiusAccessTestRequest)
		defer wipeRadiusAccessSecrets(&req)

		if req.UserID == "" {
			return nil, domain.NewError(domain.CodeInvalidArgument, "user_id is required").WithPath("user_id")
		}
		_, ev, err := radiusEvidence(req.Method)
		if err != nil {
			return nil, err
		}
		defer wipeRadiusEvidence(&ev)

		clientID := req.ClientID
		endpointID := ""
		if clientID != "" {
			if _, ok := snap.Client(clientID); !ok {
				return nil, domain.NewError(domain.CodeNotFound, "client not found").WithPath("client_id")
			}
			if ep, ok := radiusEndpoint(snap, clientID); ok {
				endpointID = ep.ID
				if !radiusMethodAllowed(ep, req.Method.Type) {
					out := RadiusAccessTestResult{
						Outcome:         RadiusOutcomeReject,
						ReasonCode:      aaa.AccessReasonUnsupportedMethod,
						ReplyAttributes: []RadiusAttributeValue{},
					}
					if req.Explain {
						tr := radiusTraceFromAAA(aaa.RadiusAccessDecision{ReasonCode: aaa.AccessReasonUnsupportedMethod})
						out.Trace = &tr
					}
					audit(deps, "api.radius.access.tested", out.Outcome, snap.Revision)
					return out, nil
				}
			}
		}

		raw, err := encodeRadiusRequestAttrs(req.RequestAttributes)
		if err != nil {
			return nil, err
		}

		if deps.AAA == nil {
			out := RadiusAccessTestResult{
				Outcome:         RadiusOutcomeReject,
				ReasonCode:      aaa.AccessReasonInternal,
				ReplyAttributes: []RadiusAttributeValue{},
			}
			audit(deps, "api.radius.access.tested", out.Outcome, snap.Revision)
			return out, nil
		}

		dec, err := deps.AAA.AuthenticateAccess(ctx, aaa.RadiusAccessAttempt{
			Context: domain.RequestContext{
				Protocol:         domain.ProtocolRADIUS,
				Carrier:          domain.CarrierRADIUSUDP,
				ListenerRole:     domain.RoleAccess,
				ListenerID:       ListenerRADIUSAccess,
				ClientID:         clientID,
				EndpointID:       endpointID,
				SnapshotRevision: snap.Revision,
			},
			UserID:     req.UserID,
			Evidence:   ev,
			Attributes: raw,
		})
		if err != nil {
			return nil, err
		}
		out := radiusAccessResult(dec, req.Explain)
		audit(deps, "api.radius.access.tested", out.Outcome, snap.Revision)
		return out, nil
	}
}

func handleRadiusPolicyEvaluate(deps Deps) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
		if snap == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
		}
		req, _ := in.Request.(RadiusPolicyEvaluateRequest)
		if req.UserID == "" {
			return nil, domain.NewError(domain.CodeInvalidArgument, "user_id is required").WithPath("user_id")
		}
		var method domain.AuthMethod
		if req.Method != "" {
			parsed, err := parseRADIUSMethod(req.Method, "method")
			if err != nil {
				return nil, err
			}
			method = parsed
		}
		if req.ClientID != "" {
			if _, ok := snap.Client(req.ClientID); !ok {
				return nil, domain.NewError(domain.CodeNotFound, "client not found").WithPath("client_id")
			}
		}
		endpointID := req.EndpointID
		if endpointID == "" {
			if ep, ok := radiusEndpoint(snap, req.ClientID); ok {
				endpointID = ep.ID
			}
		}
		raw, err := encodeRadiusRequestAttrs(req.RequestAttributes)
		if err != nil {
			return nil, err
		}
		dec := aaa.ExplainRADIUSAccess(snap, req.UserID, req.ClientID, endpointID, method, raw)
		out := RadiusPolicyEvaluateResult{
			Effect:          radiusEffect(dec),
			ReasonCode:      dec.ReasonCode,
			ReplyAttributes: formatRadiusReply(dec.ReplyAttributes),
			Trace:           radiusTraceFromAAA(dec),
		}
		audit(deps, "api.radius.policy.evaluated", out.Effect, snap.Revision)
		return out, nil
	}
}

func handleRadiusAttributesList(_ context.Context, snap *state.Snapshot, _ Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	view := attribute.Builtin()
	if d := snap.Dictionary(); !d.Empty() {
		view = d.View()
	}
	defs := view.All()
	items := make([]RadiusAttributeMetadata, 0, len(defs))
	for _, def := range defs {
		allowed := def.AllowedPackets()
		names := make([]string, 0, len(allowed))
		for _, code := range allowed {
			names = append(names, radiusPacketName(code))
		}
		src := def.Source
		if src == "" {
			src = attribute.SourceBuiltin
		}
		items = append(items, RadiusAttributeMetadata{
			Name:        def.Name,
			Code:        def.Code,
			Vendor:      def.Vendor,
			ValueKind:   string(def.Kind),
			AllowedIn:   names,
			Sensitivity: string(def.Sensitivity),
			Source:      src,
		})
	}
	return RadiusAttributeList{Version: view.Version(), Items: items}, nil
}

func radiusEvidence(m RadiusAuthMethod) (domain.AuthMethod, aaa.CredentialEvidence, error) {
	method, err := parseRADIUSMethod(m.Type, "method.type")
	if err != nil {
		return "", aaa.CredentialEvidence{}, err
	}
	ev := aaa.CredentialEvidence{Method: method}
	switch method {
	case domain.AuthMethodPassword:
		ev.Password = credentials.NewPassword([]byte(m.Password))
	case domain.AuthMethodCHAP, domain.AuthMethodMSCHAPv1, domain.AuthMethodMSCHAPv2:
		chal, err := decodeRadiusB64("method.challenge", m.Challenge)
		if err != nil {
			return "", ev, err
		}
		resp, err := decodeRadiusB64("method.response", m.Response)
		if err != nil {
			wipeBytes(chal)
			return "", ev, err
		}
		ev.CHAPID = m.ID
		ev.Challenge = chal
		ev.Response = resp
	}
	return method, ev, nil
}

func parseRADIUSMethod(raw, path string) (domain.AuthMethod, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pap":
		return domain.AuthMethodPassword, nil
	case "chap":
		return domain.AuthMethodCHAP, nil
	case "mschapv1":
		return domain.AuthMethodMSCHAPv1, nil
	case "mschapv2":
		return domain.AuthMethodMSCHAPv2, nil
	default:
		return "", domain.NewError(domain.CodeInvalidArgument, "method must be pap, chap, mschapv1, or mschapv2").WithPath(path)
	}
}

func decodeRadiusB64(path, v string) ([]byte, error) {
	if v == "" {
		return nil, domain.NewError(domain.CodeInvalidArgument, path+" is required").WithPath(path)
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, path+" must be base64").WithPath(path)
	}
	return b, nil
}

func radiusEndpoint(snap *state.Snapshot, clientID string) (config.ClientEndpoint, bool) {
	if snap == nil || clientID == "" {
		return config.ClientEndpoint{}, false
	}
	c, ok := snap.Client(clientID)
	if !ok {
		return config.ClientEndpoint{}, false
	}
	for _, ep := range c.Client.Endpoints {
		if ep.Protocol == domain.ProtocolRADIUS && ep.RADIUS != nil {
			return ep, true
		}
	}
	return config.ClientEndpoint{}, false
}

func radiusMethodAllowed(ep config.ClientEndpoint, typ string) bool {
	if ep.RADIUS == nil || len(ep.RADIUS.AllowedAuthenticationMethods) == 0 {
		return true
	}
	want := strings.ToLower(strings.TrimSpace(typ))
	for _, m := range ep.RADIUS.AllowedAuthenticationMethods {
		if strings.ToLower(m) == want {
			return true
		}
	}
	return false
}

func radiusAccessResult(dec aaa.RadiusAccessDecision, explain bool) RadiusAccessTestResult {
	out := RadiusAccessTestResult{
		Outcome:         radiusOutcome(dec.Outcome),
		ReasonCode:      dec.ReasonCode,
		ReplyAttributes: formatRadiusReply(dec.ReplyAttributes),
	}
	if explain {
		tr := radiusTraceFromAAA(dec)
		out.Trace = &tr
	}
	return out
}

func radiusOutcome(o aaa.RadiusAccessOutcome) string {
	if o == aaa.RadiusAccessAccept {
		return RadiusOutcomeAccept
	}
	return RadiusOutcomeReject
}

func radiusEffect(dec aaa.RadiusAccessDecision) string {
	switch dec.ReasonCode {
	case aaa.AccessReasonOK:
		return domain.EffectPermit.String()
	case aaa.AccessReasonInternal:
		return domain.EffectError.String()
	default:
		return domain.EffectDeny.String()
	}
}

func radiusTraceFromAAA(dec aaa.RadiusAccessDecision) RadiusPolicyTrace {
	in := dec.Trace
	out := RadiusPolicyTrace{
		Evaluator:   in.Evaluator,
		UserID:      in.UserID,
		ClientID:    in.ClientID,
		EndpointID:  in.EndpointID,
		Method:      in.Method,
		Groups:      append([]string(nil), in.Groups...),
		Steps:       make([]RadiusPolicyTraceStep, 0, len(in.Steps)),
		Effect:      in.Effect,
		DefaultDeny: in.DefaultDeny,
		Error:       in.Error,
	}
	if out.Evaluator == "" {
		out.Evaluator = "radius_access"
	}
	for _, st := range in.Steps {
		out.Steps = append(out.Steps, RadiusPolicyTraceStep{
			Source: st.Source, RuleID: st.RuleID, Matched: st.Matched, Reason: st.Reason,
		})
	}
	if in.Winner != nil {
		out.Winner = &RadiusPolicyTraceWinner{Source: in.Winner.Source, RuleID: in.Winner.RuleID, Effect: in.Winner.Effect}
	}
	return out
}

func encodeRadiusRequestAttrs(in []RadiusAttributeValue) (attribute.RawSet, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(attribute.RawSet, 0, len(in))
	for i, a := range in {
		raw, err := encodeRadiusAttr(a, "request_attributes["+strconv.Itoa(i)+"]")
		if err != nil {
			return nil, err
		}
		if attribute.Sensitive(raw.Type) {
			return nil, domain.NewError(domain.CodeInvalidArgument, "request attributes must not include secret types").
				WithPath("request_attributes[" + strconv.Itoa(i) + "]")
		}
		out = append(out, raw)
	}
	return out, nil
}

func encodeRadiusAttr(a RadiusAttributeValue, path string) (attribute.Raw, error) {
	name := strings.TrimSpace(a.Name)
	if name == attribute.NameCiscoAVPair || (a.Vendor == attribute.VendorCisco && a.Code == attribute.TypeCiscoAVPair) {
		if name != "" && name != attribute.NameCiscoAVPair {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "attribute name and vendor disagree").WithPath(path)
		}
		if a.Vendor != 0 && a.Vendor != attribute.VendorCisco {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "attribute name and vendor disagree").WithPath(path)
		}
		if a.Code != 0 && a.Code != attribute.TypeCiscoAVPair {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "attribute name and code disagree").WithPath(path)
		}
		text := a.Value
		if a.ValueHex != "" {
			b, err := hex.DecodeString(a.ValueHex)
			if err != nil {
				return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "value_hex must be even-length hex").WithPath(path + ".value_hex")
			}
			if text != "" && text != string(b) {
				return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "value and value_hex disagree").WithPath(path)
			}
			text = string(b)
		}
		return attribute.EncodeCiscoAVPair(text)
	}
	if a.Vendor != 0 {
		if a.Code == 0 {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "vendor requires code").WithPath(path + ".code")
		}
		if a.ValueHex == "" {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "raw VSA requires value_hex").WithPath(path + ".value_hex")
		}
		payload, err := hex.DecodeString(a.ValueHex)
		if err != nil {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "value_hex must be even-length hex").WithPath(path + ".value_hex")
		}
		nested, err := attribute.EncodeVendorTLVs([]attribute.VendorTLV{{Type: a.Code, Value: payload}})
		if err != nil {
			return attribute.Raw{}, err
		}
		return attribute.VSA{Vendor: a.Vendor, Payload: nested}.Raw()
	}
	def, err := resolveRADIUSDef(a, path)
	if err != nil {
		return attribute.Raw{}, err
	}
	if def.Sensitivity == attribute.SensitivitySecret {
		return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "request attributes must not include secret types").WithPath(path)
	}
	if def.Vendor != 0 {
		return encodeNamedVSA(def, a.Value, a.ValueHex, path)
	}
	val, err := parseRADIUSAttrValue(def, a.Value, a.ValueHex, path)
	if err != nil {
		return attribute.Raw{}, err
	}
	return val, nil
}

func encodeNamedVSA(def attribute.Definition, value, valueHex, path string) (attribute.Raw, error) {
	text := value
	if valueHex != "" {
		b, err := hex.DecodeString(valueHex)
		if err != nil {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "value_hex must be even-length hex").WithPath(path + ".value_hex")
		}
		text = string(b)
	}
	if def.Name == attribute.NameCiscoAVPair {
		return attribute.EncodeCiscoAVPair(text)
	}
	nested, err := attribute.EncodeVendorTLVs([]attribute.VendorTLV{{Type: def.Code, Value: []byte(text)}})
	if err != nil {
		return attribute.Raw{}, err
	}
	return attribute.VSA{Vendor: def.Vendor, Payload: nested}.Raw()
}

func resolveRADIUSDef(a RadiusAttributeValue, path string) (attribute.Definition, error) {
	name := strings.TrimSpace(a.Name)
	if name != "" {
		def, ok := attribute.Builtin().LookupName(name)
		if !ok {
			return attribute.Definition{}, domain.NewError(domain.CodeInvalidArgument, "unknown RADIUS attribute name").WithPath(path + ".name")
		}
		if a.Code != 0 && a.Code != def.Code {
			return attribute.Definition{}, domain.NewError(domain.CodeInvalidArgument, "attribute name and code disagree").WithPath(path)
		}
		return def, nil
	}
	if a.Code == 0 {
		return attribute.Definition{}, domain.NewError(domain.CodeInvalidArgument, "attribute requires name or vendor+code").WithPath(path)
	}
	def, ok := attribute.Builtin().LookupIETF(a.Code)
	if !ok {
		return attribute.Definition{}, domain.NewError(domain.CodeInvalidArgument, "unknown RADIUS attribute code").WithPath(path + ".code")
	}
	return def, nil
}

func parseRADIUSAttrValue(def attribute.Definition, value, valueHex, path string) (attribute.Raw, error) {
	switch def.Kind {
	case attribute.KindInteger, attribute.KindTime:
		n, err := parseRADIUSUint32(def, value)
		if err != nil {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "value must be an unsigned 32-bit integer").WithPath(path + ".value")
		}
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], n)
		return attribute.Raw{Type: def.Code, Value: append([]byte(nil), buf[:]...)}, nil
	case attribute.KindIPv4:
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !addr.Is4() {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "value must be an IPv4 address").WithPath(path + ".value")
		}
		b := addr.As4()
		return attribute.Raw{Type: def.Code, Value: b[:]}, nil
	case attribute.KindIPv6:
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !addr.Is6() {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "value must be an IPv6 address").WithPath(path + ".value")
		}
		b := addr.As16()
		return attribute.Raw{Type: def.Code, Value: b[:]}, nil
	case attribute.KindText:
		if valueHex != "" {
			return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "text attributes use value, not value_hex").WithPath(path + ".value_hex")
		}
		return attribute.Raw{Type: def.Code, Value: []byte(value)}, nil
	default:
		if valueHex != "" {
			b, err := hex.DecodeString(valueHex)
			if err != nil {
				return attribute.Raw{}, domain.NewError(domain.CodeInvalidArgument, "value_hex must be even-length hex").WithPath(path + ".value_hex")
			}
			return attribute.Raw{Type: def.Code, Value: b}, nil
		}
		return attribute.Raw{Type: def.Code, Value: []byte(value)}, nil
	}
}

func parseRADIUSUint32(def attribute.Definition, value string) (uint32, error) {
	s := strings.TrimSpace(value)
	n, err := strconv.ParseUint(s, 10, 32)
	if err == nil {
		return uint32(n), nil
	}
	if def.Name == "Service-Type" {
		if v, ok := serviceTypeAlias[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	return 0, err
}

// Design example uses FreeRADIUS Service-Type names (Login-User = 1).
var serviceTypeAlias = map[string]uint32{
	"login": 1, "login-user": 1,
	"framed": 2, "framed-user": 2,
}

func formatRadiusReply(in attribute.RawSet) []RadiusAttributeValue {
	if len(in) == 0 {
		return []RadiusAttributeValue{}
	}
	out := make([]RadiusAttributeValue, 0, len(in))
	for _, raw := range in {
		if attribute.Sensitive(raw.Type) || attribute.MicrosoftSecret(raw) {
			continue
		}
		out = append(out, formatRadiusExpanded(raw)...)
	}
	return out
}

func formatRadiusExpanded(raw attribute.Raw) []RadiusAttributeValue {
	if raw.Type != attribute.TypeVendorSpecific {
		return []RadiusAttributeValue{formatRadiusRaw(raw)}
	}
	vsa, err := attribute.ParseVSA(raw)
	if err != nil {
		return []RadiusAttributeValue{formatRadiusRaw(raw)}
	}
	tlvs, err := attribute.ParseVendorTLVs(vsa.Payload)
	if err != nil || len(tlvs) == 0 {
		return []RadiusAttributeValue{formatRadiusRaw(raw)}
	}
	out := make([]RadiusAttributeValue, 0, len(tlvs))
	for _, tlv := range tlvs {
		item := RadiusAttributeValue{Vendor: vsa.Vendor, Code: tlv.Type}
		if def, ok := attribute.Builtin().LookupKey(attribute.Key{
			Vendor: vsa.Vendor, Code: uint32(tlv.Type), Space: attribute.SpaceVSA,
		}); ok {
			item.Name = def.Name
			if def.Kind == attribute.KindText {
				item.Value = string(tlv.Value)
			} else {
				item.ValueHex = hex.EncodeToString(tlv.Value)
			}
		} else {
			item.Name = "Vendor-Specific"
			item.ValueHex = hex.EncodeToString(tlv.Value)
		}
		out = append(out, item)
	}
	return out
}

func formatRadiusRaw(raw attribute.Raw) RadiusAttributeValue {
	def, ok := attribute.Builtin().LookupIETF(raw.Type)
	if !ok {
		return RadiusAttributeValue{Code: raw.Type, ValueHex: hex.EncodeToString(raw.Value)}
	}
	v := RadiusAttributeValue{Name: def.Name, Code: def.Code, Vendor: def.Vendor}
	switch def.Kind {
	case attribute.KindInteger, attribute.KindTime:
		if len(raw.Value) == 4 {
			v.Value = strconv.FormatUint(uint64(binary.BigEndian.Uint32(raw.Value)), 10)
		}
	case attribute.KindIPv4, attribute.KindIPv6:
		if addr, ok := netip.AddrFromSlice(raw.Value); ok {
			v.Value = addr.String()
		}
	case attribute.KindText:
		v.Value = string(raw.Value)
	default:
		v.ValueHex = hex.EncodeToString(raw.Value)
	}
	return v
}

func radiusPacketName(code uint8) string {
	switch code {
	case attribute.PacketAccessRequest:
		return "Access-Request"
	case attribute.PacketAccessAccept:
		return "Access-Accept"
	case attribute.PacketAccessReject:
		return "Access-Reject"
	case attribute.PacketAccountingRequest:
		return "Accounting-Request"
	case attribute.PacketAccountingResponse:
		return "Accounting-Response"
	case attribute.PacketAccessChallenge:
		return "Access-Challenge"
	default:
		return "Packet(" + strconv.Itoa(int(code)) + ")"
	}
}

func wipeRadiusAccessSecrets(req *RadiusAccessTestRequest) {
	if req == nil {
		return
	}
	wipeString(&req.Method.Password)
	wipeString(&req.Method.Challenge)
	wipeString(&req.Method.Response)
}

func wipeRadiusEvidence(ev *aaa.CredentialEvidence) {
	if ev == nil {
		return
	}
	ev.Password.Wipe()
	wipeBytes(ev.Challenge)
	wipeBytes(ev.Response)
}
