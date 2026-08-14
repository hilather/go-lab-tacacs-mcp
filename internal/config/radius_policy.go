package config

import (
	"encoding/hex"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func normalizeRADIUSPolicies(raw []rawRADIUSPolicy) ([]RADIUSPolicy, error) {
	out := make([]RADIUSPolicy, 0, len(raw))
	seen := map[string]struct{}{}
	for i, p := range raw {
		path := indexPath("radius_policies", i)
		if p.ID == "" {
			return nil, yamlErrorAt(path+".id", "id is required")
		}
		if _, ok := seen[p.ID]; ok {
			return nil, yamlErrorAt(path+".id", "duplicate radius policy id")
		}
		seen[p.ID] = struct{}{}
		rules, err := normalizeRADIUSRules(p.Rules, "radius_policies."+p.ID+".rules")
		if err != nil {
			return nil, err
		}
		out = append(out, RADIUSPolicy{ID: p.ID, Rules: rules})
	}
	return out, nil
}

func normalizeRADIUSRules(raw []rawRADIUSRule, path string) ([]RADIUSRule, error) {
	out := make([]RADIUSRule, 0, len(raw))
	seen := map[string]struct{}{}
	for i, r := range raw {
		p := indexPath(path, i)
		if r.ID == "" {
			return nil, yamlErrorAt(p+".id", "id is required")
		}
		idPath := strings.TrimSuffix(path, ".rules") + ".rules." + r.ID
		if _, ok := seen[r.ID]; ok {
			return nil, yamlErrorAt(idPath, "duplicate rule id")
		}
		seen[r.ID] = struct{}{}
		if r.Effect == "" {
			return nil, yamlErrorAt(idPath+".effect", "effect is required")
		}
		eff, err := domain.ParseEffect(r.Effect)
		if err != nil || (eff != domain.EffectPermit && eff != domain.EffectDeny) {
			return nil, yamlErrorAt(idPath+".effect", "effect must be permit or deny")
		}
		match, err := normalizeRADIUSMatch(r.Match, idPath+".match")
		if err != nil {
			return nil, err
		}
		out = append(out, RADIUSRule{
			ID:            r.ID,
			Enabled:       boolOr(r.Enabled, true),
			Match:         match,
			Effect:        eff,
			ReplyProfiles: copyStrings(r.ReplyProfiles),
		})
	}
	return out, nil
}

func normalizeRADIUSMatch(raw rawRADIUSMatch, path string) (RADIUSMatch, error) {
	var method *domain.AuthMethod
	if strings.TrimSpace(raw.Method) != "" {
		m, err := domain.ParseAuthMethod(raw.Method)
		if err != nil {
			return RADIUSMatch{}, yamlErrorAt(path+".method", "authentication method must be password, pap, or chap")
		}
		method = &m
	}
	attrs := make([]RADIUSAttrMatch, 0, len(raw.Attributes))
	for i, a := range raw.Attributes {
		got, err := normalizeRADIUSAttrMatch(a, indexPath(path+".attributes", i))
		if err != nil {
			return RADIUSMatch{}, err
		}
		attrs = append(attrs, got)
	}
	return RADIUSMatch{
		GroupsAny:  copyStrings(raw.GroupsAny),
		Method:     method,
		Attributes: attrs,
	}, nil
}

func normalizeRADIUSAttrMatch(raw rawRADIUSAttrMatch, path string) (RADIUSAttrMatch, error) {
	vendor, code, err := normalizeAttrIdentity(raw.Name, raw.Vendor, raw.Code, path)
	if err != nil {
		return RADIUSAttrMatch{}, err
	}
	op := strings.ToLower(strings.TrimSpace(raw.Op))
	switch op {
	case RADIUSMatchOpEquals, RADIUSMatchOpPresent, RADIUSMatchOpAbsent:
	case "":
		return RADIUSAttrMatch{}, yamlErrorAt(path+".op", "op must be equals, present, or absent")
	default:
		return RADIUSAttrMatch{}, yamlErrorAt(path+".op", "op must be equals, present, or absent")
	}
	if op != RADIUSMatchOpEquals && (raw.Value != "" || raw.ValueHex != "") {
		return RADIUSAttrMatch{}, yamlErrorAt(path, "present and absent matches must not set value")
	}
	if op == RADIUSMatchOpEquals && raw.Value == "" && raw.ValueHex == "" {
		return RADIUSAttrMatch{}, yamlErrorAt(path+".value", "equals match requires value or value_hex")
	}
	if raw.ValueHex != "" {
		if _, err := hex.DecodeString(raw.ValueHex); err != nil {
			return RADIUSAttrMatch{}, yamlErrorAt(path+".value_hex", "value_hex must be even-length hex")
		}
	}
	return RADIUSAttrMatch{
		Name:     raw.Name,
		Vendor:   vendor,
		Code:     code,
		Op:       op,
		Value:    raw.Value,
		ValueHex: raw.ValueHex,
	}, nil
}

func normalizeRADIUSReplyProfiles(raw []rawRADIUSReplyProfile) ([]RADIUSReplyProfile, error) {
	out := make([]RADIUSReplyProfile, 0, len(raw))
	seen := map[string]struct{}{}
	for i, p := range raw {
		path := indexPath("radius_reply_profiles", i)
		if p.ID == "" {
			return nil, yamlErrorAt(path+".id", "id is required")
		}
		if _, ok := seen[p.ID]; ok {
			return nil, yamlErrorAt(path+".id", "duplicate radius reply profile id")
		}
		seen[p.ID] = struct{}{}
		attrs := make([]RADIUSReplyAttr, 0, len(p.Attributes))
		for j, a := range p.Attributes {
			got, err := normalizeRADIUSReplyAttr(a, indexPath("radius_reply_profiles."+p.ID+".attributes", j))
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, got)
		}
		out = append(out, RADIUSReplyProfile{ID: p.ID, Attributes: attrs})
	}
	return out, nil
}

func normalizeRADIUSReplyAttr(raw rawRADIUSReplyAttr, path string) (RADIUSReplyAttr, error) {
	vendor, code, err := normalizeAttrIdentity(raw.Name, raw.Vendor, raw.Code, path)
	if err != nil {
		return RADIUSReplyAttr{}, err
	}
	if raw.Value == "" && raw.ValueHex == "" {
		return RADIUSReplyAttr{}, yamlErrorAt(path+".value", "reply attribute requires value or value_hex")
	}
	if raw.ValueHex != "" {
		if _, err := hex.DecodeString(raw.ValueHex); err != nil {
			return RADIUSReplyAttr{}, yamlErrorAt(path+".value_hex", "value_hex must be even-length hex")
		}
	}
	return RADIUSReplyAttr{
		Name:     raw.Name,
		Vendor:   vendor,
		Code:     code,
		Value:    raw.Value,
		ValueHex: raw.ValueHex,
	}, nil
}

func normalizeAttrIdentity(name string, vendor *uint32, code *int, path string) (uint32, uint8, error) {
	hasName := strings.TrimSpace(name) != ""
	hasCode := code != nil
	hasVendor := vendor != nil
	if !hasName && !hasCode {
		return 0, 0, yamlErrorAt(path, "attribute requires name or vendor+code")
	}
	if hasVendor && !hasCode {
		return 0, 0, yamlErrorAt(path+".code", "vendor requires code")
	}
	var v uint32
	if hasVendor {
		v = *vendor
	}
	var c uint8
	if hasCode {
		if *code < 0 || *code > 255 {
			return 0, 0, yamlErrorAt(path+".code", "code must be 0-255")
		}
		if *code == 0 {
			return 0, 0, yamlErrorAt(path+".code", "code must be 1-255")
		}
		c = uint8(*code)
	}
	return v, c, nil
}

func validateRADIUSPolicyRefs(doc *Document, groups map[string]struct{}) error {
	policies := make(map[string]struct{}, len(doc.RADIUSPolicies))
	for i, p := range doc.RADIUSPolicies {
		if p.ID == "" {
			return domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath(indexPath("radius_policies", i) + ".id")
		}
		if _, ok := policies[p.ID]; ok {
			return domain.NewError(domain.CodeInvalidArgument, "duplicate radius policy id").WithPath("radius_policies." + p.ID)
		}
		policies[p.ID] = struct{}{}
		if err := validateRADIUSRules(p, groups, doc); err != nil {
			return err
		}
	}
	profiles := make(map[string]struct{}, len(doc.RADIUSReplyProfiles))
	for i, p := range doc.RADIUSReplyProfiles {
		if p.ID == "" {
			return domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath(indexPath("radius_reply_profiles", i) + ".id")
		}
		if _, ok := profiles[p.ID]; ok {
			return domain.NewError(domain.CodeInvalidArgument, "duplicate radius reply profile id").WithPath("radius_reply_profiles." + p.ID)
		}
		profiles[p.ID] = struct{}{}
	}
	if id := doc.FallbackRADIUSPolicyID; id != "" {
		if _, ok := policies[id]; !ok {
			return domain.NewError(domain.CodeNotFound, "fallback_radius_policy_id does not exist").WithPath("fallback_radius_policy_id")
		}
	}
	for i, c := range doc.Clients {
		ep := radiusEndpoint(c)
		if ep == nil || ep.RADIUS == nil {
			continue
		}
		id := ep.RADIUS.AccessPolicyID
		if id == "" {
			continue
		}
		if _, ok := policies[id]; !ok {
			return domain.NewError(domain.CodeNotFound, "access_policy_id does not exist").
				WithPath(indexPath("clients", i) + ".endpoints." + ep.ID + ".radius.access_policy_id")
		}
	}
	for _, p := range doc.RADIUSPolicies {
		for _, r := range p.Rules {
			base := "radius_policies." + p.ID + ".rules." + r.ID
			for j, pid := range r.ReplyProfiles {
				if pid == "" {
					return domain.NewError(domain.CodeInvalidArgument, "reply profile id is required").
						WithPath(indexPath(base+".reply_profiles", j))
				}
				if _, ok := profiles[pid]; !ok {
					return domain.NewError(domain.CodeNotFound, "reply profile does not exist").
						WithPath(indexPath(base+".reply_profiles", j))
				}
			}
		}
	}
	return nil
}

func validateRADIUSRules(p RADIUSPolicy, groups map[string]struct{}, _ *Document) error {
	seen := map[string]struct{}{}
	for _, r := range p.Rules {
		base := "radius_policies." + p.ID + ".rules." + r.ID
		if r.ID == "" {
			return domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath("radius_policies." + p.ID + ".rules")
		}
		if _, ok := seen[r.ID]; ok {
			return domain.NewError(domain.CodeInvalidArgument, "duplicate rule id").WithPath(base)
		}
		seen[r.ID] = struct{}{}
		if r.Effect != domain.EffectPermit && r.Effect != domain.EffectDeny {
			return domain.NewError(domain.CodeInvalidArgument, "effect must be permit or deny").WithPath(base + ".effect")
		}
		if r.Match.Method != nil && !r.Match.Method.Valid() {
			return domain.NewError(domain.CodeInvalidArgument, "authentication method must be password, pap, or chap").
				WithPath(base + ".match.method")
		}
		for i, g := range r.Match.GroupsAny {
			if g == "" {
				return domain.NewError(domain.CodeInvalidArgument, "group id is required").
					WithPath(indexPath(base+".match.groups_any", i))
			}
			if _, ok := groups[g]; !ok {
				return domain.NewError(domain.CodeGroupNotFound, "group does not exist").
					WithPath(indexPath(base+".match.groups_any", i))
			}
		}
		for i, a := range r.Match.Attributes {
			switch a.Op {
			case RADIUSMatchOpEquals, RADIUSMatchOpPresent, RADIUSMatchOpAbsent:
			default:
				return domain.NewError(domain.CodeInvalidArgument, "op must be equals, present, or absent").
					WithPath(indexPath(base+".match.attributes", i) + ".op")
			}
		}
	}
	return nil
}
