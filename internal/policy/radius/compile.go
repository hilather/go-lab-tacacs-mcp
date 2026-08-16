package radius

import (
	"encoding/hex"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Input is the snapshot-time compile source. YAML syntax types are not used.
type Input struct {
	Policies      []config.RADIUSPolicy
	ReplyProfiles []config.RADIUSReplyProfile
	FallbackID    string
	Clients       []config.Client
	Users         []config.User
	Groups        []config.Group
}

// Engine is an immutable compiled RADIUS access policy.
type Engine struct {
	policies map[string]compiledPolicy
	clients  map[string]compiledClient
	users    map[string]compiledUser
	groups   map[string]compiledGroup
	fallback string
}

type compiledClient struct {
	endpointID      string
	policyID        string
	defaultGroupIDs []string
}

type compiledUser struct {
	id       string
	enabled  bool
	groupIDs []string
	policyID string
}

type compiledGroup struct {
	id       string
	enabled  bool
	priority int
	policyID string
}

type compiledPolicy struct {
	id    string
	rules []compiledRule
}

type compiledRule struct {
	id     string
	match  compiledMatch
	effect domain.Effect
	reply  TypedSet
}

type compiledMatch struct {
	groupsAny []string
	method    *domain.AuthMethod
	attrs     []compiledAttrMatch
}

type compiledAttrMatch struct {
	key    AttrKey
	label  string
	op     string
	equals Typed
}

// CompileDocument compiles RADIUS policies from a normalized document.
func CompileDocument(doc *config.Document) (*Engine, error) {
	if doc == nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "document is required")
	}
	return Compile(Input{
		Policies:      doc.RADIUSPolicies,
		ReplyProfiles: doc.RADIUSReplyProfiles,
		FallbackID:    doc.FallbackRADIUSPolicyID,
		Clients:       doc.Clients,
		Users:         doc.Users,
		Groups:        doc.Groups,
	})
}

// Compile builds first-match lists and reply-profile merges. Dictionary
// lookups happen here, never per request.
func Compile(in Input) (*Engine, error) {
	profiles, err := compileReplyProfiles(in.ReplyProfiles)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		policies: make(map[string]compiledPolicy, len(in.Policies)),
		clients:  make(map[string]compiledClient, len(in.Clients)),
		users:    make(map[string]compiledUser, len(in.Users)),
		groups:   make(map[string]compiledGroup, len(in.Groups)),
	}
	for _, p := range in.Policies {
		cp, err := compilePolicy(p, profiles)
		if err != nil {
			return nil, err
		}
		if _, ok := e.policies[p.ID]; ok {
			return nil, domain.NewError(domain.CodeConfigYAMLInvalid, "duplicate radius policy id").
				WithPath("radius_policies." + p.ID)
		}
		e.policies[p.ID] = cp
	}
	if in.FallbackID != "" {
		if _, ok := e.policies[in.FallbackID]; !ok {
			return nil, domain.NewError(domain.CodeNotFound, "fallback_radius_policy_id does not exist").
				WithPath("fallback_radius_policy_id")
		}
		e.fallback = in.FallbackID
	}
	for _, c := range in.Clients {
		if !c.Enabled {
			continue
		}
		for _, ep := range c.Endpoints {
			if ep.Protocol != domain.ProtocolRADIUS || ep.RADIUS == nil {
				continue
			}
			pid := ep.RADIUS.AccessPolicyID
			if pid != "" {
				if _, ok := e.policies[pid]; !ok {
					return nil, domain.NewError(domain.CodeNotFound, "access_policy_id does not exist").
						WithPath("radius_policies." + pid)
				}
			}
			e.clients[c.ID] = compiledClient{
				endpointID:      ep.ID,
				policyID:        pid,
				defaultGroupIDs: append([]string(nil), c.Authorization.DefaultGroupIDs...),
			}
		}
	}
	for _, g := range in.Groups {
		if g.RADIUSPolicyID != "" {
			if _, ok := e.policies[g.RADIUSPolicyID]; !ok {
				return nil, domain.NewError(domain.CodeConfigYAMLInvalid, "radius_policy_id does not exist").
					WithPath("groups." + g.ID + ".radius_policy_id")
			}
		}
		e.groups[g.ID] = compiledGroup{
			id:       g.ID,
			enabled:  g.Enabled,
			priority: g.Priority,
			policyID: g.RADIUSPolicyID,
		}
	}
	for _, u := range in.Users {
		if u.RADIUSPolicyID != "" {
			if _, ok := e.policies[u.RADIUSPolicyID]; !ok {
				return nil, domain.NewError(domain.CodeConfigYAMLInvalid, "radius_policy_id does not exist").
					WithPath("users." + u.ID + ".radius_policy_id")
			}
		}
		e.users[u.ID] = compiledUser{
			id:       u.ID,
			enabled:  u.Enabled,
			groupIDs: append([]string(nil), u.GroupIDs...),
			policyID: u.RADIUSPolicyID,
		}
	}
	return e, nil
}

// effectiveGroups matches policy/compile.go: user group_ids in listed
// order, then client default_group_ids not already present, then sort
// by ascending group priority then id. Disabled groups are omitted.
func (e *Engine) effectiveGroups(userID, clientID string) []compiledGroup {
	ids := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)
	if u, ok := e.users[userID]; ok && u.enabled {
		for _, id := range u.groupIDs {
			if id == "" {
				continue
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	if c, ok := e.clients[clientID]; ok {
		for _, id := range c.defaultGroupIDs {
			if id == "" {
				continue
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	out := make([]compiledGroup, 0, len(ids))
	for _, id := range ids {
		g, ok := e.groups[id]
		if !ok || !g.enabled {
			continue
		}
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].priority != out[j].priority {
			return out[i].priority < out[j].priority
		}
		return out[i].id < out[j].id
	})
	return out
}

func compilePolicy(p config.RADIUSPolicy, profiles map[string]compiledProfile) (compiledPolicy, error) {
	out := compiledPolicy{id: p.ID, rules: make([]compiledRule, 0, len(p.Rules))}
	seen := map[string]struct{}{}
	for _, r := range p.Rules {
		if !r.Enabled {
			continue
		}
		base := "radius_policies." + p.ID + ".rules." + r.ID
		if r.ID == "" {
			return compiledPolicy{}, domain.NewError(domain.CodeConfigYAMLInvalid, "id is required").WithPath(base)
		}
		if _, ok := seen[r.ID]; ok {
			return compiledPolicy{}, domain.NewError(domain.CodeConfigYAMLInvalid, "duplicate rule id").WithPath(base)
		}
		seen[r.ID] = struct{}{}
		if r.Effect != domain.EffectPermit && r.Effect != domain.EffectDeny {
			return compiledPolicy{}, domain.NewError(domain.CodeConfigYAMLInvalid, "effect must be permit or deny").
				WithPath(base + ".effect")
		}
		match, err := compileMatch(r.Match, base+".match")
		if err != nil {
			return compiledPolicy{}, err
		}
		reply, err := mergeReplyProfiles(r.Effect, r.ReplyProfiles, profiles, base)
		if err != nil {
			return compiledPolicy{}, err
		}
		out.rules = append(out.rules, compiledRule{
			id:     r.ID,
			match:  match,
			effect: r.Effect,
			reply:  reply,
		})
	}
	return out, nil
}

func compileMatch(m config.RADIUSMatch, path string) (compiledMatch, error) {
	out := compiledMatch{
		groupsAny: append([]string(nil), m.GroupsAny...),
		attrs:     make([]compiledAttrMatch, 0, len(m.Attributes)),
	}
	if m.Method != nil {
		if !m.Method.Valid() {
			return compiledMatch{}, domain.NewError(domain.CodeConfigYAMLInvalid, "authentication method must be password, pap, chap, mschapv1, mschapv2, or eap").
				WithPath(path + ".method")
		}
		v := *m.Method
		out.method = &v
	}
	for i, a := range m.Attributes {
		got, err := compileAttrMatch(a, indexPath(path+".attributes", i))
		if err != nil {
			return compiledMatch{}, err
		}
		out.attrs = append(out.attrs, got)
	}
	return out, nil
}

func compileAttrMatch(a config.RADIUSAttrMatch, path string) (compiledAttrMatch, error) {
	def, key, err := resolveAttr(a.Name, a.Vendor, a.Code, path)
	if err != nil {
		return compiledAttrMatch{}, err
	}
	if def.Secret || def.Name == "Message-Authenticator" {
		return compiledAttrMatch{}, domain.NewError(domain.CodeConfigYAMLInvalid, "attribute is not a named policy match key").
			WithPath(path)
	}
	if !def.allowReq && a.Vendor == 0 {
		return compiledAttrMatch{}, domain.NewError(domain.CodeConfigYAMLInvalid, "attribute is not legal as an Access-Request match key").
			WithPath(path)
	}
	label := key.Name
	if label == "" {
		label = attrLabel(key)
	}
	out := compiledAttrMatch{key: key, label: label, op: a.Op}
	switch a.Op {
	case config.RADIUSMatchOpPresent, config.RADIUSMatchOpAbsent:
		if a.Value != "" || a.ValueHex != "" {
			return compiledAttrMatch{}, domain.NewError(domain.CodeConfigYAMLInvalid, "present and absent matches must not set value").
				WithPath(path)
		}
		return out, nil
	case config.RADIUSMatchOpEquals:
		tv, err := parseTypedValue(def, key, a.Value, a.ValueHex, path)
		if err != nil {
			return compiledAttrMatch{}, err
		}
		out.equals = tv
		return out, nil
	default:
		return compiledAttrMatch{}, domain.NewError(domain.CodeConfigYAMLInvalid, "op must be equals, present, or absent").
			WithPath(path + ".op")
	}
}

type compiledProfile struct {
	id    string
	attrs []compiledReplyAttr
}

type compiledReplyAttr struct {
	def  attrDef
	key  AttrKey
	attr Typed
}

func compileReplyProfiles(in []config.RADIUSReplyProfile) (map[string]compiledProfile, error) {
	out := make(map[string]compiledProfile, len(in))
	for _, p := range in {
		path := "radius_reply_profiles." + p.ID
		attrs := make([]compiledReplyAttr, 0, len(p.Attributes))
		for i, a := range p.Attributes {
			got, err := compileReplyAttr(a, indexPath(path+".attributes", i))
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, got)
		}
		out[p.ID] = compiledProfile{id: p.ID, attrs: attrs}
	}
	return out, nil
}

func compileReplyAttr(a config.RADIUSReplyAttr, path string) (compiledReplyAttr, error) {
	def, key, err := resolveAttr(a.Name, a.Vendor, a.Code, path)
	if err != nil {
		return compiledReplyAttr{}, err
	}
	if def.Secret || def.ServerOwned {
		return compiledReplyAttr{}, domain.NewError(domain.CodeConfigYAMLInvalid, "attribute is not a policy reply attribute").
			WithPath(path)
	}
	tv, err := parseTypedValue(def, key, a.Value, a.ValueHex, path)
	if err != nil {
		return compiledReplyAttr{}, err
	}
	return compiledReplyAttr{def: def, key: key, attr: tv}, nil
}

func mergeReplyProfiles(effect domain.Effect, ids []string, profiles map[string]compiledProfile, rulePath string) (TypedSet, error) {
	if len(ids) == 0 {
		return TypedSet{}, nil
	}
	packet := packetAccessAccept
	if effect == domain.EffectDeny {
		packet = packetAccessReject
	}
	out := make(TypedSet, 0)
	seenSingle := map[AttrKey]string{}
	for i, id := range ids {
		p, ok := profiles[id]
		if !ok {
			return nil, domain.NewError(domain.CodeNotFound, "reply profile does not exist").
				WithPath(indexPath(rulePath+".reply_profiles", i))
		}
		for _, a := range p.attrs {
			if packet == packetAccessAccept && !a.def.allowAccept && a.key.Vendor == 0 {
				return nil, domain.NewError(domain.CodeConfigYAMLInvalid, "attribute is not legal in Access-Accept").
					WithPath(rulePath + ".reply_profiles")
			}
			// Deny replies are Reply-Message only. Raw VSAs (vendor != 0)
			// skip IETF role bits on Accept; they must not slip through here.
			if packet == packetAccessReject && (a.key.Vendor != 0 || !a.def.allowReject) {
				return nil, domain.NewError(domain.CodeConfigYAMLInvalid, "deny rules may include only Access-Reject attributes (Reply-Message)").
					WithPath(rulePath + ".reply_profiles")
			}
			if a.def.Cardinality == CardinalitySingle {
				if prev, ok := seenSingle[a.key]; ok {
					return nil, domain.NewError(domain.CodeConfigYAMLInvalid, "duplicate single-cardinality attribute "+a.key.Name+" from profiles "+prev+" and "+id).
						WithPath(rulePath + ".reply_profiles")
				}
				seenSingle[a.key] = id
			}
			out = append(out, a.attr)
		}
	}
	return out, nil
}

func resolveAttr(name string, vendor uint32, code uint8, path string) (attrDef, AttrKey, error) {
	name = strings.TrimSpace(name)
	if vendor != 0 {
		if code == 0 {
			return attrDef{}, AttrKey{}, domain.NewError(domain.CodeConfigYAMLInvalid, "vendor requires code").WithPath(path + ".code")
		}
		if name != "" && name != "Vendor-Specific" {
			return attrDef{}, AttrKey{}, domain.NewError(domain.CodeConfigYAMLInvalid, "named Cisco-AVPair and other named VSAs are not accepted").
				WithPath(path + ".name")
		}
		def, _ := builtinDict.lookupName("Vendor-Specific")
		return def, AttrKey{Vendor: vendor, Code: code, Name: "Vendor-Specific"}, nil
	}
	if name != "" {
		def, ok := builtinDict.lookupName(name)
		if !ok {
			return attrDef{}, AttrKey{}, domain.NewError(domain.CodeConfigYAMLInvalid, "unknown RADIUS attribute name").
				WithPath(path + ".name")
		}
		if def.Kind == KindVSA && code == 0 {
			return attrDef{}, AttrKey{}, domain.NewError(domain.CodeConfigYAMLInvalid, "raw VSA requires vendor and code").
				WithPath(path)
		}
		if code != 0 && code != def.Code {
			return attrDef{}, AttrKey{}, domain.NewError(domain.CodeConfigYAMLInvalid, "attribute name and code disagree").
				WithPath(path)
		}
		return def, def.key(), nil
	}
	if code == 0 {
		return attrDef{}, AttrKey{}, domain.NewError(domain.CodeConfigYAMLInvalid, "attribute requires name or vendor+code").
			WithPath(path)
	}
	def, ok := builtinDict.lookupCode(code)
	if !ok {
		return attrDef{}, AttrKey{}, domain.NewError(domain.CodeConfigYAMLInvalid, "unknown RADIUS attribute code").
			WithPath(path + ".code")
	}
	return def, def.key(), nil
}

func parseTypedValue(def attrDef, key AttrKey, value, valueHex, path string) (Typed, error) {
	out := Typed{Key: key, Kind: def.Kind}
	if def.Kind == KindVSA || key.Vendor != 0 {
		if valueHex == "" {
			return Typed{}, domain.NewError(domain.CodeConfigYAMLInvalid, "raw VSA requires value_hex").
				WithPath(path + ".value_hex")
		}
		b, err := hex.DecodeString(valueHex)
		if err != nil {
			return Typed{}, domain.NewError(domain.CodeConfigYAMLInvalid, "value_hex must be even-length hex").
				WithPath(path + ".value_hex")
		}
		out.Kind = KindVSA
		out.Raw = b
		return out, nil
	}
	switch def.Kind {
	case KindInteger, KindTime:
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
		if err != nil {
			return Typed{}, domain.NewError(domain.CodeConfigYAMLInvalid, "value must be an unsigned 32-bit integer").
				WithPath(path + ".value")
		}
		out.Uint = uint32(n)
	case KindIPv4:
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !addr.Is4() {
			return Typed{}, domain.NewError(domain.CodeConfigYAMLInvalid, "value must be an IPv4 address").
				WithPath(path + ".value")
		}
		out.Addr = addr
	case KindIPv6:
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !addr.Is6() {
			return Typed{}, domain.NewError(domain.CodeConfigYAMLInvalid, "value must be an IPv6 address").
				WithPath(path + ".value")
		}
		out.Addr = addr
	case KindText:
		if valueHex != "" {
			return Typed{}, domain.NewError(domain.CodeConfigYAMLInvalid, "text attributes use value, not value_hex").
				WithPath(path + ".value_hex")
		}
		out.Text = value
	case KindString:
		if valueHex != "" {
			b, err := hex.DecodeString(valueHex)
			if err != nil {
				return Typed{}, domain.NewError(domain.CodeConfigYAMLInvalid, "value_hex must be even-length hex").
					WithPath(path + ".value_hex")
			}
			out.Raw = b
		} else {
			out.Raw = []byte(value)
		}
	default:
		return Typed{}, domain.NewError(domain.CodeConfigYAMLInvalid, "unsupported attribute kind").WithPath(path)
	}
	return out, nil
}

func attrLabel(k AttrKey) string {
	if k.Name != "" {
		return k.Name
	}
	if k.Vendor != 0 {
		return "vsa:" + strconv.FormatUint(uint64(k.Vendor), 10) + ":" + strconv.Itoa(int(k.Code))
	}
	return "type:" + strconv.Itoa(int(k.Code))
}

func indexPath(parent string, i int) string {
	return parent + "[" + strconv.Itoa(i) + "]"
}
