package policy

import (
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Input is the snapshot-time compile source. YAML syntax types are not used.
type Input struct {
	Users    []config.User
	Groups   []config.Group
	Clients  []config.Client
	Fallback config.RuleSet
	Limits   config.Limits
	Now      func() time.Time
}

// Engine is an immutable compiled policy. Matchers are built once.
type Engine struct {
	users    map[string]compiledUser
	groups   map[string]compiledGroup
	clients  map[string]compiledClient
	fallback compiledRuleSet
	limits   limits
	now      func() time.Time
}

type limits struct {
	maxArgs       int
	maxArgBytes   int
	maxCmdBytes   int
	maxTraceSteps int
}

type compiledUser struct {
	id          string
	enabled     bool
	groupIDs    []string
	rules       compiledRuleSet
	clientIDs   []string
	validAfter  *time.Time
	validBefore *time.Time
}

type compiledGroup struct {
	id       string
	enabled  bool
	priority int
	rules    compiledRuleSet
}

type compiledClient struct {
	id              string
	enabled         bool
	defaultGroupIDs []string
}

type compiledRuleSet struct {
	services []compiledService
	commands []compiledCommand
}

type compiledService struct {
	id       string
	service  string
	protocol *string
	action   domain.AuthorDecision
	reply    domain.AVPairs
}

type compiledCommand struct {
	id       string
	priority int
	action   domain.AuthorDecision
	command  matcher
	args     matcher
	reason   string
}

type matcher struct {
	exact   string
	pattern *regexp.Regexp
}

func (m matcher) match(s string) bool {
	if m.pattern != nil {
		return m.pattern.MatchString(s)
	}
	return m.exact == s
}

// CompileDocument compiles users, groups, clients, and fallback from a
// normalized document.
func CompileDocument(doc *config.Document) (*Engine, error) {
	if doc == nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "document is required")
	}
	return Compile(Input{
		Users:    doc.Users,
		Groups:   doc.Groups,
		Clients:  doc.Clients,
		Fallback: doc.FallbackRules,
		Limits:   doc.Limits,
	})
}

// Compile builds RE2 matchers and sorted first-match lists.
func Compile(in Input) (*Engine, error) {
	e := &Engine{
		users:   make(map[string]compiledUser, len(in.Users)),
		groups:  make(map[string]compiledGroup, len(in.Groups)),
		clients: make(map[string]compiledClient, len(in.Clients)),
		limits:  compileLimits(in.Limits),
		now:     in.Now,
	}
	if e.now == nil {
		e.now = func() time.Time { return time.Time{} }
	}
	for i, g := range in.Groups {
		rules, err := compileRuleSet(config.RuleSet{Services: g.Services, CommandRules: g.CommandRules}, "groups["+strconv.Itoa(i)+"]")
		if err != nil {
			return nil, err
		}
		e.groups[g.ID] = compiledGroup{
			id:       g.ID,
			enabled:  g.Enabled,
			priority: g.Priority,
			rules:    rules,
		}
	}
	for i, u := range in.Users {
		rules, err := compileRuleSet(u.Rules, "users["+strconv.Itoa(i)+"].rules")
		if err != nil {
			return nil, err
		}
		e.users[u.ID] = compiledUser{
			id:          u.ID,
			enabled:     u.Enabled,
			groupIDs:    append([]string(nil), u.GroupIDs...),
			rules:       rules,
			clientIDs:   append([]string(nil), u.Restrictions.ClientIDs...),
			validAfter:  u.Restrictions.ValidAfter,
			validBefore: u.Restrictions.ValidBefore,
		}
	}
	for _, c := range in.Clients {
		e.clients[c.ID] = compiledClient{
			id:              c.ID,
			enabled:         c.Enabled,
			defaultGroupIDs: append([]string(nil), c.Authorization.DefaultGroupIDs...),
		}
	}
	fb, err := compileRuleSet(in.Fallback, "fallback_rules")
	if err != nil {
		return nil, err
	}
	e.fallback = fb
	return e, nil
}

func compileLimits(l config.Limits) limits {
	out := limits{
		maxArgs:       l.MaxAuthorizationArguments,
		maxArgBytes:   l.MaxArgumentBytes,
		maxCmdBytes:   l.MaxCommandBytes,
		maxTraceSteps: l.MaxPolicyTraceSteps,
	}
	if out.maxArgs <= 0 {
		out.maxArgs = 256
	}
	if out.maxArgBytes <= 0 {
		out.maxArgBytes = 65535
	}
	if out.maxCmdBytes <= 0 {
		out.maxCmdBytes = 65535
	}
	if out.maxTraceSteps <= 0 {
		out.maxTraceSteps = 1000
	}
	return out
}

func compileRuleSet(rs config.RuleSet, path string) (compiledRuleSet, error) {
	out := compiledRuleSet{}
	for i, r := range rs.Services {
		reply, err := compileReply(r.ReplyAttributes, path+".services["+strconv.Itoa(i)+"].reply_attributes")
		if err != nil {
			return compiledRuleSet{}, err
		}
		var proto *string
		if r.Protocol != nil {
			v := *r.Protocol
			proto = &v
		}
		out.services = append(out.services, compiledService{
			id:       "services[" + strconv.Itoa(i) + "]",
			service:  r.Service,
			protocol: proto,
			action:   r.Action,
			reply:    reply,
		})
	}
	for i, r := range rs.CommandRules {
		cmd, err := compileMatcher(r.Command, path+".command_rules["+strconv.Itoa(i)+"].command")
		if err != nil {
			return compiledRuleSet{}, err
		}
		args, err := compileMatcher(r.Arguments, path+".command_rules["+strconv.Itoa(i)+"].arguments")
		if err != nil {
			return compiledRuleSet{}, err
		}
		out.commands = append(out.commands, compiledCommand{
			id:       r.ID,
			priority: r.Priority,
			action:   r.Action,
			command:  cmd,
			args:     args,
			reason:   r.Reason,
		})
	}
	sort.SliceStable(out.commands, func(i, j int) bool {
		if out.commands[i].priority != out.commands[j].priority {
			return out.commands[i].priority < out.commands[j].priority
		}
		return out.commands[i].id < out.commands[j].id
	})
	return out, nil
}

func compileMatcher(m config.StringMatch, path string) (matcher, error) {
	if m.Pattern != "" {
		re, err := regexp.Compile(m.Pattern)
		if err != nil {
			return matcher{}, domain.NewError(domain.CodeRegexInvalid, "invalid regular expression").WithPath(path + ".pattern")
		}
		return matcher{pattern: re}, nil
	}
	return matcher{exact: m.Exact}, nil
}

func compileReply(in domain.AVPairs, path string) (domain.AVPairs, error) {
	if len(in) == 0 {
		return domain.AVPairs{}, nil
	}
	out := make(domain.AVPairs, 0, len(in))
	for i, p := range in {
		if err := ValidatePair(p); err != nil {
			return nil, domain.NewError(domain.CodeInvalidArgument, "invalid reply attribute").WithPath(path + "[" + strconv.Itoa(i) + "]")
		}
		out = append(out, p)
	}
	return out, nil
}

// effectiveGroups: user.group_ids in listed order, then client
// default_group_ids not already present. Walk order is group priority then id.
func (e *Engine) effectiveGroups(u compiledUser, clientID string) []compiledGroup {
	ids := make([]string, 0, len(u.groupIDs)+4)
	seen := make(map[string]struct{}, len(u.groupIDs)+4)
	for _, id := range u.groupIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if c, ok := e.clients[clientID]; ok && c.enabled {
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
