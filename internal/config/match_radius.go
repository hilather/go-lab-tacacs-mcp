package config

import (
	"net"
	"sort"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// RADIUSIndex is an immutable source-IP LPM compiled for one RADIUS role.
// Certificate match modes do not apply to UDP.
type RADIUSIndex struct {
	role     domain.ListenerRole
	byID     map[string]radiusIndexClient
	warnings []string
}

type radiusIndexClient struct {
	id         string
	endpointID string
	priority   int
	cidrs      []indexCIDR
}

// CompileRADIUSIndex builds an IPv4/IPv6 LPM for enabled clients that have a
// RADIUS endpoint including role. Access and accounting indexes are independent.
// A remaining same-prefix, same-priority tie is CLIENT_MATCH_AMBIGUOUS.
func CompileRADIUSIndex(clients []Client, role domain.ListenerRole) (*RADIUSIndex, error) {
	switch role {
	case domain.RoleAccess, domain.RoleAccounting:
	default:
		return nil, domain.NewError(domain.CodeInvalidArgument, "RADIUS index role must be access or accounting")
	}
	idx := &RADIUSIndex{
		role: role,
		byID: make(map[string]radiusIndexClient, len(clients)),
	}
	for i, c := range clients {
		if !c.Enabled {
			continue
		}
		ep := radiusEndpoint(c)
		if ep == nil || !endpointHasRole(*ep, role) {
			continue
		}
		ic, err := radiusIndexFromClient(c, *ep, i)
		if err != nil {
			return nil, err
		}
		idx.byID[c.ID] = ic
	}
	if err := idx.checkAmbiguity(); err != nil {
		return nil, err
	}
	return idx, nil
}

func radiusIndexFromClient(c Client, ep ClientEndpoint, i int) (radiusIndexClient, error) {
	path := indexPath("clients", i)
	if len(c.Match.SourceCIDRs) == 0 {
		return radiusIndexClient{}, domain.NewError(domain.CodeInvalidArgument, "RADIUS clients require match.source_cidrs").WithPath(path + ".match.source_cidrs")
	}
	ic := radiusIndexClient{
		id:         c.ID,
		endpointID: ep.ID,
		priority:   c.Priority,
	}
	for _, s := range c.Match.SourceCIDRs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return radiusIndexClient{}, domain.NewError(domain.CodeInvalidArgument, "invalid CIDR").WithPath(path + ".match.source_cidrs")
		}
		ones, _ := n.Mask.Size()
		ip := n.IP
		v4 := ip.To4() != nil
		if v4 {
			ip = ip.To4()
		} else {
			ip = ip.To16()
		}
		ic.cidrs = append(ic.cidrs, indexCIDR{
			network: net.IPNet{IP: append(net.IP(nil), ip...), Mask: append(net.IPMask(nil), n.Mask...)},
			bits:    ones,
			v4:      v4,
		})
	}
	return ic, nil
}

// Role is the compiled RADIUS listener role.
func (idx *RADIUSIndex) Role() domain.ListenerRole {
	if idx == nil {
		return ""
	}
	return idx.role
}

// Warnings returns compile diagnostics that did not fail the index.
func (idx *RADIUSIndex) Warnings() []string {
	if idx == nil {
		return nil
	}
	return append([]string(nil), idx.warnings...)
}

// Match selects one enabled RADIUS client by source IP. A remaining tie is an
// error, never a lexicographic ID pick.
func (idx *RADIUSIndex) Match(ip net.IP) (clientID, endpointID string, err error) {
	if idx == nil {
		return "", "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	canon, v4 := canonicalizeIP(ip)
	if canon == nil {
		return "", "", domain.NewError(domain.CodeInvalidArgument, "peer address is not a valid IP").WithPath("clients")
	}

	var cand []matchCandidate
	bestPrefix := -1
	hits := map[string]string{}
	for _, ic := range idx.byID {
		bits, ok := longestContaining(ic.cidrs, canon, v4)
		if !ok {
			continue
		}
		if bits > bestPrefix {
			bestPrefix = bits
		}
		cand = append(cand, matchCandidate{id: ic.id, priority: ic.priority, prefix: bits})
		hits[ic.id] = ic.endpointID
	}

	var final []matchCandidate
	for _, c := range cand {
		if c.prefix == bestPrefix {
			final = append(final, c)
		}
	}
	if len(final) == 0 {
		return "", "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}

	bestPri := final[0].priority
	for _, c := range final[1:] {
		if c.priority < bestPri {
			bestPri = c.priority
		}
	}
	var winners []string
	for _, c := range final {
		if c.priority == bestPri {
			winners = append(winners, c.id)
		}
	}
	sort.Strings(winners)
	if len(winners) > 1 {
		return "", "", ambiguousError(winners[0], winners[1])
	}
	return winners[0], hits[winners[0]], nil
}

func (idx *RADIUSIndex) checkAmbiguity() error {
	ids := make([]string, 0, len(idx.byID))
	for id := range idx.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			a := idx.byID[ids[i]]
			b := idx.byID[ids[j]]
			if a.priority != b.priority {
				continue
			}
			if shareIdenticalRADIUSCIDR(a, b) {
				return ambiguousError(a.id, b.id)
			}
		}
	}
	return nil
}

func shareIdenticalRADIUSCIDR(a, b radiusIndexClient) bool {
	for _, x := range a.cidrs {
		for _, y := range b.cidrs {
			if x.v4 == y.v4 && x.bits == y.bits && x.network.IP.Equal(y.network.IP) && masksEqual(x.network.Mask, y.network.Mask) {
				return true
			}
		}
	}
	return false
}
