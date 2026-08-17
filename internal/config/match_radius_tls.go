package config

import (
	"net"
	"sort"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// RADIUSCertIndex is an immutable cert matcher compiled for one RADIUS TLS role.
type RADIUSCertIndex struct {
	role     domain.ListenerRole
	byID     map[string]radiusCertClient
	warnings []string
}

type radiusCertClient struct {
	id         string
	endpointID string
	priority   int
	mode       domain.MatchMode
	cidrs      []indexCIDR
	dns        []string
	ips        []net.IP
}

// CompileRADIUSCertIndex builds a RadSec client matcher for enabled clients
// that have a RADIUS TLS endpoint including role.
func CompileRADIUSCertIndex(clients []Client, role domain.ListenerRole) (*RADIUSCertIndex, error) {
	switch role {
	case domain.RoleAccess, domain.RoleAccounting:
	default:
		return nil, domain.NewError(domain.CodeInvalidArgument, "RADIUS cert index role must be access or accounting")
	}
	idx := &RADIUSCertIndex{
		role: role,
		byID: make(map[string]radiusCertClient, len(clients)),
	}
	for i, c := range clients {
		if !c.Enabled {
			continue
		}
		ep := radiusEndpoint(c, EndpointTransportTLS)
		if ep == nil || !endpointHasRole(*ep, role) {
			continue
		}
		ic, warn, err := radiusCertFromClient(c, *ep, i)
		if err != nil {
			return nil, err
		}
		idx.byID[c.ID] = ic
		idx.warnings = append(idx.warnings, warn...)
	}
	if err := idx.checkAmbiguity(); err != nil {
		return nil, err
	}
	return idx, nil
}

func radiusCertFromClient(c Client, ep ClientEndpoint, i int) (radiusCertClient, []string, error) {
	path := indexPath("clients", i)
	mode := c.Match.Mode
	if mode == "" {
		mode = domain.MatchAddressAndCertificate
	}
	if mode == domain.MatchAddressAndCertificate && len(c.Match.SourceCIDRs) == 0 {
		return radiusCertClient{}, nil, domain.NewError(domain.CodeInvalidArgument, "RADIUS clients with address_and_certificate require match.source_cidrs").WithPath(path + ".match.source_cidrs")
	}
	ic := radiusCertClient{
		id:         c.ID,
		endpointID: ep.ID,
		priority:   c.Priority,
		mode:       mode,
		dns:        append([]string(nil), c.Match.Certificate.DNSSANs...),
	}
	ips, err := parseStoredIPSAN(c.Match.Certificate.IPSANs, path)
	if err != nil {
		return radiusCertClient{}, nil, err
	}
	ic.ips = ips
	var warnings []string
	if mode == domain.MatchCertificateOnly && len(c.Match.SourceCIDRs) > 0 {
		warnings = append(warnings, path+".match.source_cidrs is ignored when match.mode is certificate_only")
	}
	for _, s := range c.Match.SourceCIDRs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return radiusCertClient{}, nil, domain.NewError(domain.CodeInvalidArgument, "invalid CIDR").WithPath(path + ".match.source_cidrs")
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
	return ic, warnings, nil
}

// Role is the compiled RADIUS TLS listener role.
func (idx *RADIUSCertIndex) Role() domain.ListenerRole {
	if idx == nil {
		return ""
	}
	return idx.role
}

// Warnings returns compile diagnostics that did not fail the index.
func (idx *RADIUSCertIndex) Warnings() []string {
	if idx == nil {
		return nil
	}
	return append([]string(nil), idx.warnings...)
}

// Match selects one enabled RADIUS TLS client after the handshake.
// cert is required. TCP peer IP is used only for address_and_certificate.
func (idx *RADIUSCertIndex) Match(ip net.IP, cert *CertIdentity) (clientID, endpointID string, err error) {
	if idx == nil {
		return "", "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	if cert == nil || (len(cert.DNSSANs) == 0 && len(cert.IPSANs) == 0 && !idx.hasUnconstrained()) {
		return "", "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}

	var cand []matchCandidate
	bestPrefix := -1
	hits := map[string]string{}
	for _, ic := range idx.byID {
		if !radiusCertSatisfied(ic, cert) {
			continue
		}
		if ic.mode == domain.MatchCertificateOnly {
			cand = append(cand, matchCandidate{id: ic.id, priority: ic.priority, prefix: -1})
			hits[ic.id] = ic.endpointID
			continue
		}
		canon, v4 := canonicalizeIP(ip)
		if canon == nil {
			continue
		}
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
		if c.prefix < 0 || c.prefix == bestPrefix {
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

func (idx *RADIUSCertIndex) hasUnconstrained() bool {
	for _, ic := range idx.byID {
		if len(ic.dns) == 0 && len(ic.ips) == 0 {
			return true
		}
	}
	return false
}

func radiusCertSatisfied(ic radiusCertClient, cert *CertIdentity) bool {
	if len(ic.dns) == 0 && len(ic.ips) == 0 {
		return cert != nil
	}
	return certSatisfied(indexClient{dns: ic.dns, ips: ic.ips}, cert)
}

func (idx *RADIUSCertIndex) checkAmbiguity() error {
	ids := make([]string, 0, len(idx.byID))
	for id := range idx.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			a := idx.byID[ids[i]]
			b := idx.byID[ids[j]]
			if err := radiusCertPairAmbiguous(a, b); err != nil {
				return err
			}
		}
	}
	return nil
}

func radiusCertPairAmbiguous(a, b radiusCertClient) error {
	if a.priority != b.priority {
		return nil
	}
	if !radiusCertsMayOverlap(a, b) {
		return nil
	}
	if a.mode == domain.MatchCertificateOnly || b.mode == domain.MatchCertificateOnly {
		return ambiguousError(a.id, b.id)
	}
	if shareIdenticalRADIUSCIDR(radiusIndexClient{cidrs: a.cidrs}, radiusIndexClient{cidrs: b.cidrs}) {
		return ambiguousError(a.id, b.id)
	}
	return nil
}

func radiusCertsMayOverlap(a, b radiusCertClient) bool {
	return certsMayOverlap(indexClient{dns: a.dns, ips: a.ips}, indexClient{dns: b.dns, ips: b.ips})
}
