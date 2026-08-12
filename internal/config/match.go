package config

import (
	"net"
	"sort"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// CertIdentity is the peer certificate view used for TLS client selection.
// Empty slices mean the peer presented no SAN of that type.
type CertIdentity struct {
	DNSSANs []string
	IPSANs  []net.IP
}

// ClientIndex is an immutable dual-stack matcher compiled from enabled clients.
type ClientIndex struct {
	byID     map[string]indexClient
	warnings []string
}

type indexClient struct {
	id         string
	priority   int
	mode       domain.MatchMode
	transports []domain.Transport
	cidrs      []indexCIDR
	dns        []string
	ips        []net.IP
}

type indexCIDR struct {
	network net.IPNet
	bits    int
	v4      bool
}

type matchCandidate struct {
	id       string
	priority int
	prefix   int // -1 when CIDR is not a match key
}

// CompileClientIndex builds IPv4/IPv6 LPM input and rejects indistinguishable
// enabled clients. Disabled clients are omitted from the index.
func CompileClientIndex(clients []Client) (*ClientIndex, error) {
	idx := &ClientIndex{
		byID: make(map[string]indexClient, len(clients)),
	}
	for i, c := range clients {
		if !c.Enabled {
			continue
		}
		ic, warn, err := indexFromClient(c, i)
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

func indexFromClient(c Client, i int) (indexClient, []string, error) {
	path := indexPath("clients", i)
	if len(c.Match.Transports) == 0 {
		return indexClient{}, nil, domain.NewError(domain.CodeInvalidArgument, "at least one transport is required").WithPath(path + ".match.transports")
	}
	ic := indexClient{
		id:         c.ID,
		priority:   c.Priority,
		mode:       c.Match.Mode,
		transports: append([]domain.Transport(nil), c.Match.Transports...),
		dns:        append([]string(nil), c.Match.Certificate.DNSSANs...),
	}
	ips, err := parseStoredIPSAN(c.Match.Certificate.IPSANs, path)
	if err != nil {
		return indexClient{}, nil, err
	}
	ic.ips = ips
	var warnings []string
	if c.Match.Mode == domain.MatchCertificateOnly && len(c.Match.SourceCIDRs) > 0 {
		warnings = append(warnings, path+".match.source_cidrs is ignored when match.mode is certificate_only")
	}
	for _, s := range c.Match.SourceCIDRs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return indexClient{}, nil, domain.NewError(domain.CodeInvalidArgument, "invalid CIDR").WithPath(path + ".match.source_cidrs")
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

func parseStoredIPSAN(vals []string, path string) ([]net.IP, error) {
	out := make([]net.IP, 0, len(vals))
	for i, s := range vals {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, domain.NewError(domain.CodeInvalidArgument, "invalid IP address").WithPath(indexPath(path+".match.certificate.ip_sans", i))
		}
		out = append(out, ip)
	}
	return out, nil
}

// Warnings returns compile diagnostics that did not fail the index.
func (idx *ClientIndex) Warnings() []string {
	if idx == nil {
		return nil
	}
	return append([]string(nil), idx.warnings...)
}

// Match selects one enabled client. A remaining tie is an error, never a
// lexicographic ID pick.
func (idx *ClientIndex) Match(transport domain.Transport, ip net.IP, cert *CertIdentity) (string, error) {
	if idx == nil {
		return "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	canon, v4 := canonicalizeIP(ip)
	if canon == nil {
		return "", domain.NewError(domain.CodeInvalidArgument, "peer address is not a valid IP").WithPath("clients")
	}

	var cand []matchCandidate
	bestPrefix := -1
	for _, ic := range idx.byID {
		if !hasTransport(ic.transports, transport) {
			continue
		}
		if transport == domain.TransportTLS && !certSatisfied(ic, cert) {
			continue
		}
		if ic.mode == domain.MatchCertificateOnly {
			cand = append(cand, matchCandidate{id: ic.id, priority: ic.priority, prefix: -1})
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
	}

	var final []matchCandidate
	for _, c := range cand {
		if c.prefix < 0 || c.prefix == bestPrefix {
			final = append(final, c)
		}
	}
	if len(final) == 0 {
		return "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
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
		return "", ambiguousError(winners[0], winners[1])
	}
	return winners[0], nil
}

func canonicalizeIP(ip net.IP) (net.IP, bool) {
	if ip == nil {
		return nil, false
	}
	if v4 := ip.To4(); v4 != nil {
		return append(net.IP(nil), v4...), true
	}
	v6 := ip.To16()
	if v6 == nil {
		return nil, false
	}
	return append(net.IP(nil), v6...), false
}

func longestContaining(cidrs []indexCIDR, ip net.IP, v4 bool) (int, bool) {
	best := -1
	ok := false
	for _, c := range cidrs {
		if c.v4 != v4 {
			continue
		}
		if !c.network.Contains(ip) {
			continue
		}
		if !ok || c.bits > best {
			best = c.bits
			ok = true
		}
	}
	return best, ok
}

func hasTransport(list []domain.Transport, want domain.Transport) bool {
	for _, t := range list {
		if t == want {
			return true
		}
	}
	return false
}

func certSatisfied(ic indexClient, cert *CertIdentity) bool {
	if len(ic.dns) == 0 && len(ic.ips) == 0 {
		return true
	}
	if cert == nil {
		return false
	}
	for _, want := range ic.dns {
		for _, got := range cert.DNSSANs {
			if strings.EqualFold(want, got) {
				return true
			}
		}
	}
	for _, want := range ic.ips {
		for _, got := range cert.IPSANs {
			if want.Equal(got) {
				return true
			}
		}
	}
	return false
}

func (idx *ClientIndex) checkAmbiguity() error {
	ids := make([]string, 0, len(idx.byID))
	for id := range idx.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			a := idx.byID[ids[i]]
			b := idx.byID[ids[j]]
			if err := pairAmbiguous(a, b); err != nil {
				return err
			}
		}
	}
	return nil
}

func pairAmbiguous(a, b indexClient) error {
	if a.priority != b.priority {
		return nil
	}
	shared := sharedTransports(a.transports, b.transports)
	if len(shared) == 0 {
		return nil
	}
	for _, tr := range shared {
		if tr == domain.TransportTLS && !certsMayOverlap(a, b) {
			continue
		}
		if a.mode == domain.MatchCertificateOnly || b.mode == domain.MatchCertificateOnly {
			return ambiguousError(a.id, b.id)
		}
		if shareIdenticalCIDR(a, b) {
			return ambiguousError(a.id, b.id)
		}
	}
	return nil
}

func sharedTransports(a, b []domain.Transport) []domain.Transport {
	var out []domain.Transport
	for _, t := range a {
		if hasTransport(b, t) && !hasTransport(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func certsMayOverlap(a, b indexClient) bool {
	if len(a.dns) == 0 && len(a.ips) == 0 {
		return true
	}
	if len(b.dns) == 0 && len(b.ips) == 0 {
		return true
	}
	for _, x := range a.dns {
		for _, y := range b.dns {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	for _, x := range a.ips {
		for _, y := range b.ips {
			if x.Equal(y) {
				return true
			}
		}
	}
	return false
}

func shareIdenticalCIDR(a, b indexClient) bool {
	for _, x := range a.cidrs {
		for _, y := range b.cidrs {
			if x.v4 == y.v4 && x.bits == y.bits && x.network.IP.Equal(y.network.IP) && masksEqual(x.network.Mask, y.network.Mask) {
				return true
			}
		}
	}
	return false
}

func masksEqual(a, b net.IPMask) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ambiguousError(a, b string) error {
	ids := []string{a, b}
	sort.Strings(ids)
	return domain.NewError(domain.CodeClientMatchAmbiguous, "clients "+ids[0]+" and "+ids[1]+" are indistinguishable").
		WithPath("clients").
		WithDetail("ids", ids)
}
