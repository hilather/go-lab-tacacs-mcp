package observability

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Labels is a bounded set of metric dimensions.
type Labels map[string]string

// Registry is a process-local Prometheus registry.
type Registry struct {
	mu           sync.Mutex
	counters     map[string]*labeledCounter
	gauges       map[string]*labeledGauge
	histograms   map[string]*labeledHistogram
	dropped      atomic.Uint64
	maxClientIDs int
	clientIDs    map[string]struct{}
}

type labeledCounter struct {
	help   string
	series map[string]*counter
}

type labeledGauge struct {
	help   string
	series map[string]*gauge
}

type labeledHistogram struct {
	help    string
	buckets []float64
	series  map[string]*histogram
}

type counter struct {
	v atomic.Uint64
}

type gauge struct {
	v atomic.Uint64 // float64 bits
}

type histogram struct {
	mu     sync.Mutex
	count  uint64
	sum    float64
	bucket []uint64
}

// defaultHistogramBuckets are coarse enough for lab latency.
var defaultHistogramBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

const defaultMaxClientIDs = 256

// NewRegistry constructs an empty registry with required series pre-declared.
func NewRegistry() *Registry {
	r := &Registry{
		counters:     map[string]*labeledCounter{},
		gauges:       map[string]*labeledGauge{},
		histograms:   map[string]*labeledHistogram{},
		maxClientIDs: defaultMaxClientIDs,
		clientIDs:    map[string]struct{}{},
	}
	r.declare()
	return r
}

func (r *Registry) declare() {
	r.mustGauge(MetricConnectionsActive, "Active TACACS connections.")
	r.mustCounter(MetricConnectionsAccepted, "Accepted TACACS connections.")
	r.mustCounter(MetricConnectionsRejected, "Rejected TACACS connections.")
	r.mustGauge(MetricSessionsActive, "Active TACACS sessions.")
	r.mustCounter(MetricAuthenTotal, "Authentication outcomes.")
	r.mustCounter(MetricAuthorTotal, "Authorization outcomes.")
	r.mustCounter(MetricAcctTotal, "Accounting outcomes.")
	r.mustCounter(MetricProtocolErrors, "Protocol-level errors.")
	r.mustCounter(MetricAPIRequests, "REST operation outcomes.")
	r.mustHistogram(MetricAPIDuration, "REST operation duration in seconds.")
	r.mustCounter(MetricMCPTools, "MCP tool-call outcomes.")
	r.mustHistogram(MetricMCPDuration, "MCP tool-call duration in seconds.")
	r.mustGauge(MetricStateRevision, "Published snapshot revision.")
	r.mustCounter(MetricReloadTotal, "Configuration reload attempts.")
	r.mustGauge(MetricSecretLifecycle, "Legacy shared-secret lifecycle counts by status.")
	r.mustCounter(MetricSecretWarnings, "Legacy shared-secret warnings by status.")
	r.mustGauge(MetricEventSubscribers, "Live event subscribers.")
	r.mustCounter(MetricEventOverwritten, "Event-ring overwrite count.")
	r.mustCounter(MetricEventSubscriberResets, "Slow event subscribers detached.")
	r.mustGauge(MetricGoGoroutines, "Number of goroutines.")
	r.mustGauge(MetricGoThreads, "Number of OS threads created.")
	r.mustGauge(MetricGoMemAllocBytes, "Bytes allocated and still in use.")
	r.mustGauge(MetricGoMemSysBytes, "Bytes obtained from the system.")
	r.mustGauge(MetricGoMemHeapAllocBytes, "Heap bytes allocated and still in use.")
	r.mustGauge(MetricGoMemHeapInuseBytes, "Heap bytes in in-use spans.")
	r.mustGauge(MetricGoMemHeapObjects, "Number of allocated heap objects.")
	r.mustGauge(MetricGoGCPauseSeconds, "Most recent GC pause in seconds.")
	r.mustCounter(MetricGoNumGC, "Number of completed GC cycles.")
	r.mustCounter(MetricProtocolRequests, "Protocol request outcomes (RADIUS and future carriers).")
	r.mustCounter(MetricProtocolDiscards, "Silent protocol discards by closed reason_code.")
	r.mustHistogram(MetricProtocolDuration, "Protocol request duration in seconds.")
	r.mustGauge(MetricRADIUSQueueDepth, "RADIUS worker-queue depth by role.")
	r.mustGauge(MetricRADIUSInflight, "RADIUS in-flight datagrams by role.")
	r.mustCounter(MetricRADIUSRetransmission, "RADIUS retransmission-cache lookups.")
	r.mustGauge(MetricRADIUSCacheEntries, "RADIUS retransmission-cache occupancy.")
	r.mustCounter(MetricRADIUSCacheSaturations, "RADIUS retransmission-cache saturation drops.")
	r.mustCounter(MetricRADIUSJournalSaturations, "RADIUS accounting journal saturations.")
	r.mustCounter(MetricRADIUSAuthenticatorFail, "RADIUS authenticator validation failures.")
	r.mustCounter(MetricRADIUSChallenges, "RADIUS Challenge-State gate outcomes.")
	r.mustGauge(MetricRADIUSChallengeEntries, "RADIUS Challenge-State store occupancy.")
	r.mustCounter(MetricRADIUSChallengeSaturations, "RADIUS Challenge-State store saturations.")
	r.mustGauge(MetricRADIUSSessionIndexEntries, "RADIUS accounting session-index occupancy.")
	r.mustCounter(MetricRADIUSSessionIndexSaturations, "RADIUS session-index insert refusals.")
	r.mustCounter(MetricRADIUSDynAuthTotal, "RADIUS CoA/Disconnect originate and inbound outcomes.")

	// Always publish the closed lifecycle set so scrapes do not invent status.
	for _, st := range SecretLifecycleStatuses {
		r.Set(MetricSecretLifecycle, Labels{LabelStatus: st}, 0)
	}
}

func (r *Registry) mustCounter(name, help string) {
	r.counters[name] = &labeledCounter{help: help, series: map[string]*counter{}}
}

func (r *Registry) mustGauge(name, help string) {
	r.gauges[name] = &labeledGauge{help: help, series: map[string]*gauge{}}
}

func (r *Registry) mustHistogram(name, help string) {
	r.histograms[name] = &labeledHistogram{help: help, buckets: defaultHistogramBuckets, series: map[string]*histogram{}}
}

// DroppedLabels is how many observations were rejected for label policy.
func (r *Registry) DroppedLabels() uint64 {
	if r == nil {
		return 0
	}
	return r.dropped.Load()
}

// Inc adds n to a counter. Invalid labels are dropped.
func (r *Registry) Inc(name string, labels Labels, n uint64) {
	if r == nil || n == 0 {
		return
	}
	norm, ok := r.normalize(name, labels)
	if !ok {
		return
	}
	r.mu.Lock()
	lc := r.counters[name]
	if lc == nil {
		r.mu.Unlock()
		r.dropped.Add(1)
		return
	}
	key := seriesKey(norm)
	c := lc.series[key]
	if c == nil {
		c = &counter{}
		lc.series[key] = c
	}
	r.mu.Unlock()
	c.v.Add(n)
}

// Add is Inc with a signed delta; negative values are ignored.
func (r *Registry) Add(name string, labels Labels, n int64) {
	if n <= 0 {
		return
	}
	r.Inc(name, labels, uint64(n))
}

// Set writes a gauge. Invalid labels are dropped.
func (r *Registry) Set(name string, labels Labels, v float64) {
	if r == nil {
		return
	}
	norm, ok := r.normalize(name, labels)
	if !ok {
		return
	}
	r.mu.Lock()
	lg := r.gauges[name]
	if lg == nil {
		r.mu.Unlock()
		r.dropped.Add(1)
		return
	}
	key := seriesKey(norm)
	g := lg.series[key]
	if g == nil {
		g = &gauge{}
		lg.series[key] = g
	}
	r.mu.Unlock()
	g.v.Store(floatToBits(v))
}

// AddGauge adds delta to a gauge, creating it at zero if needed.
func (r *Registry) AddGauge(name string, labels Labels, delta float64) {
	if r == nil || delta == 0 {
		return
	}
	norm, ok := r.normalize(name, labels)
	if !ok {
		return
	}
	r.mu.Lock()
	lg := r.gauges[name]
	if lg == nil {
		r.mu.Unlock()
		r.dropped.Add(1)
		return
	}
	key := seriesKey(norm)
	g := lg.series[key]
	if g == nil {
		g = &gauge{}
		lg.series[key] = g
	}
	cur := bitsToFloat(g.v.Load())
	g.v.Store(floatToBits(cur + delta))
	r.mu.Unlock()
}

// Observe records a histogram sample in seconds.
func (r *Registry) Observe(name string, labels Labels, seconds float64) {
	if r == nil || seconds < 0 {
		return
	}
	norm, ok := r.normalize(name, labels)
	if !ok {
		return
	}
	r.mu.Lock()
	lh := r.histograms[name]
	if lh == nil {
		r.mu.Unlock()
		r.dropped.Add(1)
		return
	}
	key := seriesKey(norm)
	h := lh.series[key]
	if h == nil {
		h = &histogram{bucket: make([]uint64, len(lh.buckets)+1)}
		lh.series[key] = h
	}
	buckets := lh.buckets
	r.mu.Unlock()
	h.observe(seconds, buckets)
}

func (h *histogram) observe(v float64, buckets []float64) {
	h.mu.Lock()
	h.count++
	h.sum += v
	placed := false
	for i, le := range buckets {
		if v <= le {
			h.bucket[i]++
			placed = true
			break
		}
	}
	if !placed {
		h.bucket[len(buckets)]++
	}
	h.mu.Unlock()
}

func (r *Registry) normalize(name string, labels Labels) (Labels, bool) {
	allow, known := allowedLabels[name]
	if !known {
		r.dropped.Add(1)
		return nil, false
	}
	if _, life := lifecycleSeries[name]; life {
		return r.normalizeLifecycle(name, labels)
	}
	out := Labels{}
	for k, v := range labels {
		if k == "" {
			r.dropped.Add(1)
			return nil, false
		}
		if _, bad := forbiddenLabelKeys[k]; bad {
			r.dropped.Add(1)
			return nil, false
		}
		if _, ok := allow[k]; !ok {
			r.dropped.Add(1)
			return nil, false
		}
		if !validLabelValue(name, k, v) {
			r.dropped.Add(1)
			return nil, false
		}
		if k == LabelClientID {
			v = r.boundClientID(v)
			if v == "" {
				r.dropped.Add(1)
				return nil, false
			}
		}
		out[k] = v
	}
	return out, true
}

func (r *Registry) normalizeLifecycle(name string, labels Labels) (Labels, bool) {
	if len(labels) == 0 {
		r.dropped.Add(1)
		return nil, false
	}
	status, ok := labels[LabelStatus]
	if !ok {
		r.dropped.Add(1)
		return nil, false
	}
	if name == MetricSecretWarnings {
		if !knownWarningStatus(status) {
			r.dropped.Add(1)
			return nil, false
		}
	} else if !knownLifecycleStatus(status) {
		r.dropped.Add(1)
		return nil, false
	}
	if len(labels) != 1 {
		// Extra keys — including client_id — are a hard drop.
		r.dropped.Add(1)
		return nil, false
	}
	return Labels{LabelStatus: status}, true
}

func (r *Registry) boundClientID(id string) string {
	if id == "" || len(id) > 64 || strings.ContainsAny(id, " \t\n\r\"\\") {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.clientIDs[id]; ok {
		return id
	}
	if len(r.clientIDs) >= r.maxClientIDs {
		return "other"
	}
	r.clientIDs[id] = struct{}{}
	return id
}

func validLabelValue(name, key, value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	if strings.ContainsAny(value, "\n\r\"\\") {
		return false
	}
	switch key {
	case LabelListener:
		return knownListener(value)
	case LabelTransport:
		return knownTransport(value)
	case LabelStatus:
		return knownLifecycleStatus(value)
	case LabelResultClass:
		return knownResultClass(value)
	case LabelAuthenType:
		return knownAuthenType(value)
	case LabelErrorCode:
		return knownErrorCode(value)
	case LabelOperationID:
		return knownOperationID(value)
	case LabelClientID:
		return true
	case LabelProtocol:
		return knownProtocol(value)
	case LabelRole:
		return knownRole(value)
	case LabelReasonCode:
		return knownReasonCode(value)
	case LabelOutcome:
		return knownOutcome(value)
	case LabelPacketCode:
		return knownPacketCode(value)
	case LabelResult:
		return knownRetransmitResult(value) || knownChallengeResult(value)
	case LabelType:
		return knownAuthenticatorType(value)
	default:
		_ = name
		return false
	}
}

func knownResultClass(v string) bool {
	switch v {
	case ResultSuccess, ResultError, ResultFail, ResultDeny, ResultReject, ResultRestart,
		"permit_add", "permit_replace", "unauthenticated", "permission_denied",
		"invalid_argument", "rate_limited", "unavailable", "conflict",
		"revision_mismatch", "already_exists", "not_found":
		return true
	default:
		return false
	}
}

func knownAuthenType(v string) bool {
	switch v {
	case "ascii", "pap", "chap", "mschap", "mschapv2", "enable", "chpass", "unknown":
		return true
	default:
		return false
	}
}

func knownErrorCode(v string) bool {
	switch v {
	case "", "none", "conn_limit", "unknown_client", "secret_unavailable",
		"unencrypted", "missing_unencrypted", "secret_mismatch", "protocol",
		"timeout", "canceled", "internal",
		"invalid_argument", "unauthenticated", "permission_denied",
		"not_found", "already_exists", "conflict", "revision_mismatch",
		"rate_limited", "unavailable":
		return true
	default:
		return false
	}
}

func knownOperationID(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, c := range v {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func seriesKey(labels Labels) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
	}
	return b.String()
}

func parseSeriesKey(key string) Labels {
	if key == "" {
		return nil
	}
	out := Labels{}
	for _, part := range strings.Split(key, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[k] = v
	}
	return out
}

func formatLabels(labels Labels) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, k, escapeLabel(labels[k]))
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
