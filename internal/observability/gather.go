package observability

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// WritePrometheus writes the registry in Prometheus text exposition format.
func (r *Registry) WritePrometheus(w io.Writer) error {
	if r == nil {
		return nil
	}
	r.RefreshRuntime()
	r.mu.Lock()
	defer r.mu.Unlock()

	names := make([]string, 0, len(r.counters)+len(r.gauges)+len(r.histograms))
	seen := map[string]struct{}{}
	for n := range r.counters {
		names = append(names, n)
		seen[n] = struct{}{}
	}
	for n := range r.gauges {
		if _, ok := seen[n]; !ok {
			names = append(names, n)
		}
	}
	for n := range r.histograms {
		if _, ok := seen[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if lc, ok := r.counters[name]; ok {
			if err := writeCounter(w, name, lc); err != nil {
				return err
			}
		}
		if lg, ok := r.gauges[name]; ok {
			if err := writeGauge(w, name, lg); err != nil {
				return err
			}
		}
		if lh, ok := r.histograms[name]; ok {
			if err := writeHistogram(w, name, lh); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeCounter(w io.Writer, name string, lc *labeledCounter) error {
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, lc.help, name); err != nil {
		return err
	}
	keys := sortedKeys(lc.series)
	if len(keys) == 0 {
		_, err := fmt.Fprintf(w, "%s 0\n", name)
		return err
	}
	for _, k := range keys {
		c := lc.series[k]
		if _, err := fmt.Fprintf(w, "%s%s %d\n", name, formatLabels(parseSeriesKey(k)), c.v.Load()); err != nil {
			return err
		}
	}
	return nil
}

func writeGauge(w io.Writer, name string, lg *labeledGauge) error {
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, lg.help, name); err != nil {
		return err
	}
	keys := sortedKeys(lg.series)
	if len(keys) == 0 {
		_, err := fmt.Fprintf(w, "%s 0\n", name)
		return err
	}
	for _, k := range keys {
		g := lg.series[k]
		v := bitsToFloat(g.v.Load())
		if _, err := fmt.Fprintf(w, "%s%s %s\n", name, formatLabels(parseSeriesKey(k)), formatFloat(v)); err != nil {
			return err
		}
	}
	return nil
}

func writeHistogram(w io.Writer, name string, lh *labeledHistogram) error {
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, lh.help, name); err != nil {
		return err
	}
	keys := make([]string, 0, len(lh.series))
	for k := range lh.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		// Empty histogram still exposes +Inf bucket, sum, and count.
		if _, err := fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} 0\n%s_sum 0\n%s_count 0\n", name, name, name); err != nil {
			return err
		}
		return nil
	}
	for _, k := range keys {
		h := lh.series[k]
		base := parseSeriesKey(k)
		h.mu.Lock()
		var cum uint64
		for i, le := range lh.buckets {
			cum += h.bucket[i]
			lbl := cloneLabels(base)
			lbl["le"] = formatFloat(le)
			if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", name, formatLabels(lbl), cum); err != nil {
				h.mu.Unlock()
				return err
			}
		}
		cum += h.bucket[len(lh.buckets)]
		lbl := cloneLabels(base)
		lbl["le"] = "+Inf"
		if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", name, formatLabels(lbl), cum); err != nil {
			h.mu.Unlock()
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_sum%s %s\n", name, formatLabels(base), formatFloat(h.sum)); err != nil {
			h.mu.Unlock()
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_count%s %d\n", name, formatLabels(base), h.count); err != nil {
			h.mu.Unlock()
			return err
		}
		h.mu.Unlock()
	}
	return nil
}

func cloneLabels(in Labels) Labels {
	if len(in) == 0 {
		return Labels{}
	}
	out := make(Labels, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// ContainsSeries reports whether name appears in a Prometheus text dump.
func ContainsSeries(text, name string) bool {
	return strings.Contains(text, name)
}
