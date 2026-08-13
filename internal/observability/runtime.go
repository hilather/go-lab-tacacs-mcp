package observability

import (
	"runtime"
	"time"
)

var numThreadFn = func() int {
	n, _ := runtime.ThreadCreateProfile(nil)
	return n
}

// RefreshRuntime writes Go runtime gauges. Safe to call on every scrape.
func (r *Registry) RefreshRuntime() {
	if r == nil {
		return
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	r.Set(MetricGoGoroutines, nil, float64(runtime.NumGoroutine()))
	r.Set(MetricGoThreads, nil, float64(numThreadFn()))
	r.Set(MetricGoMemAllocBytes, nil, float64(ms.Alloc))
	r.Set(MetricGoMemSysBytes, nil, float64(ms.Sys))
	r.Set(MetricGoMemHeapAllocBytes, nil, float64(ms.HeapAlloc))
	r.Set(MetricGoMemHeapInuseBytes, nil, float64(ms.HeapInuse))
	r.Set(MetricGoMemHeapObjects, nil, float64(ms.HeapObjects))
	var pause time.Duration
	if ms.NumGC > 0 {
		pause = time.Duration(ms.PauseNs[(ms.NumGC+255)%256])
	}
	r.Set(MetricGoGCPauseSeconds, nil, pause.Seconds())
	// NumGC is a counter; set via gauge-as-absolute then expose as counter by storing last.
	r.SetCounterAbs(MetricGoNumGC, nil, uint64(ms.NumGC))
}

// SetCounterAbs stores an absolute counter value (for runtime NumGC).
func (r *Registry) SetCounterAbs(name string, labels Labels, v uint64) {
	if r == nil {
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
	c.v.Store(v)
	r.mu.Unlock()
}
