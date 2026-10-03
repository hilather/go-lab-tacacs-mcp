# PEAP bounds — RAD-REV-002

Reference: Go 1.26.8, linux/amd64, Intel Core i7-8750H. Sequential before/after runs with the same two-fragment 2 KiB TLS flight fixture: `go test ./internal/radius/eap/peap -run '^$' -bench BenchmarkPEAPReassemble -benchmem -benchtime=200ms -cpu=1 -count=10`.

| Implementation | ns/op samples | Median ns/op | B/op | allocs/op |
|---|---|---:|---:|---:|
| Before | 1650, 1380, 1459, 1480, 1399, 1548, 1492, 1571, 1506, 1422 | 1486 | 4096 | 2 |
| After | 1841, 1827, 1861, 1903, 1921, 2068, 1727, 1894, 1495, 1610 | 1851 | 4096 | 2 |

Equivalent median comparison: +24.6% latency (+365 ns per reassembled flight), unchanged bytes and allocations. Reviewing root agent explicitly approved this measured cost for mandatory total-length, framing and memory-bound validation. No security check was removed to meet a latency budget. The new reservation cap eliminates unbounded retained buffers/tunnels; this benchmark covers reassembly rather than TLS cryptography or registry admission.
