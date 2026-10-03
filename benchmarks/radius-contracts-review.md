# RADIUS contracts review — RAD-REV-003–005

Go 1.26.8, linux/amd64, same Intel Core i7-8750H runner and fixtures; baseline `35986e1`. Commands use `GOMAXPROCS=2`, `-p=2`, `-run '^$'`, `-benchmem`, `-benchtime=100ms`, and `-count=6`. Raw [before](radius-contracts-review/before.txt), [after](radius-contracts-review/after.txt), and [new journal](radius-contracts-review/journal.txt) samples are retained. Baseline includes the same engine-lookup benchmark added to this change. Equivalent comparison below uses the median of six samples.

The host was heavily contended during measurement. Latency samples are unsuitable for asserting improvements or a stable latency regression; the allocations and bytes represent the change reliably. No throughput or latency improvement is claimed.

Matched command:

```sh
GOMAXPROCS=2 go test -p=2 ./internal/aaa ./internal/state ./internal/policy/radius ./internal/radius/server -run '^$' -bench 'BenchmarkPublishedPolicyEngineLookup|BenchmarkSnapshotPublish_Medium|BenchmarkRadiusPolicyEvaluate|BenchmarkRadiusPolicyCompile|BenchmarkAccountingHandle|BenchmarkRadiusAccountingRequest' -benchmem -benchtime=100ms -count=6
```

| Workload | Before median ns/op | After median ns/op | Before B/op | After B/op | Before allocs/op | After allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| PublishedPolicyEngineLookup | 184.75 | 10.658 | 0 | 0 | 0 | 0 |
| SnapshotPublish_Medium | 3.04921e+07 | 1.55223e+07 | 1.46914e+06 | 1.55432e+06 | 6068 | 7062 |
| RadiusPolicyEvaluate | 238463 | 88305 | 8120 | 8120 | 11 | 11 |
| RadiusPolicyCompile | 17797 | 19559.5 | 1072 | 1072 | 11 | 11 |
| AccountingHandle | 74752.5 | 25424.5 | 1008 | 1008 | 21 | 21 |
| RadiusAccountingRequest | 58822 | 18084.5 | 1008 | 1008 | 21 | 21 |

Publication allocs increase 16.38% and bytes 5.8%. The reviewing root agent explicitly approved this work-placement tradeoff: the TACACS engine is now compiled before snapshot publication instead of lazily allocated on the first request and retained forever in AAA's revision map. A snapshot owns both immutable policy engines and releases them when its last request/session reference disappears. Publication still produces existing compiled rule views, which could be consolidated in a later representation optimization. This change removes unbounded historical retention and per-request compilation without weakening validation.

The atomic journal is a new workload, measured with `go test -p=2 ./internal/radius/udp -run '^$' -bench BenchmarkJournalSemantic -benchmem -benchtime=100ms -count=6`:

| Workload | Median ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| JournalSemanticCompletedRetry | 1199.5 | 0 | 0 |
| JournalSemanticReserveCommit | 5165.5 | 112 | 1 |

Reserve/commit uses a one-nanosecond injected clock/TTL to expire the prior key each iteration and keep the fixture bounded; completed retries reuse one accepted identity. Pending identities count toward both journal limits, cannot expire while their owner executes, and wait within the request cancellation boundary.
