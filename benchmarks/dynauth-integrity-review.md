# RFC 5176 request signing — RAD-REV-006

Go 1.26.8, linux/amd64, Intel Core i7-8750H; `GOMAXPROCS=2`, `-p=2`, identical CoA/User-Name fixture. Baseline and new implementation were run sequentially with `go test ./internal/radius/server -run '^$' -bench '^BenchmarkSignDynAuthRequest$' -benchmem -count=5`. Raw results: [before](dynauth-integrity-review/before.txt), [after](dynauth-integrity-review/after.txt).

| Implementation | Median ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| Before (nonce/header HMAC; missing request checksum) | 5515 | 809 | 15 |
| After (zero-header HMAC, populated-MA request checksum) | 4396 | 809 | 15 |

The loaded shared host produced wide timing ranges (before 2812–6213 ns, after 3992–8133 ns); these samples do not establish an improvement. Allocation counts are unchanged. The additional MD5 checksum is required by RFC 5176 and cannot be omitted for performance. The root reviewer approved the raw-sample median comparison as the repository equivalent on 2026-10-03, with the host-contention limitation and no speed claim.

Fixed-vector reproduction (Python standard library only; test lab secret, no production credentials):

```python
import hashlib, hmac
secret = b'LabSecret-16chars!'
for code in (40, 43):
    packet = bytearray(bytes([code, 9, 0, 41]) + bytes(16)
                       + bytes([80, 18]) + bytes(16) + bytes([1, 3]) + b'u')
    packet[22:38] = hmac.new(secret, packet, hashlib.md5).digest()
    packet[4:20] = hashlib.md5(packet + secret).digest()
    print(packet.hex())
```

Disconnect: `280900299fec6b17d1858824761e5d028f64e2305012a5041bbb1195ae3ddbd27538e55cc46a010375`.
CoA: `2b09002920622bdf5fc6472155915daf063ac3475012a756daa992df1e011455b1610b0d0448010375`.
These RFC-derived raw samples verify both independent Go implementations in `TestDynAuthRFC5176FixedVectors`.
