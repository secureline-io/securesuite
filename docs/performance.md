# SecureSuite — performance

Measured on **Apple Silicon (arm64), macOS**, **release** build
(`cargo build --release`), **loopback only** (isolates proxy cost from the
network). Tools: ApacheBench (`ab`), a 2-byte keep-alive origin, `ps` for RSS.

## Footprint

| Metric | SecureSuite (release) | Note |
|---|---|---|
| Binary size | **11.3 MB** | single native binary, no runtime |
| Idle RSS | **~12 MB** | |
| RSS after ~9k proxied requests | **~26 MB** | stable, no growth |
| Cold start (mints the CA) | **604 ms** | one-time only |
| Warm start | **18.5 ms** | |

For contrast, Burp Suite ships a **~640 MB** install (install4j JVM monolith +
bundled JRE) on a multi-hundred-MB JVM heap. SecureSuite is an ~11 MB binary
with a 12–26 MB resident set and sub-20 ms start.

## Proxy throughput & latency

ApacheBench, `-n 3000 -c 20`, loopback origin:

| Path | req/s | p50 | p95 | p99 | failed |
|---|---|---|---|---|---|
| Direct (no proxy) | **10,324** | 2 ms | 2 ms | 3 ms | 0 |
| Through SecureSuite MITM | **~4,000** | 5 ms | 11 ms | 14 ms | 0 |

Per request, the proxy adds **~3 ms median** while it records the full exchange,
writes it through to SQLite, and applies Match & Replace. It sustains **~4k
req/s** with one CPU core saturated and **zero failed requests**.

## Interpretation

- Loopback isolates the proxy; in real use **network latency dominates**, so the
  proxy is not the bottleneck for interactive testing or Intruder runs.
- The throughput limiter is the **synchronous SQLite write-through** (one
  `INSERT` per request behind a single `Mutex<Connection>`). Clear optimization
  path if ever needed: SQLite **WAL** mode, a dedicated **async writer task**, or
  **batched inserts**.
- Memory is flat under sustained load; no leaks observed.

## Reproduce

```
# release engine on alt ports with a throwaway data dir
HOME=/tmp/ssb SECURESUITE_PROXY_PORT=8186 SECURESUITE_UI_PORT=8187 \
  ./target/release/securesuite &
python3 -m http.server 8090 &          # or any local origin
ab -n 3000 -c 20 http://127.0.0.1:8090/              # direct baseline
ab -X 127.0.0.1:8186 -n 3000 -c 20 http://127.0.0.1:8090/   # through the proxy
```
