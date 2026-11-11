# SecureSuite

**A free, open-source (AGPL) web application security testing toolkit.** An
intercepting HTTP/HTTPS/WebSocket proxy plus the full manual workflow — Repeater,
Intruder, Decoder, Comparer, Sequencer — a passive and active scanner, and an
out-of-band (OAST) server, in a single **~11 MB native binary**. No JVM. ~18 ms
warm start. Scriptable over a local HTTP + WebSocket API from the first commit.

> **Mission:** keep serious web security testing a permanent commons. The
> features comparable tools paywall — the active scanner, OAST, project files,
> reporting, every Intruder attack mode — are free and open here.

> ⚠️ **For authorized security testing only.** Use SecureSuite exclusively
> against systems you own or have explicit written permission to test.

---

## Why

Professional web application security testing is effectively gated behind one
commercial tool. SecureSuite exists so the capability — not a crippled free tier
— belongs to everyone, and the licence is chosen so it can never be taken
private again (see [LICENSING.md](LICENSING.md)).

It is a **clean-room** project: built from public specifications (RFC / W3C /
OWASP) and observed, on-the-wire behaviour only. It contains **no** code,
strings, payloads, or assets copied from Burp Suite or any other proprietary
product. Provenance is logged in [docs/PROVENANCE.md](docs/PROVENANCE.md).

## What works today

SecureSuite is in **active development**. The manual testing workflow is solid
and real-time interception is verified on the wire; the automated scanner is
still growing. Honest status:

**Solid and verified**
- Intercepting **HTTP/HTTPS/WebSocket** proxy with its own on-the-fly CA.
- Request **and** response interception — hold, edit, forward, drop (verified live).
- **Match & Replace** (literal + regex, both directions).
- **Repeater** (edit + resend), **Intruder** with all four attack modes
  (sniper, battering-ram, pitchfork, cluster-bomb), **Decoder**, **Comparer**,
  **Sequencer**.
- **Target** site map + scope + content discovery.
- **Passive scanner** (missing headers, cookie flags, info leaks) → Issues.
- **Unified Logger** and HTTP history with search/filter/export. History, scope,
  rules and issues persist in SQLite; the Logger, WebSocket log and OAST
  interactions are in-memory.
- Local **HTTP + WebSocket API** — headless and CI-friendly by design.

**Early / in progress**
- **Active scanner** is narrow today: SQLi (error-based) + reflected XSS
  (HTML-gated). Breadth (SSRF, traversal, SSTI, CORS, and more) is the next milestone.
- **OAST** is HTTP-only; DNS/SMTP canaries are on the roadmap.
- No dedicated crawler yet (site map is history-driven).

Roughly **90% of the core manual workflow** and **~65% of the full surface** of
the tool it is modelled on. The roadmap is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Architecture

A **Rust engine** does the heavy lifting — TLS MITM proxying, hostile-input
parsing, storage, the scan pipeline — and exposes a local **HTTP + WebSocket
API**. A **web console** (and any CLI or automation) drives the engine over that
one API, so a headless/server mode comes for free. Full detail in
[docs/architecture.md](docs/architecture.md).

- `engine/crates/securesuite` — the proxy, console, API, store, and tools (one binary).
- `engine/crates/ss-ca` — tested CA crate (root CA + per-host leaf minting). Not
  wired in yet; the engine currently uses an inline CA.
- `ext-sdk/` — the Apache-2.0 extension SDK (language-agnostic HTTP webhooks).

Stack: Rust, [hudsucker](https://github.com/omjadas/hudsucker) (MITM core),
axum, rustls / rcgen / aws-lc, bundled SQLite. No OpenSSL, no JVM.

## Build & run

Prerequisites: **Rust (stable)** and a C toolchain (Xcode CLT / build-essential).

```bash
# build the engine
cargo build -p securesuite

# run it (console at http://127.0.0.1:8081)
./target/debug/securesuite
```

Then point your browser or system proxy at `127.0.0.1:8080` and trust the
SecureSuite CA (console → Download CA) to intercept HTTPS and `wss://`. The
console starts empty and fills as traffic routes through it.

Ports are environment-configurable: `SECURESUITE_PROXY_PORT` (8080),
`SECURESUITE_UI_PORT` (8081), `SECURESUITE_OAST_PORT` (8082). If another proxy
such as Burp already uses 8080, set `SECURESUITE_PROXY_PORT` to a free port.

### Practice lab

Deliberately vulnerable targets for local testing only:

```bash
cd lab && docker compose up -d   # juice-shop, dvwa, httpbin
```

The lab publishes `127.0.0.1:8080` and `127.0.0.1:8081`, the engine's default
proxy and console ports. When using the lab, start the engine on other ports:

```bash
SECURESUITE_PROXY_PORT=8086 SECURESUITE_UI_PORT=8087 ./target/debug/securesuite
```

## Contributing

Contributions are welcome under the **Developer Certificate of Origin**
(`git commit -s`), which keeps copyright distributed and the project
un-monopolisable. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

- **Platform** (engine, console, servers): **AGPL-3.0-or-later** — see [LICENSE](LICENSE).
- **Extension SDK** (`ext-sdk/`): **Apache-2.0** — see [ext-sdk/LICENSE](ext-sdk/LICENSE).

Rationale in [LICENSING.md](LICENSING.md).
