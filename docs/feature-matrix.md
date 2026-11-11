# Burp Suite → SecureSuite Feature Matrix

The authoritative inventory of what we are reimplementing. Goal: **full feature parity, then improvements.** Studied against Burp Suite 2026.9.2 (black-box + public docs only — see `PROVENANCE.md`).

**Status legend:** ⬜ not started · 🟦 planned (designed) · 🟨 partial · ✅ shipped (working MVP, verified end-to-end — not yet Burp's full depth)

## Phase status — all 6 phases have a verified MVP

| Phase | Scope | State |
|---|---|---|
| **1 · Proxy** | intercept req **+ resp**, Match&Replace, **WebSocket capture**, SQLite persistence (history, scope, rules, issues) | ✅ |
| 2 · Target | site map, content discovery | ✅ |
| 3 · Comparer + Sequencer | LCS diff, entropy/randomness | ✅ |
| 4 · Active scanner | insertion points + SQLi/XSS injection, issue model | ✅ |
| 5 · Extensions + OAST | language-agnostic HTTP webhooks, OAST canary | ✅ (DNS OAST deferred) |
| 6 · Packaging | macOS `.app` + `.dmg` | ✅ (native-window Tauri shell deferred) |

> **Engine:** the **`securesuite`** crate runs an intercepting **HTTP + HTTPS (MITM) proxy** (hudsucker; HTTP/1.1 + HTTP/2), records full exchanges with **SQLite persistence** (`~/.securesuite/`, survives restart), and serves a **live web console** + **JSON/WebSocket API**, backed by a persistent **SecureSuite root CA** (tested `ss-ca` crate). 27 tests pass; clippy clean. Ports env-configurable (`SECURESUITE_{PROXY,UI,OAST}_PORT`, default 8080/8081/8082) so it coexists with Burp. Run: `cargo build -p securesuite && ./target/debug/securesuite`, or `./packaging/build-macos-app.sh` for the app bundle.

---

## 1. Proxy — Phase 1

| Feature | Status | Notes |
|---|---|---|
| Intercepting HTTP/1.1 proxy | ✅ | hudsucker core |
| HTTPS interception via on-the-fly CA | ✅ | persistent `SecureSuite CA`, per-host leaves |
| HTTP/2 interception | ✅ | via hudsucker |
| HTTP/3 / QUIC interception | 🟦 | **improvement** — Burp support is limited |
| WebSocket interception & history | ✅ | capture both directions + hold/edit/drop frames → `/api/wslog`, `/api/ws/intercept`, WS panel |
| HTTP history (searchable, filterable) | ✅ | SQLite-persisted, live WS feed |
| Request interception (hold/edit/forward/drop) | ✅ | |
| Response interception & edit | ✅ | separate toggle, status-editable |
| Match & replace (request/response rewrite) | ✅ | literal + Rust regex, 5 parts |
| Intercept rules (which requests to hold) | 🟨 | global req/resp toggles; per-match rules later |
| Proxy listeners (multiple, binding, redirect) | 🟦 | single configurable listener today |
| Invisible / transparent proxying | 🟦 | |
| Upstream proxy / SOCKS chaining | 🟦 | |
| TLS pass-through / SNI / client certs | 🟦 | |
| CA export & trust onboarding | ✅ | UI download + `/api/ca.pem` |
| Launch pre-configured browser | 🟦 | |

## 2. Target — Phase 2

| Feature | Status | Notes |
|---|---|---|
| Site map (tree of discovered content) | ✅ | aggregated from history (`/api/sitemap`) |
| Scope (include/exclude) | ✅ | persisted, shared by tools |
| Content discovery / brute-force of paths | ✅ | built-in wordlist + concurrency (`/api/discover`) |
| Issue definitions / knowledge base | 🟦 | |
| Target analytics (params, hosts) | 🟨 | site map covers hosts/paths |

## 3. Repeater — Phase 1

| Feature | Status | Notes |
|---|---|---|
| Send request, view response | ✅ | |
| Multiple tabs, named & reorderable | 🟦 | |
| History per tab, follow redirects | 🟦 | |
| Send to other tools | 🟦 | |

## 4. Intruder — Phase 1

| Feature | Status | Notes |
|---|---|---|
| Payload positions (markers) | ✅ | `§marker§` across url/headers/body |
| Attack types: sniper, battering-ram, pitchfork, cluster-bomb | ✅ | **all four, free** (Burp paywalls these) |
| Payload sets (lists, numbers) | 🟨 | per-position sets |
| Payload processing rules & encoding | 🟦 | |
| Grep-match / extract | 🟦 | |
| Resource pool / throttling / concurrency | ✅ | bounded semaphore |
| Results grid (sort/filter + diff) | ✅ | basic grid |

## 5. Decoder — Phase 1

| Feature | Status | Notes |
|---|---|---|
| Encode/decode: URL, HTML, Base64, hex | ✅ | |
| Base64URL, octal, binary, gzip | 🟦 | |
| Hashes (MD5, SHA-*) | 🟦 | |
| Smart decode / chained transforms | 🟦 | **improvement** — pipeline |

## 6. Comparer — Phase 3

| Feature | Status | Notes |
|---|---|---|
| Line & word diff (LCS) | ✅ | colored segment view |
| Byte-level diff | 🟦 | |
| Compare any two messages | ✅ | paste A/B |

## 7. Sequencer — Phase 3

| Feature | Status | Notes |
|---|---|---|
| Manual token load | ✅ | |
| Entropy & randomness analysis | ✅ | Shannon + duplicate detection; FIPS battery later |
| Live token capture | 🟦 | |

## 8. Scanner — Phase 3 (passive) + Phase 4 (active)

| Feature | Status | Notes |
|---|---|---|
| Passive scanning | ✅ | headers, cookies, banner → `/api/issues` |
| Active scanning (insertion points + attacks) | ✅ | SQLi (error) + reflected XSS (HTML-gated) |
| Crawler / spider | 🟦 | history-driven today; dedicated crawler later |
| Scan configurations / profiles | 🟦 | |
| Issue model, severity | ✅ | persisted, deduped |
| Custom checks | ✅ | via extension webhooks (below) |
| Community template engine (nuclei-style) | 🟦 | **improvement** |
| Out-of-band (OAST) driven checks | 🟨 | OAST exists; auto-correlation later |

## 9. Collaborator / OAST — Phase 5

| Feature | Status | Notes |
|---|---|---|
| HTTP interaction capture | ✅ | built-in canary listener (`:8082`) |
| DNS / SMTP interaction capture | 🟦 | HTTP-only today |
| Self-hostable server | ✅ | **it is the engine** — first-class self-host |
| Correlation & polling | ✅ | `/api/oast/{generate,interactions}` |

## 10. Extender — Phase 5

| Feature | Status | Notes |
|---|---|---|
| Extension API | ✅ | **language-agnostic HTTP webhooks** (`docs/extensions.md`) |
| Extension manager / marketplace | 🟦 | community store |
| WASM runtime (sandboxed) | 🟦 | **improvement** over Jython/Java-only |
| Burp-compat shim | 🟦 | reimplemented shape, no Burp code |

## 11. Session handling — future

| Feature | Status |
|---|---|
| Session-handling rules / macros / cookie jar / auth flows | 🟦 |

## 12. Platform & UX

| Feature | Status | Notes |
|---|---|---|
| Unified logger (all traffic) | ✅ | history + live feed |
| REST + WebSocket API for automation | ✅ | **improvement** — API-first from day one |
| Project persistence (save/restore) | 🟨 | SQLite; git-friendly text format later |
| Desktop packaging (macOS `.app` + `.dmg`) | ✅ | `packaging/build-macos-app.sh` |
| Native-window desktop shell (Tauri/WKWebView) | 🟦 | browser-launched today |
| Linux/Windows installers (.deb/.msi) | 🟦 | release binary runs on all three |
| Dashboard / Inspector / Organizer / global search | 🟨 | filter + viewer today |
| Embedded browser / DOM-XSS / CSRF & clickjacking PoC | 🟦 | |
| Headless / CI mode | 🟨 | engine is headless API; dedicated CLI later |

## Cross-cutting improvements over Burp

- **Scriptable & API-first** from day one — automation is not a paywalled add-on.
- **All four Intruder attack modes free** (Burp Pro paywalls them).
- **Language-agnostic extensions** (HTTP webhooks today; WASM planned) vs Jython/Java-only.
- **Self-hostable OAST** is the engine itself — no third-party server.
- **Native HTTP/2** (HTTP/3 planned).
- **Single static binary** per OS + headless API/CI mode.
- No feature paywall: passive **and** active scanning are free and open (AGPL).
