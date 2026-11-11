# SecureSuite — feature roadmap

> **Mission.** A clean-room, **AGPL**, community-owned web application security
> testing platform — full Burp Suite workflow parity **plus** improvements, with
> every tier Burp charges for (Scanner, OAST, project files, reporting) kept
> **free and open**. One tiny native binary, no JVM, no licence.

## 0. Architecture (today)

- **Engine:** single Rust bin crate `engine/crates/securesuite` on **hudsucker
  0.25** (MITM core) + `ss-ca` (CA crate). ~12 MB native binary, ~12–26 MB RSS,
  ~4,000 req/s proxied.
- **Surface:** intercepting HTTP/HTTPS/WebSocket proxy + **live web console**
  (`http://127.0.0.1:8081`) + local **HTTP+WS JSON API** (headless/CLI falls out
  for free) + persistent **SQLite** history/scope/rules/issues + per-host CA.
- **Ports:** proxy `8080` · UI `8081` · OAST `8082` (all env-configurable; move
  the proxy port if another proxy such as Burp already holds `8080`).
- **Packaging:** macOS `.dmg`, Windows `.zip`, Linux `.deb`/`.tar.gz`, all
  branded with the supplied logo kit.

## 1. Current state — mapped to Burp's tools

Legend: ✅ shipped & verified · 🟡 partial · 🔲 not yet.

| Burp tool | SecureSuite today | State |
|---|---|---|
| Proxy — intercept req **+ resp** | hold/edit/drop both directions; **verified real-time tamper on the wire** | ✅ |
| Proxy — HTTP history | SQLite-persisted, live console table | ✅ |
| Proxy — WebSocket history | `wscap.rs` records every frame both directions (`/api/wslog` + WS panel) | ✅ |
| Proxy — Match & Replace | literal/regex rewrite of url/headers/body both directions, persisted | ✅ |
| Target — Site map | `/api/sitemap` hosts→paths/methods/statuses | ✅ |
| Target — Scope | include patterns gate capture/scan (`/api/scope`, `in_scope()`) | ✅ |
| Target — content discovery | `/api/discover` wordlist probing | ✅ |
| Repeater | manual edit + resend + response view | ✅ |
| Intruder | all 4 attack types (sniper/battering-ram/pitchfork/cluster-bomb), `§` positions, per-position sets, bounded concurrency | ✅ |
| Decoder | encode/decode/hash transforms | ✅ |
| Comparer | LCS line/word diff | ✅ |
| Sequencer | Shannon entropy + duplicate verdict | ✅ |
| Scanner — passive | missing headers, cookie flags, info leaks → Issues | ✅ |
| Scanner — active | SQLi (error-based) + reflected XSS (HTML-gated), insertion points | 🟡 (narrow check set) |
| Collaborator / OAST | **HTTP** canary listener (`/api/oast/*`) | 🟡 (HTTP only) |
| Extensions | language-agnostic **HTTP webhooks** (POST exchange → JSON issues) | 🟡 (no in-proc API/store) |
| Logger | *(history serves part of this)* | 🟡 |
| Inspector | *(raw editor only)* | 🔲 |
| Scanner — crawler | — | 🔲 |
| Session handling / macros | — | 🔲 |
| Project files (save/load) | *(SQLite persists, but no portable project file)* | 🟡 |
| Organizer | — | 🔲 |
| DOM Invader (client-side) | — | 🔲 |
| Clickbandit | — | 🔲 |
| Embedded browser | — | 🔲 |
| Reporting (HTML/XML) | — | 🔲 |
| Native desktop window | *(web console only)* | 🔲 |
| Transparent/system-wide capture | explicit proxy + `system-proxy.sh`; no TUN/pf mode | 🟡 |

**Honest parity:** ~**65%** of Burp's total surface, but ~**90%** of the **core
manual workflow** (capture → intercept → repeat → intrude → compare → basic scan).

## 2. Roadmap

### Phase A — Polish & high-value gaps *(near-term, days)*
Goal: make the manual workflow feel complete and fix sharp edges.
1. **Intercept API/UX fixes** — accept header shape `{name,value}` **and**
   `[name,value]` in `/api/intercept/resolve` (found during real-time testing);
   add a proper **Intercept panel** with editable request/response + per-rule
   auto-forward; **WebSocket frame interception** (edit/drop frames, not just log).
2. **Inspector-style structured editor** — query/headers/cookies/body as editable
   key-values with safe re-encoding.
3. **History search/filter** + columns (method/host/status/type/scope) + export.
4. **Logger** — unified, filterable log of all engine-generated traffic + export.
5. **Resolve the “empty console” onboarding** — first-run guide + one-click
   system-proxy toggle + CA install helper in the console.

### Phase B — Automation depth *(near/mid-term)*
Goal: close the Pro-tier gap that matters most.
6. **Scanner breadth** — add checks: SSRF, path traversal, open redirect, OS
   command injection, header/host injection, CORS misconfig, SSTI, XXE,
   directory listing, mixed content, JWT issues. Each as an independent,
   false-positive-gated predicate (our own logic, OWASP-referenced).
7. **Dedicated crawler** — follow links/forms within scope, build the site map
   automatically, feed the active scanner.
8. **Intruder payload processing** — encode/hash/prefix/suffix/substitution
   rules + **grep-match / grep-extract**; resource pool / rate limiting.
9. **Retro-scan** — scan history loaded from SQLite on startup (today only live
   `push()` is scanned).

### Phase C — Out-of-band & client-side *(mid-term)*
10. **OAST parity (Collaborator)** — add **DNS** and **SMTP** canary listeners
    beside HTTP; wildcard-subdomain tokens; private/self-host friendly.
11. **DOM Invader equivalent** — inject a content script that reports controllable
    sinks, DOM-XSS, prototype pollution and `postMessage` flows from the page.
12. **Embedded browser** — ship/launch a Chromium pre-wired to proxy + CA so
    there's zero setup (kills the #1 “it's not working / blank console” confusion).

### Phase D — Workflow & delivery *(mid-term)*
13. **Project files** — portable save/load of a whole session (history, scope,
    rules, issues) as one file.
14. **Session handling + macros** — auto-login / token-refresh so scans stay
    authenticated.
15. **Organizer** — save/tag/annotate/status on requests.
16. **Reporting** — HTML/JSON issue reports (severity, evidence, remediation).
17. **Native desktop window (Tauri)** wrapping the console.

### Phase E — Ecosystem, scale & release *(longer-term)*
18. **Extension SDK v2** — keep the language-agnostic webhooks, add a **WASM**
    in-proc extension path + a simple **extension registry** (BApp-store analogue).
19. **Wire `ss-ca` as the live CA** (currently a tested, separate crate).
20. **Transparent / system-wide capture** — `SO_ORIGINAL_DST` (Linux) / `pf`
    (macOS) redirect so even non-proxy-aware apps are captured (the true
    “capture all system traffic” mode).
21. **Publish + sign** — push to GitHub, run CI on native runners to produce
    **x86_64-Linux**, **.msi**, and **code-signed/notarized** mac/Windows
    artifacts + a Releases download page.
22. **DAST tier** — headless/CI/scheduled scanning, dashboards, RBAC/SSO.
23. **Optional AI assist** — local-LLM issue explanations / agentic testing
    (integrates with the owner's existing ML harness; opt-in, never required).

## 3. Why SecureSuite (differentiators vs Burp)

- **Free & AGPL** — Scanner, OAST, project files, reporting are **not** paywalled.
- **Tiny, fast, no JVM** — ~12 MB single binary vs Burp's ~640 MB JVM+bundle.
- **Headless-first** — the same engine is a CLI/API, ideal for CI from day one.
- **Language-agnostic extensions** — HTTP webhooks (any language) instead of a
  Java-only API.
- **Permanent commons** — no single-vendor lock-in; community-owned.
