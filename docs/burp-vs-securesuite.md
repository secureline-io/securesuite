# Burp Suite vs SecureSuite — difference & gap sheet

> Side-by-side of every major Burp capability against SecureSuite's current
> state, the gap, and the priority to close it. Built clean-room from public
> docs + observed behaviour (see `docs/roadmap-burp.md`). Parity figures are
> honest self-assessment.

Legend: ✅ have · 🟡 partial · 🔲 missing · **P1** now / **P2** next / **P3** later.

## 1. Capture & proxy core

| Capability | Burp | SecureSuite | Gap → to build | Pri |
|---|---|---|---|---|
| HTTP/HTTPS MITM proxy | ✅ Community | ✅ | — | — |
| Per-host TLS cert from own CA | ✅ | ✅ (CA, but `ss-ca` not yet the live CA) | Wire `ss-ca` as live CA | P2 |
| Request interception (hold/edit/drop) | ✅ | ✅ **verified real-time** | — | — |
| Response interception | ✅ | ✅ | — | — |
| HTTP history + persistence | ✅ (project=Pro) | ✅ SQLite | — | — |
| WebSocket **history** | ✅ | ✅ (`/api/wslog`) | — | — |
| WebSocket **interception** (edit frames) | ✅ | ✅ hold/edit/drop | — | — |
| Match & Replace | ✅ (script mode Pro) | ✅ literal+regex both dirs | Optional script/lambda mode | P3 |
| History search / filter / columns | ✅ | ✅ filter + CSV export | — | — |
| Scope include/exclude gating | ✅ | ✅ | Exclude patterns + per-tool scope | P2 |
| Resolve API header-shape consistency | ✅ | ✅ accepts both shapes | — | — |

## 2. Manual analysis tools

| Capability | Burp | SecureSuite | Gap → to build | Pri |
|---|---|---|---|---|
| Repeater (edit/resend) | ✅ | ✅ | Tabs, history, follow-redirects, render | P2 |
| Inspector (structured editor) | ✅ | ✅ query + cookies (Repeater) | — | — |
| Decoder | ✅ | ✅ | Smart-decode heuristics + chaining | P3 |
| Comparer | ✅ word/byte diff | ✅ LCS line/word | — | — |
| Sequencer | ✅ FIPS battery | ✅ Shannon entropy | Add more statistical tests | P3 |
| Organizer (save/annotate) | ✅ Pro | 🔲 | Save/tag/status store | P2 |

## 3. Automation

| Capability | Burp | SecureSuite | Gap → to build | Pri |
|---|---|---|---|---|
| Intruder — 4 attack types | ✅ (full=Pro) | ✅ all 4, full-speed | — | — |
| Intruder — payload **processing** rules | ✅ | 🔲 | encode/hash/prefix/substitution/skip | P2 |
| Intruder — grep match / extract | ✅ | 🔲 | flag + pull values from responses | P2 |
| Intruder — resource pool / throttle | ✅ | 🟡 (fixed concurrency) | Configurable rate/pool | P2 |
| Scanner — **passive** | ✅ Pro | ✅ (headers/cookies/leaks) | More checks | P2 |
| Scanner — **active** | ✅ Pro (huge check set) | 🟡 (SQLi + reflected XSS) | SSRF, traversal, redirect, cmdi, CORS, SSTI, XXE, JWT… | **P1** |
| Scanner — **crawler** | ✅ | 🔲 | Link/form crawl within scope | **P1** |
| Retro-scan of loaded history | ✅ | 🔲 | Scan SQLite-loaded history, not just live | P2 |
| Custom checks (BChecks) | ✅ | 🟡 (via webhooks) | Declarative check DSL | P3 |

## 4. Out-of-band & client-side

| Capability | Burp | SecureSuite | Gap → to build | Pri |
|---|---|---|---|---|
| OAST — HTTP | ✅ Collaborator (Pro) | ✅ canary `:8082` | — | — |
| OAST — **DNS** | ✅ | 🔲 | DNS canary listener + wildcard tokens | **P1** |
| OAST — **SMTP** | ✅ | 🔲 | SMTP canary listener | P2 |
| Private/self-host OAST | ✅ | 🟡 (it's already local) | Document deployable mode | P3 |
| DOM Invader (DOM-XSS, proto-pollution, postMessage) | ✅ Community | 🔲 | Injected content-script instrumentation | P2 |
| Clickbandit (clickjacking PoC) | ✅ | 🔲 | PoC generator | P3 |

## 5. Workflow, delivery & platform

| Capability | Burp | SecureSuite | Gap → to build | Pri |
|---|---|---|---|---|
| Project files (portable save/load) | ✅ Pro | 🟡 (SQLite, not portable) | One-file session export/import | P2 |
| Session handling + macros (auth) | ✅ Pro | 🔲 | Auto-login / token refresh | P2 |
| Logger (unified traffic log) | ✅ | ✅ `/api/log` + panel | — | — |
| Reporting (HTML/XML) | ✅ Pro | 🔲 | Issue report export | P2 |
| Embedded preconfigured browser | ✅ | 🔲 | Chromium pre-wired to proxy+CA | P2 |
| Native desktop window | ✅ | 🔲 (web console) | Tauri shell | P3 |
| Transparent/system-wide capture | ✅ (OS proxy) | 🟡 (`system-proxy.sh`; no TUN/pf) | `SO_ORIGINAL_DST`/`pf` transparent mode | P2 |
| Extension API + store | ✅ Montoya + 300+ BApps | 🟡 webhooks only | WASM in-proc API + registry | P3 |
| AI assist / agentic | ✅ Burp AI/AT (2026) | 🔲 | Optional local-LLM assist | P3 |
| Headless/CI/scheduled (DAST) | ✅ DAST tier | 🟡 (API is headless) | Scheduler, dashboards, RBAC | P3 |

## 6. Where SecureSuite already **wins**

| Dimension | Burp | SecureSuite |
|---|---|---|
| Price / licence | Paid (Pro/DAST) for the best features | **Free, AGPL, community-owned** |
| Footprint | ~640 MB (JVM + bundle) | **~12 MB single native binary** |
| Startup | JVM warm-up | **~18 ms warm** |
| Scanner / OAST / reporting | **Paywalled (Pro)** | **Free** |
| Headless / API-first | Add-on mindset | **Native HTTP+WS API from day one** |
| Extensions | Java/Kotlin (Montoya) | **Any language via HTTP webhooks** |
| Lock-in | Single vendor | **Permanent open commons** |

## 7. Bottom line

- **Core manual testing (capture, intercept, repeat, intrude, compare): ~90%
  there** and genuinely usable today — real-time interception is proven.
- **The real gaps are the automation/breadth tier** — a broader **active
  scanner + crawler** (P1), **DNS/SMTP OAST** (P1), **Inspector / history
  search / Logger** (P1 polish), then session macros, reporting, embedded
  browser, DOM Invader.
- **Strategic framing:** the gaps that matter are exactly the features Burp
  **charges for**. Closing P1 items gets SecureSuite to a credible free
  alternative for ~80% of real engagements; P2 closes most of the Pro gap.

### Suggested next build order
1. Active-scanner breadth + crawler *(biggest capability gap)*
2. DNS/SMTP OAST *(unlocks blind-bug confirmation)*
3. Intercept polish (WS frame edit, header-shape fix) + Inspector + history search
4. Logger + reporting *(deliverable value)*
5. Session handling/macros + project files *(real-engagement workflow)*
6. Publish + sign + CI *(so people can actually download it)*
