# SecureSuite — Pending Development Roadmap

> **Scope:** only what's **left to build**. For the Burp gap analysis see
> `docs/burp-vs-securesuite.md`. Snapshot: 2026-11-01.

**Effort legend:** `S` < ½ day · `M` 1–2 days · `L` 3–5 days · `XL` > 1 week.

**Definition of Done (every item):** builds (`cargo build -p securesuite`) · tests
green (`cargo test --all`) · `clippy --all-targets -- -D warnings` clean ·
`cargo fmt --check` · **live-verified receipt** (demo against the lab/httpbin) ·
`docs/feature-matrix.md` updated · DCO-signed commit.

**Recommended order:** M1 (polish + the known bug) → M2 (scanner depth, the
biggest capability gap) → M3 (OOB + client-side) → M4 (workflow/delivery) →
M5 (ecosystem/scale/release).

---

## Milestone 1 — Manual-workflow polish & fixes  *(quick wins, highest usability ROI)*

- [x] **M1.1 — Fix `/api/intercept/resolve` header shape** `S` ✅ *(done 2026-11-01)*
  Accept both `{name,value}` objects **and** `[name,value]` pairs (queue returns
  the former, resolve only accepts the latter → HTTP 422, found in live testing).
  Files: `engine/crates/securesuite/src/web.rs` (`ResolveReq`, custom deserialize).
  Accept: queue → edit → resolve round-trips with no 422; add a regression test.
- [x] **M1.2 — WebSocket frame interception** `M` ✅ *(done 2026-11-01)*
  Hold/edit/drop WS frames, not just log them. Files: `wscap.rs`, `store.rs`
  (frame hold queue), `web.rs` (`/api/ws/intercept*`), `assets/index.html` (WS panel).
  Accept: a `wss://` frame is held, edited, forwarded; verified via a live demo.
- [x] **M1.3 — Inspector (structured editor)** `M` ✅ *(done 2026-11-01)*
  Query / headers / cookies / body as editable key-values with safe re-encoding.
  Files: `assets/index.html` (+ small `web.rs` parse helpers).
  Accept: edit a header via the key-value UI and resend from Repeater.
- [x] **M1.4 — History search / filter / export** `M` ✅ *(done 2026-11-01)*
  Filter by host/method/status/scope + columns + JSON/CSV export. Files:
  `web.rs` (`/api/exchanges` query params, `/api/export`), `assets/index.html`.
  Accept: filter narrows the table; export produces a valid file.
- [x] **M1.5 — Logger (unified traffic log)** `M` ✅ *(done 2026-11-01)*
  One filterable log of **all** engine-generated traffic, tagged by tool (proxy /
  repeater / intruder / scanner). Files: `store.rs` (source tag), `web.rs`
  (`/api/log`), `assets/index.html`. Accept: tool-tagged, filterable, exportable.
- [x] **M1.6 — First-run onboarding** `S` ✅ *(done 2026-11-01)*
  In-console CA-install helper + one-click `system-proxy.sh` toggle, to kill the
  "blank console = broken" confusion. Files: `assets/index.html`, `web.rs`.
  Accept: a new user can route + trust the CA in under a minute.

## Milestone 2 — Scanner depth  *(the biggest capability gap vs Burp Pro)*

- [ ] **M2.1 — Dedicated crawler** `L`
  Follow in-scope links/forms, build the site map automatically, feed the active
  scanner. New file: `engine/crates/securesuite/src/crawl.rs`; `web.rs`
  (`/api/crawl`). Accept: crawl a lab app → site map auto-populates within scope.
- [ ] **M2.2 — Active-scanner breadth** `L`
  Add independent, false-positive-gated checks: SSRF, path traversal, open
  redirect, OS command injection, header/host injection, CORS misconfig, SSTI,
  XXE, directory listing, JWT weaknesses, mixed content. Our own logic, OWASP-
  referenced. Files: `active.rs` (one predicate per check + tests).
  Accept: each check fires on a lab fixture and **not** on a benign control.
- [ ] **M2.3 — Retro-scan loaded history** `S`
  Scan history reloaded from SQLite on startup (today only live `push()` scans).
  Files: `scan.rs`, `store.rs`, `main.rs`. Accept: restart → old history → issues.
- [ ] **M2.4 — Intruder payload processing + grep** `M`
  Processing rules (encode/hash/prefix/suffix/substitution/skip) +
  grep-match / grep-extract + configurable rate/resource pool. Files: `web.rs`
  (intruder handler), `assets/index.html`. Accept: processed payloads sent;
  extracted values surfaced per request.

## Milestone 3 — Out-of-band & client-side

- [ ] **M3.1 — DNS OAST** `M`
  DNS canary listener + wildcard-subdomain tokens beside the HTTP canary. New
  DNS listener; `web.rs` (`/api/oast/*`). Accept: a DNS lookup of a token is recorded.
- [ ] **M3.2 — SMTP OAST** `M`
  SMTP canary listener. Accept: an SMTP connection to a token is recorded.
- [ ] **M3.3 — DOM Invader equivalent** `L`
  Injected content script reporting controllable sinks, DOM-XSS, prototype
  pollution, and `postMessage` flows to a collector endpoint. Accept: a DOM-XSS
  sink is flagged on a lab page.
- [ ] **M3.4 — Embedded browser** `M`
  Launch a Chromium pre-wired to proxy + trusted CA (zero setup). Accept: launch
  → browse → traffic captured with no manual proxy/CA steps.

## Milestone 4 — Workflow & delivery

- [ ] **M4.1 — Project files** `M` — portable one-file save/load of a session
  (history/scope/rules/issues). Accept: export → import restores state.
- [ ] **M4.2 — Session handling + macros** `L` — auto-login / token-refresh so
  scans stay authenticated. Accept: a scan survives a login macro.
- [ ] **M4.3 — Organizer** `M` — save/tag/annotate/status on requests.
- [ ] **M4.4 — Reporting** `M` — HTML/JSON issue reports (severity, evidence,
  remediation). Accept: export a report for the current issues.
- [ ] **M4.5 — Native desktop window (Tauri)** `M` — wrap the console in a native
  shell with proxy lifecycle management.

## Milestone 5 — Ecosystem, scale & release

- [ ] **M5.1 — Wire `ss-ca` as the live CA** `M` — replace the inline CA path with
  the tested `ss-ca` crate.
- [ ] **M5.2 — Transparent / system-wide capture** `L` — `SO_ORIGINAL_DST` (Linux)
  / `pf` (macOS) so even non-proxy-aware apps are captured (true "all traffic").
- [ ] **M5.3 — Extension SDK v2** `L` — keep webhooks, add a WASM in-proc path +
  a simple extension registry.
- [ ] **M5.4 — Publish + sign** `M` — push to GitHub, CI on native runners for
  **x86_64-Linux**, **.msi**, and **code-signed/notarized** mac/Windows artifacts
  + a Releases download page. *(Unblocks everything a real download needs.)*
- [ ] **M5.5 — DAST tier** `XL` — headless/CI/scheduled scanning, dashboards,
  RBAC/SSO.
- [ ] **M5.6 — Optional AI assist** `L` — local-LLM issue explanations / agentic
  testing (opt-in; ties to the owner's existing ML harness).

---

## Progress tracking

Tick boxes as items land. Keep `docs/feature-matrix.md` and
`docs/burp-vs-securesuite.md` in sync. Target parity after **M1+M2 ≈ 80%** of
real-engagement needs; after **M4 ≈ Burp Pro workflow parity**.

**Next up:** Milestone 1 complete ✅ (M1.1–M1.6) → **Milestone 2 — scanner depth** (crawler + active-check breadth).
