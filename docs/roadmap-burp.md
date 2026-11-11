# Burp Suite — feature teardown & roadmap (clean-room reference)

> **Clean-room note.** This document is built from PortSwigger's **public
> documentation** and **observed, black-box feature behaviour** of a running
> Burp Suite instance (confirmed live on `127.0.0.1:8080`, pid observed).
> We do **not** decompile Burp, and we never copy its code, strings, payload
> lists, or scan-check logic. We study *what* each tool does and *why*, then
> implement our own expression in SecureSuite. Public sources are logged in
> `docs/PROVENANCE.md`.

## 1. The product shape

Burp Suite is a **manual-first, tool-augmented** web security testing platform.
Everything is organised around **one shared captured-traffic stream**: the Proxy
sees traffic, and every other tool (Repeater, Intruder, Scanner, Comparer…)
operates on requests pulled from that stream. State lives in a **project file**.

**Editions** (this matters for a parity plan — half of Burp's value is behind the
Pro paywall):

| Edition | What you get | Price model |
|---|---|---|
| **Community** (free) | Intercepting HTTP/WebSocket proxy, HTTP history, Repeater, Decoder, Sequencer, Comparer, Logger, a **demo-rate-limited** Intruder, manual tools. **No Scanner. No project files. No Collaborator.** | Free |
| **Professional** | Everything in Community **+ full-speed Intruder, Burp Scanner (crawl + audit), Collaborator (OAST), project files, session handling, search, reporting, extension APIs, AI assist** | Per-user/year |
| **DAST** (ex-Enterprise) | Automated scanning at portfolio scale: scheduled/CI scans, dashboards, RBAC/SSO, integrations, cloud or self-host | Org licence |
| **Burp AI / Burp AT** (2026) | AI-assisted explanations + **agentic testing** (public beta, credit-metered) | Add-on |

> **Strategic takeaway for SecureSuite:** the biggest, most defensible wins are
> the features Burp charges for — **Scanner, Collaborator, project files,
> session handling, reporting**. Making those free/AGPL is the whole point.

## 2. The core workflow (why the tools are shaped the way they are)

```
 Browser ──▶ Proxy (intercept / history) ──▶ Target (site map + scope)
                   │                                   │
          send to  ▼                                   ▼
            Repeater (manual probe) ◀── Inspector ──▶ Intruder (automate)
                   │                                   │
                   ▼                                   ▼
            Collaborator (out-of-band)         Scanner (crawl + audit)
                   │                                   │
                   └────────────▶ Issues / Reporting ◀─┘
```

The reasoning: **capture → understand → hypothesise → probe → automate →
confirm (incl. out-of-band) → report**, with everything extensible via the API.

## 3. Tool-by-tool teardown

### 3.1 Proxy  *(Community)*
- **What:** an intercepting man-in-the-middle proxy between browser and server.
  Intercept (hold/edit/drop requests **and** responses), **HTTP history**,
  **WebSockets history**, **Match & Replace** rules (auto-rewrite headers/body
  on the wire — Java script-mode is Pro-only), TLS pass-through, proxy listeners.
- **Logic:** Burp mints a per-host leaf cert from its own CA so it can read TLS.
  Interception is a *hold queue* — the connection is paused until the tester
  forwards/drops. History records everything even when intercept is off.
- **Why it's the foundation:** every other tool consumes requests captured here.

### 3.2 Burp's Browser + Inspector  *(Community)*
- **What:** a bundled Chromium pre-wired to the proxy with the CA trusted, so
  there's zero cert/proxy setup. **Inspector** is a structured side panel to
  view/edit request/response components (query, headers, cookies, body) as
  editable key/values instead of raw text.
- **Logic:** removes the #1 onboarding friction (installing a CA) and makes
  editing structured parts safe (auto re-encodes).

### 3.3 Target  *(Community; advanced bits Pro)*
- **What:** the **Site map** (tree of hosts/paths/params discovered from
  traffic), **Scope** control (include/exclude rules that gate every tool),
  **Issue definitions** (the catalogue of what Scanner can find), and content
  discovery / attack-surface analysis.
- **Logic:** scope is the master filter that keeps you legal and keeps noise out;
  the site map is the mental model of the attack surface.

### 3.4 Repeater  *(Community)*
- **What:** manually edit and resend a single request, see the response; many
  tabs; request history per tab; follow redirects; render responses.
- **Logic:** the core *hypothesis loop* — change one thing (an ID, a header, a
  content-type, a GraphQL query), resend, compare. Automation can't replace it.

### 3.5 Intruder  *(Community = rate-limited; Pro = full)*
- **What:** automated customised attacks. Mark **payload positions** (`§…§`),
  choose an **attack type**, supply **payload sets**, apply **payload
  processing** rules (encode, hash, prefix/suffix, substitution, skip),
  **grep-match / grep-extract** to flag or pull values from responses, and a
  **resource pool** to throttle concurrency.
- **Attack types (the key design):**
  | Type | Payload placement | Request count |
  |---|---|---|
  | Sniper | one set, each position in turn | positions × payloads |
  | Battering ram | one set, all positions at once | one per payload |
  | Pitchfork | a set per position, advanced in parallel | size of smallest set |
  | Cluster bomb | a set per position, every combination | product of all sets |
- **Logic:** fuzzing, enumeration, boundary/credential testing. The attack type
  decides the combinatorics — pick wrong and you drown in requests.

### 3.6 Scanner  *(Professional)*
- **What:** automated **crawl** (build the site map, handle JS/forms/auth) +
  **audit** (passive checks on observed traffic + active checks that inject
  payloads). Scan configurations tune speed/coverage. **BChecks** let users add
  custom checks via a small DSL.
- **Logic:** passive = never touches the app, infers from responses (missing
  headers, info leaks); active = injects and watches for signal (errors,
  reflection, time delays, out-of-band hits). This is the single biggest Pro
  feature and the hardest to build well (low false positives = years of tuning).

### 3.7 Sequencer  *(Community)*
- **What:** statistical analysis of randomness in tokens (session IDs, CSRF/reset
  tokens). Runs entropy + a battery of FIPS-style tests, reports effective bits.
- **Logic:** weak session tokens = account takeover; this quantifies predictability.

### 3.8 Decoder  *(Community)*
- **What:** encode/decode/hash (URL, base64, HTML, hex, gzip, ASCII-hex…) with
  **smart-decode** heuristics, chainable transforms.

### 3.9 Comparer  *(Community)*
- **What:** visual **word/byte diff** between two items (e.g. two responses to
  spot how a param changes behaviour, or two users' views of a resource).

### 3.10 Logger  *(Community basic; Pro full)*
- **What:** a unified, filterable log of **all** HTTP traffic Burp generates
  across every tool, with search/filter/export.
- **Logic:** forensic trail + "what exactly did Intruder/Scanner send?".

### 3.11 Organizer  *(Professional)*
- **What:** save, tag, annotate, and set status on interesting requests to
  revisit later — a lightweight work-tracking layer over captured traffic.

### 3.12 Collaborator  *(Professional)*
- **What:** an **out-of-band (OAST)** service. Burp hands you unique
  subdomains/payloads; inject them; Burp polls the Collaborator server for
  **DNS / HTTP / SMTP** interactions proving the target reached out.
- **Logic:** the *only* way to confirm **blind** bugs — blind SSRF, blind XSS,
  blind/async injection, external entity — that produce no visible response.
  Private/self-hosted server option for sensitive engagements.

### 3.13 DOM Invader  *(Community, inside Burp's Browser)*
- **What:** a DevTools-integrated tool for **client-side** bugs: an augmented DOM
  showing controllable **sinks** + sanitisation context, **DOM XSS** detection,
  **prototype-pollution** source + gadget scanning, **DOM clobbering**, and
  log/modify/resend of **`postMessage()`** web messages.
- **Logic:** server-side proxies can't see DOM XSS — it lives entirely in the
  browser, so you need in-page instrumentation.

### 3.14 Clickbandit  *(Community)*
- **What:** records a clickjacking attack and generates a working PoC HTML page.

### 3.15 Extensibility  *(APIs: Pro for full)*
- **BApp Store:** 300+ community/commercial extensions (a real moat).
- **Montoya API:** Java/Kotlin extension API — register handlers, add tabs,
  augment Scanner, drive Repeater/Intruder.
- **BChecks:** declarative DSL for custom Scanner checks.
- **Bambdas:** small Java snippets for filtering/handling inside Burp (e.g.
  custom proxy-history filters, custom columns).

### 3.16 Project, session handling & config  *(Project files = Pro)*
- **Project files** (persist full state), **session handling rules + macros**
  (auto-login, refresh CSRF tokens, re-auth mid-scan), **upstream proxies**,
  **scan configs**, **settings** (project + user level).
- **Logic:** macros/session rules are what let automated tools stay
  authenticated — without them, Scanner/Intruder get logged out instantly.

### 3.17 Reporting  *(Professional)*
- **What:** export found issues to HTML/XML with severity, confidence,
  evidence, remediation. The deliverable clients actually pay for.

### 3.18 Burp AI / Burp AT  *(2026, add-on)*
- **What:** AI explanations of issues, AI-assisted Repeater, and **Burp AT** —
  agentic testing that drives the toolchain semi-autonomously (beta).

## 4. Maturity ladder (how a Burp-equivalent grows)

1. **Capture core** — proxy + TLS MITM + history + scope. *(table stakes)*
2. **Manual tools** — Repeater, Decoder, Comparer, Sequencer, Inspector.
3. **Automation** — Intruder, then Scanner (passive → active → crawler).
4. **Out-of-band** — Collaborator (DNS/HTTP/SMTP).
5. **Client-side** — DOM Invader, embedded browser.
6. **Workflow** — project files, session macros, Organizer, reporting.
7. **Extensibility** — extension API + store.
8. **Scale** — headless/CI/scheduled scanning, dashboards, RBAC (DAST tier).
