# Provenance & Clean-Room Ledger

SecureSuite must remain legally distributable as open source. This file records **where each non-trivial design or implementation drew its knowledge from**, and proves we did not copy proprietary expression.

## The rule

- ✅ Public specifications (RFCs, W3C, OWASP, IANA registries).
- ✅ Observed, black-box **behavior** of other tools (what goes on the wire) — behavior and protocols are not copyrightable.
- ✅ **Permissively licensed** open-source references, with their license honored and recorded below.
- ❌ Copying/translating code, strings, assets, wordlists, or scan-check logic from Burp Suite or any proprietary tool.
- ❌ Shipping another project's content under an incompatible license.

If you contribute, add a row for any external source you leaned on.

## Reference sources (study / compatibility)

| Source | License | Used for | Notes |
|---|---|---|---|
| IETF RFCs (7230–7235, 9110–9114, 6455) | Public | HTTP/1.1, HTTP/2, HTTP/3, WebSocket semantics | Primary spec authority |
| OWASP Testing Guide / WSTG | CC-BY-SA | Scanner check design, methodology | Attribute per CC-BY-SA |
| OWASP ZAP | Apache-2.0 | Passive/active scan rule *concepts*, spider design | Compatible; attribute if code adapted |
| mitmproxy | MIT | Proxy/TLS-MITM architecture *concepts*, addon model | Compatible |
| nuclei templates | MIT | Template-driven scan-check format inspiration | Template content must be license-checked individually |
| SecLists | MIT | Candidate wordlists/payloads | Ship only MIT-compatible lists, attributed |
| rustls / rcgen / hyper / tokio | MIT/Apache-2.0 | Engine dependencies | Standard crate deps |

## Burp Suite — study scope (NOT a code source)

We studied Burp Suite **2026.9.2** only as a black box and via **public documentation**:

- Bundle structure (install4j launcher, bundled JRE, obfuscated `burpsuite.jar`, JNA, bundled Chromium) — observed via standard file inspection.
- Publicly documented feature set and UX (PortSwigger docs).
- The **publicly shipped** `burp.*` extension interface names (documented API surface) — used to design a compatible API *shape*, not copied.
- On-the-wire behavior against lab targets.

We did **not** decompile its obfuscated implementation classes into SecureSuite, nor copy any asset, payload list, or scan definition. The jar is obfuscated regardless, making decompilation both low-value and off-limits.

### Feature roadmap / teardown (2026 analysis)

`docs/roadmap-burp.md`, `docs/roadmap-securesuite.md`, and
`docs/burp-vs-securesuite.md` were written from **public PortSwigger
documentation** plus **observed black-box behaviour** of a running instance
(confirmed live on `127.0.0.1:8080`) — no decompilation, no copied text/payloads.
Public sources consulted:

- https://portswigger.net/burp/documentation/desktop/tools — tool reference
- https://portswigger.net/support/burp-suite-tools — tool summaries
- https://portswigger.net/burp/documentation — per-tool docs (Proxy, Intruder, Scanner, Collaborator, DOM Invader, Sequencer, etc.)
