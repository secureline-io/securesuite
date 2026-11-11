# Burp Suite — clean-room visibility analysis

**Clean-room boundary (read first).** This document records what we learned by
observing the **distribution** of Burp Suite (installer packaging, version,
runtime shape) and by consulting **public documentation** for its feature
surface. We did **not** decompile `burpsuite.jar`; **no** proprietary code,
strings, UI assets, payload lists, or scan-check logic were read, extracted, or
ported. SecureSuite is an independent clean-room reimplementation — see
`PROVENANCE.md`.

## What the attachments are

| | macOS `.dmg` | Windows `.exe` |
|---|---|---|
| Product / version | Burp Suite **2026.10.1** (build 20261022135027) | Burp Suite **2026.10.1** |
| Download size | ~364 MB | ~420 MB |
| Packager | **install4j** (`CFBundleIdentifier com.install4j…`) | **install4j** GUI installer (PE32+) |
| Launcher | `JavaApplicationStub` → JVM | install4j native stub → JVM |
| App payload | `Contents/Resources/app/burpsuite.jar` (one monolith) | bundled `burpsuite.jar` |
| Bundled runtime | private JRE | bundled JRE (**Adoptium / Zulu**) |
| Installed footprint | ~**641 MB** | ~**400+ MB** |
| JVM tuning | `vmoptions.txt` | `.vmoptions` |

**Architecture (fact, for parity planning):** Burp is a **Java/Swing desktop
monolith** — essentially one large `.jar` run on a **bundled JRE**, wrapped by
install4j into a per-OS native launcher + installer. Cross-platform is achieved
by shipping the JVM on every platform.

## SecureSuite's distribution — a deliberate improvement

| Dimension | Burp Suite | SecureSuite |
|---|---|---|
| Runtime | bundled JRE (hundreds of MB) | **none** — single native binary |
| Binary size | `burpsuite.jar` + JRE, ~640 MB installed | **~12 MB** engine, ~6 MB `.dmg` |
| Language | Java/Swing | **Rust** (memory-safe) engine + web UI |
| UI | native Swing window | local web console (Tauri native-window shell planned) |
| Automation | REST API (Pro), paywalled | **API + WebSocket from day one, free** |
| Headless/CI | Pro feature | first-class |
| License | **proprietary**, paid Pro tier | **AGPL-3.0**, all features free & open |
| Extensions | Jython/Java (Montoya API) | **language-agnostic HTTP webhooks** (WASM planned) |

## Feature surface → SecureSuite status

The authoritative parity inventory lives in `feature-matrix.md`. Summary of
where the open-source reimplementation stands (all verified MVPs):

- **Shipped & verified:** intercepting HTTP/HTTPS proxy (req + resp intercept),
  Match & Replace, Repeater, Intruder (all 4 attack modes, free), Decoder,
  Target (site map + content discovery), Comparer, Sequencer, passive scanner,
  **active scanner** (SQLi + reflected XSS), scope, SQLite persistence,
  extension webhooks, OAST canary, macOS packaging.
- **Deferred (honest gaps):** DNS/SMTP OAST, native
  Swing-equivalent window (Tauri), embedded browser / DOM-XSS tooling,
  session-handling macros, dedicated crawler, payload-processing rules.

Parity estimate: **~65%** of a Burp 1.0 feature set by breadth; depth varies by
tool. The goal remains full parity **and** improvements, kept permanently free
and open.
