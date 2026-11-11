# SecureSuite Architecture

> Status: living document. Reflects the intended design; modules land per the roadmap.

## Guiding choices

- **Rust engine, web UI.** The heavy lifting (proxying, TLS interception, parsing hostile input, scan orchestration) is in Rust for throughput and memory safety. The UI is web tech in a Tauri shell. This is the proven Caido-style split; it also yields a headless/server mode for free.
- **Everything is an API client.** The desktop UI, the CLI, and future automation all talk to the engine through one local **HTTP + WebSocket API**. No logic hides in the UI.
- **Clean-room.** Behavior and specs in, fresh implementation out. No proprietary code. See `PROVENANCE.md`.

## Repository layout

```
securesuite/
  engine/
    crates/
      ss-ca/         # root CA + per-host leaf certificate minting (TLS MITM)
      ss-proxy/      # intercepting HTTP/1.1 + HTTP/2 proxy, WebSocket relay
      ss-store/      # exchange storage, search, project persistence (SQLite)
      ss-core/       # shared types: HttpExchange, Scope, ids, events
      ss-api/        # local HTTP+WS API surface the UI/CLI consume
      ss-repeater/   # manual edit-and-resend
      sl-intruder/   # payload-position fuzzing engine
      sl-decoder/    # encode/decode/hash transforms
      sl-comparer/   # message diffing
      sl-sequencer/  # token randomness analysis
      ss-scanner/    # passive + active scan pipeline, template engine
      ss-oast/       # out-of-band interaction (Collaborator-equivalent) server
      ss-ext/        # extension runtime (WASM + scripting) + Burp-compat shim
      sl-sessions/   # session-handling rules, macros, cookie jar
      ss-browser/    # driven/bundled Chromium integration
      sl-cli/        # headless entrypoint
  ui/                # Tauri + web frontend (TypeScript)
  ext-sdk/           # public extension API (Apache-2.0)
  lab/               # docker-compose vulnerable targets for testing
  docs/              # this folder
```

## Core data model (`ss-core`)

- `HttpExchange` — one request/response pair with metadata (id, timestamps, host, port, tls, protocol, size, source tool, tags, notes).
- `HttpRequest` / `HttpResponse` — method, target, version, headers (ordered, case-preserving), body (bytes), trailers.
- `Scope` — include/exclude rules (host/port/path/protocol, regex or literal) governing what every tool acts on.
- `Event` — append-only stream (new exchange, scan issue, intercept hold, task state) broadcast over the API WebSocket.

## Data flow

```
browser ──TLS──▶ ss-proxy ──┬─▶ ss-store (persist) ──▶ ss-api (query)
                            │                             ▲
                  ss-ca (mint leaf cert)                  │ WS events
                            │                             │
                   intercept queue ◀───────────── UI / CLI (forward/drop/edit)
                            │
                 upstream server ◀── re-originated TLS
```

Repeater, Intruder, and Scanner are *producers* of exchanges that flow through the same store and event bus, tagged by originating tool.

## Local API (engine ⇄ UI/CLI)

- REST for queries and commands (`GET /exchanges`, `POST /repeater/send`, `PUT /scope`, `POST /intruder/attacks`, ...).
- One WebSocket for the live event stream (new traffic, intercept prompts, scan progress/issues).
- Bound to loopback by default, token-authenticated, so the engine can also run on a remote host with the UI/CLI attached.

## Extensions (`ss-ext` + `ext-sdk`)

- **Primary runtime: WASM** (via a Wasm engine) — safe, sandboxed, language-agnostic (write extensions in Rust, Go, AssemblyScript, etc.).
- **Scripting bridge** for quick/dynamic extensions.
- **Burp-compat shim** mapping a Burp-like API *shape* (listeners, message editors, scanner checks, intruder payloads) onto SecureSuite events, so community extensions can be ported. This reimplements an API surface — it copies no Burp code.
- SDK is Apache-2.0 so extensions may use any license.

## Persistence (`ss-store`)

- Working store: SQLite (bundled, no system dependency).
- **Project files**: a documented, ideally text/JSON-exportable format so test artifacts are diffable and git-versionable — an improvement over opaque binary project files.

## Security model

- CA private key stored with strict file permissions; never logged; never committed (enforced by `.gitignore`).
- The engine parses hostile input: fuzz-tested parsers, strict limits, no panics-as-DoS.
- Extension sandbox is a trust boundary; capabilities are explicit and grantable.
- OAST server isolates interaction data per-session.
