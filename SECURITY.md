# Security Policy

## Authorized use only

SecureSuite is offensive security tooling. Use it **only** against systems you own or are explicitly authorized in writing to test. Unauthorized testing is illegal in most jurisdictions and is not a supported use of this project.

## Reporting a vulnerability in SecureSuite itself

The SecureSuite engine processes hostile input by design (it proxies and attacks untrusted servers) and runs third-party extensions — so its own security matters a great deal.

- Please report suspected vulnerabilities **privately** first, via a GitHub Security Advisory (preferred) or the maintainer contact listed in the repository, before any public disclosure.
- Include a description, impact, and reproduction steps or a PoC.
- We aim to acknowledge within a few days and to coordinate a fix and disclosure timeline with you.

There is no paid bug bounty at this stage; credit will be given in release notes unless you prefer otherwise.

## Scope of particular interest

- Sandbox escapes in the extension runtime (`ss-ext`).
- Memory-safety or parsing bugs in the proxy/HTTP/TLS path (`ss-proxy`, `ss-ca`).
- SSRF/RCE via the local engine API or OAST server (`ss-oast`).
- CA private-key handling and leaf-cert minting weaknesses.

## Supported versions

Pre-alpha: only `main` is supported. Formal supported-version ranges will be published at the first tagged release.
