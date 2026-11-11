# Contributing to SecureSuite

Thank you for helping build a community-owned security testing platform. This project only works if it's genuinely *ours* — contributions of code, docs, scan checks, extensions, and testing are all welcome.

## The one hard rule: clean-room

SecureSuite must stay legally distributable as open source. Therefore:

- **Never** paste, translate, or adapt code, strings, assets, payload lists, or scan-check logic from Burp Suite or any other proprietary/closed product.
- **Do** build from public specifications (RFCs, W3C, OWASP), observed on-the-wire behavior, and permissively licensed open-source references (OWASP ZAP, mitmproxy, nuclei templates, SecLists — respecting their licenses).
- Record any external source you drew on in [`docs/PROVENANCE.md`](docs/PROVENANCE.md).

If you have decompiled a proprietary tool to understand it, that knowledge does **not** entitle you to copy its expression. Describe behavior; reimplement freshly.

## Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying you wrote the change (or have the right to submit it) under the project's license:

```bash
git commit -s -m "feat(proxy): add HTTP/2 upstream support"
```

This appends a `Signed-off-by: Your Name <you@example.com>` line. PRs with unsigned commits will be asked to amend. See [LICENSING.md](LICENSING.md) for why we use DCO instead of a CLA.

## Dev setup

```bash
# Rust toolchain (stable) — https://rustup.rs
rustup component add rustfmt clippy

# UI toolchain
corepack enable && pnpm --version    # Node >= 20

# Practice lab (local, deliberately vulnerable targets)
cd lab && docker compose up -d
```

## Before you push

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

CI runs all three and will block merges on failure.

## Conventions

- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`), scoped to a module where useful (`feat(scanner): ...`).
- **Branches:** `feat/<slug>`, `fix/<slug>`, `docs/<slug>`.
- **TDD:** new behavior ships with tests. Write the failing test first where practical.
- **Crates:** engine modules live in `engine/crates/sl-*`. One responsibility per crate.
- **No secrets, no live targets** in tests — use the lab or local fixtures.

## Good first areas

- Decoder transforms (`sl-decoder`), Comparer diff (`sl-comparer`) — self-contained and well-specified.
- Passive scan checks as community templates (`ss-scanner`).
- Protocol conformance fixtures for the proxy (chunked, gzip, HTTP/2, websockets).

## Reporting bugs / proposing features

Open an issue with clear reproduction steps (for bugs) or a short motivation + sketch (for features). Security issues in SecureSuite itself: see [SECURITY.md](SECURITY.md).
