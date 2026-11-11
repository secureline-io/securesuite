# Licensing

SecureSuite uses a deliberate two-license structure to serve one goal: **the platform can never be taken proprietary, while the extension ecosystem stays maximally open.**

## The platform — AGPL-3.0-or-later

Everything under `engine/`, the desktop app, and any network/server components (e.g. the OAST/Collaborator server) is licensed **GNU Affero General Public License v3.0 or later**.

Why AGPL and not MIT/Apache:

- **Anti-monopoly guarantee.** Anyone may use, study, modify, and redistribute SecureSuite — but any *distributed* or *network-hosted* modified version must also be released under the AGPL, with source. Nobody — including a well-funded company — can take SecureSuite, improve it privately, and sell or host a closed, better version. That is exactly the dynamic we exist to prevent.
- **Closes the SaaS loophole.** Plain GPL only triggers on distribution of binaries. A scanning/proxy platform has an obvious hosted-service future; AGPL's §13 extends the copyleft to users interacting with a modified version *over a network*.
- **Using the tool is not distribution.** Running SecureSuite to test a system — even a client's, even at an employer — does not trigger any AGPL obligation. Pentesters can use it freely at work. Obligations arise only if you *distribute a modified SecureSuite* or *offer a modified SecureSuite as a network service*.

## The extension SDK — Apache-2.0

Everything under `ext-sdk/` (the public extension API, bindings, and compatibility shim) is licensed **Apache-2.0**.

Why permissive here:

- Extension authors can release their extensions under **any** license, including proprietary — just like Burp's BApp ecosystem includes closed-source extensions. This maximizes ecosystem growth.
- Apache-2.0 adds an explicit patent grant, valuable for a security tool.

## Contributions — Developer Certificate of Origin (DCO)

Contributions are accepted under the [DCO](https://developercertificate.org/) via a `Signed-off-by` line (`git commit -s`). We deliberately use the DCO rather than a corporate CLA:

- No single entity is assigned copyright, so **no single entity can ever relicense SecureSuite closed.** Copyright stays distributed across the whole contributor community — a structural guarantee of the commons.

## Relicensing note

While the contributor base is small, a future community vote could still migrate licenses (e.g. to GPL-3.0 or Apache-2.0) if contributors agree. This gets structurally harder — by design — as contributors grow. Raise it early if you disagree with these defaults.
