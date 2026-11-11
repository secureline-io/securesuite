# SecureSuite Extension SDK

> **License: Apache-2.0** (not AGPL). You may write and distribute extensions under **any** license, including proprietary.

This directory holds SecureSuite's public extension API: the stable surface extensions build against, language bindings, and a **Burp-compatibility shim** that maps a Burp-like API *shape* (HTTP listeners, message editors, scanner checks, Intruder payload generators) onto SecureSuite events — so community extensions can be ported.

The shim reimplements an API *shape*; it contains no code from Burp Suite.

Status: 🚧 placeholder — lands in Phase 4 (`ss-ext`). See `../docs/architecture.md`.
