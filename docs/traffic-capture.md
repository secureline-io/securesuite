# How SecureSuite captures traffic

SecureSuite is an **intercepting MITM proxy**. A client's traffic is captured
when it is routed through the proxy (default `127.0.0.1:8080`) and — for HTTPS —
when the client **trusts the SecureSuite CA** (`~/.securesuite/ca-cert.pem`,
download from the console or `GET /api/ca.pem`). It does **not** silently sniff
the machine; something has to send traffic to the proxy. There are three ways to
do that, least to most invasive.

## 1. Per-app / browser proxy (default, recommended)

Point one app at the proxy — the classic Burp workflow, rest of the machine
untouched.

- **Browser:** set HTTP & HTTPS proxy to `127.0.0.1:8080`.
- **CLI:** `export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080`
  or `curl -x http://127.0.0.1:8080 --cacert ~/.securesuite/ca-cert.pem https://…`

## 2. System-wide proxy (all proxy-aware apps)

Set the OS proxy so every proxy-respecting app routes through SecureSuite:

```
./scripts/system-proxy.sh on     "Wi-Fi" 127.0.0.1 8080   # enable
./scripts/system-proxy.sh status "Wi-Fi"                  # inspect
./scripts/system-proxy.sh off    "Wi-Fi"                  # revert
```

Captures most apps system-wide via macOS `networksetup`. **Caveat:** apps that
ignore the system proxy (some CLIs, cert-pinned apps, apps with their own proxy
logic) are not captured. Fully reversible.

## 3. Transparent / "all traffic" capture (incl. non-proxy-aware apps)

Capturing *literally all* TCP HTTP(S) — even apps that ignore proxy settings —
requires redirecting packets at the firewall to the proxy port **and** running
the proxy in transparent mode:

- **macOS:** a `pf` anchor redirecting `:80`/`:443` to the proxy port (root).
- **Linux:** `iptables -t nat … -j REDIRECT --to-port <proxy>`.

**Status — partial / honest:** the firewall redirect is standard OS tooling, but
the engine's transparent mode (recovering the original destination for
connections that arrive **without** a `CONNECT`, via `SO_ORIGINAL_DST` on Linux
or a `pf` state lookup on macOS) is **not implemented yet** — today the engine
expects explicit-proxy semantics (`CONNECT` / absolute-form requests). So #3 is
roadmap work; #1 and #2 work now.

## WebSocket

WebSocket traffic **is captured.** The proxy installs a WebSocket handler that
records every frame — both directions, opcode, size, and a payload preview — and
shows them live in the console's **WS** panel (also `GET /api/wslog`). Secure
WebSockets (`wss://`) are captured when the client trusts the SecureSuite CA,
exactly like HTTPS.

## Summary

| You want to capture… | Use |
|---|---|
| One browser / app | #1 per-app proxy |
| Whole machine, proxy-aware apps | #2 `system-proxy.sh on` |
| All traffic incl. stubborn apps | #3 transparent (redirect works; engine mode = roadmap) |
| WebSocket frames | automatic — open the **WS** panel |

For HTTPS/wss in every mode, trust the CA once.
