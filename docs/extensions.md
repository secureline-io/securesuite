# SecureSuite Extension SDK (HTTP webhooks)

SecureSuite extensions are **language-agnostic HTTP webhooks** — any program that
can serve HTTP can extend the scanner, in any language. Register one or more
endpoint URLs in the console (**Ext/OAST** panel) or via `POST /api/extensions`
with a JSON array of URLs.

## Contract

For every captured proxy exchange, SecureSuite sends:

```
POST <your-endpoint>
Content-Type: application/json

{ "id", "ts_ms", "method", "url", "host", "scheme", "status", "mime",
  "req_headers": [{ "name", "value" }], "req_body",
  "resp_headers": [{ "name", "value" }], "resp_body", ... }
```

Your endpoint may reply with a JSON **array of issues** to raise in the Issues
panel:

```json
[ { "severity": "high|medium|low|info", "name": "Your Check", "detail": "why" } ]
```

Return `[]` (or any non-array) to raise nothing. Calls time out after 5 s and run
concurrently; failures are ignored. Issues are deduped per `(name, host, endpoint)`.

## OAST (out-of-band)

`GET /api/oast/generate` returns `{ token, url }` for the built-in HTTP canary
listener (default `:8082`, env `SECURESUITE_OAST_PORT`). Plant the URL in a
payload; any HTTP callback to it is recorded and listed by
`GET /api/oast/interactions` (and shown live in the console).

A full DNS-based Collaborator is future work; the HTTP canary covers SSRF,
blind-injection callbacks, and webhook exfil today.
