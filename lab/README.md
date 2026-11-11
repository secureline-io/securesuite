# SecureSuite Practice Lab

Local, deliberately vulnerable targets to develop and test SecureSuite against — so we can verify behavior without ever touching a system we don't own.

```bash
docker compose up -d     # start targets
docker compose ps        # check
docker compose down      # stop
```

| Target | URL | Purpose |
|---|---|---|
| OWASP Juice Shop | http://localhost:3000 | Modern SPA, rich API, many vuln classes |
| DVWA | http://localhost:8080 | Classic vuln playground (SQLi, XSS, etc.) |
| httpbin | http://localhost:8081 | Echoes requests; great for proxy/encoding conformance tests |

## Safety

- All ports bind to `127.0.0.1` only.
- These images are **intentionally insecure**. Never expose them beyond your machine.
- The lab is the project's *oracle*: SecureSuite's integration tests assert behavior against these targets. We compare **our own** captures — never another tool's code.

> Legal reminder: SecureSuite and this lab are for **authorized** testing. Using the tool against third-party systems without written permission is illegal.
