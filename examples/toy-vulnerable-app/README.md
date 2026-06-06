# Toy vulnerable local app

Known-bad local target for harness development and false-positive/false-negative checks.

Run:

```bash
python examples/toy-vulnerable-app/server.py --port 8765
```

Smoke/replay:

```bash
security-harness validate-target examples/toy-vulnerable-app/web-target.yaml
security-harness http-smoke examples/toy-vulnerable-app/web-target.yaml \
  --artifacts /tmp/security-harness-toy-smoke
security-harness replay-poc \
  examples/toy-vulnerable-app/web-target.yaml \
  examples/toy-vulnerable-app/pocs/unsafe-redirect.json \
  --artifacts /tmp/security-harness-toy-poc
```

Seeded signals:

- missing baseline security headers
- reflected XSS-style unescaped echo at `/reflect?q=...`
- unsafe redirect at `/redirect?next=...`
- IDOR-style unscoped object lookup at `/api/customer?id=...`

Keep this app localhost-only. It is intentionally vulnerable.
