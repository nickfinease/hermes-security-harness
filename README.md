# Hermes Security Harness

Hermes-native defensive security harness for authorized, source-backed web targets.

The harness combines deterministic scanners, source-aware reconnaissance, structured artifact contracts, and optional Hermes/LLM-assisted reasoning. It is built for local and staging assessments where the operator controls the target and can provide explicit scope.

## Safety posture

- Local/staging targets only by default.
- Explicit `allowedHosts` checks on every target config.
- Public production URLs are rejected. Public staging domains require an operator-controlled allowlist via `SECURITY_HARNESS_APPROVED_STAGING_HOSTS`; target-controlled YAML alone cannot approve a public host.
- Metadata IPs and redirect escapes are blocked.
- Dynamic PoC replay is gated behind sandbox/egress/no-credential/ephemeral-home checks for mutation-capable PoCs.
- Agent/static runs capture transcripts and command metadata as artifacts.
- Scan artifacts are written under `runs/` or `runs-*` directories and should not be committed.

## Current capabilities

| Area | Commands / modules | Notes |
|---|---|---|
| Target validation | `validate-target` | Validates `web-target/v1` YAML/JSON configs and safety gates. |
| HTTP smoke | `http-smoke` | Deterministic GET-only reachability plus security-header checks. |
| Source/static review | `static-scan` | Source inventory, threat model, structured findings, optional Hermes runner review. |
| Reconnaissance | `recon` | Forms, OpenAPI/Swagger, sitemap, JS bundle, hidden endpoints, filesystem/source-dir route discovery, staged unauth/auth support in Python API. |
| Injection testing | `injection-scan` | XSS, SQLi, SSRF payload testing with smoke/recon/auth surface support in the full `scan` flow. |
| Auth/session testing | `auth-scan` | Login flow, cookie checks, bypass tests, rate checks. |
| WSTG modules | `csrf`, `http-verb`, `idor`, `jwt`, `stored-xss` | OWASP WSTG-aligned focused scanners. |
| TLS | `security_harness.tls_scan` Python module | TLS/SSL configuration testing module. CLI wiring is not yet exposed. |
| Dependencies | `dependency-audit` | Lockfile parsing and CVE cross-reference. |
| Rate limiting | `rate-limit` | Burst checks against configured endpoints. |
| PoC replay | `replay-poc` | Structured HTTP PoC replay with sandbox gates. |
| Chain correlation | `chain` | Deterministic vulnerability chain correlation across findings. |
| Reporting | `report` | Structured report generation from findings JSON files. |
| Full scan | `scan` | Orchestrates smoke → static → auth → recon → injection → chain → LLM chain reasoning/report. |
| Async jobs | `job-start`, `job-status`, `job-report`, `job-worker` | JSON job registry/worker for gateway-safe polling. |

## Install and test

```bash
cd /home/beans/hermes-security-harness
uv venv
uv pip install -e '.[dev]'
.venv/bin/python -m pytest tests/ -q
.venv/bin/python -m security_harness.cli --help
```

If `security-harness` is on your PATH after editable install, the examples below can use `security-harness` directly. Otherwise use `.venv/bin/python -m security_harness.cli`.

## Target config

Create a `web-target/v1` config for an authorized local/staging target:

```yaml
schemaVersion: web-target/v1
id: my-target
name: My Target
environment: local
baseUrl: http://localhost:3000
allowedHosts:
  - localhost
  - 127.0.0.1
sourceDir: /path/to/source  # optional; enables source-backed route discovery
scope:
  includePaths: ["/", "/login", "/api/health"]
  excludePaths: ["/.env", "/debug"]
  maxRequests: 100
  maxRuntimeSeconds: 300
detectors:
  enabled: [reachability-smoke, security-headers-smoke]
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
```

## Quick smoke

```bash
security-harness validate-target examples/web-target.local.yaml

security-harness http-smoke examples/web-target.local.yaml \
  --artifacts runs/http-smoke

security-harness static-scan examples/web-target.local.yaml \
  --source-root . \
  --artifacts runs/static-smoke \
  --toolsets file \
  --skip-agent
```

`http-smoke` never crawls wildcard `includePaths`; add concrete paths such as `/login` or `/api/health` to the target config for broader reachability checks.

## Full scan pipeline

The `scan` command is the preferred path when you want scanner outputs to feed later stages:

```bash
security-harness scan target.yaml --artifacts runs
```

Current high-level flow:

1. HTTP smoke
2. Static/source scan
3. Auth scan
4. Recon
5. Injection scan using upstream smoke/recon/auth context where available
6. Deterministic chain correlation
7. LLM-assisted recursive chain reasoning/report artifacts where configured

This is the safest default because it avoids the common false-negative pattern where scanners are run independently and never receive discovered routes, forms, cookies, or smoke paths from earlier stages.

## Architecture and data flow

The harness is organized around a small set of shared contracts and scanner modules:

1. **Target config and safety** — `web_target.py` loads `web-target/v1` configs, validates allowed hosts, rejects unsafe environments, and provides the source directory and scope used by scanners.
2. **CLI dispatch** — `cli.py` exposes the operator commands and adapts CLI arguments into scanner calls.
3. **Full scan orchestration** — `scan_handler.py` coordinates the scanner data flow for `security-harness scan`.
4. **Scanner execution** — individual scanner modules write JSON artifacts and return typed summaries where available.
5. **Artifact consumers** — `chains.py`, `chain_reasoning.py`, `report.py`, and the async `jobs.py` worker consume scanner findings and publish follow-on artifacts.

The most important runtime data flow is:

```text
target.yaml
  └─ load_target_config() safety gates
      ├─ http_smoke → request/status/header artifacts
      ├─ auth_scan → authenticated session/cookie artifacts
      ├─ recon → discovered routes/forms/surfaces
      └─ static_scan → source inventory/findings

smoke + auth + recon context
  └─ injection_scan → XSS/SQLi/SSRF findings

all findings
  ├─ WSTG focused scanners
  ├─ deterministic chain correlation
  ├─ optional LLM chain hypotheses
  └─ final report artifacts
```

Focused WSTG scanners (`csrf`, `http-verb`, `idor`, `jwt`, `stored-xss`) use concrete endpoint paths from `--endpoints` when provided, otherwise they default to `scope.includePaths` from the target config. Detector names under `detectors.enabled` are not endpoint paths.

## Focused scanner examples

```bash
security-harness recon target.yaml \
  --artifacts runs/recon \
  --max-depth 2 \
  --max-pages 50

security-harness auth-scan target.yaml \
  --login-url http://localhost:3000/login \
  --username user@example.com \
  --password 'REDACTED' \
  --artifacts runs/auth

security-harness injection-scan target.yaml \
  --artifacts runs/injection \
  --request-timeout 10

security-harness csrf target.yaml --endpoints /api/profile,/api/settings
security-harness idor target.yaml --endpoints /api/users/1,/api/users/2
security-harness jwt target.yaml --endpoints /api/me
security-harness http-verb target.yaml --endpoints /api/resource
security-harness stored-xss target.yaml --endpoints /comments,/profile
```

## PoC replay

Read-only PoCs can be replayed directly:

```bash
security-harness replay-poc \
  examples/toy-vulnerable-app/web-target.yaml \
  examples/toy-vulnerable-app/pocs/unsafe-redirect.json \
  --artifacts runs/poc-smoke
```

Mutation-capable PoCs require sandbox flags, concrete reset/seed lifecycle commands, an ephemeral home, a base-origin egress allowlist, and no credential mounts.

## Chain correlation and reports

```bash
security-harness chain \
  --findings runs/**/injection-scan.json runs/**/auth-scan.json \
  --output runs/chains.json

security-harness report \
  --findings runs/**/injection-scan.json runs/**/auth-scan.json runs/chains.json \
  --config target.yaml \
  --output runs/report.md
```

Reports include risk summaries, evidence, OWASP/MITRE-style mappings, CVSS-like scoring, and remediation guidance where available.

## LLM-assisted vulnerability chaining

There are two chain-analysis paths:

1. `security-harness chain` is deterministic. It auto-tags findings and applies table-driven correlation rules from `security_harness/chains.py`. This command does not call an LLM.
2. The full `security-harness scan ...` flow can run recursive LLM chain reasoning after deterministic chain correlation. The implementation lives in `security_harness/chain_reasoning.py` and is invoked from `security_harness/scan_handler.py`.

Current behavior in the full scan path:

- Step `[6/7]` runs deterministic chain correlation.
- Step `[7/7]` runs `run_recursive_chain_analysis(...)` only when findings exist and deterministic chain analysis produced at least one chain.
- The LLM prompt is built from up to 50 findings plus existing chain context.
- The LLM is asked to return a JSON array of multi-hop chain hypotheses.
- Successful hypotheses are written to `llm_chains.json` in the scan artifact directory.
- Each hypothesis is marked as requiring validation; this is intended as analyst guidance, not a deterministic finding.

Example full-scan invocation:

```bash
security-harness scan target.yaml \
  --artifacts runs/full-scan \
  --provider openai-api \
  --model local-qwen36-nvfp4
```

If no `llm_chains.json` appears, check the scan output. The current implementation skips LLM chain reasoning when deterministic chain correlation returns zero chains, even if individual findings exist.

## Python API highlights

```python
from security_harness import (
    run_http_smoke,
    run_static_scan,
    run_recon,
    run_auth_scan,
    run_injection_scan,
    run_chain_analysis,
)

smoke = run_http_smoke("target.yaml", "runs")
recon = run_recon("target.yaml", "runs")
auth = run_auth_scan("target.yaml", artifacts_root="runs")
injection = run_injection_scan(
    "target.yaml",
    "runs",
    recon_surfaces=[s.__dict__ for s in recon.surfaces],
    recon_routes=recon.discovered_routes,
)
```

Prefer the `scan` CLI for normal use; use the Python API when composing custom workflows or tests.

## Project structure

```text
security_harness/
  _http_client.py      shared HTTP client: redirects, cookies, errors, redaction
  web_target.py        target config loader and safety validation
  http_smoke.py        deterministic GET-only reachability + headers
  static_scan.py       source inventory + optional Hermes runner review
  recon.py             recon discovery, source-dir route discovery, staged recon helpers
  auth_scan.py         login/session/cookie/bypass/rate tests
  auth_client.py       authenticated session replay helpers
  injection_scanner.py XSS/SQLi/SSRF testing
  dependency_audit.py  lockfile parsing + CVE cross-reference
  rate_limit.py        burst request rate-limit checks
  csrf_scan.py         WSTG 4.6.05 CSRF testing
  http_verb_scan.py    WSTG 4.7.03 HTTP verb tampering
  idor_scan.py         WSTG 4.5.04 IDOR/BOLA testing
  jwt_scan.py          WSTG 4.6.10 JWT weakness testing
  stored_xss_scan.py   WSTG 4.7.02 stored XSS testing
  tls_scan.py          TLS/SSL configuration testing
  chains.py            deterministic vulnerability chain rules
  chain_reasoning.py   recursive LLM-assisted chain hypotheses
  engagement.py        engagement state + encrypted credentials
  intake.py            interactive intake helpers
  findings.py          accumulated findings with dedup/severity upgrades
  pipeline.py          WSTG-aligned phase orchestration primitives
  chain_gate.py        LLM reasoning gates between phases
  scan_handler.py      full scan command orchestration
  cli.py               CLI entrypoint
contracts/             JSON schemas for artifact contracts
plugins/               Hermes plugin scaffold
examples/              local toy target and sample configs
```

## Artifact and git hygiene

- Use `runs/` or `runs-*` for scan outputs.
- Do not commit scan outputs unless a fixture is intentionally added under `tests/` or `examples/`.
- Credentials captured by engagement/intake helpers are encrypted, but engagement files should still be treated as sensitive operational artifacts.
- Async jobs publish reports before the terminal `succeeded`/`failed` status is written; when `job-status` returns `succeeded`, `job-report` should be available immediately.
- Before opening a PR or pushing main, run:

```bash
git status --short
.venv/bin/python -m pytest tests/ -q
```

## Known remaining work

These are tracked as GitHub issues when identified during maintenance:

- End-to-end verification of the engagement + phased pipeline flow against a live authorized FinEase/local target.
- Expose and test first-class CLI commands for `intake` and `pipeline` if the engagement workflow is intended to be operator-facing rather than Python-only.
- Decide whether `tls_scan.py` should have a public CLI command and full pipeline integration.
- Harden full-scan execution status so required stage failures cannot look successful to CI/gateway callers.
- Remove project-local assumptions such as the `/home/beans/FinEase` static-scan fallback from public scan behavior.
- Refactor recon/injection/CLI internals to reduce global mutable state, duplicated dispatch boilerplate, and scanner-specific result schemas.

## License

Apache-2.0
