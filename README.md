# Hermes Security Harness

Hermes-native defensive security harness for authorized, source-backed web targets.

This repository is an MVP scaffold inspired by Anthropic's defending-code reference harness, but replaces Claude Code headless execution with a provider-agnostic `AgentRunner` abstraction and a first implementation that drives Hermes headlessly via `hermes chat`.

## Safety posture

- Staging/local targets only by default.
- Explicit allowed-host checks.
- Public production URLs are rejected. Public staging domains also require an operator-controlled allowlist via `SECURITY_HARNESS_APPROVED_STAGING_HOSTS`; target-controlled YAML alone cannot approve a public host.
- Metadata IPs and redirect escapes are blocked.
- Agent runs capture transcripts and command metadata.
- Dynamic scans should run in an external sandbox; this MVP provides validation, artifact contracts, runner plumbing, and plugin scaffolding.

## MVP components

- `security_harness.runners.HermesCliRunner` — headless Hermes CLI runner.
- `security_harness.web_target.WebTargetConfig` — authorized web target config and URL safety gates.
- `security_harness.artifacts` — HTTP PoC, finding, grader, and report contracts.
- `security_harness.http_smoke` — deterministic GET-only reachability, redirect-allowlist, and security-header smoke checks for explicit local/staging paths.
- `security_harness.poc_replay` — HTTP PoC replay with grader artifacts and hard gates for mutation-capable dynamic replay.
- `security_harness.jobs` — JSON job registry/worker for gateway-safe start/status/report polling.
- `security_harness.static_scan` — read-only source/static scan orchestration that writes `source-inventory.json`, `threat-model.md`, `prompt.txt`, `findings.json`, inert `patchCandidates`, `report.md`, and captured Hermes runner artifacts.
- `plugins/hermes_security_harness` — Hermes plugin exposing validate/start/status/report tools.

## Quick smoke

```bash
uv venv
uv pip install -e '.[dev]'
pytest -q
security-harness validate-target examples/web-target.local.yaml
security-harness http-smoke examples/web-target.local.yaml \
  --artifacts runs/http-smoke
# http-smoke never crawls wildcard includePaths; add concrete paths such as
# /login or /api/health to the target config for broader reachability checks.
security-harness static-scan examples/web-target.local.yaml \
  --source-root . \
  --artifacts runs/static-smoke \
  --toolsets file
security-harness job-start \
  --workdir runs/jobs \
  --scan-type http-smoke \
  --config examples/web-target.local.yaml
# Replay read-only PoCs directly. Mutation-capable PoCs require sandbox flags,
# concrete required reset/seed lifecycle commands, an ephemeral home,
# a base-origin egress allowlist, and no credential mounts.
security-harness replay-poc \
  examples/toy-vulnerable-app/web-target.yaml \
  examples/toy-vulnerable-app/pocs/unsafe-redirect.json \
  --artifacts runs/poc-smoke
```

## Not yet included

- Browser automation.
- Real OS-level sandbox launchers; mutation-capable replay is currently blocked unless the operator supplies sandbox/egress/no-credential/ephemeral-home gates.
- Full detector payload library beyond safe HTTP smoke and structured PoC replay.

Those should be added behind explicit sandbox gates after this harness remains boring and test-covered.
