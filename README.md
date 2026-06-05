# Hermes Security Harness

Hermes-native defensive security harness for authorized, source-backed web targets.

This repository is an MVP scaffold inspired by Anthropic's defending-code reference harness, but replaces Claude Code headless execution with a provider-agnostic `AgentRunner` abstraction and a first implementation that drives Hermes headlessly via `hermes chat`.

## Safety posture

- Staging/local targets only by default.
- Explicit allowed-host checks.
- Public production URLs are rejected unless the config is explicitly marked as staging/local and allowlisted.
- Metadata IPs and redirect escapes are blocked.
- Agent runs capture transcripts and command metadata.
- Dynamic scans should run in an external sandbox; this MVP provides validation, artifact contracts, runner plumbing, and plugin scaffolding.

## MVP components

- `security_harness.runners.HermesCliRunner` — headless Hermes CLI runner.
- `security_harness.web_target.WebTargetConfig` — authorized web target config and URL safety gates.
- `security_harness.artifacts` — HTTP PoC, finding, grader, and report contracts.
- `security_harness.static_scan` — read-only source/static scan orchestration that writes `source-inventory.json`, `threat-model.md`, `prompt.txt`, `findings.json`, `report.md`, and captured Hermes runner artifacts.
- `plugins/hermes_security_harness` — Hermes plugin skeleton exposing validation/status/report tools.

## Quick smoke

```bash
uv venv
uv pip install -e '.[dev]'
pytest -q
security-harness validate-target examples/web-target.local.yaml
security-harness static-scan examples/web-target.local.yaml \
  --source-root . \
  --artifacts runs/static-smoke \
  --toolsets file
```

## Not yet included

- Real detector execution.
- Browser automation.
- gVisor orchestration.
- Dynamic attack loops.

Those should be added behind explicit sandbox gates after this MVP is boring and test-covered.
