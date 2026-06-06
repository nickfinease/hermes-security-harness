# Architecture

```text
Hermes user/session
  -> security-harness plugin tools
  -> security-harness CLI
       -> validate-target
       -> http-smoke
       -> static-scan
       -> replay-poc
       -> job-start/status/report
  -> AgentRunner protocol
       -> HermesCliRunner now
       -> HermesApiRunner later
  -> artifacts under runs/<run-id>/
  -> jobs/reports under <workdir>/ for gateway polling
```

## Runner abstraction

`AgentRunner` accepts an `AgentRunRequest` and returns an `AgentRunResult`. The current `HermesCliRunner` invokes:

```bash
hermes chat --query <prompt> --quiet --source security-harness --max-turns <n> --toolsets <list>
```

It captures raw stdout/stderr/command/result JSON in a run artifact directory. It does not assume Claude Code stream JSON or any Claude-specific protocol.

## Web target contract

`web-target/v1` configs are staging/local by default. They include:

- `baseUrl`
- `allowedHosts`
- request/runtime budget
- reset/seed lifecycle commands
- detector allowlist
- safety flags

The MVP validates safety and artifact contracts only; real detector execution is a future phase.

## Job registry

`job-start` writes `security-harness-job/v1` JSON under `<workdir>/jobs/<job_id>.json`, starts a worker, and publishes reports under `<workdir>/reports/<job_id>/`:

- `report.summary` — short text for plugin responses
- `report.md` — markdown report path
- `report.json` — structured job result

Plugin tools expose `security_start_scan`, `security_status`, and `security_report` so gateway callers receive a job ID first and poll/fetch reports later.

## Dynamic replay gates

`replay-poc` accepts `http-poc/v1` artifacts. Read-only `GET`/`HEAD` PoCs can run directly against local/staging targets. Mutation-capable PoCs are refused unless all gates are present:

- sandbox mode (`gvisor`, `bwrap`, `container`, or `firejail`)
- ephemeral home directory
- no credential mounts
- target-scoped egress host allowlist
- reset/seed lifecycle execution with concrete required reset and seed commands
- same-origin PoC URLs; allowedHosts remain host-only, but PoC replay also pins scheme/host/port to `baseUrl`

The current code enforces the contract before requests are sent; actual OS-level sandbox launchers remain future integration work. Public non-local staging hosts require an operator-controlled `SECURITY_HARNESS_APPROVED_STAGING_HOSTS` allowlist in addition to target YAML.
