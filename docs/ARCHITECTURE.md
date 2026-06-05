# Architecture

```text
Hermes user/session
  -> security-harness plugin tools
  -> security-harness CLI
  -> AgentRunner protocol
       -> HermesCliRunner now
       -> HermesApiRunner later
  -> artifacts under runs/<run-id>/
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
