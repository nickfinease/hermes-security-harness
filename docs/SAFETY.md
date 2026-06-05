# Safety

This harness is defensive and source-backed. It must fail closed.

Current enforced gates:

- `web-target/v1` only.
- `environment` must be `local` or `staging` when `requireLocalOrStaging` is true.
- `baseUrl` host must be listed in `allowedHosts` when `requireAllowedHostMatch` is true.
- Cloud metadata IPs such as `169.254.169.254` are blocked.
- Reset/seed commands are required when marked required.
- Request/runtime budgets must be positive.

Future dynamic scan gates:

- gVisor or stronger sandbox required.
- No normal Hermes home/profile mounted into scanner agents.
- No secrets mounted into scan containers.
- Network allowlist: target app + model endpoint only.
- One writer agent per workspace.
- Evidence pack for every finding and grader replay.
