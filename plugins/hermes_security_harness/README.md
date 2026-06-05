# Hermes security-harness plugin

This plugin is a thin wrapper around the `security-harness` CLI. Install by copying this directory into the active Hermes profile plugin directory, for example:

```bash
# From the repo root after installing the package
mkdir -p ~/.hermes/plugins/hermes_security_harness
cp -R plugins/hermes_security_harness/* ~/.hermes/plugins/hermes_security_harness/

# Use the installed console script path
SECURITY_HARNESS_CLI="$(pwd)/.venv/bin/security-harness"
mkdir -p /home/beans/data/security-harness
SECURITY_HARNESS_WORKDIR=/home/beans/data/security-harness
```

Add those environment variables to `$(hermes config env-path)`, then restart Hermes/gateway. For named profiles, use that profile's plugin/env paths instead of the default profile.

MVP tools:

- `security_validate_target`
- `security_status`
- `security_report`

Long-running static/dynamic scan tools are intentionally deferred until the job runner and sandbox gates are implemented.
