import importlib
import json
import os
from pathlib import Path


def plugin_module(name):
    import sys
    plugin_root = Path(__file__).resolve().parents[1] / "plugins"
    sys.path.insert(0, str(plugin_root))
    try:
        return importlib.import_module(f"hermes_security_harness.{name}")
    finally:
        sys.path.remove(str(plugin_root))


def test_plugin_tools_return_json_errors_when_env_missing(monkeypatch):
    tools = plugin_module("tools")
    monkeypatch.delenv("SECURITY_HARNESS_CLI", raising=False)
    result = json.loads(tools.validate_target({"config_path": "missing.yaml"}))
    assert result["success"] is False
    assert "SECURITY_HARNESS_CLI" in result["error"]


def test_plugin_validate_target_uses_fixed_argv_and_returns_cli_json(tmp_path, monkeypatch):
    tools = plugin_module("tools")
    fake_cli = tmp_path / "security-harness"
    fake_cli.write_text("""#!/usr/bin/env python3
import json, sys
assert sys.argv[1] == 'validate-target'
print(json.dumps({'success': True, 'target_id': 'fake'}))
""")
    fake_cli.chmod(0o755)
    config = tmp_path / "target.yaml"
    config.write_text("schemaVersion: web-target/v1\n")
    monkeypatch.setenv("SECURITY_HARNESS_CLI", str(fake_cli))

    result = json.loads(tools.validate_target({"config_path": str(config)}))

    assert result == {"success": True, "target_id": "fake"}


def test_plugin_rejects_invalid_job_id_with_json_error(monkeypatch, tmp_path):
    tools = plugin_module("tools")
    monkeypatch.setenv("SECURITY_HARNESS_WORKDIR", str(tmp_path))
    result = json.loads(tools.status({"job_id": "../oops"}))
    assert result["success"] is False
    assert "invalid job_id" in result["error"]
