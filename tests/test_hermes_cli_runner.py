import os
from pathlib import Path

from security_harness.runners import AgentRunRequest, HermesCliRunner


def make_fake_hermes(tmp_path: Path) -> Path:
    fake = tmp_path / "hermes"
    fake.write_text("""#!/usr/bin/env python3
import sys
print('FAKE HERMES OK')
print('argv=' + repr(sys.argv[1:]))
""")
    fake.chmod(0o755)
    return fake


def test_hermes_cli_runner_builds_expected_command_and_captures_artifacts(tmp_path, monkeypatch):
    fake = make_fake_hermes(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    artifact_dir = tmp_path / "artifacts"
    runner = HermesCliRunner(artifact_root=artifact_dir)

    result = runner.run(AgentRunRequest(
        prompt="Return JSON",
        workdir=tmp_path,
        source="security-harness-test",
        max_turns=7,
        toolsets=["file", "terminal"],
        provider="openrouter",
        model="test-model",
    ))

    assert result.ok is True
    assert result.exit_code == 0
    assert "FAKE HERMES OK" in result.stdout
    assert result.command[:3] == ["hermes", "chat", "--query"]
    assert "--quiet" in result.command
    assert "--source" in result.command
    assert "security-harness-test" in result.command
    assert "--toolsets" in result.command
    assert "file,terminal" in result.command
    assert "--ignore-rules" not in result.command
    assert result.stdout_path and result.stdout_path.exists()
    assert result.stderr_path and result.stderr_path.exists()
    assert result.command_path and result.command_path.exists()


def test_hermes_cli_runner_timeout_records_failure(tmp_path, monkeypatch):
    fake = tmp_path / "hermes"
    fake.write_text("""#!/usr/bin/env python3
import time
time.sleep(5)
""")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    runner = HermesCliRunner(artifact_root=tmp_path / "artifacts")

    result = runner.run(AgentRunRequest(prompt="hang", workdir=tmp_path, timeout_s=0.1))

    assert result.ok is False
    assert result.timed_out is True
    assert result.exit_code == -1
    assert result.stderr_path and "timed out" in result.stderr_path.read_text()
