import json
import os
from pathlib import Path

from security_harness.cli import main


def write_target_config(path: Path) -> None:
    path.write_text(
        """
schemaVersion: web-target/v1
id: static-demo
name: Static Demo
environment: local
baseUrl: http://localhost:3000
allowedHosts:
  - localhost
scope:
  includePaths:
    - /
    - /api/*
  maxRequests: 5
  maxRuntimeSeconds: 30
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
""".strip()
        + "\n"
    )


def make_fake_hermes(tmp_path: Path) -> Path:
    fake = tmp_path / "hermes"
    fake.write_text(
        """#!/usr/bin/env python3
import json
print(json.dumps({
    "schemaVersion": "static-agent-findings/v1",
    "findings": [
        {
            "id": "agent-finding-1",
            "title": "Missing CSRF validation on sample route",
            "severity": "medium",
            "confidence": "low",
            "affected": {"file": "app/api/sample/route.ts", "url": "http://localhost:3000/api/sample"},
            "description": "Fake agent finding for parser test.",
            "evidence": {"line": 3},
            "remediation": {"summary": "Add CSRF validation."}
        }
    ],
    "notes": ["fake hermes static review"]
}))
"""
    )
    fake.chmod(0o755)
    return fake


def test_static_scan_cli_creates_source_only_artifacts_and_parses_agent_findings(tmp_path, monkeypatch, capsys):
    make_fake_hermes(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    source_root = tmp_path / "source"
    route = source_root / "app" / "api" / "sample" / "route.ts"
    route.parent.mkdir(parents=True)
    route.write_text("export async function POST() { return Response.json({ ok: true }) }\n")
    config = tmp_path / "target.yaml"
    write_target_config(config)
    artifacts = tmp_path / "artifacts"

    rc = main([
        "static-scan",
        str(config),
        "--source-root",
        str(source_root),
        "--artifacts",
        str(artifacts),
        "--max-turns",
        "3",
        "--timeout",
        "30",
    ])

    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is True
    assert out["target_id"] == "static-demo"
    assert out["finding_count"] == 1
    assert out["agent_success"] is True

    run_dir = Path(out["run_dir"])
    assert run_dir.exists()
    for name in ["threat-model.md", "source-inventory.json", "findings.json", "report.md", "prompt.txt"]:
        assert (run_dir / name).exists(), name

    inventory = json.loads((run_dir / "source-inventory.json").read_text())
    assert inventory["schemaVersion"] == "source-inventory/v1"
    assert inventory["targetId"] == "static-demo"
    assert inventory["files"][0]["path"] == "app/api/sample/route.ts"
    assert "http://localhost:3000" not in (run_dir / "prompt.txt").read_text().split("Do not issue network requests", 1)[0]

    findings = json.loads((run_dir / "findings.json").read_text())
    assert findings["schemaVersion"] == "static-findings/v1"
    assert findings["findings"][0]["id"] == "agent-finding-1"
    assert findings["agent"]["ok"] is True
    assert Path(findings["agent"]["stdoutPath"]).exists()

    command = json.loads(Path(findings["agent"]["commandPath"]).read_text())
    assert command["cwd"] == str(source_root.resolve())
    assert "--toolsets" in command["argv"]
    assert command["argv"][command["argv"].index("--toolsets") + 1] == "file"
    assert "--yolo" not in command["argv"]


def test_static_scan_rejects_missing_source_root(tmp_path, capsys):
    config = tmp_path / "target.yaml"
    write_target_config(config)

    rc = main([
        "static-scan",
        str(config),
        "--source-root",
        str(tmp_path / "missing"),
        "--artifacts",
        str(tmp_path / "artifacts"),
    ])

    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is False
    assert "source root" in out["error"]


def test_static_scan_rejects_terminal_and_dynamic_toolsets_case_insensitively(tmp_path, capsys):
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "route.ts").write_text("export async function GET() {}\n")
    config = tmp_path / "target.yaml"
    write_target_config(config)

    rc = main([
        "static-scan",
        str(config),
        "--source-root",
        str(source_root),
        "--artifacts",
        str(tmp_path / "artifacts"),
        "--skip-agent",
        "--toolsets",
        "file,Terminal",
    ])

    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is False
    assert "file-only" in out["error"]

    rc = main([
        "static-scan",
        str(config),
        "--source-root",
        str(source_root),
        "--artifacts",
        str(tmp_path / "artifacts2"),
        "--skip-agent",
        "--toolsets",
        "Web",
    ])

    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is False
    assert "file-only" in out["error"]


def test_static_scan_rejects_artifacts_inside_source_root(tmp_path, capsys):
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "route.ts").write_text("export async function GET() {}\n")
    config = tmp_path / "target.yaml"
    write_target_config(config)

    rc = main([
        "static-scan",
        str(config),
        "--source-root",
        str(source_root),
        "--artifacts",
        str(source_root / "runs"),
        "--skip-agent",
    ])

    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is False
    assert "outside source root" in out["error"]
    assert not (source_root / "runs").exists()
