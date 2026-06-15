"""Small JSON job registry and worker for gateway-triggered harness runs."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import os
import shutil
import subprocess
import sys
import uuid

from .http_smoke import run_http_smoke
from .poc_replay import preflight_poc_replay, run_poc_replay
from .sandbox import SandboxPolicy
from .static_scan import DEFAULT_STATIC_TEMPLATE, run_static_scan
from .web_target import load_target_config

SCAN_TYPES = {"http-smoke", "static-scan", "poc-replay"}


@dataclass(frozen=True)
class JobStartResult:
    success: bool
    job_id: str
    status: str
    job_path: Path
    pid: int | None = None
    error: str | None = None

    def to_summary(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "job_id": self.job_id,
            "status": self.status,
            "job_path": str(self.job_path),
            "pid": self.pid,
            "error": self.error,
        }


def start_job(
    workdir: str | Path,
    *,
    scan_type: str,
    config_path: str | Path,
    source_root: str | Path | None = None,
    poc_path: str | Path | None = None,
    foreground: bool = False,
    request_timeout_s: float = 10,
    template: str = DEFAULT_STATIC_TEMPLATE,
    toolsets: list[str] | None = None,
    model: str | None = None,
    provider: str | None = None,
    max_turns: int = 16,
    timeout_s: float = 900,
    max_files: int = 250,
    skip_agent: bool = False,
    sandbox_policy: SandboxPolicy | None = None,
    run_lifecycle_commands: bool = False,
) -> JobStartResult:
    if scan_type not in SCAN_TYPES:
        raise ValueError(f"scan-type must be one of {sorted(SCAN_TYPES)}")
    root = _validate_workdir(workdir)
    config = Path(config_path).expanduser().resolve()
    if not config.exists():
        raise ValueError("config path does not exist")
    spec = {
        "scanType": scan_type,
        "configPath": str(config),
        "sourceRoot": str(Path(source_root).expanduser().resolve()) if source_root else None,
        "pocPath": str(Path(poc_path).expanduser().resolve()) if poc_path else None,
        "requestTimeoutSeconds": request_timeout_s,
        "template": template,
        "toolsets": toolsets or ["file"],
        "model": model,
        "provider": provider,
        "maxTurns": max_turns,
        "timeoutSeconds": timeout_s,
        "maxFiles": max_files,
        "skipAgent": skip_agent,
        "sandbox": (sandbox_policy or SandboxPolicy()).to_summary(),
        "runLifecycle": run_lifecycle_commands,
    }
    _preflight_spec(spec, sandbox_policy=sandbox_policy, run_lifecycle_commands=run_lifecycle_commands)

    job_id = _new_job_id(scan_type)
    job_path = root / "jobs" / f"{job_id}.json"
    now = _now()
    job = {
        "schemaVersion": "security-harness-job/v1",
        "success": True,
        "job_id": job_id,
        "status": "queued",
        "createdAt": now,
        "updatedAt": now,
        "pid": None,
        "spec": spec,
        "result": None,
        "artifacts": {},
        "error": None,
    }
    _write_json(job_path, job)
    if foreground:
        final = run_job_worker(root, job_id)
        return JobStartResult(True, job_id, final["status"], job_path, pid=os.getpid(), error=final.get("error"))

    cmd = [sys.executable, "-m", "security_harness.cli", "job-worker", "--workdir", str(root), job_id]
    stdout_path = root / "logs" / f"{job_id}.stdout.txt"
    stderr_path = root / "logs" / f"{job_id}.stderr.txt"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_fh = stdout_path.open("w")
    stderr_fh = stderr_path.open("w")
    proc = subprocess.Popen(cmd, stdout=stdout_fh, stderr=stderr_fh, start_new_session=True)
    job["pid"] = proc.pid
    job["status"] = "running"
    job["updatedAt"] = _now()
    job["worker"] = {"argv": cmd, "stdoutPath": str(stdout_path), "stderrPath": str(stderr_path)}
    _write_json(job_path, job)
    stdout_fh.close()
    stderr_fh.close()
    return JobStartResult(True, job_id, "running", job_path, pid=proc.pid)


def run_job_worker(workdir: str | Path, job_id: str) -> dict[str, Any]:
    root = _validate_workdir(workdir)
    job = read_job(root, job_id)
    _update_job(root, job_id, {"status": "running", "pid": os.getpid(), "updatedAt": _now()})
    try:
        result = _run_job_spec(root, job_id, job["spec"])
        final = read_job(root, job_id)
        final.update({
            "status": "succeeded" if result.get("success") else "failed",
            "updatedAt": _now(),
            "result": result,
            "artifacts": result.get("artifacts", {}),
            "error": None if result.get("success") else result.get("error"),
        })
        _publish_report(root, job_id, result)
        _write_json(_job_path(root, job_id), final)
        return final
    except Exception as exc:
        final = read_job(root, job_id)
        final.update({"status": "failed", "updatedAt": _now(), "error": str(exc), "result": {"success": False, "error": str(exc)}})
        _write_json(_job_path(root, job_id), final)
        _publish_report(root, job_id, final["result"])
        return final


def read_job(workdir: str | Path, job_id: str) -> dict[str, Any]:
    safe = _safe_job_id(job_id)
    path = _job_path(_validate_workdir(workdir), safe)
    if not path.exists():
        raise ValueError("job not found")
    return json.loads(path.read_text())


def get_report(workdir: str | Path, job_id: str, fmt: str = "summary") -> dict[str, Any]:
    safe = _safe_job_id(job_id)
    root = _validate_workdir(workdir)
    ext = "md" if fmt == "markdown" else fmt
    if ext not in {"summary", "json", "md"}:
        raise ValueError("invalid report format")
    report_path = root / "reports" / safe / f"report.{ext}"
    if not _under(report_path, root) or not report_path.exists():
        raise ValueError("report not found")
    if ext == "summary":
        return {"success": True, "job_id": safe, "summary": report_path.read_text()}
    return {"success": True, "job_id": safe, "path": str(report_path)}


def _run_job_spec(root: Path, job_id: str, spec: dict[str, Any]) -> dict[str, Any]:
    artifacts_root = root / "artifacts" / job_id
    scan_type = spec["scanType"]
    if scan_type == "http-smoke":
        result = run_http_smoke(spec["configPath"], artifacts_root, request_timeout_s=float(spec["requestTimeoutSeconds"]))
        return result.to_summary()
    if scan_type == "static-scan":
        if not spec.get("sourceRoot"):
            raise ValueError("static-scan job requires source-root")
        result = run_static_scan(
            spec["configPath"],
            spec["sourceRoot"],
            artifacts_root,
            template=spec.get("template") or DEFAULT_STATIC_TEMPLATE,
            toolsets=list(spec.get("toolsets") or ["file"]),
            model=spec.get("model"),
            provider=spec.get("provider"),
            max_turns=int(spec.get("maxTurns") or 16),
            timeout_s=float(spec.get("timeoutSeconds") or 900),
            max_files=int(spec.get("maxFiles") or 250),
            run_agent=not bool(spec.get("skipAgent")),
        )
        return result.to_summary()
    if scan_type == "poc-replay":
        if not spec.get("pocPath"):
            raise ValueError("poc-replay job requires poc path")
        sandbox = _sandbox_from_spec(spec.get("sandbox") or {})
        result = run_poc_replay(
            spec["configPath"],
            spec["pocPath"],
            artifacts_root,
            request_timeout_s=float(spec.get("requestTimeoutSeconds") or 10),
            sandbox_policy=sandbox,
            run_lifecycle_commands=bool(spec.get("runLifecycle")),
        )
        return result.to_summary()
    raise ValueError(f"unknown scan type {scan_type}")


def _preflight_spec(spec: dict[str, Any], *, sandbox_policy: SandboxPolicy | None, run_lifecycle_commands: bool) -> None:
    scan_type = spec["scanType"]
    load_target_config(spec["configPath"])
    if scan_type == "static-scan" and not spec.get("sourceRoot"):
        raise ValueError("static-scan job requires --source-root")
    if scan_type == "poc-replay":
        if not spec.get("pocPath"):
            raise ValueError("poc-replay job requires --poc")
        preflight_poc_replay(
            spec["configPath"],
            spec["pocPath"],
            sandbox_policy=sandbox_policy,
            run_lifecycle_commands=run_lifecycle_commands,
        )


def _publish_report(root: Path, job_id: str, result: dict[str, Any]) -> None:
    report_dir = root / "reports" / job_id
    report_dir.mkdir(parents=True, exist_ok=True)
    report_json = report_dir / "report.json"
    report_summary = report_dir / "report.summary"
    report_md = report_dir / "report.md"
    _write_json(report_json, result)
    summary = json.dumps(result, indent=2, sort_keys=True)
    artifacts = result.get("artifacts") if isinstance(result.get("artifacts"), dict) else {}
    report_src = artifacts.get("report") if isinstance(artifacts, dict) else None
    if report_src and Path(report_src).exists():
        text = Path(report_src).read_text()
        report_md.write_text(text)
        summary = text[:4000]
    else:
        report_md.write_text(summary + "\n")
    report_summary.write_text(summary[:4000])


def _sandbox_from_spec(data: dict[str, Any]) -> SandboxPolicy:
    home = data.get("ephemeralHome")
    return SandboxPolicy(
        mode=str(data.get("mode") or "none"),
        egress_hosts=list(data.get("egressHosts") or []),
        ephemeral_home=Path(home) if home else None,
        credentials_mounted=bool(data.get("credentialsMounted", True)),
    )


def _update_job(root: Path, job_id: str, updates: dict[str, Any]) -> None:
    job = read_job(root, job_id)
    job.update(updates)
    _write_json(_job_path(root, job_id), job)


def _validate_workdir(workdir: str | Path) -> Path:
    root = Path(workdir).expanduser().resolve()
    if root.exists() and root.is_symlink():
        raise ValueError("workdir must not be a symlink")
    if not root.exists():
        root.mkdir(parents=True)
    if not root.is_dir():
        raise ValueError("workdir must be a directory")
    return root


def _job_path(root: Path, job_id: str) -> Path:
    safe = _safe_job_id(job_id)
    path = root / "jobs" / f"{safe}.json"
    if not _under(path, root):
        raise ValueError("job path escapes workdir")
    return path


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _safe_job_id(value: str) -> str:
    if not value or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in value):
        raise ValueError("invalid job_id")
    return value


def _new_job_id(scan_type: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = scan_type.replace("-", "_")
    return f"job_{stamp}_{safe}_{uuid.uuid4().hex[:8]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
