"""Safe thin wrapper tools for Hermes plugin use.

The plugin exposes validate/start/status/report wrappers. Scan starts return a
job ID; long-running work happens in the CLI job worker and reports are fetched
from the bounded workdir.
"""
from __future__ import annotations

from pathlib import Path
import json
import os
import subprocess


def validate_target(params, **kwargs):
    del kwargs
    try:
        cli = _cli_path()
        config_path = _config_path(params.get("config_path", ""))
        result = subprocess.run(
            [str(cli), "validate-target", str(config_path)],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            return _json_error(result.stderr or result.stdout or "validate-target failed")
        return result.stdout
    except Exception as exc:
        return _json_error(str(exc))


def start_scan(params, **kwargs):
    del kwargs
    try:
        cli = _cli_path()
        workdir = _workdir()
        scan_type = _safe_scan_type(params.get("scan_type", "http-smoke"))
        config_path = _config_path(params.get("config_path", ""))
        argv = [str(cli), "job-start", "--workdir", str(workdir), "--scan-type", scan_type, "--config", str(config_path)]
        if params.get("source_root"):
            argv += ["--source-root", str(_source_root(params.get("source_root")))]
        if params.get("poc_path"):
            argv += ["--poc", str(_config_path(params.get("poc_path")))]
        if params.get("skip_agent"):
            argv.append("--skip-agent")
        if params.get("run_lifecycle"):
            argv.append("--run-lifecycle")
        for key, flag in [
            ("request_timeout", "--request-timeout"),
            ("max_turns", "--max-turns"),
            ("timeout", "--timeout"),
            ("max_files", "--max-files"),
        ]:
            if params.get(key) is not None:
                argv += [flag, str(params[key])]
        if params.get("sandbox_mode"):
            argv += ["--sandbox-mode", str(params["sandbox_mode"])]
        for host in params.get("egress_hosts") or []:
            argv += ["--egress-host", str(host)]
        if params.get("ephemeral_home"):
            argv += ["--ephemeral-home", str(_source_root(params.get("ephemeral_home")))]
        if params.get("no_credential_mounts"):
            argv.append("--no-credential-mounts")
        result = subprocess.run(argv, text=True, capture_output=True, timeout=30, check=False)
        if result.returncode not in {0, 1}:
            return _json_error(result.stderr or result.stdout or "job-start failed")
        return result.stdout
    except Exception as exc:
        return _json_error(str(exc))


def status(params, **kwargs):
    del kwargs
    try:
        job_id = _safe_job_id(params.get("job_id", ""))
        workdir = _workdir()
        job_path = workdir / "jobs" / f"{job_id}.json"
        if not _under(job_path, workdir):
            return _json_error("job path escapes workdir")
        if not job_path.exists():
            return json.dumps({"success": False, "error": "job not found", "job_id": job_id})
        return job_path.read_text()
    except Exception as exc:
        return _json_error(str(exc))


def report(params, **kwargs):
    del kwargs
    try:
        job_id = _safe_job_id(params.get("job_id", ""))
        fmt = _safe_format(params.get("format", "summary"))
        workdir = _workdir()
        report_path = workdir / "reports" / job_id / f"report.{fmt}"
        if not _under(report_path, workdir):
            return _json_error("report path escapes workdir")
        if not report_path.exists():
            return json.dumps({"success": False, "error": "report not found", "job_id": job_id})
        if fmt == "summary":
            return json.dumps({"success": True, "job_id": job_id, "summary": report_path.read_text()[:4000]})
        return json.dumps({"success": True, "job_id": job_id, "path": str(report_path)})
    except Exception as exc:
        return _json_error(str(exc))


def _json_error(message: str):
    return json.dumps({"success": False, "error": message})


def _cli_path() -> Path:
    value = os.environ.get("SECURITY_HARNESS_CLI")
    if not value:
        raise RuntimeError("SECURITY_HARNESS_CLI is not configured")
    path = Path(value).expanduser().resolve()
    if not path.is_absolute() or not path.exists():
        raise RuntimeError("SECURITY_HARNESS_CLI must be an absolute existing path")
    return path


def _workdir() -> Path:
    value = os.environ.get("SECURITY_HARNESS_WORKDIR")
    if not value:
        raise RuntimeError("SECURITY_HARNESS_WORKDIR is not configured")
    path = Path(value).expanduser().resolve()
    if not path.is_absolute():
        raise RuntimeError("SECURITY_HARNESS_WORKDIR must be absolute")
    if path.exists() and path.is_symlink():
        raise RuntimeError("SECURITY_HARNESS_WORKDIR must not be a symlink")
    if not path.exists():
        raise RuntimeError("SECURITY_HARNESS_WORKDIR must already exist")
    return path


def _config_path(value: str) -> Path:
    if not value:
        raise RuntimeError("config_path is required")
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise RuntimeError("config_path does not exist")
    roots = [r for r in os.environ.get("SECURITY_HARNESS_ALLOWED_CONFIG_ROOTS", "").split(os.pathsep) if r]
    if roots:
        allowed = [Path(r).expanduser().resolve() for r in roots]
        if not any(_under(path, root) for root in allowed):
            raise RuntimeError("config_path is outside SECURITY_HARNESS_ALLOWED_CONFIG_ROOTS")
    return path


def _source_root(value: str) -> Path:
    if not value:
        raise RuntimeError("path is required")
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise RuntimeError("path does not exist")
    roots = [r for r in os.environ.get("SECURITY_HARNESS_ALLOWED_SOURCE_ROOTS", "").split(os.pathsep) if r]
    if roots:
        allowed = [Path(r).expanduser().resolve() for r in roots]
        if not any(_under(path, root) for root in allowed):
            raise RuntimeError("path is outside SECURITY_HARNESS_ALLOWED_SOURCE_ROOTS")
    return path


def _safe_scan_type(value: str) -> str:
    if value not in {"http-smoke", "static-scan", "poc-replay"}:
        raise RuntimeError("invalid scan_type")
    return value


def _safe_job_id(value: str) -> str:
    if not value or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in value):
        raise RuntimeError("invalid job_id")
    return value


def _safe_format(value: str) -> str:
    if value not in {"summary", "json", "markdown"}:
        raise RuntimeError("invalid report format")
    return "md" if value == "markdown" else value


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
