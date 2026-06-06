"""HTTP PoC replay and grading with explicit dynamic safety gates."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener
import json
import re
import socket
import uuid

from .artifacts import GraderResult, redact_secrets
from .lifecycle import run_lifecycle
from .sandbox import SandboxPolicy, SandboxValidationError, request_is_dynamic, validate_sandbox_for_dynamic
from .web_target import WebTargetConfig, load_target_config


@dataclass(frozen=True)
class PocReplayResult:
    success: bool
    verified: bool
    run_id: str
    target_id: str
    run_dir: Path
    step_count: int
    finding_count: int
    artifacts: dict[str, Path]
    warnings: list[str]

    def to_summary(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "verified": self.verified,
            "run_id": self.run_id,
            "target_id": self.target_id,
            "run_dir": str(self.run_dir),
            "step_count": self.step_count,
            "finding_count": self.finding_count,
            "artifacts": {k: str(v) for k, v in self.artifacts.items()},
            "warnings": self.warnings,
        }


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401, ANN001
        return None


def load_http_poc(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError("HTTP PoC must be a JSON object")
    if data.get("schemaVersion") != "http-poc/v1":
        raise ValueError("HTTP PoC schemaVersion must be http-poc/v1")
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("HTTP PoC requires at least one step")
    for idx, step in enumerate(steps, start=1):
        if not isinstance(step, dict) or not isinstance(step.get("request"), dict):
            raise ValueError(f"HTTP PoC step {idx} must contain request object")
    return data


def poc_requires_dynamic_sandbox(poc: dict[str, Any]) -> bool:
    for step in poc.get("steps", []):
        req = step.get("request", {}) if isinstance(step, dict) else {}
        if request_is_dynamic(str(req.get("method", "GET")), req.get("body")):
            return True
    return False


def preflight_poc_replay(
    config_path: str | Path,
    poc_path: str | Path,
    *,
    sandbox_policy: SandboxPolicy | None = None,
    run_lifecycle_commands: bool = False,
) -> tuple[WebTargetConfig, dict[str, Any], bool]:
    target = load_target_config(config_path)
    poc = load_http_poc(poc_path)
    if str(poc.get("targetId")) != target.id:
        raise ValueError("HTTP PoC targetId does not match target config")
    dynamic = poc_requires_dynamic_sandbox(poc)
    if dynamic:
        validate_sandbox_for_dynamic(target, sandbox_policy or SandboxPolicy())
        if not run_lifecycle_commands:
            raise SandboxValidationError("dynamic PoC replay requires --run-lifecycle reset/seed gate")
        if not (target.reset.command and target.seed.command and target.reset.required and target.seed.required):
            raise SandboxValidationError("dynamic PoC replay requires concrete required reset and seed lifecycle commands")
    for step in poc.get("steps", []):
        req = step["request"]
        url = str(req.get("url") or "")
        if not url:
            raise ValueError("HTTP PoC request.url is required")
        if not target.is_url_allowed(url):
            raise ValueError(f"HTTP PoC URL is outside target allowedHosts: {url}")
        if not _same_origin(url, target.base_url):
            raise ValueError(f"HTTP PoC URL must match target base origin: {url}")
    return target, poc, dynamic


def _same_origin(url: str, base_url: str) -> bool:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    base = urlparse(base_url)
    parsed_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    base_port = base.port or (443 if base.scheme == "https" else 80)
    return (
        parsed.scheme == base.scheme
        and (parsed.hostname or "").lower().rstrip(".") == (base.hostname or "").lower().rstrip(".")
        and parsed_port == base_port
    )


def run_poc_replay(
    config_path: str | Path,
    poc_path: str | Path,
    artifacts_root: str | Path = "runs",
    *,
    request_timeout_s: float = 10,
    sandbox_policy: SandboxPolicy | None = None,
    run_lifecycle_commands: bool = False,
    lifecycle_timeout_s: float = 60,
) -> PocReplayResult:
    if request_timeout_s <= 0:
        raise ValueError("request-timeout must be greater than zero")
    target, poc, dynamic = preflight_poc_replay(
        config_path,
        poc_path,
        sandbox_policy=sandbox_policy,
        run_lifecycle_commands=run_lifecycle_commands,
    )
    run_id = _new_run_id(target, poc)
    run_dir = _validate_artifacts_root(artifacts_root) / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    lifecycle: dict[str, Any] = {}
    if run_lifecycle_commands:
        lifecycle = run_lifecycle(target, config_path, timeout_s=lifecycle_timeout_s)

    opener = build_opener(_NoRedirect)
    steps: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    deadline = monotonic() + target.scope.max_runtime_seconds

    for idx, step in enumerate(poc["steps"], start=1):
        if idx > target.scope.max_requests:
            warnings.append("PoC replay stopped at target maxRequests budget")
            break
        remaining = deadline - monotonic()
        if remaining <= 0:
            warnings.append("PoC replay stopped at target maxRuntimeSeconds budget")
            break
        result = _replay_step(opener, target, poc, step, idx, min(request_timeout_s, remaining))
        steps.append(result)
        findings.extend(_findings_for_step(target, run_id, result))

    verified = not findings and len(steps) == min(len(poc["steps"]), target.scope.max_requests)
    doc = {
        "schemaVersion": "poc-replay/v1",
        "runId": run_id,
        "targetId": target.id,
        "pocId": poc.get("id"),
        "findingId": poc.get("findingId"),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "verified": verified,
        "dynamic": dynamic,
        "sandbox": (sandbox_policy or SandboxPolicy()).to_summary(),
        "lifecycle": lifecycle,
        "warnings": warnings,
        "steps": steps,
        "findings": findings,
    }
    replay_path = run_dir / "poc-replay.json"
    grader_path = run_dir / "grader-result.json"
    report_path = run_dir / "report.md"
    _write_json(replay_path, doc)
    grader = GraderResult(
        run_id=run_id,
        target_id=target.id,
        status="verified" if verified else "unverified",
        findings=[f["id"] for f in findings],
        gates=[
            {"name": "sandbox", "passed": (not dynamic) or (sandbox_policy is not None)},
            {"name": "lifecycle", "passed": (not dynamic) or bool(lifecycle)},
            {"name": "egress-allowlist", "passed": True},
        ],
        artifacts={"pocReplay": str(replay_path), "report": str(report_path)},
    )
    _write_json(grader_path, grader.to_dict())
    report_path.write_text(_build_report(target, poc, doc))
    return PocReplayResult(
        success=verified,
        verified=verified,
        run_id=run_id,
        target_id=target.id,
        run_dir=run_dir,
        step_count=len(steps),
        finding_count=len(findings),
        artifacts={"poc_replay": replay_path, "grader_result": grader_path, "report": report_path},
        warnings=warnings,
    )


def _replay_step(opener, target: WebTargetConfig, poc: dict[str, Any], step: dict[str, Any], idx: int, timeout: float) -> dict[str, Any]:  # noqa: ANN001
    req_data = step["request"]
    method = str(req_data.get("method", "GET")).upper()
    url = str(req_data.get("url"))
    headers = {str(k): str(v) for k, v in (req_data.get("headers") or {}).items()}
    body = req_data.get("body")
    body_bytes = None if body in {None, ""} else str(body).encode()
    started = monotonic()
    status: int | None = None
    response_headers: Any = {}
    sample_bytes = 0
    error: str | None = None
    try:
        request = Request(url, data=body_bytes, method=method, headers=headers)
        with opener.open(request, timeout=timeout) as response:
            status = int(response.getcode())
            response_headers = response.headers
            sample_bytes = len(response.read(4096) or b"")
    except HTTPError as exc:
        status = int(exc.code)
        response_headers = exc.headers
        try:
            sample_bytes = len(exc.read(4096) or b"")
        except OSError:
            sample_bytes = 0
    except (TimeoutError, socket.timeout) as exc:
        error = f"timeout: {exc}"
    except URLError as exc:
        error = f"url error: {exc.reason}"
    except OSError as exc:
        error = f"os error: {exc}"

    expect = step.get("expect") if isinstance(step.get("expect"), dict) else {}
    expected_status = expect.get("status")
    redirect = _redirect_summary(target, url, response_headers, status)
    ok = error is None
    if expected_status is not None:
        ok = ok and status == int(expected_status)
    if redirect and redirect.get("allowed") is False:
        ok = False
    return {
        "index": idx,
        "name": str(step.get("name") or f"step-{idx}"),
        "method": method,
        "url": redact_secrets(url),
        "status": status,
        "expectedStatus": expected_status,
        "ok": ok,
        "durationMs": round((monotonic() - started) * 1000, 2),
        "bodyBytesSampled": sample_bytes,
        "redirect": redirect,
        "error": redact_secrets(error) if error else None,
    }


def _redirect_summary(target: WebTargetConfig, url: str, headers: Any, status: int | None) -> dict[str, Any] | None:
    if status is None or not (300 <= status < 400):
        return None
    location = headers.get("Location") if headers else None
    if not location:
        return None
    absolute_url = urljoin(url, str(location))
    return {
        "location": redact_secrets(str(location)),
        "absoluteUrl": redact_secrets(absolute_url),
        "allowed": target.is_redirect_allowed(url, absolute_url),
    }


def _findings_for_step(target: WebTargetConfig, run_id: str, step: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    affected = {"url": step["url"], "step": step["name"]}
    redirect = step.get("redirect")
    redirect_bad = isinstance(redirect, dict) and redirect.get("allowed") is False
    if redirect_bad:
        findings.append(_finding(run_id, target, "poc-redirect-outside-allowlist", "PoC redirect escaped target allowlist", "high", affected, {"redirect": redirect}))
    if step.get("error"):
        findings.append(_finding(run_id, target, f"poc-request-error-{_slug(str(step['name']))}", "PoC request failed", "informational", affected, {"error": step.get("error")}))
    elif not step.get("ok") and not redirect_bad:
        findings.append(_finding(run_id, target, f"poc-expectation-mismatch-{_slug(str(step['name']))}", "PoC response did not match expectation", "medium", affected, {"status": step.get("status"), "expectedStatus": step.get("expectedStatus")}))
    return findings


def _finding(run_id: str, target: WebTargetConfig, finding_id: str, title: str, severity: str, affected: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": "finding/v1",
        "id": finding_id,
        "runId": run_id,
        "targetId": target.id,
        "detectorId": "poc-replay",
        "title": title,
        "description": title,
        "severity": severity,
        "confidence": "high",
        "affected": affected,
        "evidence": evidence,
        "remediation": {"summary": "Review the PoC replay evidence and adjust the target behavior or PoC expectation."},
    }


def _build_report(target: WebTargetConfig, poc: dict[str, Any], doc: dict[str, Any]) -> str:
    lines = [
        f"# PoC replay report: {poc.get('title') or poc.get('id')}",
        "",
        f"- Run ID: `{doc['runId']}`",
        f"- Target ID: `{target.id}`",
        f"- PoC ID: `{poc.get('id')}`",
        f"- Verified: `{doc['verified']}`",
        f"- Dynamic: `{doc['dynamic']}`",
        f"- Findings: {len(doc['findings'])}",
        "",
        "## Safety gates",
        "",
        f"- Sandbox mode: `{doc['sandbox']['mode']}`",
        f"- Credentials mounted: `{doc['sandbox']['credentialsMounted']}`",
        f"- Lifecycle run: `{bool(doc['lifecycle'])}`",
        "",
        "## Steps",
        "",
    ]
    for step in doc["steps"]:
        lines.extend([
            f"### {step['name']}",
            "",
            f"- Method: `{step['method']}`",
            f"- URL: `{step['url']}`",
            f"- Status: `{step['status']}`",
            f"- Expected status: `{step['expectedStatus']}`",
            f"- OK: `{step['ok']}`",
            "",
        ])
    if doc["findings"]:
        lines.extend(["## Findings", ""])
        for finding in doc["findings"]:
            lines.extend([f"- `{finding['id']}`: {finding['title']}"])
        lines.append("")
    return "\n".join(lines)


def _new_run_id(target: WebTargetConfig, poc: dict[str, Any]) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"poc-replay-{stamp}-{_slug(target.id)}-{_slug(str(poc.get('id') or 'poc'))}-{uuid.uuid4().hex[:8]}"


def _validate_artifacts_root(artifacts_root: str | Path) -> Path:
    root = Path(artifacts_root).expanduser().resolve()
    if root.exists() and root.is_symlink():
        raise ValueError("artifacts root must not be a symlink")
    return root


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(_redact_obj(obj), indent=2, sort_keys=True) + "\n")


def _redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_secrets(obj)
    if isinstance(obj, dict):
        return {str(k): _redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v) for v in obj]
    return obj


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower() or "item"
