"""Deterministic read-only HTTP smoke scanner.

This module implements the first deliberately narrow dynamic tier: bounded GET
requests to explicitly configured local/staging paths. It does not crawl, follow
redirects, submit forms, authenticate, mutate state, or run detector payloads.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
import fnmatch
import json
import re
import socket
import uuid

from .artifacts import redact_secrets
from .web_target import WebTargetConfig, load_target_config

READ_ONLY_METHOD = "GET"
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]
HTTPS_ONLY_SECURITY_HEADERS = ["Strict-Transport-Security"]
_OBSERVED_HEADERS = SECURITY_HEADERS + HTTPS_ONLY_SECURITY_HEADERS


@dataclass(frozen=True)
class HttpSmokeResult:
    success: bool
    run_id: str
    target_id: str
    run_dir: Path
    request_count: int
    finding_count: int
    artifacts: dict[str, Path]
    warnings: list[str]

    def to_summary(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "run_id": self.run_id,
            "target_id": self.target_id,
            "run_dir": str(self.run_dir),
            "request_count": self.request_count,
            "finding_count": self.finding_count,
            "artifacts": {key: str(value) for key, value in self.artifacts.items()},
            "warnings": self.warnings,
        }


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401, ANN001
        return None


def run_http_smoke(
    config_path: str | Path,
    artifacts_root: str | Path = "runs",
    *,
    request_timeout_s: float = 10,
) -> HttpSmokeResult:
    """Run bounded GET-only reachability/security-header checks."""
    if request_timeout_s <= 0:
        raise ValueError("request-timeout must be greater than zero")
    target = load_target_config(config_path)
    warnings: list[str] = []
    paths = _concrete_scope_paths(target, warnings)
    if not paths:
        raise ValueError("http-smoke requires at least one concrete includePaths entry; wildcard paths are not crawled")
    if len(paths) > target.scope.max_requests:
        warnings.append(
            f"request list truncated from {len(paths)} to maxRequests={target.scope.max_requests}"
        )
        paths = paths[: target.scope.max_requests]

    run_id = _new_run_id(target)
    run_dir = _validate_artifacts_root(artifacts_root) / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    started = monotonic()
    deadline = started + target.scope.max_runtime_seconds
    opener = build_opener(_NoRedirect)
    requests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for path in paths:
        remaining = deadline - monotonic()
        if remaining <= 0:
            warnings.append("maxRuntimeSeconds reached before all configured paths were checked")
            break
        timeout = min(request_timeout_s, remaining)
        url = _url_for_path(target, path)
        if not target.is_url_allowed(url):
            raise ValueError(f"configured scope URL is outside allowedHosts: {url}")
        result = _fetch_once(opener, target, path, url, timeout)
        requests.append(result)
        findings.extend(_findings_for_request(target, run_id, result))

    doc = {
        "schemaVersion": "http-smoke/v1",
        "runId": run_id,
        "targetId": target.id,
        "target": target.to_summary(),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "safety": {
            "methods": [READ_ONLY_METHOD],
            "redirectFollowing": False,
            "crawling": False,
            "authentication": False,
            "formSubmission": False,
            "requestBudget": target.scope.max_requests,
            "maxRuntimeSeconds": target.scope.max_runtime_seconds,
        },
        "summary": {
            "requestCount": len(requests),
            "findingCount": len(findings),
            "okStatuses": sum(1 for item in requests if 200 <= int(item.get("status") or 0) < 400),
            "errors": sum(1 for item in requests if item.get("error")),
        },
        "warnings": warnings,
        "requests": requests,
        "findings": findings,
    }
    smoke_path = run_dir / "http-smoke.json"
    report_path = run_dir / "report.md"
    _write_json(smoke_path, doc)
    report_path.write_text(_build_report(target, run_id, doc))

    return HttpSmokeResult(
        success=True,
        run_id=run_id,
        target_id=target.id,
        run_dir=run_dir,
        request_count=len(requests),
        finding_count=len(findings),
        artifacts={"http_smoke": smoke_path, "report": report_path},
        warnings=warnings,
    )


def _concrete_scope_paths(target: WebTargetConfig, warnings: list[str]) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for raw_path in target.scope.include_paths:
        path = str(raw_path).strip()
        if not path:
            continue
        if any(token in path for token in ("*", "[", "]", "{")):
            warnings.append(f"skipped wildcard includePath {path!r}; http-smoke does not crawl or expand globs")
            continue
        if not path.startswith("/"):
            raise ValueError("http-smoke includePaths entries must start with '/'")
        if _path_excluded(path, target.scope.exclude_paths):
            warnings.append(f"skipped excluded includePath {path!r}")
            continue
        normalized = path or "/"
        if normalized not in seen:
            seen.add(normalized)
            paths.append(normalized)
    return paths


def _path_excluded(path: str, exclude_paths: list[str]) -> bool:
    bare_path = urlparse(path).path or "/"
    return any(fnmatch.fnmatch(bare_path, pattern) for pattern in exclude_paths)


def _url_for_path(target: WebTargetConfig, path: str) -> str:
    base = target.base_url.rstrip("/") + "/"
    return urljoin(base, path.lstrip("/"))


def _fetch_once(opener, target: WebTargetConfig, path: str, url: str, timeout: float) -> dict[str, Any]:  # noqa: ANN001
    started = monotonic()
    status: int | None = None
    headers: Any = {}
    body_bytes = 0
    error: str | None = None
    try:
        req = Request(url, method=READ_ONLY_METHOD, headers={"User-Agent": "HermesSecurityHarness/0.1"})
        with opener.open(req, timeout=timeout) as response:
            status = int(response.getcode())
            headers = response.headers
            body_bytes = len(response.read(4096) or b"")
    except HTTPError as exc:
        status = int(exc.code)
        headers = exc.headers
        try:
            body_bytes = len(exc.read(4096) or b"")
        except OSError:
            body_bytes = 0
    except (TimeoutError, socket.timeout) as exc:
        error = f"timeout: {exc}"
    except URLError as exc:
        error = f"url error: {exc.reason}"
    except OSError as exc:
        error = f"os error: {exc}"

    duration_ms = round((monotonic() - started) * 1000, 2)
    security = _security_header_summary(target, headers)
    redirect = _redirect_summary(target, url, headers)
    return {
        "path": path,
        "url": redact_secrets(url),
        "method": READ_ONLY_METHOD,
        "status": status,
        "durationMs": duration_ms,
        "bodyBytesSampled": body_bytes,
        "contentType": redact_secrets(str(_header(headers, "Content-Type") or "")) or None,
        "securityHeaders": security,
        "redirect": redirect,
        "error": redact_secrets(error) if error else None,
    }


def _security_header_summary(target: WebTargetConfig, headers: Any) -> dict[str, Any]:
    required = list(SECURITY_HEADERS)
    if urlparse(target.base_url).scheme == "https":
        required += HTTPS_ONLY_SECURITY_HEADERS
    present = [name for name in _OBSERVED_HEADERS if _header(headers, name)]
    missing = [name for name in required if not _header(headers, name)]
    values = {name: redact_secrets(str(_header(headers, name))) for name in present}
    return {"required": required, "present": present, "missing": missing, "values": values}


def _redirect_summary(target: WebTargetConfig, url: str, headers: Any) -> dict[str, Any] | None:
    location = _header(headers, "Location")
    if not location:
        return None
    absolute_url = urljoin(url, str(location))
    return {
        "location": redact_secrets(str(location)),
        "absoluteUrl": redact_secrets(absolute_url),
        "allowed": target.is_redirect_allowed(url, absolute_url),
    }


def _findings_for_request(target: WebTargetConfig, run_id: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    affected = {"url": result["url"], "path": result["path"]}
    redirect = result.get("redirect")
    if isinstance(redirect, dict) and redirect.get("allowed") is False:
        findings.append(
            _finding(
                run_id,
                target,
                "redirect-outside-allowlist",
                "Redirect points outside target allowlist",
                "medium",
                "high",
                affected,
                {
                    "status": result.get("status"),
                    "location": redirect.get("location"),
                    "absoluteUrl": redirect.get("absoluteUrl"),
                },
                "Normalize redirects server-side and allow only same-origin or explicitly allowlisted destinations.",
            )
        )
    missing = result.get("securityHeaders", {}).get("missing", [])
    if missing:
        slug = _slug_for_path(str(result.get("path") or "root"))
        findings.append(
            _finding(
                run_id,
                target,
                f"missing-security-headers-{slug}",
                "Response is missing baseline security headers",
                "low",
                "high",
                affected,
                {"missingHeaders": missing, "status": result.get("status")},
                "Add the missing headers in shared middleware so all scoped responses receive the same baseline policy.",
            )
        )
    if result.get("error"):
        slug = _slug_for_path(str(result.get("path") or "root"))
        findings.append(
            _finding(
                run_id,
                target,
                f"target-unreachable-{slug}",
                "Configured target path was unreachable during smoke scan",
                "informational",
                "high",
                affected,
                {"error": result.get("error")},
                "Verify the local/staging app is running and the target path is in scope before deeper scans.",
            )
        )
    return findings


def _finding(
    run_id: str,
    target: WebTargetConfig,
    finding_id: str,
    title: str,
    severity: str,
    confidence: str,
    affected: dict[str, Any],
    evidence: dict[str, Any],
    remediation_summary: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": "finding/v1",
        "id": finding_id,
        "runId": run_id,
        "targetId": target.id,
        "detectorId": "http-smoke",
        "title": title,
        "description": title,
        "severity": severity,
        "confidence": confidence,
        "affected": affected,
        "evidence": evidence,
        "remediation": {"summary": remediation_summary},
    }


def _build_report(target: WebTargetConfig, run_id: str, doc: dict[str, Any]) -> str:
    lines = [
        f"# HTTP smoke report: {target.name}",
        "",
        f"- Run ID: `{run_id}`",
        f"- Target ID: `{target.id}`",
        f"- Base URL: `{target.base_url}`",
        f"- Requests: {doc['summary']['requestCount']}",
        f"- Findings: {doc['summary']['findingCount']}",
        "",
        "## Safety boundary",
        "",
        "This run used deterministic GET-only requests to explicit includePaths. It did not crawl, follow redirects, authenticate, submit forms, or mutate state.",
        "",
        "## Requests",
        "",
    ]
    for item in doc["requests"]:
        redirect = item.get("redirect") or {}
        lines.extend(
            [
                f"### GET {item['path']}",
                "",
                f"- URL: `{item['url']}`",
                f"- Status: `{item['status']}`",
                f"- Duration ms: `{item['durationMs']}`",
                f"- Redirect: `{redirect.get('location') if redirect else None}`",
                f"- Redirect allowed: `{redirect.get('allowed') if redirect else None}`",
                f"- Missing security headers: {item['securityHeaders']['missing']}",
                "",
            ]
        )
    if doc["findings"]:
        lines.extend(["## Findings", ""])
        for finding in doc["findings"]:
            lines.extend(
                [
                    f"### {finding['title']}",
                    "",
                    f"- ID: `{finding['id']}`",
                    f"- Severity: `{finding['severity']}`",
                    f"- Affected: `{json.dumps(finding['affected'], sort_keys=True)}`",
                    "",
                ]
            )
    if doc["warnings"]:
        lines.extend(["## Warnings", ""])
        for warning in doc["warnings"]:
            lines.append(f"- {warning}")
        lines.append("")
    return "\n".join(lines)


def _header(headers: Any, name: str) -> str | None:
    if not headers:
        return None
    value = headers.get(name)
    return str(value) if value is not None else None


def _new_run_id(target: WebTargetConfig) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_target = re.sub(r"[^A-Za-z0-9_-]+", "-", target.id).strip("-") or "target"
    return f"http-smoke-{stamp}-{safe_target}-{uuid.uuid4().hex[:8]}"


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
        return {str(key): _redact_obj(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(value) for value in obj]
    return obj


def _slug_for_path(path: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", path.strip("/")).strip("-").lower()
    return slug or "root"
