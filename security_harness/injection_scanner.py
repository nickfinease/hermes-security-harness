"""Dynamic HTTP injection scanner for XSS, SQLi, and SSRF testing.

This module performs controlled, deterministic injection tests against a target
web application. It is designed for the Hermes Security Harness and does not
use external tools — only the Python stdlib (urllib).

Public API (``__all__``):
    XSSPayload, SQLiPayload, SSRFEndpoint, InjectionScanResult,
    XSS_PAYLOADS, SQLI_PAYLOADS, SSRF_ENDPOINTS,
    run_injection_scan,
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urljoin
from urllib.request import Request

from ._http_client import _make_http_request, make_url, new_run_id, write_json, _json_dumps
from .artifacts import redact_secrets
from .web_target import WebTargetConfig, load_target_config


# ── Payload Definitions ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class XSSPayload:
    """An XSS payload definition.

    Attributes:
        id: Stable identifier for the payload.
        category: Sub-category (e.g. "script-tag", "event-handler", "svg").
        payload: The raw payload string to inject.
        expected_pattern: A regex pattern indicating reflected XSS.
    """

    id: str
    category: str
    payload: str
    expected_pattern: str | None = None

    @property
    def type(self) -> str:
        return self.category


@dataclass(frozen=True)
class SQLiPayload:
    """An SQL injection payload definition.

    Attributes:
        id: Stable identifier for the payload.
        category: Sub-category (e.g. "union", "boolean", "time-based").
        payload: The raw payload string to inject.
        error_pattern: A regex pattern indicating SQL error leakage.
    """

    id: str
    category: str
    payload: str
    error_pattern: str | None = None

    @property
    def type(self) -> str:
        return self.category


@dataclass(frozen=True)
class SSRFEndpoint:
    """An SSRF endpoint definition.

    Attributes:
        id: Stable identifier for the endpoint.
        category: Sub-category (e.g. "cloud-metadata", "internal").
        url: The URL to probe.
    """

    id: str
    category: str
    url: str


# ── Known Payloads ────────────────────────────────────────────────────────────

XSS_PAYLOADS: list[XSSPayload] = [
    XSSPayload("xss-script-tag", "script-tag", "<script>alert(1)</script>"),
    XSSPayload("xss-event-handler", "event-handler", 'onerror=alert(1)'),
    XSSPayload("xss-svg", "svg", "<svg/onload=alert(1)>"),
    XSSPayload("xss-img", "img", '<img src=x onerror=alert(1)>'),
    XSSPayload("xss-input", "input", '<input value=">alert(1)">'),
]

SQLI_PAYLOADS: list[SQLiPayload] = [
    SQLiPayload("sqli-union", "union", "1' UNION SELECT 1,2,3--"),
    SQLiPayload("sqli-boolean", "boolean", "1' OR '1'='1"),
    SQLiPayload("sqli-time", "time-based", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
]

SSRF_ENDPOINTS: list[SSRFEndpoint] = [
    SSRFEndpoint("ssrf-aws", "cloud-metadata", "http://169.254.169.254/latest/meta-data/"),
    SSRFEndpoint("ssrf-gcp", "cloud-metadata", "http://metadata.google.internal/"),
    SSRFEndpoint("ssrf-localhost", "internal", "http://localhost:6379/"),
    SSRFEndpoint("ssrf-docker", "internal", "http://host.docker.internal:80/"),
]


# ── Scan Result ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class InjectionScanResult:
    """Result of an injection scan run.

    Attributes:
        run_id: Stable identifier for this scan run.
        target_id: ID of the scanned target.
        run_dir: Directory containing artifacts.
        success: True if the scan completed without internal errors.
        xss_tests: Number of XSS tests performed.
        sqli_tests: Number of SQLi tests performed.
        ssrf_tests: Number of SSRF tests performed.
        finding_count: Total findings discovered.
        artifacts: Mapping of artifact name to file path.
        warnings: Warnings produced during the scan.
    """

    success: bool
    run_id: str
    target_id: str
    run_dir: Path
    xss_tests: int = 0
    sqli_tests: int = 0
    ssrf_tests: int = 0
    finding_count: int = 0
    artifacts: dict[str, Path] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_summary(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "run_id": self.run_id,
            "target_id": self.target_id,
            "run_dir": str(self.run_dir),
            "xss_tests": self.xss_tests,
            "sqli_tests": self.sqli_tests,
            "ssrf_tests": self.ssrf_tests,
            "finding_count": self.finding_count,
            "artifacts": {k: str(v) for k, v in self.artifacts.items()},
            "warnings": self.warnings,
        }


# ── Main Scan ─────────────────────────────────────────────────────────────────


def run_injection_scan(
    config_path: str | Path,
    artifacts_root: str | Path = "runs",
    *,
    request_timeout_s: float = 5.0,
    request_timeout: float | None = None,  # alias for request_timeout_s
) -> InjectionScanResult:
    """Run an injection scan against a web target and write structured artifacts.

    Args:
        config_path: Path to web-target/v1 YAML or JSON config.
        artifacts_root: Directory for output artifacts.
        request_timeout_s: HTTP request timeout in seconds (default 5.0).
        request_timeout: Alias for request_timeout_s.

    Returns:
        InjectionScanResult with findings and artifacts.
    """
    effective_timeout = request_timeout or request_timeout_s
    target = load_target_config(config_path)
    base_url = target.base_url.rstrip("/")

    artifacts_root_path = Path(artifacts_root).expanduser().resolve()
    if artifacts_root_path.exists() and artifacts_root_path.is_symlink():
        raise ValueError("artifacts root must not be a symlink")

    run_id = new_run_id("injection", target.id)
    run_dir = artifacts_root_path / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    xss_results = _test_xss(base_url, effective_timeout)
    sqli_results = _test_sqli(base_url, effective_timeout)
    ssrf_results = _test_ssrf(base_url, effective_timeout)

    all_findings: list[dict[str, Any]] = []
    all_findings.extend(xss_results.findings)
    all_findings.extend(sqli_results.findings)
    all_findings.extend(ssrf_results.findings)

    warnings: list[str] = list(xss_results.warnings)
    warnings.extend(sqli_results.warnings)
    warnings.extend(ssrf_results.warnings)

    doc = {
        "schemaVersion": "injection-scan/v1",
        "runId": run_id,
        "targetId": target.id,
        "target": target.to_summary(),
        "generatedAt": _iso_now(),
        "safety": {
            "methods": ["GET", "POST"],
            "xss": True,
            "sqli": True,
            "ssrf": True,
        },
        "summary": {
            "xssTests": xss_results.test_count,
            "sqliTests": sqli_results.test_count,
            "ssrfTests": ssrf_results.test_count,
            "findingCount": len(all_findings),
        },
        "warnings": warnings,
        "xssTests": xss_results.to_dict(),
        "sqliTests": sqli_results.to_dict(),
        "ssrfTests": ssrf_results.to_dict(),
        "findings": all_findings,
    }
    scan_path = run_dir / "injection-scan.json"
    scan_path.write_text(_json_dumps(doc) + "\n")

    report_path = run_dir / "report.md"
    report_path.write_text(_build_report(target, run_id, all_findings, warnings))

    result = InjectionScanResult(
        success=True,
        run_id=run_id,
        target_id=target.id,
        run_dir=run_dir,
        xss_tests=xss_results.test_count,
        sqli_tests=sqli_results.test_count,
        ssrf_tests=ssrf_results.test_count,
        finding_count=len(all_findings),
        artifacts={"injection_scan": scan_path, "report": report_path},
        warnings=warnings,
    )
    return result


# ── XSS Testing ───────────────────────────────────────────────────────────────


class _XssResult:
    """Result from XSS tests."""

    def __init__(self) -> None:
        self.test_count: int = 0
        self.findings: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.steps: list[dict[str, Any]] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "testCount": self.test_count,
            "steps": self.steps,
            "findings": self.findings,
            "warnings": self.warnings,
        }


def _test_xss(base_url: str, timeout: float) -> _XssResult:
    """Test for reflected XSS in URL parameters."""
    result = _XssResult()
    params_to_test = ["q", "search", "input", "name", "email", "comment"]

    for param in params_to_test:
        url = make_url(base_url, f"/?{param}=")

        for payload in XSS_PAYLOADS:
            encoded = quote(payload.payload, safe="")
            test_url = f"{url}{encoded}"

            resp = _make_http_request(test_url, timeout=timeout)
            result.test_count += 1

            step = {
                "name": f"xss-{payload.id}",
                "request": {
                    "method": "GET",
                    "url": test_url,
                    "payload": f"[xss/{payload.category}]",
                },
                "status": resp["status"],
                "bodyBytes": resp["bodyBytes"],
            }
            result.steps.append(step)

            xss_finding = _xss_finding(param, test_url, resp, payload)
            if xss_finding:
                result.findings.append(xss_finding)

    return result


def _xss_finding(param: str, url: str, resp: dict[str, Any], payload: XSSPayload) -> dict[str, Any] | None:
    """Check for reflected XSS in response body."""
    body = resp.get("rawBody", b"") or b""

    if isinstance(body, str):
        body_str = body.lower()
    else:
        body_str = body.decode("utf-8", errors="replace").lower()

    payload_body = payload.payload.lower()

    if payload_body in body_str:
        return {
            "schemaVersion": "finding/v1",
            "id": f"xss-reflected-{payload.id}",
            "runId": "",
            "targetId": "",
            "detectorId": "injection-scan",
            "title": f"Reflected XSS in parameter '{param}'",
            "description": f"The XSS payload was reflected in the response body.",
            "severity": "high",
            "confidence": "high",
            "affected": {"url": url, "parameter": param},
            "evidence": {
                "payload": payload.payload,
                "category": payload.category,
                "reflected": True,
            },
            "remediation": {
                "summary": "Implement output encoding and Content-Security-Policy.",
            },
        }

    return None


# ── SQLi Testing ──────────────────────────────────────────────────────────────


class _SqlInjectionResult:
    """Result from SQL injection tests."""

    def __init__(self) -> None:
        self.test_count: int = 0
        self.findings: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.steps: list[dict[str, Any]] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "testCount": self.test_count,
            "steps": self.steps,
            "findings": self.findings,
            "warnings": self.warnings,
        }


def _test_sqli(base_url: str, timeout: float) -> _SqlInjectionResult:
    """Test for SQL injection in URL parameters."""
    result = _SqlInjectionResult()
    params_to_test = ["id", "page", "user", "category", "sort"]

    for param in params_to_test:
        url = make_url(base_url, f"/?{param}=")

        for payload in SQLI_PAYLOADS:
            encoded = quote(payload.payload, safe="")
            test_url = f"{url}{encoded}"

            resp = _make_http_request(test_url, timeout=timeout)
            result.test_count += 1

            step = {
                "name": f"sqli-{payload.id}",
                "request": {
                    "method": "GET",
                    "url": test_url,
                    "payload": f"[sqli/{payload.category}]",
                },
                "status": resp["status"],
            }
            result.steps.append(step)

            sqli_finding = _sqli_finding(param, test_url, resp, payload)
            if sqli_finding:
                result.findings.append(sqli_finding)

    return result


def _sqli_finding(
    param: str, url: str, resp: dict[str, Any], payload: SQLiPayload
) -> dict[str, Any] | None:
    """Check for SQL error leakage in response."""
    status = resp.get("status") or 0
    error_msg = resp.get("error") or ""
    body = resp.get("rawBody", b"") or b""

    if isinstance(body, str):
        body_str = body.lower()
    else:
        body_str = body.decode("utf-8", errors="replace").lower()

    # Check for SQL error patterns in body
    sql_errors = [
        "sql syntax",
        "mysql",
        "postgres",
        "sqlite",
        "oracle",
        "syntax error",
        "unexpected",
        "database",
    ]

    for sql_err in sql_errors:
        if sql_err in body_str:
            return {
                "schemaVersion": "finding/v1",
                "id": f"sqli-error-leak-{payload.id}",
                "runId": "",
                "targetId": "",
                "detectorId": "injection-scan",
                "title": f"SQL error leakage in parameter '{param}'",
                "description": "SQL error messages were found in the response body.",
                "severity": "high",
                "confidence": "medium",
                "affected": {"url": url, "parameter": param},
                "evidence": {
                    "payload": payload.payload,
                    "category": payload.category,
                    "sqlErrors": [sql_err],
                },
                "remediation": {
                    "summary": "Use parameterized queries and suppress database errors.",
                },
            }

    return None


# ── SSRF Testing ─────────────────────────────────────────────────────────────


class _SsrfResult:
    """Result from SSRF tests."""

    def __init__(self) -> None:
        self.test_count: int = 0
        self.findings: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.steps: list[dict[str, Any]] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "testCount": self.test_count,
            "steps": self.steps,
            "findings": self.findings,
            "warnings": self.warnings,
        }


def _test_ssrf(base_url: str, timeout: float) -> _SsrfResult:
    """Test for SSRF in URL parameters."""
    result = _SsrfResult()

    for endpoint in SSRF_ENDPOINTS:
        test_url = make_url(base_url, "/")

        resp = _make_http_request(endpoint.url, timeout=timeout)
        result.test_count += 1

        step = {
            "name": f"ssrf-{endpoint.id}",
            "request": {
                "method": "GET",
                "url": endpoint.url,
            },
            "status": resp["status"],
            "redirect": resp.get("error"),
        }
        result.steps.append(step)

        ssrf_finding = _ssrf_finding(endpoint.url, resp)
        if ssrf_finding:
            result.findings.append(ssrf_finding)

    return result


def _ssrf_finding(url: str, resp: dict[str, Any]) -> dict[str, Any] | None:
    """Create an SSRF finding if the endpoint is reachable."""
    status = resp.get("status")
    error = resp.get("error")

    # SSRF is concerning if the probe actually reaches the target
    if status and 200 <= status < 500 and not error:
        return {
            "schemaVersion": "finding/v1",
            "id": f"ssrf-{url.split('://')[1].replace('/', '-')}",
            "runId": "",
            "targetId": "",
            "detectorId": "injection-scan",
            "title": f"SSRF: endpoint reachable at {url}",
            "description": f"The SSRF probe to {url} was successful.",
            "severity": "high",
            "confidence": "high",
            "affected": {"url": url, "status": status},
            "evidence": {"status": status},
            "remediation": {
                "summary": "Implement allowlists and restrict outbound connections.",
            },
        }

    return None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _build_report(target: WebTargetConfig, run_id: str, findings: list[dict[str, Any]], warnings: list[str]) -> str:
    """Build a Markdown report."""
    lines = [
        f"# Injection scan report: {target.name}",
        "",
        f"- Run ID: `{run_id}`",
        f"- Target ID: `{target.id}`",
        f"- Base URL: `{target.base_url}`",
        f"- Findings: {len(findings)}",
        "",
        "## Safety boundary",
        "",
        "This run used controlled injection payloads (XSS, SQLi, SSRF) to probe configured endpoints.",
        "",
    ]
    if findings:
        lines.extend(["## Findings", ""])
        for finding in findings:
            lines.extend([
                f"### {finding.get('title', 'Unknown')}",
                "",
                f"- ID: `{finding.get('id', '')}`",
                f"- Severity: `{finding.get('severity', '')}`",
                f"- Description: {finding.get('description', '')}",
                "",
            ])
    if warnings:
        lines.extend(["## Warnings", ""])
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")
    return "\n".join(lines)


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
