"""Rate limit detection for the Hermes Security Harness.

This module detects rate limiting behavior on web endpoints by
sending burst requests and analyzing response patterns.

Public API (``__all__``):
    RateLimitConfig, RateLimitResult,
    run_rate_limit_scan,
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._http_client import _make_http_request, make_url, new_run_id, write_json, _json_dumps
from .web_target import WebTargetConfig, load_target_config


# ── Configuration ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RateLimitConfig:
    """Configuration for rate limit detection tests.

    Attributes:
        burst_size: Number of requests to send in a burst.
        delay_ms: Milliseconds delay between requests.
        endpoints: URLs to test.
        login_url: Login URL for authenticated tests.
        signup_url: Signup URL for rate limit tests.
    """

    burst_size: int = 10
    delay_ms: int = 100
    endpoints: list[str] = field(default_factory=lambda: ["/api", "/health"])
    login_url: str = "/login"
    signup_url: str = "/signup"


# ── Result ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RateLimitResult:
    """Result of a rate limit scan.

    Attributes:
        run_id: Stable identifier for this scan run.
        target_id: ID of the scanned target.
        run_dir: Directory containing artifacts.
        success: True if the scan completed without internal errors.
        endpoint_count: Number of endpoints tested.
        total_requests: Total HTTP requests sent.
        finding_count: Total findings discovered.
        artifacts: Mapping of artifact name to file path.
        warnings: Warnings produced during the scan.
    """

    success: bool
    run_id: str
    target_id: str
    run_dir: Path
    endpoint_count: int = 0
    total_requests: int = 0
    finding_count: int = 0
    artifacts: dict[str, Path] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_summary(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "run_id": self.run_id,
            "target_id": self.target_id,
            "run_dir": str(self.run_dir),
            "endpoint_count": self.endpoint_count,
            "total_requests": self.total_requests,
            "finding_count": self.finding_count,
            "artifacts": {k: str(v) for k, v in self.artifacts.items()},
            "warnings": self.warnings,
        }


# ── Main Scan ─────────────────────────────────────────────────────────────────


def run_rate_limit_scan(
    config_path: str | Path,
    artifacts_root: str | Path = "runs",
    *,
    request_timeout: float = 3.0,
    config: RateLimitConfig | None = None,
) -> RateLimitResult:
    """Run a rate limit detection scan and write structured artifacts.

    Args:
        config_path: Path to web-target/v1 YAML or JSON config.
        artifacts_root: Directory for output artifacts.
        request_timeout: HTTP request timeout in seconds.
        config: RateLimitConfig with test parameters.

    Returns:
        RateLimitResult with findings and artifacts.
    """
    target = load_target_config(config_path)
    base_url = target.base_url.rstrip("/")

    if config is None:
        config = RateLimitConfig(
            burst_size=10,
            delay_ms=100,
            endpoints=["/api", "/health"],
        )

    endpoint_paths = config.endpoints if config.endpoints else ["/api", "/health"]

    artifacts_root_path = Path(artifacts_root).expanduser().resolve()
    if artifacts_root_path.exists() and artifacts_root_path.is_symlink():
        raise ValueError("artifacts root must not be a symlink")

    run_id = new_run_id("rate-limit", target.id)
    run_dir = artifacts_root_path / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    if config is None:
        config = RateLimitConfig(
            burst_size=10,
            delay_ms=100,
            endpoints=endpoint_paths,
        )

    endpoint_results = [_rate_limit_endpoint(base_url, endpoint, config) for endpoint in endpoint_paths]
    all_findings: list[dict[str, Any]] = []
    total_requests = 0

    for ep_result in endpoint_results:
        all_findings.extend(ep_result.findings)
        total_requests += ep_result.requests_sent

    warnings: list[str] = []
    for ep_result in endpoint_results:
        warnings.extend(ep_result.warnings)

    doc = {
        "schemaVersion": "rate-limit/v1",
        "runId": run_id,
        "targetId": target.id,
        "target": target.to_summary(),
        "generatedAt": _iso_now(),
        "safety": {
            "burstRequests": config.burst_size,
            "delayMs": config.delay_ms,
        },
        "summary": {
            "endpointCount": len(endpoint_paths),
            "totalRequests": total_requests,
            "findingCount": len(all_findings),
        },
        "warnings": warnings,
        "endpoints": [ep.to_dict() for ep in endpoint_results],
        "findings": all_findings,
    }
    scan_path = run_dir / "rate-limit.json"
    scan_path.write_text(_json_dumps(doc) + "\n")

    report_path = run_dir / "report.md"
    report_path.write_text(_build_report(target, run_id, all_findings, warnings))

    result = RateLimitResult(
        success=True,
        run_id=run_id,
        target_id=target.id,
        run_dir=run_dir,
        endpoint_count=len(endpoint_paths),
        total_requests=total_requests,
        finding_count=len(all_findings),
        artifacts={"rate_limit": scan_path, "report": report_path},
        warnings=warnings,
    )
    return result


# ── Endpoint Testing ──────────────────────────────────────────────────────────


class _EndpointResult:
    """Result from testing a single endpoint."""

    def __init__(self) -> None:
        self.findings: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.requests_sent: int = 0
        self.statuses: list[int] = []
        self.retry_after: list[str] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "statuses": self.statuses,
            "findings": self.findings,
            "warnings": self.warnings,
        }


def _rate_limit_endpoint(
    base_url: str, endpoint: str, config: RateLimitConfig
) -> _EndpointResult:
    """Test a single endpoint for rate limiting."""
    result = _EndpointResult()

    for i in range(config.burst_size):
        full_url = make_url(base_url, endpoint)

        resp = _make_http_request(full_url, timeout=5.0)
        result.requests_sent += 1

        status = resp.get("status") or 0
        result.statuses.append(status)

        if status == 429:
            retry_after = ""
            for key, val in resp.get("headers", {}).items():
                if key.lower() == "retry-after":
                    retry_after = val
                    break
            result.retry_after.append(retry_after)

            finding = _rate_limit_finding(full_url, i + 1, resp)
            if finding:
                result.findings.append(finding)

    # Detect error escalation pattern
    if len(result.statuses) >= 2:
        escalation_finding = _rate_limit_gradual_finding(base_url + endpoint, result.statuses)
        if escalation_finding:
            result.findings.append(escalation_finding)

    # Check for auth bypass after rate limit
    last_url = make_url(base_url, endpoint)
    if len(result.statuses) >= 3:
        first = result.statuses[0]
        second = result.statuses[1]
        third = result.statuses[2]
        if first and second and third:
            if first != second and second == 429 and third != 429:
                bypass_finding = _rate_limit_bypass_finding(last_url, result.statuses)
                if bypass_finding:
                    result.findings.append(bypass_finding)

    return result


def _rate_limit_finding(url: str, attempt: int, resp: dict[str, Any]) -> dict[str, Any]:
    """Create a finding for rate limiting on an endpoint."""
    retry_after = ""
    for key, val in resp.get("headers", {}).items():
        if key.lower() == "retry-after":
            retry_after = val
            break

    return {
        "schemaVersion": "finding/v1",
        "id": f"rate-limit-{url.split('/')[-1] or 'root'}-{attempt}",
        "runId": "",
        "targetId": "",
        "detectorId": "rate-limit",
        "title": f"Rate limiting on {url}",
        "description": f"The endpoint returned a 429 status on attempt {attempt}.",
        "severity": "informational",
        "confidence": "high",
        "affected": {"url": url, "attempt": attempt},
        "evidence": {
            "status": resp.get("status"),
            "retryAfter": retry_after,
        },
        "remediation": {
            "summary": "Implement proper rate limiting on all endpoints.",
        },
    }


def _rate_limit_gradual_finding(url: str, statuses: list[int]) -> dict[str, Any] | None:
    """Detect gradual error escalation pattern."""
    if len(statuses) >= 3:
        escalating = any(
            statuses[i] < statuses[i + 1]
            for i in range(len(statuses) - 1)
            if statuses[i] and statuses[i + 1]
        )
        if escalating:
            return {
                "schemaVersion": "finding/v1",
                "id": f"gradual-error-escalation-{url.split('/')[-1] or 'root'}",
                "runId": "",
                "targetId": "",
                "detectorId": "rate-limit",
                "title": f"Gradual error escalation on {url}",
                "description": "Status codes escalated from 200 to higher codes, indicating rate limiting.",
                "severity": "medium",
                "confidence": "medium",
                "affected": {"url": url, "statuses": statuses},
                "evidence": {"statuses": statuses},
                "remediation": {
                    "summary": "Implement consistent error responses for rate-limited requests.",
                },
            }
    return None


def _rate_limit_bypass_finding(url: str, statuses: list[int]) -> dict[str, Any] | None:
    """Detect auth bypass after rate limit exhaustion."""
    if len(statuses) >= 3:
        # If we see 200, 429, 200 pattern, that's concerning
        if statuses[0] and statuses[0] < 400 and statuses[1] and statuses[1] == 429 and statuses[2] and statuses[2] < 400:
            return {
                "schemaVersion": "finding/v1",
                "id": f"rate-limit-bypass-{url.split('/')[-1] or 'root'}",
                "runId": "",
                "targetId": "",
                "detectorId": "rate-limit",
                "title": f"Possible rate limit bypass on {url}",
                "description": "Status went 200 → 429 → 200, which may indicate rate limiting is not enforced.",
                "severity": "medium",
                "confidence": "medium",
                "affected": {"url": url, "statuses": statuses},
                "evidence": {"statuses": statuses},
                "remediation": {
                    "summary": "Verify rate limiting is properly enforced and consistent.",
                },
            }
    return None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _build_report(target: WebTargetConfig, run_id: str, findings: list[dict[str, Any]], warnings: list[str]) -> str:
    """Build a Markdown report."""
    lines = [
        f"# Rate limit report: {target.name}",
        "",
        f"- Run ID: `{run_id}`",
        f"- Target ID: `{target.id}`",
        f"- Base URL: `{target.base_url}`",
        f"- Findings: {len(findings)}",
        "",
        "## Safety boundary",
        "",
        "This run sent burst requests to configured endpoints to detect rate limiting patterns.",
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
