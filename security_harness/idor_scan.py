"""IDOR / BOLA (Insecure Direct Object Reference / Broken Object Level Authorization).
WSTG 4.5.04: Testing for Insecure Direct Object References
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .wstg_base import BaseScanConfig, BaseScanResult, _run_scan

PATH_PARAM_PATTERN = re.compile(r"\{(\w+)\}|:(\w+)")


@dataclass
class IDORAuthConfig:
    """Authentication configuration for IDOR scanning."""
    login_url: str
    username: str | None = None
    password: str | None = None
    session_cookie: str = "sessionid"

    def __post_init__(self) -> None:
        if self.username is None or self.password is None:
            raise ValueError("IDOR auth requires both username and password credentials")


@dataclass
class IDORConfig(BaseScanConfig):
    """Configuration for IDOR scanning."""
    auth: Any = None
    test_values: list[str] | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.test_values is None:
            self.test_values = ["user1", "user2", "admin", "test123"]


@dataclass
class IDORScanResult(BaseScanResult):
    """Result of an IDOR scan."""


def _extract_path_params(endpoint: str) -> list[str]:
    """Extract path parameters from an endpoint URL."""
    params: list[str] = []
    for match in PATH_PARAM_PATTERN.finditer(endpoint):
        name = match.group(1) or match.group(2)
        if name and name not in params:
            params.append(name)
    return params


def _test_idor_endpoint(base_url: str, endpoint: str, timeout: float = 5.0) -> tuple[int, list[dict[str, Any]]]:
    """Test a single endpoint for IDOR vulnerabilities."""
    from ._http_client import _make_http_request, make_url

    findings: list[dict[str, Any]] = []
    requests_sent = 0
    params = _extract_path_params(endpoint)

    if not params:
        return 0, findings

    # Test with multiple values
    responses: list[tuple[str, int]] = []
    for value in ["user1", "user2", "admin", "test123"]:
        url = endpoint
        for param in params:
            url = url.replace(f"{{{param}}}", value).replace(f":{param}", value)
        full_url = make_url(base_url, url)

        resp = _make_http_request(full_url, method="GET", timeout=timeout)
        requests_sent += 1
        status = resp.get("status") or 0
        responses.append((value, status))

    # Check for IDOR: same status for different values
    if len(responses) >= 2:
        statuses = set(s for _, s in responses)
        if len(statuses) <= 1 and 200 in statuses:
            values_list = [v for v, _ in responses]
            findings.append({
                "id": f"idor-unauthenticated-{endpoint}",
                "title": "Potential IDOR: unauthenticated access returns 200",
                "severity": "HIGH",
                "description": f"The endpoint {endpoint} returns 200 for values {values_list} without authentication",
                "confidence": "HIGH",
                "remediation": "Implement ownership verification on all resource endpoints",
                "details": {"endpoint": endpoint, "method": "GET", "test_values": values_list, "status_code": 200, "requires_auth": True},
            })

    return requests_sent, findings


def run_idor_scan(
    config_path: str,
    endpoints: list[str] | None = None,
    *,
    artifacts_root: str = "runs",
    request_timeout: float = 5.0,
) -> IDORScanResult:
    """Run IDOR scan against target."""
    result = _run_scan(
        config_path,
        run_func=_test_idor_endpoint,
        scan_name="idor",
        artifact_name="idor-summary",
        artifacts_root=artifacts_root,
        request_timeout=request_timeout,
        extra_endpoints=endpoints or [],
    )

    return IDORScanResult(
        run_id=result["run_id"],
        target_id=result["target_id"],
        findings=result.get("findings", []),
        total_requests=result.get("total_requests", 0),
        endpoints_tested=result.get("endpoints_tested", 0),
        artifacts={"idor_summary": result["artifacts"].get("idor-summary", "")},
    )
