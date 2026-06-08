"""CSRF (Cross-Site Request Forgery) scan module.
WSTG 4.6.05: Testing for Cross-Site Request Forgery
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .wstg_base import BaseScanConfig, BaseScanResult, _run_scan

# Common CSRF token field names
DEFAULT_CSRF_FIELD_NAMES = ["_csrf", "csrf_token", "csrf-token", "X-CSRF-Token", "_token", "token"]


@dataclass
class CSRFAuthConfig:
    """Authentication configuration for CSRF scanning."""
    login_url: str
    username: str | None = None
    password: str | None = None
    session_cookie: str = "sessionid"

    def __post_init__(self) -> None:
        if self.username is None or self.password is None:
            raise ValueError("CSRF auth requires both username and password credentials")


@dataclass
class CSRFConfig(BaseScanConfig):
    """Configuration for CSRF scanning."""
    auth: Any = None
    token_fields: list[str] | None = None
    token_rotation: bool = True

    def __post_init__(self) -> None:
        super().__post_init__()  # Base validation
        if self.token_fields is None:
            self.token_fields = DEFAULT_CSRF_FIELD_NAMES


@dataclass
class CSRFScanResult(BaseScanResult):
    """Result of a CSRF scan."""

    @property
    def finding_count(self) -> int:
        return len(self.findings)


def _calculate_token_entropy(token: str) -> float:
    """Calculate Shannon entropy of a token string."""
    import math
    if not token:
        return 0.0
    freq: dict[str, int] = {}
    for char in token:
        freq[char] = freq.get(char, 0) + 1
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)


def _check_csrf_token_present(response: dict[str, Any]) -> bool:
    """Check if a response contains a CSRF token."""
    try:
        raw = response.get("rawBody", b"")
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        for field_name in DEFAULT_CSRF_FIELD_NAMES:
            if field_name in text:
                return True
    except Exception:
        pass
    return False


def _test_csrf_endpoint(base_url: str, endpoint: str, timeout: float = 5.0) -> tuple[int, list[dict[str, Any]]]:
    """Test a single endpoint for CSRF vulnerabilities."""
    from ._http_client import _make_http_request, make_url

    findings: list[dict[str, Any]] = []
    requests_sent = 0
    url = make_url(base_url, endpoint)

    # Test GET for CSRF token presence
    get_resp = _make_http_request(url, method="GET", timeout=timeout)
    requests_sent += 1

    has_token_in_get = _check_csrf_token_present(get_resp)
    has_csrf_header = any(
        h.lower() in ("x-csrf-token", "csrf-token")
        for h in get_resp.get("headers", {})
    )

    # Test POST without CSRF token
    post_resp = _make_http_request(
        url, method="POST", body={f: "test" for f in DEFAULT_CSRF_FIELD_NAMES[:2]}, timeout=timeout
    )
    requests_sent += 1

    post_status = post_resp.get("status") or 0

    if post_status == 403:
        findings.append({
            "id": f"csrf-required-{endpoint}",
            "title": "CSRF token required on POST",
            "severity": "INFO",
            "description": f"Endpoint {endpoint} rejects POST requests without CSRF token",
            "confidence": "HIGH",
            "remediation": "Ensure CSRF token validation is consistent across all state-changing endpoints",
            "details": {"endpoint": endpoint, "method": "POST", "status_code": post_status},
        })
    elif post_status == 200 and (has_token_in_get or has_csrf_header):
        try:
            raw = get_resp.get("rawBody", b"")
            body_text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        except Exception:
            body_text = ""
        if "csrf" in body_text.lower() or "_token" in body_text.lower():
            findings.append({
                "id": f"csrf-token-no-validation-{endpoint}",
                "title": "CSRF token present but not validated on POST",
                "severity": "MEDIUM",
                "description": f"GET on {endpoint} returns CSRF token but POST succeeds without it",
                "confidence": "MEDIUM",
                "remediation": "Ensure CSRF tokens are validated on all state-changing requests",
                "details": {"endpoint": endpoint, "method": "POST", "token_in_get": has_token_in_get, "status_code": 200},
            })

    return requests_sent, findings


def run_csrf_scan(
    config_path: str,
    endpoints: list[str] | None = None,
    *,
    artifacts_root: str = "runs",
    request_timeout: float = 5.0,
) -> CSRFScanResult:
    """Run CSRF scan against target."""
    result = _run_scan(
        config_path,
        run_func=_test_csrf_endpoint,
        scan_name="csrf",
        artifact_name="csrf-summary",
        artifacts_root=artifacts_root,
        request_timeout=request_timeout,
        extra_endpoints=endpoints or [],
    )

    return CSRFScanResult(
        run_id=result["run_id"],
        target_id=result["target_id"],
        findings=result.get("findings", []),
        total_requests=result.get("total_requests", 0),
        endpoints_tested=result.get("endpoints_tested", 0),
        artifacts={"csrf_summary": result["artifacts"].get("csrf-summary", "")},
    )
