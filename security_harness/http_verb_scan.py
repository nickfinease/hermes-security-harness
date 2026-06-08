"""HTTP Verb Tampering scan module.
WSTG 4.7.03: Testing for HTTP Verb Tampering
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .wstg_base import BaseScanConfig, BaseScanResult, _run_scan

# HTTP methods to test (all verb tampering candidates)
HTTP_VERB_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]


@dataclass
class HTTPVerbConfig(BaseScanConfig):
    """Configuration for HTTP Verb tampering scanning."""


@dataclass
class HTTPVerbResult(BaseScanResult):
    """Result of an HTTP Verb tampering scan."""


def _test_http_verb_endpoint(base_url: str, endpoint: str, timeout: float = 5.0) -> tuple[int, list[dict[str, Any]]]:
    """Test a single endpoint for HTTP verb tampering."""
    from ._http_client import _make_http_request, make_url

    findings: list[dict[str, Any]] = []
    requests_sent = 0

    for method in HTTP_VERB_METHODS:
        resp = _make_http_request(make_url(base_url, endpoint), method=method, timeout=timeout)
        requests_sent += 1

        status = resp.get("status") or 0
        body_text = ""
        try:
            raw = resp.get("rawBody", b"")
            body_text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        except Exception:
            pass

        if status == 200 and '"ok"' in body_text and method in ("PUT", "DELETE", "PATCH"):
            findings.append({
                "id": f"http-verb-tampering-{endpoint}-{method.lower()}",
                "title": f"HTTP Verb Tampering: {method} accepted on {endpoint}",
                "severity": "MEDIUM",
                "description": f"The endpoint {endpoint} accepts {method} requests when typically only GET/POST are expected",
                "confidence": "HIGH",
                "remediation": "Implement proper HTTP method restrictions on all endpoints",
                "details": {"endpoint": endpoint, "tampered_method": method, "status_code": status},
            })

    return requests_sent, findings


def run_http_verb_scan(
    config_path: str,
    endpoints: list[str] | None = None,
    *,
    artifacts_root: str = "runs",
    request_timeout: float = 5.0,
) -> HTTPVerbResult:
    """Run HTTP Verb tampering scan against target."""
    result = _run_scan(
        config_path,
        run_func=_test_http_verb_endpoint,
        scan_name="http-verb",
        artifact_name="http-verb-summary",
        artifacts_root=artifacts_root,
        request_timeout=request_timeout,
        extra_endpoints=endpoints or [],
    )

    return HTTPVerbResult(
        run_id=result["run_id"],
        target_id=result["target_id"],
        findings=result.get("findings", []),
        total_requests=result.get("total_requests", 0),
        endpoints_tested=result.get("endpoints_tested", 0),
        artifacts={"http_verb_summary": result["artifacts"].get("http-verb-summary", "")},
    )
