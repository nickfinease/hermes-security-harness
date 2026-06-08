"""Stored XSS (Cross-Site Scripting) scan module.
WSTG 4.7.02: Testing for Stored Cross-Site Scripting
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .wstg_base import BaseScanConfig, BaseScanResult, _run_scan

# XSS payload patterns to test
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
]

UNENCODED_XSS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'on\w+\s*=\s*["\']?javascript',
    r'<\w+\s[^>]*on\w+\s*=',
    r'javascript:',
    r'<iframe[^>]*src\s*=',
    r'<img[^>]*onerror\s*=',
    r'<svg[^>]*onload\s*=',
]


@dataclass
class StoredXSSConfig(BaseScanConfig):
    """Configuration for Stored XSS scanning."""


@dataclass
class StoredXSSResult(BaseScanResult):
    """Result of a stored XSS scan."""


def _detect_xss_in_content(content: str) -> bool:
    """Check if content contains XSS payloads."""
    for pattern in UNENCODED_XSS_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            return True
    return False


def _is_html_encoded(content: str) -> bool:
    """Check if content has HTML encoding applied."""
    return "&lt;" in content or "&gt;" in content or "&amp;" in content or "&#x" in content


def _test_stored_xss_endpoint(base_url: str, endpoint: str, timeout: float = 5.0) -> tuple[int, list[dict[str, Any]]]:
    """Test a single endpoint for stored XSS."""
    from ._http_client import _make_http_request, make_url

    findings: list[dict[str, Any]] = []
    requests_sent = 0

    for payload in XSS_PAYLOADS:
        post_resp = _make_http_request(make_url(base_url, endpoint), method="POST", body={"data": payload}, timeout=timeout)
        requests_sent += 1

        get_resp = _make_http_request(make_url(base_url, endpoint), method="GET", timeout=timeout)
        requests_sent += 1

        get_body = ""
        try:
            raw = get_resp.get("rawBody", b"")
            get_body = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        except Exception:
            pass

        if payload in get_body and not _is_html_encoded(get_body):
            findings.append({
                "id": f"stored-xss-{endpoint}-{len(findings)}",
                "title": "Stored XSS: payload reflected without encoding",
                "severity": "CRITICAL",
                "description": f"The endpoint {endpoint} stores and reflects the payload without HTML encoding",
                "confidence": "HIGH",
                "remediation": "Implement context-aware output encoding on all user-generated content",
                "details": {"endpoint": endpoint, "method": "POST", "payload": payload, "stored": True, "reflected": True},
            })
            break

    return requests_sent, findings


def run_stored_xss_scan(
    config_path: str,
    endpoints: list[str] | None = None,
    *,
    artifacts_root: str = "runs",
    request_timeout: float = 5.0,
) -> StoredXSSResult:
    """Run stored XSS scan against target."""
    result = _run_scan(
        config_path,
        run_func=_test_stored_xss_endpoint,
        scan_name="stored-xss",
        artifact_name="stored-xss-summary",
        artifacts_root=artifacts_root,
        request_timeout=request_timeout,
        extra_endpoints=endpoints or [],
    )

    return StoredXSSResult(
        run_id=result["run_id"],
        target_id=result["target_id"],
        findings=result.get("findings", []),
        total_requests=result.get("total_requests", 0),
        endpoints_tested=result.get("endpoints_tested", 0),
        artifacts={"stored_xss_summary": result["artifacts"].get("stored-xss-summary", "")},
    )
