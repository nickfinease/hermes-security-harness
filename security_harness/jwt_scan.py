"""JWT (JSON Web Token) weaknesses scan module.
WSTG 4.6.10: Testing JSON Web Tokens
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any

from .wstg_base import BaseScanConfig, BaseScanResult, _run_scan

JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+\.[A-Za-z0-9_-]*$")

SENSITIVE_CLAIMS = ["password", "secret", "apiKey", "api_key", "token", "refresh_token", "private_key", "credentials"]


@dataclass
class JWTConfig(BaseScanConfig):
    """Configuration for JWT scanning."""


@dataclass
class JWTScanResult(BaseScanResult):
    """Result of a JWT scan."""


def _b64url_decode(s: str) -> str | None:
    """Decode a base64url-encoded string."""
    try:
        padding = "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s + padding).decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_jwt_header(jwt_token: str) -> dict[str, Any] | None:
    """Extract and decode the JWT header."""
    parts = jwt_token.split(".")
    if len(parts) < 2:
        return None
    header_json = _b64url_decode(parts[0])
    if not header_json:
        return None
    try:
        return json.loads(header_json)
    except (json.JSONDecodeError, TypeError):
        return None


def _is_valid_jwt(token: str) -> bool:
    """Check if a string looks like a valid JWT."""
    return bool(JWT_PATTERN.match(token))


def _detect_alg_none(header: dict[str, Any]) -> bool:
    """Check if the JWT header uses alg: none."""
    return header.get("alg", "").lower() == "none"


def _detect_sensitive_claims(payload: dict[str, Any]) -> bool:
    """Check if the JWT payload contains sensitive claims."""
    payload_str = json.dumps(payload).lower()
    return any(s in payload_str for s in SENSITIVE_CLAIMS)


def _test_jwt_endpoint(base_url: str, endpoint: str, timeout: float = 5.0) -> tuple[int, list[dict[str, Any]]]:
    """Test a single endpoint for JWT weaknesses."""
    from ._http_client import _make_http_request, make_url

    findings: list[dict[str, Any]] = []
    requests_sent = 0

    resp = _make_http_request(make_url(base_url, endpoint), method="GET", timeout=timeout)
    requests_sent += 1

    body_text = ""
    try:
        raw = resp.get("rawBody", b"")
        body_text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
    except Exception:
        pass

    tokens = re.findall(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+\.[A-Za-z0-9_-]*", body_text)
    for token in tokens[:3]:
        if not _is_valid_jwt(token):
            continue

        header = _decode_jwt_header(token)
        if not header:
            continue

        if _detect_alg_none(header):
            findings.append({
                "id": f"jwt-alg-none-{endpoint}",
                "title": "JWT algorithm: none",
                "severity": "CRITICAL",
                "description": f"JWT on {endpoint} uses alg: none, allowing unverified tokens",
                "confidence": "HIGH",
                "remediation": "Reject tokens with alg: none; verify signature",
                "details": {"endpoint": endpoint, "algorithm": "none", "token_type": "JWT", "has_signature": False},
            })
            continue

        payload_json = _b64url_decode(token.split(".")[1])
        if payload_json:
            try:
                payload = json.loads(payload_json)
                if _detect_sensitive_claims(payload):
                    findings.append({
                        "id": f"jwt-sensitive-data-{endpoint}",
                        "title": "JWT contains sensitive data",
                        "severity": "HIGH",
                        "description": f"JWT on {endpoint} contains sensitive claims",
                        "confidence": "HIGH",
                        "remediation": "Remove sensitive data from JWT claims; use secure storage",
                        "details": {"endpoint": endpoint, "sensitive_claims": ["password", "apiKey", "token"]},
                    })
                    continue
            except (json.JSONDecodeError, TypeError):
                pass

        parts = token.split(".")
        if len(parts) == 3 and parts[2] == "":
            findings.append({
                "id": f"jwt-no-signature-{endpoint}",
                "title": "JWT has no signature",
                "severity": "HIGH",
                "description": f"JWT on {endpoint} has an empty signature section",
                "confidence": "HIGH",
                "remediation": "Ensure all JWTs are signed with a secure algorithm",
                "details": {"endpoint": endpoint, "has_signature": False},
            })

    return requests_sent, findings


def run_jwt_scan(
    config_path: str,
    endpoints: list[str] | None = None,
    *,
    artifacts_root: str = "runs",
    request_timeout: float = 5.0,
) -> JWTScanResult:
    """Run JWT weaknesses scan against target."""
    result = _run_scan(
        config_path,
        run_func=_test_jwt_endpoint,
        scan_name="jwt",
        artifact_name="jwt-summary",
        artifacts_root=artifacts_root,
        request_timeout=request_timeout,
        extra_endpoints=endpoints or [],
    )

    return JWTScanResult(
        run_id=result["run_id"],
        target_id=result["target_id"],
        findings=result.get("findings", []),
        total_requests=result.get("total_requests", 0),
        endpoints_tested=result.get("endpoints_tested", 0),
        artifacts={"jwt_summary": result["artifacts"].get("jwt-summary", "")},
    )
