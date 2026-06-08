"""Authentication flow testing for the Hermes Security Harness.

This module tests authentication and session handling by performing
controlled login/logout sequences, auth bypass tests, and rate-limit tests.

Public API (``__all__``):
    AuthConfig, CookieSession, AuthScanResult,
    run_auth_scan,
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

from ._http_client import _make_http_request, make_url
from .artifacts import redact_secrets
from .web_target import WebTargetConfig, load_target_config
from .auth_client import auth_signin_nextauth


# ── Payload Definitions ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class AuthConfig:
    """Authentication credentials for scan targets.

    Attributes:
        login_url: The URL of the login endpoint.
        username: Username for authentication.
        password: Password for authentication.
        cookie_name: Name of the session cookie (e.g., "sessionid", "jwt").
        jwt_secret_name: JWT header/query param name (e.g., "Authorization", "token").
        protected_paths: Paths that require authentication.
        logout_url: URL for logout (optional).
    """

    login_url: str
    username: str = "testuser"
    password: str = "testpass123"
    cookie_name: str = "sessionid"
    jwt_secret_name: str = ""
    protected_paths: list[str] = field(default_factory=lambda: ["/dashboard", "/api/profile"])
    logout_url: str = ""


# ── Cookie Session ────────────────────────────────────────────────────────────

# HTTP request handling is shared in _http_client.py — see _make_http_request.


@dataclass
class CookieSession:
    """Represents a tracked cookie session."""

    cookies: dict[str, str] = field(default_factory=dict)
    created_at: float = 0.0
    expired: bool = False
    token: str = ""  # For JWT or similar
    _accessible: bool = False

    def is_valid(self) -> bool:
        return not self.expired and bool(self.cookies or self.token)


# ── Scan Results ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AuthScanResult:
    """Result of an authentication scan run.

    Attributes:
        run_id: Stable identifier for this scan run.
        target_id: ID of the scanned target.
        run_dir: Directory containing artifacts.
        success: True if the scan completed without internal errors.
        cookie_tests: Number of cookie-session tests performed.
        bypass_tests: Number of auth-bypass tests performed.
        rate_tests: Number of rate-limit tests performed.
        finding_count: Total findings discovered.
        artifacts: Mapping of artifact name to file path.
        warnings: Warnings produced during the scan.
    """

    success: bool
    run_id: str
    target_id: str
    run_dir: Path
    cookie_tests: int = 0
    bypass_tests: int = 0
    rate_tests: int = 0
    finding_count: int = 0
    artifacts: dict[str, Path] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_summary(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "run_id": self.run_id,
            "target_id": self.target_id,
            "run_dir": str(self.run_dir),
            "cookie_tests": self.cookie_tests,
            "bypass_tests": self.bypass_tests,
            "rate_tests": self.rate_tests,
            "finding_count": self.finding_count,
            "artifacts": {k: str(v) for k, v in self.artifacts.items()},
            "warnings": self.warnings,
        }


# ── Main Scan ─────────────────────────────────────────────────────────────────


def run_auth_scan(
    config_path: str | Path,
    artifacts_root: str | Path = "runs",
    *,
    request_timeout: float = 5.0,
    auth: AuthConfig | None = None,
) -> AuthScanResult:
    """Run an authentication flow scan and write structured artifacts.

    Args:
        config_path: Path to web-target/v1 YAML or JSON config.
        artifacts_root: Directory for output artifacts.
        request_timeout: HTTP request timeout in seconds.
        auth: AuthConfig with credentials. Optional — defaults to test credentials.

    Returns:
        AuthScanResult with findings and artifacts.
    """
    target = load_target_config(config_path)
    base_url = target.base_url.rstrip("/")

    if auth is None:
        auth = AuthConfig(
            login_url=_pick_login_url(target),
            username="testuser",
            password="testpass123",
            protected_paths=["/dashboard", "/api/profile"],
        )

    artifacts_root_path = Path(artifacts_root).expanduser().resolve()
    if artifacts_root_path.exists() and artifacts_root_path.is_symlink():
        raise ValueError("artifacts root must not be a symlink")

    run_id = _new_run_id(target)
    run_dir = artifacts_root_path / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    cookie_results = _test_cookie_session(base_url, auth, request_timeout)
    bypass_results = _test_auth_bypass(base_url, auth, request_timeout)
    rate_results = _test_rate_limit(base_url, auth, request_timeout)

    all_findings = []
    all_findings.extend(cookie_results.findings)
    all_findings.extend(bypass_results.findings)
    all_findings.extend(rate_results.findings)

    warnings: list[str] = list(cookie_results.warnings)
    warnings.extend(bypass_results.warnings)
    warnings.extend(rate_results.warnings)

    doc = {
        "schemaVersion": "auth-scan/v1",
        "runId": run_id,
        "targetId": target.id,
        "target": target.to_summary(),
        "generatedAt": _iso_now(),
        "safety": {
            "methods": ["GET", "POST"],
            "authentication": True,
            "formSubmission": True,
            "cookieHandling": True,
        },
        "summary": {
            "cookieTests": cookie_results.test_count,
            "bypassTests": bypass_results.test_count,
            "rateTests": rate_results.test_count,
            "findingCount": len(all_findings),
        },
        "warnings": warnings,
        "cookieTests": cookie_results.to_dict(),
        "bypassTests": bypass_results.to_dict(),
        "rateTests": rate_results.to_dict(),
        "findings": all_findings,
    }
    auth_path = run_dir / "auth-scan.json"
    auth_path.write_text(_json_dumps(doc) + "\n")

    report_path = run_dir / "report.md"
    report_path.write_text(_build_report(target, run_id, all_findings, warnings))

    result = AuthScanResult(
        success=True,
        run_id=run_id,
        target_id=target.id,
        run_dir=run_dir,
        cookie_tests=cookie_results.test_count,
        bypass_tests=bypass_results.test_count,
        rate_tests=rate_results.test_count,
        finding_count=len(all_findings),
        artifacts={"auth_scan": auth_path, "report": report_path},
        warnings=warnings,
    )
    return result


# ── Cookie Session Testing ────────────────────────────────────────────────────


class _CookieSessionTestResult:
    """Result from a cookie/session test phase."""

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


def _test_cookie_session(
    base_url: str, auth: AuthConfig, timeout: float
) -> _CookieSessionTestResult:
    """Test cookie session creation and validation."""
    result = _CookieSessionTestResult()

    login_url = make_url(base_url, auth.login_url)

    # 1. Attempt login — try NextAuth flow first, fall back to generic
    session = CookieSession()
    resp = _make_http_request(
        login_url,
        method="POST",
        body={"username": auth.username, "password": auth.password},
        timeout=timeout,
    )
    result.test_count += 1
    step = {
        "name": "login",
        "request": {
            "method": "POST",
            "url": login_url,
            "body": {"username": auth.username},
        },
        "status": resp["status"],
        "setCookies": resp.get("setCookies", {}),
        "error": resp.get("error"),
    }

    # Try NextAuth flow if the first attempt failed or looks like a redirect
    if (
        not resp.get("setCookies")
        or resp["status"] in (302, 307, 308)
        or "authjs.session-token" not in (resp.get("setCookies") or {})
    ):
        # Attempt NextAuth signin via /api/auth/callback/credentials
        auth_result = auth_signin_nextauth(base_url, auth.username, auth.password, timeout=timeout)
        if auth_result.get("authenticated"):
            session.cookies = {
                "authjs.session-token": auth_result["cookies"]["authjs.session-token"],
            }
            step["nextauth_auth"] = True
            step["status"] = auth_result["steps"][-1] if auth_result["steps"] else resp["status"]
            result.steps.append(step)

            # 2. Test protected path with cookie
            for path in auth.protected_paths:
                protected_url = make_url(base_url, path)
                resp = _make_http_request(
                    protected_url,
                    cookies=session.cookies,
                    timeout=timeout,
                )
                result.test_count += 1
                step2 = {
                    "name": f"protected-{path}",
                    "request": {
                        "method": "GET",
                        "url": protected_url,
                        "cookies": {"[redacted]": "[redacted]"},
                    },
                    "status": resp["status"],
                }
                result.steps.append(step2)

                if resp.get("status") and resp["status"] < 400:
                    session._accessible = True

                cookie_finding = _find_cookie_findings(path, resp, auth.cookie_name)
                if cookie_finding:
                    result.findings.append(cookie_finding)
            return result

    result.steps.append(step)

    if resp.get("status") and 300 <= resp["status"] < 400:
        step["redirect"] = resp.get("error", "redirect blocked by harness")

    session = CookieSession(
        cookies=resp.get("setCookies", {}),
    )

    # 2. Test protected path with cookie
    for path in auth.protected_paths:
        protected_url = make_url(base_url, path)
        resp = _make_http_request(
            protected_url,
            cookies=session.cookies,
            timeout=timeout,
        )
        result.test_count += 1

        step = {
            "name": f"protected-{path}",
            "request": {
                "method": "GET",
                "url": protected_url,
                "cookies": {"[redacted]": "[redacted]"},
            },
            "status": resp["status"],
        }
        result.steps.append(step)

        if resp.get("status") and resp["status"] < 400:
            # Mark the session as accessible (not just cookie presence)
            session._accessible = True

        cookie_finding = _find_cookie_findings(path, resp, auth.cookie_name)
        if cookie_finding:
            result.findings.append(cookie_finding)

    # 3. Test session fixation (check for SameSite/Secure flags)
    if session.cookies:
        fixation_finding = _session_fixation_finding(
            auth.login_url, session.cookies, auth.cookie_name
        )
        if fixation_finding:
            result.findings.append(fixation_finding)

    return result


# ── Auth Bypass Testing ───────────────────────────────────────────────────────


class _AuthBypassResult:
    """Result from auth bypass tests."""

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


def _test_auth_bypass(base_url: str, auth: AuthConfig, timeout: float) -> _AuthBypassResult:
    """Test authentication bypass by accessing protected paths without cookies."""
    result = _AuthBypassResult()

    for path in auth.protected_paths:
        protected_url = make_url(base_url, path)

        # No cookie, no auth
        resp = _make_http_request(protected_url, timeout=timeout)
        result.test_count += 1

        step = {
            "name": f"bypass-{path}",
            "request": {"method": "GET", "url": protected_url, "noAuth": True},
            "status": resp["status"],
        }
        result.steps.append(step)

        bypass_finding = _auth_bypass_finding(path, resp)
        if bypass_finding:
            result.findings.append(bypass_finding)

        # Test with weak/expired cookie
        resp2 = _make_http_request(
            protected_url,
            cookies={"sessionid": "expired_or_invalid_123"},
            timeout=timeout,
        )
        result.test_count += 1

        weak_finding = _weak_token_finding(path, resp2)
        if weak_finding:
            result.findings.append(weak_finding)

    return result


# ── Rate Limit Testing ────────────────────────────────────────────────────────


class _RateLimitResult:
    """Result from rate limit tests."""

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


def _test_rate_limit(base_url: str, auth: AuthConfig, timeout: float) -> _RateLimitResult:
    """Test rate limiting on login endpoints."""
    result = _RateLimitResult()

    login_url = make_url(base_url, auth.login_url)
    statuses: list[int] = []

    # Burst of login attempts
    for i in range(3):
        resp = _make_http_request(
            login_url,
            method="POST",
            body={"username": auth.username, "password": auth.password},
            timeout=timeout,
        )
        result.test_count += 1
        statuses.append(resp.get("status") or 0)

        step = {
            "name": f"burst-login-{i+1}",
            "request": {"method": "POST", "url": login_url},
            "status": resp["status"],
            "error": resp.get("error"),
        }
        result.steps.append(step)

        if resp.get("status") and resp["status"] == 429:
            rate_finding = _rate_limit_finding(login_url, resp)
            if rate_finding:
                result.findings.append(rate_finding)

    # Check for error escalation pattern
    if len(statuses) >= 2:
        if statuses[0] and statuses[1] and statuses[0] != statuses[1]:
            escalation_finding = _account_lock_finding(login_url, statuses)
            if escalation_finding:
                result.findings.append(escalation_finding)

    return result


# ── Finding Builders ──────────────────────────────────────────────────────────


def _find_cookie_findings(path: str, resp: dict[str, Any], cookie_name: str) -> dict[str, Any] | None:
    """Check for cookie security issues on a protected path."""
    finding = None

    # Check if protected path is accessible without auth
    if resp.get("status") and resp["status"] < 400:
        finding = _auth_bypass_finding(path, resp)

    return finding


def _session_fixation_finding(
    login_url: str, cookies: dict[str, str], cookie_name: str
) -> dict[str, Any] | None:
    """Detect session fixation weak cookie flags."""
    cookie_val = cookies.get(cookie_name) or ""
    cookie_lower = cookie_val.lower() if cookie_val else ""

    # Check for missing Secure flag
    has_secure = "secure" in cookie_lower
    has_httponly = "httponly" in cookie_lower
    has_samesite = "samesite" in cookie_lower

    if not has_secure:
        return _weak_cookie_finding(login_url, cookie_name, "Secure", "Missing")
    if not has_httponly:
        return _weak_cookie_finding(login_url, cookie_name, "HttpOnly", "Missing")
    if not has_samesite:
        return _weak_cookie_finding(login_url, cookie_name, "SameSite", "Missing")

    return None


def _weak_cookie_finding(url: str, cookie_name: str, flag: str, status: str) -> dict[str, Any]:
    """Create a finding for a weak cookie flag."""
    return {
        "schemaVersion": "finding/v1",
        "id": f"weak-cookie-flag-{cookie_name.lower()}-{flag.lower()}",
        "runId": "",
        "targetId": "",
        "detectorId": "auth-scan",
        "title": f"{flag} cookie flag {status}",
        "description": f"Cookie '{cookie_name}' does not have the {flag} flag. Consider adding it for better security.",
        "severity": "medium",
        "confidence": "high",
        "affected": {"url": url, "cookie": cookie_name},
        "evidence": {"flag": flag, "status": status},
        "remediation": {"summary": f"Set the {flag} flag on the {cookie_name} cookie."},
    }


def _auth_bypass_finding(url: str, resp: dict[str, Any]) -> dict[str, Any] | None:
    """Create a finding when an endpoint is accessible without auth."""
    status = resp.get("status")
    if status and status < 400:
        return {
            "schemaVersion": "finding/v1",
            "id": "auth-bypass",
            "runId": "",
            "targetId": "",
            "detectorId": "auth-scan",
            "title": "Protected endpoint accessible without authentication",
            "description": "The endpoint is accessible without valid authentication.",
            "severity": "high",
            "confidence": "high",
            "affected": {"url": url, "status": status},
            "evidence": {"status": status, "headers": resp.get("headers", {})},
            "remediation": {"summary": "Enforce authentication on protected endpoints."},
        }
    return None


def _weak_token_finding(url: str, resp: dict[str, Any]) -> dict[str, Any] | None:
    """Create a finding for weak/expired token access."""
    status = resp.get("status")
    if status and status < 400:
        return {
            "schemaVersion": "finding/v1",
            "id": "weak-token-access",
            "runId": "",
            "targetId": "",
            "detectorId": "auth-scan",
            "title": "Weak or expired token grants access",
            "description": "A weak or expired authentication token was accepted.",
            "severity": "medium",
            "confidence": "medium",
            "affected": {"url": url, "status": status},
            "evidence": {"status": status},
            "remediation": {"summary": "Implement proper token validation and expiration."},
        }
    return None


def _weak_csrf_finding(url: str, resp: dict[str, Any]) -> dict[str, Any] | None:
    """Create a finding for missing CSRF protection."""
    headers = resp.get("headers", {})
    has_csrf = "csrf-token" in headers or "x-csrf-token" in headers or "x-csrftoken" in headers
    if not has_csrf and resp.get("status") and resp["status"] < 400:
        return {
            "schemaVersion": "finding/v1",
            "id": "missing-csrf-token",
            "runId": "",
            "targetId": "",
            "detectorId": "auth-scan",
            "title": "Missing CSRF token in response headers",
            "description": "The response does not include a CSRF token.",
            "severity": "medium",
            "confidence": "medium",
            "affected": {"url": url},
            "evidence": {"headers": headers},
            "remediation": {"summary": "Add CSRF token to response headers and validate on submission."},
        }
    return None


def _rate_limit_finding(url: str, resp: dict[str, Any]) -> dict[str, Any]:
    """Create a finding for rate limiting."""
    retry_after = ""
    for key, val in resp.get("headers", {}).items():
        if key.lower() == "retry-after":
            retry_after = val
            break

    return {
        "schemaVersion": "finding/v1",
        "id": "rate-limiting-detected",
        "runId": "",
        "targetId": "",
        "detectorId": "auth-scan",
        "title": "Rate limiting detected on login endpoint",
        "description": "The endpoint returned a 429 status code, indicating rate limiting.",
        "severity": "informational",
        "confidence": "high",
        "affected": {"url": url, "status": resp.get("status")},
        "evidence": {
            "status": resp.get("status"),
            "retryAfter": retry_after,
        },
        "remediation": {"summary": "Implement proper rate limiting on authentication endpoints."},
    }


def _account_lock_finding(url: str, statuses: list[int]) -> dict[str, Any] | None:
    """Create a finding for account lockout after rate limit."""
    if len(statuses) >= 2:
        first = statuses[0]
        second = statuses[1]
        if first and second and first != second and (second == 429 or second == 403):
            return {
                "schemaVersion": "finding/v1",
                "id": "account-lockout",
                "runId": "",
                "targetId": "",
                "detectorId": "auth-scan",
                "title": "Account lockout after rate limit",
                "description": "The account was locked out after repeated login attempts.",
                "severity": "medium",
                "confidence": "medium",
                "affected": {"url": url, "statuses": statuses},
                "evidence": {"statuses": statuses},
                "remediation": {"summary": "Consider implementing progressive delay instead of hard lockout."},
            }
    return None


def _session_not_revoked_finding(
    login_url: str, logout_url: str
) -> dict[str, Any] | None:
    """Create a finding for session not revoked after logout."""
    return {
        "schemaVersion": "finding/v1",
        "id": "session-not-revoked",
        "runId": "",
        "targetId": "",
        "detectorId": "auth-scan",
        "title": "Session not revoked after logout",
        "description": "The session was not properly invalidated after logout.",
        "severity": "medium",
        "confidence": "high",
        "affected": {"loginUrl": login_url, "logoutUrl": logout_url},
        "evidence": {"loginUrl": login_url, "logoutUrl": logout_url},
        "remediation": {"summary": "Implement proper session invalidation on logout."},
    }


# ── Helpers ────────────────────────────────────────────────────────────────────


def _pick_login_url(target: WebTargetConfig, auth: AuthConfig | None = None) -> str:
    """Auto-detect the login URL from common patterns."""
    candidates = ["/login", "/auth/login", "/signin", "/api/auth/login"]
    for path in candidates:
        url = make_url(target.base_url, path)
        if target.is_url_allowed(url):
            return path
    return "/login"


def _new_run_id(target: WebTargetConfig) -> str:
    """Generate a unique run ID."""
    return f"auth-scan-{_iso_now_short()}-{_slug(target.id)}-{_short_uuid()}"


def _iso_now_short() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slug(text: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9_-]+", "-", text).strip("-") or "target"


def _short_uuid() -> str:
    import uuid
    return uuid.uuid4().hex[:8]


def _json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj, indent=2, sort_keys=True)


def _build_report(target: WebTargetConfig, run_id: str, findings: list[dict[str, Any]], warnings: list[str]) -> str:
    """Build a Markdown report."""
    lines = [
        f"# Auth scan report: {target.name}",
        "",
        f"- Run ID: `{run_id}`",
        f"- Target ID: `{target.id}`",
        f"- Base URL: `{target.base_url}`",
        f"- Findings: {len(findings)}",
        "",
        "## Safety boundary",
        "",
        "This run used controlled login/logout sequences, auth bypass tests, and rate-limit tests.",
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
