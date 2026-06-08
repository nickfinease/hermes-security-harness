"""Dynamic HTTP injection scanner for XSS, SQLi, and SSRF testing.

This module performs controlled, deterministic injection tests against a target
web application. It is designed for the Hermes Security Harness and does not
use external tools — only the Python stdlib (urllib).

Public API (``__all__``):
    XSSPayload, SQLiPayload, SSRFEndpoint, AuthenticationResult,
    UserInputSurface, InputSurfaceType,
    build_user_input_surfaces_from_smoke,
    XSS_PAYLOADS, SQLI_PAYLOADS, SSRF_ENDPOINTS,
    run_injection_scan,
    InjectionScanResult,
"""
from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlparse, parse_qs
from urllib.request import Request

from ._http_client import _make_http_request, make_url, new_run_id, write_json, _json_dumps
from .artifacts import redact_secrets
from .web_target import WebTargetConfig, load_target_config
from .auth_client import auth_signin_nextauth


# ── Authentication ──────────────────────────────────────────────────────────────


@dataclass
class AuthenticationResult:
    """Result of an authentication login attempt.

    Attributes:
        success: True if the scan ran (even if auth itself failed).
        authenticated: True if cookies were obtained.
        cookie_name: Name of the session cookie.
        cookies: Cookie dict from Set-Cookie header.
        warnings: Warnings produced during authentication.
    """

    success: bool
    authenticated: bool
    cookie_name: str
    cookies: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def _auth_login(
    base_url: str,
    auth: dict[str, Any] | None,
    timeout: float,
) -> AuthenticationResult:
    """Attempt login and extract session cookies.

    Args:
        base_url: The target base URL.
        auth: Auth config dict with login_url, username, password, cookie_name, protected_paths.
        timeout: HTTP timeout in seconds.

    Returns:
        AuthenticationResult with cookies (or empty if login failed).
    """
    if auth is None:
        return AuthenticationResult(
            success=True,
            authenticated=False,
            cookie_name="",
            cookies={},
        )

    login_url = make_url(base_url, auth.get("login_url", "/login"))

    resp = _make_http_request(
        login_url,
        method="POST",
        body={
            "username": auth.get("username", "test"),
            "password": auth.get("password", "test"),
        },
        timeout=timeout,
    )

    status = resp.get("status") or 0
    set_cookies = resp.get("setCookies", {})

    if set_cookies and "authjs.session-token" not in set_cookies:
        # Standard cookie — return as-is
        return AuthenticationResult(
            success=True,
            authenticated=True,
            cookie_name=auth.get("cookie_name", "sessionid"),
            cookies=set_cookies,
        )

    # No session cookie from standard login — try NextAuth flow
    auth_result = auth_signin_nextauth(
        base_url,
        auth.get("username", ""),
        auth.get("password", ""),
        timeout=timeout,
    )

    if auth_result.get("authenticated"):
        session_token = auth_result["cookies"].get("authjs.session-token", "")
        if session_token:
            return AuthenticationResult(
                success=True,
                authenticated=True,
                cookie_name="authjs.session-token",
                cookies={"authjs.session-token": session_token},
            )

    return AuthenticationResult(
        success=True,
        authenticated=False,
        cookie_name=auth.get("cookie_name", "sessionid"),
        cookies={},
        warnings=[f"Authentication failed: status={status}, no cookies received"],
    )


class InputSurfaceType(Enum):
    """Type of user input surface."""

    QUERY_PARAM = "query_param"
    BODY_JSON = "body_json"
    BODY_FORM = "body_form"
    COOKIE = "cookie"
    HEADER = "header"
    URL_PATH = "url_path"
    FORM_INPUT = "form_input"  # Discovered from HTML forms


@dataclass(frozen=True)
class UserInputSurface:
    """A user input surface to test.

    Attributes:
        id: Stable identifier for the surface.
        url: The URL of the surface.
        type: Type of input (query param, body JSON, etc.).
        method: HTTP method (GET, POST, etc.).
        parameters: List of parameter names that accept user input.
        confidence: How confident we are this is a real input surface.
        raw_body: Original request body if available.
        response_body: Response body for form discovery.
        source: Where this surface was discovered (smoke, recon, default).
    """

    id: str
    url: str
    type: InputSurfaceType
    method: str
    parameters: list[str]
    confidence: str
    raw_body: str | None = None
    response_body: str | None = None
    source: str = "smoke"


def build_user_input_surfaces_from_smoke(
    smoke_steps: list[dict[str, Any]],
) -> list[UserInputSurface]:
    """Build user input surfaces from HTTP smoke scan results.

    This function analyzes smoke scan results to discover potential user input
    surfaces. It looks for:
    - GET requests with query parameters
    - POST requests with JSON or form bodies
    - HTML responses containing forms with input fields

    The smoke scan artifact uses "requests" array with fields like:
    - request.method, request.url, request.body (or url, path, etc.)
    - request.status

    Args:
        smoke_steps: List of smoke scan step results.

    Returns:
        List of discovered user input surfaces.
    """
    surfaces: list[UserInputSurface] = []

    for step in smoke_steps:
        # Handle both old format (request key) and new format (direct keys)
        request = step.get("request", {})
        method = (
            request.get("method", "") or step.get("method", "GET")
        ).upper()
        url = request.get("url", "") or step.get("url", "")
        raw_body = request.get("body") or step.get("body") or None
        path = request.get("path", "") or step.get("path", "")

        if not url and path:
            url = f"http://localhost:3000{path}"

        # Extract query parameters from URL
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        param_names = list(query_params.keys())

        # Check for forms in response body
        response_body = step.get("rawBody", b"") or step.get("bodyBytes", b"") or b""
        # Handle different response body types
        if isinstance(response_body, int):
            response_str = ""  # Just bytes count, no content to analyze
        elif isinstance(response_body, str):
            response_str = response_body
        else:
            try:
                response_str = response_body.decode("utf-8", errors="replace")
            except (UnicodeDecodeError, AttributeError):
                response_str = ""

        # Discover form fields from HTML
        if method == "GET" and _has_form_tags(response_str):
            form_fields = _extract_form_fields(response_str, url)
            if form_fields:
                surface_id = f"form-{_hash_url(url)}"
                surfaces.append(
                    UserInputSurface(
                        id=surface_id,
                        url=url,
                        type=InputSurfaceType.FORM_INPUT,
                        method="POST",
                        parameters=form_fields,
                        confidence="medium",
                    )
                )

        # Create surface for query params
        if param_names and method == "GET":
            surface_id = f"query-{_hash_url(url)}"
            surfaces.append(
                UserInputSurface(
                    id=surface_id,
                    url=url,
                    type=InputSurfaceType.QUERY_PARAM,
                    method="GET",
                    parameters=param_names,
                    confidence="high",
                )
            )

        # Create surface for path (for paths that accept user input)
        if path and method == "GET" and _has_form_tags(response_str):
            # Path-based form input
            surface_id = f"path-form-{_hash_url(url)}"
            surfaces.append(
                UserInputSurface(
                    id=surface_id,
                    url=url,
                    type=InputSurfaceType.FORM_INPUT,
                    method="POST",
                    parameters=_extract_form_fields(response_str, url),
                    confidence="medium",
                )
            )

        # Default surfaces for common paths (backwards compatible)
        # Match smoke scan paths
        if path and method == "GET":
            common_paths = [
                ("q", "search", "filter"),  # Query params for search/filter
                ("username", "email", "password"),  # Login params
            ]
            surface_id = f"default-{_hash_url(url)}"
            surfaces.append(
                UserInputSurface(
                    id=surface_id,
                    url=url,
                    type=InputSurfaceType.QUERY_PARAM,
                    method="GET",
                    parameters=list(common_paths[0]) if any(k in url.lower() for k in ["search", "filter", "query", "q"]) else list(common_paths[1]),
                    confidence="low",
                )
            )

        # Create surface for POST body
        if method == "POST" and raw_body:
            # Determine body type based on content or parameter names
            is_json = False
            if isinstance(raw_body, str):
                try:
                    json.loads(raw_body)
                    is_json = True
                except json.JSONDecodeError:
                    is_json = False

            if is_json:
                surface_type = InputSurfaceType.BODY_JSON
                try:
                    body_data = json.loads(raw_body)
                    if isinstance(body_data, dict):
                        param_names = list(body_data.keys())
                    else:
                        param_names = ["body"]
                except (json.JSONDecodeError, TypeError):
                    param_names = ["body"]
            else:
                surface_type = InputSurfaceType.BODY_FORM
                # Parse form data
                try:
                    if isinstance(raw_body, str):
                        body_data = dict(parse_qs(raw_body))
                        param_names = list(body_data.keys())
                    else:
                        param_names = ["body"]
                except Exception:
                    param_names = ["body"]

            if param_names:
                surface_id = f"post-{_hash_url(url)}"
                surfaces.append(
                    UserInputSurface(
                        id=surface_id,
                        url=url,
                        type=surface_type,
                        method="POST",
                        parameters=param_names,
                        confidence="high",
                        raw_body=raw_body,
                    )
                )

    return surfaces


def _hash_url(url: str) -> str:
    """Simple hash for URL to create stable surface IDs."""
    import hashlib
    return hashlib.md5(url.encode()).hexdigest()[:8]


def _extract_path_params(path: str) -> list[str]:
    """Extract URL path parameters like :id or {id} from a route path.

    Args:
        path: Route path string (e.g., "/api/users/:id", "/api/users/{id}").

    Returns:
        List of parameter names (e.g., ["id"]).
    """
    params: list[str] = []
    # Match :param and {param} patterns
    for match in re.finditer(r':[a-zA-Z_]\w*', path):
        params.append(match.group()[1:])  # Strip leading :
    for match in re.finditer(r'\{([a-zA-Z_]\w*)\}', path):
        params.append(match.group(1))
    return params


def _test_xss_path_param(surfaces: list[UserInputSurface], cookies: dict[str, str], timeout: float) -> _XssResult:
    """Test XSS on URL path parameters (e.g., /api/users/<script>alert(1)</script>)."""
    result = _XssResult()

    for surface in surfaces:
        if surface.type != InputSurfaceType.URL_PATH:
            continue
        for pp in surface.parameters:
            for payload in XSS_PAYLOADS:
                test_url = surface.url + "/" + quote(payload.payload, safe="")

                resp = _make_http_request(
                    test_url,
                    cookies=cookies if cookies else None,
                    timeout=timeout,
                )
                result.test_count += 1

                step = {
                    "name": f"xss-path-{surface.id}-{pp}-{payload.id}",
                    "request": {
                        "method": surface.method,
                        "url": test_url,
                        "payload": f"[xss/path-param/{pp}/{payload.id}]",
                        "cookie": bool(cookies),
                    },
                    "status": resp["status"],
                    "bodyBytes": resp.get("bodyBytes", b""),
                }
                result.steps.append(step)

                xss_finding = _xss_finding(pp, test_url, resp, payload)
                if xss_finding:
                    xss_finding["affected"]["surface"] = surface.id
                    xss_finding["affected"]["surfaceType"] = "url_path_param"
                    result.findings.append(xss_finding)

    return result


def _test_sqli_path_param(surfaces: list[UserInputSurface], cookies: dict[str, str], timeout: float) -> _SqlInjectionResult:
    """Test SQLi on URL path parameters (e.g., /api/users/1' OR 1=1--)."""
    result = _SqlInjectionResult()

    for surface in surfaces:
        if surface.type != InputSurfaceType.URL_PATH:
            continue
        for pp in surface.parameters:
            for payload in SQLI_PAYLOADS:
                test_url = surface.url + "/" + quote(payload.payload, safe="")

                resp = _make_http_request(
                    test_url,
                    cookies=cookies if cookies else None,
                    timeout=timeout,
                )
                result.test_count += 1

                step = {
                    "name": f"sqli-path-{surface.id}-{pp}-{payload.id}",
                    "request": {
                        "method": surface.method,
                        "url": test_url,
                        "payload": f"[sqli/path-param/{pp}/{payload.id}]",
                        "cookie": bool(cookies),
                    },
                    "status": resp["status"],
                    "redirectTarget": resp.get("headers", {}).get("Location", ""),
                }
                result.steps.append(step)

                sqli_finding = _sqli_finding(pp, test_url, resp, payload)
                if sqli_finding:
                    sqli_finding["affected"]["surface"] = surface.id
                    sqli_finding["affected"]["surfaceType"] = "url_path_param"
                    result.findings.append(sqli_finding)

    return result


def _has_form_tags(html: str) -> bool:
    """Check if HTML contains form tags."""
    return bool(re.search(r"<form", html, re.IGNORECASE))


def _extract_form_fields(html: str, form_action: str) -> list[str]:
    """Extract form field names from HTML."""
    # Find all input fields in forms
    input_pattern = re.compile(
        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>',
        re.IGNORECASE,
    )
    select_pattern = re.compile(
        r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>',
        re.IGNORECASE,
    )
    textarea_pattern = re.compile(
        r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>',
        re.IGNORECASE,
    )

    fields = set()
    for pattern in [input_pattern, select_pattern, textarea_pattern]:
        matches = pattern.findall(html)
        fields.update(matches)

    return list(fields)


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
    smoke_steps: list[dict[str, Any]] | str | None = None,  # List, JSON file path, or artifact obj
    auth: dict[str, Any] | None = None,  # Optional auth credentials
    recon_surfaces: list[dict[str, Any]] | None = None,  # Optional recon-discovered surfaces
    recon_routes: list[dict[str, Any]] | str | None = None,  # Optional recon-discovered API routes or JSON file path
    auth_cookies: dict[str, str] | None = None,  # Pre-existing cookies from auth scan
) -> InjectionScanResult:
    """Run an injection scan against a web target and write structured artifacts.

    Args:
        config_path: Path to web-target/v1 YAML or JSON config.
        artifacts_root: Directory for output artifacts.
        request_timeout_s: HTTP request timeout in seconds (default 5.0).
        request_timeout: Alias for request_timeout_s.
        smoke_steps: Optional smoke scan results to discover user input surfaces.
        auth: Optional auth credentials dict with login_url, username, password,
              cookie_name, protected_paths.
        recon_surfaces: Optional list of recon-discovered surfaces (dicts with
            url, input_type, parameter_name, method, source, confidence).
        recon_routes: Optional list of recon-discovered API routes for URL path
            parameter testing (dicts with path, methods).
        auth_cookies: Optional pre-existing cookies from a prior auth scan run.
            Takes priority over auth-login cookies.

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

    # Authenticate first if credentials provided
    auth_cfg = auth  # Save for later use in auth steps
    auth_result = _auth_login(base_url, auth, effective_timeout)

    # Use pre-existing cookies from auth scan if provided, otherwise use login cookies
    effective_cookies = auth_cookies or auth_result.cookies

    # Track login URL for auth steps in output
    login_url = f"{base_url}/{auth.get('login_url', '').lstrip('/')}" if auth else ""

    # 1. Discover user input surfaces from smoke scan results
    surfaces: list[UserInputSurface] = []
    smoke_source_count = 0
    if smoke_steps is not None:
        smoke_steps_list: list[dict[str, Any]] = []
        if isinstance(smoke_steps, str):
            import json
            with open(smoke_steps) as f:
                smoke_data = json.load(f)
            smoke_steps_list = smoke_data.get("requests", smoke_data.get("steps", []))
        elif hasattr(smoke_steps, 'artifacts') and 'http_smoke' in smoke_steps.artifacts:
            import json
            smoke_path = smoke_steps.artifacts['http_smoke']
            with open(smoke_path) as f:
                smoke_data = json.load(f)
            smoke_steps_list = smoke_data.get("requests", smoke_data.get("steps", []))
        surfaces = build_user_input_surfaces_from_smoke(smoke_steps_list)
        smoke_source_count = len(surfaces)
        _write_surfaces_json(run_dir / "surfaces.json", surfaces)
    else:
        # Fallback: use default parameter names (backwards compatible)
        surfaces = _build_default_surfaces(base_url)
        smoke_source_count = len(surfaces)

    # 2. Merge recon-discovered surfaces (dedup by URL+param)
    recon_count = 0
    if recon_surfaces:
        seen_ids: set[str] = set()
        for s in surfaces:
            seen_ids.add(s.id)
        for rs in recon_surfaces:
            surf_id = f"recon-{_hash_url(rs.get('url', ''))}-{rs.get('parameter_name', '')}"
            if surf_id in seen_ids:
                continue
            seen_ids.add(surf_id)
            input_type_str = rs.get("input_type", "query_param")
            input_type_map = {
                "query_param": InputSurfaceType.QUERY_PARAM,
                "form_field": InputSurfaceType.BODY_FORM,
                "path_param": InputSurfaceType.URL_PATH,
                "header": InputSurfaceType.HEADER,
                "cookie": InputSurfaceType.COOKIE,
                "body_json": InputSurfaceType.BODY_JSON,
            }
            stype = input_type_map.get(input_type_str, InputSurfaceType.QUERY_PARAM)
            if stype == InputSurfaceType.QUERY_PARAM and rs.get("method", "").upper() in ("POST", "PUT"):
                stype = InputSurfaceType.BODY_FORM
            surfaces.append(
                UserInputSurface(
                    id=surf_id,
                    url=rs.get("url", ""),
                    type=stype,
                    method=rs.get("method", "GET").upper(),
                    parameters=[rs.get("parameter_name", "")] if rs.get("parameter_name") else [],
                    confidence=rs.get("confidence", "medium"),
                    source="recon",
                )
            )
            recon_count += 1

    # Handle recon_routes: resolve from file path if string
    resolved_routes: list[dict[str, Any]] = []
    if recon_routes:
        if isinstance(recon_routes, str):
            try:
                with open(recon_routes) as f:
                    data = json.load(f)
                    resolved_routes = data.get("routes", data.get("discovered_routes", [data])) if isinstance(data, dict) else data
            except (FileNotFoundError, json.JSONDecodeError):
                resolved_routes = []
        elif hasattr(recon_routes, '__iter__'):
            resolved_routes = list(recon_routes)

    # 3. Add URL path parameter surfaces from recon routes
    path_param_surfaces: list[UserInputSurface] = []
    if recon_routes:
        for route in recon_routes:
            path = route.get("path", "")
            path_params = _extract_path_params(path)
            for pp in path_params:
                for method in route.get("methods", ["GET"]):
                    surf_id = f"path-param-{_hash_url(path)}-{pp}-{method.lower()}"
                    path_param_surfaces.append(
                        UserInputSurface(
                            id=surf_id,
                            url=f"{base_url}{path}",
                            type=InputSurfaceType.URL_PATH,
                            method=method.upper(),
                            parameters=[pp],
                            confidence="high",
                            source="recon-route",
                        )
                    )

    # 4. Add query params for discovered API routes (even without form info)
    # Limit to prevent combinatorial explosion: max 50 routes, only those with user-facing params
    api_param_surfaces: list[UserInputSurface] = []
    if resolved_routes:
        # Filter to only routes that look like they accept user input
        user_param_indicators = ["id", "filter", "q", "search", "page", "sort", "sort_by", "status", "type", "role", "username", "email", "name", "file", "url", "redirect", "path", "token"]
        user_param_routes = []
        for route in resolved_routes:
            p = route.get("path", "")
            if not p:
                continue
            # Skip static/internal routes
            if any(c in p.lower() for c in ["health", "readyz", "metrics", "swagger", "openapi", "docs", "favicon", "static", "_next"]):
                continue
            # Check if route path contains parameter-like segments
            has_param_like = any(segment.isdigit() or segment == "_id" or segment.startswith(":") or segment.startswith("{") for segment in p.split("/"))
            if has_param_like or any(indicator in p.lower() for indicator in user_param_indicators):
                user_param_routes.append(route)

        # Limit to top 20 routes to prevent explosion
        for route in user_param_routes[:20]:
            p = route.get("path", "")
            for method in ["GET", "POST"]:
                for param in ["id", "q", "filter"]:
                    surf_id = f"api-param-{_hash_url(f'{base_url}{p}')}-{param}-{method.lower()}"
                    api_param_surfaces.append(
                        UserInputSurface(
                            id=surf_id,
                            url=f"{base_url}{p}",
                            type=InputSurfaceType.QUERY_PARAM if method == "GET" else InputSurfaceType.BODY_FORM,
                            method=method.upper(),
                            parameters=[param],
                            confidence="medium",
                            source="recon-route",
                        )
                    )

    surfaces.extend(path_param_surfaces)
    surfaces.extend(api_param_surfaces)
    total_paths = smoke_source_count + recon_count + len(path_param_surfaces) + len(api_param_surfaces)

    # 5. Write full surface list with source info
    surf_list = []
    for s in surfaces:
        item = {
            "id": s.id,
            "url": s.url,
            "type": s.type.value,
            "method": s.method,
            "parameters": s.parameters,
            "confidence": s.confidence,
            "source": getattr(s, 'source', 'smoke'),
        }
        surf_list.append(item)
    _write_surfaces_json(run_dir / "surfaces.json", surfaces)

    # Test XSS, SQLi, and SSRF on discovered surfaces
    xss_results = _test_xss_on_surfaces(surfaces, effective_cookies, effective_timeout)
    sqli_results = _test_sqli_on_surfaces(surfaces, effective_cookies, effective_timeout)
    ssrf_results = _test_ssrf_on_surfaces(surfaces, effective_cookies, effective_timeout)

    # 6. Test URL path parameter injection (unique for path params)
    path_xss_results = _test_xss_path_param(path_param_surfaces, effective_cookies, effective_timeout)
    path_sqli_results = _test_sqli_path_param(path_param_surfaces, effective_cookies, effective_timeout)

    # Merge path param findings
    path_xss_findings = path_xss_results.findings
    path_sqli_findings = path_sqli_results.findings

    all_findings: list[dict[str, Any]] = []
    all_findings.extend(xss_results.findings)
    all_findings.extend(sqli_results.findings)
    all_findings.extend(ssrf_results.findings)
    all_findings.extend(path_xss_findings)
    all_findings.extend(path_sqli_findings)

    # Detect auth-coverage: if all GET requests redirect to login, no public input vectors exist
    all_xss_statuses = [s.get("status") for s in xss_results.steps] + \
                       [s.get("status") for s in path_xss_results.steps]
    all_sqli_statuses = [s.get("status") for s in sqli_results.steps] + \
                        [s.get("status") for s in path_sqli_results.steps]
    all_statuses = all_xss_statuses + all_sqli_statuses

    # 307/302/301 = explicit auth redirect; 308 = Next.js canonical redirect (also blocks access)
    auth_redirects = sum(1 for s in all_statuses if s in (307, 308, 302, 301))
    total_get_tests = len(all_statuses)
    if total_get_tests > 0 and auth_redirects >= total_get_tests * 0.5:
        # Collect unique redirect targets from all test steps
        redirect_targets: set[str] = set()
        for s in xss_results.steps + sqli_results.steps + path_xss_results.steps + path_sqli_results.steps:
            t = s.get("redirectTarget", "")
            if t:
                redirect_targets.add(t)
        target_str = ", ".join(sorted(redirect_targets)) if redirect_targets else "none (self-redirects only)"

        # Collect status codes
        redirect_status_codes = sorted(set(s for s in all_statuses if s in (307, 308, 302, 301)))
        status_str = ", ".join(str(s) for s in redirect_status_codes)

        all_findings.append({
            "schemaVersion": "finding/v1",
            "id": "all-get-redirects-to-login",
            "runId": run_id,
            "targetId": target.id,
            "detectorId": "injection-scan",
            "title": "All tested GET surfaces redirect to login",
            "description": f"Out of {total_get_tests} GET injection tests, {auth_redirects} ({auth_redirects*100//total_get_tests}%) returned redirect responses ({status_str}). Redirect targets: {target_str}. No public input vectors were detected — all tested surfaces require authentication.",
            "severity": "informational",
            "confidence": "high",
            "affected": {"surfaces_tested": len(surfaces), "get_tests": total_get_tests, "auth_redirects": auth_redirects},
            "remediation": {"summary": "If public input is expected, verify that those routes are intentionally protected."},
        })

    warnings: list[str] = list(xss_results.warnings)
    warnings.extend(sqli_results.warnings)
    warnings.extend(ssrf_results.warnings)
    warnings.extend(auth_result.warnings)

    # Build auth steps for the scan output
    auth_steps: list[dict[str, Any]] = []
    if auth_result.authenticated:
        auth_steps.append({
            "name": "auth-login",
            "request": {
                "method": "POST",
                "url": login_url,
                "auth": True,
            },
            "status": 302,
            "setCookies": {k: "[redacted]" for k in auth_result.cookies},
        })

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
        "auth": {
            "authenticated": auth_result.authenticated,
            "cookieName": auth_result.cookie_name,
        },
        "surfaces": {
            "total": len(surfaces),
            "bySource": {
                "smoke": smoke_source_count,
                "recon": recon_count,
                "path_params": len(path_param_surfaces),
                "api_routes": len(api_param_surfaces),
            },
        },
        "summary": {
            "xssTests": xss_results.test_count + path_xss_results.test_count,
            "sqliTests": sqli_results.test_count + path_sqli_results.test_count,
            "ssrfTests": ssrf_results.test_count,
            "pathParamTests": path_xss_results.test_count + path_sqli_results.test_count,
            "totalTests": (xss_results.test_count + path_xss_results.test_count) +
                         (sqli_results.test_count + path_sqli_results.test_count) +
                         ssrf_results.test_count,
            "findingCount": len(all_findings),
        },
        "authSteps": auth_steps,
        "steps": auth_steps,
        "warnings": warnings,
        "xssTests": xss_results.to_dict(),
        "sqliTests": sqli_results.to_dict(),
        "ssrfTests": ssrf_results.to_dict(),
        "pathParamTests": {
            "xss": path_xss_results.to_dict(),
            "sqli": path_sqli_results.to_dict(),
        },
        "findings": all_findings,
        "surfacesList": [
            {
                "id": s.id,
                "url": s.url,
                "type": s.type.value,
                "method": s.method,
                "parameters": s.parameters,
                "confidence": s.confidence,
                "source": getattr(s, "source", "smoke"),
            }
            for s in surfaces
        ],
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


def _build_default_surfaces(base_url: str) -> list[UserInputSurface]:
    """Build fallback surfaces using default parameter names (backwards compatible)."""
    surfaces: list[UserInputSurface] = []
    base = base_url.rstrip("/")

    # Query parameter surfaces - test on various common paths
    default_paths = ["/", "/search", "/login", "/dashboard", "/about"]
    query_params = ["q", "search", "input", "name", "email", "comment", "id", "page", "user"]

    for path in default_paths:
        for param in query_params:
            url = f"{base}{path}"
            surfaces.append(
                UserInputSurface(
                    id=f"query-{_hash_url(url)}-{param}",
                    url=url,
                    type=InputSurfaceType.QUERY_PARAM,
                    method="GET",
                    parameters=[param],
                    confidence="low",  # Default fallback
                )
            )

    # Form body surfaces
    form_params = ["username", "password", "email", "message"]
    form_path = "/api/auth/signin"
    for param in form_params:
        url = f"{base}{form_path}"
        surfaces.append(
            UserInputSurface(
                id=f"form-{_hash_url(url)}-{param}",
                url=url,
                type=InputSurfaceType.BODY_FORM,
                method="POST",
                parameters=[param],
                confidence="low",  # Default fallback
            )
        )

    return surfaces


def _write_surfaces_json(path: Path, surfaces: list[UserInputSurface]) -> None:
    """Write discovered surfaces to a JSON file."""
    import json
    data = [
        {
            "id": s.id,
            "url": s.url,
            "type": s.type.value,  # Convert enum to string
            "method": s.method,
            "parameters": s.parameters,
            "confidence": s.confidence,
        }
        for s in surfaces
    ]
    path.write_text(json.dumps(data, indent=2) + "\n")


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
                "redirectTarget": resp.get("headers", {}).get("Location", ""),
            }
            result.steps.append(step)

            xss_finding = _xss_finding(param, test_url, resp, payload)
            if xss_finding:
                result.findings.append(xss_finding)

    return result


def _test_xss_on_surfaces(surfaces: list[UserInputSurface], cookies: dict[str, str], timeout: float) -> _XssResult:
    """Test XSS on discovered user input surfaces."""
    result = _XssResult()

    for surface in surfaces:
        # Skip SSRF-only surfaces (they don't accept user input)
        if surface.type in (InputSurfaceType.URL_PATH,):
            continue

        for param in surface.parameters:
            for payload in XSS_PAYLOADS:
                # Determine how to inject based on surface type
                if surface.type == InputSurfaceType.QUERY_PARAM:
                    # GET request with query parameter
                    test_url = make_url(surface.url, f"?{param}=")
                    encoded = quote(payload.payload, safe="")
                    test_url = f"{test_url}{encoded}"
                    resp = _make_http_request(test_url, timeout=timeout, cookies=cookies)
                    result.test_count += 1

                    step = {
                        "name": f"xss-query-{surface.id}-{payload.id}",
                        "request": {
                            "method": "GET",
                            "url": test_url,
                            "payload": f"[xss/{surface.type.value}/{param}/{payload.category}]",
                            "cookie": cookies and surface.type.value == "query_param",
                        },
                        "status": resp["status"],
                        "bodyBytes": resp["bodyBytes"],
                        "redirectTarget": resp.get("headers", {}).get("Location", ""),
                    }
                    result.steps.append(step)

                    xss_finding = _xss_finding(param, test_url, resp, payload)
                    if xss_finding:
                        xss_finding["affected"]["surface"] = surface.id
                        xss_finding["affected"]["surfaceType"] = surface.type.value
                        result.findings.append(xss_finding)

                elif surface.type in (InputSurfaceType.BODY_JSON, InputSurfaceType.BODY_FORM):
                    # POST request with body parameter
                    if surface.type == InputSurfaceType.BODY_JSON:
                        body = {param: payload.payload}
                        headers = {"Content-Type": "application/json"}
                    else:
                        body = {param: payload.payload}
                        headers = {"Content-Type": "application/x-www-form-urlencoded"}

                    resp = _make_http_request(
                        surface.url,
                        method="POST",
                        body=body,
                        headers=headers,
                        cookies=cookies,
                        timeout=timeout,
                    )
                    result.test_count += 1

                    step = {
                        "name": f"xss-post-{surface.id}-{payload.id}",
                        "request": {
                            "method": "POST",
                            "url": surface.url,
                            "payload": f"[xss/{surface.type.value}/{param}/{payload.category}]",
                            "cookie": bool(cookies),
                        },
                        "status": resp["status"],
                        "bodyBytes": resp["bodyBytes"],
                        "redirectTarget": resp.get("headers", {}).get("Location", ""),
                    }
                    result.steps.append(step)

                    xss_finding = _xss_finding(param, surface.url, resp, payload)
                    if xss_finding:
                        xss_finding["affected"]["surface"] = surface.id
                        xss_finding["affected"]["surfaceType"] = surface.type.value
                        result.findings.append(xss_finding)

                elif surface.type == InputSurfaceType.FORM_INPUT:
                    # POST request with form input field
                    body = {param: payload.payload}
                    headers = {"Content-Type": "application/x-www-form-urlencoded"}

                    resp = _make_http_request(
                        surface.url,
                        method="POST",
                        body=body,
                        headers=headers,
                        cookies=cookies,
                        timeout=timeout,
                    )
                    result.test_count += 1

                    step = {
                        "name": f"xss-form-{surface.id}-{payload.id}",
                        "request": {
                            "method": "POST",
                            "url": surface.url,
                            "payload": f"[xss/{surface.type.value}/{param}/{payload.category}]",
                            "cookie": bool(cookies),
                        },
                        "status": resp["status"],
                        "bodyBytes": resp["bodyBytes"],
                        "redirectTarget": resp.get("headers", {}).get("Location", ""),
                    }
                    result.steps.append(step)

                    xss_finding = _xss_finding(param, surface.url, resp, payload)
                    if xss_finding:
                        xss_finding["affected"]["surface"] = surface.id
                        xss_finding["affected"]["surfaceType"] = surface.type.value
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
                "redirectTarget": resp.get("headers", {}).get("Location", ""),
            }
            result.steps.append(step)

            sqli_finding = _sqli_finding(param, test_url, resp, payload)
            if sqli_finding:
                result.findings.append(sqli_finding)

    return result


def _test_sqli_on_surfaces(surfaces: list[UserInputSurface], cookies: dict[str, str], timeout: float) -> _SqlInjectionResult:
    """Test SQL injection on discovered user input surfaces."""
    result = _SqlInjectionResult()

    for surface in surfaces:
        # Skip SSRF-only surfaces
        if surface.type in (InputSurfaceType.URL_PATH,):
            continue

        for param in surface.parameters:
            for payload in SQLI_PAYLOADS:
                # Determine how to inject based on surface type
                if surface.type == InputSurfaceType.QUERY_PARAM:
                    # GET request with query parameter
                    test_url = make_url(surface.url, f"?{param}=")
                    encoded = quote(payload.payload, safe="")
                    test_url = f"{test_url}{encoded}"

                    resp = _make_http_request(test_url, timeout=timeout, cookies=cookies)
                    result.test_count += 1

                    step = {
                        "name": f"sqli-query-{surface.id}-{payload.id}",
                        "request": {
                            "method": "GET",
                            "url": test_url,
                            "payload": f"[sqli/{surface.type.value}/{param}/{payload.category}]",
                            "cookie": bool(cookies),
                        },
                        "status": resp["status"],
                        "redirectTarget": resp.get("headers", {}).get("Location", ""),
                    }
                    result.steps.append(step)

                    sqli_finding = _sqli_finding(param, test_url, resp, payload)
                    if sqli_finding:
                        sqli_finding["affected"]["surface"] = surface.id
                        sqli_finding["affected"]["surfaceType"] = surface.type.value
                        result.findings.append(sqli_finding)

                elif surface.type in (InputSurfaceType.BODY_JSON, InputSurfaceType.BODY_FORM):
                    # POST request with body parameter
                    if surface.type == InputSurfaceType.BODY_JSON:
                        body = {param: payload.payload}
                        headers = {"Content-Type": "application/json"}
                    else:
                        body = {param: payload.payload}
                        headers = {"Content-Type": "application/x-www-form-urlencoded"}

                    resp = _make_http_request(
                        surface.url,
                        method="POST",
                        body=body,
                        headers=headers,
                        cookies=cookies,
                        timeout=timeout,
                    )
                    result.test_count += 1

                    step = {
                        "name": f"sqli-post-{surface.id}-{payload.id}",
                        "request": {
                            "method": "POST",
                            "url": surface.url,
                            "payload": f"[sqli/{surface.type.value}/{param}/{payload.category}]",
                            "cookie": bool(cookies),
                        },
                        "status": resp["status"],
                        "redirectTarget": resp.get("headers", {}).get("Location", ""),
                    }
                    result.steps.append(step)

                    sqli_finding = _sqli_finding(param, surface.url, resp, payload)
                    if sqli_finding:
                        sqli_finding["affected"]["surface"] = surface.id
                        sqli_finding["affected"]["surfaceType"] = surface.type.value
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
            "redirectTarget": resp.get("headers", {}).get("Location", ""),
        }
        result.steps.append(step)

        ssrf_finding = _ssrf_finding(endpoint.url, resp)
        if ssrf_finding:
            result.findings.append(ssrf_finding)

    return result


def _test_ssrf_on_surfaces(surfaces: list[UserInputSurface], cookies: dict[str, str], timeout: float) -> _SsrfResult:
    """Test SSRF on discovered user input surfaces."""
    result = _SsrfResult()

    for surface in surfaces:
        # Only test surfaces that accept URLs or external values
        if surface.type not in (InputSurfaceType.BODY_JSON, InputSurfaceType.BODY_FORM):
            continue

        # Test each URL-like parameter
        for param in surface.parameters:
            # Check if parameter name suggests it accepts a URL
            if any(keyword in param.lower() for keyword in ["url", "redirect", "callback", "webhook", "external", "destination"]):
                for endpoint in SSRF_ENDPOINTS:
                    # Inject SSRF payload into the parameter
                    if surface.type == InputSurfaceType.BODY_JSON:
                        body = {param: endpoint.url}
                        headers = {"Content-Type": "application/json"}
                    else:
                        body = {param: endpoint.url}
                        headers = {"Content-Type": "application/x-www-form-urlencoded"}

                    resp = _make_http_request(
                        surface.url,
                        method="POST",
                        body=body,
                        headers=headers,
                        cookies=cookies,
                        timeout=timeout,
                    )
                    result.test_count += 1

                    step = {
                        "name": f"ssrf-post-{surface.id}-{param}-{endpoint.id}",
                        "request": {
                            "method": "POST",
                            "url": surface.url,
                            "payload": f"[ssrf/{surface.type.value}/{param}/{endpoint.category}]",
                            "cookie": bool(cookies),
                        },
                        "status": resp["status"],
                        "redirectTarget": resp.get("headers", {}).get("Location", ""),
                    }
                    result.steps.append(step)

                    ssrf_finding = _ssrf_finding(endpoint.url, resp)
                    if ssrf_finding:
                        ssrf_finding["affected"]["surface"] = surface.id
                        ssrf_finding["affected"]["surfaceType"] = surface.type.value
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
