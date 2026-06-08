"""Target reconnaissance for the Hermes Security Harness.

Discovers attack surfaces beyond what HTTP smoke tests reveal:
- HTML form field extraction from page content
- API route discovery from JavaScript bundles, OpenAPI/Swagger specs, and Sitemap
- URL parameter pattern detection (path params, route params)
- Authentication surface mapping (login endpoints, OAuth, SSO, 2FA)
- Link graph analysis to discover nested pages and hidden endpoints
- Static asset analysis (robots.txt, sitemap.xml, .well-known/)

Public API (``__all__``):
    ReconTarget, ReconSurface, ReconConfig, ReconResult,
    run_recon, discover_from_openapi, discover_from_js_bundle,
    discover_from_sitemap, discover_url_patterns, discover_auth_surfaces,
    discover_hidden_endpoints, build_recon_surfaces,
"""
from __future__ import annotations

import json
import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from urllib.request import Request, urlopen, HTTPError

from ._http_client import make_url, _json_dumps
from .web_target import WebTargetConfig


# ── Recon surface types ────────────────────────────────────────────────────────


class ReconSource(Enum):
    """Source of a discovered surface."""

    SMOKE_TEST = "smoke_test"
    HTML_FORM = "html_form"
    OPENAPI = "openapi"
    JS_BUNDLE = "js_bundle"
    SITEMAP = "sitemap"
    ROBOTS_TXT = "robots_txt"
    URL_PATTERN = "url_pattern"
    AUTH = "auth"
    WELL_KNOWN = "well_known"
    LINK_CRAWL = "link_crawl"
    # Staged recon phases
    UNAUTH_PHASE = "unauth_phase"
    AUTH_PHASE = "auth_phase"


class ReconStage(IntEnum):
    """Stage of reconnaissance."""
    UNAUTH = 1
    AUTH = 2


@dataclass(frozen=True)
class ReconSurface:
    """A discovered input surface from recon.

    Attributes:
        id: Stable identifier.
        url: URL of the surface.
        input_type: Type of user input (param, form_field, path_param, header, etc.)
        parameter_name: Name of the parameter/field.
        method: HTTP method.
        source: Where this surface was discovered.
        confidence: How confident we are (high/medium/low).
        context: Extra metadata about the surface.
    """
    id: str
    url: str
    input_type: str
    parameter_name: str
    method: str
    source: ReconSource
    confidence: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReconResult:
    """Result of a recon run.

    Attributes:
        run_id: Stable identifier.
        target_id: Target ID.
        surfaces: Discovered input surfaces.
        discovered_routes: Discovered API routes.
        discovered_forms: Discovered HTML forms.
        auth_surfaces: Discovered auth surfaces.
        hidden_endpoints: Discovered hidden endpoints.
        total_requests: Number of HTTP requests made.
        warnings: Warnings.
        artifacts: Output artifact paths.
    """
    run_id: str
    target_id: str
    surfaces: list[ReconSurface]
    discovered_routes: list[dict[str, Any]]
    discovered_forms: list[dict[str, Any]]
    auth_surfaces: list[dict[str, Any]]
    hidden_endpoints: list[dict[str, Any]]
    total_requests: int = 0
    warnings: list[str] = field(default_factory=list)
    artifacts: dict[str, Path] = field(default_factory=dict)

    def to_summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target_id": self.target_id,
            "surface_count": len(self.surfaces),
            "routes_discovered": len(self.discovered_routes),
            "forms_discovered": len(self.discovered_forms),
            "auth_surfaces_discovered": len(self.auth_surfaces),
            "hidden_endpoints_discovered": len(self.hidden_endpoints),
            "total_requests": self.total_requests,
            "warnings": self.warnings,
            "surfaces": [
                {
                    "id": s.id,
                    "url": s.url,
                    "input_type": s.input_type,
                    "parameter_name": s.parameter_name,
                    "method": s.method,
                    "source": s.source.value,
                    "confidence": s.confidence,
                }
                for s in self.surfaces
            ],
        }


# ── Helpers ──────────────────────────────────────────────────────────────────────

_RE = re.compile
_DISCOVERED_URLS: set[str] = set()


def _hash_str(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _url_key(url: str, method: str = "GET") -> str:
    return f"{method}:{url}"


def _is_unique(url: str) -> bool:
    return url not in _DISCOVERED_URLS


def _record_url(url: str) -> None:
    _DISCOVERED_URLS.add(url)


def _fetch(url: str, headers: dict[str, str] | None = None, timeout: float = 5.0) -> tuple[str, int, dict[str, str]]:
    """Fetch URL, return (body, status_code, headers_dict)."""
    try:
        req = Request(url, method="GET")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        resp = urlopen(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return body, resp.status, resp_headers
    except HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace"), e.code, {k.lower(): v for k, v in e.headers.items()}
        except Exception:
            return "", e.code, {}
    except Exception:
        return "", 0, {}


# ── Form extraction ────────────────────────────────────────────────────────────


class _FormParser(HTMLParser):
    """Extract forms and their input fields from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self._current_inputs: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "form":
            attrs_dict = {k.lower(): v or "" for k, v in attrs}
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get").upper(),
                "inputs": [],
            }
            self._current_inputs = []
        elif self._current_form is not None and tag == "input":
            attrs_dict = {k.lower(): v or "" for k, v in attrs}
            input_type = attrs_dict.get("type", "text").lower()
            if input_type not in ("submit", "hidden", "button", "reset"):
                self._current_inputs.append({
                    "name": attrs_dict.get("name", ""),
                    "type": input_type,
                    "placeholder": attrs_dict.get("placeholder", ""),
                    "autocomplete": attrs_dict.get("autocomplete", ""),
                    "pattern": attrs_dict.get("pattern", ""),
                })
        elif self._current_form is not None and tag == "select":
            attrs_dict = {k.lower(): v or "" for k, v in attrs}
            name = attrs_dict.get("name", _hash_str(_iso_now() + "select"))
            self._current_inputs.append({
                "name": name,
                "type": "select",
                "placeholder": "",
                "autocomplete": "",
            })
        elif self._current_form is not None and tag == "textarea":
            attrs_dict = {k.lower(): v or "" for k, v in attrs}
            self._current_inputs.append({
                "name": attrs_dict.get("name", _hash_str(_iso_now() + "textarea")),
                "type": "textarea",
                "placeholder": attrs_dict.get("placeholder", ""),
                "autocomplete": "",
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self._current_form["inputs"] = self._current_inputs
            self.forms.append(self._current_form)
            self._current_form = None
            self._current_inputs = []


def _extract_forms(html: str, base_url: str) -> list[dict[str, Any]]:
    """Extract HTML forms from body text."""
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    results: list[dict[str, Any]] = []
    for form in parser.forms:
        action = form["action"]
        if not action:
            action = base_url.rstrip("/") + "/"
        elif not action.startswith("http"):
            action = urljoin(base_url, action)
        results.append({
            "action": action,
            "method": form["method"],
            "inputs": [i for i in form["inputs"] if i["name"]],
        })
    return results


# ── OpenAPI discovery ─────────────────────────────────────────────────────────


def _find_openapi_paths(body: str) -> list[dict[str, Any]]:
    """Extract OpenAPI/Swagger paths from a document body."""
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return results

    is_swagger_2 = bool(data.get("swagger"))
    is_openapi_3 = bool(data.get("openapi"))

    for path_key, path_item in (data.get("paths", {}) or {}).items():
        if not isinstance(path_item, dict):
            continue

        methods = ["get", "post", "put", "patch", "delete", "head", "options", "trace"]
        if is_swagger_2:
            methods = ["get", "post", "put", "patch", "delete"]

        for method in methods:
            if method not in path_item:
                continue
            op = path_item[method]
            if not isinstance(op, dict):
                continue
            op_name = op.get("operationId", op.get("summary", ""))
            has_params = bool(op.get("parameters"))

            key = f"{method.upper()}:{path_key}:{op_name}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "path": path_key,
                    "method": method.upper(),
                    "operationId": op_name,
                    "hasParameters": has_params,
                })
    return results


def discover_from_openapi(
    base_url: str, openapi_url: str | None = None, body: str | None = None, timeout: float = 5.0,
) -> list[ReconSurface]:
    """Discover API input surfaces from an OpenAPI/Swagger specification.

    Args:
        base_url: The target base URL.
        openapi_url: Optional URL to fetch OpenAPI spec from.
        body: Optional raw OpenAPI spec body (avoids HTTP request).
        timeout: HTTP timeout.

    Returns:
        List of ReconSurface entries for each discovered endpoint/parameter.
    """
    surfaces: list[ReconSurface] = []
    openapi_body = body

    if not openapi_body:
        url = openapi_url or f"{base_url}/api-docs"
        body_resp, status, _ = _fetch(url, timeout=timeout)
        if status != 200:
            body_resp, status, _ = _fetch(f"{base_url}/swagger.json", timeout=timeout)
        if status != 200:
            body_resp, status, _ = _fetch(f"{base_url}/openapi.json", timeout=timeout)
        if status != 200:
            body_resp, status, _ = _fetch(f"{base_url}/swagger.yaml", timeout=timeout)
        if status == 200:
            openapi_body = body_resp
        else:
            return surfaces

    if not openapi_body:
        return surfaces

    parsed = _find_openapi_paths(openapi_body)
    for entry in parsed:
        path = entry["path"]
        method = entry["method"]
        # Replace OpenAPI path params like {id} with injection markers
        expanded_path = re.sub(r"\{(\w+)\}", "{\\1}", path)

        surfaces.append(ReconSurface(
            id=f"openapi-{_hash_str(_url_key(expanded_path, method))}",
            url=expanded_path,
            input_type="openapi_param",
            parameter_name=f"{{{path.strip('/').split('/')[1]}}}",
            method=method,
            source=ReconSource.OPENAPI,
            confidence="high",
            context={"operationId": entry.get("operationId", ""), "hasParameters": entry.get("hasParameters", False)},
        ))
    return surfaces


# ── JS bundle analysis (fixed: enumerate from HTML) ─────────────────────────────


_JS_ROUTE_RE = _RE(r'(?:fetch|axios|\.get|\.post|\.put|\.patch|\.delete|\.head|\.options)\s*\)\s*["\x27]([^"\047]+)\047', re.IGNORECASE)

_JS_API_RE = _RE(r'["\047](/api/[^"\047]*)["\047]', re.IGNORECASE)

_JS_ROUTE_DEF_RE = _RE(r'(?:path|route|url|endpoint|method)\s*[:=]\s*["\047]([^"\047]+)["\047]', re.IGNORECASE)



_FALSE_POSITIVE_RE = _RE(
    r'\.(js|ts|tsx|jsx|mjs|cjs|css|woff2|png|jpg|gif|svg|ico|map|json)$'
    r'|\.(check|apply|load|render|find|querySelector|getElementByName|matches|'
    r'nodeType|frameElement|hot-module-replacement)$'
    r'|\b(foo|key|name|autofocus|formenctype|formmethod|formtarget|'
    r'enctype|method|target|url|path|route|urlsearchparams|window|'
    r'document|element|node|map|get|set|add|remove|create|init|destroy|'
    r'hot|module|exports|require|module|import|const|let|var|function|'
    r'return|async|await|throw|try|catch|if|else|for|while|class|new|'
    r'void|typeof|instanceof|in|of|break|continue|switch|case|default|'
    r'import|export|from|static|extends|super|this|constructor|prototype)'
    r'$', re.IGNORECASE,
)


def _extract_routes_from_js(js_content: str) -> list[dict[str, str]]:
    """Extract API routes and URLs from JavaScript bundle content."""
    routes: list[dict[str, str]] = []
    seen: set[str] = set()

    for pattern in (_JS_ROUTE_RE, _JS_API_RE, _JS_ROUTE_DEF_RE):
        for match in pattern.finditer(js_content):
            url = match.group(1).strip().rstrip(";").rstrip("'").rstrip('"')
            if not url:
                continue
            # Skip non-API URLs
            if url.startswith("http://") or url.startswith("https://"):
                continue
            # Skip file paths and JS false positives
            if url.endswith(".js") or url.endswith(".ts"):
                continue
            if _FALSE_POSITIVE_RE.search(url):
                continue
            if url not in seen:
                seen.add(url)
                routes.append({"route": url, "source": "js_bundle"})

    return routes


def discover_from_js_bundle(
    base_url: str, bundle_url: str | None = None, body: str | None = None, timeout: float = 5.0,
) -> list[ReconSurface]:
    """Discover API input surfaces by analyzing JavaScript bundles.

    Args:
        base_url: Target base URL.
        bundle_url: Optional URL to fetch JS bundle from.
        body: Optional raw JS content (avoids HTTP request).
        timeout: HTTP timeout.

    Returns:
        List of ReconSurface entries.
    """
    surfaces: list[ReconSurface] = []
    js_bodies: list[str] = []

    if body:
        js_bodies.append(body)
    elif bundle_url:
        # Single bundle URL
        body_resp, status, _ = _fetch(bundle_url, timeout=timeout)
        if status == 200:
            js_bodies.append(body_resp)
    else:
        # Discover bundles from HTML script tags (handles Next.js, React SPA, etc.)
        shell_body, status, _ = _fetch(base_url, timeout=timeout)
        if status == 200:
            # Extract all JS bundle script tags
            script_re = _RE(r'<script[^>]*src=["\']([^"\']+\.js)[^>]*>', re.IGNORECASE)
            js_urls: set[str] = set()
            for match in script_re.finditer(shell_body):
                js_urls.add(match.group(1))

            # Also check for chunk/manifest patterns from Next.js
            for pattern in (_JS_ROUTE_RE, _JS_API_RE):
                for match in pattern.finditer(shell_body):
                    url = match.group(1).strip().rstrip(";")
                    if url.endswith(".js"):
                        js_urls.add(url)

            # Fetch discovered bundles (up to 15 to avoid too many requests)
            for js_url in sorted(js_urls)[:15]:
                full_url = urljoin(base_url, js_url)
                body_resp, status, _ = _fetch(full_url, timeout=timeout)
                if status == 200:
                    js_bodies.append(body_resp)

    for js_body in js_bodies:
        routes = _extract_routes_from_js(js_body)
        for route_info in routes:
            route = route_info["route"]
            # Convert relative paths to full URLs
            if not route.startswith("http"):
                full_url = urljoin(base_url, route)
            else:
                full_url = route

            if _is_unique(full_url):
                _record_url(full_url)
                surfaces.append(ReconSurface(
                    id=f"js-{_hash_str(full_url)}",
                    url=full_url,
                    input_type="api_route",
                    parameter_name="dynamic",
                    method="unknown",
                    source=ReconSource.JS_BUNDLE,
                    confidence="medium",
                    context={"route": route},
                ))
    return surfaces


# ── Sitemap analysis ───────────────────────────────────────────────────────────

_SITEMAP_URL_RE = _RE(r"<loc>\s*(https?://[^<]+)\s*</loc>", re.IGNORECASE)


def _parse_sitemap(body: str) -> list[str]:
    """Extract URLs from a sitemap XML body."""
    urls: list[str] = []
    for match in _SITEMAP_URL_RE.finditer(body):
        urls.append(match.group(1))

    # Handle sitemap index files
    sitemap_re = _RE(r"<sitemap>\s*<loc>\s*(https?://[^<]+)\s*</loc>", re.IGNORECASE)
    for match in sitemap_re.finditer(body):
        sitemap_url = match.group(1)
        sitemap_body, status, _ = _fetch(sitemap_url)
        if status == 200:
            urls.extend(_parse_sitemap(sitemap_body))

    return urls


def discover_from_sitemap(base_url: str, timeout: float = 5.0) -> list[ReconSurface]:
    """Discover input surfaces from sitemap.xml.

    Args:
        base_url: Target base URL.
        timeout: HTTP timeout.

    Returns:
        List of ReconSurface entries for each discovered URL.
    """
    surfaces: list[ReconSurface] = []
    body, status, _ = _fetch(f"{base_url}/sitemap.xml", timeout=timeout)
    if status != 200:
        body, status, _ = _fetch(f"{base_url}/sitemapindex.xml", timeout=timeout)
    if status != 200:
        return surfaces

    urls = _parse_sitemap(body)
    for url in urls:
        if _is_unique(url):
            _record_url(url)
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            param_names = list(query_params.keys()) if query_params else ["unknown"]
            for param in param_names:
                surfaces.append(ReconSurface(
                    id=f"sitemap-{_hash_str(url)}",
                    url=url,
                    input_type="query_param",
                    parameter_name=param,
                    method="GET",
                    source=ReconSource.SITEMAP,
                    confidence="low",
                ))
    return surfaces


# ── URL parameter pattern detection ───────────────────────────────────────────

_PATH_PARAM_RE = _RE(r"\{(\w+)\}|:(\w+)")


def _classify_url_patterns(url: str) -> list[tuple[str, str]]:
    """Classify URL parameters from a URL pattern.

    Args:
        url: URL with possible path parameters.

    Returns:
        List of (param_name, param_type) tuples.
    """
    params: list[tuple[str, str]] = []
    # Only look for params in the path component (after the host)
    parsed = urlparse(url)
    path_only = parsed.path if parsed.path else url
    # Express.js style: /users/:id  — must be in the path, not the host:port
    for match in _RE(r"/:(\w+)").finditer(path_only):
        params.append((match.group(1), "path_param"))
    # OpenAPI/REST style: /users/{id}
    for match in _PATH_PARAM_RE.finditer(path_only):
        name = match.group(1) or match.group(2)
        if name and not any(p[0] == name for p in params):
            params.append((name, "path_param"))

    # Query string params
    for key in parse_qs(parsed.query):
        params.append((key, "query_param"))

    return params


def discover_url_patterns(
    base_url: str, paths: list[str], method: str = "GET",
) -> list[ReconSurface]:
    """Create recon surfaces from known URL patterns with parameter detection.

    Args:
        base_url: Target base URL.
        paths: List of URL paths (may contain :param or {param}).
        method: HTTP method.

    Returns:
        List of ReconSurface entries.
    """
    surfaces: list[ReconSurface] = []
    for path in paths:
        url = urljoin(base_url, path)
        if _is_unique(url):
            _record_url(url)
            params = _classify_url_patterns(url)
            for param_name, param_type in params:
                surfaces.append(ReconSurface(
                    id=f"pattern-{_hash_str(f'{url}:{param_name}')}",
                    url=url,
                    input_type=param_type,
                    parameter_name=param_name,
                    method=method,
                    source=ReconSource.URL_PATTERN,
                    confidence="medium",
                ))
    return surfaces


# ── Auth surface discovery ────────────────────────────────────────────────────

_AUTH_KEYWORDS = _RE(
    r"(signin|signup|register|login|logout|oauth|sso|auth|token|session|verify|"
    r"mfa|2fa|totp|password|reset|confirm|activate|deactivate)",
    re.IGNORECASE,
)


def _extract_auth_urls_from_html(html: str, base_url: str) -> list[str]:
    """Extract auth-related URLs from HTML links and forms."""
    urls: list[str] = []
    href_re = _RE(r'<a[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)
    form_re = _RE(r'<form[^>]*action=["\']([^"\']+)["\']', re.IGNORECASE)
    script_re = _RE(r'(?:oauth|auth|login|token|session)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE)

    for regex in (href_re, form_re, script_re):
        for match in regex.finditer(html):
            url = match.group(1)
            if not url.startswith("http"):
                url = urljoin(base_url, url)
            if _AUTH_KEYWORDS.search(url) and _is_unique(url):
                _record_url(url)
                urls.append(url)

    return urls


def discover_auth_surfaces(
    base_url: str, known_auth_endpoints: list[str] | None = None, timeout: float = 5.0,
) -> list[ReconSurface]:
    """Discover authentication-related input surfaces.

    Looks for login pages, OAuth flows, SSO, 2FA, password reset, etc.

    Args:
        base_url: Target base URL.
        known_auth_endpoints: Optional list of known auth endpoint paths.
        timeout: HTTP timeout.

    Returns:
        List of ReconSurface entries.
    """
    surfaces: list[ReconSurface] = []
    auth_endpoints: list[dict[str, Any]] = []

    known = list(known_auth_endpoints or [])
    # Try common auth paths
    for path in ("/login", "/signin", "/auth", "/oauth", "/register", "/signup",
                  "/api/auth", "/api/login", "/api/session", "/token", "/api/token"):
        url = f"{base_url.rstrip('/')}{path}"
        _, status, _ = _fetch(url, timeout=timeout)
        if status in (200, 302, 404):
            known.append(path)

    # Check common auth paths
    for path in known:
        url = f"{base_url.rstrip('/')}{path}"
        if _is_unique(url):
            _record_url(url)
            surfaces.append(ReconSurface(
                id=f"auth-{_hash_str(url)}",
                url=url,
                input_type="auth_form",
                parameter_name="credentials",
                method="POST",
                source=ReconSource.AUTH,
                confidence="high",
            ))
            auth_endpoints.append({"endpoint": url, "method": "POST"})

    # Discover auth URLs from HTML
    body, status, _ = _fetch(base_url, timeout=timeout)
    if status == 200:
        auth_urls = _extract_auth_urls_from_html(body, base_url)
        for url in auth_urls:
            auth_endpoints.append({"endpoint": url, "method": "POST"})

    return surfaces


# ── Hidden endpoint discovery ─────────────────────────────────────────────────

_HIDDEN_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/.htaccess", "/.htpasswd", "/.DS_Store",
    "/wp-admin", "/wp-login.php", "/administrator", "/admin",
    "/phpmyadmin", "/pma", "/phpinfo.php", "/info.php",
    "/server-status", "/server-info", "/nginx-status",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
    "/debug", "/trace", "/healthz", "/readyz", "/livez",
    "/graphql", "/graphiql", "/playground",
    "/console", "/swagger-ui", "/swagger-ui.html", "/api-docs",
    "/metrics", "/prometheus", "/health",
    "/backup", "/dump", "/db", "/database",
    "/config", "/configs", "/settings",
    "/test", "/tests", "/dev", "/development", "/staging",
    "/.well-known/security.txt", "/.well-known/change-password",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
]


def discover_hidden_endpoints(
    base_url: str, timeout: float = 3.0, custom_paths: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Discover hidden/interesting endpoints by brute-forcing common paths.

    Args:
        base_url: Target base URL.
        timeout: HTTP timeout per request.
        custom_paths: Optional additional paths to probe.

    Returns:
        List of dict entries for endpoints that returned 200, 301, 302, or 403.
    """
    endpoints: list[dict[str, Any]] = []
    known_paths = list(_HIDDEN_PATHS) + list(custom_paths or [])
    for path in known_paths:
        url = f"{base_url.rstrip('/')}{path}"
        _, status, headers = _fetch(url, timeout=timeout)
        # Interesting: not 404 (server exists but didn't find it)
        if status in (200, 301, 302, 403):
            endpoints.append({
                "url": url,
                "status": status,
                "interesting": status in (200, 301, 302, 403),
                "headers": headers,
            })
    return endpoints


# ── HTML crawl ─────────────────────────────────────────────────────────────────

_LINK_RE = _RE(r'<a[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)
_IMG_RE = _RE(r'<img[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)


def _crawl_links(
    base_url: str, max_depth: int = 2, max_pages: int = 50,
    timeout: float = 5.0,
) -> tuple[list[dict[str, Any]], int, int]:
    """Simple HTML crawler that follows links to discover nested pages.

    Args:
        base_url: Target base URL.
        max_depth: Maximum link depth to follow.
        max_pages: Maximum pages to crawl.
        timeout: HTTP timeout.

    Returns:
        (pages, urls_checked, urls_discovered).
    """
    pages: list[dict[str, Any]] = []
    queue: list[str] = [base_url]
    urls_checked = 0
    urls_discovered = 0
    seen: set[str] = set()

    while queue and urls_discovered < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        urls_checked += 1

        body, status, _ = _fetch(url, timeout=timeout)
        if status != 200:
            continue

        pages.append({"url": url, "status": status, "size": len(body)})

        # Extract links
        for match in _LINK_RE.finditer(body):
            href = match.group(1)
            if href and not href.startswith("#") and not href.startswith("mailto:"):
                full_url = urljoin(url, href)
                # Only crawl same-origin
                parsed = urlparse(full_url)
                target_origin = urlparse(base_url).netloc
                if parsed.netloc == "" or parsed.netloc == target_origin:
                    if _is_unique(full_url):
                        _record_url(full_url)
                        urls_discovered += 1
                        queue.append(full_url)

    return pages, urls_checked, urls_discovered


def discover_from_crawl(
    base_url: str, max_depth: int = 2, max_pages: int = 50,
    timeout: float = 5.0,
) -> list[ReconSurface]:
    """Discover input surfaces by crawling the site.

    Args:
        base_url: Target base URL.
        max_depth: Max link depth.
        max_pages: Max pages to crawl.
        timeout: HTTP timeout.

    Returns:
        List of ReconSurface entries for discovered forms and query params.
    """
    surfaces: list[ReconSurface] = []
    pages, _, _ = _crawl_links(base_url, max_depth, max_pages, timeout)

    for page_info in pages:
        url = page_info["url"]

        # Extract forms from crawled pages
        body, status, _ = _fetch(url, timeout=timeout)
        if status != 200:
            continue
        forms = _extract_forms(body, base_url)
        for form in forms:
            for inp in form.get("inputs", []):
                if inp["name"]:
                    surfaces.append(ReconSurface(
                        id=f"crawl-form-{_hash_str(_url_key(form.get('action', url), inp['name']))}",
                        url=form.get("action", url),
                        input_type="form_input",
                        parameter_name=inp["name"],
                        method=form.get("method", "get").upper(),
                        source=ReconSource.LINK_CRAWL,
                        confidence="high",
                        context={"page_url": url, "input_type": inp.get("type", "text"), "autocomplete": inp.get("autocomplete", "")},
                    ))

        # Check query params
        parsed = urlparse(url)
        for key in parse_qs(parsed.query):
            surfaces.append(ReconSurface(
                id=f"crawl-qp-{_hash_str(f'{url}:{key}')}",
                url=url,
                input_type="query_param",
                parameter_name=key,
                method="GET",
                source=ReconSource.LINK_CRAWL,
                confidence="medium",
            ))

    return surfaces


# ── Next.js RSC payload parsing ────────────────────────────────────────────────
# Next.js App Router embeds route structure in the HTML shell via RSC JSON payloads.
# Parsing these gives us all page routes without filesystem access or JS execution.

_RSC_PUSH_RE = _RE(r'self\.__next_f\.push\(\[1,"(.+?)"\]\)', re.DOTALL)
_RSC_ROUTE_RE = _RE(r'"(?:segmentPath|parallelRouterKey|initialTree|children)".*?(?=\["\$|\\n"\\])', re.DOTALL)


def _extract_nextjs_routes(html: str) -> list[str]:
    """Extract route paths from a Next.js App Router shell HTML.

    Parses the RSC (React Server Components) JSON payload embedded in <script> tags.
    Returns a list of URL paths like ['/admin', '/admin/customers/[id]', '/api/auth/*'].
    """
    routes: set[str] = set()

    # Extract all quoted strings starting with / from RSC push payloads
    # These contain segment path values in the Next.js route tree
    for match in _RSC_PUSH_RE.finditer(html):
        payload = match.group(1)
        # Find all quoted values in the payload that look like route segments
        for quoted in _RE(r'["\'](/[a-zA-Z0-9_/\[\]-]*)["\']').finditer(payload):
            val = quoted.group(1)
            # Filter: keep route paths, skip Next.js internals
            if (not val.startswith("/_")
                and val != "__PAGE__"
                and "node_modules" not in val
                and ".css" not in val
                and ".js" not in val
                and ".woff" not in val
                and ".png" not in val
                and len(val) > 1
                and len(val) < 200):
                routes.add(val)

    return sorted(routes)


def discover_from_rsc_payload(
    base_url: str, timeout: float = 5.0,
) -> tuple[list[ReconSurface], list[dict[str, Any]]]:
    """Discover page and API routes from Next.js RSC payload in shell HTML.

    Args:
        base_url: Target base URL.
        timeout: HTTP timeout.

    Returns:
        Tuple of (surfaces, routes).
    """
    surfaces: list[ReconSurface] = []
    routes: list[dict[str, Any]] = []

    body, status, _ = _fetch(base_url, timeout=timeout)
    if status != 200:
        return surfaces, routes

    discovered = _extract_nextjs_routes(body)

    for route in discovered:
        full_url = urljoin(base_url, route)
        if _is_unique(full_url):
            _record_url(full_url)
            routes.append({"path": route, "method": "GET", "source": "rsc_payload"})

    return surfaces, routes


# ── Filesystem-based route discovery ──────────────────────────────────────────
# For targets where we have access to the source directory, enumerate routes from
# the file system. Especially useful for Next.js App Router.


def discover_from_source_dir(
    source_dir: str | Path,
    base_url: str,
) -> list[dict[str, Any]]:
    """Discover API and page routes by scanning the source file system.

    Args:
        source_dir: Path to the project root (where app/ directory lives).
        base_url: Target base URL (for constructing full URLs).

    Returns:
        List of route dicts with path and method.
    """
    routes: list[dict[str, Any]] = []
    seen: set[str] = set()
    source_path = Path(source_dir)

    # Next.js App Router: page.tsx files in app/ define page routes
    for page in source_path.rglob("app/**/page.tsx"):
        rel = str(page.relative_to(source_path))
        # Strip app/ prefix and convert file system path to URL path
        url_path = "/" + rel.replace("/page.tsx", "").replace("/page.ts", "")
        if url_path and url_path != "/" and not url_path.startswith("/_"):
            if url_path not in seen:
                seen.add(url_path)
                routes.append({"path": url_path, "method": "GET", "source": "source_dir", "type": "page"})

    # Next.js App Router: route.ts files in app/api/ define API routes
    for route_file in source_path.rglob("app/api/**/route.ts"):
        rel = str(route_file.relative_to(source_path))
        url_path = "/" + rel.replace("/route.ts", "").replace("/route.js", "")
        if url_path and not url_path.startswith("/_"):
            if url_path not in seen:
                seen.add(url_path)
                routes.append({"path": url_path, "method": "unknown", "source": "source_dir", "type": "api"})
            # Determine actual HTTP methods from route handler content
            try:
                content = route_file.read_text()
                methods = []
                if re.search(r"export\s+function\s+GET\s*\(", content):
                    methods.append("GET")
                if re.search(r"export\s+function\s+POST\s*\(", content):
                    methods.append("POST")
                if re.search(r"export\s+function\s+PUT\s*\(", content):
                    methods.append("PUT")
                if re.search(r"export\s+function\s+PATCH\s*\(", content):
                    methods.append("PATCH")
                if re.search(r"export\s+function\s+DELETE\s*\(", content):
                    methods.append("DELETE")
                if not methods:
                    methods = ["GET", "POST"]
                routes.append({"path": url_path, "method": ", ".join(methods), "source": "source_dir", "type": "api"})
            except Exception:
                pass

    # Express/Koa style: look for .get, .post, etc. in route files
    for src_file in source_path.rglob("**/*.ts"):
        if "node_modules" in str(src_file) or src_file.suffix not in (".ts", ".js"):
            continue
        try:
            content = src_file.read_text()
            for method_match in re.finditer(r'\.(get|post|put|patch|delete|head)\s*\(\s*[\'"]([^\'"]+)', content):
                method = method_match.group(1).upper()
                path = method_match.group(2).lstrip("/")
                full_path = f"/api/{path}" if not path.startswith("/api/") else f"/{path}"
                key = f"{method}:{full_path}"
                if key not in seen:
                    seen.add(key)
                    routes.append({"path": full_path, "method": method, "source": "source_dir", "type": "route"})
        except Exception:
            pass

    return routes


# ── JS bundle analysis (fixed: enumerate from HTML) ─────────────────────────────


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def build_recon_surfaces(
    target: WebTargetConfig,
    *,
    openapi_url: str | None = None,
    bundle_url: str | None = None,
    smoke_steps: list[dict[str, Any]] | None = None,
    known_auth: list[str] | None = None,
    max_depth: int = 2,
    max_pages: int = 50,
    request_timeout: float = 5.0,
    custom_hidden_paths: list[str] | None = None,
) -> ReconResult:
    """Run full target reconnaissance.

    Orchestrates all discovery strategies and returns a unified result.

    Args:
        target: WebTargetConfig.
        openapi_url: Optional URL to fetch OpenAPI spec.
        bundle_url: Optional URL to fetch JS bundle.
        smoke_steps: Optional smoke scan results (for baseline surfaces).
        known_auth: Optional known auth endpoint paths.
        max_depth: Max crawl depth.
        max_pages: Max pages to crawl.
        request_timeout: HTTP timeout.
        custom_hidden_paths: Optional extra paths to probe.

    Returns:
        ReconResult with all discovered surfaces.
    """
    base_url = target.base_url.rstrip("/")
    _DISCOVERED_URLS.clear()

    all_surfaces: list[ReconSurface] = []
    discovered_routes: list[dict[str, Any]] = []
    discovered_forms: list[dict[str, Any]] = []
    auth_surfaces: list[dict[str, Any]] = []
    hidden_endpoints: list[dict[str, Any]] = []
    total_requests = 0

    # Next.js RSC payload parsing (page routes from shell HTML)
    rsc_surfaces, rsc_routes = discover_from_rsc_payload(base_url, timeout=request_timeout)
    all_surfaces.extend(rsc_surfaces)
    discovered_routes.extend(rsc_routes)
    total_requests += 1

    # Filesystem-based route discovery (when source_dir is available)
    if target.source_dir:
        try:
            fs_routes = discover_from_source_dir(target.source_dir, base_url)
            discovered_routes.extend(fs_routes)
        except Exception:
            pass

    # OpenAPI discovery
    openapi_surfaces = discover_from_openapi(base_url, openapi_url, timeout=request_timeout)
    all_surfaces.extend(openapi_surfaces)
    total_requests += 1

    # JS bundle analysis (discovers API routes from JS bundles)
    js_surfaces = discover_from_js_bundle(base_url, bundle_url, timeout=request_timeout)
    all_surfaces.extend(js_surfaces)
    total_requests += 1

    # Sitemap
    sitemap_surfaces = discover_from_sitemap(base_url, timeout=request_timeout)
    all_surfaces.extend(sitemap_surfaces)
    total_requests += 1

    # Auth surfaces (expanded)
    auth_surfs = discover_auth_surfaces(base_url, known_auth, timeout=request_timeout)
    auth_surfaces = [
        {"endpoint": s.url, "method": s.method, "confidence": s.confidence}
        for s in auth_surfs
    ]

    # Hidden endpoints
    hidden = discover_hidden_endpoints(base_url, timeout=3.0, custom_paths=custom_hidden_paths)
    hidden_endpoints = hidden
    total_requests += len(hidden)

    # Crawl
    crawl_surfaces = discover_from_crawl(base_url, max_depth, max_pages, timeout=request_timeout)
    all_surfaces.extend(crawl_surfaces)
    total_requests += max_pages

    # Link crawl forms
    for surf in crawl_surfaces:
        if surf.input_type == "form_input":
            discovered_forms.append({
                "action": surf.url,
                "method": surf.method,
                "input_name": surf.parameter_name,
                "confidence": surf.confidence,
            })

    # URL pattern surfaces from known + discovered API paths
    known_paths = ["/", "/search", "/login", "/dashboard", "/api", "/api/docs",
                   "/about", "/contact", "/help", "/faq", "/terms", "/privacy",
                   # Common Next.js/SPA routes
                   "/admin", "/account", "/profile", "/settings", "/dashboard",
                   "/app", "/portal", "/status", "/support", "/docs",
                   # Common API patterns
                   "/api/auth", "/api/users", "/api/data", "/api/v1",
                   # Auth-related
                   "/api/auth/login", "/api/auth/register", "/api/auth/register",
                   "/api/auth/reset-password", "/api/auth/forgot-password",
                   "/api/auth/2fa", "/api/auth/verify", "/api/auth/refresh",
                   # Health/status
                   "/api/health", "/health", "/healthz", "/readyz",
                   # Integrations
                   "/api/integrations", "/api/webhooks",
                   ]
    pattern_surfaces = discover_url_patterns(base_url, known_paths)
    all_surfaces.extend(pattern_surfaces)

    # OpenAPI routes (re-fetch just in case)
    openapi_body: str | None = None
    try:
        body, status, _ = _fetch(openapi_url or f"{base_url}/api-docs", timeout=request_timeout)
        if status == 200:
            openapi_body = body
    except Exception:
        pass
    if openapi_body:
        routes = _find_openapi_paths(openapi_body)
        discovered_routes.extend(routes)

    return ReconResult(
        run_id=_hash_str(f"recon-{target.id}-{_iso_now()}"),
        target_id=target.id,
        surfaces=all_surfaces,
        discovered_routes=discovered_routes,
        discovered_forms=discovered_forms,
        auth_surfaces=auth_surfaces,
        hidden_endpoints=hidden_endpoints,
        total_requests=total_requests,
    )


def run_recon(
    config_path: str | Path,
    *,
    openapi_url: str | None = None,
    bundle_url: str | None = None,
    smoke_steps: list[dict[str, Any]] | None = None,
    known_auth: list[str] | None = None,
    max_depth: int = 2,
    max_pages: int = 50,
    request_timeout: float = 5.0,
    artifacts_root: str | Path = "runs",
    custom_hidden_paths: list[str] | None = None,
) -> ReconResult:
    """Run recon and write artifacts.

    Args:
        config_path: Path to target config.
        openapi_url: Optional OpenAPI spec URL.
        bundle_url: Optional JS bundle URL.
        smoke_steps: Optional smoke scan results.
        known_auth: Optional known auth paths.
        max_depth: Max crawl depth.
        max_pages: Max pages to crawl.
        request_timeout: HTTP timeout.
        artifacts_root: Output directory.
        custom_hidden_paths: Extra paths to probe.

    Returns:
        ReconResult with all discovered surfaces.
    """
    from .web_target import load_target_config
    target = load_target_config(config_path)

    result = build_recon_surfaces(
        target,
        openapi_url=openapi_url,
        bundle_url=bundle_url,
        smoke_steps=smoke_steps,
        known_auth=known_auth,
        max_depth=max_depth,
        max_pages=max_pages,
        request_timeout=request_timeout,
        custom_hidden_paths=custom_hidden_paths,
    )

    run_dir = Path(artifacts_root).expanduser().resolve() / f"recon-{result.run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    summary_path = run_dir / "recon-summary.json"
    summary_path.write_text(_json_dumps(result.to_summary()) + "\n")

    # ReconResult is frozen, so rebuild with artifacts
    return ReconResult(
        run_id=result.run_id,
        target_id=result.target_id,
        surfaces=result.surfaces,
        discovered_routes=result.discovered_routes,
        discovered_forms=result.discovered_forms,
        auth_surfaces=result.auth_surfaces,
        hidden_endpoints=result.hidden_endpoints,
        total_requests=result.total_requests,
        warnings=result.warnings,
        artifacts={"recon_summary": summary_path},
    )


# ── Staged reconnaissance (unauth/auth phases) ─────────────────────────────────


def run_unauth_recon(
    config_path: str | Path,
    *,
    artifacts_root: str | Path = "runs",
    max_depth: int = 2,
    max_pages: int = 50,
    request_timeout: float = 5.0,
) -> ReconResult:
    """Run unauthenticated reconnaissance (public surfaces only).

    Discovers surfaces that don't require authentication:
    - OpenAPI specs, sitemaps, robots.txt
    - URL pattern enumeration
    - Hidden endpoint probing
    - JS bundle analysis

    Args:
        config_path: Path to target config YAML.
        artifacts_root: Output directory for artifacts.
        max_depth: Max crawl depth.
        max_pages: Max pages to crawl.
        request_timeout: HTTP timeout in seconds.

    Returns:
        ReconResult with unauth surfaces.
    """
    from .web_target import load_target_config

    target = load_target_config(config_path)
    base_url = target.base_url.rstrip("/")

    all_surfaces: list[ReconSurface] = []
    discovered_routes: list[dict[str, Any]] = []
    discovered_forms: list[dict[str, Any]] = []
    hidden_endpoints: list[dict[str, Any]] = []
    total_requests = 0

    # OpenAPI discovery
    try:
        openapi_surfaces = discover_from_openapi(base_url, timeout=request_timeout)
        all_surfaces.extend(
            ReconSurface(
                id=s.id,
                url=s.url,
                input_type=s.input_type,
                parameter_name=s.parameter_name,
                method=s.method,
                source=ReconSource.UNAUTH_PHASE,
                confidence=s.confidence,
                context=s.context,
            )
            for s in openapi_surfaces
        )
        total_requests += 1
    except Exception:
        pass

    # Sitemap
    try:
        sitemap_surfaces = discover_from_sitemap(base_url, timeout=request_timeout)
        all_surfaces.extend(
            ReconSurface(
                id=s.id,
                url=s.url,
                input_type=s.input_type,
                parameter_name=s.parameter_name,
                method=s.method,
                source=ReconSource.UNAUTH_PHASE,
                confidence=s.confidence,
                context=s.context,
            )
            for s in sitemap_surfaces
        )
        total_requests += 1
    except Exception:
        pass

    # Hidden endpoints
    try:
        hidden = discover_hidden_endpoints(base_url, timeout=3.0)
        hidden_endpoints = hidden
        total_requests += len(hidden)
    except Exception:
        pass

    # URL patterns
    try:
        pattern_paths = ["/", "/search", "/login", "/api", "/api/docs", "/health"]
        pattern_surfaces = discover_url_patterns(base_url, pattern_paths)
        all_surfaces.extend(
            ReconSurface(
                id=s.id,
                url=s.url,
                input_type=s.input_type,
                parameter_name=s.parameter_name,
                method=s.method,
                source=ReconSource.UNAUTH_PHASE,
                confidence=s.confidence,
                context=s.context,
            )
            for s in pattern_surfaces
        )
    except Exception:
        pass

    run_id = _hash_str(f"recon-unauth-{target.id}-{_iso_now()}")

    return ReconResult(
        run_id=run_id,
        target_id=target.id,
        surfaces=all_surfaces,
        discovered_routes=discovered_routes,
        discovered_forms=discovered_forms,
        auth_surfaces=[],
        hidden_endpoints=hidden_endpoints,
        total_requests=total_requests,
    )


def run_auth_recon(
    config_path: str | Path,
    session_cookies: dict[str, str],
    *,
    artifacts_root: str | Path = "runs",
    request_timeout: float = 5.0,
) -> ReconResult:
    """Run authenticated reconnaissance (requires session).

    Discovers surfaces that require authentication:
    - Auth-protected API routes
    - Dashboard endpoints
    - Admin panels
    - User profile pages

    Args:
        config_path: Path to target config YAML.
        session_cookies: Authenticated session cookies.
        artifacts_root: Output directory for artifacts.
        request_timeout: HTTP timeout in seconds.

    Returns:
        ReconResult with auth surfaces.
    """
    from .web_target import load_target_config

    target = load_target_config(config_path)
    base_url = target.base_url.rstrip("/")

    all_surfaces: list[ReconSurface] = []
    discovered_routes: list[dict[str, Any]] = []
    discovered_forms: list[dict[str, Any]] = []
    hidden_endpoints: list[dict[str, Any]] = []
    total_requests = 0

    # Auth-specific paths to probe
    auth_paths = [
        "/api/users", "/api/dashboard", "/api/account",
        "/admin", "/profile", "/settings",
    ]

    for path in auth_paths:
        full_url = f"{base_url}{path}"
        try:
            headers = {}
            if session_cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
            body, status, _ = _fetch(full_url, headers=headers, timeout=request_timeout)
            total_requests += 1

            if status in (200, 301, 302):
                surface_id = _hash_str(f"auth-{path}")
                all_surfaces.append(ReconSurface(
                    id=surface_id,
                    url=full_url,
                    input_type="endpoint",
                    parameter_name=path,
                    method="GET",
                    source=ReconSource.AUTH_PHASE,
                    confidence="medium",
                    context={"status": status, "phase": "auth"},
                ))
        except Exception:
            pass

    run_id = _hash_str(f"recon-auth-{target.id}-{_iso_now()}")

    return ReconResult(
        run_id=run_id,
        target_id=target.id,
        surfaces=all_surfaces,
        discovered_routes=discovered_routes,
        discovered_forms=discovered_forms,
        auth_surfaces=[],
        hidden_endpoints=hidden_endpoints,
        total_requests=total_requests,
    )


def run_staged_recon(
    config_path: str | Path,
    *,
    session_cookies: dict[str, str] | None = None,
    artifacts_root: str | Path = "runs",
    max_depth: int = 2,
    max_pages: int = 50,
    request_timeout: float = 5.0,
) -> ReconResult:
    """Run full staged reconnaissance (unauth then auth).

    Args:
        config_path: Path to target config YAML.
        session_cookies: Optional auth cookies for the second phase.
        artifacts_root: Output directory for artifacts.
        max_depth: Max crawl depth.
        max_pages: Max pages to crawl.
        request_timeout: HTTP timeout in seconds.

    Returns:
        ReconResult with all surfaces from both phases.
    """
    unauth_result = run_unauth_recon(
        config_path,
        artifacts_root=artifacts_root,
        max_depth=max_depth,
        max_pages=max_pages,
        request_timeout=request_timeout,
    )

    auth_result = ReconResult(
        run_id=unauth_result.run_id,
        target_id=unauth_result.target_id,
        surfaces=[],
        discovered_routes=[],
        discovered_forms=[],
        auth_surfaces=[],
        hidden_endpoints=[],
        total_requests=0,
    )

    if session_cookies:
        auth_result = run_auth_recon(
            config_path,
            session_cookies=session_cookies,
            artifacts_root=artifacts_root,
            request_timeout=request_timeout,
        )

    # Combine results
    combined_surfaces = list(unauth_result.surfaces) + list(auth_result.surfaces)

    return ReconResult(
        run_id=unauth_result.run_id,
        target_id=unauth_result.target_id,
        surfaces=combined_surfaces,
        discovered_routes=unauth_result.discovered_routes + auth_result.discovered_routes,
        discovered_forms=unauth_result.discovered_forms + auth_result.discovered_forms,
        auth_surfaces=unauth_result.auth_surfaces + auth_result.auth_surfaces,
        hidden_endpoints=unauth_result.hidden_endpoints + auth_result.hidden_endpoints,
        total_requests=unauth_result.total_requests + auth_result.total_requests,
        warnings=unauth_result.warnings + auth_result.warnings,
    )
