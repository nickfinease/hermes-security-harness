"""Shared HTTP client for security scan modules.

Provides a minimal, deterministic HTTP request helper with structured
results. Used by auth_scan, injection_scanner, and rate_limit scanners.
"""
from __future__ import annotations

import re
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .artifacts import redact_secrets


class _NoRedirect(HTTPRedirectHandler):
    """HTTP redirect handler that prevents following redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401, ANN001
        return None


def _make_http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    *,
    timeout: float = 5.0,
    follow_redirect: bool = False,
) -> dict[str, Any]:
    """Issue a single HTTP request and return structured results.

    Args:
        url: Target URL.
        method: HTTP method (GET, POST, etc.).
        headers: Optional headers dict.
        body: Optional POST body (will be form-encoded).
        cookies: Optional cookies to send.
        timeout: Request timeout in seconds.
        follow_redirect: If True, allow redirects.

    Returns:
        Dict with status, headers, body, cookies, error, duration_ms.
    """
    started_s = time.monotonic()
    status: int | None = None
    resp_headers: dict[str, str] = {}
    body_bytes = 0
    error: str | None = None
    set_cookies: dict[str, str] = {}
    raw_body: bytes = b""

    try:
        req = Request(url, method=method, headers=headers or {})
        if cookies:
            cookie_parts = [f"{k}={v}" for k, v in cookies.items()]
            req.add_header("Cookie", "; ".join(cookie_parts))
        if body and method.upper() == "POST":
            # Check if headers specify JSON
            content_type = (headers or {}).get("Content-Type", "").lower()
            if "application/json" in content_type:
                import json
                req.data = json.dumps(body).encode()
            else:
                encoded = urlencode(body).encode()
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
                req.data = encoded

        opener = build_opener(_NoRedirect) if not follow_redirect else build_opener()

        with opener.open(req, timeout=timeout) as resp:
            status = int(resp.getcode())
            for h in resp.headers:
                resp_headers[h] = resp.headers.get(h) or ""
            raw_body = resp.read(8192) or b""
            body_bytes = len(raw_body)
            for h in resp.headers:
                if h.lower() == "set-cookie":
                    cookie_val = resp.headers.get(h) or ""
                    cookie_match = re.match(r"([^\s=]+)=([^;]*)", cookie_val)
                    if cookie_match:
                        set_cookies[cookie_match.group(1)] = cookie_match.group(2)

    except HTTPError as exc:
        status = int(exc.code)
        for h in exc.headers:
            resp_headers[h] = exc.headers.get(h) or ""
        try:
            raw_body = exc.read(4096) or b""
            body_bytes = len(raw_body)
            # Extract cookies from HTTPError response headers too
            for h in exc.headers:
                if h.lower() == "set-cookie":
                    cookie_val = exc.headers.get(h) or ""
                    cookie_match = re.match(r"([^\s=]+)=([^;]*)", cookie_val)
                    if cookie_match:
                        set_cookies[cookie_match.group(1)] = cookie_match.group(2)
        except OSError:
            body_bytes = 0
    except (TimeoutError, socket.timeout) as exc:
        error = f"timeout: {exc}"
    except URLError as exc:
        error = f"url error: {exc.reason}"
    except OSError as exc:
        error = f"os error: {exc}"

    duration_ms = round((time.monotonic() - started_s) * 1000, 2)

    return {
        "status": status,
        "headers": {k: redact_secrets(v) for k, v in resp_headers.items()},
        "bodyBytes": body_bytes,
        "rawBody": raw_body,
        "setCookies": set_cookies,
        "error": redact_secrets(error) if error else None,
        "durationMs": duration_ms,
    }


def make_url(base_url: str, path: str | None = None) -> str:
    """Construct an absolute URL from a base and path.

    Args:
        base_url: Base URL like 'http://localhost:3000'.
        path: Optional path like '/login'.

    Returns:
        Full URL like 'http://localhost:3000/login'.
    """
    if path is None:
        return base_url.rstrip("/")
    base = base_url.rstrip("/")
    path = path.lstrip("/")
    return f"{base}/{path}"


def safe_filename(text: str) -> str:
    """Convert arbitrary text to a safe filesystem filename."""
    return re.sub(r"[^A-Za-z0-9_-]+", "_", text).strip("_").lower()


def new_run_id(prefix: str, target_id: str) -> str:
    """Generate a unique run identifier.

    Args:
        prefix: Scan type prefix (e.g., 'http-smoke', 'dep-audit').
        target_id: Target identifier.

    Returns:
        Unique run ID string.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_target = re.sub(r"[^A-Za-z0-9_-]+", "-", target_id).strip("-") or "target"
    return f"{prefix}-{stamp}-{safe_target}-{uuid.uuid4().hex[:8]}"


def write_json(path: Path, obj: Any) -> None:
    """Write a JSON file with indentation and sorted keys."""
    path.write_text(_json_dumps(obj) + "\n")


def _json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj, indent=2, sort_keys=True)
