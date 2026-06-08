"""Extended HTTP client with cookie jar and redirect following for auth flows.

Handles NextAuth v5's double-submit cookie pattern where the cookie value
is URL-encoded as `token%7Chash` (131 chars). Python's http.cookiejar truncates
at 64 chars, so we send the full value manually.

For the credentials provider, the correct endpoint is /api/auth/callback/credentials
with a form-encoded body, matching next-auth/react's signIn() behavior.
"""
from __future__ import annotations

import http.cookiejar
import urllib.request
import urllib.parse
import json
from typing import Any


class _AuthCookieJar:
    """Cookie jar that manages cookies but sends the full CSRF value manually."""

    def __init__(self) -> None:
        self.jar: http.cookiejar.CookieJar | None = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            _CookieDecoderRedirectHandler(),
        )
        self._csrf_cookie_value: str | None = None

    def _get_cookie_header(self) -> str:
        """Build Cookie header: jar cookies minus CSRF, plus full CSRF manually."""
        if self.jar is None:
            return ""
        req = urllib.request.Request("http://localhost/")
        self.jar.add_cookie_header(req)
        header = req.get_header("Cookie", "")

        # Remove truncated CSRF from jar cookies
        if "authjs.csrf-token=" in header:
            header = header.split("authjs.csrf-token=")[0]
            header = header.rstrip("; ")

        # Add full CSRF cookie
        if self._csrf_cookie_value:
            decoded = self._csrf_cookie_value.replace("%7C", "|").replace("%7c", "|")
            if header:
                header += f"; authjs.csrf-token={decoded}"
            else:
                header = f"authjs.csrf-token={decoded}"
        return header

    def get(self, url: str, *, timeout: float = 5.0) -> dict[str, Any]:
        req = urllib.request.Request(url)
        req.add_unredirected_header("Cookie", self._get_cookie_header())
        resp = self._opener.open(req, timeout=timeout)
        body = resp.read()
        return {
            "status": resp.status,
            "headers": dict(resp.headers),
            "body": body,
            "rawBody": body,
            "setCookies": {c.name: c.value for c in self.jar} if self.jar else {},
            "url": resp.url,
        }

    def post_form(
        self,
        url: str,
        body: dict[str, str],
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        """POST with form-encoded body (for NextAuth credentials provider)."""
        data = urllib.parse.urlencode(body).encode()
        req_headers = headers or {}
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, headers=req_headers)
        req.add_unredirected_header("Cookie", self._get_cookie_header())
        resp = self._opener.open(req, timeout=timeout)
        body_content = resp.read()
        return {
            "status": resp.status,
            "headers": dict(resp.headers),
            "body": body_content,
            "rawBody": body_content,
            "setCookies": {c.name: c.value for c in self.jar} if self.jar else {},
            "url": resp.url,
        }

    def post_json(
        self,
        url: str,
        body: dict[str, str],
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        """POST with JSON body."""
        data = json.dumps(body).encode()
        req_headers = headers or {}
        req_headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=req_headers)
        req.add_unredirected_header("Cookie", self._get_cookie_header())
        resp = self._opener.open(req, timeout=timeout)
        body_content = resp.read()
        return {
            "status": resp.status,
            "headers": dict(resp.headers),
            "body": body_content,
            "rawBody": body_content,
            "setCookies": {c.name: c.value for c in self.jar} if self.jar else {},
            "url": resp.url,
        }

    def extract_csrf_cookie(self) -> None:
        """Store the full CSRF cookie value from the jar for manual sending."""
        if self.jar:
            for c in self.jar:
                if c.name == "authjs.csrf-token":
                    self._csrf_cookie_value = c.value
                    break

    def get_cookies(self) -> dict[str, str]:
        if self.jar is None:
            return {}
        # Exclude only CSRF tokens and callback URL, not session tokens
        return {
            c.name: c.value
            for c in self.jar
            if c.name not in ("authjs.csrf-token", "authjs.callback-url")
        }


class _CookieDecoderRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Decode %7C in cookie values before following redirects."""

    def _decode_cookie(self, req: urllib.request.Request) -> None:
        raw = req.get_header("Cookie", "")
        decoded = raw.replace("%7C", "|").replace("%7c", "|")
        if decoded != raw:
            req.add_unredirected_header("Cookie", decoded)

    def http_error_302(self, req, fp, code, msg, headers):
        self._decode_cookie(req)
        return super().http_error_302(req, fp, code, msg, headers)

    def http_error_301(self, req, fp, code, msg, headers):
        self._decode_cookie(req)
        return super().http_error_301(req, fp, code, msg, headers)

    def http_error_303(self, req, fp, code, msg, headers):
        self._decode_cookie(req)
        return super().http_error_303(req, fp, code, msg, headers)

    def http_error_307(self, req, fp, code, msg, headers):
        self._decode_cookie(req)
        return super().http_error_307(req, fp, code, msg, headers)

    def http_error_308(self, req, fp, code, msg, headers):
        self._decode_cookie(req)
        return super().http_error_308(req, fp, code, msg, headers)


def auth_signin_nextauth(
    base_url: str,
    email: str,
    password: str,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Sign in using NextAuth v5 credentials provider flow.

    Returns a dict with:
      - authenticated: bool
      - cookies: dict[str, str] (session cookies)
      - steps: list of step descriptions
      - error: error message if auth failed
    """
    result: dict[str, Any] = {
        "authenticated": False,
        "cookies": {},
        "steps": [],
        "error": None,
    }

    jar = _AuthCookieJar()

    try:
        # Step 1: Get CSRF token from /api/auth/csrf
        csrf_resp = jar.get(f"{base_url}/api/auth/csrf", timeout=timeout)
        result["steps"].append(f"GET /api/auth/csrf: status={csrf_resp['status']}")
        if csrf_resp["status"] != 200:
            result["error"] = f"CSRF endpoint returned status {csrf_resp['status']}"
            return result

        # Extract full CSRF cookie value (131 chars) from jar
        jar.extract_csrf_cookie()

        csrf_data = json.loads(csrf_resp["body"])
        csrf_token = csrf_data.get("csrfToken", "")
        result["steps"].append(f"  CSRF token obtained: {csrf_token[:20]}...")

        # Step 2: POST to /api/auth/callback/credentials (form-encoded)
        # This matches next-auth/react's signIn("credentials", {email, password}) behavior
        signin_url = f"{base_url}/api/auth/callback/credentials"
        signin_body = {
            "email": email,
            "password": password,
            "csrfToken": csrf_token,
            "callbackUrl": "/api/auth/session",
            "isSuperAdminLogin": "true",
        }

        signin_resp = jar.post_form(
            signin_url,
            body=signin_body,
            headers={"X-Auth-Return-Redirect": "1"},
            timeout=timeout,
        )
        result["steps"].append(
            f"POST /api/auth/callback/credentials: status={signin_resp['status']} "
            f"location={signin_resp['headers'].get('Location', 'N/A')}"
        )

        # Check response body for redirect URL (when X-Auth-Return-Redirect: 1)
        body_text = signin_resp["body"].decode("utf-8", errors="replace")
        if signin_resp["status"] == 200 and body_text.strip().startswith("{"):
            try:
                body_data = json.loads(body_text)
                location = body_data.get("url", "")
                if location:
                    result["steps"].append(f"  Redirect URL: {location}")

                # Check for session cookie
                session_cookies = jar.get_cookies()
                if session_cookies:
                    result["authenticated"] = True
                    result["cookies"] = session_cookies
                    result["steps"].append(f"  Session cookies: {list(session_cookies.keys())}")
                elif location:
                    # Follow the redirect URL manually
                    follow_resp = jar.get(f"{base_url}{location}", timeout=timeout)
                    result["steps"].append(
                        f"  Followed redirect: status={follow_resp['status']}"
                    )
                    session_cookies = jar.get_cookies()
                    if session_cookies:
                        result["authenticated"] = True
                        result["cookies"] = session_cookies
                        result["steps"].append(
                            f"  Session cookies after redirect: {list(session_cookies.keys())}"
                        )
            except json.JSONDecodeError:
                pass
        elif signin_resp["status"] in (302, 301, 307, 308):
            session_cookies = jar.get_cookies()
            if session_cookies:
                result["authenticated"] = True
                result["cookies"] = session_cookies
                result["steps"].append(f"  Session cookies: {list(session_cookies.keys())}")
            else:
                location = signin_resp["headers"].get("Location", "")
                result["error"] = f"Redirect but no session cookie (to {location})"
        else:
            result["error"] = f"Unexpected status: {signin_resp['status']}"
    except Exception as e:
        result["error"] = str(e)
        result["steps"].append(f"Exception: {e}")

    return result
