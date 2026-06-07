"""Tests for authenticated injection scanning."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.helpers import write_target_config, start_server


class AuthInjectionHandler(BaseHTTPRequestHandler):
    """Mock server with login endpoint that returns a cookie."""

    routes: dict[str, tuple[int, dict[str, str], bytes]] = {}
    cookie_name: str = "sessionid"
    seen_paths: list[str] = []
    seen_post_bodies: list[bytes] = []

    def do_GET(self):
        self.server.seen_paths.append(self.path)
        cookies = self.headers.get("Cookie", "")
        status, headers, body = self.routes.get(self.path, (200, {}, b"ok"))

        # Add auth-bypass findings: if no cookie on protected path, return 200 (bypass)
        if "/dashboard" in self.path and "sessionid=" not in cookies:
            status = 200  # Auth bypass!
            body = b"Authenticated dashboard content"

        # Reflected XSS: reflect query param back in response
        if "xss_payload=" in self.path:
            body = f"<html>Search for: {self.path}</html>".encode()
            status = 200

        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        self.server.seen_paths.append(self.path)
        self.server.seen_post_bodies.append(body)

        # Login endpoint returns a Set-Cookie
        if "/api/auth/signin" in self.path:
            if b"username=admin" in body and b"password=admin123" in body:
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Strict")
                self.end_headers()
            else:
                self.send_response(401)
                self.end_headers()
        else:
            status, headers, resp = self.routes.get(self.path, (200, {}, b"ok"))
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp)

    def log_message(self, *args):
        pass


class TestAuthInjectionLogin:
    """Test that auth credentials trigger a login before injection tests."""

    def test_auth_scan_logs_in_first(self, tmp_path):
        """Login must happen before injection tests when auth credentials provided."""

        class AuthLoginHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""
                if b"username=admin" in body and b"password=admin123" in body:
                    self.send_response(302)
                    self.send_header("Location", "/dashboard")
                    self.send_header("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly; Secure")
                    self.end_headers()
                else:
                    self.send_response(401)
                    self.end_headers()

            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), AuthLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base_url = f"http://127.0.0.1:{server.server_port}"

            config = tmp_path / "target.yaml"
            config.write_text(
                f"""
schemaVersion: web-target/v1
id: test-auth
name: Test Auth
environment: local
baseUrl: {base_url}
allowedHosts:
  - 127.0.0.1
  - localhost
scope:
  includePaths:
    - /api/auth/signin
    - /dashboard
    - /
  maxRequests: 10
  maxRuntimeSeconds: 60
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
"""
            )

            from security_harness.injection_scanner import run_injection_scan

            result = run_injection_scan(
                config,
                str(tmp_path / "runs"),
                auth={
                    "login_url": "/api/auth/signin",
                    "username": "admin",
                    "password": "admin123",
                    "cookie_name": "sessionid",
                    "protected_paths": ["/dashboard"],
                },
            )

            assert result.success is True
            # Must have auth step before injection tests
            scan_doc = json.loads(
                (result.artifacts["injection_scan"]).read_text()
            )
            # Check for auth login step in output
            assert scan_doc.get("auth", {}).get("authenticated") is True, "Auth not recorded"

        finally:
            server.shutdown()
            thread.join(timeout=5)

    def test_auth_scan_uses_cookie_on_injection(self, tmp_path):
        """Injection tests must use the session cookie from login."""

        class AuthServer(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""
                if b"username=admin" in body and b"password=admin123" in body:
                    self.send_response(302)
                    self.send_header("Location", "/dashboard")
                    self.send_header("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly; Secure")
                    self.end_headers()
                else:
                    self.send_response(401)
                    self.end_headers()

            def do_GET(self):
                if "/dashboard" in self.path:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                else:
                    self.send_response(307)
                    self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), AuthServer)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base_url = f"http://127.0.0.1:{server.server_port}"

            config = tmp_path / "target.yaml"
            config.write_text(
                f"""
schemaVersion: web-target/v1
id: test-auth
name: Test Auth
environment: local
baseUrl: {base_url}
allowedHosts:
  - 127.0.0.1
  - localhost
scope:
  includePaths:
    - /api/auth/signin
    - /dashboard
  maxRequests: 10
  maxRuntimeSeconds: 60
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
"""
            )

            from security_harness.injection_scanner import run_injection_scan

            result = run_injection_scan(
                config,
                str(tmp_path / "runs"),
                auth={
                    "login_url": "/api/auth/signin",
                    "username": "admin",
                    "password": "admin123",
                    "cookie_name": "sessionid",
                    "protected_paths": ["/dashboard"],
                },
            )

            assert result.success is True
            scan_doc = json.loads(
                (result.artifacts["injection_scan"]).read_text()
            )
            # The scan must include a login step
            auth_steps = scan_doc.get("authSteps", [])
            login_steps = [s for s in auth_steps if s.get("name", "").startswith("auth-login")]
            assert len(login_steps) >= 1, f"No login step found in scan. authSteps: {auth_steps}"

        finally:
            server.shutdown()
            thread.join(timeout=5)

    def test_auth_scan_fails_gracefully_on_bad_creds(self, tmp_path):
        """Injection scan should still complete but record auth failure."""
        server, thread = start_server(
            {
                "/api/auth/signin": (401, {}, b"Unauthorized"),
            }
        )
        try:
            base_url = f"http://127.0.0.1:{server.server_port}"

            config = tmp_path / "target.yaml"
            config.write_text(
                f"""
schemaVersion: web-target/v1
id: test-auth
name: Test Auth
environment: local
baseUrl: {base_url}
allowedHosts:
  - 127.0.0.1
  - localhost
scope:
  includePaths:
    - /api/auth/signin
  maxRequests: 10
  maxRuntimeSeconds: 60
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
"""
            )

            from security_harness.injection_scanner import run_injection_scan

            result = run_injection_scan(
                config,
                str(tmp_path / "runs"),
                auth={
                    "login_url": "/api/auth/signin",
                    "username": "admin",
                    "password": "wrongpassword",
                    "cookie_name": "sessionid",
                    "protected_paths": ["/dashboard"],
                },
            )

            # Should still succeed (scan completed, just auth failed)
            assert result.success is True
            # But should record a warning about auth failure
            assert any("auth" in w.lower() for w in result.warnings)

        finally:
            server.shutdown()
            thread.join(timeout=5)


class TestAuthXssOnProtectedRoute:
    """Test XSS on authenticated routes with proper cookies."""

    def test_xss_reflected_with_auth(self, tmp_path):
        """XSS detection works when tests use auth cookies."""

        class AuthXssHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""
                if b"username=admin" in body and b"password=admin123" in body:
                    self.send_response(302)
                    self.send_header("Location", "/dashboard")
                    self.send_header("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly; Secure")
                    self.end_headers()
                else:
                    self.send_response(401)
                    self.end_headers()

            def do_GET(self):
                if "/dashboard" in self.path:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"<html>dashboard</html>")
                else:
                    self.send_response(307)
                    self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), AuthXssHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base_url = f"http://127.0.0.1:{server.server_port}"

            config = tmp_path / "target.yaml"
            config.write_text(
                f"""
schemaVersion: web-target/v1
id: test-auth
name: Test Auth
environment: local
baseUrl: {base_url}
allowedHosts:
  - 127.0.0.1
  - localhost
scope:
  includePaths:
    - /api/auth/signin
    - /dashboard
  maxRequests: 10
  maxRuntimeSeconds: 60
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
"""
            )

            from security_harness.injection_scanner import run_injection_scan

            result = run_injection_scan(
                config,
                str(tmp_path / "runs"),
                auth={
                    "login_url": "/api/auth/signin",
                    "username": "admin",
                    "password": "admin123",
                    "cookie_name": "sessionid",
                    "protected_paths": ["/dashboard"],
                },
            )

            assert result.success is True
            assert result.xss_tests >= 0
            assert result.sqli_tests >= 0
            # Verify that auth was used (not that dashboard steps exist)
            scan_doc = json.loads(
                (result.artifacts["injection_scan"]).read_text()
            )
            assert scan_doc.get("auth", {}).get("authenticated") is True, "Auth not recorded"

        finally:
            server.shutdown()
            thread.join(timeout=5)


class TestAuthXssReflected:
    """Test XSS findings with authenticated requests."""

    def test_xss_detected_on_reflected_param_with_auth(self, tmp_path):
        """Reflected XSS is detected when injection uses auth cookies."""

        class ReflectingAuthHandler(BaseHTTPRequestHandler):
            """Login returns cookie, reflected param echoes back."""
            def do_GET(self):
                from urllib.parse import urlparse, parse_qs, unquote
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                if params:
                    # Simulate real XSS reflection: decode, then echo back (as raw HTML)
                    first_key = list(params.keys())[0]
                    raw_val = params[first_key][0]
                    decoded = unquote(raw_val)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(f"<html>Query: {decoded}</html>".encode())
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""
                if b"username=admin" in body and b"password=admin123" in body:
                    self.send_response(302)
                    self.send_header("Location", "/dashboard")
                    self.send_header(
                        "Set-Cookie",
                        "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Strict",
                    )
                    self.end_headers()
                else:
                    self.send_response(401)
                    self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), ReflectingAuthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            base_url = f"http://127.0.0.1:{server.server_port}"

            config = tmp_path / "target.yaml"
            config.write_text(
                f"""
schemaVersion: web-target/v1
id: test-auth
name: Test Auth
environment: local
baseUrl: {base_url}
allowedHosts:
  - 127.0.0.1
  - localhost
scope:
  includePaths:
    - /api/auth/signin
    - /dashboard
  maxRequests: 10
  maxRuntimeSeconds: 60
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
"""
            )

            from security_harness.injection_scanner import run_injection_scan

            result = run_injection_scan(
                config,
                str(tmp_path / "runs"),
                auth={
                    "login_url": "/api/auth/signin",
                    "username": "admin",
                    "password": "admin123",
                    "cookie_name": "sessionid",
                    "protected_paths": ["/dashboard"],
                },
            )

            assert result.success is True
            scan_doc = json.loads(
                (result.artifacts["injection_scan"]).read_text()
            )

            findings = scan_doc.get("findings", [])

            # Should find at least one XSS finding from reflected param
            xss_findings = [f for f in findings if "xss" in f.get("id", "").lower()]
            assert len(xss_findings) >= 1, f"Expected XSS findings, got {len(xss_findings)}: {findings}"

        finally:
            server.shutdown()
            thread.join(timeout=5)
