"""Tests for the route-aware injection scanner improvements."""
import pytest
from security_harness.injection_scanner import (
    InjectionScanResult,
    UserInputSurface,
    InputSurfaceType,
    build_user_input_surfaces_from_smoke,
    run_injection_scan,
    _test_xss,
    _test_sqli,
    _auth_login,
)
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import json


class TestUserInputSurface:
    """Test the UserInputSurface dataclass."""

    def test_create_get_surface(self):
        surface = UserInputSurface(
            id="test-get",
            url="http://localhost:3000/api/test",
            type=InputSurfaceType.QUERY_PARAM,
            method="GET",
            parameters=["q", "filter"],
            confidence="high",
        )
        assert surface.id == "test-get"
        assert surface.type == InputSurfaceType.QUERY_PARAM
        assert surface.parameters == ["q", "filter"]

    def test_create_post_surface(self):
        surface = UserInputSurface(
            id="test-post",
            url="http://localhost:3000/api/apply",
            type=InputSurfaceType.BODY_JSON,
            method="POST",
            parameters=["name", "email", "description"],
            confidence="high",
        )
        assert surface.method == "POST"
        assert surface.type == InputSurfaceType.BODY_JSON


class TestSurfaceDiscovery:
    """Test surface discovery from smoke scan results."""

    def test_discover_query_param_surfaces(self):
        """Discover surfaces from GET requests with query params."""
        smoke_steps = [
            {
                "name": "get-search",
                "request": {
                    "method": "GET",
                    "url": "http://localhost:3000/?q=test",
                    "body": None,
                },
                "status": 200,
                "bodyBytes": 1234,
            }
        ]
        surfaces = build_user_input_surfaces_from_smoke(smoke_steps)
        assert len(surfaces) >= 1
        assert any(s.type == InputSurfaceType.QUERY_PARAM for s in surfaces)

    def test_discover_post_surfaces(self):
        """Discover POST surfaces from smoke scan results."""
        smoke_steps = [
            {
                "name": "post-login",
                "request": {
                    "method": "POST",
                    "url": "http://localhost:3000/api/auth/signin",
                    "body": '{"email":"test@test.com","password":"test"}',
                },
                "status": 302,
                "bodyBytes": 0,
            }
        ]
        surfaces = build_user_input_surfaces_from_smoke(smoke_steps)
        assert any(s.type == InputSurfaceType.BODY_JSON for s in surfaces)

    def test_discover_form_surfaces(self):
        """Discover form surfaces from HTML responses."""
        smoke_steps = [
            {
                "name": "get-form",
                "request": {
                    "method": "GET",
                    "url": "http://localhost:3000/apply",
                    "body": None,
                },
                "status": 200,
                "bodyBytes": b'<form action="/api/apply" method="POST"><input name="name"><input name="email"><button>Submit</button></form>',
            }
        ]
        surfaces = build_user_input_surfaces_from_smoke(smoke_steps)
        assert len(surfaces) >= 1


class TestInjectionWithSurfaces:
    """Test injection scanning using discovered surfaces."""

    def test_xss_on_query_param(self):
        """Test XSS on a discovered query parameter."""
        # This test will be implemented after the feature is developed
        # For now, we're setting up the test structure
        pass

    def test_sqli_on_form_field(self):
        """Test SQLi on a discovered form field."""
        pass

    def test_ssrf_on_body_param(self):
        """Test SSRF on a body parameter that accepts URLs."""
        pass


class TestInjectionScanIntegration:
    """Integration tests for the improved injection scanner."""

    def test_injection_scan_with_surfaces(self, tmp_path):
        """Test that injection scan works with surface-based scanning."""
        config_path = tmp_path / "target.yaml"
        config_path.write_text("""
schemaVersion: web-target/v1
id: test-surface
name: Test Surface
environment: local
baseUrl: http://localhost:3000
allowedHosts:
  - 127.0.0.1
  - localhost
scope:
  includePaths:
    - /api/auth/signin
    - /api/auth/session
    - /api/auth/csrf
    - /dashboard
    - /
    - /apply
    - /about
  maxRequests: 10
  maxRuntimeSeconds: 60
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
""")
        result = run_injection_scan(config_path, str(tmp_path / "runs"))
        assert result.success is True
        assert result.run_id is not None
        assert result.xss_tests >= 0
        assert result.sqli_tests >= 0


class TestAuthLogin:
    """Test auth login extraction."""

    def test_auth_login_extracts_cookies_from_302(self):
        """Login 302 with Set-Cookie returns cookies."""
        class LoginHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""
                if b"username=admin" in body and b"password=admin123" in body:
                    self.send_response(302)
                    self.send_header("Location", "/dashboard")
                    self.send_header(
                        "Set-Cookie",
                        "sessionid=abc123; Path=/; HttpOnly; Secure",
                    )
                    self.end_headers()
                else:
                    self.send_response(401)
                    self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), LoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            base_url = f"http://127.0.0.1:{server.server_port}"
            auth = {
                "login_url": "/api/auth/signin",
                "username": "admin",
                "password": "admin123",
                "cookie_name": "sessionid",
                "protected_paths": ["/dashboard"],
            }

            result = _auth_login(base_url, auth, 5.0)

            assert result.success is True
            assert result.cookie_name == "sessionid"
            assert "sessionid" in result.cookies
            assert result.cookies["sessionid"] == "abc123"

        finally:
            server.shutdown()
            thread.join(timeout=5)

    def test_auth_login_returns_empty_on_401(self):
        """Login 401 returns no cookies and a warning."""
        class LoginHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""
                self.send_response(401)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), LoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            base_url = f"http://127.0.0.1:{server.server_port}"
            auth = {
                "login_url": "/api/auth/signin",
                "username": "admin",
                "password": "wrong",
                "cookie_name": "sessionid",
                "protected_paths": ["/dashboard"],
            }

            result = _auth_login(base_url, auth, 5.0)

            assert result.success is True
            assert result.cookies == {}
            assert len(result.warnings) >= 1
            assert "auth" in result.warnings[0].lower()

        finally:
            server.shutdown()
            thread.join(timeout=5)

    def test_auth_scan_uses_cookie_on_dashboard(self, tmp_path):
        """Injection scan uses auth cookie when targeting protected paths."""
        seen_auth_paths: list[str] = []

        class ReflectingAuthHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen_auth_paths.append(self.path)
                if "/dashboard" in self.path and "sessionid=" in (self.headers.get("Cookie", "")):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"<html>Dashboard</html>")
                else:
                    self.send_response(307)
                    self.send_header("Location", "/login")
                    self.end_headers()

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

            # Must have a login step recorded
            steps = scan_doc.get("steps", [])
            login_steps = [s for s in steps if "auth-login" in s.get("name", "")]
            assert len(login_steps) >= 1, "No login step recorded"

        finally:
            server.shutdown()
            thread.join(timeout=5)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
