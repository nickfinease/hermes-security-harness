"""Tests for auth scan."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_harness.auth_scan import AuthConfig, run_auth_scan
from tests.helpers import write_target_config, start_server


class AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen_paths.append(self.path)
        auth_cookie = self.headers.get("Cookie") or ""
        if "/dashboard" in self.path or "/api/profile" in self.path:
            if "sessionid" in auth_cookie:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"user":"test"}')
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"error":"unauthorized"}')
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"page")

    def do_POST(self):
        self.server.seen_paths.append(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)

        if "/login" in self.path:
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly; SameSite=Strict")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def test_auth_scan_result_has_summary(tmp_path, capsys):
    server, thread = start_server({})
    try:
        server.seen_paths = []
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/login", "/dashboard", "/api/profile"])

        from security_harness.cli import main
        rc = main([
            "auth-scan", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--login-url", "/login",
            "--username", "testuser",
            "--password", "testpass",
            "--protected-paths", "/dashboard,/api/profile",
        ])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is True
        assert "run_id" in out
        assert "cookie_tests" in out
        assert "bypass_tests" in out
        assert "rate_tests" in out
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_auth_scan_detects_missing_security_headers(tmp_path, capsys):
    """When cookies lack Secure/HttpOnly/SameSite, report findings."""
    server, thread = start_server({})
    try:
        server.seen_paths = []

        class WeakAuthHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.server.seen_paths.append(self.path)
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length:
                    self.rfile.read(content_length)
                # Return cookies WITHOUT security flags
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Set-Cookie", "sessionid=abc123")  # No Secure/HttpOnly/SameSite
                self.end_headers()

            def do_GET(self):
                self.server.seen_paths.append(self.path)
                if "/dashboard" in self.path or "/api/profile" in self.path:
                    auth_cookie = self.headers.get("Cookie") or ""
                    if "sessionid=abc123" in auth_cookie:
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'{"user":"test"}')
                    else:
                        self.send_response(401)
                        self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()

            def log_message(self, *args):
                pass

        HandlerClass = WeakAuthHandler
        HandlerClass.routes = {}
        HandlerClass.seen_paths = []

        server2 = ThreadingHTTPServer(("127.0.0.1", 0), HandlerClass)
        server2.seen_paths = []
        thread2 = threading.Thread(target=server2.serve_forever, daemon=True)
        thread2.start()

        try:
            base_url = f"http://127.0.0.1:{server2.server_port}"
            config = tmp_path / "target2.yaml"
            write_target_config(config, base_url, ["/login", "/dashboard", "/api/profile"])

            from security_harness.cli import main
            main([
                "auth-scan", str(config),
                "--artifacts", str(tmp_path / "runs2"),
                "--login-url", "/login",
            ])

            out = json.loads(capsys.readouterr().out)
            # Should have findings about weak cookies
            assert out["success"] is True
        finally:
            server2.shutdown()
            thread2 = None
            for t in threading.enumerate():
                if t.name.startswith("ThreadingHTTP"):
                    t.join(timeout=5)
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_auth_config_creates_proper_auth_config():
    config = AuthConfig(
        login_url="/auth/login",
        username="alice",
        password="secret123",
        protected_paths=["/admin", "/dashboard"],
    )
    assert config.login_url == "/auth/login"
    assert config.username == "alice"
    assert config.password == "secret123"
    assert config.protected_paths == ["/admin", "/dashboard"]
    assert config.cookie_name == "sessionid"  # default
