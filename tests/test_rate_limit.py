"""Tests for rate limit detection."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_harness.rate_limit import RateLimitConfig, run_rate_limit_scan
from tests.helpers import write_target_config


class RateLimitHandler(BaseHTTPRequestHandler):
    """Handler that simulates rate limiting after a burst."""
    request_count: int = 0

    def do_GET(self):
        self.server.seen_paths.append(self.path)
        RateLimitHandler.request_count += 1
        count = RateLimitHandler.request_count

        if count <= 5:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        elif count <= 10:
            self.send_response(429)
            self.send_header("Retry-After", "10")
            self.end_headers()
            self.wfile.write(b'{"error":"rate limited"}')
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"recovered")

    def do_POST(self):
        self.server.seen_paths.append(self.path)
        RateLimitHandler.request_count += 1
        self.server.seen_paths.append(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)

        if RateLimitHandler.request_count <= 5:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(429)
            self.send_header("Retry-After", "5")
            self.end_headers()
            self.wfile.write(b'{"error":"rate limited"}')

    def log_message(self, *args):
        pass


class NoRateLimitHandler(BaseHTTPRequestHandler):
    """Handler with no rate limiting."""
    request_count: int = 0

    def do_GET(self):
        self.server.seen_paths.append(self.path)
        NoRateLimitHandler.request_count += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok always")

    def do_POST(self):
        self.server.seen_paths.append(self.path)
        NoRateLimitHandler.request_count += 1
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok always")

    def log_message(self, *args):
        pass


def test_rate_limit_scan_detects_rate_limiting(tmp_path, capsys):
    """A server that rate limits should produce findings about rate limiting."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), RateLimitHandler)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api", "/health"])

        from security_harness.cli import main
        rc = main([
            "rate-limit", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--burst-size", "5",
            "--delay-ms", "10",
            "--endpoints", "/api,/health",
        ])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is True
        assert "run_id" in out
        assert "endpoint_count" in out
        assert "total_requests" in out
    finally:
        server.shutdown()
        thread = None


def test_rate_limit_scan_result_structure(tmp_path, capsys):
    """Verify scan result has all required fields."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), NoRateLimitHandler)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "rate-limit", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--burst-size", "3",
            "--endpoints", "/api",
        ])

        out = json.loads(capsys.readouterr().out)
        for field in ["run_id", "target_id", "endpoint_count", "total_requests", "finding_count"]:
            assert field in out
    finally:
        server.shutdown()
        thread = None


def test_rate_limit_config_can_be_constructed():
    """Verify RateLimitConfig dataclass."""
    config = RateLimitConfig(
        burst_size=20,
        delay_ms=50,
        endpoints=["/login", "/signup"],
        login_url="/auth/login",
        signup_url="/register",
    )
    assert config.burst_size == 20
    assert config.delay_ms == 50
    assert config.endpoints == ["/login", "/signup"]
    assert config.login_url == "/auth/login"
    assert config.signup_url == "/register"
