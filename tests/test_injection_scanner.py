"""Tests for the injection scanner (XSS, SQLi, SSRF)."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_harness.injection_scanner import (
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    SSRF_ENDPOINTS,
    InjectionScanResult,
    run_injection_scan,
)
from tests.helpers import write_target_config, start_server


class InjectionHandler(BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, dict[str, str], bytes]] = {}

    def do_GET(self):
        self.server.seen_paths.append(self.path)
        status, headers, body = self.routes.get(self.path, (200, {}, b"ok"))
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
        status, headers, resp = self.routes.get(self.path, (200, {}, b"ok"))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *args):
        pass


def test_xss_payloads_are_defined():
    """Verify XSS payload definitions exist and have required fields."""
    assert len(XSS_PAYLOADS) > 0
    for p in XSS_PAYLOADS:
        assert p.id
        assert p.category
        assert p.payload
        # Payloads should be simple strings, not actual exploit code that modifies state
        assert "<" in p.payload or "onerror" in p.payload or "script" in p.payload.lower()


def test_sqli_payloads_are_defined():
    """Verify SQLi payload definitions exist."""
    assert len(SQLI_PAYLOADS) > 0
    for p in SQLI_PAYLOADS:
        assert p.id
        p.type  # category is also accessible as type for compatibility
        assert p.payload


def test_ssrf_endpoints_are_defined():
    """Verify SSRF probe definitions exist."""
    assert len(SSRF_ENDPOINTS) > 0
    for p in SSRF_ENDPOINTS:
        assert p.id
        assert p.url


def test_injection_scan_cli_with_healthy_server(tmp_path, capsys):
    """Run injection-scan CLI and verify basic result structure."""
    server, thread = start_server({"/": (200, {}, b"ok")})
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/"])

        from security_harness.cli import main
        rc = main(["injection-scan", str(config), "--artifacts", str(tmp_path / "runs")])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is True
        assert "run_id" in out
        assert "finding_count" in out
        assert "artifacts" in out

        run_dir = Path(out["run_dir"])
        assert (run_dir / "injection-scan.json").exists()
        assert (run_dir / "report.md").exists()
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_injection_scan_result_has_summary(tmp_path, capsys):
    """Verify scan result has correct summary fields."""
    server, thread = start_server({"/": (200, {}, b"ok")})
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/"])

        from security_harness.cli import main
        main(["injection-scan", str(config), "--artifacts", str(tmp_path / "runs")])

        out = json.loads(capsys.readouterr().out)
        for field in ["run_id", "target_id", "xss_tests", "sqli_tests", "ssrf_tests", "finding_count"]:
            assert field in out, f"Missing field: {field}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
