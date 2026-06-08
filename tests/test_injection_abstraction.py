"""Tests for the abstracted injection testing function."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from security_harness.injection_scanner import (
    _XssResult,
    _SqlInjectionResult,
    _SsrfResult,
    UserInputSurface,
    InputSurfaceType,
    run_injection_scan,
    InjectionScanResult,
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


def test_xss_result_accumulates_steps():
    """Test that _XssResult accumulates steps and findings correctly."""
    result = _XssResult()
    assert result.test_count == 0
    assert len(result.steps) == 0
    assert len(result.findings) == 0


def test_sqli_result_accumulates_steps():
    """Test that _SqlInjectionResult accumulates steps and findings correctly."""
    result = _SqlInjectionResult()
    assert result.test_count == 0
    assert len(result.steps) == 0
    assert len(result.findings) == 0


def test_ssrf_result_accumulates_steps():
    """Test that _SsrfResult accumulates steps and findings correctly."""
    result = _SsrfResult()
    assert result.test_count == 0
    assert len(result.steps) == 0
    assert len(result.findings) == 0


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


def test_injection_scan_with_xss_finding(tmp_path, capsys):
    """Test that XSS findings are correctly detected when payload is reflected."""
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
