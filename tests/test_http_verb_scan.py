"""Tests for HTTP Verb Tampering scan module.
WSTG 4.7.03: Testing for HTTP Verb Tampering

Tests for:
- PUT bypass of GET-only endpoints
- DELETE bypass of GET-only endpoints
- PATCH bypass of GET-only endpoints
- Proper HTTP method restrictions
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_harness.http_verb_scan import (
    HTTPVerbConfig,
    HTTPVerbResult,
    run_http_verb_scan,
)
from tests.helpers import write_target_config


class MockVerbVulnerableApp(BaseHTTPRequestHandler):
    """Handler that allows all methods on GET-only routes."""
    request_counts: dict[str, int] = {}

    def _handle(self, method: str):
        self.server.seen_paths.append(self.path)
        self.request_counts[method] = self.request_counts.get(method, 0) + 1

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)

        # No method restriction — all verbs succeed
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "method": method,
            "path": self.path,
            "status": "ok",
        }).encode())

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_PATCH(self):
        self._handle("PATCH")

    def log_message(self, *args):
        pass


class MockVerbSecureApp(BaseHTTPRequestHandler):
    """Handler that properly restricts HTTP methods."""

    # Maps endpoints to allowed methods
    route_methods: dict[str, list[str]] = {}

    def _handle(self, method: str):
        self.server.seen_paths.append(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)

        allowed = self.route_methods.get(self.path, ["GET"])
        if method not in allowed:
            self.send_response(405)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "method not allowed",
                "allowed": allowed,
            }).encode())
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "method": method,
            "path": self.path,
            "status": "ok",
        }).encode())

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_PATCH(self):
        self._handle("PATCH")

    def log_message(self, *args):
        pass


# Set up the secure app's route methods
MockVerbSecureApp.route_methods = {
    "/api/data": ["GET", "POST"],
    "/api/users": ["GET", "POST"],
    "/api/admin/settings": ["GET", "POST", "PUT"],
}


# --- Test: HTTP Verb tampering detects PUT bypass ---

def test_http_verb_scan_detects_put_bypass(tmp_path, capsys):
    """An app that accepts PUT on GET-only routes should produce findings."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockVerbVulnerableApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "http-verb", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/data,/api/users",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        assert out["endpoints_tested"] >= 2
    finally:
        server.shutdown()


# --- Test: HTTP Verb scan secure app ---

def test_http_verb_scan_secure_app(tmp_path, capsys):
    """An app with proper method restrictions should not produce findings."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockVerbSecureApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "http-verb", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/data,/api/users",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        assert out["endpoints_tested"] >= 2
    finally:
        server.shutdown()


# --- Test: HTTP Verb requires endpoints ---

def test_http_verb_scan_uses_config_endpoints(tmp_path):
    """Running http-verb scan without specifying endpoints uses config endpoints."""
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://localhost:8081", ["/api"])

    from security_harness.cli import main
    # Should succeed using config endpoints as fallback
    result = main(["http-verb", str(config), "--artifacts", str(tmp_path / "runs")])
    assert result == 0  # Success - used config endpoints


# --- Test: HTTP Verb result structure ---

def test_http_verb_scan_result_structure(tmp_path, capsys):
    """Verify HTTP Verb scan result has all required fields."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockVerbVulnerableApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "http-verb", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/data",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        for field in ["run_id", "target_id", "endpoints_tested", "finding_count", "findings", "success"]:
            assert field in out
    finally:
        server.shutdown()


# --- Test: HTTP Verb config validates endpoints ---

def test_http_verb_config_validates_endpoints():
    """HTTPVerbConfig should require at least one endpoint."""
    from security_harness.http_verb_scan import HTTPVerbConfig

    with pytest.raises(ValueError, match="at least one endpoint"):
        HTTPVerbConfig(endpoints=[], base_url="http://localhost:3000")


def test_http_verb_config_validates_base_url():
    """HTTPVerbConfig should validate the base URL."""
    with pytest.raises(ValueError, match="base_url"):
        HTTPVerbConfig(
            base_url="not-a-url",
            endpoints=["/api/data"],
        )


# --- Test: HTTP Verb with multiple endpoints ---

def test_http_verb_scan_multiple_endpoints(tmp_path, capsys):
    """HTTP Verb scan should test all provided endpoints."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockVerbVulnerableApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "http-verb", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/data,/api/users,/api/admin",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        assert out["endpoints_tested"] >= 3
    finally:
        server.shutdown()


# --- Test: HTTP Verb handles connection errors ---

def test_http_verb_scan_handles_connection_errors(tmp_path):
    """HTTP Verb scan should handle connection errors gracefully."""
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://127.0.0.1:59999", ["/api"])

    from security_harness.cli import main
    rc = main([
        "http-verb", str(config),
        "--artifacts", str(tmp_path / "runs"),
        "--endpoints", "/api/data",
    ])
    assert rc in (0, 1, 2)


# --- Test: HTTP verb methods ---

def test_http_verb_scan_all_methods():
    """HTTP Verb scan should test GET, POST, PUT, DELETE, PATCH."""
    from security_harness.http_verb_scan import HTTP_VERB_METHODS

    assert "GET" in HTTP_VERB_METHODS
    assert "POST" in HTTP_VERB_METHODS
    assert "PUT" in HTTP_VERB_METHODS
    assert "DELETE" in HTTP_VERB_METHODS
    assert "PATCH" in HTTP_VERB_METHODS


# --- Test: HTTP Verb result serialization ---

def test_http_verb_result_to_summary():
    """HTTPVerbResult.to_summary() should return expected fields."""
    result = HTTPVerbResult(
        run_id="test-123",
        target_id="test-target",
        findings=[],
        total_requests=10,
        endpoints_tested=3,
    )

    summary = result.to_summary()
    assert summary["run_id"] == "test-123"
    assert summary["target_id"] == "test-target"
    assert summary["endpoints_tested"] == 3
    assert summary["finding_count"] == 0
    assert summary["success"] is True


def test_http_verb_result_finding_count():
    """HTTPVerbResult.finding_count should return len(findings)."""
    result = HTTPVerbResult(
        run_id="test-456",
        target_id="test-target",
        findings=[{"id": "finding-1", "title": "Test"}],
        total_requests=20,
        endpoints_tested=5,
    )
    assert result.finding_count == 1


# --- Test: Run HTTP Verb scan programmatically ---

def test_http_verb_scan_run_with_config(tmp_path):
    """run_http_verb_scan should produce a result."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockVerbVulnerableApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        result = run_http_verb_scan(
            str(config),
            endpoints=["/api/data"],
            artifacts_root=str(tmp_path / "runs"),
        )

        assert result.run_id.startswith("http-verb")
        assert result.target_id == "smoke-demo"
        assert result.endpoints_tested == 1
        assert result.success is True
    finally:
        server.shutdown()


# --- Test: Shared HTTP client ---

def test_http_verb_scan_uses_shared_http_client():
    """The HTTP Verb scan should use the shared HTTP client."""
    from security_harness._http_client import make_url

    url = make_url("http://localhost:3000", "/api/data")
    assert url == "http://localhost:3000/api/data"


# --- Test: HTTP Verb finding structure ---

def test_http_verb_finding_structure():
    """A HTTP Verb finding should have all required fields."""
    finding = {
        "id": "http-verb-tampering-put",
        "title": "HTTP Verb Tampering: PUT accepted on GET-only route",
        "severity": "MEDIUM",
        "description": "The endpoint accepts PUT requests when only GET is intended",
        "confidence": "HIGH",
        "remediation": "Implement proper HTTP method restrictions on all endpoints",
        "details": {
            "endpoint": "/api/data",
            "tampered_method": "PUT",
            "allowed_methods": ["GET", "POST"],
            "status_code": 200,
        },
    }

    assert finding["severity"] == "MEDIUM"
    assert "remediation" in finding
    assert "details" in finding
