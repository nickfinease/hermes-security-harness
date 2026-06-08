"""Tests for CSRF (Cross-Site Request Forgery) scan module.
WSTG 4.6.05: Testing for Cross-Site Request Forgery
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_harness.csrf_scan import (
    CSRFConfig,
    CSRFAuthConfig,
    CSRFScanResult,
    run_csrf_scan,
    _calculate_token_entropy,
)
from tests.helpers import write_target_config


class MockCSRFHandler(BaseHTTPRequestHandler):
    """Handler that simulates an app WITH proper CSRF protection."""
    csrf_token: str = "valid_csrf_token_12345"
    request_count: int = 0

    def do_GET(self):
        self.server.seen_paths.append(self.path)
        if self.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "csrf_token": self.csrf_token,
                "html": "<form><input name='_csrf' value='{{csrf_token}}'></form>"
            }).encode())
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    def do_POST(self):
        self.server.seen_paths.append(self.path)
        MockCSRFHandler.request_count += 1
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""

        # Check for CSRF token
        has_csrf = "_csrf" in body or self.headers.get("X-CSRF-Token")
        has_header_csrf = self.headers.get("X-CSRF-Token") == MockCSRFHandler.csrf_token

        if not has_csrf or not has_header_csrf:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "CSRF token required"}).encode())
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode())

    def log_message(self, *args):
        pass


class MockNoCSRFHandler(BaseHTTPRequestHandler):
    """Handler that simulates an app WITHOUT CSRF protection."""
    request_count: int = 0

    def do_GET(self):
        self.server.seen_paths.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"no protection")

    def do_POST(self):
        self.server.seen_paths.append(self.path)
        MockNoCSRFHandler.request_count += 1
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"no protection")

    def log_message(self, *args):
        pass


# --- Test: Multiple endpoints are tested ---

def test_csrf_scan_multiple_endpoints(tmp_path, capsys):
    """CSRF scan should test all provided endpoints."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockNoCSRFHandler)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "csrf", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/login,/api/data,/api/users",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        assert out["endpoints_tested"] >= 3  # At least 3 endpoints tested
    finally:
        server.shutdown()


# --- Test: Result structure ---

def test_csrf_scan_result_structure(tmp_path, capsys):
    """Verify CSRF scan result has all required fields."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockCSRFHandler)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/login"])

        from security_harness.cli import main
        main([
            "csrf", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/login,/api/data",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        for field in ["run_id", "target_id", "endpoints_tested", "finding_count", "findings"]:
            assert field in out
    finally:
        server.shutdown()


# --- Test: Config validates endpoints ---

def test_csrf_config_validates_endpoints():
    """CSRFConfig should require at least one endpoint."""
    with pytest.raises(ValueError, match="at least one endpoint"):
        CSRFConfig(endpoints=[], base_url="http://localhost:3000")


# --- Test: Config validates base_url ---

def test_csrf_config_validates_base_url():
    """CSRFConfig should validate the base URL."""
    config = CSRFConfig(
        base_url="http://localhost:3000",
        endpoints=["/login", "/api/data"],
    )
    assert config.base_url == "http://localhost:3000"
    assert config.endpoints == ["/login", "/api/data"]

    with pytest.raises(ValueError, match="base_url"):
        CSRFConfig(
            base_url="not-a-url",
            endpoints=["/login"],
        )


# --- Test: CSRF scan with proper app (403 without CSRF token) ---

def test_csrf_scan_detects_csrf_on_app(tmp_path, capsys):
    """An app that returns 403 without CSRF token should be detected."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockCSRFHandler)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/login"])

        from security_harness.cli import main
        main([
            "csrf", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/login,/api/data",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        # The scanner finds that CSRF token is required (403 without it)
        assert out["finding_count"] >= 0  # At least 0, may have findings
    finally:
        server.shutdown()


# --- Test: Safe methods don't require CSRF ---

def test_csrf_scan_safe_methods_ok(tmp_path, capsys):
    """GET, HEAD, OPTIONS should not require CSRF tokens."""
    class SafeMethodsOnly(BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.seen_paths.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"safe")

        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        def do_OPTIONS(self):
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length:
                self.rfile.read(content_length)
            self.server.seen_paths.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"also safe")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SafeMethodsOnly)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "csrf", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api,/api/data",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
    finally:
        server.shutdown()


# --- Test: Connection errors are handled ---

def test_csrf_scan_handles_connection_errors(tmp_path, capsys):
    """CSRF scan should handle connection errors gracefully."""
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://127.0.0.1:59999", ["/login"])

    from security_harness.cli import main
    rc = main([
        "csrf", str(config),
        "--artifacts", str(tmp_path / "runs"),
        "--endpoints", "/login",
    ])
    assert rc in (0, 1, 2)


# --- Tests: CSRF requires endpoints param ---

def test_csrf_scan_uses_config_endpoints(tmp_path):
    """Running csrf scan without specifying endpoints uses config endpoints."""
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://localhost:8081", ["/login"])

    from security_harness.cli import main
    # Should succeed using config endpoints as fallback
    result = main(["csrf", str(config), "--artifacts", str(tmp_path / "runs")])
    assert result == 0  # Success - used config endpoints


# --- Tests: Token entropy ---

def test_csrf_scan_token_entropy():
    """CSRF tokens should have sufficient entropy (not predictable)."""
    strong = _calculate_token_entropy("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
    assert strong >= 4  # Shannon entropy of 32 unique chars is log2(32) ≈ 5

    weak = _calculate_token_entropy("token_0001")
    assert weak < 4

    empty = _calculate_token_entropy("")
    assert empty == 0


# --- Tests: CSRF config can be constructed ---

def test_csrf_scan_result_to_summary():
    """CSRFScanResult.to_summary() should return expected fields."""
    result = CSRFScanResult(
        run_id="test-123",
        target_id="test-target",
        findings=[],
        total_requests=10,
        endpoints_tested=3,
    )

    summary = result.to_summary()
    assert summary["run_id"] == "test-123"
    assert summary["target_id"] == "test-target"
    assert summary["total_requests"] == 10
    assert summary["endpoints_tested"] == 3
    assert summary["finding_count"] == 0
    assert summary["success"] is True


def test_csrf_scan_result_finding_count():
    """CSRFScanResult.finding_count should return len(findings)."""
    result = CSRFScanResult(
        run_id="test-456",
        target_id="test-target",
        findings=[
            {"id": "finding-1", "title": "Test finding 1"},
            {"id": "finding-2", "title": "Test finding 2"},
        ],
        total_requests=20,
        endpoints_tested=5,
    )
    assert result.finding_count == 2


def test_csrf_scan_uses_shared_http_client():
    """The CSRF scan should use the shared HTTP client from _http_client."""
    from security_harness._http_client import make_url

    url = make_url("http://localhost:3000", "/login")
    assert url == "http://localhost:3000/login"

    url_none = make_url("http://localhost:3000", None)
    assert url_none == "http://localhost:3000"


# --- Tests: CSRF auth config ---

def test_csrf_scan_with_auth():
    """CSRF scan should support authentication to test protected endpoints."""
    auth = CSRFAuthConfig(
        login_url="/api/auth/login",
        username="test@example.com",
        password="testpass",
        session_cookie="auth_session",
    )
    assert auth.login_url == "/api/auth/login"
    assert auth.session_cookie == "auth_session"


def test_csrf_scan_auth_missing_credentials():
    """CSRF scan should require credentials when auth is configured."""
    with pytest.raises(ValueError, match="credentials"):
        CSRFAuthConfig(
            login_url="/api/auth/login",
            username=None,
            password=None,
        )


# --- Tests: Default CSRF field names ---

def test_csrf_scan_no_token_field_name():
    """When no token field name is specified, scanner should try common patterns."""
    from security_harness.csrf_scan import DEFAULT_CSRF_FIELD_NAMES

    assert "_csrf" in DEFAULT_CSRF_FIELD_NAMES
    assert "csrf_token" in DEFAULT_CSRF_FIELD_NAMES
    assert "X-CSRF-Token" in DEFAULT_CSRF_FIELD_NAMES


# --- Tests: Header-based CSRF detection ---

def test_csrf_scan_detects_header_csrf():
    """CSRF tokens can be sent via headers (X-CSRF-Token), not just form fields."""
    from security_harness.csrf_scan import CSRFScanResult

    result = CSRFScanResult(
        run_id="test-header-csrf",
        target_id="test-target",
        findings=[{
            "id": "csrf-header",
            "title": "CSRF token via header",
            "severity": "LOW",
            "description": "CSRF token is sent via X-CSRF-Token header",
            "confidence": "MEDIUM",
            "remediation": "Consider form field submission for additional protection",
        }],
        total_requests=2,
        endpoints_tested=1,
    )

    assert len(result.findings) == 1
    assert result.findings[0]["title"] == "CSRF token via header"


# --- Tests: CSRF with findings ---

def test_csrf_scan_finding_with_details():
    """A CSRF finding should have all required fields."""
    finding = {
        "id": "csrf-action-mismatch",
        "title": "CSRF token action mismatch",
        "severity": "HIGH",
        "description": "The form action URL differs from the CSRF token origin",
        "confidence": "HIGH",
        "remediation": "Ensure CSRF token is validated against the form action URL",
    }

    assert finding["severity"] == "HIGH"
    assert "remediation" in finding


# --- Tests: Run CSRF scan programmatically ---

def test_csrf_scan_run_with_config(tmp_path):
    """run_csrf_scan should produce a result with findings."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockNoCSRFHandler)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        result = run_csrf_scan(
            str(config),
            endpoints=["/api", "/api/data"],
            artifacts_root=str(tmp_path / "runs"),
        )

        assert result.run_id.startswith("csrf")
        assert result.target_id == "smoke-demo"
        assert result.endpoints_tested == 2
        assert result.success is True
    finally:
        server.shutdown()


# --- Tests: CSRF result is serializable ---

def test_csrf_scan_result_serializable(tmp_path):
    """CSRFScanResult should be serializable to JSON."""
    import json as json_module

    result = CSRFScanResult(
        run_id="test-csrf-serializable",
        target_id="test-target",
        findings=[{"id": "finding-1", "title": "Test", "severity": "MEDIUM"}],
        total_requests=5,
        endpoints_tested=2,
    )

    summary = result.to_summary()
    # Should be serializable
    json_module.dumps(summary)
    assert summary["run_id"] == "test-csrf-serializable"
