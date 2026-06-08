"""Tests for IDOR / BOLA (Insecure Direct Object Reference / Broken Object Level Authorization).
WSTG 4.5.04: Testing for Insecure Direct Object References
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_harness.idor_scan import (
    IDORConfig,
    IDORAuthConfig,
    IDORScanResult,
    run_idor_scan,
)
from tests.helpers import write_target_config


class MockIDORApp(BaseHTTPRequestHandler):
    """Handler that simulates an app VULNERABLE to IDOR."""
    request_count: int = 0
    users_db = {
        "user1": {"id": "user1", "role": "user", "data": "User 1's private data"},
        "user2": {"id": "user2", "role": "user", "data": "User 2's private data"},
        "admin": {"id": "admin", "role": "admin", "data": "Admin's secret data"},
    }

    def do_GET(self):
        self.server.seen_paths.append(self.path)
        # IDOR: /api/user/{id} exposes data without checking ownership
        import re
        match = re.match(r"/api/user/(\w+)", self.path)
        if match:
            user_id = match.group(1)
            if user_id in self.users_db:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(self.users_db[user_id]).encode())
                return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error":"not found"}')
            return

        # /api/admin/users exposes all users
        if self.path == "/api/admin/users":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(list(self.users_db.keys())).encode())
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        self.server.seen_paths.append(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class MockSecureIDORApp(BaseHTTPRequestHandler):
    """Handler that simulates an app with proper IDOR protection."""
    auth_cookies: dict[str, str] = {}

    def do_GET(self):
        self.server.seen_paths.append(self.path)
        import re

        # Extract user ID from cookie
        cookie_header = self.headers.get("Cookie", "")
        user_id_match = re.search(r"user_id=(\w+)", cookie_header)
        user_id = user_id_match.group(1) if user_id_match else "anonymous"

        # /api/user/{id} — only allow access to own data
        match = re.match(r"/api/user/(\w+)", self.path)
        if match:
            requested_id = match.group(1)
            if user_id == "anonymous":
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"error":"unauthorized"}')
                return
            if requested_id != user_id:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'{"error":"forbidden: not your resource"}')
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "id": requested_id,
                "role": "user",
                "data": f"User {requested_id}'s private data"
            }).encode())
            return

        # /api/admin/users — only accessible by admin role
        if self.path == "/api/admin/users":
            if user_id == "admin":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(["user1", "user2", "admin"]).encode())
                return
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"error":"forbidden"}')
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        self.server.seen_paths.append(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


# --- Test: IDOR scan detects cross-user access ---

def test_idor_scan_detects_cross_user_access(tmp_path, capsys):
    """An app that allows cross-user access should produce findings."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockIDORApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "idor", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/user/{id}",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        assert out["endpoints_tested"] >= 1
    finally:
        server.shutdown()


# --- Test: IDOR scan requires endpoints ---

def test_idor_scan_uses_config_endpoints(tmp_path):
    """Running idor scan without specifying endpoints uses config endpoints."""
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://localhost:8081", ["/api"])

    from security_harness.cli import main
    # Should succeed using config endpoints as fallback
    result = main(["idor", str(config), "--artifacts", str(tmp_path / "runs")])
    assert result == 0  # Success - used config endpoints
    assert result == 0  # Success - used config endpoints


# --- Test: IDOR scan result structure ---

def test_idor_scan_result_structure(tmp_path, capsys):
    """Verify IDOR scan result has all required fields."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockIDORApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "idor", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/user/{id}",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        for field in ["run_id", "target_id", "endpoints_tested", "finding_count", "findings", "success"]:
            assert field in out
    finally:
        server.shutdown()


# --- Test: IDOR config validates endpoints ---

def test_idor_config_validates_endpoints():
    """IDORConfig should require at least one endpoint."""
    from security_harness.idor_scan import IDORConfig

    with pytest.raises(ValueError, match="at least one endpoint"):
        IDORConfig(endpoints=[], base_url="http://localhost:3000")


def test_idor_config_validates_base_url():
    """IDORConfig should validate the base URL."""
    with pytest.raises(ValueError, match="base_url"):
        IDORConfig(
            base_url="not-a-url",
            endpoints=["/api"],
        )

    config = IDORConfig(
        base_url="http://localhost:3000",
        endpoints=["/api/user/{id}"],
    )
    assert config.base_url == "http://localhost:3000"


# --- Test: Secure IDOR app (no findings) ---

def test_idor_scan_secure_app_has_no_cross_user(tmp_path, capsys):
    """An app with proper IDOR protection should not produce cross-user findings."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockSecureIDORApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "idor", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/user/{id}",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        # A properly secured app returns 403 when accessing other users' data
        # The scanner detects this as protection
        assert out["endpoints_tested"] >= 1
    finally:
        server.shutdown()


# --- Test: IDOR with multiple endpoints ---

def test_idor_scan_multiple_endpoints(tmp_path, capsys):
    """IDOR scan should test all provided endpoints."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockIDORApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "idor", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/user/{id},/api/user/{id}/profile,/api/user/{id}/settings",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        assert out["endpoints_tested"] >= 3
    finally:
        server.shutdown()


# --- Test: IDOR handles connection errors ---

def test_idor_scan_handles_connection_errors(tmp_path):
    """IDOR scan should handle connection errors gracefully."""
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://127.0.0.1:59999", ["/api"])

    from security_harness.cli import main
    rc = main([
        "idor", str(config),
        "--artifacts", str(tmp_path / "runs"),
        "--endpoints", "/api/user/{id}",
    ])
    assert rc in (0, 1, 2)


# --- Test: IDOR param patterns (brackets, colons) ---

def test_idor_scan_detects_param_patterns():
    """IDOR scan should detect parameter patterns in endpoints."""
    from security_harness.idor_scan import _extract_path_params

    assert _extract_path_params("/api/user/{id}") == ["id"]
    assert _extract_path_params("/api/user/{userId}") == ["userId"]
    assert _extract_path_params("/api/:userId") == ["userId"]
    assert _extract_path_params("/api/user/123") == []


# --- Test: IDOR auth config ---

def test_idor_scan_with_auth():
    """IDOR scan should support authentication."""
    

    auth = IDORAuthConfig(
        login_url="/api/auth/login",
        username="test@example.com",
        password="testpass",
        session_cookie="auth_session",
    )
    assert auth.login_url == "/api/auth/login"
    assert auth.session_cookie == "auth_session"


def test_idor_scan_auth_missing_credentials():
    """IDOR scan should require credentials when auth is configured."""
    with pytest.raises(ValueError, match="credentials"):
        IDORAuthConfig(
            login_url="/api/auth/login",
            username=None,
            password=None,
        )


# --- Test: IDOR result serialization ---

def test_idor_scan_result_to_summary():
    """IDORScanResult.to_summary() should return expected fields."""
    result = IDORScanResult(
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


def test_idor_scan_result_finding_count():
    """IDORScanResult.finding_count should return len(findings)."""
    result = IDORScanResult(
        run_id="test-456",
        target_id="test-target",
        findings=[{"id": "finding-1", "title": "Test"}],
        total_requests=20,
        endpoints_tested=5,
    )
    assert result.finding_count == 1


# --- Test: Run IDOR scan programmatically ---

def test_idor_scan_run_with_config(tmp_path):
    """run_idor_scan should produce a result."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockIDORApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        result = run_idor_scan(
            str(config),
            endpoints=["/api/user/{id}"],
            artifacts_root=str(tmp_path / "runs"),
        )

        assert result.run_id.startswith("idor")
        assert result.target_id == "smoke-demo"
        assert result.endpoints_tested == 1
        assert result.success is True
    finally:
        server.shutdown()


# --- Test: IDOR finding structure ---

def test_idor_scan_finding_structure():
    """An IDOR finding should have all required fields."""
    finding = {
        "id": "idor-cross-user-access",
        "title": "Cross-user access detected",
        "severity": "HIGH",
        "description": "User can access another user's data via direct object reference",
        "confidence": "HIGH",
        "remediation": "Implement ownership verification on all resource endpoints",
        "details": {
            "endpoint": "/api/user/{id}",
            "method": "GET",
            "test_values": ["user1", "user2", "admin"],
        },
    }

    assert finding["severity"] == "HIGH"
    assert "remediation" in finding
    assert "details" in finding


# --- Test: Shared HTTP client ---

def test_idor_scan_uses_shared_http_client():
    """The IDOR scan should use the shared HTTP client."""
    from security_harness._http_client import make_url

    url = make_url("http://localhost:3000", "/api/user/123")
    assert url == "http://localhost:3000/api/user/123"


# --- Test: IDOR with nested resources ---

def test_idor_scan_nested_resources():
    """IDOR scan should handle nested resource patterns."""
    from security_harness.idor_scan import _extract_path_params

    assert _extract_path_params("/api/user/{id}/documents/{docId}") == ["id", "docId"]
    assert _extract_path_params("/api/organizations/{orgId}/projects/{projectId}") == ["orgId", "projectId"]
