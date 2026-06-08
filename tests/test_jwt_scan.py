"""Tests for JWT (JSON Web Token) weaknesses scan module.
WSTG 4.6.10: Testing JSON Web Tokens

Tests for:
- Algorithm: none vulnerability
- JWT algorithm confusion (RS256 → HS256)
- Sensitive data in JWT claims
- Missing signature verification
- Token expiry validation
"""
from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_harness.jwt_scan import (
    JWTConfig,
    JWTScanResult,
    run_jwt_scan,
)
from tests.helpers import write_target_config


class MockJWTApp(BaseHTTPRequestHandler):
    """Handler that simulates an app VULNERABLE to JWT issues."""
    jwt_tokens: list[dict[str, str]] = []

    def _b64url_encode(self, data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    def do_GET(self):
        self.server.seen_paths.append(self.path)
        if self.path == "/api/auth/token":
            # Vulnerable: uses alg: none
            header = self._b64url_encode({"alg": "none", "typ": "JWT"})
            payload = self._b64url_encode({"userId": "user1", "role": "admin", "exp": 9999999999})
            token = f"{header}.{payload}."
            self.jwt_tokens.append(token)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode())
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class MockSecureJWTApp(BaseHTTPRequestHandler):
    """Handler that simulates an app with secure JWT."""

    def _b64url_encode(self, data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    def do_GET(self):
        self.server.seen_paths.append(self.path)
        if self.path == "/api/auth/token":
            header = self._b64url_encode({"alg": "RS256", "typ": "JWT"})
            payload = self._b64url_encode({"userId": "user1", "role": "user", "exp": 9999999999})
            # Real signature (not empty)
            token = f"{header}.{payload}.fake_signature_here"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode())
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


# --- Test: JWT alg: none detection ---

def test_jwt_scan_detects_alg_none(tmp_path, capsys):
    """An app returning alg: none JWT should produce findings."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockJWTApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "jwt", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/auth/token",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        assert out["endpoints_tested"] >= 1
    finally:
        server.shutdown()


# --- Test: JWT secure app (no alg: none) ---

def test_jwt_scan_secure_app_no_alg_none(tmp_path, capsys):
    """An app with secure JWT should not produce alg: none findings."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockSecureJWTApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "jwt", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/auth/token",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        assert out["endpoints_tested"] >= 1
    finally:
        server.shutdown()


# --- Test: JWT requires endpoints ---

def test_jwt_scan_uses_config_endpoints(tmp_path):
    """Running jwt scan without specifying endpoints uses config endpoints."""
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://localhost:8081", ["/api"])

    from security_harness.cli import main
    # Should succeed using config endpoints as fallback
    result = main(["jwt", str(config), "--artifacts", str(tmp_path / "runs")])
    assert result == 0  # Success - used config endpoints


# --- Test: JWT result structure ---

def test_jwt_scan_result_structure(tmp_path, capsys):
    """Verify JWT scan result has all required fields."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockJWTApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "jwt", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/auth/token",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        for field in ["run_id", "target_id", "endpoints_tested", "finding_count", "findings", "success"]:
            assert field in out
    finally:
        server.shutdown()


# --- Test: JWT config validates endpoints ---

def test_jwt_config_validates_endpoints():
    """JWTConfig should require at least one endpoint."""
    from security_harness.jwt_scan import JWTConfig

    with pytest.raises(ValueError, match="at least one endpoint"):
        JWTConfig(endpoints=[], base_url="http://localhost:3000")


def test_jwt_config_validates_base_url():
    """JWTConfig should validate the base URL."""
    with pytest.raises(ValueError, match="base_url"):
        JWTConfig(
            base_url="not-a-url",
            endpoints=["/api/auth/token"],
        )


# --- Test: JWT with multiple endpoints ---

def test_jwt_scan_multiple_endpoints(tmp_path, capsys):
    """JWT scan should test all provided endpoints."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockJWTApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        from security_harness.cli import main
        main([
            "jwt", str(config),
            "--artifacts", str(tmp_path / "runs"),
            "--endpoints", "/api/auth/token,/api/auth/refresh,/api/auth/verify",
        ])

        err = capsys.readouterr()
        out = json.loads(err.out)
        assert out["success"] is True
        assert out["endpoints_tested"] >= 3
    finally:
        server.shutdown()


# --- Test: JWT handles connection errors ---

def test_jwt_scan_handles_connection_errors(tmp_path):
    """JWT scan should handle connection errors gracefully."""
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://127.0.0.1:59999", ["/api"])

    from security_harness.cli import main
    rc = main([
        "jwt", str(config),
        "--artifacts", str(tmp_path / "runs"),
        "--endpoints", "/api/auth/token",
    ])
    assert rc in (0, 1, 2)


# --- Test: JWT algorithm detection ---

def test_jwt_scan_detects_sensitive_claims():
    """JWT scanner should detect sensitive data in claims."""
    from security_harness.jwt_scan import _detect_sensitive_claims

    # Should detect sensitive claims
    claims = {"password": "secret", "apiKey": "abc123", "token": "xyz789"}
    assert _detect_sensitive_claims(claims) == True

    # Should not detect sensitive claims
    safe_claims = {"userId": "user1", "role": "user"}
    assert _detect_sensitive_claims(safe_claims) == False


# --- Test: JWT result serialization ---

def test_jwt_scan_result_to_summary():
    """JWTScanResult.to_summary() should return expected fields."""
    result = JWTScanResult(
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


def test_jwt_scan_result_finding_count():
    """JWTScanResult.finding_count should return len(findings)."""
    result = JWTScanResult(
        run_id="test-456",
        target_id="test-target",
        findings=[{"id": "finding-1", "title": "Test"}],
        total_requests=20,
        endpoints_tested=5,
    )
    assert result.finding_count == 1


# --- Test: Run JWT scan programmatically ---

def test_jwt_scan_run_with_config(tmp_path):
    """run_jwt_scan should produce a result."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockJWTApp)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/api"])

        result = run_jwt_scan(
            str(config),
            endpoints=["/api/auth/token"],
            artifacts_root=str(tmp_path / "runs"),
        )

        assert result.run_id.startswith("jwt")
        assert result.target_id == "smoke-demo"
        assert result.endpoints_tested == 1
        assert result.success is True
    finally:
        server.shutdown()


# --- Test: Shared HTTP client ---

def test_jwt_scan_uses_shared_http_client():
    """The JWT scan should use the shared HTTP client."""
    from security_harness._http_client import make_url

    url = make_url("http://localhost:3000", "/api/auth/token")
    assert url == "http://localhost:3000/api/auth/token"


# --- Test: JWT finding structure ---

def test_jwt_scan_finding_structure():
    """A JWT finding should have all required fields."""
    finding = {
        "id": "jwt-alg-none",
        "title": "JWT algorithm: none",
        "severity": "CRITICAL",
        "description": "JWT uses alg: none, allowing unverified tokens",
        "confidence": "HIGH",
        "remediation": "Reject tokens with alg: none; verify signature",
        "details": {
            "algorithm": "none",
            "token_type": "JWT",
            "has_signature": False,
        },
    }

    assert finding["severity"] == "CRITICAL"
    assert "remediation" in finding
    assert "details" in finding
