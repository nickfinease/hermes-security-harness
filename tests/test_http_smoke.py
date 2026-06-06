"""Tests for the HTTP smoke scan."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_harness.cli import main
from tests.helpers import write_target_config, start_server, SECURITY_HEADERS


class SmokeHandler(BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, dict[str, str], bytes]] = {}

    def do_GET(self):
        self.server.seen_paths.append(self.path)  # type: ignore[attr-defined]
        status, extra_headers, body = self.routes.get(self.path, (404, {}, b"not found"))
        self.send_response(status)
        if getattr(self, "include_security_headers", True):
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
        for key, value in extra_headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def test_http_smoke_cli_checks_configured_paths_and_writes_artifacts(tmp_path, capsys):
    server, thread = start_server(
        {
            "/": (307, {"Location": "/login"}, b""),
            "/login": (200, {}, b"login"),
            "/api/health": (200, {"Content-Type": "application/json"}, b'{"status":"healthy"}'),
        }
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/", "/login", "/api/health"])
        artifacts = tmp_path / "artifacts"

        rc = main(["http-smoke", str(config), "--artifacts", str(artifacts)])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is True
        assert out["target_id"] == "smoke-demo"
        assert out["request_count"] == 3
        assert out["finding_count"] == 0

        run_dir = Path(out["run_dir"])
        smoke = json.loads((run_dir / "http-smoke.json").read_text())
        assert smoke["schemaVersion"] == "http-smoke/v1"
        assert [item["path"] for item in smoke["requests"]] == ["/", "/login", "/api/health"]
        assert smoke["requests"][0]["status"] == 307
        assert smoke["requests"][0]["redirect"]["location"] == "/login"
        assert smoke["requests"][0]["redirect"]["allowed"] is True
        assert smoke["requests"][1]["securityHeaders"]["missing"] == []
        assert (run_dir / "report.md").exists()
        assert server.seen_paths == ["/", "/login", "/api/health"]
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_http_smoke_skips_wildcard_paths_instead_of_crawling(tmp_path, capsys):
    server, thread = start_server({"/": (200, {}, b"ok")})
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/", "/api/*"])

        rc = main(["http-smoke", str(config), "--artifacts", str(tmp_path / "artifacts")])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        smoke = json.loads((Path(out["run_dir"]) / "http-smoke.json").read_text())
        assert out["request_count"] == 1
        assert server.seen_paths == ["/"]
        assert any("wildcard" in warning for warning in smoke["warnings"])
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_http_smoke_records_redirect_escape_as_finding(tmp_path, capsys):
    server, thread = start_server({"/out": (302, {"Location": "https://evil.example/"}, b"")})
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/out"])

        rc = main(["http-smoke", str(config), "--artifacts", str(tmp_path / "artifacts")])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["finding_count"] == 1
        smoke = json.loads((Path(out["run_dir"]) / "http-smoke.json").read_text())
        assert smoke["requests"][0]["redirect"]["allowed"] is False
        assert smoke["findings"][0]["id"] == "redirect-outside-allowlist"
        assert smoke["findings"][0]["affected"]["url"].endswith("/out")
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_http_smoke_rejects_wildcard_only_scope_without_creating_artifacts(tmp_path, capsys):
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://127.0.0.1:3000", ["/api/*"])
    artifacts = tmp_path / "artifacts"

    rc = main(["http-smoke", str(config), "--artifacts", str(artifacts)])

    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is False
    assert "concrete includePaths" in out["error"]
    assert not artifacts.exists()


def test_http_smoke_records_missing_security_headers_as_finding(tmp_path, capsys):
    server, thread = start_server({"/": (200, {}, b"ok")}, include_security_headers=False)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, ["/"])

        rc = main(["http-smoke", str(config), "--artifacts", str(tmp_path / "artifacts")])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["finding_count"] == 1
        smoke = json.loads((Path(out["run_dir"]) / "http-smoke.json").read_text())
        assert smoke["findings"][0]["id"] == "missing-security-headers-root"
        assert "Content-Security-Policy" in smoke["findings"][0]["evidence"]["missingHeaders"]
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_http_smoke_rejects_non_positive_request_timeout_without_creating_artifacts(tmp_path, capsys):
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://127.0.0.1:3000", ["/"])
    artifacts = tmp_path / "artifacts"

    rc = main(["http-smoke", str(config), "--artifacts", str(artifacts), "--request-timeout", "0"])

    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is False
    assert "request-timeout" in out["error"]
    assert not artifacts.exists()
