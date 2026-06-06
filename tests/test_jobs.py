import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from security_harness.cli import main


class JobHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append(self.path)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        return


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), JobHandler)
    server.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def write_target_config(path: Path, base_url: str) -> None:
    path.write_text(f"""
schemaVersion: web-target/v1
id: job-demo
name: Job Demo
environment: local
baseUrl: {base_url}
allowedHosts:
  - 127.0.0.1
scope:
  includePaths:
    - /
  maxRequests: 5
  maxRuntimeSeconds: 30
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
""".lstrip())


def parse_last_json(captured: str) -> dict:
    return json.loads(captured)


def test_job_start_foreground_http_smoke_writes_status_and_reports(tmp_path, capsys):
    server, thread = start_server()
    try:
        config = tmp_path / "target.yaml"
        write_target_config(config, f"http://127.0.0.1:{server.server_port}")
        workdir = tmp_path / "workdir"
        workdir.mkdir()

        rc = main([
            "job-start",
            "--workdir", str(workdir),
            "--scan-type", "http-smoke",
            "--config", str(config),
            "--foreground",
        ])

        assert rc == 0
        started = parse_last_json(capsys.readouterr().out)
        job_id = started["job_id"]
        assert started["status"] == "succeeded"
        assert (workdir / "jobs" / f"{job_id}.json").exists()
        assert (workdir / "reports" / job_id / "report.md").exists()
        assert (workdir / "reports" / job_id / "report.json").exists()
        assert (workdir / "reports" / job_id / "report.summary").exists()

        rc = main(["job-status", "--workdir", str(workdir), job_id])
        assert rc == 0
        status = parse_last_json(capsys.readouterr().out)
        assert status["status"] == "succeeded"
        assert status["result"]["request_count"] == 1

        rc = main(["job-report", "--workdir", str(workdir), job_id, "--format", "summary"])
        assert rc == 0
        report = parse_last_json(capsys.readouterr().out)
        assert report["success"] is True
        assert "HTTP smoke report" in report["summary"]
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_job_start_async_worker_completes_http_smoke(tmp_path, capsys):
    server, thread = start_server()
    try:
        config = tmp_path / "target.yaml"
        write_target_config(config, f"http://127.0.0.1:{server.server_port}")
        workdir = tmp_path / "workdir"
        workdir.mkdir()

        rc = main([
            "job-start",
            "--workdir", str(workdir),
            "--scan-type", "http-smoke",
            "--config", str(config),
        ])
        assert rc == 0
        started = parse_last_json(capsys.readouterr().out)
        assert started["status"] in {"queued", "running"}
        job_id = started["job_id"]

        for _ in range(50):
            rc = main(["job-status", "--workdir", str(workdir), job_id])
            assert rc == 0
            status = parse_last_json(capsys.readouterr().out)
            if status["status"] == "succeeded":
                break
            time.sleep(0.1)
        else:
            raise AssertionError(f"job did not complete: {status}")

        assert status["result"]["request_count"] == 1
        assert (workdir / "reports" / job_id / "report.md").exists()
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_job_start_rejects_dynamic_poc_without_sandbox(tmp_path, capsys):
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://127.0.0.1:3000")
    poc = tmp_path / "poc.json"
    poc.write_text(json.dumps({
        "schemaVersion": "http-poc/v1",
        "id": "poc-1",
        "findingId": "f1",
        "targetId": "job-demo",
        "title": "unsafe",
        "steps": [{"name": "post", "request": {"method": "POST", "url": "http://127.0.0.1:3000/x", "body": "x"}}],
    }))
    workdir = tmp_path / "workdir"
    workdir.mkdir()

    rc = main([
        "job-start",
        "--workdir", str(workdir),
        "--scan-type", "poc-replay",
        "--config", str(config),
        "--poc", str(poc),
    ])

    assert rc == 2
    out = parse_last_json(capsys.readouterr().out)
    assert out["success"] is False
    assert "sandbox" in out["error"].lower()
    assert not (workdir / "jobs").exists()
