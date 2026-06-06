import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from security_harness.cli import main


def write_target_config(path: Path, base_url: str, *, lifecycle: bool = False) -> tuple[Path | None, Path | None]:
    reset = seed = None
    lifecycle_block = ""
    if lifecycle:
        reset = path.parent / "reset.py"
        seed = path.parent / "seed.py"
        reset.write_text("from pathlib import Path\nPath('reset.marker').write_text('reset')\n")
        seed.write_text("from pathlib import Path\nPath('seed.marker').write_text('seed')\n")
        lifecycle_block = f"""
lifecycle:
  reset:
    command: {sys.executable} {reset}
    cwd: .
    required: true
  seed:
    command: {sys.executable} {seed}
    cwd: .
    required: true
"""
    path.write_text(
        f"""
schemaVersion: web-target/v1
id: poc-demo
name: PoC Demo
environment: local
baseUrl: {base_url}
allowedHosts:
  - 127.0.0.1
scope:
  includePaths:
    - /
  maxRequests: 10
  maxRuntimeSeconds: 30
{lifecycle_block}safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
""".lstrip()
    )
    return reset, seed


class PocHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append(("GET", self.path, None))  # type: ignore[attr-defined]
        if self.path == "/ok":
            self.send_response(200)
            self.send_header("Location", "/ok")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/out":
            self.send_response(302)
            self.send_header("Location", "https://evil.example/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0") or 0))
        self.server.seen.append(("POST", self.path, body.decode()))  # type: ignore[attr-defined]
        self.send_response(201)
        self.end_headers()
        self.wfile.write(b"created")

    def log_message(self, *_args):
        return


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), PocHandler)
    server.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def write_poc(path: Path, target_id: str, steps: list[dict]) -> None:
    path.write_text(json.dumps({
        "schemaVersion": "http-poc/v1",
        "id": "poc-1",
        "findingId": "finding-1",
        "targetId": target_id,
        "title": "Test PoC",
        "steps": steps,
    }))


def test_replay_poc_runs_read_only_get_and_writes_grader_artifacts(tmp_path, capsys):
    server, thread = start_server()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url)
        poc = tmp_path / "poc.json"
        write_poc(poc, "poc-demo", [{
            "name": "ok",
            "request": {"method": "GET", "url": f"{base_url}/ok"},
            "expect": {"status": 200},
        }])

        rc = main(["replay-poc", str(config), str(poc), "--artifacts", str(tmp_path / "artifacts")])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is True
        assert out["verified"] is True
        assert out["finding_count"] == 0
        run_dir = Path(out["run_dir"])
        replay = json.loads((run_dir / "poc-replay.json").read_text())
        assert replay["schemaVersion"] == "poc-replay/v1"
        assert replay["steps"][0]["status"] == 200
        assert (run_dir / "grader-result.json").exists()
        assert server.seen == [("GET", "/ok", None)]
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_replay_poc_blocks_mutating_request_without_sandbox_and_lifecycle(tmp_path, capsys):
    server, thread = start_server()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url)
        poc = tmp_path / "poc.json"
        write_poc(poc, "poc-demo", [{
            "name": "create",
            "request": {"method": "POST", "url": f"{base_url}/mutate", "body": "x=1"},
            "expect": {"status": 201},
        }])
        artifacts = tmp_path / "artifacts"

        rc = main(["replay-poc", str(config), str(poc), "--artifacts", str(artifacts)])

        assert rc == 2
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is False
        assert "sandbox" in out["error"].lower()
        assert server.seen == []
        assert not artifacts.exists()
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_replay_poc_blocks_mutating_request_without_concrete_lifecycle_commands(tmp_path, capsys):
    server, thread = start_server()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url)
        poc = tmp_path / "poc.json"
        write_poc(poc, "poc-demo", [{
            "name": "create",
            "request": {"method": "POST", "url": f"{base_url}/mutate", "body": "x=1"},
            "expect": {"status": 201},
        }])
        ephemeral_home = tmp_path / "ephemeral-home"
        ephemeral_home.mkdir()
        artifacts = tmp_path / "artifacts"

        rc = main([
            "replay-poc", str(config), str(poc),
            "--artifacts", str(artifacts),
            "--run-lifecycle",
            "--sandbox-mode", "gvisor",
            "--ephemeral-home", str(ephemeral_home),
            "--egress-host", "127.0.0.1",
            "--no-credential-mounts",
        ])

        assert rc == 2
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is False
        assert "reset and seed" in out["error"]
        assert server.seen == []
        assert not artifacts.exists()
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_replay_poc_rejects_different_port_on_allowed_host(tmp_path, capsys):
    server, thread = start_server()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url)
        poc = tmp_path / "poc.json"
        other_port = server.server_port + 1
        write_poc(poc, "poc-demo", [{
            "name": "wrong-port",
            "request": {"method": "GET", "url": f"http://127.0.0.1:{other_port}/ok"},
            "expect": {"status": 200},
        }])
        artifacts = tmp_path / "artifacts"

        rc = main(["replay-poc", str(config), str(poc), "--artifacts", str(artifacts)])

        assert rc == 2
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is False
        assert "base origin" in out["error"]
        assert server.seen == []
        assert not artifacts.exists()
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_replay_poc_allows_mutating_request_only_with_sandbox_and_lifecycle(tmp_path, capsys):
    server, thread = start_server()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url, lifecycle=True)
        poc = tmp_path / "poc.json"
        write_poc(poc, "poc-demo", [{
            "name": "create",
            "request": {"method": "POST", "url": f"{base_url}/mutate", "body": "x=1"},
            "expect": {"status": 201},
        }])
        ephemeral_home = tmp_path / "ephemeral-home"
        ephemeral_home.mkdir()

        rc = main([
            "replay-poc", str(config), str(poc),
            "--artifacts", str(tmp_path / "artifacts"),
            "--run-lifecycle",
            "--sandbox-mode", "gvisor",
            "--ephemeral-home", str(ephemeral_home),
            "--egress-host", "127.0.0.1",
            "--no-credential-mounts",
        ])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is True
        assert out["verified"] is True
        assert server.seen == [("POST", "/mutate", "x=1")]
        assert (tmp_path / "reset.marker").read_text() == "reset"
        assert (tmp_path / "seed.marker").read_text() == "seed"
        replay = json.loads((Path(out["run_dir"]) / "poc-replay.json").read_text())
        assert replay["sandbox"]["mode"] == "gvisor"
        assert replay["lifecycle"]["reset"]["ok"] is True
        assert replay["lifecycle"]["seed"]["ok"] is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_replay_poc_rejects_lifecycle_cwd_escape_before_request(tmp_path, capsys):
    server, thread = start_server()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config = config_dir / "target.yaml"
        reset = config_dir / "reset.py"
        seed = config_dir / "seed.py"
        reset.write_text("print('reset')\n")
        seed.write_text("print('seed')\n")
        config.write_text(f"""
schemaVersion: web-target/v1
id: poc-demo
name: PoC Demo
environment: local
baseUrl: {base_url}
allowedHosts:
  - 127.0.0.1
scope:
  includePaths: [/]
  maxRequests: 10
  maxRuntimeSeconds: 30
lifecycle:
  reset:
    command: {sys.executable} {reset}
    cwd: ..
    required: true
  seed:
    command: {sys.executable} {seed}
    cwd: .
    required: true
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
""".lstrip())
        poc = tmp_path / "poc.json"
        write_poc(poc, "poc-demo", [{
            "name": "create",
            "request": {"method": "POST", "url": f"{base_url}/mutate", "body": "x=1"},
            "expect": {"status": 201},
        }])
        ephemeral_home = tmp_path / "ephemeral-home"
        ephemeral_home.mkdir()

        rc = main([
            "replay-poc", str(config), str(poc),
            "--artifacts", str(tmp_path / "artifacts"),
            "--run-lifecycle",
            "--sandbox-mode", "gvisor",
            "--ephemeral-home", str(ephemeral_home),
            "--egress-host", "127.0.0.1",
            "--no-credential-mounts",
        ])

        assert rc == 2
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is False
        assert "cwd" in out["error"]
        assert server.seen == []
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_replay_poc_records_redirect_escape_as_unverified(tmp_path, capsys):
    server, thread = start_server()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        config = tmp_path / "target.yaml"
        write_target_config(config, base_url)
        poc = tmp_path / "poc.json"
        write_poc(poc, "poc-demo", [{
            "name": "out",
            "request": {"method": "GET", "url": f"{base_url}/out"},
            "expect": {"status": 302},
        }])

        rc = main(["replay-poc", str(config), str(poc), "--artifacts", str(tmp_path / "artifacts")])

        assert rc == 1
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is False
        assert out["verified"] is False
        replay = json.loads((Path(out["run_dir"]) / "poc-replay.json").read_text())
        assert replay["findings"][0]["id"] == "poc-redirect-outside-allowlist"
    finally:
        server.shutdown()
        thread.join(timeout=5)
