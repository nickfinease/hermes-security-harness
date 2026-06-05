"""Headless Hermes CLI agent runner."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import os
import re
import subprocess
import uuid

from security_harness.artifacts import redact_secrets

from .base import AgentRunRequest, AgentRunResult

_SESSION_RE = re.compile(r"session[_ -]?id[:=]\s*([A-Za-z0-9_.:-]+)", re.IGNORECASE)
_ALLOWED_ENV_NAMES = {
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TERM",
    "HERMES_HOME",
    "HERMES_PROFILE",
    "HERMES_YOLO_MODE",
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "XAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "NOUS_API_KEY",
    "AI_GATEWAY_API_KEY",
}


class HermesCliRunner:
    """Run Hermes via `hermes chat --query` and persist redacted artifacts.

    This runner deliberately captures raw stdout/stderr instead of assuming a
    Claude Code-style event stream. A future Hermes API runner can be added
    behind the same AgentRunner protocol.
    """

    def __init__(self, artifact_root: str | Path):
        self.artifact_root = Path(artifact_root)

    def run(self, request: AgentRunRequest) -> AgentRunResult:
        if request.max_turns <= 0:
            raise ValueError("max_turns must be greater than zero")
        if request.timeout_s <= 0:
            raise ValueError("timeout_s must be greater than zero")
        request.workdir.mkdir(parents=True, exist_ok=True)
        run_dir = self._new_run_dir()
        cmd = self._build_command(request)
        env = self._build_env(request)
        stdout = ""
        stderr = ""
        exit_code = 0
        timed_out = False

        try:
            proc = subprocess.run(
                cmd,
                cwd=request.workdir,
                env=env,
                text=True,
                capture_output=True,
                timeout=request.timeout_s,
                check=False,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = -1
            stdout = _to_text(exc.stdout)
            stderr = _to_text(exc.stderr) + f"\nHermes CLI timed out after {request.timeout_s} seconds"
        except FileNotFoundError as exc:
            exit_code = 127
            stderr = str(exc)

        redacted_stdout = redact_secrets(stdout)
        redacted_stderr = redact_secrets(stderr)
        stdout_path = run_dir / "stdout.txt"
        stderr_path = run_dir / "stderr.txt"
        command_path = run_dir / "command.json"
        result_path = run_dir / "result.json"
        stdout_path.write_text(redacted_stdout)
        stderr_path.write_text(redacted_stderr)
        command_path.write_text(json.dumps({"argv": _redact_argv(cmd), "cwd": str(request.workdir)}, indent=2) + "\n")

        session_id = _extract_session_id(redacted_stdout + "\n" + redacted_stderr)
        result = AgentRunResult(
            ok=(exit_code == 0 and not timed_out),
            exit_code=exit_code,
            stdout=redacted_stdout,
            stderr=redacted_stderr,
            final_response=redacted_stdout.strip() or None,
            command=cmd,
            timed_out=timed_out,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            command_path=command_path,
            result_path=result_path,
            session_id=session_id,
        )
        result_path.write_text(json.dumps(_result_to_jsonable(result), indent=2) + "\n")
        return result

    def _new_run_dir(self) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = self.artifact_root / f"agent-{stamp}-{uuid.uuid4().hex[:8]}"
        run_dir.mkdir(parents=True, exist_ok=False)
        return run_dir

    @staticmethod
    def _build_command(request: AgentRunRequest) -> list[str]:
        cmd = [
            "hermes",
            "chat",
            "--query",
            request.prompt,
            "--quiet",
            "--source",
            request.source,
            "--max-turns",
            str(request.max_turns),
        ]
        if request.toolsets:
            cmd += ["--toolsets", ",".join(request.toolsets)]
        if request.provider:
            cmd += ["--provider", request.provider]
        if request.model:
            cmd += ["--model", request.model]
        if request.ignore_rules:
            cmd.append("--ignore-rules")
        if request.ignore_user_config:
            cmd.append("--ignore-user-config")
        if request.yolo:
            cmd.append("--yolo")
        return cmd

    @staticmethod
    def _build_env(request: AgentRunRequest) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if k in _ALLOWED_ENV_NAMES}
        env.update(request.env)
        return env


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _extract_session_id(text: str) -> str | None:
    match = _SESSION_RE.search(text)
    return match.group(1) if match else None


def _redact_argv(argv: list[str]) -> list[str]:
    redacted = []
    skip_next = False
    for item in argv:
        if skip_next:
            redacted.append(redact_secrets(item))
            skip_next = False
            continue
        redacted.append(item)
        if item == "--query":
            skip_next = True
    return redacted


def _result_to_jsonable(result: AgentRunResult) -> dict[str, object]:
    return {
        "ok": result.ok,
        "exitCode": result.exit_code,
        "timedOut": result.timed_out,
        "sessionId": result.session_id,
        "stdoutPath": str(result.stdout_path) if result.stdout_path else None,
        "stderrPath": str(result.stderr_path) if result.stderr_path else None,
        "commandPath": str(result.command_path) if result.command_path else None,
    }
