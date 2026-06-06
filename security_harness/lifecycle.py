"""Reset/seed lifecycle execution for controlled dynamic replay."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import shlex
import subprocess

from .artifacts import redact_secrets
from .web_target import LifecycleCommand, WebTargetConfig


@dataclass(frozen=True)
class LifecycleRun:
    phase: str
    ok: bool
    command: str | None
    cwd: str | None
    exit_code: int | None
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "ok": self.ok,
            "command": redact_secrets(self.command or "") if self.command else None,
            "cwd": self.cwd,
            "exitCode": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def run_lifecycle(target: WebTargetConfig, config_path: str | Path, *, timeout_s: float = 60) -> dict[str, Any]:
    """Run reset then seed lifecycle commands with shell=False.

    Lifecycle commands are operator-controlled config. They are still opt-in at
    call sites and never run as a shell string.
    """
    if timeout_s <= 0:
        raise ValueError("lifecycle timeout must be greater than zero")
    base_dir = Path(config_path).expanduser().resolve().parent
    reset = _run_one("reset", target.reset, base_dir, timeout_s)
    seed = _run_one("seed", target.seed, base_dir, timeout_s)
    return {"reset": reset.to_dict(), "seed": seed.to_dict()}


def _run_one(phase: str, command: LifecycleCommand, base_dir: Path, timeout_s: float) -> LifecycleRun:
    if not command.command:
        if command.required:
            raise ValueError(f"{phase} lifecycle command is required")
        return LifecycleRun(phase, True, None, None, None, "", "")
    raw_cwd = Path(command.cwd).expanduser()
    cwd = raw_cwd.resolve() if raw_cwd.is_absolute() else (base_dir / raw_cwd).resolve()
    if not _under(cwd, base_dir):
        raise ValueError(f"{phase} lifecycle cwd must stay under the target config directory")
    if not cwd.exists() or not cwd.is_dir() or cwd.is_symlink():
        raise ValueError(f"{phase} lifecycle cwd must be an existing non-symlink directory")
    try:
        argv = shlex.split(command.command)
    except ValueError as exc:
        raise ValueError(f"invalid {phase} lifecycle command: {exc}") from exc
    if not argv:
        raise ValueError(f"{phase} lifecycle command is empty")
    proc = subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout_s,
        check=False,
    )
    stdout = redact_secrets(proc.stdout or "")
    stderr = redact_secrets(proc.stderr or "")
    if proc.returncode != 0 and command.required:
        raise ValueError(
            f"{phase} lifecycle command failed: "
            + json.dumps({"exitCode": proc.returncode, "stderr": stderr[-1000:]})
        )
    return LifecycleRun(phase, proc.returncode == 0, command.command, str(cwd), proc.returncode, stdout, stderr)


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
