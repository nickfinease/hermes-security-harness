"""Provider-neutral agent runner protocol."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class AgentRunRequest:
    prompt: str
    workdir: Path
    max_turns: int = 90
    timeout_s: float = 600
    model: str | None = None
    provider: str | None = None
    toolsets: list[str] = field(default_factory=list)
    source: str = "security-harness"
    env: dict[str, str] = field(default_factory=dict)
    ignore_rules: bool = False
    ignore_user_config: bool = False
    yolo: bool = False


@dataclass(frozen=True)
class AgentRunResult:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    final_response: str | None
    command: list[str]
    timed_out: bool = False
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    command_path: Path | None = None
    result_path: Path | None = None
    session_id: str | None = None


class AgentRunner(Protocol):
    def run(self, request: AgentRunRequest) -> AgentRunResult:
        """Run an agent and return captured artifacts."""
