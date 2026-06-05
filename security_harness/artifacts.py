"""Artifact contracts for defensive web security findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import re

SEVERITIES = {"critical", "high", "medium", "low", "informational"}
CONFIDENCES = {"high", "medium", "low"}

_SECRET_PATTERNS = [
    re.compile(r"Authorization:\s*(Bearer|Basic)\s+[^\s]+", re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"(password|passwd|pwd|secret|client_secret|access_token|refresh_token)\s*[=:]\s*([^\s;&,}\]]+)", re.IGNORECASE),
    re.compile(r"(sessionid|session|token|api[_-]?key|x-api-key)\s*[=:]\s*([^\s;&,}\]]+)", re.IGNORECASE),
    re.compile(r"Cookie:\s*[^\n\r]+", re.IGNORECASE),
    re.compile(r"(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[0-9A-Z]{12,})"),
]


def redact_secrets(text: str) -> str:
    """Best-effort report/log redaction for common auth material."""
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: _redact_match(m), redacted)
    return redacted


def _redact_match(match: re.Match[str]) -> str:
    groups = match.groups()
    if len(groups) >= 2 and groups[0]:
        return f"{groups[0]}=[REDACTED]"
    prefix = match.group(0).split()[0] if match.group(0).split() else "secret"
    if prefix.lower().startswith("authorization"):
        return "Authorization: [REDACTED]"
    if prefix.lower().startswith("cookie"):
        return "Cookie: [REDACTED]"
    return "[REDACTED]"


@dataclass(frozen=True)
class HttpStep:
    name: str
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    expect: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "request": {
                "method": self.method.upper(),
                "url": self.url,
                "headers": {k: redact_secrets(v) for k, v in self.headers.items()},
                "body": redact_secrets(self.body) if self.body is not None else None,
            },
            "expect": self.expect,
            "evidence": _redact_obj(self.evidence),
        }


@dataclass(frozen=True)
class HttpPoc:
    id: str
    finding_id: str
    target_id: str
    title: str
    steps: list[HttpStep]
    preconditions: list[str] = field(default_factory=list)
    replay_safety: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.steps:
            raise ValueError("HTTP PoC requires at least one step")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": "http-poc/v1",
            "id": self.id,
            "findingId": self.finding_id,
            "targetId": self.target_id,
            "title": self.title,
            "preconditions": self.preconditions,
            "steps": [s.to_dict() for s in self.steps],
            "replaySafety": self.replay_safety,
        }


@dataclass(frozen=True)
class Finding:
    id: str
    run_id: str
    target_id: str
    title: str
    severity: str
    confidence: str
    affected: dict[str, Any]
    detector_id: str | None = None
    description: str = ""
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    poc_id: str | None = None
    remediation: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(SEVERITIES)}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"confidence must be one of {sorted(CONFIDENCES)}")
        if not self.affected.get("url"):
            raise ValueError("affected.url is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": "finding/v1",
            "id": self.id,
            "runId": self.run_id,
            "targetId": self.target_id,
            "detectorId": self.detector_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "affected": _redact_obj(self.affected),
            "evidence": _redact_obj(self.evidence),
            "pocId": self.poc_id,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class GraderResult:
    run_id: str
    target_id: str
    status: str
    findings: list[str] = field(default_factory=list)
    gates: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": "grader-result/v1",
            "runId": self.run_id,
            "targetId": self.target_id,
            "status": self.status,
            "gates": self.gates,
            "findings": self.findings,
            "artifacts": self.artifacts,
        }


def _redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_secrets(obj)
    if isinstance(obj, dict):
        return {k: _redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v) for v in obj]
    return obj
