"""Read-only static/source scan orchestration.

This module deliberately implements the first non-dynamic scan tier. It validates
the target boundary, inventories source files, writes a threat-model prompt, and
optionally runs a Hermes source-review agent with file-only tools. It must not
perform browser/HTTP probing or mutate the target workspace.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
import re
import uuid

from .artifacts import CONFIDENCES, SEVERITIES, redact_secrets
from .runners import AgentRunRequest, AgentRunResult, HermesCliRunner
from .web_target import WebTargetConfig, load_target_config

DEFAULT_STATIC_TEMPLATE = "source-static-v1"
DEFAULT_STATIC_TOOLSETS = ["file"]

_INCLUDED_SUFFIXES = {
    ".cfg",
    ".cjs",
    ".conf",
    ".go",
    ".graphql",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".md",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}
_EXCLUDED_DIR_NAMES = {
    ".cache",
    ".claude",
    ".git",
    ".github",
    ".gitnexus",
    ".hg",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".turbo",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "venv",
}
_BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".sqlite", ".db"}
_SIGNAL_PATTERNS = {
    "api-route": re.compile(r"(?:^|/)(app|pages)/api/|route\.(?:ts|tsx|js|jsx)$|routes?", re.IGNORECASE),
    "auth-session": re.compile(r"auth|session|cookie|csrf|jwt|oauth|same\s*site|httponly|secure", re.IGNORECASE),
    "authorization": re.compile(r"role|permission|tenant|owner|organization|authori[sz]", re.IGNORECASE),
    "upload": re.compile(r"upload|multipart|formdata|blob|file", re.IGNORECASE),
    "redirect": re.compile(r"redirect|callbackurl|returnto|nexturl|location", re.IGNORECASE),
    "database": re.compile(r"postgres|mysql|sqlite|prisma|drizzle|sql\b|select\b|insert\b|update\b", re.IGNORECASE),
    "secret-handling": re.compile(r"secret|api[_-]?key|password|token|private[_-]?key", re.IGNORECASE),
    "rate-limit": re.compile(r"rate\s*limit|ratelimit|throttle|bruteforce|lockout", re.IGNORECASE),
}
_LANGUAGE_BY_SUFFIX = {
    ".cfg": "config",
    ".cjs": "javascript",
    ".conf": "config",
    ".go": "go",
    ".graphql": "graphql",
    ".ini": "config",
    ".java": "java",
    ".js": "javascript",
    ".json": "json",
    ".jsx": "javascript-react",
    ".kt": "kotlin",
    ".md": "markdown",
    ".mjs": "javascript",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".sql": "sql",
    ".swift": "swift",
    ".toml": "toml",
    ".ts": "typescript",
    ".tsx": "typescript-react",
    ".yaml": "yaml",
    ".yml": "yaml",
}


@dataclass(frozen=True)
class StaticScanResult:
    success: bool
    run_id: str
    target_id: str
    run_dir: Path
    finding_count: int
    agent_success: bool
    artifacts: dict[str, Path]
    warnings: list[str]

    def to_summary(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "run_id": self.run_id,
            "target_id": self.target_id,
            "run_dir": str(self.run_dir),
            "finding_count": self.finding_count,
            "agent_success": self.agent_success,
            "artifacts": {k: str(v) for k, v in self.artifacts.items()},
            "warnings": self.warnings,
        }


def run_static_scan(
    config_path: str | Path,
    source_root: str | Path,
    artifacts_root: str | Path = "runs",
    *,
    template: str = DEFAULT_STATIC_TEMPLATE,
    toolsets: list[str] | None = None,
    max_turns: int = 16,
    timeout_s: float = 900,
    model: str | None = None,
    provider: str | None = None,
    max_files: int = 250,
    run_agent: bool = True,
    ignore_rules: bool = False,
    ignore_user_config: bool = False,
) -> StaticScanResult:
    """Run a source-only static scan and write all scan artifacts.

    The scan has two layers:
    1. deterministic target validation + source inventory + threat model;
    2. optional Hermes source-review agent with file-only tools.
    """
    target = load_target_config(config_path)
    root = _validate_source_root(source_root)
    if max_turns <= 0:
        raise ValueError("max-turns must be greater than zero")
    if timeout_s <= 0:
        raise ValueError("timeout must be greater than zero")
    if max_files <= 0:
        raise ValueError("max-files must be greater than zero")
    selected_toolsets = _normalize_static_toolsets(toolsets or list(DEFAULT_STATIC_TOOLSETS))

    run_id = _new_run_id(target)
    run_dir = _validate_artifacts_root(artifacts_root, root) / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    inventory_path = run_dir / "source-inventory.json"
    threat_model_path = run_dir / "threat-model.md"
    prompt_path = run_dir / "prompt.txt"
    findings_path = run_dir / "findings.json"
    report_path = run_dir / "report.md"

    inventory = build_source_inventory(root, target, max_files=max_files)
    _write_json(inventory_path, inventory)

    threat_model = build_threat_model(target, inventory, template=template)
    threat_model_path.write_text(threat_model)

    prompt = build_static_prompt(target, inventory_path, threat_model_path, template=template)
    prompt_path.write_text(prompt)

    agent_result: AgentRunResult | None = None
    warnings: list[str] = []
    if run_agent:
        agent_result = HermesCliRunner(run_dir / "agent").run(
            AgentRunRequest(
                prompt=prompt,
                workdir=root,
                source="security-harness-static",
                toolsets=[t for t in selected_toolsets if t],
                provider=provider,
                model=model,
                max_turns=max_turns,
                timeout_s=timeout_s,
                ignore_rules=ignore_rules,
                ignore_user_config=ignore_user_config,
                yolo=False,
            )
        )
        if not agent_result.ok:
            warnings.append("agent runner failed; deterministic artifacts were still written")
    else:
        warnings.append("agent runner skipped by operator flag")

    findings_doc = build_findings_document(target, run_id, root, agent_result, warnings)
    _write_json(findings_path, findings_doc)

    report = build_report(target, run_id, root, inventory, findings_doc, agent_result, warnings)
    report_path.write_text(report)

    artifacts = {
        "threat_model": threat_model_path,
        "source_inventory": inventory_path,
        "prompt": prompt_path,
        "findings": findings_path,
        "report": report_path,
    }
    if agent_result:
        if agent_result.stdout_path:
            artifacts["agent_stdout"] = agent_result.stdout_path
        if agent_result.stderr_path:
            artifacts["agent_stderr"] = agent_result.stderr_path
        if agent_result.command_path:
            artifacts["agent_command"] = agent_result.command_path
        if agent_result.result_path:
            artifacts["agent_result"] = agent_result.result_path

    agent_success = agent_result.ok if agent_result else False
    return StaticScanResult(
        success=(agent_success if run_agent else True),
        run_id=run_id,
        target_id=target.id,
        run_dir=run_dir,
        finding_count=len(findings_doc["findings"]),
        agent_success=agent_success,
        artifacts=artifacts,
        warnings=warnings,
    )


def build_source_inventory(source_root: Path, target: WebTargetConfig, *, max_files: int = 250) -> dict[str, Any]:
    root = _validate_source_root(source_root)
    files: list[dict[str, Any]] = []
    skipped = {"directories": 0, "binary_or_unsupported": 0, "symlinks": 0, "over_budget": 0, "unreadable": 0}
    total_candidate_files = 0
    total_bytes = 0
    eligible_paths: list[Path] = []

    for path in sorted(root.rglob("*")):
        if _is_under_excluded_dir(path, root):
            if path.is_dir():
                skipped["directories"] += 1
            continue
        if path.is_symlink():
            skipped["symlinks"] += 1
            continue
        if not path.is_file():
            continue
        total_candidate_files += 1
        suffix = path.suffix.lower()
        if suffix in _BINARY_SUFFIXES or suffix not in _INCLUDED_SUFFIXES:
            skipped["binary_or_unsupported"] += 1
            continue
        eligible_paths.append(path)

    selected_paths = sorted(eligible_paths, key=lambda p: _inventory_priority(p, root))[:max_files]
    skipped["over_budget"] = max(0, len(eligible_paths) - len(selected_paths))

    for path in selected_paths:
        try:
            stat = path.stat()
            rel = path.relative_to(root).as_posix()
            digest = _sha256_file(path)
            sample = _sample_text(path)
        except OSError:
            skipped["unreadable"] += 1
            continue
        total_bytes += stat.st_size
        files.append(
            {
                "path": rel,
                "sizeBytes": stat.st_size,
                "sha256": digest,
                "language": _language_for(path),
                "category": _category_for(rel),
                "signals": _signals_for(rel, sample),
            }
        )

    by_category: dict[str, int] = {}
    by_signal: dict[str, int] = {}
    for item in files:
        by_category[item["category"]] = by_category.get(item["category"], 0) + 1
        for signal in item["signals"]:
            by_signal[signal] = by_signal.get(signal, 0) + 1

    return {
        "schemaVersion": "source-inventory/v1",
        "targetId": target.id,
        "target": target.to_summary(),
        "sourceRoot": str(root),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "limits": {"maxFiles": max_files},
        "totals": {
            "candidateFiles": total_candidate_files,
            "eligibleFiles": len(eligible_paths),
            "includedFiles": len(files),
            "includedBytes": total_bytes,
            "truncated": skipped["over_budget"] > 0,
        },
        "summary": {
            "byCategory": dict(sorted(by_category.items())),
            "bySignal": dict(sorted(by_signal.items())),
        },
        "skipped": skipped,
        "selection": {
            "strategy": "security-signal-prioritized",
            "priority": ["middleware", "auth", "api", "source", "config", "test", "documentation"],
        },
        "files": files,
    }


def build_threat_model(target: WebTargetConfig, inventory: dict[str, Any], *, template: str) -> str:
    signals = inventory.get("summary", {}).get("bySignal", {})
    categories = inventory.get("summary", {}).get("byCategory", {})
    include_paths = ", ".join(target.scope.include_paths)
    exclude_paths = ", ".join(target.scope.exclude_paths) or "none"
    lines = [
        f"# Static threat model: {target.name}",
        "",
        f"- Template: `{template}`",
        f"- Target ID: `{target.id}`",
        f"- Environment: `{target.environment}`",
        f"- Base URL: `{target.base_url}`",
        f"- Included scope paths: {include_paths}",
        f"- Excluded paths: {exclude_paths}",
        f"- Source files inventoried: {inventory.get('totals', {}).get('includedFiles', 0)}",
        "",
        "## Safety boundary",
        "",
        "This is a source-only static review. Dynamic HTTP/browser probing, form submission, login attempts, database mutation, and patch application are out of scope.",
        "",
        "## Inferred attack surfaces",
        "",
    ]
    if signals:
        for signal, count in sorted(signals.items()):
            lines.append(f"- {signal}: {count} file(s)")
    else:
        lines.append("- No high-signal source categories detected in the inventory budget.")
    lines.extend(["", "## Source categories", ""])
    if categories:
        for category, count in sorted(categories.items()):
            lines.append(f"- {category}: {count} file(s)")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Review focus",
            "",
            "- Auth/session boundaries: cookie flags, CSRF, login/rate-limit protections.",
            "- Authorization boundaries: tenant/account/object ownership checks before data access or mutation.",
            "- Redirect and callback handling: same-origin allowlists and URL normalization.",
            "- Upload/form pipelines: validate-before-persist, size/type checks, stale-lock recovery.",
            "- Secret handling: no committed credentials, no secret leakage in reports/logs.",
            "",
        ]
    )
    return "\n".join(lines)


def build_static_prompt(
    target: WebTargetConfig,
    inventory_path: Path,
    threat_model_path: Path,
    *,
    template: str,
) -> str:
    target_summary = json.dumps(target.to_summary(), indent=2)
    return f"""You are running inside Hermes Security Harness static/source-only mode.

Mandatory safety rules:
- Do not issue network requests of any kind. No curl, fetch, browser, web search, HTTP clients, or app startup.
- Do not log in, submit forms, seed/reset databases, run migrations, or mutate application state.
- Do not write, patch, delete, format, or otherwise modify files in the target source tree.
- Read source files only. Prefer search/read operations. If a tool is unavailable, report the limitation instead of bypassing it.
- Generate inert remediation guidance only; do not produce executable patch commands.

Template: {template}
Target summary:
{target_summary}

Artifacts already written by the harness:
- Source inventory JSON: {inventory_path}
- Threat model markdown: {threat_model_path}

Task:
1. Read the source inventory and threat model.
2. Inspect the most relevant source files for auth/session, authorization, redirects, uploads/forms, API routes, and secret-handling risks.
3. Return exactly one JSON object, with no markdown wrapper, using this schema:
{{
  "schemaVersion": "static-agent-findings/v1",
  "findings": [
    {{
      "id": "stable-short-id",
      "title": "concise title",
      "severity": "critical|high|medium|low|informational",
      "confidence": "high|medium|low",
      "affected": {{"file": "relative/path", "url": "optional scoped URL or route"}},
      "description": "what source evidence indicates and why it matters",
      "evidence": {{"files": ["relative/path"], "lines": [1, 2], "snippet": "short redacted source quote if useful"}},
      "remediation": {{"summary": "inert guidance only; no patch commands"}}
    }}
  ],
  "notes": ["scope limits, uncertainty, or why findings is empty"]
}}

If you cannot substantiate a finding from source evidence, omit it or mark confidence low. Do not invent dynamic proof.
"""


def build_findings_document(
    target: WebTargetConfig,
    run_id: str,
    source_root: Path,
    agent_result: AgentRunResult | None,
    warnings: list[str],
) -> dict[str, Any]:
    parsed: dict[str, Any] = {"ok": False, "error": "agent not run", "notes": []}
    findings: list[dict[str, Any]] = []
    if agent_result is not None:
        parsed_findings, parsed = _parse_agent_findings(agent_result.stdout)
        findings = [_normalize_finding(item, target, run_id, idx) for idx, item in enumerate(parsed_findings, start=1)]

    patch_candidates = build_patch_candidates(target, run_id, findings)
    return {
        "schemaVersion": "static-findings/v1",
        "runId": run_id,
        "targetId": target.id,
        "sourceRoot": str(source_root),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "workspaceWritesEnabled": False,
        "patchCandidates": patch_candidates,
        "agent": _agent_summary(agent_result),
        "parser": parsed,
        "warnings": warnings,
        "findings": findings,
    }


def build_patch_candidates(target: WebTargetConfig, run_id: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create inert patch-candidate metadata from source findings.

    These are intentionally not unified diffs and contain no executable patch
    commands. They give a later workspace-enabled phase enough structure to
    decide what to edit while keeping source-only mode non-mutating.
    """
    candidates: list[dict[str, Any]] = []
    for idx, finding in enumerate(findings, start=1):
        affected = finding.get("affected") if isinstance(finding.get("affected"), dict) else {}
        files = []
        if affected.get("file"):
            files.append(str(affected["file"]))
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        for item in evidence.get("files", []) if isinstance(evidence.get("files"), list) else []:
            if isinstance(item, str) and item not in files:
                files.append(item)
        candidates.append(
            {
                "schemaVersion": "patch-candidate/v1",
                "id": f"patch-candidate-{idx}",
                "runId": run_id,
                "targetId": target.id,
                "findingId": finding.get("id"),
                "title": f"Inert remediation candidate for {finding.get('title') or finding.get('id')}",
                "affectedFiles": files,
                "workspaceWritesEnabled": False,
                "requiresHumanReview": True,
                "patch": None,
                "guidance": finding.get("remediation", {}),
            }
        )
    return candidates


def build_report(
    target: WebTargetConfig,
    run_id: str,
    source_root: Path,
    inventory: dict[str, Any],
    findings_doc: dict[str, Any],
    agent_result: AgentRunResult | None,
    warnings: list[str],
) -> str:
    findings = findings_doc.get("findings", [])
    lines = [
        f"# Static scan report: {target.name}",
        "",
        f"- Run ID: `{run_id}`",
        f"- Target ID: `{target.id}`",
        f"- Source root: `{source_root}`",
        f"- Base URL: `{target.base_url}`",
        f"- Agent success: `{agent_result.ok if agent_result else False}`",
        f"- Findings: {len(findings)}",
        "- Workspace writes enabled: `False`",
        "",
        "## Safety boundary",
        "",
        "This run was static/source-only. It did not require dynamic probing, login, form submission, database mutation, browser automation, or patch application.",
        "",
        "## Inventory summary",
        "",
        f"- Candidate files: {inventory.get('totals', {}).get('candidateFiles', 0)}",
        f"- Included files: {inventory.get('totals', {}).get('includedFiles', 0)}",
        f"- Truncated: {inventory.get('totals', {}).get('truncated', False)}",
        "",
        "## Findings",
        "",
    ]
    if findings:
        for item in findings:
            lines.extend(
                [
                    f"### {item.get('title', item.get('id'))}",
                    "",
                    f"- ID: `{item.get('id')}`",
                    f"- Severity: `{item.get('severity')}`",
                    f"- Confidence: `{item.get('confidence')}`",
                    f"- Affected: `{json.dumps(item.get('affected', {}), sort_keys=True)}`",
                    "",
                    str(item.get("description") or "No description provided."),
                    "",
                    f"Remediation: {json.dumps(item.get('remediation', {}), sort_keys=True)}",
                    "",
                ]
            )
    else:
        lines.append("No source-substantiated findings were emitted by the static agent.")
        lines.append("")
    if warnings:
        lines.extend(["## Warnings", ""])
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")
    lines.extend(
        [
            "## Agent artifacts",
            "",
            f"- stdout: `{agent_result.stdout_path if agent_result else None}`",
            f"- stderr: `{agent_result.stderr_path if agent_result else None}`",
            f"- command: `{agent_result.command_path if agent_result else None}`",
            f"- result: `{agent_result.result_path if agent_result else None}`",
            "",
        ]
    )
    return "\n".join(lines)


def _validate_source_root(source_root: str | Path) -> Path:
    root = Path(source_root).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("source root must be an existing directory")
    if Path(source_root).expanduser().is_symlink():
        raise ValueError("source root must not be a symlink")
    return root


def _validate_artifacts_root(artifacts_root: str | Path, source_root: Path) -> Path:
    root = Path(artifacts_root).expanduser().resolve()
    if _path_under_or_equal(root, source_root):
        raise ValueError("artifacts root must be outside source root for static-scan")
    if root.exists() and root.is_symlink():
        raise ValueError("artifacts root must not be a symlink")
    return root


def _normalize_static_toolsets(toolsets: list[str]) -> list[str]:
    normalized = [t.strip().lower() for t in toolsets if t and t.strip()]
    if not normalized:
        return list(DEFAULT_STATIC_TOOLSETS)
    if any(t != "file" for t in normalized):
        raise ValueError("static-scan is file-only; toolsets must be exactly 'file'")
    return ["file"]


def _path_under_or_equal(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _new_run_id(target: WebTargetConfig) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_target = re.sub(r"[^A-Za-z0-9_-]+", "-", target.id).strip("-") or "target"
    return f"static-{stamp}-{safe_target}-{uuid.uuid4().hex[:8]}"


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(_redact_obj(obj), indent=2, sort_keys=True) + "\n")


def _is_under_excluded_dir(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in _EXCLUDED_DIR_NAMES for part in rel_parts[:-1] if part)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sample_text(path: Path, limit: int = 8192) -> str:
    try:
        return path.read_text(errors="ignore")[:limit]
    except UnicodeDecodeError:
        return ""


def _language_for(path: Path) -> str:
    return _LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "text")


def _category_for(rel_path: str) -> str:
    lower = rel_path.lower()
    if "/api/" in f"/{lower}" or lower.endswith("route.ts") or lower.endswith("route.js"):
        return "api"
    if "middleware" in lower:
        return "middleware"
    if "auth" in lower or "session" in lower:
        return "auth"
    if "test" in lower or "spec" in lower:
        return "test"
    if lower.endswith((".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".cfg")):
        return "config"
    if lower.endswith(".md"):
        return "documentation"
    return "source"


def _inventory_priority(path: Path, root: Path) -> tuple[int, int, int, str]:
    rel = path.relative_to(root).as_posix()
    sample = _sample_text(path, limit=2048)
    category_rank = {
        "middleware": 0,
        "auth": 1,
        "api": 2,
        "source": 3,
        "config": 4,
        "test": 5,
        "documentation": 6,
    }.get(_category_for(rel), 9)
    signal_rank = -len(_signals_for(rel, sample))
    hidden_rank = 1 if any(part.startswith(".") for part in Path(rel).parts) else 0
    return (category_rank, signal_rank, hidden_rank, rel)


def _signals_for(rel_path: str, sample: str) -> list[str]:
    haystack = f"{rel_path}\n{sample}"
    return sorted(name for name, pattern in _SIGNAL_PATTERNS.items() if pattern.search(haystack))


def _parse_agent_findings(stdout: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    text = stdout.strip()
    if not text:
        return [], {"ok": False, "error": "empty agent stdout", "notes": []}
    try:
        data = _load_json_from_text(text)
    except ValueError as exc:
        return [], {"ok": False, "error": str(exc), "notes": []}
    if not isinstance(data, dict):
        return [], {"ok": False, "error": "agent JSON root is not an object", "notes": []}
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        return [], {"ok": False, "error": "agent JSON findings is not a list", "notes": []}
    return [f for f in findings if isinstance(f, dict)], {
        "ok": True,
        "error": None,
        "agentSchemaVersion": data.get("schemaVersion"),
        "notes": data.get("notes", []) if isinstance(data.get("notes", []), list) else [],
    }


def _load_json_from_text(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.IGNORECASE | re.DOTALL)
    if fenced:
        return json.loads(fenced.group(1))
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return json.loads(text[start : end + 1])
    raise ValueError("agent stdout did not contain a JSON object")


def _normalize_finding(item: dict[str, Any], target: WebTargetConfig, run_id: str, idx: int) -> dict[str, Any]:
    severity = str(item.get("severity", "informational")).lower()
    if severity not in SEVERITIES:
        severity = "informational"
    confidence = str(item.get("confidence", "low")).lower()
    if confidence not in CONFIDENCES:
        confidence = "low"
    affected = item.get("affected") if isinstance(item.get("affected"), dict) else {}
    finding_id = str(item.get("id") or f"static-{idx}")
    return {
        "schemaVersion": "static-finding/v1",
        "id": finding_id,
        "runId": run_id,
        "targetId": target.id,
        "title": str(item.get("title") or finding_id),
        "severity": severity,
        "confidence": confidence,
        "affected": _redact_obj(affected),
        "description": redact_secrets(str(item.get("description") or "")),
        "evidence": _redact_obj(item.get("evidence") if isinstance(item.get("evidence"), dict) else {}),
        "remediation": _redact_obj(item.get("remediation") if isinstance(item.get("remediation"), dict) else {}),
    }


def _agent_summary(agent_result: AgentRunResult | None) -> dict[str, Any]:
    if agent_result is None:
        return {"ok": False, "skipped": True}
    return {
        "ok": agent_result.ok,
        "skipped": False,
        "exitCode": agent_result.exit_code,
        "timedOut": agent_result.timed_out,
        "sessionId": agent_result.session_id,
        "stdoutPath": str(agent_result.stdout_path) if agent_result.stdout_path else None,
        "stderrPath": str(agent_result.stderr_path) if agent_result.stderr_path else None,
        "commandPath": str(agent_result.command_path) if agent_result.command_path else None,
        "resultPath": str(agent_result.result_path) if agent_result.result_path else None,
    }


def _redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_secrets(obj)
    if isinstance(obj, dict):
        return {str(k): _redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v) for v in obj]
    return obj
