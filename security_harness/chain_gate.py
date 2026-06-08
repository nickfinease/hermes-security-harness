"""LLM chain reasoning gates between pipeline phases.

After each phase completes, the chain gate sends accumulated findings
to an LLM and asks for:
- Recommended next phase and priority attack paths
- Findings that are already exploitable (no further testing needed)
- Findings that need authentication to proceed
- Cross-phase vulnerability chains identified so far

The LLM output guides what the next phase tests should focus on.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import redact_secrets
from .findings import FindingsAccumulator


@dataclass
class ChainGateResult:
    """Result of a chain reasoning gate."""

    # What phase(s) to run next
    recommended_phases: list[str] = field(default_factory=list)

    # Priority attack paths identified
    attack_paths: list[str] = field(default_factory=list)

    # Findings that are already exploitable
    exploitable: list[str] = field(default_factory=list)

    # Findings that need auth to proceed
    needs_auth: list[str] = field(default_factory=list)

    # Cross-phase chains identified
    chains: list[dict[str, Any]] = field(default_factory=list)

    # LLM reasoning summary (stored for audit trail)
    reasoning: str = ""

    # Phase context when this gate ran
    phase_context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommended_phases": self.recommended_phases,
            "attack_paths": self.attack_paths,
            "exploitable": self.exploitable,
            "needs_auth": self.needs_auth,
            "chains": self.chains,
            "reasoning": self.reasoning,
            "phase_context": self.phase_context,
        }


# ── LLM prompt template ──────────────────────────────────────────────────────

CHAIN_GATE_PROMPT = """\
You are a security testing analyst reviewing accumulated findings from a web application security assessment.

## Current Phase: {phase}
## Target: {target_id}

## Accumulated Findings:
{findings_text}

## Previous Phase History:
{phase_history}

## Task:
Review all accumulated findings and provide:
1. **Recommended next phase** - which WSTG testing phase should run next and why
2. **Priority attack paths** - specific attack chains identified across findings
3. **Exploitable findings** - findings that are already exploitable without further testing
4. **Findings needing auth** - findings that require authenticated access to test further
5. **Cross-phase chains** - combinations of findings that together create higher-severity risks

Respond in structured JSON format:
{{
  "recommended_phases": ["phase1", "phase2"],
  "attack_paths": ["description of attack path"],
  "exploitable": ["finding title"],
  "needs_auth": ["finding title"],
  "chains": [{{"finding1": "title", "finding2": "title", "combined_severity": "high", "description": "..."}}],
  "reasoning": "Your analysis..."
}}
"""


def run_chain_gate(
    findings: FindingsAccumulator,
    phase: str,
    target_id: str,
    phase_history: list[dict[str, Any]],
    artifact_root: Path,
    *,
    model: str | None = None,
    provider: str | None = None,
    max_turns: int = 8,
    timeout_s: float = 120,
) -> ChainGateResult:
    """Run a chain reasoning gate using LLM.

    Args:
        findings: Accumulated findings from completed phases.
        phase: Current phase name.
        target_id: Target identifier.
        phase_history: History of completed phases.
        artifact_root: Directory to write LLM artifacts.
        model: LLM model to use.
        provider: LLM provider to use.
        max_turns: Max agent turns for reasoning.
        timeout_s: Timeout in seconds.

    Returns:
        ChainGateResult with LLM recommendations.
    """
    from .runners import AgentRunRequest, HermesCliRunner

    # Build prompt
    findings_text = findings.export_for_llm()
    history_text = _format_phase_history(phase_history)

    prompt = CHAIN_GATE_PROMPT.format(
        phase=phase,
        target_id=target_id,
        findings_text=redact_secrets(findings_text),
        phase_history=history_text,
    )

    # Run LLM reasoning
    runner = HermesCliRunner(artifact_root)
    result = runner.run(
        AgentRunRequest(
            prompt=prompt,
            model=model,
            provider=provider,
            max_turns=max_turns,
            timeout_s=timeout_s,
        )
    )

    # Parse LLM output
    return _parse_chain_result(result, phase)


def _format_phase_history(history: list[dict[str, Any]]) -> str:
    """Format phase history for LLM prompt."""
    lines = []
    for i, entry in enumerate(history, 1):
        phase = entry.get("phase", "unknown")
        status = entry.get("status", "unknown")
        count = entry.get("findings_count", 0)
        lines.append(f"{i}. Phase {phase}: {status} ({count} findings)")
    return "\n".join(lines) if lines else "No phases completed yet"


def _parse_chain_result(result: Any, phase: str) -> ChainGateResult:
    """Parse LLM output into ChainGateResult."""
    # Extract JSON from LLM output
    content = ""
    if hasattr(result, "output"):
        content = result.output
    elif isinstance(result, dict):
        content = result.get("output", result.get("content", ""))
    elif isinstance(result, str):
        content = result

    # Try to parse JSON from the response
    try:
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return ChainGateResult(
                recommended_phases=data.get("recommended_phases", []),
                attack_paths=data.get("attack_paths", []),
                exploitable=data.get("exploitable", []),
                needs_auth=data.get("needs_auth", []),
                chains=data.get("chains", []),
                reasoning=data.get("reasoning", content[:500]),
                phase_context=phase,
            )
    except Exception:
        pass

    # Fallback: return raw result
    return ChainGateResult(
        reasoning=content[:1000],
        phase_context=phase,
    )


# ── Deterministic chain rules (no LLM) ────────────────────────────────────────

def run_deterministic_chain_gate(
    findings: FindingsAccumulator,
    phase: str,
) -> ChainGateResult:
    """Run chain reasoning using deterministic rules (no LLM).

    Uses predefined chain detection rules to identify vulnerability
    combinations across accumulated findings.

    Args:
        findings: Accumulated findings.
        phase: Current phase name.

    Returns:
        ChainGateResult with chain detections.
    """
    from .chains import RULES_DEFAULT, find_chains

    chains = find_chains(findings.findings, RULES_DEFAULT)

    # Convert ChainFinding objects to dicts
    chain_dicts = []
    for chain in chains:
        if hasattr(chain, "__dict__"):
            chain_dicts.append(chain.__dict__)
        elif isinstance(chain, dict):
            chain_dicts.append(chain)
        else:
            chain_dicts.append(str(chain))

    return ChainGateResult(
        chains=chain_dicts,
        reasoning=f"Deterministic chain analysis: {len(chains)} chains found",
        phase_context=phase,
    )


__all__ = [
    "ChainGateResult",
    "run_chain_gate",
    "run_deterministic_chain_gate",
]
