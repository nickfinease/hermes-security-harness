"""Phased pipeline orchestrator.

Runs security tests in WSTG-aligned phases, accumulating findings
and passing state between phases. Chain reasoning gates run between
phases to guide testing focus.

Phases:
  1. recon       - Unauthenticated reconnaissance
  2. config      - Configuration & deployment (TLS, headers)
  3. auth        - Authentication (JWT, session)
  4. authorization - Authorization (IDOR, role-boundary)
  5. session     - Session management (CSRF, cookie flags)
  6. input       - Input validation (XSS, SQLi, SSRF)
  7. business    - Business logic testing

Each phase reads accumulated findings, runs its scans, writes findings
back, and passes control to the chain gate for reasoning.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .engagement import Engagement, EngagementError
from .findings import FindingsAccumulator


@dataclass
class PhaseResult:
    """Result from a single pipeline phase."""
    phase: str
    status: str  # "completed", "skipped", "failed"
    findings_count: int = 0
    requests_made: int = 0
    error: str = ""
    scan_results: list[dict[str, Any]] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "status": self.status,
            "findings_count": self.findings_count,
            "requests_made": self.requests_made,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class PipelineResult:
    """Result from a complete pipeline run."""
    engagement_id: str
    target_id: str
    phases_run: list[str] = field(default_factory=list)
    total_findings: int = 0
    total_requests: int = 0
    phase_results: list[dict[str, Any]] = field(default_factory=list)
    chain_gate_results: list[dict[str, Any]] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "phases_run": self.phases_run,
            "total_findings": self.total_findings,
            "total_requests": self.total_requests,
            "phase_results": self.phase_results,
            "chain_gate_results": self.chain_gate_results,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
        }

    def to_summary(self) -> dict[str, Any]:
        summary = self.to_dict()
        summary["findings_by_severity"] = {}
        # This would be populated from engagement findings
        return summary


# ── Phase definitions ─────────────────────────────────────────────────────────

PHASES = {
    "recon": {
        "name": "Information Gathering",
        "description": "Unauthenticated reconnaissance: map public endpoints, auth surfaces, tech fingerprint",
        "requires_auth": False,
        "default_scans": ["recon", "http-smoke"],
    },
    "config": {
        "name": "Configuration & Deployment",
        "description": "TLS config, security headers, static analysis",
        "requires_auth": False,
        "default_scans": ["tls", "static"],
    },
    "auth": {
        "name": "Authentication",
        "description": "Authenticate, JWT scan, session tests, authenticated recon",
        "requires_auth": True,
        "default_scans": ["auth", "jwt", "recon-auth"],
    },
    "authorization": {
        "name": "Authorization",
        "description": "IDOR, role-boundary, privilege escalation",
        "requires_auth": True,
        "default_scans": ["idor", "authorization"],
    },
    "session": {
        "name": "Session Management",
        "description": "CSRF, cookie flags, session fixation",
        "requires_auth": True,
        "default_scans": ["csrf"],
    },
    "input": {
        "name": "Input Validation",
        "description": "XSS, SQLi, SSRF on all discovered surfaces",
        "requires_auth": True,
        "default_scans": ["injection"],
    },
    "business": {
        "name": "Business Logic",
        "description": "Workflow tests, race conditions, multi-step exploits",
        "requires_auth": True,
        "default_scans": ["business-logic"],
    },
}


@dataclass
class Pipeline:
    """Phased pipeline orchestrator."""
    engagement: Engagement
    findings: FindingsAccumulator = field(default_factory=FindingsAccumulator)

    def run_phases(
        self,
        phases: list[str] | None = None,
        run_chain_gates: bool = True,
        chain_deterministic: bool = True,
    ) -> PipelineResult:
        """Run pipeline phases.

        Args:
            phases: List of phase names to run. None = all phases.
            run_chain_gates: Run chain reasoning gates between phases.
            chain_deterministic: Use deterministic rules instead of LLM.

        Returns:
            PipelineResult with execution summary.
        """
        if phases is None:
            phases = list(PHASES.keys())

        started_at = datetime.now(timezone.utc).isoformat()
        result = PipelineResult(
            engagement_id=self.engagement.engagement_id,
            target_id=self.engagement.target_id,
            started_at=started_at,
        )

        for phase in phases:
            if phase not in PHASES:
                print(f"  Warning: Unknown phase '{phase}', skipping")
                continue

            phase_info = PHASES[phase]
            print(f"\n{'='*60}")
            print(f"Phase: {phase_info['name']} ({phase})")
            print(f"{'='*60}")

            # Check auth requirement
            if phase_info.get("requires_auth") and not self.engagement.credentials:
                print(f"  Skipped: {phase} requires credentials but none stored")
                result.phase_results.append({
                    "phase": phase,
                    "status": "skipped",
                    "error": "credentials required but not available",
                })
                continue

            # Run phase
            phase_result = self._run_phase(phase, phase_info)
            result.phases_run.append(phase)
            result.phase_results.append(phase_result.to_dict())
            result.total_findings += phase_result.findings_count
            result.total_requests += phase_result.requests_made

            # Save engagement after phase
            self._sync_to_engagement()

            # Chain reasoning gate
            if run_chain_gates and phase_result.status == "completed":
                gate_result = self._chain_gate(phase, chain_deterministic)
                result.chain_gate_results.append(gate_result)

        result.completed_at = datetime.now(timezone.utc).isoformat()
        duration = (
            datetime.fromisoformat(result.completed_at) -
            datetime.fromisoformat(result.started_at)
        ).total_seconds()
        result.duration_seconds = duration

        # Save final state
        self._sync_to_engagement()

        print(f"\n{'='*60}")
        print(f"Pipeline complete: {len(result.phases_run)} phases, {result.total_findings} findings")
        print(f"{'='*60}")

        return result

    def _run_phase(self, phase: str, phase_info: dict[str, Any]) -> PhaseResult:
        """Execute a single phase."""
        import time
        start = time.time()

        try:
            scan_results = []
            findings_count = 0
            requests_made = 0

            # TODO: Wire actual scan modules here
            # For now, this is a scaffold that shows the structure

            # Example of wiring a scan:
            # if "recon" in phase_info["default_scans"]:
            #     from .recon import run_recon
            #     result = run_recon(self.engagement.base_url)
            #     findings_count += self.findings.add_from_scan_result(result.to_summary())
            #     scan_results.append(result.to_summary())

            duration = time.time() - start
            return PhaseResult(
                phase=phase,
                status="completed",
                findings_count=findings_count,
                requests_made=requests_made,
                scan_results=scan_results,
                duration_seconds=duration,
            )
        except Exception as exc:
            return PhaseResult(
                phase=phase,
                status="failed",
                error=str(exc),
                duration_seconds=time.time() - start,
            )

    def _chain_gate(self, phase: str, deterministic: bool) -> dict[str, Any]:
        """Run chain reasoning gate after a phase."""
        if deterministic:
            from .chain_gate import run_deterministic_chain_gate
            gate_result = run_deterministic_chain_gate(self.findings, phase)
        else:
            from .chain_gate import run_chain_gate
            artifact_dir = self.engagement.path.parent / "chain-gates"
            gate_result = run_chain_gate(
                self.findings,
                phase,
                self.engagement.target_id,
                self.engagement.phase_history,
                artifact_root=artifact_dir,
            )

        gate_dict = gate_result.to_dict() if hasattr(gate_result, "to_dict") else {}
        reasoning = gate_dict.get("reasoning", "")
        print(f"  Chain gate: {reasoning[:100]}...")
        return gate_dict

    def _sync_to_engagement(self) -> None:
        """Sync accumulated findings back to engagement."""
        self.engagement.findings = self.findings.findings
        self.engagement.save()


def run_pipeline(
    target_id: str,
    *,
    phases: list[str] | None = None,
    chain_deterministic: bool = True,
    engagement: Engagement | None = None,
) -> PipelineResult:
    """Run a full pipeline for a target.

    Args:
        target_id: Target identifier.
        phases: Phases to run (None = all).
        chain_deterministic: Use deterministic chain rules instead of LLM.
        engagement: Pre-loaded engagement (loads from file if not provided).

    Returns:
        PipelineResult with execution summary.
    """
    if engagement is None:
        try:
            engagement = Engagement.load(target_id)
        except EngagementError:
            raise EngagementError(
                f"Engagement not found for '{target_id}'. "
                f"Run 'security-harness intake --target {target_id}' first."
            )

    # Load accumulated findings from engagement
    findings = FindingsAccumulator()
    findings.findings = engagement.findings

    pipeline = Pipeline(engagement=engagement, findings=findings)
    return pipeline.run_phases(phases, chain_deterministic=chain_deterministic)


__all__ = ["Pipeline", "PipelineResult", "PhaseResult", "PHASES", "run_pipeline"]
