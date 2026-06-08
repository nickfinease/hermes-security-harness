"""Findings accumulator: shared state across pipeline phases.

Accumulates findings from all scan phases, deduplicates them,
and provides export for LLM chain reasoning gates.
"""
from __future__ import annotations

import json
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


class FindingsAccumulator:
    """Shared findings store that grows across pipeline phases."""

    def __init__(self) -> None:
        self.findings: list[dict[str, Any]] = []

    def add(self, finding: dict[str, Any]) -> bool:
        """Add a finding, deduplicating by title + endpoint.

        Returns True if finding was added (not duplicate).
        """
        key = (finding.get("title", ""), finding.get("endpoint", finding.get("url", "")))
        for existing in self.findings:
            existing_key = (existing.get("title", ""), existing.get("endpoint", existing.get("url", "")))
            if existing_key == key:
                # Update severity if new finding is higher
                new_sev = SEVERITY_ORDER.get(finding.get("severity", "informational"), 4)
                existing_sev = SEVERITY_ORDER.get(existing.get("severity", "informational"), 4)
                if new_sev < existing_sev:
                    existing["severity"] = finding.get("severity")
                    existing["confidence"] = finding.get("confidence")
                    existing["evidence"] = finding.get("evidence", {})
                return False
        finding.setdefault("severity", "informational")
        self.findings.append(finding)
        return True

    def add_from_scan_result(self, scan_result: dict[str, Any]) -> int:
        """Add all findings from a scan result dict, return count added."""
        results = scan_result.get("findings") or []
        if not isinstance(results, list):
            return 0
        added = 0
        for finding in results:
            # Merge scan metadata into finding
            merged = dict(finding)
            merged.setdefault("target_id", scan_result.get("target_id", ""))
            merged.setdefault("run_id", scan_result.get("run_id", ""))
            if self.add(merged):
                added += 1
        return added
    def filter(self, *, phase: str | None = None, severity: str | None = None) -> list[dict[str, Any]]:
        """Filter findings by phase and/or severity."""
        result = self.findings
        if phase:
            result = [f for f in result if f.get("phase") == phase]
        if severity:
            result = [f for f in result if f.get("severity") == severity]
        return result

    def by_severity(self) -> dict[str, int]:
        """Count findings by severity level."""
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.get("severity", "informational")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def high_severity_count(self) -> int:
        """Count findings with severity critical or high."""
        return sum(1 for f in self.findings if f.get("severity") in ("critical", "high"))

    def export_for_llm(self) -> str:
        """Export accumulated findings as a text prompt for chain reasoning."""
        lines = [f"Total findings: {len(self.findings)}", ""]

        grouped: dict[str, list[dict]] = {}
        for f in self.findings:
            sev = f.get("severity", "informational")
            grouped.setdefault(sev, []).append(f)

        for sev in ("critical", "high", "medium", "low", "informational"):
            findings = grouped.get(sev, [])
            if findings:
                lines.append(f"\n## {sev.upper()} ({len(findings)})")
                for i, f in enumerate(findings, 1):
                    title = f.get("title", "Untitled")
                    endpoint = f.get("endpoint", f.get("url", "unknown"))
                    phase = f.get("phase", "unknown")
                    lines.append(f"\n{i}. {title}")
                    lines.append(f"   Endpoint: {endpoint}")
                    lines.append(f"   Phase: {phase}")
                    evidence = f.get("evidence", {})
                    if evidence:
                        lines.append(f"   Evidence: {json.dumps(evidence, default=str)[:200]}")

        return "\n".join(lines)

    def export_summary(self) -> dict[str, Any]:
        """Export a compact summary of all findings."""
        return {
            "total": len(self.findings),
            "by_severity": self.by_severity(),
            "high_severity": self.high_severity_count(),
            "findings": self.findings,
        }

    def merge(self, other: "FindingsAccumulator") -> int:
        """Merge findings from another accumulator. Returns count added."""
        added = 0
        for finding in other.findings:
            if self.add(dict(finding)):
                added += 1
        return added


__all__ = ["FindingsAccumulator", "SEVERITY_ORDER"]
