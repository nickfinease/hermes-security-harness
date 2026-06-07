"""Structured security scan report generation.

Produces human-readable, prioritized reports from raw scan findings
with:
- Executive summary with risk score
- CVSS-like scoring per finding
- Risk matrix (likelihood × impact)
- Prioritized remediation recommendations
- Compliance mapping (OWASP Top 10, CWE, MITRE ATT&CK)

Public API (``__all__``):
    generate_report, generate_json_report, ReportConfig,
    compute_cvss_score, risk_matrix, RiskLevel,
"""
from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .artifacts import Finding, redact_secrets


# ── Enumerations ────────────────────────────────────────────────────────────────


class RiskLevel(Enum):
    """Overall risk level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class SeverityWeight(Enum):
    """CVSS-like severity weights."""
    CRITICAL = 9.8
    HIGH = 7.5
    MEDIUM = 4.0
    LOW = 2.0
    INFORMATIONAL = 0.0


class OWASPCategory(Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTographic_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SEC_MISCONFIG = "A05:2021-Security Misconfiguration"
    A06_VULN_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_DATA_INTEGRITY = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"


# ── CVSS-like scoring ─────────────────────────────────────────────────────────

_CWE_BASE_SCORES = {
    # Injection
    "CWE-89": 9.8,   # SQL Injection
    "CWE-79": 8.5,   # XSS
    "CWE-94": 9.8,   # Code Injection
    "CWE-78": 9.8,   # OS Command Injection
    "CWE-91": 9.0,   # XML External Entity
    "CWE-611": 8.6,  # XXE (External Entity)
    "CWE-20": 7.5,   # Improper Input Validation
    "CWE-77": 9.0,   # Command Injection
    # SSRF
    "CWE-918": 9.8,  # SSRF
    # Authentication
    "CWE-287": 9.0,  # Authentication Bypass
    "CWE-306": 9.0,  # Missing Authentication
    "CWE-307": 9.0,  # Improper Restriction of Excessive Auth
    "CWE-352": 7.5,  # CSRF
    "CWE-613": 7.5,  # Insufficient Session Expiration
    # Information Disclosure
    "CWE-200": 5.3,  # Information Exposure
    "CWE-209": 5.3,  # Info Disclosure in Error Msg
    "CWE-532": 5.3,  # Info Exposure in Logs
    "CWE-615": 5.3,  # Information Exposure via Headers
    # Access Control
    "CWE-22": 8.5,   # Path Traversal
    "CWE-58": 9.0,   # BP: Incorrect Permissions
    "CWE-732": 9.0,  # Incorrect Permissions
    "CWE-862": 7.5,  # Missing Authorization
    "CWE-863": 9.0,  # Incorrect Authorization
    "CWE-915": 9.8,  # Improper Control of Dynamically-Identified Objects
    # Configuration
    "CWE-489": 7.5,  # Active Web Server
    "CWE-497": 5.3,  # Info Exposure via Debug
    "CWE-501": 5.3,  # Trust Boundary Violation
    "CWE-522": 7.5,  # Insufficiently Protected Credentials
    "CWE-798": 9.8,  # Use of Hardcoded Credentials
    "CWE-942": 5.3,  # Permissive Cross-domain Policy
    # Rate limiting
    "CWE-307": 6.5,  # Rate Limiting Missing
    # Headers
    "CWE-693": 3.7,  # Missing Security Headers
    "CWE-1021": 3.7, # Missing HSTS
    "CWE-16": 3.0,   # Missing CSP
    # Serialization
    "CWE-502": 9.8,  # Deserialization of Untrusted Data
    "CWE-917": 9.8,  # improper neutralizatio of special
    # Other
    "CWE-799": 5.3,  # Improper control of interaction frequency
    "CWE-927": 5.3,  # Improper Control of Line Terminators
    "CWE-1321": 7.5, # HTTP Request Smuggling
    "CWE-434": 8.5,  # Unrestricted Upload of File with
    "CWE-436": 7.5,  # Interpreter Interaction
    "CWE-770": 9.0,  # Allocation of Resources Without Limits
    "CWE-470": 7.5,  # Use of Externally-Controlled Input
    "CWE-829": 7.5,  # Inclusion of Functionality from
    "CWE-913": 7.5,  # Overly Permissive Cross-domain Whitelist
}


def compute_cvss_score(finding: Finding, severity_override: float | None = None) -> float:
    """Compute a CVSS-like score for a finding.

    Base score = severity weight × confidence factor × CWE score factor.

    Args:
        finding: The Finding object.
        severity_override: Optional manual score override.

    Returns:
        CVSS-like score (0-10).
    """
    if severity_override is not None:
        return min(10.0, max(0.0, severity_override))

    severity_weights = {
        "critical": 9.8,
        "high": 7.5,
        "medium": 4.0,
        "low": 2.0,
        "informational": 0.0,
    }
    base_score = severity_weights.get(finding.severity, 5.0)

    # Confidence factor
    confidence_factors = {
        "high": 1.0,
        "medium": 0.8,
        "low": 0.6,
    }
    conf_factor = confidence_factors.get(finding.confidence, 0.7)

    # CWE factor: boost if we have a known CWE with a high score
    cwe_score = 0
    for cwe_id in finding.cwe:
        cwe_score = max(cwe_score, _CWE_BASE_SCORES.get(cwe_id, 5.0))

    # Weight: 80% severity, 10% confidence, 10% CWE
    combined = (base_score * 0.8) + (base_score * conf_factor * 0.1) + (cwe_score * 0.1)
    return round(min(10.0, max(0.0, combined)), 1)


def severity_to_risk_level(severity: str) -> RiskLevel:
    """Map severity string to RiskLevel."""
    mapping = {
        "critical": RiskLevel.CRITICAL,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
        "informational": RiskLevel.INFO,
    }
    return mapping.get(severity, RiskLevel.MEDIUM)


def risk_matrix(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by severity.

    Args:
        findings: List of finding dicts (from injection scan or other scanner).

    Returns:
        Dict of severity -> count.
    """
    matrix: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev in matrix:
            matrix[sev] += 1
        else:
            matrix["informational"] += 1
    return matrix


def overall_risk_level(matrix: dict[str, int]) -> RiskLevel:
    """Determine overall risk level from severity matrix.

    Logic: if any critical → CRITICAL, if any high → HIGH, etc.
    """
    if matrix.get("critical", 0) > 0:
        return RiskLevel.CRITICAL
    if matrix.get("high", 0) > 0:
        return RiskLevel.HIGH
    if matrix.get("medium", 0) > 0:
        return RiskLevel.MEDIUM
    if matrix.get("low", 0) > 0:
        return RiskLevel.LOW
    return RiskLevel.INFO


# ── OWASP mapping ─────────────────────────────────────────────────────────────

_FINDING_OWASP_MAP = {
    "xss": OWASPCategory.A03_INJECTION,
    "XSS": OWASPCategory.A03_INJECTION,
    "sqli": OWASPCategory.A03_INJECTION,
    "SQLi": OWASPCategory.A03_INJECTION,
    "ssrf": OWASPCategory.A10_SSRF,
    "SSRF": OWASPCategory.A10_SSRF,
    "path traversal": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "Path Traversal": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "command injection": OWASPCategory.A03_INJECTION,
    "Command Injection": OWASPCategory.A03_INJECTION,
    "xxe": OWASPCategory.A03_INJECTION,
    "XXE": OWASPCategory.A03_INJECTION,
    "csrf": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "CSRF": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "header injection": OWASPCategory.A03_INJECTION,
    "Header Injection": OWASPCategory.A03_INJECTION,
    "rate limiting": OWASPCategory.A02_CRYPTographic_FAILURES,
    "Rate Limit": OWASPCategory.A02_CRYPTographic_FAILURES,
    "csrf": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "HTTP Param Pollution": OWASPCategory.A03_INJECTION,
    "http param pollution": OWASPCategory.A03_INJECTION,
    "server-side request forgery": OWASPCategory.A10_SSRF,
    "server side request forgery": OWASPCategory.A10_SSRF,
}


def map_owasp(finding_title: str, finding_desc: str = "") -> list[OWASPCategory]:
    """Map a finding title to OWASP Top 10 categories.

    Args:
        finding_title: Finding title or description.
        finding_desc: Optional additional description.

    Returns:
        List of matching OWASP categories.
    """
    combined = f"{finding_title} {finding_desc}".lower()
    categories: list[OWASPCategory] = []

    for key, category in _FINDING_OWASP_MAP.items():
        if key in combined and category not in categories:
            categories.append(category)

    # Default: inject if contains injection keywords
    if not categories:
        for kw in ("inject", "xss", "sqli", "cmdi", "ssrf", "xxe"):
            if kw in combined:
                categories.append(OWASPCategory.A03_INJECTION)
                break

    return categories


# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────

_MITRE_MAP = {
    "xss": ["T1189"],  # Drive-by Compromise
    "sqli": ["T1190"],  # Exploit Public-Facing Application
    "sql injection": ["T1190"],  # Full term
    "ssrf": ["T1557"],  # Adversary-in-the-Middle
    "command injection": ["T1059"],  # Full term
    "cmdi": ["T1059"],  # Short form
    "path traversal": ["T1083"],  # File and Directory Discovery
    "xxe": ["T1559"],  # Inter-Component Communication
    "csrf": ["T1556"],  # Modify Authentication Mechanism
    "header injection": ["T1556"],  # Modify Authentication Mechanism
    "rate limiting": ["T1041"],  # Exfiltration Over C2 Channel
    "auth bypass": ["T1078"],  # Valid Accounts
    "privilege escalation": ["T1078"],  # Valid Accounts
}


def map_mitre(finding_title: str) -> list[str]:
    """Map a finding title to MITRE ATT&CK techniques.

    Args:
        finding_title: Finding title.

    Returns:
        List of MITRE ATT&CK technique IDs.
    """
    title = finding_title.lower()
    techniques: list[str] = []

    for key, mitre_ids in _MITRE_MAP.items():
        if key in title and mitre_ids:
            techniques.extend(mitre_ids)

    return list(set(techniques))


# ── Remediation recommendations ───────────────────────────────────────────────

_REMEDIATION_DB = {
    "xss": {
        "summary": "Implement output encoding and Content Security Policy",
        "details": (
            "1. Encode all user-supplied output based on context (HTML, JS, CSS, URL)\n"
            "2. Implement Content Security Policy (CSP) headers\n"
            "3. Use httpOnly and Secure flags on cookies\n"
            "4. Consider framework-level XSS protection (React, Angular auto-encode)\n"
            "5. Implement input validation as defense-in-depth"
        ),
    },
    "sqli": {
        "summary": "Use parameterized queries and input validation",
        "details": (
            "1. Use parameterized queries (prepared statements) exclusively\n"
            "2. Implement input validation and sanitization\n"
            "3. Use ORM frameworks that abstract SQL generation\n"
            "4. Apply least-privilege database permissions\n"
            "5. Implement Web Application Firewall (WAF) rules"
        ),
    },
    "sql injection": {
        "summary": "Use parameterized queries and input validation",
        "details": (
            "1. Use parameterized queries (prepared statements) exclusively\n"
            "2. Implement input validation and sanitization\n"
            "3. Use ORM frameworks that abstract SQL generation\n"
            "4. Apply least-privilege database permissions\n"
            "5. Implement Web Application Firewall (WAF) rules"
        ),
    },
    "ssrf": {
        "summary": "Validate and restrict URL inputs, block internal IPs",
        "details": (
            "1. Implement allowlist validation for URLs\n"
            "2. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)\n"
            "3. Disable HTTP redirects or validate redirect destinations\n"
            "4. Use network segmentation to limit server-side SSRF impact\n"
            "5. Implement egress filtering"
        ),
    },
    "path traversal": {
        "summary": "Validate and normalize file paths, use chroot",
        "details": (
            "1. Use allowlist of permitted directories\n"
            "2. Normalize paths and verify they stay within the allowed directory\n"
            "3. Use chroot or containerization\n"
            "4. Never use user input directly in file path construction\n"
            "5. Implement proper access controls on file system"
        ),
    },
    "command injection": {
        "summary": "Avoid shell execution, use parameterized APIs",
        "details": (
            "1. Avoid system() and shell=True in subprocess calls\n"
            "2. Use library functions instead of command-line tools\n"
            "3. If shell execution is necessary, use list-based subprocess calls\n"
            "4. Implement strict input validation and allowlisting\n"
            "5. Run commands with minimal privileges"
        ),
    },
    "xxe": {
        "summary": "Disable external entity processing in XML parsers",
        "details": (
            "1. Disable DTDs and external entity processing in XML parsers\n"
            "2. Use JSON instead of XML where possible\n"
            "3. Implement XML parser security configurations\n"
            "4. Validate XML input with strict schemas\n"
            "5. Apply principle of least privilege to file read permissions"
        ),
    },
    "rate limiting": {
        "summary": "Implement rate limiting on sensitive endpoints",
        "details": (
            "1. Apply rate limiting to authentication endpoints (5-10 attempts/minute)\n"
            "2. Implement progressive delays and account lockouts\n"
            "3. Use CAPTCHA after failed attempts\n"
            "4. Monitor for brute force patterns\n"
            "5. Implement IP-based and account-based rate limiting"
        ),
    },
    "auth bypass": {
        "summary": "Fix authentication logic, implement multi-factor auth",
        "details": (
            "1. Review and fix authentication bypass logic\n"
            "2. Implement MFA/2FA\n"
            "3. Use established authentication libraries\n"
            "4. Implement proper session management\n"
            "5. Add password complexity requirements and breach checking"
        ),
    },
}


def get_remediation(finding_title: str) -> dict[str, str]:
    """Get remediation recommendation for a finding.

    Args:
        finding_title: Finding title.

    Returns:
        Dict with 'summary' and 'details' keys.
    """
    title_lower = finding_title.lower()
    for key, remediation in _REMEDIATION_DB.items():
        if key in title_lower:
            return {
                "summary": remediation["summary"],
                "details": remediation["details"],
            }
    return {
        "summary": "Review and remediate based on OWASP guidelines",
        "details": "Consult the OWASP Top 10 and application security best practices for remediation guidance.",
    }


# ── Report generation ─────────────────────────────────────────────────────────


@dataclass
class ReportConfig:
    """Configuration for report generation.

    Attributes:
        target_name: Display name for the target.
        target_url: Base URL of the target.
        run_id: Scan run identifier.
        generated_at: Report generation timestamp.
        include_evidence: Include raw evidence in report.
        include_remediation: Include remediation recommendations.
        include_owasp: Include OWASP Top 10 mapping.
        include_mitre: Include MITRE ATT&CK mapping.
        include_cvss: Include CVSS-like scores.
        include_summary: Include executive summary.
    """
    target_name: str = "Target Application"
    target_url: str = ""
    run_id: str = "unknown"
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    include_evidence: bool = True
    include_remediation: bool = True
    include_owasp: bool = True
    include_mitre: bool = True
    include_cvss: bool = True
    include_summary: bool = True


def _format_severity(score: float) -> str:
    """Format CVSS score with severity label."""
    if score >= 9.0:
        return f"{score:.1f} (Critical)"
    elif score >= 7.0:
        return f"{score:.1f} (High)"
    elif score >= 4.0:
        return f"{score:.1f} (Medium)"
    elif score >= 0.1:
        return f"{score:.1f} (Low)"
    return f"{score:.1f} (Informational)"


def _format_finding(findings_item: dict[str, Any], config: ReportConfig, index: int) -> list[str]:
    """Format a single finding into report lines."""
    lines: list[str] = []
    title = findings_item.get("title", "Unknown Finding")
    severity = findings_item.get("severity", "medium")
    confidence = findings_item.get("confidence", "medium")
    cwe = findings_item.get("cwe", [])

    score = compute_cvss_score(
        Finding(
            id=findings_item.get("id", f"F-{index:03d}"),
            run_id=config.run_id,
            target_id="target",
            title=title,
            severity=severity,
            confidence=confidence,
            affected={"url": findings_item.get("affected", {}).get("url", "N/A")},
        ),
    ) if config.include_cvss else 0.0

    lines.append(f"### {index}. {title}")
    lines.append("")

    lines.append(f"- **Severity**: {severity.upper()} ({_format_severity(score)})")
    lines.append(f"- **Confidence**: {confidence.upper()}")

    if cwe:
        cwe_str = ", ".join(cwe)
        lines.append(f"- **CWE**: {cwe_str}")

    if config.include_owasp:
        owasp_cats = map_owasp(title)
        if owasp_cats:
            lines.append(f"- **OWASP**: {', '.join(c.value for c in owasp_cats)}")

    if config.include_mitre:
        mitre_ids = map_mitre(title)
        if mitre_ids:
            lines.append(f"- **MITRE ATT&CK**: {', '.join(mitre_ids)}")

    if config.include_summary:
        affected = findings_item.get("affected", {})
        url = affected.get("url", affected.get("endpoint", "N/A"))
        if isinstance(url, dict):
            url = url.get("url", "N/A")
        lines.append(f"- **Affected URL**: `{url}`")

    description = findings_item.get("description", "")
    if description:
        lines.append(f"\n{description}")

    # Evidence
    if config.include_evidence:
        evidence = findings_item.get("evidence", {})
        response = evidence.get("response", evidence.get("raw_response", ""))
        if response:
            lines.append(f"\n**Evidence:**\n```\n{str(response)[:500]}\n```")

    # Remediation
    if config.include_remediation:
        rem = get_remediation(title)
        lines.append(f"\n**Remediation:** {rem['summary']}")
        lines.append(f"\n{rem['details']}")

    lines.append("")
    return lines


def generate_report(
    findings: list[dict[str, Any]],
    config: ReportConfig | None = None,
    *,
    scan_metadata: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
) -> str:
    """Generate a structured Markdown security report.

    Args:
        findings: List of finding dicts from scan results.
        config: Optional report configuration.
        scan_metadata: Optional scan metadata (target info, timestamps, etc.)
        warnings: Optional list of warnings.

    Returns:
        Formatted Markdown report string.
    """
    if config is None:
        config = ReportConfig()

    if scan_metadata is None:
        scan_metadata = {
            "target": config.target_name,
            "url": config.target_url,
            "run_id": config.run_id,
        }

    lines: list[str] = []

    # Header
    lines.append(f"# Security Assessment Report: {config.target_name}")
    lines.append("")
    lines.append(f"**Generated**: {config.generated_at}")
    lines.append(f"**Run ID**: `{config.run_id}`")
    lines.append(f"**Target**: {config.target_url}")
    lines.append("")

    # Matrix
    matrix = risk_matrix(findings)
    total = sum(matrix.values())
    lines.append("## Summary")
    lines.append("")
    lines.append(f"Total findings: **{total}**")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low", "informational"):
        count = matrix.get(sev, 0)
        lines.append(f"| {sev.upper()} | {count} |")
    lines.append("")

    # Risk level
    risk = overall_risk_level(matrix)
    risk_labels = {
        RiskLevel.CRITICAL: "🔴 CRITICAL",
        RiskLevel.HIGH: "🟠 HIGH",
        RiskLevel.MEDIUM: "🟡 MEDIUM",
        RiskLevel.LOW: "🟢 LOW",
        RiskLevel.INFO: "⚪ INFORMATIONAL",
    }
    lines.append(f"**Overall Risk Level**: {risk_labels.get(risk, risk)}")
    lines.append("")

    # Executive summary
    if config.include_summary:
        lines.append("## Executive Summary")
        lines.append("")
        critical = matrix.get("critical", 0)
        high = matrix.get("high", 0)
        medium = matrix.get("medium", 0)
        low = matrix.get("low", 0)

        if critical > 0:
            lines.append(f"**{critical} critical** and **{high} high** severity findings were identified. "
                         "Immediate remediation is required for these findings as they can lead to "
                         "compromise of the target application, data breach, or unauthorized access.")
        elif high > 0:
            lines.append(f"**{high} high** and **{medium} medium** severity findings were identified. "
                         "These should be addressed in the next development cycle.")
        elif medium > 0:
            lines.append(f"**{medium} medium** and **{low} low** severity findings were identified. "
                         "Remediation should be scheduled in the upcoming sprint.")
        else:
            lines.append("Low-severity findings detected. Review recommended during routine security reviews.")
        lines.append("")

        # Prioritized action items
        lines.append("### Prioritized Actions")
        lines.append("")
        action_num = 1
        if critical > 0:
            lines.append(f"{action_num}. **CRITICAL**: Immediately investigate and remediate {critical} critical findings")
            action_num += 1
        if high > 0:
            lines.append(f"{action_num}. **HIGH**: Address {high} high-severity findings within 24-48 hours")
            action_num += 1
        if medium > 0:
            lines.append(f"{action_num}. **MEDIUM**: Plan remediation for {medium} medium-severity findings")
            action_num += 1
        if low > 0:
            lines.append(f"{action_num}. **LOW**: Review {low} low-severity findings")
            action_num += 1
        lines.append("")

    # Detailed findings
    if findings:
        lines.append("## Detailed Findings")
        lines.append("")

        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "medium"), 2))

        for i, finding in enumerate(sorted_findings, 1):
            lines.extend(_format_finding(finding, config, i))

    # Warnings
    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for warning in warnings:
            lines.append(f"- {redact_secrets(warning)}")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append(f"*Report generated by Hermes Security Harness at {config.generated_at}*")

    return "\n".join(lines)


def generate_json_report(
    findings: list[dict[str, Any]],
    config: ReportConfig | None = None,
    *,
    scan_metadata: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a structured JSON report.

    Args:
        findings: List of finding dicts.
        config: Optional report configuration.
        scan_metadata: Optional scan metadata.
        warnings: Optional warnings.

    Returns:
        Dict with structured report data.
    """
    if config is None:
        config = ReportConfig()

    matrix = risk_matrix(findings)
    risk = overall_risk_level(matrix)
    total = sum(matrix.values())

    # Compute CVSS for each finding
    enriched_findings: list[dict[str, Any]] = []
    for i, f in enumerate(findings, 1):
        score = compute_cvss_score(
            Finding(
                id=f.get("id", f"F-{i:03d}"),
                run_id=config.run_id,
                target_id="target",
                title=f.get("title", "Unknown"),
                severity=f.get("severity", "medium"),
                confidence=f.get("confidence", "medium"),
                affected={"url": f.get("affected", {}).get("url", "N/A")},
            ),
        ) if config.include_cvss else 0.0

        enriched_f = {
            "index": i,
            "title": f.get("title", "Unknown"),
            "severity": f.get("severity", "medium"),
            "score": score,
            "confidence": f.get("confidence", "medium"),
            "owasp": map_owasp(f.get("title", "")) if config.include_owasp else [],
            "mitre": map_mitre(f.get("title", "")) if config.include_mitre else [],
            "remediation": get_remediation(f.get("title", "")) if config.include_remediation else {},
        }
        if config.include_evidence and "evidence" in f:
            enriched_f["evidence"] = f["evidence"]
        enriched_findings.append(enriched_f)

    return {
        "reportVersion": "security-report/v1",
        "generatedAt": config.generated_at,
        "target": {
            "name": config.target_name,
            "url": config.target_url,
        },
        "summary": {
            "totalFindings": total,
            "matrix": matrix,
            "overallRisk": risk.value,
            "runId": config.run_id,
        },
        "findings": enriched_findings,
        "warnings": warnings or [],
    }


def write_report(
    findings: list[dict[str, Any]],
    output_path: str | Path,
    config: ReportConfig | None = None,
    *,
    scan_metadata: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
) -> Path:
    """Write report to file.

    Args:
        findings: List of finding dicts.
        output_path: Path to write report (auto-detect format from extension).
        config: Optional report configuration.
        scan_metadata: Optional scan metadata.
        warnings: Optional warnings.

    Returns:
        Path to written file.
    """
    output_path = Path(output_path).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.suffix in (".json", ".jsonl"):
        report_data = generate_json_report(findings, config, scan_metadata=scan_metadata, warnings=warnings)
        import json
        output_path.write_text(json.dumps(report_data, indent=2) + "\n")
    else:
        report_text = generate_report(findings, config, scan_metadata=scan_metadata, warnings=warnings)
        output_path.write_text(report_text)

    return output_path
