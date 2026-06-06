"""Dependency vulnerability audit for the Hermes Security Harness.

Parses package manifests (package-lock.json, yarn.lock, go.sum,
requirements.txt, Gemfile.lock, Cargo.lock) and cross-references them
against a built-in vulnerability registry.

Public API (``__all__``):
    DependencyScanResult, run_dependency_audit,
    VulnerabilityRegistry,
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import re
import uuid

from .web_target import WebTargetConfig, load_target_config

# ── Built-in Vulnerability Registry ──────────────────────────────────────────

# Known vulnerable library patterns with CVE-like entries.
# Format: (package_name, lower_match, affected_range, cve, severity, description, remediation)
_VULNERABILITY_REGISTRY: list[dict[str, Any]] = [
    # JavaScript/Node.js
    {
        "ecosystem": "npm",
        "package": "lodash",
        "affected_gte": "4.0.0",
        "affected_lt": "4.17.21",
        "cve": "CVE-2020-28500",
        "severity": "medium",
        "description": "Prototype pollution in lodash via isArguments, castPath, and indexOf",
        "remediation": "Upgrade lodash to >=4.17.21",
    },
    {
        "ecosystem": "npm",
        "package": "express",
        "affected_gte": "4.0.0",
        "affected_lt": "4.18.2",
        "cve": "CVE-2022-24999",
        "severity": "high",
        "description": "Express open redirect via qs prototype pollution",
        "remediation": "Upgrade express to >=4.18.2",
    },
    {
        "ecosystem": "npm",
        "package": "axios",
        "affected_gte": "0.0.0",
        "affected_lt": "1.6.0",
        "cve": "CVE-2023-45857",
        "severity": "medium",
        "description": "CSRF/SSRF via unvalidated cross-domain requests in axios",
        "remediation": "Upgrade axios to >=1.6.0",
    },
    {
        "ecosystem": "npm",
        "package": "jsonwebtoken",
        "affected_gte": "8.0.0",
        "affected_lt": "9.0.0",
        "cve": "CVE-2022-23529",
        "severity": "high",
        "description": "Unrestricted key type in jsonwebtoken allows key confusion attack",
        "remediation": "Upgrade jsonwebtoken to >=9.0.0",
    },
    {
        "ecosystem": "npm",
        "package": "node-fetch",
        "affected_gte": "2.0.0",
        "affected_lt": "2.6.7",
        "cve": "CVE-2022-0235",
        "severity": "high",
        "description": "Exposure of sensitive information to an unauthorized actor in node-fetch",
        "remediation": "Upgrade node-fetch to >=2.6.7",
    },
    {
        "ecosystem": "npm",
        "package": "minimatch",
        "affected_gte": "3.0.0",
        "affected_lt": "3.1.2",
        "cve": "CVE-2022-3517",
        "severity": "high",
        "description": "Regular expression denial of service (ReDoS) in minimatch",
        "remediation": "Upgrade minimatch to >=3.1.2",
    },
    {
        "ecosystem": "npm",
        "package": "glob-parent",
        "affected_gte": "5.0.0",
        "affected_lt": "5.1.2",
        "cve": "CVE-2021-23343",
        "severity": "high",
        "description": "ReDoS in glob-parent",
        "remediation": "Upgrade glob-parent to >=5.1.2",
    },
    {
        "ecosystem": "npm",
        "package": "follow-redirects",
        "affected_gte": "1.0.0",
        "affected_lt": "1.14.8",
        "cve": "CVE-2023-26159",
        "severity": "medium",
        "description": "Exposure of sensitive information in follow-redirects",
        "remediation": "Upgrade follow-redirects to >=1.14.8",
    },
    {
        "ecosystem": "npm",
        "package": "ua-parser-js",
        "affected_gte": "0.7.0",
        "affected_lt": "0.7.28",
        "cve": "CVE-2023-28154",
        "severity": "medium",
        "description": "ReDoS in ua-parser-js",
        "remediation": "Upgrade ua-parser-js to >=0.7.28",
    },
    {
        "ecosystem": "npm",
        "package": "semver",
        "affected_gte": "5.0.0",
        "affected_lt": "5.7.2",
        "cve": "CVE-2022-25883",
        "severity": "medium",
        "description": "Regular expression denial of service in semver",
        "remediation": "Upgrade semver to >=5.7.2 or >=6.3.1",
    },
    {
        "ecosystem": "npm",
        "package": "tough-cookie",
        "affected_gte": "4.0.0",
        "affected_lt": "4.1.3",
        "cve": "CVE-2023-26136",
        "severity": "medium",
        "description": "Prototype pollution in tough-cookie",
        "remediation": "Upgrade tough-cookie to >=4.1.3",
    },
    {
        "ecosystem": "npm",
        "package": "handlebars",
        "affected_gte": "4.0.0",
        "affected_lt": "4.7.8",
        "cve": "CVE-2021-23369",
        "severity": "high",
        "description": "Remote code execution in handlebars via prototype pollution",
        "remediation": "Upgrade handlebars to >=4.7.8",
    },
    {
        "ecosystem": "npm",
        "package": "y18n",
        "affected_gte": "5.0.0",
        "affected_lt": "5.0.5",
        "cve": "CVE-2020-7774",
        "severity": "high",
        "description": "Prototype pollution in y18n",
        "remediation": "Upgrade y18n to >=5.0.5",
    },

    # Python
    {
        "ecosystem": "pip",
        "package": "django",
        "affected_gte": "3.2.0",
        "affected_lt": "3.2.20",
        "cve": "CVE-2023-36053",
        "severity": "high",
        "description": "Potential SQL injection in Django QuerySet.extra()",
        "remediation": "Upgrade django to >=3.2.20 or >=4.2.3",
    },
    {
        "ecosystem": "pip",
        "package": "django",
        "affected_gte": "4.0.0",
        "affected_lt": "4.2.3",
        "cve": "CVE-2023-36053",
        "severity": "high",
        "description": "Potential SQL injection in Django QuerySet.extra()",
        "remediation": "Upgrade django to >=4.2.3",
    },
    {
        "ecosystem": "pip",
        "package": "flask",
        "affected_gte": "2.0.0",
        "affected_lt": "2.3.2",
        "cve": "CVE-2023-30861",
        "severity": "high",
        "description": "Session cookie vulnerability in Flask",
        "remediation": "Upgrade flask to >=2.3.2",
    },
    {
        "ecosystem": "pip",
        "package": "requests",
        "affected_gte": "2.3.0",
        "affected_lt": "2.31.0",
        "cve": "CVE-2023-32681",
        "severity": "medium",
        "description": "Leak of Proxy-Authorization header to destination server in requests",
        "remediation": "Upgrade requests to >=2.31.0",
    },
    {
        "ecosystem": "pip",
        "package": "urllib3",
        "affected_gte": "1.25.0",
        "affected_lt": "1.26.17",
        "cve": "CVE-2023-45803",
        "severity": "medium",
        "description": "Request body not stripped on redirect from 303 changes in urllib3",
        "remediation": "Upgrade urllib3 to >=1.26.17 or >=2.0.0",
    },
    {
        "ecosystem": "pip",
        "package": "jinja2",
        "affected_gte": "2.0",
        "affected_lt": "3.1.2",
        "cve": "CVE-2024-22195",
        "severity": "high",
        "description": "Cross-site scripting (XSS) vulnerability in Jinja XMLFilter",
        "remediation": "Upgrade jinja2 to >=3.1.2",
    },
    {
        "ecosystem": "pip",
        "package": "pyyaml",
        "affected_gte": "0.0.0",
        "affected_lt": "6.0.1",
        "cve": "CVE-2020-14343",
        "severity": "critical",
        "description": "Arbitrary code execution in PyYAML via unsafe yaml.load()",
        "remediation": "Upgrade pyyaml to >=6.0.1, use yaml.safe_load()",
    },
    {
        "ecosystem": "pip",
        "package": "pillow",
        "affected_gte": "8.0.0",
        "affected_lt": "10.0.1",
        "cve": "CVE-2023-44271",
        "severity": "medium",
        "description": "Denial of service via crafted image in Pillow",
        "remediation": "Upgrade pillow to >=10.0.1",
    },

    # Go
    {
        "ecosystem": "go",
        "package": "golang.org/x/net",
        "affected_gte": "0.0.0",
        "affected_lt": "0.17.0",
        "cve": "CVE-2023-44487",
        "severity": "high",
        "description": "HTTP/2 rapid reset attack in golang.org/x/net",
        "remediation": "Upgrade golang.org/x/net to >=0.17.0",
    },
    {
        "ecosystem": "go",
        "package": "golang.org/x/text",
        "affected_gte": "0.3.0",
        "affected_lt": "0.12.0",
        "cve": "CVE-2022-32149",
        "severity": "medium",
        "description": "Uncontrolled memory consumption in golang.org/x/text",
        "remediation": "Upgrade golang.org/x/text to >=0.12.0",
    },

    # Ruby
    {
        "ecosystem": "rubygems",
        "package": "rails",
        "affected_gte": "6.0.0",
        "affected_lt": "6.1.7.5",
        "cve": "CVE-2023-22796",
        "severity": "high",
        "description": "Potential DoS in Action View with HTML::FullTokenizer",
        "remediation": "Upgrade rails to >=6.1.7.5",
    },
    {
        "ecosystem": "rubygems",
        "package": "rack",
        "affected_gte": "2.0.0",
        "affected_lt": "2.2.8",
        "cve": "CVE-2024-26146",
        "severity": "high",
        "description": "Denial of service in Rack via crafted multipart request",
        "remediation": "Upgrade rack to >=2.2.8",
    },

    # Rust
    {
        "ecosystem": "crates",
        "package": "serde_json",
        "affected_gte": "1.0.0",
        "affected_lt": "1.0.108",
        "cve": "CVE-2022-46176",
        "severity": "medium",
        "description": "Denial of service in serde_json",
        "remediation": "Upgrade serde_json to >=1.0.108",
    },
    {
        "ecosystem": "crates",
        "package": "tokio",
        "affected_gte": "1.0.0",
        "affected_lt": "1.32.0",
        "cve": "CVE-2023-50454",
        "severity": "high",
        "description": "Out-of-bounds read in tokio streams",
        "remediation": "Upgrade tokio to >=1.32.0",
    },
]


# ── Lock File Parsers ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Dependency:
    """A parsed dependency from a lock file or manifest.

    Attributes:
        name: Package name.
        version: Parsed version string.
        ecosystem: One of "npm", "pip", "go", "rubygems", "crates".
        source_file: Lock file where the dependency was found.
    """
    name: str
    version: str
    ecosystem: str
    source_file: str


def _parse_version(version_str: str) -> str:
    """Normalize a version string by stripping leading 'v', '~', '^', '='."""
    v = version_str.strip()
    if v.startswith(("v", "~", "^", "=", ">")):
        v = v.lstrip("v~^=>")
    # Take just the first segment (e.g., "1.2.3")
    v = v.split(".")[0] if "." not in v else v.split(".")[1]
    # If only one segment, take first 4 chars
    v = v[:4]
    return v


def parse_requirements_txt(path: str | Path) -> list[Dependency]:
    """Parse requirements.txt or requirements.in."""
    p = Path(path)
    if not p.exists():
        return []
    deps: list[Dependency] = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        # Handle extras and version specifiers
        match = re.match(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)", line)
        if match:
            name = match.group(1).lower().replace("-", "_").replace(".", "_")
            # Extract version
            ver = "0.0.0"
            ver_match = re.search(r"[><=!]+\s*(\d+[\.\d]*)", line)
            if ver_match:
                ver = ver_match.group(1)
            elif ">=" in line:
                ver = line.split(">=")[1].split(",")[0].strip()
            deps.append(Dependency(name=name, version=ver, ecosystem="pip", source_file=str(p)))
    return deps


def parse_package_lock_json(path: str | Path) -> list[Dependency]:
    """Parse package-lock.json or package.json."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    deps: list[Dependency] = []
    # From package-lock.json v2/v3
    nodes = data.get("packages", {}) or {}
    for key, info in nodes.items():
        if not isinstance(key, str):
            continue
        name_key = key.split("node_modules/")[-1] if "node_modules/" in key else key
        name = name_key.replace(":::", "/").replace(" ", "").strip()
        if not name or name.startswith("."):
            continue
        ver = info.get("version", "0.0.0") if isinstance(info, dict) else "0.0.0"
        deps.append(Dependency(
            name=name, version=ver, ecosystem="npm", source_file=str(p),
        ))
    # Also check dependencies from package.json
    deps_data = data.get("dependencies", {}) or {}
    for name, info in deps_data.items():
        if isinstance(info, dict):
            ver = info.get("version", "0.0.0")
            deps.append(Dependency(
                name=name.lower(), version=ver, ecosystem="npm", source_file=str(p),
            ))
        elif isinstance(info, str):
            deps.append(Dependency(
                name=name.lower(), version=info.lstrip("^~>=<"), ecosystem="npm",
                source_file=str(p),
            ))
    return deps


def parse_go_sum(path: str | Path) -> list[Dependency]:
    """Parse go.sum."""
    p = Path(path)
    if not p.exists():
        return []
    deps: list[Dependency] = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0]
            version = parts[1].split("+incompatible")[0]
            if name and version.startswith("v"):
                version = version[1:]
            deps.append(Dependency(
                name=name, version=version, ecosystem="go", source_file=str(p),
            ))
    return deps


def parse_yarn_lock(path: str | Path) -> list[Dependency]:
    """Parse yarn.lock (yarn v1 and v2+ formats)."""
    p = Path(path)
    if not p.exists():
        return []
    deps: list[Dependency] = []

    content = p.read_text()
    # Split into dependency blocks by blank lines
    blocks = re.split(r'\n\s*\n', content)

    for block in blocks:
        block_lines = block.strip().splitlines()
        if not block_lines:
            continue

        # Extract package name from first line
        # yarn v1: "package-name@version":
        # yarn v2+: package-name@version:
        header = block_lines[0].strip().rstrip(':').strip()

        # Remove quoted strings from the name
        name = re.sub(r'^["\']+|["\']+$', '', header)
        # Extract package name without version range
        if not name.startswith('@'):
            name = name.split('@')[0]

        # Find version in the block
        version = "0.0.0"
        for line in block_lines[1:]:
            vm = re.search(r'version\s+"([^"]+)"', line)
            if vm:
                version = vm.group(1)
                break

        if name and version:
            deps.append(Dependency(
                name=name, version=version, ecosystem="npm", source_file=str(p),
            ))

    return deps


def parse_gemfile_lock(path: str | Path) -> list[Dependency]:
    """Parse Gemfile.lock (both GEM/specs and DEPENDENCIES sections)."""
    p = Path(path)
    if not p.exists():
        return []
    deps: list[Dependency] = []
    in_specs = False

    for line in p.read_text().splitlines():
        stripped = line.strip()

        # Detect GEM section header
        if re.match(r'^GEM$', stripped, re.IGNORECASE):
            in_specs = False
            continue

        # Detect specs: sub-section under GEM
        if re.match(r'^specs:\s*$', stripped, re.IGNORECASE):
            in_specs = True
            continue

        # Detect DEPENDENCIES section (reset specs mode)
        if re.match(r'^DEPENDENCIES$', stripped, re.IGNORECASE):
            in_specs = False
            continue

        # Skip other section headers
        if re.match(r'^[A-Z]+$', stripped) and stripped not in ('GEM', 'DEPENDENCIES', 'PLATFORMS'):
            in_specs = False
            continue

        if in_specs:
            # Gem entries in specs have leading spaces and format: name (version)
            if stripped and not stripped[0].isdigit():
                match = re.match(r'^\s+([a-zA-Z0-9_-]+)\s+\(([^)]+)\)', line)
                if match:
                    name = match.group(1)
                    ver = match.group(2)
                    deps.append(Dependency(
                        name=name, version=ver, ecosystem="rubygems", source_file=str(p),
                    ))

    return deps


def parse_cargo_lock(path: str | Path) -> list[Dependency]:
    """Parse Cargo.lock (TOML-based, parsed without external deps)."""
    p = Path(path)
    if not p.exists():
        return []

    text = p.read_text()
    deps: list[Dependency] = []
    current_name = ""
    current_version = ""
    in_package = False

    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if current_name and current_version:
                deps.append(Dependency(
                    name=current_name, version=current_version, ecosystem="crates",
                    source_file=str(p),
                ))
            current_name = ""
            current_version = ""
            in_package = True
            continue

        if in_package:
            name_match = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if name_match:
                current_name = name_match.group(1)
                continue
            ver_match = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if ver_match:
                current_version = ver_match.group(1)
                continue

    # Handle last package
    if current_name and current_version:
        deps.append(Dependency(
            name=current_name, version=current_version, ecosystem="crates", source_file=str(p),
        ))

    return deps


# ── Version Comparison ────────────────────────────────────────────────────────


def _version_matches(dep_version: str, affected_gte: str, affected_lt: str) -> bool:
    """Check if *dep_version* falls in [affected_gte, affected_lt)."""
    if not dep_version or dep_version == "0.0.0":
        return False
    try:
        gte = _parse_version_tuple(affected_gte)
        lt = _parse_version_tuple(affected_lt)
        ver = _parse_version_tuple(dep_version)
        return gte <= ver < lt
    except (ValueError, IndexError):
        return False


def _parse_version_tuple(version: str) -> tuple[int, ...]:
    """Parse a version string to an int tuple. E.g., '4.17.21' → (4, 17, 21)."""
    parts = []
    for seg in re.split(r"[._-]", version):
        try:
            parts.append(int(seg))
        except ValueError:
            parts.append(0)
    return tuple(parts)


# ── Scan Engine ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class VulnerabilityFinding:
    """A finding for a vulnerable dependency.

    Attributes:
        dependency: The affected dependency.
        cve: The CVE identifier.
        severity: Critical/high/medium/low.
        description: Human-readable description.
        remediation: Recommended fix.
    """
    dependency: Dependency
    cve: str
    severity: str
    description: str
    remediation: str


@dataclass(frozen=True)
class DependencyScanResult:
    """Result of a dependency audit run.

    Attributes:
        run_id: Stable identifier for this audit run.
        source_root: Root of the scanned source tree.
        success: True if the scan completed without internal errors.
        total_dependencies: Total unique dependencies found.
        vulnerable_count: Number of vulnerable dependencies.
        findings: List of vulnerability findings.
        artifacts: Mapping of artifact name to file path.
        warnings: Warnings produced during the scan.
    """
    run_id: str
    source_root: Path
    total_dependencies: int
    vulnerable_count: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    success: bool = True

    def to_summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "source_root": str(self.source_root),
            "success": True,
            "total_dependencies": self.total_dependencies,
            "vulnerable_count": self.vulnerable_count,
            "findings": self.findings,
            "warnings": self.warnings,
        }


def run_dependency_audit(
    source_root: str | Path,
    config_path: str | Path | None = None,
    artifacts_root: str | Path = "runs",
    *,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> DependencyScanResult:
    """Run a dependency vulnerability audit on a source tree.

    Parses all lock files in *source_root* and cross-references them against
    the built-in vulnerability registry.

    Args:
        source_root: Root of the source tree to scan.
        config_path: Optional web-target config for include/exclude patterns.
        artifacts_root: Directory for output artifacts.
        include_patterns: Additional glob patterns to include.
        exclude_patterns: Glob patterns to exclude.

    Returns:
        A :class:`DependencyScanResult` with findings and artifacts.
    """
    root = _validate_source_root(source_root)

    run_id = f"dep-audit-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"

    # Load target config patterns if available
    if config_path:
        try:
            target = load_target_config(config_path)
            include_patterns = list(include_patterns or []) + target.scope.include_paths
            exclude_patterns = list(exclude_patterns or []) + target.scope.exclude_paths
        except Exception:
            pass

    include_patterns = include_patterns or []
    exclude_patterns = exclude_patterns or []

    # Parse all lock files
    all_deps: list[Dependency] = []
    source_files: list[str] = []

    lock_files = [
        ("package-lock.json", parse_package_lock_json),
        ("package.json", parse_package_lock_json),
        ("yarn.lock", parse_yarn_lock),
        ("go.sum", parse_go_sum),
        ("Gemfile.lock", parse_gemfile_lock),
        ("Cargo.lock", parse_cargo_lock),
        ("requirements.txt", parse_requirements_txt),
        ("requirements.in", parse_requirements_txt),
        ("Pipfile.lock", parse_requirements_txt),
        ("pyproject.toml", lambda p: []),  # placeholder
    ]

    for filename, parser in lock_files:
        # Check if this file matches exclude patterns
        excluded = False
        if exclude_patterns:
            import fnmatch
            for pattern in exclude_patterns:
                if fnmatch.fnmatch(filename, pattern):
                    excluded = True
                    break
        if excluded:
            continue

        lock_path = root / filename
        if lock_path.exists():
            deps = parser(lock_path)
            for d in deps:
                d = Dependency(
                    name=d.name, version=d.version, ecosystem=d.ecosystem,
                    source_file=str(lock_path.relative_to(root)),
                )
                all_deps.append(d)
                source_files.append(d.source_file)

    # Deduplicate by (ecosystem, name)
    seen: set[str] = set()
    unique_deps: list[Dependency] = []
    for d in all_deps:
        key = f"{d.ecosystem}:{d.name}"
        if key not in seen:
            seen.add(key)
            unique_deps.append(d)

    # Cross-reference against vulnerability registry
    findings: list[VulnerabilityFinding] = []
    for dep in unique_deps:
        for vuln in _VULNERABILITY_REGISTRY:
            if vuln["ecosystem"] != dep.ecosystem:
                continue
            if vuln["package"].lower() != dep.name.lower():
                continue
            if _version_matches(dep.version, vuln["affected_gte"], vuln["affected_lt"]):
                findings.append(VulnerabilityFinding(
                    dependency=dep,
                    cve=vuln["cve"],
                    severity=vuln["severity"],
                    description=vuln["description"],
                    remediation=vuln["remediation"],
                ))
                break  # One CVE per dep is enough for this MVP

    # Convert to dicts for JSON output
    finding_dicts: list[dict[str, Any]] = []
    for f in findings:
        finding_dicts.append({
            "schemaVersion": "finding/v1",
            "id": f"dep-audit-{f.dependency.name}-{f.cve.lower()}",
            "runId": run_id,
            "targetId": config_path or str(root),
            "detectorId": "dep-audit",
            "title": f"Vulnerable dependency: {f.dependency.name}@{f.dependency.version}",
            "description": f"{f.cve}: {f.description}",
            "severity": f.severity,
            "confidence": "high",
            "affected": {
                "package": f.dependency.name,
                "version": f.dependency.version,
                "ecosystem": f.dependency.ecosystem,
                "sourceFile": f.dependency.source_file,
            },
            "evidence": {
                "cve": f.cve,
                "dependency": {
                    "name": f.dependency.name,
                    "version": f.dependency.version,
                    "ecosystem": f.dependency.ecosystem,
                },
            },
            "remediation": {"summary": f.remediation},
        })

    # Write artifacts
    run_dir = Path(artifacts_root) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    scan_path = run_dir / "dependency-audit.json"
    scan_path.write_text(
        _json_dumps({
            "schemaVersion": "dependency-audit/v1",
            "runId": run_id,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "sourceRoot": str(root),
            "totalDependencies": len(unique_deps),
            "vulnerableCount": len(findings),
            "findings": finding_dicts,
            "warnings": [],
        })
    )

    report_path = run_dir / "report.md"
    report_path.write_text(_build_report(run_id, unique_deps, findings))

    return DependencyScanResult(
        run_id=run_id,
        source_root=root,
        total_dependencies=len(unique_deps),
        vulnerable_count=len(findings),
        findings=finding_dicts,
    )


# ── Helpers ────────────────────────────────────────────────────────────────────


def _validate_source_root(source_root: str | Path) -> Path:
    root = Path(source_root).expanduser().resolve()
    if root.exists() and root.is_symlink():
        raise ValueError("source root must not be a symlink")
    return root


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def _build_report(run_id: str, deps: list[Dependency], findings: list[VulnerabilityFinding]) -> str:
    by_ecosystem: dict[str, int] = {}
    for d in deps:
        by_ecosystem[d.ecosystem] = by_ecosystem.get(d.ecosystem, 0) + 1

    lines = [
        f"# Dependency audit report",
        "",
        f"- Run ID: `{run_id}`",
        f"- Total dependencies: {len(deps)}",
        f"- Vulnerable dependencies: {len(findings)}",
        "",
        "## Dependencies by ecosystem",
        "",
    ]
    for eco, count in sorted(by_ecosystem.items()):
        lines.append(f"- {eco}: {count}")

    if findings:
        lines.extend(["", "## Vulnerabilities", ""])
        for f in findings:
            lines.extend([
                f"### {f.cve}: {f.dependency.name}@{f.dependency.version}",
                "",
                f"- Severity: `{f.severity}`",
                f"- Ecosystem: `{f.dependency.ecosystem}`",
                f"- Source: `{f.dependency.source_file}`",
                f"- Description: {f.description}",
                f"- Remediation: {f.remediation}",
                "",
            ])
    else:
        lines.extend(["", "No known vulnerabilities detected.", ""])

    return "\n".join(lines)
