"""Common base classes and utilities for WSTG-aligned scan modules.

Provides reusable base classes that all scanner modules can inherit from,
reducing code duplication across scan modules.
"""
from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._http_client import new_run_id, write_json


# --- Base Result class ---

@dataclass
class BaseScanResult:
    """Base result dataclass for all scan modules.

    Subclasses add module-specific fields.
    """
    run_id: str
    target_id: str
    findings: list[dict[str, Any]]
    total_requests: int
    endpoints_tested: int
    success: bool = True
    artifacts: dict[str, str] = field(default_factory=dict)

    def to_summary(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "run_id": self.run_id,
            "target_id": self.target_id,
            "finding_count": len(self.findings),
            "total_requests": self.total_requests,
            "endpoints_tested": self.endpoints_tested,
            "findings": self.findings,
        }

    @property
    def finding_count(self) -> int:
        return len(self.findings)


# --- Base Config class ---

@dataclass
class BaseScanConfig:
    """Base config dataclass for all scan modules.

    Subclasses add module-specific fields.
    """
    base_url: str
    endpoints: list[str]
    request_timeout: float = 5.0

    def __post_init__(self) -> None:
        if not self.endpoints:
            raise ValueError("Config requires at least one endpoint to test")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be a valid URL")


# --- Base scan runner function ---

def _run_scan(
    config_path: str,
    run_func,
    *,
    scan_name: str,
    artifact_name: str,
    artifacts_root: str = "runs",
    request_timeout: float = 5.0,
    extra_endpoints: list[str] | None = None,
) -> dict[str, Any]:
    """Run a WSTG-aligned scan with common boilerplate.

    Args:
        config_path: Path to YAML target config.
        run_func: Function called for each endpoint, receiving (base_url, endpoint, timeout) and returning (requests_sent, findings_list).
        scan_name: Name for the scan (used in run_id prefix and artifact dir).
        artifact_name: Name for the artifact file.
        artifacts_root: Output directory.
        request_timeout: Request timeout in seconds.
        extra_endpoints: Additional endpoints to append.

    Returns:
        dict with success, error, and result fields.
    """
    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f)

        target_id = raw.get("id", "unknown")
        base_url = raw.get("baseUrl", "").rstrip("/")

        all_findings: list[dict[str, Any]] = []
        total_requests = 0
        endpoints = list(extra_endpoints or [])

        # Load endpoints from config if available
        config_endpoints = raw.get("detectors", {}).get("enabled", [])
        if config_endpoints and not extra_endpoints:
            endpoints.extend(str(e) for e in config_endpoints)

        for endpoint in endpoints:
            try:
                requests, findings = run_func(base_url, endpoint, request_timeout)
                total_requests += requests
                all_findings.extend(findings)
            except Exception as exc:
                all_findings.append({
                    "id": f"{scan_name}-error-{endpoint}",
                    "title": f"{scan_name} error on {endpoint}",
                    "severity": "LOW",
                    "description": f"Error testing {endpoint}: {exc}",
                    "confidence": "LOW",
                    "remediation": f"Check endpoint {endpoint} is reachable and properly configured",
                })

        run_id = new_run_id(scan_name, target_id)
        run_dir = Path(artifacts_root).expanduser().resolve() / f"{scan_name}-{run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)

        summary_path = run_dir / f"{artifact_name}.json"
        result = {
            "success": True,
            "run_id": run_id,
            "target_id": target_id,
            "finding_count": len(all_findings),
            "total_requests": total_requests,
            "endpoints_tested": len(endpoints),
            "findings": all_findings,
            "artifacts": {artifact_name: str(summary_path)},
        }

        write_json(summary_path, result)
        return result

    except Exception as exc:
        return {"success": False, "error": str(exc)}
