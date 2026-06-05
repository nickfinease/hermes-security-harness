"""Web target configuration and safety gates.

The MVP intentionally accepts only local/staging-style targets with explicit
host allowlists. It is not a generic public-URL scanner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import ipaddress
import json
import re

try:
    import yaml
except Exception:  # pragma: no cover - dependency declared, fallback defensive
    yaml = None


class TargetValidationError(ValueError):
    """Raised when a web target config is unsafe or malformed."""


_LINK_LOCAL_V4 = ipaddress.ip_network("169.254.0.0/16")
_LINK_LOCAL_V6 = ipaddress.ip_network("fe80::/10")
_METADATA_HOSTNAMES = {"metadata.google.internal"}
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$|^\[[0-9A-Fa-f:.]+\]$")


@dataclass(frozen=True)
class ScopeConfig:
    include_paths: list[str] = field(default_factory=lambda: ["/"])
    exclude_paths: list[str] = field(default_factory=list)
    max_requests: int = 100
    max_runtime_seconds: int = 300


@dataclass(frozen=True)
class LifecycleCommand:
    command: str | None = None
    cwd: str = "."
    required: bool = False


@dataclass(frozen=True)
class SafetyConfig:
    require_local_or_staging: bool = True
    require_allowed_host_match: bool = True
    block_cloud_metadata_ips: bool = True


@dataclass(frozen=True)
class WebTargetConfig:
    id: str
    name: str
    environment: str
    base_url: str
    allowed_hosts: list[str]
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    reset: LifecycleCommand = field(default_factory=LifecycleCommand)
    seed: LifecycleCommand = field(default_factory=LifecycleCommand)
    detectors_enabled: list[str] = field(default_factory=list)
    safety: SafetyConfig = field(default_factory=SafetyConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WebTargetConfig":
        if data.get("schemaVersion") != "web-target/v1":
            raise TargetValidationError("schemaVersion must be web-target/v1")
        target_id = _required_str(data, "id")
        name = _required_str(data, "name")
        environment = _required_str(data, "environment").lower()
        base_url = _required_str(data, "baseUrl")
        allowed_hosts_raw = list(data.get("allowedHosts") or [])
        if not allowed_hosts_raw:
            raise TargetValidationError("allowedHosts must contain at least one host")

        safety_data = data.get("safety") or {}
        # MVP safety gates are hard enforced. Future unsafe override support
        # should live behind an operator CLI flag, not inside target-controlled config.
        for key in ("requireLocalOrStaging", "requireAllowedHostMatch", "blockCloudMetadataIps"):
            if key in safety_data and safety_data[key] is False:
                raise TargetValidationError(f"target config cannot disable safety gate {key}")
        safety = SafetyConfig()
        if environment not in {"local", "staging"}:
            raise TargetValidationError(
                f"production or non-local/staging target refused by default: environment={environment!r}"
            )

        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise TargetValidationError("baseUrl must be an http(s) URL with a host")
        if _is_metadata_host(parsed.hostname):
            raise TargetValidationError("baseUrl points at a blocked metadata/link-local IP")
        normalized_allowed = [_normalize_allowed_host(h) for h in allowed_hosts_raw]
        if _normalize_host(parsed.hostname) not in normalized_allowed:
            raise TargetValidationError("baseUrl host must be listed in allowedHosts")

        scope_data = data.get("scope") or {}
        scope = ScopeConfig(
            include_paths=list(scope_data.get("includePaths") or ["/"]),
            exclude_paths=list(scope_data.get("excludePaths") or []),
            max_requests=int(scope_data.get("maxRequests", 100)),
            max_runtime_seconds=int(scope_data.get("maxRuntimeSeconds", 300)),
        )
        if scope.max_requests <= 0:
            raise TargetValidationError("maxRequests must be greater than zero")
        if scope.max_runtime_seconds <= 0:
            raise TargetValidationError("maxRuntimeSeconds must be greater than zero")

        lifecycle = data.get("lifecycle") or {}
        reset = _lifecycle_command(lifecycle.get("reset") or {}, "reset")
        seed = _lifecycle_command(lifecycle.get("seed") or {}, "seed")
        detectors = list((data.get("detectors") or {}).get("enabled") or [])

        return cls(
            id=target_id,
            name=name,
            environment=environment,
            base_url=base_url,
            allowed_hosts=normalized_allowed,
            scope=scope,
            reset=reset,
            seed=seed,
            detectors_enabled=detectors,
            safety=safety,
        )

    def is_url_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        host = _normalize_host(parsed.hostname)
        if _is_metadata_host(host):
            return False
        return host in self.allowed_hosts

    def is_redirect_allowed(self, from_url: str, to_url: str) -> bool:
        del from_url
        return self.is_url_allowed(to_url)

    def to_summary(self) -> dict[str, Any]:
        return {
            "schemaVersion": "web-target/v1",
            "id": self.id,
            "name": self.name,
            "environment": self.environment,
            "baseUrl": self.base_url,
            "allowedHosts": self.allowed_hosts,
            "scope": {
                "maxRequests": self.scope.max_requests,
                "maxRuntimeSeconds": self.scope.max_runtime_seconds,
            },
            "detectors": {"enabled": self.detectors_enabled},
            "safety": {
                "requireLocalOrStaging": self.safety.require_local_or_staging,
                "requireAllowedHostMatch": self.safety.require_allowed_host_match,
                "blockCloudMetadataIps": self.safety.block_cloud_metadata_ips,
            },
        }


def load_target_config(path: str | Path) -> WebTargetConfig:
    p = Path(path)
    text = p.read_text()
    if p.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            raise TargetValidationError("PyYAML is required to load YAML target configs")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise TargetValidationError("target config must parse to an object")
    return WebTargetConfig.from_dict(data)


def _required_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TargetValidationError(f"{key} is required")
    return value.strip()


def _lifecycle_command(data: dict[str, Any], name: str) -> LifecycleCommand:
    required = bool(data.get("required", False))
    command = data.get("command")
    if required and (not isinstance(command, str) or not command.strip()):
        raise TargetValidationError(f"{name} lifecycle command is required when {name}.required=true")
    return LifecycleCommand(
        command=command.strip() if isinstance(command, str) and command.strip() else None,
        cwd=str(data.get("cwd") or "."),
        required=required,
    )


def _normalize_allowed_host(host: str) -> str:
    if not isinstance(host, str) or not host.strip():
        raise TargetValidationError("allowedHosts entries must be non-empty hostnames or IPs")
    raw = host.strip()
    if "://" in raw or "/" in raw or "@" in raw:
        raise TargetValidationError("allowedHosts entries must be bare hosts, not URLs")
    if ":" in raw and not (raw.startswith("[") and raw.endswith("]")):
        # Keep MVP host-only. If origin scoping is needed later, model scheme/host/port explicitly.
        raise TargetValidationError("allowedHosts entries must not include ports in MVP")
    if not _HOST_RE.match(raw):
        raise TargetValidationError("allowedHosts contains an invalid host entry")
    return _normalize_host(raw.strip("[]"))


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _is_metadata_host(host: str) -> bool:
    normalized = _normalize_host(host.strip("[]"))
    if normalized in _METADATA_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return ip in _LINK_LOCAL_V4 or ip in _LINK_LOCAL_V6
