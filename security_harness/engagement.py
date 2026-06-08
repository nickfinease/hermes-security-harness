"""Engagement management: credential store, encryption, and shared state.

An engagement is the lifecycle of a single security assessment against a target.
It stores credentials (encrypted), findings (accumulated across phases),
authentication sessions, and phase history.

Engagement files live in ~/.hermes/harness/engagements/<target>.json.
"""
from __future__ import annotations

import json
import os
import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from cryptography.fernet import Fernet

# Default engagement directory
DEFAULT_ENGAGEMENTS_DIR = Path.home() / ".hermes" / "harness" / "engagements"


class EngagementError(Exception):
    """Raised when engagement operations fail."""
    pass


class EngagementCryptoError(EngagementError):
    """Raised when encryption/decryption fails."""
    pass


# ── Encryption helper ─────────────────────────────────────────────────────────


def _get_cipher() -> Fernet:
    """Get or create a Fernet cipher for credential encryption.

    Uses an operator-level key derived from environment or a file key.
    Falls back to a default key (acceptable for local/dev use).
    """
    key_env = os.environ.get("HARNESS_ENGAGEMENT_KEY")
    if key_env:
        # Base64-encoded key from environment
        key = base64.urlsafe_b64encode(bytes.fromhex(key_env))
    else:
        # Derive from a file-based key or create a default
        key_file = Path.home() / ".hermes" / "harness" / ".engagement-key"
        if key_file.exists():
            key = base64.urlsafe_b64encode(key_file.read_bytes()[:32])
        else:
            # Generate and persist a default key
            key_bytes = os.urandom(32)
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_bytes(key_bytes)
            key_file.chmod(0o600)
            key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(key)


def encrypt_value(value: str) -> str:
    """Encrypt a string value for storage in engagement files."""
    if not value:
        return value
    cipher = _get_cipher()
    return "<ENC:" + base64.urlsafe_b64encode(
        cipher.encrypt(value.encode()).lstrip(b"\x00")
    ).decode()


def decrypt_value(encrypted: str) -> str:
    """Decrypt an encrypted string from engagement files."""
    if not encrypted or not encrypted.startswith("<ENC:"):
        return encrypted
    cipher = _get_cipher()
    try:
        payload = base64.urlsafe_b64decode(encrypted[5:])
        return cipher.decrypt(payload).decode()
    except Exception as exc:
        raise EngagementCryptoError(
            f"Cannot decrypt credential (key mismatch or corruption): {exc}"
        ) from exc


# ── Engagement data model ─────────────────────────────────────────────────────


@dataclass
class Credential:
    """A stored credential set."""
    username: str
    password: str = ""
    token: str = ""
    bearer: str = ""
    cookie: str = ""
    cookie_name: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, str]:
        d: dict[str, str] = {"username": self.username}
        if self.password:
            d["password"] = encrypt_value(self.password)
        if self.token:
            d["token"] = encrypt_value(self.token)
        if self.bearer:
            d["bearer"] = encrypt_value(self.bearer)
        if self.cookie:
            d["cookie"] = encrypt_value(self.cookie)
        if self.cookie_name:
            d["cookie_name"] = self.cookie_name
        if self.notes:
            d["notes"] = self.notes
        return d

    @classmethod
    def from_dict(cls, d: dict[str, str]) -> "Credential":
        return cls(
            username=d.get("username", ""),
            password=decrypt_value(d.get("password", "")),
            token=decrypt_value(d.get("token", "")),
            bearer=decrypt_value(d.get("bearer", "")),
            cookie=decrypt_value(d.get("cookie", "")),
            cookie_name=d.get("cookie_name", ""),
            notes=d.get("notes", ""),
        )

    def has_credentials(self) -> bool:
        return bool(self.username and (self.password or self.token or self.bearer or self.cookie))


@dataclass
class EngagementScope:
    include_paths: list[str] = field(default_factory=lambda: ["/*"])
    exclude_paths: list[str] = field(default_factory=list)
    max_requests: int = 300
    max_runtime_seconds: int = 600


@dataclass
class Engagement:
    """A complete engagement representing a single security assessment."""
    engagement_id: str
    target_id: str
    target_name: str = ""
    environment: str = "local"
    base_url: str = ""
    created_at: str = ""
    updated_at: str = ""

    # Scope
    scope: EngagementScope = field(default_factory=EngagementScope)

    # Credentials (keyed by role: admin, user, service, etc.)
    credentials: dict[str, Credential] = field(default_factory=dict)

    # Context about the target
    context: dict[str, Any] = field(default_factory=dict)

    # Accumulated findings across all phases
    findings: list[dict[str, Any]] = field(default_factory=list)

    # Authenticated sessions (keyed by role)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Current phase
    phase: str = "intake"

    # Phase execution history
    phase_history: list[dict[str, Any]] = field(default_factory=list)

    # Recon surfaces (populated by recon phases)
    surfaces: list[dict[str, Any]] = field(default_factory=list)

    @property
    def path(self) -> Path:
        return DEFAULT_ENGAGEMENTS_DIR / f"{self.target_id}.json"

    @classmethod
    def new(
        cls,
        target_id: str,
        base_url: str,
        target_name: str = "",
        environment: str = "local",
    ) -> "Engagement":
        """Create a new engagement."""
        now = datetime.now(timezone.utc).isoformat()
        engagement_id = f"{target_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        return cls(
            engagement_id=engagement_id,
            target_id=target_id,
            target_name=target_name or target_id,
            environment=environment,
            base_url=base_url,
            created_at=now,
            updated_at=now,
        )

    def add_credential(self, role: str, credential: Credential) -> None:
        """Store a credential set under a role name."""
        self.credentials[role] = credential
        self._touch()

    def get_credential(self, role: str) -> Credential | None:
        """Retrieve a decrypted credential set."""
        if role not in self.credentials:
            return None
        return self.credentials[role]

    def add_session(self, role: str, session: dict[str, Any]) -> None:
        """Store an authenticated session (cookies, tokens)."""
        self.sessions[role] = session
        self._touch()

    def get_session(self, role: str) -> dict[str, Any] | None:
        return self.sessions.get(role)

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a finding, deduplicating by title + endpoint."""
        key = (finding.get("title", ""), finding.get("endpoint", ""))
        for existing in self.findings:
            existing_key = (existing.get("title", ""), existing.get("endpoint", ""))
            if existing_key == key:
                # Update severity if new finding is higher
                sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
                new_sev = sev_order.get(finding.get("severity", "informational"), 4)
                existing_sev = sev_order.get(existing.get("severity", "informational"), 4)
                if new_sev < existing_sev:
                    existing["severity"] = finding.get("severity")
                    existing["evidence"] = finding.get("evidence", {})
                return
        finding["addedAt"] = datetime.now(timezone.utc).isoformat()
        self.findings.append(finding)
        self._touch()

    def add_phase_result(self, phase: str, result: dict[str, Any]) -> None:
        """Record phase execution in history."""
        entry = {
            "phase": phase,
            "completedAt": datetime.now(timezone.utc).isoformat(),
            "status": result.get("status", "completed"),
            "findings_count": result.get("findings_count", 0),
            "requests_made": result.get("requests_made", 0),
        }
        self.phase_history.append(entry)
        self._touch()

    def set_phase(self, phase: str) -> None:
        """Advance to a new phase."""
        self.phase = phase
        self._touch()

    def _touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Serialize engagement to dict (credentials encrypted)."""
        return {
            "schemaVersion": "engagement/v1",
            "engagementId": self.engagement_id,
            "targetId": self.target_id,
            "targetName": self.target_name,
            "environment": self.environment,
            "baseUrl": self.base_url,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "phase": self.phase,
            "scope": {
                "includePaths": self.scope.include_paths,
                "excludePaths": self.scope.exclude_paths,
                "maxRequests": self.scope.max_requests,
                "maxRuntimeSeconds": self.scope.max_runtime_seconds,
            },
            "credentials": {
                role: cred.to_dict()
                for role, cred in self.credentials.items()
            },
            "context": self.context,
            "findings": self.findings,
            "sessions": {
                role: session
                for role, session in self.sessions.items()
            },
            "phaseHistory": self.phase_history,
            "surfaces": self.surfaces,
        }

    def save(self, path: Path | None = None) -> Path:
        """Persist engagement to disk."""
        save_path = path or self.path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(json.dumps(self.to_dict(), indent=2))
        return save_path

    @classmethod
    def load(cls, target_id: str) -> "Engagement":
        """Load an engagement from disk."""
        path = DEFAULT_ENGAGEMENTS_DIR / f"{target_id}.json"
        if not path.exists():
            raise EngagementError(f"Engagement not found: {path}")
        return cls.from_dict(json.loads(path.read_text()))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Engagement":
        """Deserialize engagement from dict."""
        scope_data = data.get("scope", {})
        credentials = {}
        for role, cred_data in data.get("credentials", {}).items():
            if isinstance(cred_data, dict):
                credentials[role] = Credential.from_dict(cred_data)
            else:
                credentials[role] = Credential.from_dict(cred_data)
        return cls(
            engagement_id=data.get("engagementId", ""),
            target_id=data.get("targetId", ""),
            target_name=data.get("targetName", data.get("targetId", "")),
            environment=data.get("environment", "local"),
            base_url=data.get("baseUrl", ""),
            created_at=data.get("createdAt", ""),
            updated_at=data.get("updatedAt", ""),
            scope=EngagementScope(
                include_paths=scope_data.get("includePaths", ["/*"]),
                exclude_paths=scope_data.get("excludePaths", []),
                max_requests=scope_data.get("maxRequests", 300),
                max_runtime_seconds=scope_data.get("maxRuntimeSeconds", 600),
            ),
            credentials=credentials,
            context=data.get("context", {}),
            findings=data.get("findings", []),
            sessions=data.get("sessions", {}),
            phase=data.get("phase", "intake"),
            phase_history=data.get("phaseHistory", []),
            surfaces=data.get("surfaces", []),
        )

    @classmethod
    def list_engagements(cls) -> list[str]:
        """List available engagement target IDs."""
        engagements_dir = DEFAULT_ENGAGEMENTS_DIR
        if not engagements_dir.exists():
            return []
        return [p.stem for p in engagements_dir.glob("*.json")]


__all__ = [
    "DEFAULT_ENGAGEMENTS_DIR",
    "Engagement",
    "EngagementError",
    "EngagementScope",
    "Credential",
    "encrypt_value",
    "decrypt_value",
]
