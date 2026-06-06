"""Contract loading and structural validation for security harness outputs.

This module provides:
- ``load_contract(version_str)`` — load a JSON schema from the contracts/ directory
- ``validate_against_contract(data, version_str)`` — validate data dict against a contract
- ``validate_and_raise(data, version_str)`` — same, but raises on failure

Public API (``__all__``):
    ContractValidationError, ValidationResult, ValidationRule,
    load_contract, validate_against_contract, validate_and_raise,
    validate_grader, validate_finding, validate_poc_replay, validate_job

Usage::

    from security_harness.contracts import validate_against_contract

    result = validate_against_contract(data, "grader/v1")
    if not result.ok:
        for field in result.errors:
            print(f"Missing required: {field}")
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import json

__all__ = [
    "ContractValidationError",
    "ValidationResult",
    "ValidationRule",
    "load_contract",
    "validate_against_contract",
    "validate_and_raise",
    "validate_grader",
    "validate_finding",
    "validate_poc_replay",
    "validate_job",
]

# Resolve the contracts directory relative to this module
_CONTRACTS_DIR = Path(__file__).resolve().parent.parent / "contracts"


# ── Data Classes ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ValidationRule:
    """A single validation rule for a field.

    Reserved for future type-checking extensions (enum, regex, etc.).
    Currently unused in validation logic but tested and ready.
    """
    name: str
    field: str
    expected: Any | None = None


@dataclass
class ValidationResult:
    """Result of a contract validation run."""
    ok: bool = True
    errors: list[str] = field(default_factory=list)
    rules_run: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": self.errors,
            "rules_run": self.rules_run,
        }


# ── Exception ─────────────────────────────────────────────────────────────────

class ContractValidationError(ValueError):
    """Raised when a contract is not found or is malformed."""


# ── Core Functions ────────────────────────────────────────────────────────────


def _schema_version_to_filename(version_str: str) -> str:
    """Convert version string to contract filename: finding/v1 → finding-v1.json."""
    return f"{version_str.replace('/', '-')}.json"


def load_contract(version_str: str) -> dict[str, Any]:
    """Load a contract JSON schema by version string.

    Args:
        version_str: Schema version like "grader/v1"

    Returns:
        The parsed contract JSON as a dict.

    Raises:
        ContractValidationError: If the version is malformed or the file is not found.
    """
    # Validate version format: must be <name>/<version>
    if not version_str or "/" not in version_str:
        raise ContractValidationError(
            f"Invalid schema version format '{version_str}': expected 'name/version'"
        )

    parts = version_str.split("/")
    if len(parts) < 2 or not parts[0].strip() or not parts[1].strip():
        raise ContractValidationError(
            f"Invalid schema version format '{version_str}': expected 'name/version'"
        )

    filename = _schema_version_to_filename(version_str)
    filepath = _CONTRACTS_DIR / filename

    if not filepath.exists():
        raise ContractValidationError(
            f"Contract not found: {version_str} (file {filepath.name} does not exist)"
        )

    try:
        data = json.loads(filepath.read_text())
    except json.JSONDecodeError as exc:
        raise ContractValidationError(
            f"Invalid JSON in contract {filepath.name}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ContractValidationError(
            f"Contract {filepath.name} must be a JSON object, got {type(data).__name__}"
        )

    return data


def validate_against_contract(data: Any, version_str: str) -> ValidationResult:
    """Validate a data dict against a contract schema.

    Performs:
    - Type check: data must be a dict
    - Required field check: all fields listed in contract["required"] must be present

    Args:
        data: The data dict to validate.
        version_str: Schema version like "grader/v1"

    Returns:
        ValidationResult with ok=True and empty errors if valid,
        ok=False and error messages listing missing fields.
    """
    result = ValidationResult()

    if not isinstance(data, dict):
        raise ValueError(
            f"Data to validate must be a dict, got {type(data).__name__}"
        )

    # Load contract
    contract = load_contract(version_str)
    result.rules_run.append("load_contract")

    # Check required fields
    required = contract.get("required", [])
    if isinstance(required, list):
        for field_name in required:
            if field_name not in data:
                result.errors.append(field_name)
        result.rules_run.append("required_fields")

    result.ok = len(result.errors) == 0
    return result


def validate_and_raise(data: Any, version_str: str) -> None:
    """Validate data against contract, raising on failure.

    Convenience wrapper: calls validate_against_contract and raises
    a ContractValidationError if the result is not ok.

    Args:
        data: The data dict to validate.
        version_str: Schema version like "grader/v1"

    Raises:
        ValueError: If data is not a dict.
        ContractValidationError: If validation fails or contract is not found.
    """
    result = validate_against_contract(data, version_str)
    if not result.ok:
        raise ContractValidationError(
            f"Validation failed for {version_str}: {', '.join(result.errors)}"
        )


# ── Typed Shortcuts ───────────────────────────────────────────────────────────

def validate_grader(data: dict[str, Any]) -> ValidationResult:
    """Validate a grader result dict against grader/v1 contract."""
    return validate_against_contract(data, "grader/v1")


def validate_finding(data: dict[str, Any]) -> ValidationResult:
    """Validate a finding dict against finding/v1 contract."""
    return validate_against_contract(data, "finding/v1")


def validate_poc_replay(data: dict[str, Any]) -> ValidationResult:
    """Validate a poc-replay dict against poc-replay/v1 contract."""
    return validate_against_contract(data, "poc-replay/v1")


def validate_job(data: dict[str, Any]) -> ValidationResult:
    """Validate a job dict against job/v1 contract."""
    return validate_against_contract(data, "job/v1")
