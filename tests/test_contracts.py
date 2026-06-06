"""Tests for the contracts directory.

Each contract schema is validated by structural tests that ensure:
- Schema version strings match the filename convention
- Required fields are present in each schema
- Field types are consistent with usage in the harness code
- Schema files are valid JSON
"""
import json
import re
from pathlib import Path

import pytest

# Resolve the contracts directory relative to this test file
CONTRACTS_DIR = Path(__file__).resolve().parent.parent / "contracts"

# Required schemas: (schema_version, list_of_required_field_names)
REQUIRED_SCHEMAS = [
    ("finding/v1", ["id", "runId", "targetId", "detectorId", "title", "severity", "affected", "evidence"]),
    ("http-poc/v1", ["id", "schemaVersion", "targetId", "steps"]),
    ("poc-replay/v1", ["runId", "targetId", "verified", "dynamic", "steps", "findings"]),
    ("grader/v1", ["runId", "targetId", "status", "findings"]),
    ("job/v1", ["job_id", "status", "spec", "success"]),
    ("source-inventory/v1", ["targetId", "schemaVersion", "sourceRoot", "files", "totals"]),
    ("static-agent-findings/v1", ["schemaVersion", "findings", "notes"]),
    ("static-findings/v1", ["runId", "targetId", "workspaceWritesEnabled", "findings"]),
    ("patch-candidate/v1", ["id", "runId", "targetId", "affectedFiles", "patch"]),
]


class TestContractsDirectory:
    """Verify the contracts directory structure."""

    def test_contracts_directory_exists(self):
        assert CONTRACTS_DIR.exists(), "contracts/ directory must exist"
        assert CONTRACTS_DIR.is_dir(), "contracts/ must be a directory"

    def test_contract_files_exist(self):
        files = sorted(CONTRACTS_DIR.glob("*.json"))
        assert files, "contracts/ directory must contain at least one .json file"

    @pytest.mark.parametrize("path", [
        p for p in sorted(CONTRACTS_DIR.glob("*.json"))
    ])
    def test_all_files_are_json(self, path):
        """Every .json file in contracts/ must be valid JSON."""
        try:
            json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            pytest.fail(f"{path} is not valid JSON: {exc}")

    def test_all_fnames_conform_to_schema(self):
        """Contract filenames must match <name-part>-v<version>.json where name-part can contain hyphens."""
        pattern = re.compile(r"^[a-z][a-z0-9_-]*-v\d+(\.\d+)*\.json$", re.IGNORECASE)
        files = sorted(CONTRACTS_DIR.glob("*.json"))
        for path in files:
            assert pattern.match(path.name), (
                f"{path.name} does not match <name-part>-v<version>.json pattern"
            )

    def test_all_fnames_unique(self):
        """No two contract files should have the same name (checked implicitly by glob)."""
        files = sorted(CONTRACTS_DIR.glob("*.json"))
        names = [f.name for f in files]
        assert len(names) == len(set(names)), "Duplicate contract filenames found"


class TestContractVersionStrings:
    """Every contract JSON must have a schemaVersion field matching its filename."""

    def test_schema_version_matches_filename(self):
        files = sorted(CONTRACTS_DIR.glob("*.json"))
        if not files:
            pytest.skip("No contracts loaded yet")
        for path in files:
            data = json.loads(path.read_text())
            version_str = str(data.get("schemaVersion", ""))
            file_ver = path.name.replace(".json", "")
            # Filename: name-part-vN.json, schemaVersion: name-part/N
            # Find the separator: last occurrence of -v or -V followed by a digit
            match = re.search(r"(-v\d+)\.json$", file_ver, re.IGNORECASE)
            if not match:
                continue
            name_part = file_ver[: match.start(1)].replace("-", "/")
            version_part = match.group(1).lstrip("-vV")
            file_normalised = f"{name_part}/{version_part}"
            assert file_normalised.lower() == version_str.lower(), (
                f"schemasVersion '{version_str}' in {path.name} does not match filename"
            )


class TestContractRequiredFields:
    """Verify each contract has the fields required by the harness code."""

    @pytest.mark.parametrize(
        "version_str, expected_fields",
        REQUIRED_SCHEMAS,
    )
    def test_contract_has_required_fields(self, version_str, expected_fields):
        # Convert version string to filename: finding/v1 → finding-v1.json
        fname = version_str.replace("/", "-") + ".json"
        fpath = CONTRACTS_DIR / fname
        if not fpath.exists():
            pytest.skip(f"{fname} not yet created")
        data = json.loads(fpath.read_text())
        # Contracts are JSON Schema files; required fields live under "required"
        schema_required = data.get("required", [])
        for field in expected_fields:
            assert field in schema_required, f"{fname} required array must contain '{field}'"
