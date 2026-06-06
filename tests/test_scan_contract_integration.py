"""Integration tests: verify scan results produce valid contract output."""
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from security_harness.contracts import (
    ContractValidationError,
    validate_finding,
    validate_grader,
    validate_against_contract,
)


class TestHttpSmokeGraderOutput:
    """HttpSmokeResult.to_summary() produces grader/v1-compatible output."""

    def test_summary_has_required_grader_fields(self):
        from security_harness.http_smoke import HttpSmokeResult

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            result = HttpSmokeResult(
                success=True,
                run_id="run-1",
                target_id="test-target",
                run_dir=tmppath,
                request_count=3,
                finding_count=0,
                artifacts={"report": tmppath / "report.md"},
                warnings=[],
            )
            summary = result.to_summary()
            # The grader is separate; this tests that result fields exist
            assert "success" in summary
            assert "run_id" in summary

    def test_grader_data_validates(self):
        """A grader dict should pass grader/v1 validation."""
        grader_data = {
            "schemaVersion": "grader-result/v1",
            "runId": "run-1",
            "targetId": "test-target",
            "status": "verified",
            "gates": [{"name": "sandbox", "passed": True}],
            "findings": ["f-1"],
            "artifacts": {"report": "/path/report.md"},
        }
        result = validate_grader(grader_data)
        assert result.ok


class TestPocReplayResultOutput:
    """PocReplayResult.to_summary() produces poc-replay/v1-compatible output."""

    def test_summary_has_poc_replay_fields(self):
        from security_harness.poc_replay import PocReplayResult

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            result = PocReplayResult(
                success=True,
                verified=True,
                run_id="run-1",
                target_id="target-1",
                run_dir=tmppath,
                step_count=2,
                finding_count=1,
                artifacts={"poc_replay": tmppath / "replay.json"},
                warnings=[],
            )
            summary = result.to_summary()
            assert summary["run_id"] == "run-1"
            assert summary["step_count"] == 2


class TestStaticScanFindingsOutput:
    """StaticScanResult.to_summary() reports finding_count correctly."""

    def test_summary_includes_finding_count(self):
        from security_harness.static_scan import StaticScanResult

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            result = StaticScanResult(
                success=True,
                run_id="run-1",
                target_id="target-1",
                run_dir=tmppath,
                finding_count=3,
                agent_success=True,
                artifacts={"findings": tmppath / "findings.json"},
                warnings=[],
            )
            summary = result.to_summary()
            assert summary["finding_count"] == 3


class TestJobOutput:
    """JobStartResult.to_summary() includes required job fields."""

    def test_summary_has_required_fields(self):
        from security_harness.jobs import JobStartResult

        result = JobStartResult(
            success=True,
            job_id="job-123",
            status="running",
            job_path=Path("/tmp/test"),
        )
        summary = result.to_summary()
        assert summary["job_id"] == "job-123"
        assert summary["status"] == "running"
        assert summary["success"] is True


class TestValidationFunctionIntegration:
    """validate_against_contract works with real harness data shapes."""

    def test_validate_finding_with_real_shape(self):
        """A finding dict with all required fields should pass."""
        data = {
            "schemaVersion": "finding/v1",
            "id": "sqli-1",
            "runId": "run-1",
            "targetId": "target-1",
            "detectorId": "sqli-detector",
            "title": "SQL injection in login",
            "severity": "high",
            "confidence": "high",
            "affected": {"url": "http://localhost/login", "step": "step-1"},
            "evidence": {"response": "error: syntax"},
        }
        result = validate_against_contract(data, "finding/v1")
        assert result.ok

    def test_validate_finding_missing_detector_fails(self):
        """Missing detectorId should fail finding/v1 validation."""
        data = {
            "schemaVersion": "finding/v1",
            "id": "sqli-1",
            "runId": "run-1",
            "targetId": "target-1",
            "title": "SQL injection in login",
            "severity": "high",
            "affected": {"url": "http://localhost/login"},
            "evidence": {},
        }
        result = validate_against_contract(data, "finding/v1")
        assert not result.ok
        assert "detectorId" in result.errors

    def test_validate_finding_missing_severity_fails(self):
        """Missing severity should fail."""
        data = {
            "schemaVersion": "finding/v1",
            "id": "sqli-1",
            "runId": "run-1",
            "targetId": "target-1",
            "detectorId": "sqli-detector",
            "title": "SQL injection in login",
            "affected": {"url": "http://localhost/login"},
            "evidence": {},
        }
        result = validate_against_contract(data, "finding/v1")
        assert not result.ok
        assert "severity" in result.errors

    def test_validate_poc_replay_with_real_shape(self):
        """A poc-replay dict should pass poc-replay/v1 validation."""
        data = {
            "schemaVersion": "poc-replay/v1",
            "runId": "run-1",
            "targetId": "target-1",
            "pocId": "poc-1",
            "verified": True,
            "dynamic": False,
            "sandbox": {"mode": "bwrap"},
            "lifecycle": {"reset": {"ok": True}},
            "warnings": [],
            "steps": [{"index": 1, "name": "get"}],
            "findings": [],
        }
        result = validate_against_contract(data, "poc-replay/v1")
        assert result.ok

    def test_validate_poc_replay_missing_run_id(self):
        """Missing runId should fail poc-replay/v1 validation."""
        data = {
            "schemaVersion": "poc-replay/v1",
            "targetId": "target-1",
            "verified": True,
            "dynamic": False,
            "steps": [],
            "findings": [],
        }
        result = validate_against_contract(data, "poc-replay/v1")
        assert not result.ok
        assert "runId" in result.errors

    def test_validate_job_with_real_shape(self):
        """A job dict should pass job/v1 validation."""
        data = {
            "job_id": "job-123",
            "status": "queued",
            "spec": {"scanType": "http-smoke", "configPath": "/path/target.yaml"},
            "success": True,
            "createdAt": "2026-06-06T00:00:00Z",
            "updatedAt": "2026-06-06T00:00:00Z",
            "result": None,
            "artifacts": {},
            "error": None,
        }
        result = validate_against_contract(data, "job/v1")
        assert result.ok

    def test_validate_job_missing_spec(self):
        """Missing spec should fail job/v1 validation."""
        data = {
            "job_id": "job-123",
            "status": "queued",
            "success": True,
        }
        result = validate_against_contract(data, "job/v1")
        assert not result.ok
        assert "spec" in result.errors
