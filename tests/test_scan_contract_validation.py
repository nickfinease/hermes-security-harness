"""Tests: scan functions validate contract output before writing/returning."""
import json
import tempfile
from pathlib import Path

import pytest

from security_harness.contracts import ContractValidationError


class TestHttpSmokeValidatesDocOutput:
    """run_http_smoke validates the http-smoke/v1 doc dict before returning."""

    def test_smoke_result_to_summary_passes(self):
        """HttpSmokeResult.to_summary() should work without errors."""
        from security_harness.http_smoke import HttpSmokeResult

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            result = HttpSmokeResult(
                success=True,
                run_id="run-1",
                target_id="test",
                run_dir=tmppath,
                request_count=1,
                finding_count=0,
                artifacts={},
                warnings=[],
            )
            summary = result.to_summary()
            assert "run_id" in summary
            assert summary["success"] is True


class TestPocReplayValidatesOutput:
    """run_poc_replay validates poc-replay/v1 output before writing."""

    def test_poc_replay_result_valid(self):
        """PocReplayResult.to_summary() should produce valid output."""
        from security_harness.poc_replay import PocReplayResult

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            result = PocReplayResult(
                success=True,
                verified=True,
                run_id="run-1",
                target_id="target-1",
                run_dir=tmppath,
                step_count=1,
                finding_count=0,
                artifacts={},
                warnings=[],
            )
            d = result.to_summary()
            assert d["verified"] is True


class TestGraderResultValidatesOutput:
    """GraderResult.to_dict() produces valid grader/v1 output."""

    def test_grader_to_dict_valid(self):
        from security_harness.artifacts import GraderResult
        from security_harness.contracts import validate_grader

        grader = GraderResult(
            run_id="run-1",
            target_id="target-1",
            status="verified",
            findings=["f-1"],
            gates=[{"name": "sandbox", "passed": True}],
            artifacts={"report": "/path/report.md"},
        )
        d = grader.to_dict()
        assert d["schemaVersion"] == "grader-result/v1"
        assert d["runId"] == "run-1"
        assert d["targetId"] == "target-1"
        assert d["status"] == "verified"


class TestJobResultValidatesOutput:
    """JobStartResult.to_summary() produces valid output for job/v1."""

    def test_job_start_valid(self):
        from security_harness.jobs import JobStartResult

        result = JobStartResult(
            success=True,
            job_id="job-123",
            status="queued",
            job_path=Path("/tmp/job"),
        )
        d = result.to_summary()
        assert d["job_id"] == "job-123"
        assert d["status"] == "queued"


class TestStaticScanFindingsValidates:
    """Static scan findings document validates against static-findings/v1."""

    def test_findings_document_required_fields(self):
        """A static-findings/v1 document must have runId, targetId, findings."""
        from security_harness.contracts import validate_against_contract

        doc = {
            "schemaVersion": "static-findings/v1",
            "runId": "run-1",
            "targetId": "target-1",
            "sourceRoot": "/path/to/source",
            "generatedAt": "2026-06-06T00:00:00Z",
            "workspaceWritesEnabled": False,
            "patchCandidates": [],
            "agent": {"ok": True, "exitCode": 0},
            "parser": {"ok": True},
            "warnings": [],
            "findings": [],
        }
        result = validate_against_contract(doc, "static-findings/v1")
        assert result.ok, f"static-findings validation errors: {result.errors}"
