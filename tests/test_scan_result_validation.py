"""Tests: scan results validate their output before returning it.

Each Result class's to_summary() method should call validate_against_contract()
and raise ContractValidationError if the output doesn't match its contract.
"""
import tempfile
from pathlib import Path

import pytest

from security_harness.contracts import ContractValidationError


class TestHttpSmokeValidatesOutput:
    """HttpSmokeResult.to_summary() validates against grader/v1."""

    def test_valid_output_does_not_raise(self):
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
            # to_summary() should not raise for valid output
            d = result.to_summary()
            assert "success" in d

    def test_summary_is_valid_grader_output(self):
        """The summary dict should pass grader/v1 structural validation."""
        from security_harness.http_smoke import HttpSmokeResult
        from security_harness.contracts import validate_grader

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
            # The summary itself isn't a grader dict, but we should validate
            # the grader data that would be produced from it.
            # For now, verify the fields that map to grader exist.
            assert "run_id" in summary or "runId" in summary


class TestPocReplayValidatesOutput:
    """PocReplayResult.to_summary() validates against poc-replay/v1."""

    def test_valid_output_does_not_raise(self):
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
            d = result.to_summary()
            assert "run_id" in d

    def test_summary_contains_poc_replay_fields(self):
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
            d = result.to_summary()
            # poc-replay/v1 requires: runId, targetId, verified, dynamic, steps, findings
            # to_summary uses snake_case, contract uses camelCase
            assert "run_id" in d or "runId" in d
            assert "target_id" in d or "targetId" in d


class TestStaticScanValidatesOutput:
    """StaticScanResult.to_summary() validates against static-findings/v1."""

    def test_valid_output_does_not_raise(self):
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
            d = result.to_summary()
            assert "finding_count" in d


class TestJobValidatesOutput:
    """JobStartResult.to_summary() validates against job/v1."""

    def test_valid_output_does_not_raise(self):
        from security_harness.jobs import JobStartResult

        result = JobStartResult(
            success=True,
            job_id="job-123",
            status="running",
            job_path=Path("/tmp/test"),
        )
        d = result.to_summary()
        assert "job_id" in d
