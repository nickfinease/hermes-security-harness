"""Tests for shared WSTG scanner base behavior."""
from __future__ import annotations

from security_harness.wstg_base import _run_scan
from tests.helpers import write_target_config


def test_wstg_base_defaults_to_scope_include_paths_not_detector_names(tmp_path):
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://127.0.0.1:3000", ["/profile", "/settings"])
    seen: list[str] = []

    def fake_scan(_base_url: str, endpoint: str, _timeout: float):
        seen.append(endpoint)
        return 1, []

    result = _run_scan(
        str(config),
        fake_scan,
        scan_name="test-wstg",
        artifact_name="test-wstg-summary",
        artifacts_root=str(tmp_path / "runs"),
    )

    assert result["success"] is True
    assert result["endpoints_tested"] == 2
    assert seen == ["/profile", "/settings"]


def test_wstg_base_uses_central_target_validation(tmp_path):
    config = tmp_path / "target.yaml"
    write_target_config(config, "http://example.com", ["/profile"])

    def fake_scan(_base_url: str, _endpoint: str, _timeout: float):
        return 1, []

    result = _run_scan(
        str(config),
        fake_scan,
        scan_name="test-wstg",
        artifact_name="test-wstg-summary",
        artifacts_root=str(tmp_path / "runs"),
    )

    assert result["success"] is False
    assert "public staging hosts require operator allowlist" in result["error"]
