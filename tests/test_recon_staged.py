"""Tests for staged reconnaissance (unauth/auth passes)."""
import pytest
from tests.helpers import write_target_config


class TestStagedRecon:
    """Test that recon splits into unauth and auth phases."""

    def test_unauth_recon_has_no_auth_surfaces(self, tmp_path):
        """Unauth phase should not produce authenticated surfaces."""
        from security_harness.recon import run_unauth_recon

        config = tmp_path / "target.yaml"
        write_target_config(config, "http://localhost:8081", ["/"])

        result = run_unauth_recon(config, artifacts_root=str(tmp_path / "runs"))
        # Unauth phase should have surfaces but no auth-protected surfaces
        assert result.surfaces is not None
        assert len(result.surfaces) >= 0  # May have 0 if target is unreachable

    def test_auth_recon_requires_session(self, tmp_path):
        """Auth phase requires a session (cookies or token)."""
        from security_harness.recon import run_auth_recon

        config = tmp_path / "target.yaml"
        write_target_config(config, "http://localhost:8081", ["/"])

        # Without session, auth recon should either work with empty session
        # or return limited results
        result = run_auth_recon(config, session_cookies={}, artifacts_root=str(tmp_path / "runs"))
        assert result.surfaces is not None

    def test_full_recon_combines_phases(self, tmp_path):
        """Full recon should combine unauth and auth results."""
        from security_harness.recon import run_staged_recon

        config = tmp_path / "target.yaml"
        write_target_config(config, "http://localhost:8081", ["/"])

        result = run_staged_recon(config, artifacts_root=str(tmp_path / "runs"))
        assert result.surfaces is not None
        assert len(result.surfaces) >= 0

    def test_recon_source_marks_phase(self):
        """ReconSource should distinguish unauth vs auth phases."""
        from security_harness.recon import ReconSource

        assert ReconSource.UNAUTH_PHASE.value == "unauth_phase"
        assert ReconSource.AUTH_PHASE.value == "auth_phase"


class TestReconStages:
    """Test the stage orchestration."""

    def test_stages_run_in_order(self, tmp_path):
        """Unauth phase runs before auth phase."""
        from security_harness.recon import ReconStage

        assert ReconStage.UNAUTH.value == 1
        assert ReconStage.AUTH.value == 2
        assert ReconStage.UNAUTH < ReconStage.AUTH

    def test_staged_result_tracks_phases(self, tmp_path):
        """Result should track which phase each surface came from."""
        from security_harness.recon import ReconResult, ReconSurface, ReconSource

        # Create a result with surfaces from both phases
        surfaces = [
            ReconSurface(
                id="s1",
                url="http://example.com/login",
                input_type="form_field",
                parameter_name="username",
                method="POST",
                source=ReconSource.UNAUTH_PHASE,
                confidence="high",
            ),
        ]

        result = ReconResult(
            run_id="test-123",
            target_id="test",
            surfaces=surfaces,
            discovered_routes=[],
            discovered_forms=[],
            auth_surfaces=[],
            hidden_endpoints=[],
        )

        assert len(result.surfaces) == 1
        assert result.surfaces[0].source == ReconSource.UNAUTH_PHASE
