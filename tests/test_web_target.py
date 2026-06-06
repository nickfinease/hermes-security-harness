import pytest

from security_harness.web_target import WebTargetConfig, TargetValidationError


def minimal_config(**overrides):
    cfg = {
        "schemaVersion": "web-target/v1",
        "id": "local-demo",
        "name": "Local Demo",
        "environment": "local",
        "baseUrl": "http://localhost:3000",
        "allowedHosts": ["localhost", "127.0.0.1"],
        "scope": {"maxRequests": 10, "maxRuntimeSeconds": 30},
        "lifecycle": {
            "reset": {"command": "./reset.sh", "required": True},
            "seed": {"command": "./seed.sh", "required": True},
        },
        "detectors": {"enabled": ["reflected-xss"]},
        "safety": {
            "requireLocalOrStaging": True,
            "requireAllowedHostMatch": True,
            "blockCloudMetadataIps": True,
        },
    }
    cfg.update(overrides)
    return cfg


def test_accepts_localhost_target():
    target = WebTargetConfig.from_dict(minimal_config())
    assert target.id == "local-demo"
    assert target.is_url_allowed("http://localhost:3000/search?q=x") is True


def test_rejects_public_production_url_by_default():
    cfg = minimal_config(environment="production", baseUrl="https://example.com", allowedHosts=["example.com"])
    with pytest.raises(TargetValidationError, match="production"):
        WebTargetConfig.from_dict(cfg)


def test_blocks_metadata_ip_even_if_seen_in_redirect():
    target = WebTargetConfig.from_dict(minimal_config())
    assert target.is_url_allowed("http://169.254.169.254/latest/meta-data") is False


def test_blocks_redirect_outside_allowlist():
    target = WebTargetConfig.from_dict(minimal_config())
    assert target.is_redirect_allowed("http://localhost:3000", "https://evil.example/path") is False


def test_requires_reset_and_seed_commands_when_marked_required():
    cfg = minimal_config(lifecycle={"reset": {"required": True}, "seed": {"required": True}})
    with pytest.raises(TargetValidationError, match="reset.*command"):
        WebTargetConfig.from_dict(cfg)


def test_rejects_zero_request_budget():
    cfg = minimal_config(scope={"maxRequests": 0, "maxRuntimeSeconds": 30})
    with pytest.raises(TargetValidationError, match="maxRequests"):
        WebTargetConfig.from_dict(cfg)


def test_rejects_public_staging_host_without_operator_allowlist(monkeypatch):
    monkeypatch.delenv("SECURITY_HARNESS_APPROVED_STAGING_HOSTS", raising=False)
    cfg = minimal_config(environment="staging", baseUrl="https://example.com", allowedHosts=["example.com"])
    with pytest.raises(TargetValidationError, match="operator allowlist"):
        WebTargetConfig.from_dict(cfg)


def test_accepts_public_staging_host_with_operator_allowlist(monkeypatch):
    monkeypatch.setenv("SECURITY_HARNESS_APPROVED_STAGING_HOSTS", "example.com")
    cfg = minimal_config(environment="staging", baseUrl="https://example.com", allowedHosts=["example.com"])
    target = WebTargetConfig.from_dict(cfg)
    assert target.base_url == "https://example.com"
