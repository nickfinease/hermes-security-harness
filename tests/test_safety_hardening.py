import pytest

from security_harness.web_target import WebTargetConfig, TargetValidationError


def cfg(**overrides):
    base = {
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
    base.update(overrides)
    return base


def test_safety_gates_cannot_be_disabled_by_target_config():
    bad = cfg(safety={"requireLocalOrStaging": False, "requireAllowedHostMatch": True, "blockCloudMetadataIps": True})
    with pytest.raises(TargetValidationError, match="cannot disable"):
        WebTargetConfig.from_dict(bad)


def test_blocks_entire_link_local_metadata_range():
    target = WebTargetConfig.from_dict(cfg())
    assert target.is_url_allowed("http://169.254.1.1/latest/meta-data") is False
    assert target.is_url_allowed("http://[fe80::1]/") is False


def test_rejects_malformed_allowed_host_entries():
    bad = cfg(allowedHosts=["http://localhost:3000/path"])
    with pytest.raises(TargetValidationError, match="allowedHosts"):
        WebTargetConfig.from_dict(bad)
