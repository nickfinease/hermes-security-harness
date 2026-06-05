import json

import pytest

from security_harness.artifacts import Finding, HttpPoc, HttpStep, redact_secrets


def test_finding_requires_valid_severity_confidence_and_affected_url():
    with pytest.raises(ValueError, match="severity"):
        Finding(id="f1", run_id="r1", target_id="t1", title="Bad", severity="urgent", confidence="high", affected={"url": "http://localhost"})
    with pytest.raises(ValueError, match="confidence"):
        Finding(id="f1", run_id="r1", target_id="t1", title="Bad", severity="high", confidence="certain", affected={"url": "http://localhost"})
    with pytest.raises(ValueError, match="affected.url"):
        Finding(id="f1", run_id="r1", target_id="t1", title="Bad", severity="high", confidence="high", affected={})


def test_http_poc_serializes_stable_schema_version():
    poc = HttpPoc(
        id="poc-1",
        finding_id="finding-1",
        target_id="target-1",
        title="Reflected XSS",
        steps=[HttpStep(name="probe", method="GET", url="http://localhost:3000/search?q=x")],
    )
    data = poc.to_dict()
    assert data["schemaVersion"] == "http-poc/v1"
    assert data["steps"][0]["request"]["method"] == "GET"
    json.dumps(data)


def test_redact_secrets_removes_tokens_passwords_and_cookies():
    text = "Authorization: Bearer abc123\npassword=secret\nCookie: sessionid=abcdef"
    redacted = redact_secrets(text)
    assert "abc123" not in redacted
    assert "secret" not in redacted
    assert "abcdef" not in redacted
    assert "[REDACTED]" in redacted
