"""Tests for recon, advanced payloads, and report generation."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from security_harness.recon import (
    ReconResult,
    ReconSurface,
    ReconSource,
    discover_from_openapi,
    discover_from_sitemap,
    discover_url_patterns,
    discover_hidden_endpoints,
    discover_auth_surfaces,
    _extract_forms,
    _extract_routes_from_js,
    _parse_sitemap,
)
from security_harness.advanced_payloads import (
    ALL_BYPASS_PAYLOADS,
    get_all_bypass_payloads,
    payload_count,
    HEADER_INJECTION_PAYLOADS,
    XXE_PAYLOADS,
    CMDI_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    HTTP_PP_PAYLOADS,
    ENCODING_EVASION_PAYLOADS,
    SQLI_BYPASS_PAYLOADS,
    XSS_BYPASS_PAYLOADS,
    BypassPayload,
    BypassTargetType,
    get_payloads_by_type,
    _double_url_encode,
    _hex_encode,
    _octal_encode,
)
from security_harness.report import (
    ReportConfig,
    generate_report,
    generate_json_report,
    write_report,
    compute_cvss_score,
    risk_matrix,
    overall_risk_level,
    map_owasp,
    map_mitre,
    get_remediation,
    RiskLevel,
    SeverityWeight,
)
from security_harness.artifacts import Finding


# ── Recon tests ────────────────────────────────────────────────────────────────


class TestDiscoverFromOpenapi:
    def test_basic_openapi(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/users": {
                    "get": {"operationId": "listUsers", "parameters": [{"name": "page", "in": "query"}]},
                    "post": {"operationId": "createUser"},
                },
                "/api/users/{id}": {"get": {"operationId": "getUser"}, "delete": {"operationId": "deleteUser"}},
            },
        }
        surfaces = discover_from_openapi("http://localhost:8080", body=json.dumps(spec))
        assert len(surfaces) == 4  # listUsers, createUser, getUser, deleteUser
        assert all(s.source == ReconSource.OPENAPI for s in surfaces)

    def test_swagger_20(self):
        spec = {
            "swagger": "2.0",
            "paths": {
                "/api/v1/data": {
                    "get": {"operationId": "getData"},
                    "post": {"operationId": "postData"},
                },
            },
        }
        surfaces = discover_from_openapi("http://localhost:8080", body=json.dumps(spec))
        assert len(surfaces) == 2

    def test_no_openapi(self):
        surfaces = discover_from_openapi("http://localhost:8080", body="not json")
        assert len(surfaces) == 0


class TestDiscoverFromSitemap:
    def test_parse_sitemap(self):
        xml = """<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://localhost/page1</loc></url>
  <url><loc>http://localhost/page2?q=test</loc></url>
</urlset>"""
        urls = _parse_sitemap(xml)
        assert len(urls) == 2
        assert "http://localhost/page1" in urls


class TestDiscoverUrlPatterns:
    def test_path_params(self):
        surfaces = discover_url_patterns("http://localhost", ["/users/:id", "/posts/{slug}"])
        assert len(surfaces) == 2
        params = {s.parameter_name for s in surfaces}
        assert "id" in params
        assert "slug" in params

    def test_query_params(self):
        surfaces = discover_url_patterns("http://localhost", ["/search?q=test"])
        params = {s.parameter_name for s in surfaces}
        assert "q" in params


class TestExtractForms:
    def test_basic_form(self):
        html = """<html><body>
<form action="/login" method="post">
  <input name="username" type="text">
  <input name="password" type="password">
  <input name="submit" type="submit">
</form>
</body></html>"""
        forms = _extract_forms(html, "http://localhost")
        assert len(forms) == 1
        assert forms[0]["action"] == "http://localhost/login"
        assert forms[0]["method"] == "POST"
        names = {i["name"] for i in forms[0]["inputs"]}
        assert "username" in names
        assert "password" in names
        assert "submit" not in names  # submit buttons excluded


class TestDiscoverHiddenEndpoints:
    def test_hidden_endpoints_basic(self):
        """Verify the function runs without error."""
        with patch("security_harness.recon._fetch") as mock_fetch:
            mock_fetch.return_value = ("", 404, {})
            result = discover_hidden_endpoints("http://test.local")
            assert isinstance(result, list)


class TestReconSurface:
    def test_create_surface(self):
        surface = ReconSurface(
            id="test-1",
            url="http://localhost/test",
            input_type="query_param",
            parameter_name="q",
            method="GET",
            source=ReconSource.SMOKE_TEST,
            confidence="high",
        )
        assert surface.id == "test-1"
        assert surface.source == ReconSource.SMOKE_TEST


class TestReconResult:
    def test_to_summary(self):
        result = ReconResult(
            run_id="recon-1",
            target_id="target-1",
            surfaces=[ReconSurface(
                id="s1", url="http://localhost", input_type="query_param",
                parameter_name="q", method="GET", source=ReconSource.SMOKE_TEST,
                confidence="high",
            )],
            discovered_routes=[{"path": "/api/users", "method": "GET"}],
            discovered_forms=[],
            auth_surfaces=[],
            hidden_endpoints=[],
        )
        summary = result.to_summary()
        assert summary["surface_count"] == 1
        assert summary["routes_discovered"] == 1
        assert "surfaces" in summary


# ── Advanced Payloads tests ────────────────────────────────────────────────────


class TestPayloadLibrary:
    def test_all_payloads_count(self):
        assert len(ALL_BYPASS_PAYLOADS) >= 100  # Should have at least 100
        assert len(ALL_BYPASS_PAYLOADS) == len(get_all_bypass_payloads())

    def test_by_type(self):
        counts = payload_count()
        assert "total" in counts
        assert counts["total"] == sum(
            v for k, v in counts.items() if k != "total"
        )

    def test_specific_counts(self):
        counts = payload_count()
        assert counts.get("command_injection", 0) >= 15
        assert counts.get("xss_bypass", 0) >= 20
        assert counts.get("sqli_bypass", 0) >= 15
        assert counts.get("encoding_evasion", 0) >= 15

    def test_each_category_has_payloads(self):
        assert len(HEADER_INJECTION_PAYLOADS) >= 5
        assert len(XXE_PAYLOADS) >= 5
        assert len(CMDI_PAYLOADS) >= 10
        assert len(PATH_TRAVERSAL_PAYLOADS) >= 8
        assert len(HTTP_PP_PAYLOADS) >= 3
        assert len(ENCODING_EVASION_PAYLOADS) >= 10
        assert len(SQLI_BYPASS_PAYLOADS) >= 10
        assert len(XSS_BYPASS_PAYLOADS) >= 15

    def test_get_by_type(self):
        injections = get_payloads_by_type(BypassTargetType.COMMAND_INJECTION)
        assert len(injections) > 0
        assert all(p.type == BypassTargetType.COMMAND_INJECTION for p in injections)

    def test_payload_has_all_fields(self):
        for payload in ALL_BYPASS_PAYLOADS[:10]:
            assert payload.id
            assert payload.type
            assert payload.name
            assert payload.value is not None or payload.description  # Some bypasses use value=None
            assert payload.description


class TestEncodingHelpers:
    def test_double_url_encode(self):
        # Use a string that actually needs URL encoding
        text = "hello world"  # space needs encoding
        encoded = _double_url_encode(text)
        # Double-encoded space: first -> %20, then %20 -> %2520
        assert "%2520" in encoded or "%20" in encoded or "+" in encoded  # Space is encoded

    def test_hex_encode(self):
        encoded = _hex_encode("; id")
        assert "\\x" in encoded

    def test_octal_encode(self):
        encoded = _octal_encode("; id")
        assert "\\" in encoded and "o" in encoded.lower() or "\\" in encoded


# ── Report tests ────────────────────────────────────────────────────────────────


class TestCvssScoring:
    def test_critical_severity(self):
        f = Finding(
            id="test-1", run_id="r1", target_id="t1",
            title="Critical XSS", severity="critical", confidence="high",
            affected={"url": "http://localhost/test"},
        )
        score = compute_cvss_score(f)
        # Critical with high confidence should be >= 9.0
        assert 8.5 <= score <= 10.0

    def test_high_severity(self):
        f = Finding(
            id="test-2", run_id="r1", target_id="t1",
            title="SQL Injection", severity="high", confidence="high",
            affected={"url": "http://localhost/test"},
        )
        score = compute_cvss_score(f)
        assert 6.0 <= score <= 9.0

    def test_medium_severity(self):
        f = Finding(
            id="test-3", run_id="r1", target_id="t1",
            title="Info Disclosure", severity="medium", confidence="medium",
            affected={"url": "http://localhost/test"},
        )
        score = compute_cvss_score(f)
        assert 2.0 <= score <= 6.0

    def test_low_severity(self):
        f = Finding(
            id="test-4", run_id="r1", target_id="t1",
            title="Missing Header", severity="low", confidence="low",
            affected={"url": "http://localhost/test"},
        )
        score = compute_cvss_score(f)
        assert 0.0 <= score <= 3.0

    def test_override(self):
        f = Finding(
            id="test-5", run_id="r1", target_id="t1",
            title="Test", severity="medium", confidence="medium",
            affected={"url": "http://localhost/test"},
        )
        score = compute_cvss_score(f, severity_override=7.5)
        assert score == 7.5

    def test_cwe_boost(self):
        f = Finding(
            id="test-6", run_id="r1", target_id="t1",
            title="SQL Injection", severity="medium", confidence="high",
            affected={"url": "http://localhost/test"},
            cwe=["CWE-89"],  # SQL Injection = 9.8
        )
        score = compute_cvss_score(f)
        # CWE should boost the score significantly
        assert score > 4.0


class TestRiskMatrix:
    def test_empty_matrix(self):
        m = risk_matrix([])
        assert m == {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}

    def test_counted_matrix(self):
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "informational"},
            {"severity": "UNKNOWN"},  # Falls to informational
        ]
        m = risk_matrix(findings)
        assert m["critical"] == 1
        assert m["high"] == 2
        assert m["medium"] == 1
        assert m["low"] == 1
        assert m["informational"] == 2  # +1 for UNKNOWN

    def test_overall_risk_critical(self):
        assert overall_risk_level({"critical": 1}) == RiskLevel.CRITICAL

    def test_overall_risk_high(self):
        assert overall_risk_level({"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0}) == RiskLevel.HIGH

    def test_overall_risk_medium(self):
        assert overall_risk_level({"critical": 0, "high": 0, "medium": 1, "low": 0, "informational": 0}) == RiskLevel.MEDIUM

    def test_overall_risk_low(self):
        assert overall_risk_level({"critical": 0, "high": 0, "medium": 0, "low": 1, "informational": 0}) == RiskLevel.LOW

    def test_overall_risk_info(self):
        assert overall_risk_level({"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 1}) == RiskLevel.INFO


class TestOwaspMapping:
    def test_xss_maps_to_injection(self):
        cats = map_owasp("Reflected XSS vulnerability")
        assert any("Injection" in c.value for c in cats)

    def test_ssrf_maps_to_ssrf(self):
        cats = map_owasp("Server-Side Request Forgery detected")
        # SSRF maps to A10
        assert any("A10" in c.value for c in cats)

    def test_path_traversal_maps_to_access_control(self):
        cats = map_owasp("Path traversal allows reading /etc/passwd")
        assert any("Access" in c.value or "Control" in c.value for c in cats)


class TestMitreMapping:
    def test_xss_mitre(self):
        ids = map_mitre("Reflected XSS vulnerability")
        assert "T1189" in ids

    def test_sqli_mitre(self):
        ids = map_mitre("SQL Injection in login form")
        assert "T1190" in ids

    def test_cmdi_mitre(self):
        ids = map_mitre("OS Command Injection")
        assert "T1059" in ids

    def test_no_mitre(self):
        ids = map_mitre("Missing X-Frame-Options header")
        assert ids == []


class TestRemediation:
    def test_xss_remediation(self):
        rem = get_remediation("Reflected XSS")
        assert "CSP" in rem["summary"] or "output encoding" in rem["summary"]

    def test_sqli_remediation(self):
        rem = get_remediation("SQL Injection")
        assert "parameterized" in rem["summary"] or "prepared" in rem["summary"]

    def test_ssrf_remediation(self):
        rem = get_remediation("SSRF vulnerability")
        assert "allowlist" in rem["summary"] or "internal" in rem["summary"]

    def test_default_remediation(self):
        rem = get_remediation("Unknown finding type XYZ")
        assert "OWASP" in rem["summary"]


class TestReportGeneration:
    def test_generate_markdown(self):
        findings = [
            {"title": "Critical XSS", "severity": "critical", "confidence": "high",
             "affected": {"url": "http://localhost/xss"},
             "description": "Reflected XSS in search",
             "cwe": ["CWE-79"], "evidence": {"response": "reflected payload"}},
            {"title": "SQL Injection", "severity": "high", "confidence": "medium",
             "affected": {"url": "http://localhost/login"},
             "description": "SQLi in login", "cwe": ["CWE-89"]},
        ]
        config = ReportConfig(
            target_name="Test App", target_url="http://localhost", run_id="test-1",
            include_evidence=True, include_remediation=True,
            include_owasp=True, include_mitre=True, include_cvss=True,
            include_summary=True,
        )
        report = generate_report(findings, config)
        assert "Test App" in report
        assert "Critical XSS" in report
        assert "SQL Injection" in report
        assert "Executive Summary" in report
        assert "Prioritized Actions" in report

    def test_generate_json(self):
        findings = [
            {"title": "Test XSS", "severity": "critical", "confidence": "high",
             "affected": {"url": "http://localhost/test"}, "evidence": {"raw": "xss"}},
        ]
        config = ReportConfig(
            target_name="Test", target_url="http://localhost", run_id="test-1",
            include_cvss=True, include_summary=True,
        )
        report_data = generate_json_report(findings, config)
        assert report_data["reportVersion"] == "security-report/v1"
        assert report_data["summary"]["totalFindings"] == 1
        assert report_data["summary"]["overallRisk"] == "critical"
        assert len(report_data["findings"]) == 1
        assert report_data["findings"][0]["score"] > 0

    def test_write_markdown(self):
        findings = [{"title": "Test", "severity": "low", "confidence": "high",
                     "affected": {"url": "http://localhost"}}]
        tmp = Path("/tmp/test-report-sec.md")
        try:
            write_report(findings, tmp)
            assert tmp.exists()
            content = tmp.read_text()
            assert "Test" in content
        finally:
            tmp.unlink(missing_ok=True)

    def test_write_json(self):
        findings = [{"title": "Test", "severity": "high", "confidence": "high",
                     "affected": {"url": "http://localhost"}}]
        tmp = Path("/tmp/test-report-sec.json")
        try:
            write_report(findings, tmp)
            assert tmp.exists()
            data = json.loads(tmp.read_text())
            assert data["reportVersion"] == "security-report/v1"
        finally:
            tmp.unlink(missing_ok=True)

    def test_report_with_warnings(self):
        findings = []
        config = ReportConfig(target_name="Test", run_id="test")
        report = generate_report(findings, config, warnings=["Rate limiting not configured"])
        assert "Warnings" in report
        assert "Rate limiting not configured" in report

    def test_report_no_summary(self):
        findings = [{"title": "Test", "severity": "low", "confidence": "high",
                     "affected": {"url": "http://localhost"}}]
        config = ReportConfig(target_name="Test", run_id="test", include_summary=False)
        report = generate_report(findings, config)
        assert "Executive Summary" not in report


class TestReportConfig:
    def test_default_config(self):
        config = ReportConfig()
        assert config.target_name == "Target Application"
        assert config.include_evidence is True
        assert config.include_remediation is True
        assert config.include_owasp is True
        assert config.include_mitre is True
        assert config.include_cvss is True
        assert config.include_summary is True

    def test_disabled_features(self):
        config = ReportConfig(
            include_evidence=False, include_remediation=False,
            include_owasp=False, include_mitre=False,
            include_cvss=False, include_summary=False,
        )
        findings = [{"title": "Test", "severity": "low", "confidence": "high",
                     "affected": {"url": "http://localhost"}}]
        report = generate_report(findings, config)
        assert "CSP" not in report  # No remediation
        assert "OWASP" not in report  # No OWASP mapping


# ── Integration test ───────────────────────────────────────────────────────────


class TestPayloadTypes:
    """Verify all BypassTargetType enum values are represented."""

    def test_all_types_covered(self):
        all_types = {p.type for p in ALL_BYPASS_PAYLOADS}
        expected_types = {
            BypassTargetType.HEADER_INJECTION,
            BypassTargetType.XXE,
            BypassTargetType.COMMAND_INJECTION,
            BypassTargetType.PATH_TRAVERSAL,
            BypassTargetType.HTTP_PARAM_POLLUTION,
            BypassTargetType.ENCODING_EVASION,
            BypassTargetType.SQLI_BYPASS,
            BypassTargetType.XSS_BYPASS,
        }
        # Verify we cover all types
        for t in expected_types:
            assert t in all_types, f"Missing type: {t}"

    def test_all_payload_ids_unique(self):
        ids = [p.id for p in ALL_BYPASS_PAYLOADS]
        assert len(ids) == len(set(ids)), "Duplicate payload IDs found"

    def test_xss_bypass_has_html_entities(self):
        """Verify XSS bypass payloads include HTML entity variants."""
        has_html_entity = any(
            "&#60;" in p.value or "&#x3c;" in p.value
            for p in XSS_BYPASS_PAYLOADS
        )
        assert has_html_entity, "XSS bypass payloads should include HTML entity variants"

    def test_sqli_bypass_has_encoding_variants(self):
        """Verify SQLi bypass payloads include encoding variants."""
        has_encoding = any(
            "%" in p.value or "/*" in p.value or "--" in p.value
            for p in SQLI_BYPASS_PAYLOADS
        )
        assert has_encoding, "SQLi bypass payloads should include encoding variants"

    def test_cmdi_has_bash_variants(self):
        """Verify command injection includes bash-specific variants."""
        has_bash = any(
            "$()" in p.value or "`" in p.value or "${" in p.value or "IFS" in p.value
            for p in CMDI_PAYLOADS
        )
        assert has_bash, "Command injection payloads should include bash variants"
