"""Tests for findings accumulator."""
from __future__ import annotations

from security_harness.findings import FindingsAccumulator


def test_add_finding():
    """Test adding a finding."""
    acc = FindingsAccumulator()
    assert acc.add({"title": "XSS Found", "endpoint": "/api/users"})
    assert len(acc.findings) == 1


def test_add_duplicate():
    """Test deduplication of findings."""
    acc = FindingsAccumulator()
    assert acc.add({"title": "XSS Found", "endpoint": "/api/users"})
    assert not acc.add({"title": "XSS Found", "endpoint": "/api/users"})
    assert len(acc.findings) == 1


def test_add_severity_upgrade():
    """Test severity upgrade on duplicate."""
    acc = FindingsAccumulator()
    acc.add({"title": "XSS Found", "endpoint": "/api/users", "severity": "medium"})
    acc.add({"title": "XSS Found", "endpoint": "/api/users", "severity": "high"})
    assert acc.findings[0]["severity"] == "high"


def test_filter_by_severity():
    """Test filtering findings by severity."""
    acc = FindingsAccumulator()
    acc.add({"title": "Low Issue", "severity": "low"})
    acc.add({"title": "High Issue", "severity": "high"})
    acc.add({"title": "Critical Issue", "severity": "critical"})

    critical = acc.filter(severity="critical")
    assert len(critical) == 1
    assert critical[0]["title"] == "Critical Issue"


def test_by_severity():
    """Test severity counts."""
    acc = FindingsAccumulator()
    acc.add({"title": "High 1", "severity": "high"})
    acc.add({"title": "High 2", "severity": "high"})
    acc.add({"title": "Low 1", "severity": "low"})

    counts = acc.by_severity()
    assert counts["high"] == 2
    assert counts["low"] == 1


def test_high_severity_count():
    """Test high severity count."""
    acc = FindingsAccumulator()
    acc.add({"title": "C1", "endpoint": "/c1", "severity": "critical"})
    acc.add({"title": "H1", "endpoint": "/h1", "severity": "high"})
    acc.add({"title": "M1", "endpoint": "/m1", "severity": "medium"})

    assert acc.high_severity_count() == 2


def test_export_for_llm():
    """Test LLM export format."""
    acc = FindingsAccumulator()
    acc.add({"title": "XSS Found", "endpoint": "/api/users", "severity": "high"})

    text = acc.export_for_llm()
    assert "Total findings: 1" in text
    assert "XSS Found" in text


def test_add_from_scan_result():
    """Test adding findings from scan result."""
    acc = FindingsAccumulator()
    scan_result = {
        "target_id": "test",
        "run_id": "run-1",
        "findings": [
            {"title": "Finding 1", "endpoint": "/api/1"},
            {"title": "Finding 2", "endpoint": "/api/2"},
        ]
    }
    added = acc.add_from_scan_result(scan_result)
    assert added == 2
    assert len(acc.findings) == 2


def test_merge():
    """Test merging accumulators."""
    acc1 = FindingsAccumulator()
    acc1.add({"title": "Finding A", "endpoint": "/api/a"})

    acc2 = FindingsAccumulator()
    acc2.add({"title": "Finding B", "endpoint": "/api/b"})

    added = acc1.merge(acc2)
    assert added == 1
    assert len(acc1.findings) == 2


def test_export_summary():
    """Test export summary."""
    acc = FindingsAccumulator()
    acc.add({"title": "XSS", "severity": "high"})
    acc.add({"title": "SQLi", "severity": "medium"})

    summary = acc.export_summary()
    assert summary["total"] == 2
    assert summary["by_severity"]["high"] == 1
