"""Tests for dependency audit."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_harness.dependency_audit import (
    Dependency,
    DependencyScanResult,
    VulnerabilityFinding,
    parse_package_lock_json,
    parse_requirements_txt,
    parse_go_sum,
    parse_yarn_lock,
    parse_gemfile_lock,
    parse_cargo_lock,
    run_dependency_audit,
)


def test_parse_requirements_txt_simple(tmp_path):
    """Parse a simple requirements.txt."""
    req = tmp_path / "requirements.txt"
    req.write_text("django==4.2.3\nflask>=2.0.0\nrequests==2.31.0\n")
    deps = parse_requirements_txt(req)
    assert len(deps) >= 3
    names = [d.name for d in deps]
    assert "django" in names


def test_parse_requirements_txt_skips_comments(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("# Comment line\ndjango==4.2.3\n  # indented comment\nflask==2.0.0\n")
    deps = parse_requirements_txt(req)
    names = [d.name for d in deps]
    assert "django" in names
    assert "flask" in names


def test_parse_package_lock_json(tmp_path):
    """Parse package-lock.json with dependencies."""
    pkg = tmp_path / "package-lock.json"
    pkg.write_text(json.dumps({
        "packages": {
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/express": {"version": "4.18.1"},
        }
    }))
    deps = parse_package_lock_json(pkg)
    assert len(deps) >= 2
    names = [d.name for d in deps]
    assert "lodash" in names


def test_parse_go_sum(tmp_path):
    """Parse go.sum."""
    go_sum = tmp_path / "go.sum"
    go_sum.write_text(
        "golang.org/x/net v0.15.0 h1:...\n"
        "golang.org/x/net v0.15.0/go.mod h1:...\n"
    )
    deps = parse_go_sum(go_sum)
    assert any(d.name == "golang.org/x/net" for d in deps)
    assert all(d.ecosystem == "go" for d in deps)


def test_parse_yarn_lock(tmp_path):
    """Parse yarn.lock."""
    yarn = tmp_path / "yarn.lock"
    yarn.write_text('''
lodash@^4.17.0:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"

express@^4.18.0:
  version "4.18.2"
''')
    deps = parse_yarn_lock(yarn)
    assert any(d.name == "lodash" for d in deps)


def test_parse_gemfile_lock(tmp_path):
    """Parse Gemfile.lock."""
    gemfile = tmp_path / "Gemfile.lock"
    gemfile.write_text('''
GEM
  remote: https://rubygems.org/
  specs:
    rails (6.1.7)
    rack (2.2.7)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 6.1)
''')
    deps = parse_gemfile_lock(gemfile)
    assert any(d.name == "rails" for d in deps)
    assert all(d.ecosystem == "rubygems" for d in deps)


def test_parse_cargo_lock(tmp_path):
    """Parse Cargo.lock."""
    cargo = tmp_path / "Cargo.lock"
    cargo.write_text('''
[[package]]
name = "serde_json"
version = "1.0.107"

[[package]]
name = "tokio"
version = "1.30.0"
''')
    deps = parse_cargo_lock(cargo)
    assert any(d.name == "serde_json" for d in deps)
    assert any(d.name == "tokio" for d in deps)


def test_version_matches():
    from security_harness.dependency_audit import _version_matches
    assert _version_matches("4.17.20", "4.0.0", "4.17.21") is True
    assert _version_matches("4.17.21", "4.0.0", "4.17.21") is False
    assert _version_matches("5.0.0", "4.0.0", "4.17.21") is False


def test_run_dependency_audit_on_real_source(tmp_path):
    """Run full dependency audit and verify results."""
    # Create a fake source tree with a requirements.txt containing a known vulnerable lib
    source_root = tmp_path / "source"
    source_root.mkdir()
    req = source_root / "requirements.txt"
    req.write_text("django==3.2.15\nflask==2.3.0\nrequests==2.28.0\n")

    result = run_dependency_audit(
        source_root,
        artifacts_root=tmp_path / "runs",
    )

    assert isinstance(result, DependencyScanResult)
    assert result.success is True
    assert result.total_dependencies >= 1
    # django 3.2.15 should be flagged (CVE-2023-36053)
    vulnerable_names = [f.get("affected", {}).get("package", "") for f in result.findings]
    assert "django" in vulnerable_names


def test_run_dependency_audit_respects_exclude(tmp_path):
    """Verify audit can skip excluded files."""
    source_root = tmp_path / "source"
    source_root.mkdir()
    req = source_root / "requirements.txt"
    req.write_text("django==3.2.15\n")

    result = run_dependency_audit(
        source_root,
        exclude_patterns=["requirements.txt"],
        artifacts_root=tmp_path / "runs",
    )

    # Should find no deps because we excluded requirements.txt
    assert result.total_dependencies == 0
