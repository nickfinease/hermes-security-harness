"""Tests for the OS-level sandbox launchers."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from security_harness.sandbox import (
    SANDBOX_MODES,
    SandboxHandle,
    SandboxModeError,
    SandboxPolicy,
    SandboxValidationError,
    launch_bwrap,
    launch_container,
    launch_firejail,
    launch_gvisor,
    launch_sandbox,
    list_supported_modes,
    validate_sandbox_mode,
)


# ── Sandbox Mode Tests ────────────────────────────────────────────────────────


def test_sandbox_modes_constant():
    assert SANDBOX_MODES == {"gvisor", "bwrap", "container", "firejail"}


def test_validate_sandbox_mode_valid():
    for mode in SANDBOX_MODES:
        validate_sandbox_mode(mode)  # Should not raise


def test_validate_sandbox_mode_invalid():
    with pytest.raises(SandboxValidationError, match="invalid sandbox mode"):
        validate_sandbox_mode("invalid_mode")


def test_list_supported_modes_includes_container():
    modes = list_supported_modes()
    assert "container" in modes  # Always available (stdlib)


def test_launch_sandbox_dispatches_correct_mode():
    handle = launch_sandbox("container", ["echo", "hello"])
    assert handle.sandbox_mode == "container"
    assert handle.pid > 0


def test_launch_container_basic():
    handle = launch_container(["echo", "container-test"])
    assert handle.sandbox_mode == "container"
    assert handle.pid > 0
    assert handle.tmp_dir is not None


def test_launch_sandbox_rejects_invalid_mode():
    with pytest.raises(SandboxModeError, match="unknown sandbox mode"):
        launch_sandbox("invalid", ["echo", "test"])


# ── Sandbox Handle Tests ─────────────────────────────────────────────────────


def test_sandbox_handle_cleans_up(tmp_path):
    handle = launch_container(["echo", "cleanup-test"])
    tmp_dir = handle.tmp_dir
    assert tmp_dir is not None
    handle.cleanup()
    assert not tmp_dir.exists()


def test_sandbox_handle_wait_returns_none_after_cleanup():
    handle = launch_container(["echo", "wait-test"])
    result = handle.wait()
    assert handle.tmp_dir is None or not handle.tmp_dir.exists()


def test_sandbox_handle_returns_correct_mode():
    handle = launch_container(["echo", "mode-test"])
    assert handle.sandbox_mode == "container"
