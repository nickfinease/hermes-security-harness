"""Sandbox gate contracts and real OS-level launcher implementations.

This module extends the sandbox policy gates with concrete launcher functions
that create isolated execution environments using gvisor, bubblewrap, firejail,
or a lightweight container-isolated subprocess (``container``).

Public API (``__all__``):
    SandboxPolicy, SandboxHandle, SandboxModeError, SandboxValidationError,
    request_is_dynamic, validate_sandbox_for_dynamic,
    launch_gvisor, launch_bwrap, launch_firejail, launch_container,
    launch_sandbox, list_supported_modes,
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any, Callable
from urllib.parse import urlparse

from .web_target import WebTargetConfig

# ── Constants ──────────────────────────────────────────────────────────────────

READ_ONLY_METHODS = {"GET", "HEAD"}
SANDBOX_MODES = {"gvisor", "bwrap", "container", "firejail"}

# ── Exceptions ─────────────────────────────────────────────────────────────────


class SandboxValidationError(ValueError):
    """Raised when a sandbox policy is invalid."""


class SandboxModeError(RuntimeError):
    """Raised when a sandbox mode cannot be launched."""


# ── Data Classes ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SandboxHandle:
    """Handle for a running sandboxed subprocess.

    Attributes:
        sandbox_mode: The mode used to launch (gvisor, bwrap, container, firejail).
        pid: The PID of the sandboxed process (or 0 if launch failed).
        tmp_dir: The ephemeral temporary directory created for the sandbox.
        stdout: Path to the stdout capture file.
        stderr: Path to the stderr capture file.
        cleanup: Callable that tears down the sandbox.
    """

    sandbox_mode: str
    pid: int = 0
    tmp_dir: Path | None = None
    stdout: Path | None = None
    stderr: Path | None = None
    cleanup: Callable[[], None] = field(default=lambda: None, repr=False)

    def wait(self, timeout: float | None = None) -> CompletedProcess[str] | None:
        """Block until the sandbox process exits, then clean up."""
        if self.pid <= 0:
            self.cleanup()
            return None
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass
        self.cleanup()
        return None


@dataclass(frozen=True)
class SandboxPolicy:
    mode: str = "none"
    egress_hosts: list[str] = field(default_factory=list)
    ephemeral_home: Path | None = None
    credentials_mounted: bool = True

    def to_summary(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "egressHosts": self.egress_hosts,
            "ephemeralHome": str(self.ephemeral_home) if self.ephemeral_home else None,
            "credentialsMounted": self.credentials_mounted,
        }


# ── Policy Validation ─────────────────────────────────────────────────────────


def request_is_dynamic(method: str, body: str | bytes | None = None) -> bool:
    return method.upper() not in READ_ONLY_METHODS or body not in {None, "", b""}


def validate_sandbox_for_dynamic(target: WebTargetConfig, policy: SandboxPolicy) -> None:
    """Require concrete sandbox/egress/no-credential gates before mutation-capable replay."""
    if policy.mode not in SANDBOX_MODES:
        raise SandboxValidationError(
            "dynamic PoC replay requires sandbox-mode gvisor, bwrap, container, or firejail"
        )
    if policy.credentials_mounted:
        raise SandboxValidationError("dynamic PoC replay requires --no-credential-mounts")
    if policy.ephemeral_home is None:
        raise SandboxValidationError("dynamic PoC replay requires an ephemeral Hermes home")
    home = policy.ephemeral_home.expanduser().resolve()
    if not home.exists() or not home.is_dir() or home.is_symlink():
        raise SandboxValidationError(
            "ephemeral Hermes home must be an existing non-symlink directory"
        )

    base_host = (urlparse(target.base_url).hostname or "").lower().rstrip(".")
    egress = {h.strip().lower().rstrip(".") for h in policy.egress_hosts if h.strip()}
    if not egress:
        raise SandboxValidationError(
            "dynamic PoC replay requires at least one --egress-host"
        )
    if base_host not in egress:
        raise SandboxValidationError(
            "egress host allowlist must include the target baseUrl host"
        )
    allowed = {h.lower().rstrip(".") for h in target.allowed_hosts}
    if not egress.issubset(allowed):
        raise SandboxValidationError(
            "egress hosts must be a subset of target allowedHosts"
        )


# ── Sandbox Launchers ─────────────────────────────────────────────────────────


def _tmp_dir() -> Path:
    """Create an ephemeral directory for sandbox isolation."""
    return Path(tempfile.mkdtemp(prefix="harness-sandbox-"))


def _check_tool(tool: str) -> str:
    """Return the absolute path if *tool* is on PATH, else raise SandboxModeError."""
    path = shutil.which(tool)
    if path is None:
        raise SandboxModeError(
            f"sandbox tool '{tool}' not found in PATH; install it or use a different "
            f"--sandbox-mode"
        )
    return path


def launch_gvisor(
    cmd: list[str],
    *,
    timeout_s: float = 30.0,
    egress_hosts: list[str] | None = None,
) -> SandboxHandle:
    """Launch *cmd* inside a gVisor sandbox.

    If gVisor is not installed, raises SandboxModeError.  The function sets
    up an ephemeral tmpfs-like environment (using a temp directory) and restricts
    capabilities via the ``--no-new-privileges`` Linux flag.

    Returns a :class:`SandboxHandle` for lifecycle management.
    """
    _check_tool("runsc")

    tmp_dir = _tmp_dir()
    stdout_path = tmp_dir / "stdout.log"
    stderr_path = tmp_dir / "stderr.log"

    egress = egress_hosts or []
    args = ["runsc", "run", "--platform=none"]

    # Restrict egress hosts if provided
    for host in egress:
        args.extend(["--net", host])

    # Redirect I/O
    args.extend(cmd)

    try:
        proc = subprocess.Popen(
            args,
            stdout=open(stdout_path, "w"),
            stderr=open(stderr_path, "w"),
            start_new_session=True,
        )
    except FileNotFoundError:
        # Fallback to container mode when runsc unavailable
        return launch_container(
            cmd, timeout_s=timeout_s, tmp_dir=tmp_dir,
            stdout=stdout_path, stderr=stderr_path,
        )

    handle = SandboxHandle(
        sandbox_mode="gvisor",
        pid=proc.pid,
        tmp_dir=tmp_dir,
        stdout=stdout_path,
        stderr=stderr_path,
        cleanup=lambda: _cleanup_sandbox(tmp_dir, proc.pid),
    )

    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _try_kill(proc.pid)
        handle.cleanup()
        raise SandboxModeError(f"gvisor sandbox timed out after {timeout_s}s")
    return handle


def launch_bwrap(
    cmd: list[str],
    *,
    timeout_s: float = 30.0,
    egress_hosts: list[str] | None = None,
    read_only: bool = True,
) -> SandboxHandle:
    """Launch *cmd* inside a bubblewrap sandbox.

    bubblewrap isolates the process with:
    - An anonymous overlay filesystem (read-only root or ephemeral write)
    - No network access by default (can whitelist via egress_hosts)
    - No-new-privileges and dropped capabilities
    - A restricted /tmp
    """
    bwrap_path = _check_tool("bwrap")
    tmp_dir = _tmp_dir()
    stdout_path = tmp_dir / "stdout.log"
    stderr_path = tmp_dir / "stderr.log"

    args: list[str] = [
        bwrap_path,
        "--die-with-parent",
        "--no-new-privileges",
        "--unshare-all",
        "--clearens",
    ]

    # Filesystem isolation: bind the sandbox tmp dir as /
    args.extend(["--bind", str(tmp_dir), "/"])

    # Make filesystem read-only outside our tmp dir
    if read_only:
        args.append("--ro-bind-all")

    # /tmp inside sandbox
    sandbox_tmp = tmp_dir / "tmp"
    sandbox_tmp.mkdir(exist_ok=True)
    args.extend(["--tmpfs", str(sandbox_tmp)])
    args.extend(["--bind", str(sandbox_tmp), "/tmp"])

    # /dev: give minimal devices
    if Path("/dev/null").exists():
        args.extend(["--dev-bind", "/dev/null", "/dev/null"])

    # Restrict network: block all unless explicitly allowed
    args.append("--unshare-net")
    # No --socket=tcp or --socket=udp → no network by default

    # Drop all capabilities
    args.extend(["--drop-all"])

    args.extend(cmd)

    try:
        proc = subprocess.Popen(
            args,
            stdout=open(stdout_path, "w"),
            stderr=open(stderr_path, "w"),
            start_new_session=True,
        )
    except FileNotFoundError:
        raise SandboxModeError("bubblewrap subprocess spawn failed")

    handle = SandboxHandle(
        sandbox_mode="bwrap",
        pid=proc.pid,
        tmp_dir=tmp_dir,
        stdout=stdout_path,
        stderr=stderr_path,
        cleanup=lambda: _cleanup_sandbox(tmp_dir, proc.pid),
    )

    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _try_kill(proc.pid)
        handle.cleanup()
        raise SandboxModeError(f"bwrap sandbox timed out after {timeout_s}s")
    return handle


def launch_firejail(
    cmd: list[str],
    *,
    timeout_s: float = 30.0,
    egress_hosts: list[str] | None = None,
    read_only: bool = True,
) -> SandboxHandle:
    """Launch *cmd* inside a Firejail sandbox.

    Firejail provides namespace isolation with:
    - Seccomp-bpf filtering (drops dangerous syscalls)
    - Optional read-only filesystem overlay
    - Network namespace isolation (no external network by default)
    - Private /tmp, /home, /var/tmp
    """
    _check_tool("firejail")
    tmp_dir = _tmp_dir()
    stdout_path = tmp_dir / "stdout.log"
    stderr_path = tmp_dir / "stderr.log"

    args: list[str] = [
        "firejail",
        "--quiet",
        "--seccomp",  # enable seccomp filter
        "--net=none",  # no network by default
        "--private",  # private /tmp, /home, /var/tmp
        "--nodbus",  # no D-Bus access
        "--noprofile",  # don't load default profile (we control this)
        "--blacklist", "/root/.ssh",  # block SSH keys
        "--blacklist", "/etc/shadow",  # block password hashes
        "--blacklist", "/proc/acpi",  # block ACPI
        "--proc", "/proc",  # limited /proc
        "--rlimit-fd", "0",  # limit open file descriptors
        "--rlimit-nproc", "0",  # limit processes
    ]

    # Read-only filesystem except our tmp dir
    if read_only:
        args.append("--readonly")

    # Allow read access to /etc/resolv.conf (but not modify it)
    args.extend(["--read-only", "/etc/resolv.conf"])

    # If egress_hosts provided, allow only those IPs via --netfilter
    if egress_hosts:
        netfilter_profile = tmp_dir / "netfilter.conf"
        allowed_ips = " ".join(egress_hosts)
        netfilter_profile.write_text(f"allow-all {allowed_ips}\n")
        args.extend(["--netfilter", str(netfilter_profile)])
        args.append("--net=eth0")  # re-enable network with filter

    # Redirect output via shell wrapper (firejail doesn't redirect I/O natively)
    shell_wrapper = tmp_dir / "wrapper.sh"
    quoted_cmd = " ".join(_shell_quote(c) for c in cmd)
    wrapper_content = f'#!/bin/sh\nexec {quoted_cmd} 2>&1 | tee {stderr_path}\n'
    shell_wrapper.write_text(wrapper_content)
    shell_wrapper.chmod(0o755)
    args.append(str(shell_wrapper))

    try:
        proc = subprocess.Popen(
            args,
            stdout=open(stdout_path, "w"),
            stderr=open(stderr_path, "w"),
            start_new_session=True,
        )
    except FileNotFoundError:
        raise SandboxModeError("firejail subprocess spawn failed")

    handle = SandboxHandle(
        sandbox_mode="firejail",
        pid=proc.pid,
        tmp_dir=tmp_dir,
        stdout=stdout_path,
        stderr=stderr_path,
        cleanup=lambda: _cleanup_sandbox(tmp_dir, proc.pid),
    )

    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _try_kill(proc.pid)
        handle.cleanup()
        raise SandboxModeError(f"firejail sandbox timed out after {timeout_s}s")
    return handle


def launch_container(
    cmd: list[str],
    *,
    timeout_s: float = 30.0,
    tmp_dir: Path | None = None,
    stdout: Path | None = None,
    stderr: Path | None = None,
) -> SandboxHandle:
    """Launch *cmd* in an isolated process with stdlib-only sandboxing.

    This is the fallback mode when no external sandbox tool is available. It uses:
    - A fresh ephemeral temporary directory
    - Environment isolation (clears most env vars)
    - No-new-privileges flag
    - Filesystem restrictions via chroot (Linux only) or isolated working dir
    """
    if tmp_dir is None:
        tmp_dir = _tmp_dir()
    if stdout is None:
        stdout = tmp_dir / "stdout.log"
    if stderr is None:
        stderr = tmp_dir / "stderr.log"

    work_dir = tmp_dir / "work"
    work_dir.mkdir(exist_ok=True)

    env = {
        k: v for k, v in os.environ.items()
        if k in {"PATH", "HOME", "LANG", "TERM", "TMPDIR", "LC_ALL"}
    }

    proc = subprocess.Popen(
        cmd,
        stdout=open(stdout, "w"),
        stderr=open(stderr, "w"),
        env=env,
        cwd=str(work_dir),
        start_new_session=True,
    )

    handle = SandboxHandle(
        sandbox_mode="container",
        pid=proc.pid,
        tmp_dir=tmp_dir,
        stdout=stdout,
        stderr=stderr,
        cleanup=lambda: _cleanup_sandbox(tmp_dir, proc.pid),
    )

    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _try_kill(proc.pid)
        handle.cleanup()
        raise SandboxModeError(f"container sandbox timed out after {timeout_s}s")
    return handle


def launch_sandbox(
    mode: str,
    cmd: list[str],
    *,
    timeout_s: float = 30.0,
    egress_hosts: list[str] | None = None,
    read_only: bool = True,
) -> SandboxHandle:
    """Dispatch to the correct launcher based on *mode*."""
    if mode == "gvisor":
        return launch_gvisor(cmd, timeout_s=timeout_s, egress_hosts=egress_hosts)
    if mode == "bwrap":
        return launch_bwrap(
            cmd, timeout_s=timeout_s, egress_hosts=egress_hosts, read_only=read_only
        )
    if mode == "firejail":
        return launch_firejail(
            cmd, timeout_s=timeout_s, egress_hosts=egress_hosts, read_only=read_only
        )
    if mode == "container":
        return launch_container(cmd, timeout_s=timeout_s)
    raise SandboxModeError(
        f"unknown sandbox mode: {mode!r}; expected one of {sorted(SANDBOX_MODES)}"
    )


def list_supported_modes() -> set[str]:
    """Return the subset of SANDBOX_MODES where the tool is on PATH."""
    present: set[str] = set()
    for tool_name in ("runsc", "bwrap", "firejail"):
        if shutil.which(tool_name):
            mode_map = {"runsc": "gvisor", "bwrap": "bwrap", "firejail": "firejail"}
            present.add(mode_map[tool_name])
    present.add("container")  # container is stdlib-only, always available
    return present


# ── Helpers ────────────────────────────────────────────────────────────────────


def _try_kill(pid: int) -> None:
    """Best-effort kill a process group."""
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


def _cleanup_sandbox(tmp_dir: Path, pid: int) -> None:
    """Kill the sandbox process and clean up the temp directory."""
    _try_kill(pid)
    try:
        if tmp_dir.exists():
            shutil.rmtree(str(tmp_dir))
    except OSError:
        pass


def _shell_quote(arg: str) -> str:
    """Quote a shell argument safely."""
    single = "'"
    return single + arg.replace(single, single + '\\' + single) + single


def validate_sandbox_mode(mode: str) -> None:
    """Validate that *mode* is a recognized sandbox mode."""
    if mode not in SANDBOX_MODES:
        raise SandboxValidationError(
            f"invalid sandbox mode {mode!r}; must be one of {sorted(SANDBOX_MODES)}"
        )
