"""Hermes-native defensive security harness."""

__version__ = "0.1.0"

from .artifacts import Finding, GraderResult, HttpPoc, HttpStep, redact_secrets
from .auth_scan import AuthConfig, AuthScanResult, CookieSession, run_auth_scan
from .contracts import (
    ContractValidationError,
    ValidationResult,
    load_contract,
    validate_against_contract,
    validate_and_raise,
    validate_finding,
    validate_grader,
    validate_job,
    validate_poc_replay,
)
from .dependency_audit import (
    DependencyScanResult,
    Dependency,
    VulnerabilityFinding,
    parse_requirements_txt,
    parse_package_lock_json,
    parse_go_sum,
    parse_yarn_lock,
    parse_gemfile_lock,
    parse_cargo_lock,
    run_dependency_audit,
)
from .http_smoke import HttpSmokeResult, run_http_smoke
from .injection_scanner import (
    InjectionScanResult,
    XSSPayload,
    SQLiPayload,
    SSRFEndpoint,
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    SSRF_ENDPOINTS,
    run_injection_scan,
)
from .jobs import JobStartResult, read_job, run_job_worker, start_job, get_report
from .poc_replay import PocReplayResult, load_http_poc, run_poc_replay
from .rate_limit import RateLimitConfig, RateLimitResult, run_rate_limit_scan
from .sandbox import (
    SandboxHandle,
    SandboxPolicy,
    SandboxValidationError,
    SandboxModeError,
    launch_gvisor,
    launch_bwrap,
    launch_firejail,
    launch_container,
    launch_sandbox,
    list_supported_modes,
    validate_sandbox_mode,
    SANDBOX_MODES,
)
from .static_scan import StaticScanResult, run_static_scan
from .web_target import (
    WebTargetConfig,
    TargetValidationError,
    load_target_config,
)

__all__ = [
    # Version
    "__version__",
    # Artifacts
    "Finding",
    "GraderResult",
    "HttpPoc",
    "HttpStep",
    "redact_secrets",
    # Contracts
    "ContractValidationError",
    "ValidationResult",
    "load_contract",
    "validate_against_contract",
    "validate_and_raise",
    "validate_finding",
    "validate_grader",
    "validate_job",
    "validate_poc_replay",
    # Web target
    "WebTargetConfig",
    "TargetValidationError",
    "load_target_config",
    # HTTP smoke
    "HttpSmokeResult",
    "run_http_smoke",
    # Static scan
    "StaticScanResult",
    "run_static_scan",
    # PoC replay
    "PocReplayResult",
    "load_http_poc",
    "run_poc_replay",
    # Sandbox
    "SandboxHandle",
    "SandboxPolicy",
    "SandboxValidationError",
    "SandboxModeError",
    "launch_gvisor",
    "launch_bwrap",
    "launch_firejail",
    "launch_container",
    "launch_sandbox",
    "list_supported_modes",
    "validate_sandbox_mode",
    "SANDBOX_MODES",
    # Jobs
    "JobStartResult",
    "read_job",
    "run_job_worker",
    "start_job",
    "get_report",
    # Injection scanner
    "InjectionScanResult",
    "XSSPayload",
    "SQLiPayload",
    "SSRFEndpoint",
    "XSS_PAYLOADS",
    "SQLI_PAYLOADS",
    "SSRF_ENDPOINTS",
    "run_injection_scan",
    # Auth scan
    "AuthConfig",
    "AuthScanResult",
    "CookieSession",
    "run_auth_scan",
    # Dependency audit
    "DependencyScanResult",
    "Dependency",
    "VulnerabilityFinding",
    "parse_requirements_txt",
    "parse_package_lock_json",
    "parse_go_sum",
    "parse_yarn_lock",
    "parse_gemfile_lock",
    "parse_cargo_lock",
    "run_dependency_audit",
    # Rate limit
    "RateLimitConfig",
    "RateLimitResult",
    "run_rate_limit_scan",
]
