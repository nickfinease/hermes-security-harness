"""Hermes-native defensive security harness."""

__version__ = "0.1.0"

from .artifacts import Finding, GraderResult, HttpPoc, HttpStep, redact_secrets
from .auth_scan import AuthConfig, AuthScanResult, CookieSession, run_auth_scan
from .chains import (
    ChainConfig, ChainRule, ChainFinding, run_chain_analysis,
    chain_to_finding, write_chain_report, find_chains,
    auto_tag_findings, RULES_DEFAULT,
)
from .contracts import (
    ContractValidationError, ValidationResult, load_contract,
    validate_against_contract, validate_and_raise, validate_finding,
    validate_grader, validate_job, validate_poc_replay,
)
from .csrf_scan import CSRFConfig, CSRFScanResult, run_csrf_scan, CSRFAuthConfig
from .dependency_audit import (
    DependencyScanResult, Dependency, VulnerabilityFinding,
    parse_requirements_txt, parse_package_lock_json, parse_go_sum,
    parse_yarn_lock, parse_gemfile_lock, parse_cargo_lock, run_dependency_audit,
)
from .http_smoke import HttpSmokeResult, run_http_smoke
from .http_verb_scan import HTTPVerbConfig, HTTPVerbResult, run_http_verb_scan
from .idor_scan import IDORConfig, IDORScanResult, run_idor_scan, IDORAuthConfig
from .injection_scanner import (
    InjectionScanResult, XSSPayload, SQLiPayload, SSRFEndpoint,
    AuthenticationResult, XSS_PAYLOADS, SQLI_PAYLOADS, SSRF_ENDPOINTS,
    run_injection_scan,
)
from .jobs import JobStartResult, read_job, run_job_worker, start_job, get_report
from .jwt_scan import JWTConfig, JWTScanResult, run_jwt_scan
from .poc_replay import PocReplayResult, load_http_poc, run_poc_replay
from .rate_limit import RateLimitConfig, RateLimitResult, run_rate_limit_scan
from .recon import (
    ReconResult, ReconSurface, ReconSource, run_recon, build_recon_surfaces,
    discover_from_openapi, discover_from_js_bundle, discover_from_sitemap,
    discover_url_patterns, discover_auth_surfaces, discover_hidden_endpoints,
    discover_from_rsc_payload, discover_from_source_dir, _extract_nextjs_routes,
)
from .tls_scan import TLSResult, run_tls_scan, HeaderResult, run_header_scan, check_tls_config, check_security_headers
from .sandbox import (
    SandboxHandle, SandboxPolicy, SandboxValidationError, SandboxModeError,
    launch_gvisor, launch_bwrap, launch_firejail, launch_container,
    launch_sandbox, list_supported_modes, validate_sandbox_mode, SANDBOX_MODES,
)
from .static_scan import StaticScanResult, run_static_scan
from .stored_xss_scan import StoredXSSConfig, StoredXSSResult, run_stored_xss_scan
from .web_target import WebTargetConfig, TargetValidationError, load_target_config
from .advanced_payloads import (
    BypassPayload, BypassTargetType, ALL_BYPASS_PAYLOADS,
    get_all_bypass_payloads, payload_count, HEADER_INJECTION_PAYLOADS,
    XXE_PAYLOADS, CMDI_PAYLOADS, PATH_TRAVERSAL_PAYLOADS, HTTP_PP_PAYLOADS,
    ENCODING_EVASION_PAYLOADS, SQLI_BYPASS_PAYLOADS, XSS_BYPASS_PAYLOADS,
)
from .report import (
    ReportConfig, generate_report, generate_json_report, write_report,
    compute_cvss_score, risk_matrix, RiskLevel,
)
from .wstg_base import BaseScanConfig, BaseScanResult, _run_scan
from .engagement import (
    EngagementError, EngagementCryptoError, encrypt_value, decrypt_value,
    Credential, EngagementScope, Engagement,
)
from .intake import prompt_intake, create_intake_from_config
from .findings import FindingsAccumulator
from .pipeline import PhaseResult, PipelineResult, Pipeline, run_pipeline
from .chain_gate import ChainGateResult, run_chain_gate, run_deterministic_chain_gate

__all__ = [
    "__version__",
    # Artifacts
    "Finding", "GraderResult", "HttpPoc", "HttpStep", "redact_secrets",
    # Chains
    "ChainConfig", "ChainRule", "ChainFinding", "run_chain_analysis",
    "chain_to_finding", "write_chain_report", "find_chains",
    "auto_tag_findings", "RULES_DEFAULT",
    # Contracts
    "ContractValidationError", "ValidationResult", "load_contract",
    "validate_against_contract", "validate_and_raise", "validate_finding",
    "validate_grader", "validate_job", "validate_poc_replay",
    # CSRF scan
    "CSRFConfig", "CSRFAuthConfig", "CSRFScanResult", "run_csrf_scan",
    # IDOR/BOLA scan
    "IDORConfig", "IDORAuthConfig", "IDORScanResult", "run_idor_scan",
    # JWT scan
    "JWTConfig", "JWTScanResult", "run_jwt_scan",
    # HTTP Verb tampering scan
    "HTTPVerbConfig", "HTTPVerbResult", "run_http_verb_scan",
    # Stored XSS scan
    "StoredXSSConfig", "StoredXSSResult", "run_stored_xss_scan",
    # WSTG base utilities
    "BaseScanConfig", "BaseScanResult", "_run_scan",
    # Web target
    "WebTargetConfig", "TargetValidationError", "load_target_config",
    # HTTP smoke
    "HttpSmokeResult", "run_http_smoke",
    # Static scan
    "StaticScanResult", "run_static_scan",
    # PoC replay
    "PocReplayResult", "load_http_poc", "run_poc_replay",
    # Sandbox
    "SandboxHandle", "SandboxPolicy", "SandboxValidationError", "SandboxModeError",
    "launch_gvisor", "launch_bwrap", "launch_firejail", "launch_container",
    "launch_sandbox", "list_supported_modes", "validate_sandbox_mode", "SANDBOX_MODES",
    # Jobs
    "JobStartResult", "read_job", "run_job_worker", "start_job", "get_report",
    # Injection scanner
    "InjectionScanResult", "AuthenticationResult", "XSSPayload", "SQLiPayload",
    "SSRFEndpoint", "XSS_PAYLOADS", "SQLI_PAYLOADS", "SSRF_ENDPOINTS", "run_injection_scan",
    # Auth scan
    "AuthConfig", "AuthScanResult", "CookieSession", "run_auth_scan",
    # Dependency audit
    "DependencyScanResult", "Dependency", "VulnerabilityFinding",
    "parse_requirements_txt", "parse_package_lock_json", "parse_go_sum",
    "parse_yarn_lock", "parse_gemfile_lock", "parse_cargo_lock", "run_dependency_audit",
    # Rate limit
    "RateLimitConfig", "RateLimitResult", "run_rate_limit_scan",
    # Recon
    "ReconResult", "ReconSurface", "ReconSource", "run_recon",
    "build_recon_surfaces", "discover_from_openapi", "discover_from_js_bundle",
    "discover_from_sitemap", "discover_url_patterns", "discover_auth_surfaces",
    "discover_hidden_endpoints", "discover_from_rsc_payload",
    "discover_from_source_dir", "_extract_nextjs_routes",
    # Advanced payloads
    "BypassPayload", "BypassTargetType", "ALL_BYPASS_PAYLOADS",
    "get_all_bypass_payloads", "payload_count", "HEADER_INJECTION_PAYLOADS",
    "XXE_PAYLOADS", "CMDI_PAYLOADS", "PATH_TRAVERSAL_PAYLOADS", "HTTP_PP_PAYLOADS",
    "ENCODING_EVASION_PAYLOADS", "SQLI_BYPASS_PAYLOADS", "XSS_BYPASS_PAYLOADS",
    # Report generation
    "ReportConfig", "generate_report", "generate_json_report", "write_report",
    "compute_cvss_score", "risk_matrix", "RiskLevel",
    "TLSResult", "run_tls_scan", "HeaderResult", "run_header_scan",
    # Engagement state
    "EngagementError", "EngagementCryptoError", "encrypt_value", "decrypt_value",
    "Credential", "EngagementScope", "Engagement",
    # Intake
    "prompt_intake", "create_intake_from_config",
    # Findings accumulator
    "FindingsAccumulator",
    # Pipeline
    "PhaseResult", "PipelineResult", "Pipeline", "run_pipeline",
    # Chain gate
    "ChainGateResult", "run_chain_gate", "run_deterministic_chain_gate",
]
