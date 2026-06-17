"""CLI for the Hermes security harness MVP."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .auth_scan import AuthConfig, run_auth_scan
from .dependency_audit import run_dependency_audit
from .http_smoke import run_http_smoke
from .injection_scanner import run_injection_scan
from .jobs import get_report, read_job, run_job_worker, start_job
from .poc_replay import run_poc_replay
from .rate_limit import RateLimitConfig, run_rate_limit_scan
from .runners import AgentRunRequest, HermesCliRunner
from .sandbox import SandboxPolicy, SandboxValidationError
from .static_scan import DEFAULT_STATIC_TEMPLATE, run_static_scan
from .scan_handler import handle_scan_command
from .recon import run_recon
from .csrf_scan import run_csrf_scan
from .http_verb_scan import run_http_verb_scan
from .idor_scan import run_idor_scan
from .jwt_scan import run_jwt_scan
from .stored_xss_scan import run_stored_xss_scan
from .chains import run_chain_analysis, chain_to_finding, write_chain_report, ChainConfig
from .report import ReportConfig, generate_report, generate_json_report, write_report, risk_matrix
from .web_target import TargetValidationError, load_target_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-harness")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-target", help="Validate a web target config")
    validate.add_argument("config", help="Path to web-target/v1 YAML or JSON config")

    agent = sub.add_parser("agent-run", help="Run one headless Hermes prompt and capture artifacts")
    agent.add_argument("prompt", help="Prompt text")
    agent.add_argument("--workdir", default=".")
    agent.add_argument("--artifacts", default="runs")
    agent.add_argument("--toolsets", default="file,terminal")
    agent.add_argument("--model")
    agent.add_argument("--provider")
    agent.add_argument("--max-turns", type=int, default=90)
    agent.add_argument("--timeout", type=float, default=600)
    agent.add_argument("--ignore-rules-unsafe", action="store_true", help="Pass --ignore-rules to Hermes. Unsafe; bypasses repo/user rules for reproducible sandbox runs only.")
    agent.add_argument("--ignore-user-config", action="store_true", help="Ignore ~/.hermes/config.yaml; requires credentials/config through env or flags.")
    agent.add_argument("--yolo", action="store_true", help="Bypass Hermes approvals. Use only inside a strong sandbox.")

    smoke = sub.add_parser("http-smoke", help="Run bounded GET-only reachability and security-header checks")
    smoke.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    smoke.add_argument("--artifacts", default="runs")
    smoke.add_argument("--request-timeout", type=float, default=10)

    static = sub.add_parser("static-scan", help="Run a read-only source/static scan and write structured artifacts")
    static.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    static.add_argument("--source-root", required=True, help="Source tree to review. Must be an existing directory.")
    static.add_argument("--artifacts", default="runs")
    static.add_argument("--template", default=DEFAULT_STATIC_TEMPLATE)
    static.add_argument("--toolsets", default="file", help="Hermes toolsets for the source-review agent. Defaults to file only; web/browser/search are rejected.")
    static.add_argument("--model")
    static.add_argument("--provider")
    static.add_argument("--max-turns", type=int, default=16)
    static.add_argument("--timeout", type=float, default=900)
    static.add_argument("--max-files", type=int, default=250)
    static.add_argument("--skip-agent", action="store_true", help="Write deterministic inventory/threat-model/report artifacts without running Hermes.")
    static.add_argument("--ignore-rules-unsafe", action="store_true", help="Pass --ignore-rules to Hermes source-review agent. Unsafe; use only in a sandbox.")
    static.add_argument("--ignore-user-config", action="store_true", help="Ignore ~/.hermes/config.yaml for the source-review agent.")

    replay = sub.add_parser("replay-poc", help="Replay a structured HTTP PoC with dynamic sandbox gates")
    replay.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    replay.add_argument("poc", help="Path to http-poc/v1 JSON artifact")
    replay.add_argument("--artifacts", default="runs")
    replay.add_argument("--request-timeout", type=float, default=10)
    replay.add_argument("--run-lifecycle", action="store_true", help="Run reset/seed lifecycle commands before dynamic replay")
    replay.add_argument("--lifecycle-timeout", type=float, default=60)
    _add_sandbox_args(replay)

    injection = sub.add_parser("injection-scan", help="Run injection tests (XSS, SQLi, SSRF)")
    injection.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    injection.add_argument("--artifacts", default="runs")
    injection.add_argument("--request-timeout", type=float, default=5)
    injection.add_argument("--username")
    injection.add_argument("--password")
    injection.add_argument("--login-url")
    injection.add_argument("--cookie-name", default="sessionid")
    injection.add_argument("--protected-paths", default="/dashboard,/api/profile")

    auth = sub.add_parser("auth-scan", help="Test authentication flows and session handling")
    auth.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    auth.add_argument("--artifacts", default="runs")
    auth.add_argument("--request-timeout", type=float, default=5)
    auth.add_argument("--username", default="testuser")
    auth.add_argument("--password", default="testpass123")
    auth.add_argument("--login-url")
    auth.add_argument("--protected-paths", default="/dashboard,/api/profile")

    dep_audit = sub.add_parser("dependency-audit", help="Audit dependencies for known vulnerabilities")
    dep_audit.add_argument("--source-root", required=True, help="Source tree to scan for lock files")
    dep_audit.add_argument("--config", help="Optional web-target/v1 config")
    dep_audit.add_argument("--artifacts", default="runs")

    rate_limit = sub.add_parser("rate-limit", help="Detect rate limiting on endpoints")
    rate_limit.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    rate_limit.add_argument("--artifacts", default="runs")
    rate_limit.add_argument("--request-timeout", type=float, default=3)
    rate_limit.add_argument("--burst-size", type=int, default=10)
    rate_limit.add_argument("--delay-ms", type=int, default=100)
    rate_limit.add_argument("--endpoints", default="/api,/health")
    rate_limit.add_argument("--login-url", default="/login")
    rate_limit.add_argument("--signup-url", default="/signup")

    # WSTG scan modules
    csrf_parser = sub.add_parser("csrf", help="Test CSRF protection on endpoints")
    csrf_parser.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    csrf_parser.add_argument("--artifacts", default="runs")
    csrf_parser.add_argument("--endpoints", default="", help="Comma-separated endpoints to test")
    csrf_parser.add_argument("--request-timeout", type=float, default=5)

    http_verb = sub.add_parser("http-verb", help="Test HTTP verb tampering")
    http_verb.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    http_verb.add_argument("--artifacts", default="runs")
    http_verb.add_argument("--endpoints", default="", help="Comma-separated endpoints to test")
    http_verb.add_argument("--request-timeout", type=float, default=5)

    idor_parser = sub.add_parser("idor", help="Test IDOR vulnerabilities")
    idor_parser.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    idor_parser.add_argument("--artifacts", default="runs")
    idor_parser.add_argument("--endpoints", default="", help="Comma-separated endpoints to test")
    idor_parser.add_argument("--request-timeout", type=float, default=5)
    idor_parser.add_argument("--login-url", default="/login")
    idor_parser.add_argument("--user-session", default="")

    jwt_parser = sub.add_parser("jwt", help="Test JWT security")
    jwt_parser.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    jwt_parser.add_argument("--artifacts", default="runs")
    jwt_parser.add_argument("--endpoints", default="", help="Comma-separated endpoints to test")
    jwt_parser.add_argument("--request-timeout", type=float, default=5)

    stored_xss = sub.add_parser("stored-xss", help="Test stored XSS vulnerabilities")
    stored_xss.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    stored_xss.add_argument("--artifacts", default="runs")
    stored_xss.add_argument("--endpoints", default="", help="Comma-separated endpoints to test")
    stored_xss.add_argument("--request-timeout", type=float, default=5)

    job_start = sub.add_parser("job-start", help="Start a security harness job and return a job ID")
    job_start.add_argument("--workdir", required=True, help="Job registry work directory")
    job_start.add_argument("--scan-type", required=True, choices=["http-smoke", "static-scan", "poc-replay"])
    job_start.add_argument("--config", required=True)
    job_start.add_argument("--source-root")
    job_start.add_argument("--poc")
    job_start.add_argument("--foreground", action="store_true", help="Run the worker synchronously for tests/local debugging")
    job_start.add_argument("--request-timeout", type=float, default=10)
    job_start.add_argument("--template", default=DEFAULT_STATIC_TEMPLATE)
    job_start.add_argument("--toolsets", default="file")
    job_start.add_argument("--model")
    job_start.add_argument("--provider")
    job_start.add_argument("--max-turns", type=int, default=16)
    job_start.add_argument("--timeout", type=float, default=900)
    job_start.add_argument("--max-files", type=int, default=250)
    job_start.add_argument("--skip-agent", action="store_true")
    job_start.add_argument("--run-lifecycle", action="store_true")
    _add_sandbox_args(job_start)

    job_status = sub.add_parser("job-status", help="Read a security harness job status")
    job_status.add_argument("--workdir", required=True)
    job_status.add_argument("job_id")

    job_report = sub.add_parser("job-report", help="Read a security harness job report")
    job_report.add_argument("--workdir", required=True)
    job_report.add_argument("job_id")
    job_report.add_argument("--format", choices=["summary", "json", "markdown"], default="summary")

    job_worker = sub.add_parser("job-worker", help=argparse.SUPPRESS)
    job_worker.add_argument("--workdir", required=True)
    job_worker.add_argument("job_id")

    recon = sub.add_parser("recon", help="Run target reconnaissance (crawl, form extraction, API discovery)")
    recon.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    recon.add_argument("--artifacts", default="runs")
    recon.add_argument("--request-timeout", type=float, default=5.0)
    recon.add_argument("--openapi-url", help="Direct URL to OpenAPI specification")
    recon.add_argument("--bundle-url", help="URL to fetch JS bundle for analysis")
    recon.add_argument("--known-auth", default="", help="Comma-separated known auth paths")
    recon.add_argument("--max-depth", type=int, default=2, help="Max crawl depth")
    recon.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl")
    recon.add_argument("--custom-hidden-paths", default="", help="Comma-separated custom paths to probe")

    report = sub.add_parser("report", help="Generate structured security report from findings")
    report.add_argument("--findings", nargs="+", required=True, help="Paths to scan result JSON files")
    report.add_argument("--config", required=True, help="Path to web-target/v1 YAML or JSON config")
    report.add_argument("--output", "-o", default="report.md", help="Output file path (.md or .json)")
    report.add_argument("--json", action="store_true", help="Force JSON output format")
    report.add_argument("--no-evidence", action="store_true", help="Exclude raw evidence")
    report.add_argument("--no-remediation", action="store_true", help="Exclude remediation recommendations")
    report.add_argument("--no-owasp", action="store_true", help="Exclude OWASP mapping")
    report.add_argument("--no-mitre", action="store_true", help="Exclude MITRE ATT&CK mapping")
    report.add_argument("--no-cvss", action="store_true", help="Exclude CVSS-like scoring")
    report.add_argument("--no-summary", action="store_true", help="Exclude executive summary")

    chain = sub.add_parser("chain", help="Run vulnerability chain correlation on scan findings")
    chain.add_argument("--findings", nargs="+", required=True, help="Paths to scan result JSON files")
    chain.add_argument("--output", "-o", default="chains.json", help="Output file path")
    chain.add_argument("--min-priority", type=int, default=0, help="Minimum chain priority to include")

    scan = sub.add_parser("scan", help="Run full security scan")
    scan.add_argument("config", help="web-target/v1 config")
    scan.add_argument("--artifacts", default="runs")
    scan.add_argument("--request-timeout", type=float, default=10)
    scan.add_argument("--max-turns", type=int, default=16)
    scan.add_argument("--timeout", type=float, default=600)
    scan.add_argument("--model", default=None)
    scan.add_argument("--provider", default=None)
    scan.add_argument("--no-static", action="store_true")
    scan.add_argument("--no-injection", action="store_true")
    scan.add_argument("--no-auth", action="store_true")
    scan.add_argument("--no-recon", action="store_true")
    scan.add_argument("--no-chain", action="store_true")
    scan.add_argument("--engagement", default=None, help="Target ID for a pre-saved engagement file with credentials (from 'intake' command)")

    intake = sub.add_parser("intake", help="Interactive pre-engagement credential capture")
    intake.add_argument("config", help="Path to web-target/v1 YAML or JSON config")
    intake.add_argument("--target-id", help="Override target ID for engagement storage (defaults to config id)")
    intake.add_argument("--no-credentials", action="store_true", help="Skip credential prompts")
    intake.add_argument("--no-context", action="store_true", help="Skip context prompts")

    return parser


def _add_sandbox_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sandbox-mode", default="none", help="Required for mutation-capable replay: gvisor, bwrap, container, or firejail")
    parser.add_argument("--egress-host", action="append", default=[])
    parser.add_argument("--ephemeral-home")
    parser.add_argument("--no-credential-mounts", action="store_true")


def _sandbox_policy_from_args(args) -> SandboxPolicy:
    return SandboxPolicy(
        mode=args.sandbox_mode,
        egress_hosts=list(args.egress_host or []),
        ephemeral_home=Path(args.ephemeral_home) if args.ephemeral_home else None,
        credentials_mounted=not bool(args.no_credential_mounts),
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate-target":
        try:
            target = load_target_config(args.config)
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps({"success": True, "target_id": target.id, "target": target.to_summary()}, indent=2))
        return 0

    if args.command == "agent-run":
        runner = HermesCliRunner(args.artifacts)
        result = runner.run(AgentRunRequest(
            prompt=args.prompt,
            workdir=Path(args.workdir),
            toolsets=[v for v in args.toolsets.split(",") if v],
            provider=args.provider,
            model=args.model,
            max_turns=args.max_turns,
            timeout_s=args.timeout,
            ignore_rules=args.ignore_rules_unsafe,
            ignore_user_config=args.ignore_user_config,
            yolo=args.yolo,
        ))
        print(json.dumps({
            "success": result.ok,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "stdout_path": str(result.stdout_path),
            "stderr_path": str(result.stderr_path),
            "result_path": str(result.result_path),
        }, indent=2))
        return 0 if result.ok else 1

    if args.command == "http-smoke":
        try:
            result = run_http_smoke(
                args.config,
                args.artifacts,
                request_timeout_s=args.request_timeout,
            )
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "static-scan":
        try:
            result = run_static_scan(
                args.config,
                args.source_root,
                args.artifacts,
                template=args.template,
                toolsets=[v for v in args.toolsets.split(",") if v],
                provider=args.provider,
                model=args.model,
                max_turns=args.max_turns,
                timeout_s=args.timeout,
                max_files=args.max_files,
                run_agent=not args.skip_agent,
                ignore_rules=args.ignore_rules_unsafe,
                ignore_user_config=args.ignore_user_config,
            )
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "replay-poc":
        try:
            result = run_poc_replay(
                args.config,
                args.poc,
                args.artifacts,
                request_timeout_s=args.request_timeout,
                sandbox_policy=_sandbox_policy_from_args(args),
                run_lifecycle_commands=args.run_lifecycle,
                lifecycle_timeout_s=args.lifecycle_timeout,
            )
        except (TargetValidationError, SandboxValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "job-start":
        try:
            result = start_job(
                args.workdir,
                scan_type=args.scan_type,
                config_path=args.config,
                source_root=args.source_root,
                poc_path=args.poc,
                foreground=args.foreground,
                request_timeout_s=args.request_timeout,
                template=args.template,
                toolsets=[v for v in args.toolsets.split(",") if v],
                model=args.model,
                provider=args.provider,
                max_turns=args.max_turns,
                timeout_s=args.timeout,
                max_files=args.max_files,
                skip_agent=args.skip_agent,
                sandbox_policy=_sandbox_policy_from_args(args),
                run_lifecycle_commands=args.run_lifecycle,
            )
        except (TargetValidationError, SandboxValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "job-worker":
        try:
            result = run_job_worker(args.workdir, args.job_id)
        except (OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result, indent=2))
        return 0 if result.get("status") == "succeeded" else 1

    if args.command == "job-status":
        try:
            result = read_job(args.workdir, args.job_id)
        except (OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "job-report":
        try:
            result = get_report(args.workdir, args.job_id, args.format)
        except (OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "injection-scan":
        try:
            auth_cfg = None
            if args.username and args.password and args.login_url:
                auth_cfg = {
                    "login_url": args.login_url,
                    "username": args.username,
                    "password": args.password,
                    "cookie_name": args.cookie_name,
                    "protected_paths": [p.strip() for p in args.protected_paths.split(",") if p.strip()],
                }
            result = run_injection_scan(args.config, args.artifacts, request_timeout=args.request_timeout, auth=auth_cfg)
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2

        summary = result.to_summary()
        # Add auth info to summary for backward compatibility
        scan_path = Path(result.artifacts.get("injection_scan", ""))
        if scan_path.exists():
            import json as _json
            doc = _json.loads(scan_path.read_text())
            auth_info = doc.get("auth", {})
            summary["auth"] = auth_info
            if auth_info.get("authenticated"):
                summary["loginStep"] = "auth-login"

        print(json.dumps(summary, indent=2))
        return 0 if result.success else 1

    if args.command == "auth-scan":
        try:
            auth_cfg = AuthConfig(
                login_url=args.login_url,
                username=args.username,
                password=args.password,
                protected_paths=[p.strip() for p in args.protected_paths.split(",") if p.strip()],
            )
            result = run_auth_scan(args.config, auth=auth_cfg, artifacts_root=args.artifacts, request_timeout=args.request_timeout)
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "dependency-audit":
        try:
            config_path = Path(args.config) if args.config else None
            result = run_dependency_audit(args.source_root, config_path=config_path, artifacts_root=args.artifacts)
        except (OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "rate-limit":
        try:
            endpoints = [e.strip() for e in args.endpoints.split(",") if e.strip()]
            result = run_rate_limit_scan(
                args.config,
                config=RateLimitConfig(
                    burst_size=args.burst_size,
                    delay_ms=args.delay_ms,
                    endpoints=endpoints,
                    login_url=args.login_url,
                    signup_url=args.signup_url,
                ),
                artifacts_root=args.artifacts,
                request_timeout=args.request_timeout,
            )
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    # --- WSTG scan modules ---
    if args.command == "csrf":
        try:
            endpoints = [e.strip() for e in args.endpoints.split(",") if e.strip()] or None
            result = run_csrf_scan(
                args.config,
                endpoints=endpoints,
                artifacts_root=args.artifacts,
                request_timeout=args.request_timeout,
            )
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "http-verb":
        try:
            endpoints = [e.strip() for e in args.endpoints.split(",") if e.strip()] or None
            result = run_http_verb_scan(
                args.config,
                endpoints=endpoints,
                artifacts_root=args.artifacts,
                request_timeout=args.request_timeout,
            )
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "idor":
        try:
            endpoints = [e.strip() for e in args.endpoints.split(",") if e.strip()] or None
            result = run_idor_scan(
                args.config,
                endpoints=endpoints,
                artifacts_root=args.artifacts,
                request_timeout=args.request_timeout,
            )
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "jwt":
        try:
            endpoints = [e.strip() for e in args.endpoints.split(",") if e.strip()] or None
            result = run_jwt_scan(
                args.config,
                endpoints=endpoints,
                artifacts_root=args.artifacts,
                request_timeout=args.request_timeout,
            )
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "stored-xss":
        try:
            endpoints = [e.strip() for e in args.endpoints.split(",") if e.strip()] or None
            result = run_stored_xss_scan(
                args.config,
                endpoints=endpoints,
                artifacts_root=args.artifacts,
                request_timeout=args.request_timeout,
            )
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        return 0 if result.success else 1

    if args.command == "recon":
        try:
            known_auth = [p.strip() for p in args.known_auth.split(",") if p.strip()] if args.known_auth else None
            custom_hidden = [p.strip() for p in args.custom_hidden_paths.split(",") if p.strip()] if args.custom_hidden_paths else None
            result = run_recon(
                args.config,
                openapi_url=args.openapi_url,
                bundle_url=args.bundle_url,
                known_auth=known_auth,
                max_depth=args.max_depth,
                max_pages=args.max_pages,
                request_timeout=args.request_timeout,
                artifacts_root=args.artifacts,
                custom_hidden_paths=custom_hidden,
            )
        except (TargetValidationError, OSError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
        print(json.dumps(result.to_summary(), indent=2))
        print(f"\nRecon artifacts written to: {result.artifacts.get('recon_summary', 'N/A')}")
        return 0 if result.surfaces else 1

    if args.command == "report":
        try:
            import json as _json
            all_findings: list[dict] = []
            all_warnings: list[str] = []

            for fp in args.findings:
                path = Path(fp)
                if not path.exists():
                    continue
                data = _json.loads(path.read_text())
                # Extract findings from various scan formats
                if "findings" in data:
                    all_findings.extend(data["findings"])
                if "warnings" in data:
                    all_warnings.extend(data["warnings"])
                # Also check nested formats
                if "scanResults" in data:
                    for r in data["scanResults"]:
                        if isinstance(r, dict):
                            all_findings.extend(r.get("findings", []))
                            all_warnings.extend(r.get("warnings", []))

            target = load_target_config(args.config)

            from hashlib import sha256
            from datetime import datetime, timezone
            run_id = f"report-{sha256(datetime.now(timezone.utc).isoformat().encode()).hexdigest()[:12]}"

            report_cfg = ReportConfig(
                target_name=target.name,
                target_url=target.base_url,
                run_id=run_id,
                include_evidence=not args.no_evidence,
                include_remediation=not args.no_remediation,
                include_owasp=not args.no_owasp,
                include_mitre=not args.no_mitre,
                include_cvss=not args.no_cvss,
                include_summary=not args.no_summary,
            )

            force_json = args.json or args.output.endswith(".json")

            if force_json:
                report_data = generate_json_report(all_findings, report_cfg)
                _out = Path(args.output).expanduser().resolve()
                _out.parent.mkdir(parents=True, exist_ok=True)
                _out.write_text(_json.dumps(report_data, indent=2) + "\n")
            else:
                report_text = generate_report(all_findings, report_cfg, warnings=all_warnings)
                _out = Path(args.output).expanduser().resolve()
                _out.parent.mkdir(parents=True, exist_ok=True)
                _out.write_text(report_text)

            print(f"\nReport written to: {_out}")
            matrix = risk_matrix(all_findings)
            print(json.dumps({"total_findings": len(all_findings), "matrix": matrix}, indent=2))
            return 0
        except (TargetValidationError, OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2

    if args.command == "chain":
        try:
            import json as _json

            # Collect all findings from all input files
            all_findings: list[dict] = []
            for fp in args.findings:
                path = Path(fp)
                if not path.exists():
                    continue
                data = _json.loads(path.read_text())
                if "findings" in data:
                    all_findings.extend(data["findings"])
                if "scanResults" in data:
                    for r in data["scanResults"]:
                        if isinstance(r, dict):
                            all_findings.extend(r.get("findings", []))

            config = ChainConfig(
                enabled=True,
                min_chain_priority=args.min_priority,
            )
            chains = run_chain_analysis(all_findings, config)

            _out = Path(args.output).expanduser().resolve()
            _out.parent.mkdir(parents=True, exist_ok=True)
            write_chain_report(chains, _out)

            print(f"\nChain analysis complete: {len(chains)} chain(s) detected")
            print(f"Output: {_out}")

            for chain in chains:
                print(f"  [{chain.new_severity.upper()}] {chain.name}")
                print(f"    Triggers: {', '.join(chain.trigger_findings[:3])}")
                print(f"    Delta: +{chain.severity_delta}")
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            return 2
    if args.command == "scan":
        sys.exit(handle_scan_command(args))

    if args.command == "intake":
        from .intake import prompt_intake
        target_id = args.target_id or load_target_config(args.config).id
        engagement = prompt_intake(
            target_id=target_id,
            config_path=args.config,
            ask_credentials=not args.no_credentials,
            ask_context=not args.no_context,
        )
        print(f"\nEngagement saved: {engagement.path}")
        print(f"  Target: {engagement.target_id}")
        print(f"  Credentials stored for roles: {', '.join(engagement.credentials.keys()) or '(none)'}")
        print(f"\nUse with scan: security-harness scan <config> --engagement {target_id}")
        return 0

    raise AssertionError(f"unknown command {args.command}")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
