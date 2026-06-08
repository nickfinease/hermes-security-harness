"""Full security scan - runs all scan modules and chain correlation.

This module implements the main full-scan CLI command that orchestrates
all security scan modules in sequence, with proper data flow between them:

  smoke → injection (surfaces)
  auth → injection (cookies)
  recon → injection (surfaces + routes)

Functions:
    handle_scan_command - Main entry point for the 'scan' CLI command.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .auth_scan import run_auth_scan
from .chain_reasoning import run_recursive_chain_analysis
from .chains import ChainConfig, run_chain_analysis, write_chain_report
from .csrf_scan import run_csrf_scan
from .http_verb_scan import run_http_verb_scan
from .idor_scan import run_idor_scan
from .jwt_scan import run_jwt_scan
from .stored_xss_scan import run_stored_xss_scan
from .http_smoke import run_http_smoke
from .injection_scanner import run_injection_scan
from .recon import run_recon
from .report import ReportConfig, generate_report, write_report
from .runners import AgentRunRequest, HermesCliRunner
from .static_scan import DEFAULT_STATIC_TEMPLATE, run_static_scan
from .web_target import TargetValidationError, load_target_config


def handle_scan_command(args: object) -> int:
    """Handle the 'scan' CLI command.

    Runs all scan modules in order with proper data flow:

    1. HTTP smoke test (reachability + headers → surfaces for injection)
    2. Static source scan (local LLM analysis of source code)
    3. Auth security scan (login cookies → injection)
    4. Reconnaissance (surfaces + routes → injection)
    5. Injection tests (XSS, SQLi, SSRF on ALL discovered surfaces with auth)
    6. Vulnerability chain correlation (deterministic rules)
    7. Recursive LLM-powered chain reasoning (optional)
    8. Final report generation (deterministic CVSS)

    Args:
        args: Parsed argparse.Namespace with scan command arguments.

    Returns:
        0 on success, non-zero on error.
    """
    config = load_target_config(args.config)  # type: ignore[attr-defined]
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    out = Path(args.artifacts).resolve() / f"full-scan-{run_id}"
    out.mkdir(parents=True, exist_ok=True)

    print(f"Running full scan on {config.name}...")
    print(f"Output: {out}")
    print()

    all_findings: list[dict] = []
    smoke_artifact: Path | None = None  # Will hold the smoke scan JSON path
    auth_cookies: dict[str, str] = {}   # Will hold auth cookies from login

    # ═══════════════════════════════════════════════════════════════
    # 1. HTTP smoke test (feeds surfaces to injection scanner)
    # ═══════════════════════════════════════════════════════════════
    print("  [1/7] HTTP smoke test...")
    try:
        smoke = run_http_smoke(
            args.config,  # type: ignore[attr-defined]
            artifacts_root=str(out / "smoke"),
            request_timeout_s=args.request_timeout,  # type: ignore[attr-defined]
        )
        for f in sorted((out / "smoke").glob("*/http-smoke.json")):
            with open(f) as sf:
                all_findings.extend(json.loads(sf.read()).get("findings", []))
            smoke_artifact = f  # Save path for injection scanner
            break
        print(f"    {smoke.request_count} requests, {smoke.finding_count} findings")
    except Exception as e:  # noqa: BLE001
        print(f"    ERROR: {e}", file=sys.stderr)

    # ═══════════════════════════════════════════════════════════════
    # 2. Static source scan (local LLM)
    # ═══════════════════════════════════════════════════════════════
    if not getattr(args, "no_static", False):  # type: ignore[attr-defined]
        try:
            print("  [2/7] Static source scan (local LLM)...")
            source_root = (
                getattr(config, "source_dir", None) or "/home/beans/FinEase"
            )
            static = run_static_scan(
                args.config,  # type: ignore[attr-defined]
                source_root=source_root,
                artifacts_root=str(out / "static"),
                model=getattr(args, "model", None) or "local-qwen36-nvfp4",  # type: ignore[attr-defined]
                max_turns=args.max_turns,  # type: ignore[attr-defined]
                timeout_s=args.timeout,  # type: ignore[attr-defined]
            )
            for f in sorted((out / "static").glob("*/findings.json")):
                with open(f) as sf:
                    all_findings.extend(json.loads(sf.read()).get("findings", []))
                break
            print(f"    {static.finding_count} findings")
        except Exception as e:  # noqa: BLE001
            print(f"    ERROR: {e}", file=sys.stderr)

    # ═══════════════════════════════════════════════════════════════
    # 3. Auth security scan (feeds cookies to injection scanner)
    # ═══════════════════════════════════════════════════════════════
    auth_cookies = {}
    if not getattr(args, "no_auth", False):  # type: ignore[attr-defined]
        try:
            print("  [3/7] Auth security scan...")
            auth = run_auth_scan(
                args.config,  # type: ignore[attr-defined]
                artifacts_root=str(out / "auth"),
                request_timeout=args.request_timeout,  # type: ignore[attr-defined]
            )
            for f in sorted((out / "auth").glob("*/auth-scan.json")):
                with open(f) as sf:
                    data = json.loads(sf.read())
                    all_findings.extend(data.get("findings", []))
                    # Extract cookies for injection scanner
                    for step in data.get("steps", []):
                        if step.get("setCookies"):
                            auth_cookies.update(step["setCookies"])
                break
            print(
                f"    Cookie:{auth.cookie_tests} "
                f"Bypass:{auth.bypass_tests} Rate:{auth.rate_tests}"
            )
        except Exception as e:  # noqa: BLE001
            print(f"    ERROR: {e}", file=sys.stderr)

    # ═══════════════════════════════════════════════════════════════
    # 4. Reconnaissance (feeds surfaces + routes to injection scanner)
    # ═══════════════════════════════════════════════════════════════
    recon_surfaces: list[dict] = []
    recon_routes: list[dict] = []
    if not getattr(args, "no_recon", False):  # type: ignore[attr-defined]
        try:
            print("  [4/7] Reconnaissance...")
            recon = run_recon(
                args.config,  # type: ignore[attr-defined]
                artifacts_root=str(out / "recon"),
                max_depth=2,
                request_timeout=args.request_timeout,  # type: ignore[attr-defined]
            )
            # Extract surfaces for injection scanner
            for s in recon.surfaces:
                recon_surfaces.append({
                    "url": s.url,
                    "input_type": s.input_type,
                    "parameter_name": s.parameter_name,
                    "method": s.method,
                    "source": s.source.value if hasattr(s.source, 'value') else str(s.source),
                    "confidence": s.confidence,
                })
            # Extract routes for path param testing
            recon_routes = list(recon.discovered_routes)
            print(
                f"    {len(recon.surfaces)} surfaces, "
                f"{len(recon_routes)} routes"
            )
        except Exception as e:  # noqa: BLE001
            print(f"    ERROR: {e}", file=sys.stderr)

    # ═══════════════════════════════════════════════════════════════
    # 5. Injection tests (NOW has all data: smoke + auth + recon)
    # ═══════════════════════════════════════════════════════════════
    if not getattr(args, "no_injection", False):  # type: ignore[attr-defined]
        try:
            print("  [5/7] Injection tests (with auth + recon surfaces)...")
            inj = run_injection_scan(
                args.config,  # type: ignore[attr-defined]
                artifacts_root=str(out / "injection"),
                request_timeout_s=args.request_timeout,  # type: ignore[attr-defined]
                smoke_steps=str(smoke_artifact) if smoke_artifact else None,
                auth_cookies=auth_cookies if auth_cookies else None,
                recon_surfaces=recon_surfaces if recon_surfaces else None,
                recon_routes=recon_routes if recon_routes else None,
            )
            for f in sorted((out / "injection").glob("*/injection-scan.json")):
                with open(f) as sf:
                    all_findings.extend(json.loads(sf.read()).get("findings", []))
                break

            # Print surface source breakdown
            surf_sources = "smoke,auth,recon"
            parts = []
            if smoke_artifact:
                parts.append(f"smoke")
            if auth_cookies:
                parts.append("auth")
            if recon_surfaces:
                parts.append("recon")
            if recon_routes:
                parts.append("recon-routes")
            print(
                f"    XSS:{inj.xss_tests} SQLi:{inj.sqli_tests} "
                f"SSRF:{inj.ssrf_tests} | Surfaces from: {', '.join(parts)}"
            )
        except Exception as e:  # noqa: BLE001
            print(f"    ERROR: {e}", file=sys.stderr)

    # ═══════════════════════════════════════════════════════════════
    # 5.5 WSTG scan modules (CSRF, HTTP verb, IDOR, JWT, stored XSS)
    # ═══════════════════════════════════════════════════════════════
    wstg_modules = [
        ("csrf", run_csrf_scan),
        ("http-verb", run_http_verb_scan),
        ("idor", run_idor_scan),
        ("jwt", run_jwt_scan),
        ("stored-xss", run_stored_xss_scan),
    ]
    for name, run_func in wstg_modules:
        try:
            print(f"  [{name}] {name} scan...")
            wstg_result = run_func(
                args.config,  # type: ignore[attr-defined]
                artifacts_root=str(out / name),
                request_timeout=args.request_timeout,  # type: ignore[attr-defined]
            )
            for f in sorted((out / name).glob(f"*/*{name}*.json")):
                with open(f) as sf:
                    all_findings.extend(json.loads(sf.read()).get("findings", []))
                    break
            print(f"    {wstg_result.finding_count if hasattr(wstg_result, 'finding_count') else '?'} findings")
        except Exception as e:  # noqa: BLE001
            print(f"    {name} ERROR: {e}", file=sys.stderr)

    # ═══════════════════════════════════════════════════════════════
    # 6. Vulnerability chain correlation (deterministic rules)
    # ═══════════════════════════════════════════════════════════════
    if not getattr(args, "no_chain", False) and all_findings:  # type: ignore[attr-defined]
        try:
            print()
            print("  [6/7] Chain correlation...")
            chains = run_chain_analysis(all_findings, config=ChainConfig())
            if chains:
                print(f"    {len(chains)} vulnerability chain(s):")
                for c in chains:
                    print(f"      [{c.new_severity}] {c.name}")
                write_chain_report(chains, out / "chains.json", run_id=run_id)
                print(f"    Chain report: {out / 'chains.json'}")
            else:
                print("    No vulnerability chains detected")
        except Exception as e:  # noqa: BLE001
            print(f"    Chain error: {e}", file=sys.stderr)

        # ═══════════════════════════════════════════════════════════
        # 7. Recursive LLM-powered chain reasoning (optional)
        # ═══════════════════════════════════════════════════════════
        if not getattr(args, "no_chain", False) and all_findings and len(chains) > 0:  # type: ignore[name-defined]
            try:
                print()
                print("  [7/7] LLM chain reasoning (recursive) ...")
                llm_chains = run_recursive_chain_analysis(
                    all_findings,
                    existing_chains=[],  # Will be populated from chains
                    model=getattr(args, "model", None),  # type: ignore[attr-defined]
                    provider=getattr(args, "provider", None),  # type: ignore[attr-defined]
                )
                if llm_chains:
                    print(f"    LLM identified {len(llm_chains)} additional chain hypothesis/hypotheses:")
                    for c in llm_chains:
                        print(f"      [{c.new_severity}] {c.name} (confidence: {c.confidence:.2f})")
                    # Convert to dict format for report
                    llm_chain_dicts = []
                    for c in llm_chains:
                        llm_chain_dicts.append({
                            "id": c.id,
                            "name": c.name,
                            "explanation": c.explanation,
                            "trigger_findings": c.trigger_findings,
                            "new_severity": c.new_severity,
                            "confidence": c.confidence,
                        })
                    # Write to file
                    with open(out / "llm_chains.json", "w") as f:
                        json.dump(llm_chain_dicts, f, indent=2)
                    print(f"    LLM chain report: {out / 'llm_chains.json'}")
                else:
                    print("    LLM found no additional chains")
            except Exception as e:  # noqa: BLE001
                print(f"    LLM chain reasoning error: {e}", file=sys.stderr)

    # 8. Final report (deterministic CVSS)
    if all_findings:
        try:
            print()
            print("  Generating report (deterministic CVSS)...")
            rp = write_report(all_findings, out / "report.md", config=ReportConfig())
            print(f"  Report: {rp}: {len(all_findings)} findings")
        except Exception as e:  # noqa: BLE001
            print(f"  Report failed: {e}", file=sys.stderr)

    print()
    print("Scan complete!")
    return 0
