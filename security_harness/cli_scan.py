"""Hermes Security Harness - Full Scan CLI Module.

This module implements the full security scan command that runs all scan
modules (smoke, static, injection, auth, recon) in sequence and then
performs vulnerability chain analysis.

Public API:
    add_scan_subparser - Add the "scan" subparser to the CLI parser.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# This module is meant to be imported by cli.py, not run standalone


def add_scan_subparser(parser):
    """Add the 'scan' subparser to the given parser."""
    scan = parser.add_parser(
        "scan",
        help="Run full security scan (smoke + static + injection + auth + recon + chain)",
    )
    scan.add_argument(
        "config", help="Path to web-target/v1 YAML or JSON config"
    )
    scan.add_argument("--artifacts", default="runs")
    scan.add_argument(
        "--request-timeout", type=float, default=10,
        help="Request timeout in seconds"
    )
    scan.add_argument("--max-turns", type=int, default=16)
    scan.add_argument("--timeout", type=float, default=600)
    scan.add_argument("--model", default=None, help="LLM model for static scan")
    scan.add_argument(
        "--provider", default=None, help="LLM provider (default: use cloud)"
    )
    scan.add_argument(
        "--no-static", action="store_true",
        help="Skip static source scan"
    )
    scan.add_argument(
        "--no-injection", action="store_true",
        help="Skip injection tests"
    )
    scan.add_argument(
        "--no-auth", action="store_true",
        help="Skip auth scan"
    )
    scan.add_argument(
        "--no-recon", action="store_true",
        help="Skip recon scan"
    )
    scan.add_argument(
        "--no-chain", action="store_true",
        help="Skip vulnerability chain analysis"
    )
    return scan
