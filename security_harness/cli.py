"""CLI for the Hermes security harness MVP."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .runners import AgentRunRequest, HermesCliRunner
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
    return parser


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

    raise AssertionError(f"unknown command {args.command}")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
