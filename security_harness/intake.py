"""Intake: pre-engagement credential capture and context collection.

Interactively collects credentials, scope, and target context before
a security assessment begins. Stores everything encrypted in an
engagement file for use by subsequent pipeline phases.

Usage:
    security-harness intake --target my-app --config target.yaml
"""
from __future__ import annotations

import json
import getpass
from pathlib import Path
from typing import Any

from .engagement import (
    Credential,
    Engagement,
    EngagementError,
    decrypt_value,
    encrypt_value,
)
from .web_target import WebTargetConfig, load_target_config


# ── Interactive prompts ───────────────────────────────────────────────────────

def prompt_intake(
    target_id: str,
    config_path: str | Path,
    *,
    target_name: str | None = None,
    base_url: str | None = None,
    environment: str | None = None,
    scope_include: list[str] | None = None,
    scope_max_requests: int | None = None,
    ask_credentials: bool = True,
    ask_context: bool = True,
) -> Engagement:
    """Run interactive intake for a target.

    Args:
        target_id: Target identifier (e.g., "my-app").
        config_path: Path to web-target/v1 config file.
        target_name: Override target name (from config if not provided).
        base_url: Override base URL (from config if not provided).
        environment: Override environment (from config if not provided).
        scope_include: Override scope include paths.
        scope_max_requests: Override max request count.
        ask_credentials: Prompt for credentials.
        ask_context: Prompt for target context.

    Returns:
        Engagement object (not yet saved to disk).
    """
    # Load config
    config = load_target_config(str(config_path))
    engagement = Engagement.new(
        target_id=target_id,
        base_url=base_url or config.base_url,
        target_name=target_name or config.name,
        environment=environment or config.environment,
    )

    # Scope
    if scope_include is not None:
        engagement.scope.include_paths = scope_include
    else:
        engagement.scope.include_paths = config.scope.include_paths
    if scope_max_requests is not None:
        engagement.scope.max_requests = scope_max_requests
    else:
        engagement.scope.max_requests = config.scope.max_requests
    engagement.scope.exclude_paths = config.scope.exclude_paths

    # Ask for credentials
    if ask_credentials:
        _collect_credentials(engagement)

    # Ask for context
    if ask_context:
        _collect_context(engagement, config)

    # Save
    engagement.save()
    return engagement


def _collect_credentials(engagement: Engagement) -> None:
    """Interactively collect credentials from operator."""
    print(f"\n{'='*60}")
    print(f"Credentials for target: {engagement.target_id}")
    print(f"{'='*60}")
    print()

    # Role-based credential collection
    roles = ["admin", "user"]
    while True:
        role = input(f"Role name [{', '.join(roles)} or 'done']: ").strip()
        if role == "" or role.lower() == "done":
            break
        if role == "":
            role = roles[0]

        username = input(f"  Username for '{role}': ").strip()
        if not username:
            print("  Skipping (no username).")
            continue

        password = getpass.getpass(f"  Password for '{role}' (blank for none): ").strip()

        token = input(f"  Auth token (blank for none): ").strip()

        bearer = input(f"  Bearer/API key (blank for none): ").strip()

        cookie = input(f"  Session cookie value (blank for none): ").strip()
        cookie_name = input(f"  Cookie name (blank for none): ").strip()

        notes = input(f"  Notes (blank for none): ").strip()

        cred = Credential(
            username=username,
            password=password,
            token=token,
            bearer=bearer,
            cookie=cookie,
            cookie_name=cookie_name,
            notes=notes,
        )

        if cred.has_credentials():
            engagement.add_credential(role, cred)
            print(f"  -> Stored credentials for '{role}'")
        else:
            print("  Skipping (no credentials provided).")
        print()


def _collect_context(engagement: Engagement, config: WebTargetConfig) -> None:
    """Interactively collect target context."""
    print(f"\n{'='*60}")
    print(f"Target context for: {engagement.target_id}")
    print(f"{'='*60}")
    print()

    # Framework detection
    framework = input("  Framework (e.g., 'nextjs-14', 'django', 'express'): ").strip()
    if framework:
        engagement.context["framework"] = framework

    # Auth provider
    auth_provider = input("  Auth provider (e.g., 'nextauth-v5', 'jwt', 'session'): ").strip()
    if auth_provider:
        engagement.context["authProvider"] = auth_provider

    # Known auth endpoints
    auth_endpoints = input("  Known auth endpoints (comma-separated, blank for none): ").strip()
    if auth_endpoints:
        engagement.context["authEndpoints"] = [
            e.strip() for e in auth_endpoints.split(",") if e.strip()
        ]

    # Notes
    notes = input("  Additional notes (blank for none): ").strip()
    if notes:
        engagement.context["notes"] = notes

    print(f"\n  Context: {json.dumps(engagement.context, indent=2)}")


def create_intake_from_config(
    config_path: str | Path,
    *,
    target_id: str | None = None,
    credentials: dict[str, dict[str, str]] | None = None,
    context: dict[str, Any] | None = None,
) -> Engagement:
    """Create engagement from config file without interactive prompts.

    Args:
        config_path: Path to web-target/v1 config.
        target_id: Override target ID.
        credentials: Dict of role -> {username, password, token, bearer, cookie, cookie_name}.
        context: Dict of context metadata.

    Returns:
        Engagement object saved to disk.
    """
    cfg = load_target_config(str(config_path))
    tid = target_id or cfg.id
    engagement = Engagement.new(
        target_id=tid,
        base_url=cfg.base_url,
        target_name=cfg.name,
        environment=cfg.environment,
    )

    engagement.scope.include_paths = cfg.scope.include_paths
    engagement.scope.exclude_paths = cfg.scope.exclude_paths
    engagement.scope.max_requests = cfg.scope.max_requests

    if credentials:
        for role, cred_data in credentials.items():
            cred = Credential(
                username=cred_data.get("username", ""),
                password=cred_data.get("password", ""),
                token=cred_data.get("token", ""),
                bearer=cred_data.get("bearer", ""),
                cookie=cred_data.get("cookie", ""),
                cookie_name=cred_data.get("cookie_name", ""),
            )
            if cred.has_credentials():
                engagement.add_credential(role, cred)

    if context:
        engagement.context.update(context)

    engagement.save()
    return engagement


__all__ = [
    "prompt_intake",
    "create_intake_from_config",
]
