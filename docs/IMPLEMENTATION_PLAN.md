# Hermes Security Harness Implementation Plan

> For Hermes: use subagent-driven development for independent phases and TDD for each behavior.

## Goal

Build a Hermes-native defensive security harness for authorized web targets, replacing Claude Code headless execution with a Hermes-compatible runner.

## Phase 0 — MVP scaffold (this repo)

- AgentRunner protocol.
- HermesCliRunner.
- web-target/v1 validation.
- finding/http-poc/grader artifact contracts.
- Hermes plugin skeleton for validation/status/report.
- pytest suite.

## Phase 1 — static scan workflow

- Add prompt templates for threat model, source scan, triage, patch candidates.
- Generate inert patch candidates in source-only mode.
- Keep scans read-only unless explicitly running patch generation in a workspace.

## Phase 2 — job runner

- Add SQLite or JSONL job registry.
- Add background static scan and HTTP smoke tools.
- Add start/status/report polling through plugin.

## Phase 3 — web dynamic harness

- Add local/staging app lifecycle runner.
- Add deterministic GET-only HTTP smoke checks for explicit scoped paths.
- Add HTTP PoC replay with grader artifacts.
- Add detector contracts and initial non-destructive detectors.
- Add grader agents that reset/seed then replay PoCs.

## Phase 4 — sandbox

- Require gVisor or equivalent for dynamic scans.
- Use ephemeral Hermes home/profile per run.
- Enforce network allowlist.

## Phase 5 — real staging target

- Start with one owned staging website.
- Run focused threat-model -> static -> dynamic smoke -> triage -> report loop.
- No production scanning by default.
