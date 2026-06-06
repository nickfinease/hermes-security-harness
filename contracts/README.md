# Security Harness Contracts

JSON Schema definitions for all artifact types produced and consumed by the Hermes Security Harness.

## Naming Convention

Files follow: `<name-part>-v<version>.json` where name-part can contain hyphens (e.g., `http-poc-v1.json`).

This maps to schema version strings: `<name-part>/<version>` (e.g., `http-poc/v1`).

## Schemas

| File | Schema Version | Description |
|---|---|---|
| `finding-v1.json` | `finding/v1` | Security finding from any detector or scan phase |
| `http-poc-v1.json` | `http-poc/v1` | HTTP proof-of-concept with request steps |
| `poc-replay-v1.json` | `poc-replay/v1` | Output of a PoC replay run |
| `grader-v1.json` | `grader/v1` | Grading result with gates and status |
| `job-v1.json` | `job/v1` | Job registry entry |
| `source-inventory-v1.json` | `source-inventory/v1` | Source file inventory for static analysis |
| `static-agent-findings-v1.json` | `static-agent-findings/v1` | Agent findings from source-only review |
| `static-findings-v1.json` | `static-findings/v1` | Complete findings document with patch candidates |
| `patch-candidate-v1.json` | `patch-candidate/v1` | Inert or validated patch candidate |

## Adding a New Contract

1. Create a new JSON Schema file: `contracts/<name>-v<N>.json`
2. Include `schemaVersion` at the top level
3. List all required fields in the `required` array
4. Add a test in `tests/test_contracts.py` if the contract has specific required fields not covered by the general test

## Usage

The harness code produces and validates outputs against these schemas. Tests verify:
- Every `.json` file is valid JSON
- Schema version matches filename
- Required fields are present
- Filename follows the naming convention
