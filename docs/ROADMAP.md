# WSTG Coverage Roadmap

> **Current coverage: 38/131 WSTG v4.0 tests (29%)**
>
> This document tracks the gap between the harness's current scanner set and
> full OWASP WSTG v4.0 coverage. Each phase lists the modules needed, the WSTG
> tests they cover, and acceptance criteria so contributors can pick up
> self-contained work items.

## How to Contribute

1. Pick a module from an uncompleted phase below.
2. Follow the TDD + base-module pattern in
   [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) and the
   `hermes-security-harness` skill (`skill_view(name='hermes-security-harness')`).
3. Every new scanner inherits from `wstg_base.BaseScanConfig` /
   `BaseScanResult` and uses `_run_scan()` for the common loop.
4. Add CLI subparser + handler, export in `__init__.py`, wire into
   `scan_handler.py` and `pipeline.py`.
5. Write integration tests via mock HTTP servers (see `test_csrf_scan.py`
   for the pattern). Aim for 10-20 tests per module.
6. Run `.venv/bin/python -m pytest tests/ -v` — all tests must pass.
7. Open a PR with the module name as the branch prefix (e.g.
   `feat/cmd-injection-scan`).

---

## ✅ Completed — Phase 1: Core Auth & Injection

| Module | WSTG | Tests |
|---|---|---|
| `injection_scanner.py` | 4.7.01, 4.7.05, 4.7.19 | Reflected XSS, SQLi, SSRF |
| `stored_xss_scan.py` | 4.7.02 | 15 |
| `http_verb_scan.py` | 4.7.03 | 14 |
| `auth_scan.py` | 4.4.01–4.4.04, 4.6.01, 4.6.02 | Login flow, cookies, bypass |
| `jwt_scan.py` | 4.6.10 | 14 |
| `idor_scan.py` | 4.5.04 | 17 |
| `csrf_scan.py` | 4.6.05 | 19 |
| `recon.py` | 4.1.04, 4.1.06 | Surface discovery, staged unauth/auth |
| `http_smoke.py` | 4.2.07, 4.2.12, 4.2.14 | Security headers, CSP, HSTS |
| `tls_scan.py` | 4.9.01 (partial) | TLS version, cipher, cert checks |
| `static_scan.py` | 4.9.04 (partial) | Crypto weakness, hardcoded secrets |
| `dependency_audit.py` | — | CVE cross-ref (npm/go/ruby/python/cargo) |
| `rate_limit.py` | 4.4.03 | Rate limit detection |
| `chains.py` | — | 48 deterministic chain rules |
| `chain_reasoning.py` | — | LLM multi-hop chain detection |

---

## Phase 2 — Session, Error Handling & Identity (target: ~13 modules)

### 2.1 `error_handling_scan.py`

- **WSTG:** 4.8.01, 4.8.02
- **Detects:** Stack traces, debug pages, verbose error messages, internal
  path disclosure in error responses.
- **Approach:** Send malformed inputs (bad JSON, oversized fields, null bytes,
  unexpected content types) to known endpoints; check response bodies for
  stack trace patterns, framework signatures, file paths.
- **Acceptance:** Detects at least 5 error-handling patterns across
  Express/Next.js/Flask/Django defaults.

### 2.2 `session_scan.py` (new module — distinct from auth_scan)

- **WSTG:** 4.6.03, 4.6.04, 4.6.06, 4.6.09
- **Detects:** Session fixation (pre/post-auth token rotation), exposed
  session variables in URLs/JS, session hijacking indicators, logout
  functionality gaps (session token still valid after logout).
- **Acceptance:** Tests session token before/after login, after logout;
  flags tokens that don't rotate or persist.

### 2.3 `identity_scan.py`

- **WSTG:** 4.3.01–4.3.05
- **Detects:** Role definition enumeration, registration process weaknesses,
  account provisioning flaws, account enumeration via timing/error
  differences, username policy enforcement.
- **Acceptance:** Detects user enumeration via differential responses on
  login/register/password-reset endpoints.

### 2.4 `cors_scan.py`

- **WSTG:** 4.11.07
- **Detects:** Wildcard `Access-Control-Allow-Origin` with credentials,
  origin reflection, null origin acceptance, overly permissive methods.
- **Acceptance:** Sends requests with `Origin: https://evil.com` and
  checks ACAO/ACAC headers; flags credential + wildcard combos.

### 2.5 `crypto_scan.py`

- **WSTG:** 4.9.02, 4.9.03, 4.9.04
- **Detects:** Padding oracle (via differential responses), sensitive data
  over unencrypted channels, weak crypto primitives in transit.
- **Acceptance:** Padding oracle detection via CBC mode probing with
  modified ciphertext blocks.

### 2.6 `oauth_scan.py`

- **WSTG:** 4.5.05, 4.5.05.1, 4.5.05.2
- **Detects:** Authorization server weaknesses (implicit flow, weak
  redirect_uri validation), client weaknesses (token reuse, insecure
  storage), open redirect via `redirect_uri`.
- **Acceptance:** Tests redirect_uri validation, state parameter presence,
  token scope, PKCE enforcement.

### 2.7 `password_reset_scan.py`

- **WSTG:** 4.4.09
- **Detects:** Weak reset tokens, token reuse, email enumeration via reset,
  reset flow bypass, lack of old password verification.
- **Acceptance:** Initiates reset flow, tests token validity after use,
  tests timing differences for valid/invalid emails.

---

## Phase 3 — Business Logic & API (target: ~22 modules)

### 3.1 `business_logic_scan.py`

- **WSTG:** 4.10.01–4.10.07, 4.10.10
- **Detects:** Workflow circumvention, process timing, forge requests,
  integrity checks, function usage limits, application misuse defenses,
  payment functionality manipulation.
- **Approach:** Multi-step request sequences (e.g., skip checkout step,
  reorder steps, replay steps). Requires configurable workflow definitions.
- **Acceptance:** Detects at least 3 workflow bypass patterns on a test
  app with defined multi-step flows.

### 3.2 `file_upload_scan.py`

- **WSTG:** 4.10.08, 4.10.09
- **Detects:** Malicious file upload (web shells, polyglot files),
  unexpected file types, path traversal via filename, double extensions,
  content-type mismatch.
- **Acceptance:** Uploads test files (`.php`, `.js`, `.html`, `../../../etc/`,
  polyglot JPEG/PHP); verifies server accepts/rejects correctly.

### 3.3 `api_scan.py`

- **WSTG:** 4.12.02, 4.12.03, 4.12.04
- **Detects:** Broken object-level authorization (BOLA) on API endpoints,
  broken function-level authorization, excessive data exposure (over-fetching).
- **Acceptance:** Tests API endpoints with different user roles; flags
  endpoints returning data outside the caller's scope.

### 3.4 `graphql_scan.py`

- **WSTG:** 4.12.99
- **Detects:** Introspection enabled in production, query depth/complexity
  limits missing, batching attacks, field suggestions leaking schema,
  injection via GraphQL variables.
- **Acceptance:** Sends introspection query, depth attack, batch query;
  flags enabled introspection and missing limits.

---

## Phase 4 — Advanced Injection & Client-Side (target: ~22 modules)

### 4.1 `cmd_injection_scan.py`

- **WSTG:** 4.7.11, 4.7.12
- **Detects:** OS command injection, code injection (eval, exec).
- **Note:** 25 CMDI payloads already exist in `advanced_payloads.py` —
  this module wires them into a scanner.
- **Acceptance:** Detects command injection via `;`, `|`, backticks,
  `$()`, `${IFS}` against a test endpoint that reflects output.

### 4.2 `ssti_scan.py`

- **WSTG:** 4.7.18
- **Detects:** Server-side template injection (Jinja2, Twig, FreeMarker,
  Handlebars, Velocity, Smarty).
- **Acceptance:** Sends `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` payloads;
  detects `49` reflection. Includes engine fingerprinting.

### 4.3 `smuggling_scan.py`

- **WSTG:** 4.7.16
- **Detects:** HTTP request smuggling (CL.TE, TE.CL, TE.TE).
- **Note:** Requires raw socket control (not `urllib`). Use
  `http.client` or raw sockets.
- **Acceptance:** Detects CL.TE smuggling against a test proxy.

### 4.4 `header_injection_scan.py`

- **WSTG:** 4.7.15, 4.7.17
- **Detects:** CRLF injection / HTTP response splitting, host header
  injection (password reset poisoning, cache poisoning).
- **Note:** 11 header injection payloads already in `advanced_payloads.py`.
- **Acceptance:** Detects CRLF via `%0d%0a` in parameters reflected
  into headers; host header injection in reset links.

### 4.5 `ldap_xpath_scan.py`

- **WSTG:** 4.7.06, 4.7.09
- **Detects:** LDAP injection (`*)(uid=*`), XPath injection (`' or '1'='1`).
- **Acceptance:** Detects boolean-based LDAP/XPath injection via
  differential responses.

### 4.6 `mass_assignment_scan.py`

- **WSTG:** 4.7.20
- **Detects:** Mass assignment / auto-binding (injecting `isAdmin: true`,
  `role: admin` into JSON/form bodies).
- **Acceptance:** Sends extra fields in PUT/PATCH/POST; detects privilege
  escalation via accepted fields.

### 4.7 `hpp_scan.py`

- **WSTG:** 4.7.04
- **Detects:** HTTP parameter pollution (duplicate params, HPP bypass).
- **Note:** 10 HPP payloads already in `advanced_payloads.py`.
- **Acceptance:** Sends `?id=1&id=2`; detects backend parsing differences.

### 4.8 `dom_xss_scan.py` ⚠️ Requires headless browser

- **WSTG:** 4.11.01, 4.11.02
- **Detects:** DOM-based XSS, JavaScript execution via sinks
  (`innerHTML`, `eval`, `document.write`, `setTimeout`).
- **Dependency:** Playwright or Puppeteer for JS execution.
- **Acceptance:** Injects payloads into URL fragments/params; detects
  DOM sink execution via browser console monitoring.

### 4.9 `client_side_scan.py` ⚠️ Requires headless browser

- **WSTG:** 4.11.03–4.11.06, 4.11.09–4.11.12, 4.11.14
- **Detects:** HTML injection, client-side URL redirect, CSS injection,
  client-side resource manipulation, clickjacking (missing
  `X-Frame-Options`/CSP `frame-ancestors`), WebSockets, web messaging,
  browser storage, reverse tabnabbing.
- **Dependency:** Playwright for DOM inspection and frame testing.
- **Acceptance:** Clickjacking test via iframe load; localStorage
  inspection; WebSocket origin validation.

---

## Phase 5 — External Tool Integrations

The harness is pure Python. These integrations fill classes of vulns
that HTTP payload testing alone can't catch.

| Integration | Purpose | WSTG Gap Filled | Priority |
|---|---|---|---|
| **Playwright** | DOM XSS, client-side execution, SPA routing, browser storage | 4.11.01–4.11.14 (all client-side) | **Critical** |
| **sqlmap** | Deep SQLi: boolean-blind, time-blind, UNION, OOB | 4.7.05 (current is reflection-only) | High |
| **nuclei + interactsh** | OOB detection for blind SSRF/SQLi/XXE, 8000+ CVE templates | Blind injection variants, broad CVE coverage | High |
| **testssl.sh / sslyze** | Deep TLS: cipher suites, downgrade, cert chain, Heartbleed | 4.9.01 (current `tls_scan.py` is basic) | Medium |
| **OWASP ZAP (daemon)** | Active scanner baseline, comparison oracle | Cross-validation across all categories | Medium |
| **ffuf / wfuzz** | Fuzzing endpoints, params, file paths | 4.10.08, 4.7.13, content discovery | Medium |
| **dalfox** | Advanced XSS fuzzing with DOM analysis | 4.7.01, 4.11.01 | Low |

### Integration pattern

External tools should be wrapped behind a Python adapter that:
1. Checks tool availability (`shutil.which`).
2. Runs the tool in subprocess with timeout.
3. Parses output into the harness `Finding` format.
4. Writes artifacts to the standard `runs/<scan>/` directory.
5. Integrates with `chain.py` for chain correlation.

---

## Coverage Progress Tracking

| Phase | Modules Planned | Modules Done | WSTG Tests Target | WSTG Tests Done |
|---|---|---|---|---|
| Phase 1 — Core Auth & Injection | 15 | 15 | 38 | 38 |
| Phase 2 — Session & Error | 7 | 0 | ~13 | 0 |
| Phase 3 — Business Logic & API | 4 | 0 | ~22 | 0 |
| Phase 4 — Advanced Injection & Client | 9 | 0 | ~22 | 0 |
| Phase 5 — External Tools | 7 | 0 | — | 0 |
| **Total** | **42** | **15** | **~131** | **38** |

---

## Module Template

```python
# security_harness/<name>_scan.py
from .wstg_base import BaseScanConfig, BaseScanResult, _run_scan

class XScanConfig(BaseScanConfig):
    """Config for <name> scan."""
    pass

class XScanResult(BaseScanResult):
    """Result of <name> scan."""
    pass

def run_x_scan(config_path, artifacts_root="runs", endpoints=None,
               request_timeout_s=5):
    """Run <WSTG test ID> — <title>.

    Detects: <what this scanner finds>
    """
    return _run_scan(
        config_path, _test_x, scan_name="<name>",
        artifact_name="<name>_findings",
        artifacts_root=artifacts_root,
        endpoints=endpoints, request_timeout_s=request_timeout_s,
    )

def _test_x(base_url, endpoint, timeout):
    """Per-endpoint test. Returns list of Finding dicts."""
    # ... send requests, check responses, return findings
    return []
```

See [`test_csrf_scan.py`](../tests/test_csrf_scan.py) for the test pattern:
config validation, CLI tests, mock HTTP server integration tests, result
serialization, edge cases.
