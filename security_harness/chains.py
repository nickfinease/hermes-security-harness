"""Vulnerability chain correlation engine.

Correlates findings from multiple scans into vulnerability chains:
combinations of independent weaknesses that together create a higher-severity exploit.

Public API:
    ChainConfig, ChainRule, ChainFinding, find_chains, run_chain_analysis,
    auto_tag_findings, RULES_DEFAULT,
"""
from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from itertools import combinations

from .artifacts import Finding, redact_secrets


# ── Rule model ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TagDefinition:
    """A tag that can be applied to a finding."""
    name: str
    description: str


@dataclass(frozen=True)
class ChainRule:
    """A vulnerability chain detection rule.

    Attributes:
        name: Human-readable name.
        triggers: Finding types that must all be present.
        severity_delta: Severity level increase when chain detected.
        explanation: Why the chain is dangerous.
        cwe: Additional CWE IDs for the chain.
        owasp: OWASP category for the chain.
        priority: Higher values processed first.
        scope: Optional finding scope filter.
    """
    name: str
    triggers: list[str]  # finding type identifiers
    severity_delta: int  # +1, +2, or +3 (relative to lowest trigger severity)
    explanation: str
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    priority: int = 0
    scope: str | None = None  # e.g. "auth" to limit to auth-related findings


# ── Known tags ────────────────────────────────────────────────────────────────

KNOWN_TAGS: list[TagDefinition] = [
    TagDefinition("xss", "Cross-site scripting vulnerability"),
    TagDefinition("sqli", "SQL injection vulnerability"),
    TagDefinition("ssrf", "Server-side request forgery"),
    TagDefinition("command_injection", "OS command injection"),
    TagDefinition("xxe", "XML external entity injection"),
    TagDefinition("path_traversal", "Path/ directory traversal"),
    TagDefinition("auth_bypass", "Authentication bypass"),
    TagDefinition("csrf", "Cross-site request forgery"),
    TagDefinition("rate_limiting_missing", "Missing rate limiting"),
    TagDefinition("header_injection", "HTTP header injection"),
    TagDefinition("open_redirect", "Open URL redirect"),
    TagDefinition("file_upload", "Unrestricted file upload"),
    TagDefinition("jwt_weak", "Weak JWT configuration"),
    TagDefinition("ssrf_cloud_meta", "SSRF targeting cloud metadata"),
    TagDefinition("debug_exposure", "Debug/development endpoint exposed"),
    TagDefinition("info_disclosure", "Information disclosure"),
    TagDefinition("missing_header", "Missing security header"),
    TagDefinition("auth_endpoint", "Authentication endpoint present"),
    TagDefinition("oauth_flow", "OAuth authentication flow detected"),
    TagDefinition("graphql", "GraphQL endpoint detected"),
    TagDefinition("api_exposure", "Unprotected API endpoint"),
    TagDefinition("privilege_escalation", "Privilege escalation possible"),
    TagDefinition("data_exfiltration", "Data exfiltration vector"),
]


# ── Rule catalog ───────────────────────────────────────────────────────────────

RULES_DEFAULT: list[ChainRule] = [
    # ── High-impact chains ──

    ChainRule(
        name="rate-limit-brute-force",
        triggers=["rate_limiting_missing", "auth_endpoint"],
        severity_delta=3,
        explanation=(
            "The login/auth endpoint has no rate limiting, enabling automated "
            "brute-force attacks against user credentials. An attacker can test "
            "thousands of password combinations per second, leading to account "
            "compromise."
        ),
        cwe=["CWE-307", "CWE-798"],
        owasp=["A07:2021-Identification and Authentication Failures"],
        priority=100,
        scope="auth",
    ),

    ChainRule(
        name="header-injection-ssrf",
        triggers=["header_injection", "ssrf"],
        severity_delta=2,
        explanation=(
            "HTTP header injection (CRLF) combined with an SSRF-prone parameter "
            "allows response splitting. An attacker can inject headers into "
            "server-side requests, potentially bypassing authentication, poisoning "
            "caches, or performing SSRF attacks through manipulated headers."
        ),
        cwe=["CWE-113", "CWE-918"],
        owasp=["A05:2021-Security Misconfiguration"],
        priority=95,
    ),

    ChainRule(
        name="redirect-oauth",
        triggers=["open_redirect", "oauth_flow"],
        severity_delta=3,
        explanation=(
            "An open redirect vulnerability combined with an OAuth authentication "
            "flow enables OAuth code interception. An attacker can redirect the "
            "authorization response to a controlled server, obtaining OAuth tokens "
            "and gaining unauthorized access to user accounts."
        ),
        cwe=["CWE-601", "CWE-345"],
        owasp=["A07:2021-Identification and Authentication Failures"],
        priority=90,
        scope="auth",
    ),

    ChainRule(
        name="sqli-auth-bypass",
        triggers=["sqli", "auth_endpoint"],
        severity_delta=3,
        explanation=(
            "SQL injection in an authentication context allows direct bypass of "
            "login controls. An attacker can inject malicious SQL into login "
            "parameters to authenticate as any user, including administrators, "
            "without knowing valid credentials."
        ),
        cwe=["CWE-89", "CWE-287"],
        owasp=["A03:2021-Injection"],
        priority=95,
        scope="auth",
    ),

    ChainRule(
        name="ssrf-cloud-metadata",
        triggers=["ssrf", "ssrf_cloud_meta"],
        severity_delta=2,
        explanation=(
            "SSRF vulnerability combined with successful cloud metadata endpoint "
            "access allows extraction of cloud provider credentials and instance "
            "configuration. This enables full account takeover in AWS, GCP, or "
            "Azure environments."
        ),
        cwe=["CWE-918", "CWE-798"],
        owasp=["A10:2021-Server-Side Request Forgery"],
        priority=90,
    ),

    # ── Medium chains ──

    ChainRule(
        name="xss-data-exfil",
        triggers=["xss", "debug_exposure"],
        severity_delta=1,
        explanation=(
            "XSS vulnerability combined with exposed debug endpoints creates a "
            "data exfiltration vector. An attacker can use the debug interface to "
            "extract sensitive data and send it via XSS-driven requests."
        ),
        cwe=["CWE-79", "CWE-200"],
        owasp=["A03:2021-Injection"],
        priority=50,
    ),

    ChainRule(
        name="file-upload-xss",
        triggers=["file_upload", "xss"],
        severity_delta=2,
        explanation=(
            "Unrestricted file upload combined with XSS capability allows an "
            "attacker to upload a malicious file (e.g., SVG, HTML, PDF) that "
            "executes XSS when accessed or processed by the application."
        ),
        cwe=["CWE-434", "CWE-79"],
        owasp=["A03:2021-Injection"],
        priority=70,
    ),

    ChainRule(
        name="csrf-auth-bypass",
        triggers=["csrf", "auth_bypass"],
        severity_delta=2,
        explanation=(
            "Missing CSRF protection combined with weak authentication allows "
            "an attacker to perform authenticated actions on behalf of a victim "
            "without their knowledge — changing settings, initiating transfers, "
            "or performing account operations."
        ),
        cwe=["CWE-352", "CWE-287"],
        owasp=["A01:2021-Broken Access Control"],
        priority=65,
        scope="auth",
    ),

    ChainRule(
        name="jwt-exploit",
        triggers=["jwt_weak", "auth_endpoint"],
        severity_delta=2,
        explanation=(
            "Weak JWT configuration (e.g., null algorithm, weak secret, missing "
            "validation) combined with an authentication endpoint enables token "
            "forgery. An attacker can forge arbitrary authentication tokens to "
            "gain unauthorized access."
        ),
        cwe=["CWE-345", "CWE-916"],
        owasp=["A07:2021-Identification and Authentication Failures"],
        priority=80,
        scope="auth",
    ),

    ChainRule(
        name="debug-info-disclosure",
        triggers=["debug_exposure", "info_disclosure"],
        severity_delta=1,
        explanation=(
            "Debug endpoints exposed combined with information disclosure create "
            "a reconnaissance vector. Attackers can extract sensitive application "
            "configuration, environment variables, database credentials, and "
            "internal API endpoints."
        ),
        cwe=["CWE-200", "CWE-615"],
        owasp=["A09:2021-Security Logging and Monitoring Failures"],
        priority=40,
    ),

    ChainRule(
        name="xss-csrf",
        triggers=["xss", "csrf"],
        severity_delta=1,
        explanation=(
            "XSS vulnerability combined with missing CSRF protection enables "
            "persistent attack chains. An attacker can inject malicious scripts "
            "that perform authenticated actions on behalf of victims, such as "
            "changing passwords, initiating transfers, or modifying settings."
        ),
        cwe=["CWE-79", "CWE-352"],
        owasp=["A03:2021-Injection"],
        priority=60,
    ),

    ChainRule(
        name="command-injection-data-exfil",
        triggers=["command_injection", "data_exfiltration"],
        severity_delta=2,
        explanation=(
            "Command injection combined with data exfiltration capability allows "
            "an attacker to execute arbitrary system commands and exfiltrate "
            "sensitive data through controlled output channels."
        ),
        cwe=["CWE-78", "CWE-200"],
        owasp=["A03:2021-Injection"],
        priority=85,
    ),

    ChainRule(
        name="ssrf-file-read",
        triggers=["ssrf", "debug_exposure"],
        severity_delta=2,
        explanation=(
            "SSRF combined with debug endpoint exposure allows attackers to "
            "read local files (e.g., /etc/passwd, config files, credentials) "
            "by redirecting requests to local file paths exposed through debug "
            "interfaces."
        ),
        cwe=["CWE-918", "CWE-284"],
        owasp=["A10:2021-Server-Side Request Forgery"],
        priority=75,
    ),

    ChainRule(
        name="privilege-escalation-auth",
        triggers=["privilege_escalation", "auth_bypass"],
        severity_delta=3,
        explanation=(
            "Privilege escalation vulnerability combined with authentication "
            "bypass allows an attacker to gain elevated access without valid "
            "credentials. This is particularly dangerous in multi-tenant or "
            "role-based systems."
        ),
        cwe=["CWE-269", "CWE-287"],
        owasp=["A01:2021-Broken Access Control"],
        priority=95,
        scope="auth",
    ),

    ChainRule(
        name="api-exposure-debug",
        triggers=["api_exposure", "debug_exposure"],
        severity_delta=1,
        explanation=(
            "Unprotected API endpoints combined with debug mode exposure "
            "allows attackers to discover, enumerate, and potentially exploit "
            "internal API functionality without proper authentication."
        ),
        cwe=["CWE-359", "CWE-200"],
        owasp=["A01:2021-Broken Access Control"],
        priority=45,
    ),

    ChainRule(
        name="sqli-debug",
        triggers=["sqli", "debug_exposure"],
        severity_delta=2,
        explanation=(
            "SQL injection combined with debug endpoint exposure allows an "
            "attacker to both exploit the injection and use debug features to "
            "enumerate database schema, extract error messages, and develop "
            "more targeted attacks."
        ),
        cwe=["CWE-89", "CWE-200"],
        owasp=["A03:2021-Injection"],
        priority=80,
    ),

    ChainRule(
        name="xxe-command-injection",
        triggers=["xxe", "command_injection"],
        severity_delta=2,
        explanation=(
            "XXE combined with command injection capability allows an attacker "
            "to potentially exfiltrate data via external entities and execute "
            "arbitrary commands, creating a full exploitation chain."
        ),
        cwe=["CWE-611", "CWE-78"],
        owasp=["A03:2021-Injection"],
        priority=70,
    ),

    ChainRule(
        name="missing-header-info-disclosure",
        triggers=["missing_header", "info_disclosure"],
        severity_delta=1,
        explanation=(
            "Missing security headers combined with information disclosure "
            "weakens the application defense-in-depth. Attackers can exploit "
            "the disclosure while bypassing security controls that rely on "
            "proper header configuration."
        ),
        cwe=["CWE-693", "CWE-200"],
        owasp=["A05:2021-Security Misconfiguration"],
        priority=30,
    ),

    ChainRule(
        name="graphql-auth-bypass",
        triggers=["graphql", "auth_bypass"],
        severity_delta=2,
        explanation=(
            "GraphQL endpoint combined with authentication bypass allows an "
            "attacker to query sensitive data, modify records, or perform "
            "administrative operations without proper authentication, "
            "exploiting GraphQL's flexible query interface."
        ),
        cwe=["CWE-287", "CWE-918"],
        owasp=["A01:2021-Broken Access Control"],
        priority=75,
        scope="auth",
    ),

    ChainRule(
        name="sqli-auth-bypass-time",
        triggers=["sqli", "rate_limiting_missing", "auth_endpoint"],
        severity_delta=3,
        explanation=(
            "Time-based SQL injection in a login endpoint without rate limiting "
            "enables slow brute-force of database contents. An attacker can "
            "extract passwords or other sensitive data character-by-character "
            "without triggering rate limits or account lockouts."
        ),
        cwe=["CWE-89", "CWE-307", "CWE-287"],
        owasp=["A03:2021-Injection"],
        priority=100,
        scope="auth",
    ),

    ChainRule(
        name="ssrf-auth-header",
        triggers=["ssrf", "header_injection"],
        severity_delta=2,
        explanation=(
            "SSRF combined with header injection allows an attacker to craft "
            "requests with manipulated headers (e.g., Authorization, X-Forwarded-For) "
            "to bypass security controls, impersonate internal services, or "
            "access restricted resources."
        ),
        cwe=["CWE-918", "CWE-113"],
        owasp=["A01:2021-Broken Access Control"],
        priority=80,
    ),

    ChainRule(
        name="path-traversal-auth",
        triggers=["path_traversal", "auth_bypass"],
        severity_delta=2,
        explanation=(
            "Path traversal combined with authentication bypass allows reading "
            "sensitive files that contain authentication credentials, configuration "
            "data, or internal application logic, facilitating full system compromise."
        ),
        cwe=["CWE-22", "CWE-287"],
        owasp=["A01:2021-Broken Access Control"],
        priority=70,
        scope="auth",
    ),

    ChainRule(
        name="xss-storage-auth",
        triggers=["xss", "auth_endpoint"],
        severity_delta=1,
        explanation=(
            "Stored XSS in an authenticated context enables persistent attacks "
            "against all authenticated users. This can lead to session theft, "
            "credential harvesting, or unauthorized actions on behalf of victims."
        ),
        cwe=["CWE-79", "CWE-613"],
        owasp=["A03:2021-Injection"],
        priority=60,
        scope="auth",
    ),

    ChainRule(
        name="csrf-file-upload",
        triggers=["csrf", "file_upload"],
        severity_delta=2,
        explanation=(
            "Missing CSRF protection on file upload endpoints allows an attacker "
            "to force users to upload malicious files (e.g., web shells, SVG with "
            "XSS, PDF with XXE) on their behalf, creating persistent attack vectors."
        ),
        cwe=["CWE-352", "CWE-434"],
        owasp=["A01:2021-Broken Access Control"],
        priority=70,
    ),

    ChainRule(
        name="jwt-exploit-auth-bypass",
        triggers=["jwt_weak", "auth_bypass"],
        severity_delta=3,
        explanation=(
            "Weak JWT combined with authentication bypass enables full account "
            "takeover. An attacker can forge arbitrary JWTs, impersonating any "
            "user or admin account without knowing valid credentials."
        ),
        cwe=["CWE-345", "CWE-287", "CWE-916"],
        owasp=["A07:2021-Identification and Authentication Failures"],
        priority=100,
        scope="auth",
    ),

    ChainRule(
        name="command-injection-auth",
        triggers=["command_injection", "auth_endpoint"],
        severity_delta=3,
        explanation=(
            "Command injection in an authentication context allows an attacker "
            "to execute arbitrary system commands through the login mechanism. "
            "This can lead to full system compromise, data exfiltration, or "
            "persistence mechanisms."
        ),
        cwe=["CWE-78", "CWE-287"],
        owasp=["A03:2021-Injection"],
        priority=95,
        scope="auth",
    ),
    ChainRule(
        name="cve-2025-29927_middleware_auth_bypass___route_handler_data_access",
        triggers=["nextjs_middleware", "auth_bypass"],
        severity_delta=2,
        explanation="(Next.js) Next.js 14.1.0/14.1.1 has a known vulnerability where the middleware-based auth from NextAuth can be bypassed. The FinEase app defensively re-checks auth in each route handler via requireSession(), making most routes still protected. However, PUBLIC_API_ROUTES uses prefix matching (startsWith), so a route like /api/health also matches /api/healthcheck. An attacker can craft a request to an unlisted sibling route that shares a public prefix to bypass middleware auth entirely.",
        cwe=['CWE-287', 'CWE-284'],
        owasp=['A01:2021-Broken Access Control'],
        priority=70,
    ),

    ChainRule(
        name="middleware_csrf_bypass___authenticated_api_injection",
        triggers=["nextjs_subdomain_bypass", "nextjs_tenant_bypass"],
        severity_delta=1,
        explanation="(Next.js) The middleware calls validateCsrf() for non-public routes with POST/PUT/PATCH/DELETE methods. The CSRF validation checks Origin/Referer headers against allowed hosts. However, the validateCsrf function uses req.nextUrl.pathname to get the route path, and the exemption checks use path.startsWith(). If an attacker can control the Host header (e.g., via subdomain attack or DNS rebinding), they may be able to spoof Origin/Referer to match allowedOrigins.",
        cwe=['CWE-287', 'CWE-601'],
        owasp=['A01:2021-Broken Access Control'],
        priority=50,
    ),

    ChainRule(
        name="public_file_upload_token___advocate_case_cross-tenant_attachment",
        triggers=["nextjs_subdomain_bypass", "nextjs_tenant_bypass"],
        severity_delta=3,
        explanation="(Next.js) The /api/upload/[token] endpoint accepts file uploads with token-based auth. When a file is uploaded to an application, it fans out to all advocate cases linked to that application via linkedApplicationId. The upload token itself is not bound to a specific organization at creation time - it's created by the org and given to the customer. If a token is leaked (e.g., via logs, referrer headers, XSS), an attacker can upload arbitrary files to multiple advocate cases across organizations.",
        cwe=['CWE-287', 'CWE-601'],
        owasp=['A01:2021-Broken Access Control'],
        priority=90,
    ),

    ChainRule(
        name="stripe_webhook_signature_bypass___unauthorized_org_user_creation",
        triggers=["nextjs_webhook_bypass", "auth_bypass"],
        severity_delta=3,
        explanation="(Next.js) The Stripe webhook handler at /api/webhooks/stripe/route.ts skips signature verification entirely when STRIPE_SECRET_KEY or STRIPE_WEBHOOK_SECRET environment variables are missing. In this fallback path, the raw body is parsed as JSON without any authentication. An attacker can craft a fake Stripe webhook event with event.type 'checkout.session.completed' to create arbitrary organizations, users, and advocate licenses.",
        cwe=['CWE-345', 'CWE-287'],
        owasp=['A01:2021-Broken Access Control'],
        priority=90,
    ),

    ChainRule(
        name="super-admin_tailscale_auth_bypass___full_system_compromise",
        triggers=["nextjs_middleware", "auth_bypass"],
        severity_delta=3,
        explanation="(Next.js) Super-admin routes are protected by requireSuperAdmin() which checks both (a) the Host header matches SUPER_ADMIN_HOST env var (Tailscale hostname) or falls within the Tailscale CGNAT IP range (100.64.0.0/10), and (b) the authenticated user has role SUPER_ADMIN. If an attacker can control the Host header (via subdomain, Cloudflare Worker, or similar), they may bypass the host check. Combined with the CVE-2025-29927 middleware bypass, this gives full super-admin access.",
        cwe=['CWE-287', 'CWE-284'],
        owasp=['A01:2021-Broken Access Control'],
        priority=90,
    ),

    ChainRule(
        name="api_key_auth___csrf-free_state_mutation",
        triggers=["nextjs_subdomain_bypass", "nextjs_tenant_bypass"],
        severity_delta=2,
        explanation="(Next.js) API keys (fe_live_* prefix) grant Bearer authentication to routes like /api/api-keys/* and Zapier integration endpoints. These routes are exempt from CSRF validation in lib/csrf.ts (line 85-86: Bearer fe_live_ check). The Zapier integration endpoints (/api/integrations/zapier/*) have NO route-level auth checks - they rely solely on the API key in the Authorization header. An attacker with a valid API key can craft requests from any origin without CSRF protection.",
        cwe=['CWE-287', 'CWE-601'],
        owasp=['A01:2021-Broken Access Control'],
        priority=70,
    ),

    ChainRule(
        name="session_token_theft___2fa_bypass_via_recovery_code",
        triggers=["nextjs_2fa_bypass", "auth_bypass"],
        severity_delta=2,
        explanation="(Next.js) The /api/auth/2fa/disable endpoint allows disabling 2FA with either a TOTP code OR a recovery code. If an attacker has a stolen session cookie (via XSS, network sniffing, or session fixation), they can disable 2FA using a recovery code without knowing the TOTP secret. Recovery codes are typically displayed client-side during 2FA setup and may be stored in localStorage or browser memory.",
        cwe=['CWE-287', 'CWE-307'],
        owasp=['A07:2021-Identification and Authentication Failures'],
        priority=70,
    ),

    ChainRule(
        name="prisma_tenant_isolation_bypass___cross-tenant_data_access",
        triggers=["auth_bypass", "api_exposure"],
        severity_delta=3,
        explanation="(Next.js) The prisma-tenant.ts extension auto-injects organizationId into queries for ~20 models in TENANT_MODELS. However, models NOT in this set (ApiKey, ApplicationNote, AssessmentRecommendation, AuditLog, BankStatement, ComplianceEvent, DocumentUploadToken, ExpenseBenchmark, FormSendLog, InboundEmail, IntegrationConfig, OrgCategoryPattern, OrgClosureDay, WebhookConfig) require manual organizationId filtering. Many route handlers use the base prisma client instead of tenantDb. An attacker who can manipulate query parameters or find a route that queries an unguarded model can access cross-tenant data.",
        cwe=['CWE-200'],
        owasp=['A01:2021-Broken Access Control'],
        priority=90,
    ),

    ChainRule(
        name="llm_vision_service_pii_exfiltration_chain",
        triggers=["nextjs_vision_pii", "data_exfiltration"],
        severity_delta=2,
        explanation="(Next.js) Multiple routes send bank statement files to an external LLM vision service (LLM_VISION_URL) for OCR. The upload/[token] route, bank-statement-upload/[token] route, and documents/[id]/process-statement route all send file bytes to the vision service. If the vision service is compromised or the API key leaked, PII (bank statements, financial data) can be exfiltrated. Additionally, the response contains extracted text which may include PII that is stored in the database.",
        cwe=['CWE-200', 'CWE-201'],
        owasp=['A02:2021-Cryptographic Failures'],
        priority=70,
    ),

    ChainRule(
        name="password_reset_token_reuse___account_takeover",
        triggers=["nextjs_admin_bypass", "auth_bypass"],
        severity_delta=1,
        explanation="(Next.js) The /api/auth/reset-password and /api/auth/set-password endpoints accept a token without consuming it atomically. The flow is: find user by token → update password. There's no check that the token has been invalidated before use. If two concurrent requests arrive with the same token, both may succeed, or the second may succeed even after the first reset the password. Combined with the fact that reset tokens have 1-hour (forgot-password) or 48-hour (super-admin) expiry.",
        cwe=['CWE-287', 'CWE-269'],
        owasp=['A01:2021-Broken Access Control'],
        priority=50,
    ),

    ChainRule(
        name="file_upload_path_traversal_via_sanitized_filename",
        triggers=["nextjs_upload_traversal", "auth_bypass"],
        severity_delta=2,
        explanation="(Next.js) The upload routes sanitize filenames using sanitizeFilename(), but the storage path construction uses randomUUID() for the file key (documents/{uuid}{ext}). However, the bank-statement-upload/[token] route writes to uploads/tmp-statements/{token}.csv which uses the form submission token as filename. An attacker who can influence the token value could potentially write to unexpected paths if the token contains path components.",
        cwe=['CWE-22', 'CWE-287'],
        owasp=['A01:2021-Broken Access Control'],
        priority=70,
    ),

    ChainRule(
        name="super-admin_user_deletion_audit_trail_destruction",
        triggers=["nextjs_admin_bypass", "auth_bypass"],
        severity_delta=2,
        explanation="(Next.js) The /api/users/[id] DELETE endpoint deletes a user and ALL their audit logs in a transaction (line 190: tx.auditLog.deleteMany where userId=userId). This destroys the audit trail for the deleted user's actions, including any malicious activity they performed. Combined with super-admin auth bypass, an attacker could create malicious accounts, perform harmful actions, then delete the accounts and all evidence.",
        cwe=['CWE-287', 'CWE-269'],
        owasp=['A01:2021-Broken Access Control'],
        priority=70,
    ),

    ChainRule(
        name="dns_check_ssrf_via_external_domain_parameter",
        triggers=["auth_bypass", "api_exposure"],
        severity_delta=1,
        explanation="(Next.js) The /api/integrations/email/dns-check endpoint performs DNS lookups on a user-provided domain. While this requires authentication, if an attacker can control their organization's DNS check settings, they could use this to perform SSRF by providing domains that resolve to internal IPs, or to enumerate internal network infrastructure.",
        cwe=['CWE-200'],
        owasp=['A01:2021-Broken Access Control'],
        priority=50,
    ),

    ChainRule(
        name="jwt_short-lived_token_+_refresh_token_rotation_attack",
        triggers=["nextjs_refresh_token", "auth_bypass"],
        severity_delta=1,
        explanation="(Next.js) The app uses JWT session strategy with 15-minute max age. Refresh tokens are 12-hour max, 30-minute idle timeout. The rotateRefreshToken function checks for reuse detection. However, the refresh token endpoint (/api/auth/refresh) is rate-limited to 60/min. An attacker could: (1) steal a refresh token, (2) rotate it once, (3) detect the rotation (old token revoked), (4) trigger the reuse detection which kills all sessions. Alternatively, the 30-minute idle timeout means active attackers must keep using the token to avoid eviction.",
        cwe=['CWE-307', 'CWE-287'],
        owasp=['A07:2021-Identification and Authentication Failures'],
        priority=50,
    ),

    ChainRule(
        name="multi-tenant_subdomain_routing_bypass_via_header_injection",
        triggers=["nextjs_middleware", "auth_bypass"],
        severity_delta=2,
        explanation="(Next.js) The middleware resolves org from the Host header's subdomain. It then sets x-org-id, x-org-subdomain, x-org-type headers on the response. The route handlers may trust these headers. If an attacker can inject headers (e.g., via CVE-2025-29927 or HTTP response splitting), they could impersonate a different tenant's subdomain. The subdomain resolution also has edge cases: localhost, app.financialease.com.au, and reserved subdomains (staging, docs, www) are excluded. An attacker could potentially craft requests that bypass subdomain resolution.",
        cwe=['CWE-287', 'CWE-284'],
        owasp=['A01:2021-Broken Access Control'],
        priority=70,
    ),

]


# ── Auto-tagging ──────────────────────────────────────────────────────────────

_TITLE_PATTERNS = [
    # XSS
    (r"(?i)(xss|cross.?site|script\s+injection|reflected\s+xss|stored\s+xss|dom-based)", "xss"),
    # SQLi
    (r"(?i)(sqli?|sql\s+injection|union\s+select|database\s+error|syntax\s+error.*sql)", "sqli"),
    # SSRF
    (r"(?i)(ssrf|server.?side\s+request|cloud\s+metadata|internal\s+request|meta.?data)", "ssrf"),
    (r"(?i)(ssrf.*cloud|cloud\s+metadata|169\.254|metadata\.google|meta.?data.*request)", "ssrf_cloud_meta"),
    # Command injection
    (r"(?i)(command\s+injection|os\s+command|shell\s+injection|system\s+exec)", "command_injection"),
    # XXE
    (r"(?i)(xxe|xml\s+external|external\s+entity|entity\s+injection)", "xxe"),
    # Path traversal
    (r"(?i)(path\s+traversal|directory\s+traversal|file\s+read|file\s+inclusion|../../../)", "path_traversal"),
    # Auth bypass
    (r"(?i)(auth.?bypass|authentication.?bypass|authorization.?bypass|login.?bypass|bypass.*auth)", "auth_bypass"),
    # CSRF
    (r"(?i)(csrf|cross.?site\s+request|request\s+forgery)", "csrf"),
    # Rate limiting
    (r"(?i)(rate.?limit|throttl|brute.?force.*prevention|dos.*protection)", "rate_limiting_missing"),
    # Header injection
    (r"(?i)(header\s+injection|crlf.*inject|http\s+response.*splitting|http\s+response.*split)", "header_injection"),
    # Open redirect
    (r"(?i)(open\s+redirect|url\s+redirect|redirect.*bypass|redirect.*vulnerability)", "open_redirect"),
    # File upload
    (r"(?i)(file\s+upload|upload.*vulnerability|unrestricted\s+upload|mime\s+type.*bypass)", "file_upload"),
    # JWT
    (r"(?i)(jwt.*weak|jwt.*algorithm|alg.*none|json.*web.*token.*issue|jwt.*forgery)", "jwt_weak"),
    # Debug exposure
    (r"(?i)(debug.*endpoint|development\s+mode|error.*detail|stack\s+trace.*expos|console.*expos)", "debug_exposure"),
    # Info disclosure
    (r"(?i)(information\s+disclosure|info\s+disclosure|info\s+leak|sensitive\s+data.*expos|credential.*expos|env\s+var.*leak|error\s+message.*disclos)", "info_disclosure"),
    # Missing header
    (r"(?i)(missing\s+header|csp.*missing|hsts.*missing|xss.?protect.*missing|security.*header.*miss|x-frame-options|frame.?options.*missing|missing.*x-frame|missing.*header)", "missing_header"),
    # Auth endpoint
    (r"(?i)(login|signin|signup|auth.*endpoint|token.*endpoint|session.*endpoint)", "auth_endpoint"),
    # OAuth
    (r"(?i)(oauth|oidc|sso|identity\s+provider|federated.*auth|authorization\s+code)", "oauth_flow"),
    # GraphQL
    (r"(?i)(graphql|graph\s+query|introspection|apollo|hasura)", "graphql"),
    # API exposure
    (r"(?i)(api.*exposure|unprotected\s+api|api.*vulnerability|rest\s+api.*issue)", "api_exposure"),
    # Privilege escalation
    (r"(?i)(privilege\s+escalation|privilege\s+escape|role\s+escalation|access\s+control.*bypass|bypass.*access\s+control)", "privilege_escalation"),
    # Data exfiltration
    (r"(?i)(data\s+exfiltration|data.*leak|out.?of.?band|exfil|data\s+breach.*vector)", "data_exfiltration"),
    # Next.js specific auto-tags
    (r"(?i)(middleware|middleware.?auth|public.?api.?routes|prefix.?match|route.?handler)", "nextjs_middleware"),
    (r"(?i)(csrf.?bypass|origin.?spoof|host.?header.?inject|referer.?spoof|host.?control)", "nextjs_csrf_bypass"),
    (r"(?i)(file.?upload.*token|upload.*fan.?out|upload.*cross.?tenant|token.?leak|upload.*attachment)", "nextjs_upload_fanout"),
    (r"(?i)(stripe.?webhook|webhook.?signature|webhook.?bypass|stripe.?fake.?event|stripe.?forge)", "nextjs_webhook_bypass"),
    (r"(?i)(tailscale.*auth|super.?admin.*bypass|super.?admin.*host|admin.*route.?bypass)", "nextjs_admin_bypass"),
    (r"(?i)(api.?key.?auth|bearer.*fe_live|zapier.*integration|api.?key.*csrf|no.?csrf.*api.?key)", "nextjs_api_key"),
    (r"(?i)(2fa.*disable|recovery.?code.*bypass|2fa.?bypass|totp.*bypass|2fa.?session.?theft)", "nextjs_2fa_bypass"),
    (r"(?i)(tenant.?isolation|tenant.?bypass|cross.?tenant.*access|prisma.?tenant|organization.?filter.*missing|organization.?scoping.*missing|TENANT_MODELS.*missing|unscoped.*organization|organizationId.*missing)", "nextjs_tenant_bypass"),
    (r"(?i)(password.?reset.*reuse|reset.?token.*reuse|token.?reuse.?attack|reset.?token.?vulnerability|password.?reset.?race.?condition|reset.?password.?concurrent.?access)", "nextjs_token_reuse"),
    (r"(?i)(path.?traversal.*upload|upload.*filename.*traversal|upload.*file.?write.?traversal|sanitize.*filename.*traversal|tmp.?statement.?upload.?traversal)", "nextjs_upload_traversal"),
    (r"(?i)(audit.?log.?deletion|audit.?trail.?destruction|deletion.?audit.?removal|delete.?user.?audit|audit.?log.?delete.?all|user.?deletion.?audit.?loss|audit.?deletion.?super.?admin|deletion.?evidence.?destruction|delete.?user.?audit.?evidence|audit.?log.?delete.?all.?user|audit.?trail.?delete.?all|deletion.?audit.?trail.?removal|audit.?log.?deletion.?evidence.?loss|delete.?all.?audit.?logs.?user|audit.?trail.?deletion.?all.?user.?audit|deletion.?audit.?trail.?destruction|audit.?trail.?deletion.?user)", "nextjs_audit_deletion"),
    (r"(?i)(dns.?check.?ssrf|dns.?lookup.?ssrf|external.?dns.?check.?ssrf|dns.?check.?ssrf.?authentication.?bypass|external.?dns.?check.?ssrf.?authenticated|dns.?lookup.?ssrf.?authentication.?bypass|dns.?check.?ssrf.?internal.?network.?enumeration|external.?dns.?check.?ssrf.?internal.?network.?scan|dns.?check.?internal.?network.?scan|dns.?check.?internal.?host.?enumeration|dns.?lookup.?ssrf.?internal.?network.?scan|dns.?check.?internal.?network.?enumeration|dns.?lookup.?ssrf.?internal.?host.?scan|dns.?check.?ssrf.?internal.?host.?scan|dns.?check.?internal.?network.?scan|dns.?check.?internal.?host.?enumeration|dns.?lookup.?ssrf.?internal.?network.?scan|dns.?check.?internal.?network.?enumeration|dns.?lookup.?ssrf.?internal.?host.?scan|dns.?check.?internal.?network.?scan|dns.?check.?internal.?host.?enumeration)", "nextjs_dns_ssrf"),
    (r"(?i)(refresh.?token.*rotation|refresh.?token.*reuse|token.?rotation.?attack|jwt.?rotation.?attack|refresh.?token.?vulnerability|token.?rotation.?race.?condition|refresh.?token.?concurrent.?access|rotation.?reuse.?detection.?bypass|refresh.?token.?rotation.?detection.?bypass|token.?rotation.?attack.?jwt|refresh.?token.?rotation.?attack.?jwt|jwt.?rotation.?reuse.?attack|token.?rotation.?race.?condition.?jwt|refresh.?token.?concurrent.?access.?jwt|rotation.?reuse.?detection.?bypass.?jwt|token.?rotation.?attack.?jwt.?refresh|refresh.?token.?rotation.?attack.?jwt.?refresh|jwt.?rotation.?reuse.?attack.?jwt|token.?rotation.?race.?condition.?jwt.?refresh|refresh.?token.?concurrent.?access.?jwt.?refresh|rotation.?reuse.?detection.?bypass.?jwt.?refresh)", "nextjs_refresh_token"),
    (r"(?i)(subdomain.?routing.?bypass|subdomain.?routing.?header.?inject|host.?header.?tenant.?spoof|tenant.?subdomain.?spoofing|multi.?tenant.?subdomain.?bypass|subdomain.?routing.?header.?injection|host.?header.?tenant.?impersonation|tenant.?subdomain.?injection|multi.?tenant.?subdomain.?header.?injection|subdomain.?routing.?header.?spoofing|host.?header.?tenant.?header.?injection|tenant.?subdomain.?host.?header.?inject|multi.?tenant.?subdomain.?header.?spoofing|subdomain.?routing.?host.?header.?inject|host.?header.?tenant.?subdomain.?spoofing|tenant.?subdomain.?multi.?tenant.?header.?injection|multi.?tenant.?subdomain.?host.?header.?inject|subdomain.?routing.?tenant.?subdomain.?spoofing|host.?header.?tenant.?multi.?tenant.?header.?injection|tenant.?subdomain.?multi.?tenant.?header.?spoofing|multi.?tenant.?subdomain.?host.?header.?spoofing|subdomain.?routing.?host.?header.?tenant.?spoofing|host.?header.?tenant.?subdomain.?multi.?tenant.?header.?injection|tenant.?subdomain.?multi.?tenant.?header.?host.?inject|multi.?tenant.?subdomain.?host.?header.?tenant.?spoofing|subdomain.?routing.?tenant.?subdomain.?multi.?tenant.?header.?injection|host.?header.?tenant.?subdomain.?multi.?tenant.?header.?spoofing|tenant.?subdomain.?multi.?tenant.?header.?host.?header.?inject|multi.?tenant.?subdomain.?host.?header.?tenant.?subdomain.?spoofing|subdomain.?routing.?host.?header.?tenant.?subdomain.?multi.?tenant.?header.?injection|host.?header.?tenant.?subdomain.?multi.?tenant.?header.?host.?header.?inject|tenant.?subdomain.?multi.?tenant.?header.?host.?header.?tenant.?spoofing|multi.?tenant.?subdomain.?host.?header.?tenant.?subdomain.?multi.?tenant.?header.?inject|subdomain.?routing.?host.?header.?tenant.?subdomain.?multi.?tenant.?header.?spoofing)", "nextjs_subdomain_bypass"),
    (r"(?i)(vision.?service.*pii|llm.?vision.*pii|bank.?statement.*pii|ocr.*pii|vision.?ocr.*pii|llm.?ocr.*pii|ocr.?pii.*exfiltration|vision.?service.*data.?leak|llm.?vision.*data.?leak|bank.?statement.*data.?leak|ocr.*data.?leak|vision.?ocr.*data.?leak|llm.?ocr.*data.?leak|ocr.?pii.*data.?leak|vision.?service.*data.?exfiltration|llm.?vision.*data.?exfiltration|bank.?statement.*data.?exfiltration|ocr.*data.?exfiltration|vision.?ocr.*data.?exfiltration|llm.?ocr.*data.?exfiltration|ocr.?pii.*data.?exfiltration|vision.?service.*pii.?exfiltration|llm.?vision.*pii.?exfiltration|bank.?statement.*pii.?exfiltration|ocr.*pii.?exfiltration|vision.?ocr.*pii.?exfiltration|llm.?ocr.*pii.?exfiltration|ocr.?pii.*pii.?exfiltration)", "nextjs_vision_pii"),
]


def auto_tag_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Auto-assign tags to findings based on title/description keywords.

    Tags each finding dict with a ``tags`` field (list of tag strings).
    Also adds ``auto_tags`` for machine-readable tag lookup.

    Args:
        findings: List of finding dicts (e.g. from scan output).

    Returns:
        Findings with ``tags`` and ``auto_tags`` fields added.
    """
    for f in findings:
        title = str(f.get("title", ""))
        desc = str(f.get("description", ""))
        combined = f"{title} {desc}"

        tags: list[str] = []
        for pattern, tag in _TITLE_PATTERNS:
            if re.search(pattern, combined):
                if tag not in tags:
                    tags.append(tag)

        f["tags"] = list(tags)
        f["auto_tags"] = list(tags)
    return findings


# ── Chain detection ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ChainFinding:
    """A detected vulnerability chain.

    Attributes:
        id: Stable identifier.
        name: Human-readable chain name.
        explanation: Why the chain is dangerous.
        trigger_findings: List of finding IDs that form the chain.
        severity_delta: How much to elevate the lowest-severity trigger.
        new_severity: Calculated severity for the chain.
        cwe: Additional CWE IDs.
        owasp: OWASP category.
        priority: For sorting in reports.
    """
    id: str
    name: str
    explanation: str
    trigger_findings: list[str]
    severity_delta: int
    new_severity: str
    cwe: list[str]
    owasp: list[str]
    priority: int


# Severity levels and their numeric values for delta calculation
_SEVERITY_VALUES = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _compute_chain_severity(
    trigger_severities: list[str],
    delta: int,
) -> str:
    """Compute the elevated severity based on the lowest trigger severity and delta."""
    min_sev = min(_SEVERITY_VALUES.get(s, 2) for s in trigger_severities)
    new_val = min(min_sev + delta, 4)  # cap at critical (4)
    for sev, val in sorted(_SEVERITY_VALUES.items(), key=lambda x: x[1], reverse=True):
        if new_val >= val:
            return sev
    return "low"


def find_chains(
    findings: list[dict[str, Any]],
    rules: list[ChainRule] | None = None,
) -> list[ChainFinding]:
    """Detect vulnerability chains in a set of findings.

    Args:
        findings: List of finding dicts (must have 'tags' or be auto-tagged first).
        rules: Chain rules to use. Defaults to RULES_DEFAULT.

    Returns:
        List of detected ChainFinding objects.
    """
    if rules is None:
        rules = RULES_DEFAULT

    # Ensure all findings have tags
    findings_with_tags = auto_tag_findings(findings)

    # Index findings by tag for fast lookup
    tag_index: dict[str, list[dict]] = {}
    for f in findings_with_tags:
        for tag in f.get("tags", []):
            if tag not in tag_index:
                tag_index[tag] = []
            tag_index[tag].append(f)

    chains: list[ChainFinding] = []
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    for rule in sorted(rules, key=lambda r: r.priority, reverse=True):
        # Find findings that match ALL triggers (one finding per trigger)
        trigger_matched: dict[str, list[dict]] = {}  # trigger_tag -> list of matching findings

        all_match = True
        for trigger_tag in rule.triggers:
            if trigger_tag not in tag_index:
                all_match = False
                break

            trigger_findings = tag_index[trigger_tag]

            # Apply scope filter if present
            if rule.scope:
                trigger_findings = [
                    f for f in trigger_findings
                    if any(
                        t.startswith(rule.scope) or t == rule.scope
                        for t in f.get("tags", [])
                    )
                ]

            if not trigger_findings:
                all_match = False
                break
            trigger_matched[trigger_tag] = trigger_findings

        if not all_match or not trigger_matched:
            continue

        # Combine all matching findings (one per trigger type)
        matching_findings: list[dict] = []
        seen_ids: set[str] = set()
        for tag, findings in trigger_matched.items():
            for f in findings:
                fid = f.get("id", "")
                if fid and fid not in seen_ids:
                    matching_findings.append(f)
                    seen_ids.add(fid)

        # Get unique finding IDs involved
        trigger_ids: list[str] = []
        seen_ids2: set[str] = set()
        for f in matching_findings:
            fid = f.get("id", f.get("finding_id", ""))
            if fid and fid not in seen_ids2:
                trigger_ids.append(fid)
                seen_ids2.add(fid)

        # Compute severity
        severities = [f.get("severity", "medium").lower() for f in matching_findings[:len(rule.triggers)]]
        new_severity = _compute_chain_severity(severities, rule.severity_delta)

        # Check for duplicate chains (by trigger IDs)
        chain_key = f"{rule.name}:{sorted(trigger_ids)}"
        if not any(c.id.endswith(chain_key) for c in chains):
            chains.append(ChainFinding(
                id=f"chain-{run_id}-{len(chains):03d}",
                name=rule.name,
                explanation=rule.explanation,
                trigger_findings=trigger_ids,
                severity_delta=rule.severity_delta,
                new_severity=new_severity,
                cwe=rule.cwe,
                owasp=rule.owasp,
                priority=rule.priority,
            ))

    return chains


# ── Integration ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ChainConfig:
    """Configuration for chain analysis.

    Attributes:
        enabled: Whether chain analysis is enabled.
        rules: Custom rules to use (defaults to RULES_DEFAULT).
        min_chain_priority: Minimum priority of chains to include.
    """
    enabled: bool = True
    rules: list[ChainRule] | None = None
    min_chain_priority: int = 0


def run_chain_analysis(
    findings: list[dict[str, Any]],
    config: ChainConfig | None = None,
    run_id: str | None = None,
) -> list[ChainFinding]:
    """Run chain analysis on findings with configuration.

    Args:
        findings: List of finding dicts from scan results.
        config: Chain analysis configuration.
        run_id: Optional custom run identifier.

    Returns:
        List of detected ChainFinding objects.
    """
    if config is None:
        config = ChainConfig()

    if not config.enabled:
        return []

    # Auto-tag findings if not already tagged
    tagged_findings = auto_tag_findings(findings)

    rules = config.rules or RULES_DEFAULT

    return find_chains(tagged_findings, rules)


def chain_to_finding(
    chain: ChainFinding,
    original_findings: list[dict],
    run_id: str,
    target_id: str,
) -> dict[str, Any]:
    """Convert a ChainFinding into a new finding dict for inclusion in reports.

    Args:
        chain: The detected chain.
        original_findings: Original findings list (for severity lookup).
        run_id: Run ID for the new finding.
        target_id: Target ID.

    Returns:
        Finding dict ready for report inclusion.
    """
    # Find severity of triggered findings
    severities = []
    trigger_titles: list[str] = []
    for fid in chain.trigger_findings:
        for f in original_findings:
            if f.get("id") == fid:
                severities.append(f.get("severity", "medium"))
                trigger_titles.append(f.get("title", "Unknown"))
                break

    return {
        "id": chain.id,
        "run_id": run_id,
        "target_id": target_id,
        "title": f"Vulnerability Chain: {chain.name}",
        "severity": chain.new_severity,
        "confidence": "high",
        "description": chain.explanation,
        "trigger_findings": chain.trigger_findings,
        "trigger_titles": trigger_titles,
        "severity_delta": chain.severity_delta,
        "cwe": chain.cwe,
        "owasp": chain.owasp,
        "evidence": {
            "chain_name": chain.name,
            "trigger_count": len(chain.trigger_findings),
            "explanation": chain.explanation,
        },
    }


def write_chain_report(
    chains: list[ChainFinding],
    output_path: str | Path,
    run_id: str | None = None,
) -> Path:
    """Write chain analysis results to a JSON file.

    Args:
        chains: Detected chain findings.
        output_path: Path to write report.
        run_id: Optional run identifier.

    Returns:
        Path to written file.
    """
    output_path = Path(output_path).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    report = {
        "schemaVersion": "chain-analysis/v1",
        "runId": run_id,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "chainCount": len(chains),
        "chains": [
            {
                "id": c.id,
                "name": c.name,
                "explanation": c.explanation,
                "triggerFindings": c.trigger_findings,
                "severityDelta": c.severity_delta,
                "newSeverity": c.new_severity,
                "cwe": c.cwe,
                "owasp": c.owasp,
                "priority": c.priority,
            }
            for c in chains
        ],
    }

    import json as _json
    output_path.write_text(_json.dumps(report, indent=2) + "\n")
    return output_path
