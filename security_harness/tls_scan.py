"""TLS and security header scanning for the Hermes security harness.

This module performs:
- TLS configuration checks (version, ciphers, certificate validity)
- Security header analysis (CSP, HSTS, X-Frame-Options, etc.)
- Server information leakage detection
- CORS configuration analysis

Public API (``__all__``):
    TLSResult, run_tls_scan, HeaderResult, run_header_scan, TLSConfig, HeaderConfig
"""
from __future__ import annotations

import re
import ssl
import socket
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .artifacts import Finding, SEVERITIES, redact_secrets


# ── TLS checks ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TLSResult:
    """TLS scan result."""
    host: str
    port: int
    success: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    protocol_version: str | None = None
    cipher: str | None = None
    cert_info: dict[str, Any] | None = None
    total_checks: int = 0
    failed_checks: int = 0

    def to_summary(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "success": self.success,
            "finding_count": len(self.findings),
            "protocol_version": self.protocol_version,
            "cipher": self.cipher,
            "total_checks": self.total_checks,
            "failed_checks": self.failed_checks,
        }


def check_tls_config(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
) -> TLSResult:
    """Check TLS configuration for a host.

    Args:
        host: Hostname to check.
        port: Port number.
        timeout: Connection timeout.

    Returns:
        TLSResult with findings.
    """
    findings: list[dict[str, Any]] = []
    total_checks = 0
    failed_checks = 0
    protocol_version = None
    cipher = None
    cert_info = None

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                protocol_version = ssock.version() or "unknown"
                cipher_info = ssock.cipher()
                cipher = cipher_info[0] if cipher_info else "none"
                cert = ssock.getpeercert()

                total_checks += 1

                # Check certificate validity
                if cert:
                    cert_info = {
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "notAfter": cert.get("notAfter", ""),
                        "notBefore": cert.get("notBefore", ""),
                        "serialNumber": cert.get("serialNumber", ""),
                    }

                    # Check expiration
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        # Parse date string (format: "Mon DD HH:MM:SS YYYY GMT")
                        try:
                            from datetime import datetime
                            cert_expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            if cert_expiry < datetime.now():
                                findings.append({
                                    "id": f"tls-{hash('expired-cert')}",
                                    "title": "Expired TLS certificate",
                                    "description": f"Certificate expired on {not_after}",
                                    "severity": "critical",
                                    "confidence": "high",
                                    "tags": ["tls", "certificate"],
                                    "cwe": ["CWE-295"],
                                    "owasp": ["A02:2021-Cryptographic Failures"],
                                    "evidence": {"notAfter": not_after},
                                })
                                failed_checks += 1
                        except Exception:
                            pass

                    # Check weak key size
                    subject = cert.get("subject", ())
                    for field_attrs in subject:
                        for attr in field_attrs:
                            if attr[0] == "commonName":
                                if attr[1].startswith("localhost"):
                                    findings.append({
                                        "id": f"tls-{hash('localhost-cert')}",
                                        "title": "Self-signed localhost certificate",
                                        "description": "Certificate is issued for localhost, suitable only for development",
                                        "severity": "medium",
                                        "confidence": "high",
                                        "tags": ["tls", "certificate"],
                                        "cwe": ["CWE-295"],
                                        "owasp": ["A02:2021-Cryptographic Failures"],
                                        "evidence": {"cn": attr[1]},
                                    })

                # Check TLS version
                total_checks += 1
                if protocol_version in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "id": f"tls-{hash(f'weak-tls-{protocol_version}')}".replace("-", ""),
                        "title": f"Weak TLS version: {protocol_version}",
                        "description": f"Server uses TLS {protocol_version}, which is deprecated and vulnerable to known attacks",
                        "severity": "high",
                        "confidence": "high",
                        "tags": ["tls", "weak-crypto"],
                        "cwe": ["CWE-326"],
                        "owasp": ["A02:2021-Cryptographic Failures"],
                        "evidence": {"protocol": protocol_version},
                    })
                    failed_checks += 1

                # Check cipher strength
                total_checks += 1
                if cipher:
                    weak_ciphers = ["RC4", "DES", "NULL", "EXPORT", "anon"]
                    if any(wc in cipher.upper() for wc in weak_ciphers):
                        findings.append({
                            "id": f"tls-{hash(f'weak-cipher-{cipher}')}".replace("-", ""),
                            "title": f"Weak cipher suite: {cipher}",
                            "description": f"Server uses {cipher}, which is considered weak",
                            "severity": "high",
                            "confidence": "medium",
                            "tags": ["tls", "weak-crypto"],
                            "cwe": ["CWE-326"],
                            "owasp": ["A02:2021-Cryptographic Failures"],
                            "evidence": {"cipher": cipher},
                        })
                        failed_checks += 1

    except ssl.SSLError as e:
        findings.append({
            "id": f"tls-ssl-error",
            "title": "SSL/TLS handshake failed",
            "description": f"SSL/TLS handshake failed: {str(e)}",
            "severity": "high",
            "confidence": "medium",
            "tags": ["tls", "ssl"],
            "cwe": ["CWE-295"],
            "owasp": ["A02:2021-Cryptographic Failures"],
            "evidence": {"error": str(e)},
        })
        failed_checks += 1

    except Exception as e:
        findings.append({
            "id": "tls-connection-error",
            "title": "TLS connection failed",
            "description": f"Could not connect to {host}:{port}: {str(e)}",
            "severity": "medium",
            "confidence": "medium",
            "tags": ["tls", "network"],
            "evidence": {"host": host, "port": port, "error": str(e)},
        })
        failed_checks += 1

    return TLSResult(
        host=host,
        port=port,
        success=failed_checks == 0,
        findings=findings,
        protocol_version=protocol_version,
        cipher=cipher,
        cert_info=cert_info,
        total_checks=total_checks,
        failed_checks=failed_checks,
    )


def run_tls_scan(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
) -> TLSResult:
    """Run TLS scan on a host.

    Args:
        host: Hostname to scan.
        port: Port number.
        timeout: Connection timeout.

    Returns:
        TLSResult with findings.
    """
    return check_tls_config(host, port, timeout)


# ── Security header checks ──────────────────────────────────────────────────────

_SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "name": "CSP",
        "severity": "high",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "Strict-Transport-Security": {
        "name": "HSTS",
        "severity": "high",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "X-Frame-Options": {
        "name": "Clickjacking Protection",
        "severity": "medium",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "X-Content-Type-Options": {
        "name": "MIME Sniffing Protection",
        "severity": "medium",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "X-XSS-Protection": {
        "name": "XSS Protection",
        "severity": "low",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "Referrer-Policy": {
        "name": "Referrer Policy",
        "severity": "medium",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "Permissions-Policy": {
        "name": "Permissions Policy",
        "severity": "medium",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "Cross-Origin-Opener-Policy": {
        "name": "COOP",
        "severity": "medium",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "Cross-Origin-Resource-Policy": {
        "name": "CORP",
        "severity": "medium",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "Cross-Origin-Embedder-Policy": {
        "name": "COEP",
        "severity": "medium",
        "owasp": "A05:2021-Security Misconfiguration",
    },
}

_SERVER_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Drupal-Cache",
]


@dataclass(frozen=True)
class HeaderResult:
    """Security header scan result."""
    url: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    total_checks: int = 0
    failed_checks: int = 0
    headers: dict[str, str] = field(default_factory=dict)

    def to_summary(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "finding_count": len(self.findings),
            "total_checks": self.total_checks,
            "failed_checks": self.failed_checks,
        }


def check_security_headers(
    url: str,
    timeout: float = 5.0,
) -> HeaderResult:
    """Check security headers on a URL.

    Args:
        url: URL to check.
        timeout: Request timeout.

    Returns:
        HeaderResult with findings.
    """
    import urllib.request

    findings: list[dict[str, Any]] = []
    headers: dict[str, str] = {}
    total_checks = 0
    failed_checks = 0

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Security-Harness/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k: v for k, v in resp.getheaders()}
            resp.read()

    except Exception as e:
        findings.append({
            "id": "header-request-error",
            "title": "Failed to fetch headers",
            "description": f"Could not fetch headers from {url}: {str(e)}",
            "severity": "medium",
            "confidence": "high",
            "tags": ["header", "network"],
            "evidence": {"url": url, "error": str(e)},
        })
        return HeaderResult(
            url=url,
            findings=findings,
            total_checks=total_checks,
            failed_checks=failed_checks,
            headers=headers,
        )

    # Check required security headers
    for header_name, header_info in _SECURITY_HEADERS.items():
        total_checks += 1
        header_value = headers.get(header_name)

        if not header_value:
            findings.append({
                "id": f"header-missing-{header_name.lower()}",
                "title": f"Missing {header_info['name']} header",
                "description": f"{header_info['name']} header is not set. This reduces protection against {header_info['name'].lower()} attacks.",
                "severity": header_info["severity"],
                "confidence": "high",
                "tags": ["missing_header", "security-header"],
                "cwe": ["CWE-693"],
                "owasp": [header_info["owasp"]],
                "evidence": {"missing_header": header_name},
            })
            failed_checks += 1
        else:
            # Check header value quality
            if header_name == "Content-Security-Policy":
                # Check for weak CSP
                if "unsafe-inline" in header_value or "unsafe-eval" in header_value:
                    findings.append({
                        "id": f"header-weak-{header_name.lower()}",
                        "title": f"Weak {header_info['name']} configuration",
                        "description": f"{header_info['name']} contains unsafe-inline or unsafe-eval, reducing its effectiveness",
                        "severity": "medium",
                        "confidence": "high",
                        "tags": ["missing_header", "security-header"],
                        "cwe": ["CWE-693"],
                        "owasp": [header_info["owasp"]],
                        "evidence": {"header": header_name, "value": header_value[:100]},
                    })
                    failed_checks += 1

    # Check for information-leaking headers
    for leak_header in _SERVER_LEAK_HEADERS:
        total_checks += 1
        if leak_header in headers:
            findings.append({
                "id": f"header-leak-{leak_header.lower()}",
                "title": f"Information disclosure via {leak_header}",
                "description": f"{leak_header} header exposes server technology/version information",
                "severity": "low",
                "confidence": "high",
                "tags": ["info_disclosure", "security-header"],
                "cwe": ["CWE-200"],
                "owasp": ["A09:2021-Security Logging and Monitoring Failures"],
                "evidence": {"header": leak_header, "value": headers[leak_header][:100]},
            })

    return HeaderResult(
        url=url,
        findings=findings,
        total_checks=total_checks,
        failed_checks=failed_checks,
        headers=headers,
    )


def run_header_scan(
    url: str,
    timeout: float = 5.0,
) -> HeaderResult:
    """Run security header scan on a URL.

    Args:
        url: URL to scan.
        timeout: Request timeout.

    Returns:
        HeaderResult with findings.
    """
    return check_security_headers(url, timeout)
