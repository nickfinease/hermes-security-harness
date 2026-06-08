"""Shared test helpers for HTTP server tests."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def write_target_config(path: Path, base_url: str, include_paths: list[str]) -> None:
    rendered_paths = "\n".join(f"    - {item}" for item in include_paths)
    path.write_text(
        f"""
schemaVersion: web-target/v1
id: smoke-demo
name: Smoke Demo
environment: local
baseUrl: {base_url}
allowedHosts:
  - 127.0.0.1
  - localhost
scope:
  includePaths:
{rendered_paths}
  maxRequests: 5
  maxRuntimeSeconds: 30
detectors:
  enabled:
    - reachability-smoke
    - security-headers-smoke
safety:
  requireLocalOrStaging: true
  requireAllowedHostMatch: true
  blockCloudMetadataIps: true
""".lstrip()
    )


class SmokeHandler(BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, dict[str, str], bytes]] = {}

    def do_GET(self):
        self.server.seen_paths.append(self.path)  # type: ignore[attr-defined]
        status, extra_headers, body = self.routes.get(self.path, (404, {}, b"not found"))
        self.send_response(status)
        if getattr(self, "include_security_headers", True):
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
        for key, value in extra_headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def start_server(routes: dict[str, tuple[int, dict[str, str], bytes]], *, include_security_headers: bool = True):
    class Handler(SmokeHandler):
        pass

    Handler.routes = routes
    Handler.include_security_headers = include_security_headers
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
