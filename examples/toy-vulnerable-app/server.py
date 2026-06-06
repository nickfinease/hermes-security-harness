#!/usr/bin/env python3
"""Tiny intentionally vulnerable local app for harness false-positive/negative checks.

Run only on localhost for harness development:
  python examples/toy-vulnerable-app/server.py --port 8765
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import argparse
import json


class ToyHandler(BaseHTTPRequestHandler):
    def _headers(self, status=200, content_type="text/html"):
        self.send_response(status)
        # Intentionally omit several security headers on some routes so the
        # http-smoke detector has a stable known-bad signal.
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/api/health":
            self._headers(200, "application/json")
            self.wfile.write(json.dumps({"status": "healthy"}).encode())
            return
        if parsed.path == "/reflect":
            # Known reflected-XSS benchmark: intentionally unescaped.
            value = qs.get("q", [""])[0]
            self._headers(200)
            self.wfile.write(f"<html><body>{value}</body></html>".encode())
            return
        if parsed.path == "/redirect":
            # Known unsafe redirect benchmark.
            target = qs.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return
        if parsed.path == "/api/customer":
            # Known IDOR-ish benchmark: object lookup has no auth/owner check.
            self._headers(200, "application/json")
            self.wfile.write(json.dumps({"id": qs.get("id", ["1"])[0], "ownerChecked": False}).encode())
            return
        self._headers(200)
        self.wfile.write(b"toy vulnerable app")

    def log_message(self, format, *args):  # noqa: A002
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), ToyHandler)
    print(f"toy-vulnerable-app listening on http://127.0.0.1:{server.server_port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
