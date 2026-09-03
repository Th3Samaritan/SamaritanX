"""Mock-server regression tests — lock in scanner accuracy guarantees.

Spins up a small in-process HTTP server with deliberately vulnerable and
deliberately NOT-vulnerable endpoints, then runs the real scanners against it
through a lightweight fake Context. These tests fail if a scanner starts
false-firing (e.g. flagging HTML-encoded reflections) or stops detecting the
endpoint class it exists for.
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote_plus

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from core.dashboard import Dashboard
from core.http_client import StealthHttpClient
from core.memory import Memory
from core.payload_engine import PayloadEngine
from core.utils import slugify


class _LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    last_xfh: str = ""

    def _send(self, code, body, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def do_GET(self):
        path, _, query = self.path.partition("?")
        params = {unquote_plus(k): unquote_plus(v)
                  for k, v in (kv.split("=", 1) for kv in query.split("&") if "=" in kv)}
        if path == "/sqli":
            q = params.get("q", "")
            if "'" in q:
                self._send(200, f"you have an error in your SQL syntax near '{q}'".encode())
            else:
                self._send(200, b"ok")
        elif path == "/xss":
            self._send(200, f"<html><body>{params.get('q', '')}</body></html>".encode())
        elif path == "/xss-encoded":
            import html
            self._send(200, f"<html><body>{html.escape(params.get('q', ''))}</body></html>".encode())
        elif path == "/lfi":
            f = params.get("file", "")
            if "/etc/passwd" in f or "../" in f:
                self._send(200, b"root:x:0:0:root:/root:/bin/bash\n", "text/plain")
            else:
                self._send(200, b"no file")
        elif path == "/redirect":
            self._send(302, b"", extra={"Location": params.get("url", "/")})
        elif path == "/host":
            self._send(200, f'<a href="http://{self.headers.get("Host", "")}/x">x</a>'.encode())
        elif path == "/static49":
            self._send(200, b"version 49 docs mention Werkzeug and java.lang elsewhere")
        elif path == "/api/items":
            self._send(200, json.dumps({"items": [1, 2]}).encode(), "application/json")
        elif path == "/cors":
            origin = self.headers.get("Origin", "")
            extra = {}
            if origin:
                extra = {"Access-Control-Allow-Origin": origin,
                         "Access-Control-Allow-Credentials": "true"}
            self._send(200, b'{"secret": true}', "application/json", extra)
        elif path == "/fetch":
            target = params.get("url", "")
            if "169.254.169.254" in target:
                self._send(200, b"ami-id\niam/security-credentials\ncomputeMetadata",
                           "text/plain")
            else:
                self._send(200, b"nothing")
        elif path == "/echo-param":
            # echoes the injected URL verbatim — a reflection trap that must
            # NEVER be reported as in-band SSRF
            self._send(200, f"you asked for: {params.get('url', '')}".encode())
        elif path == "/cache":
            # remembers the last X-Forwarded-Host and reflects it on later
            # (clean) requests — simulates an unkeyed-header cache
            xfh = self.headers.get("X-Forwarded-Host", "")
            if xfh:
                _LabHandler.last_xfh = xfh
            self._send(200, f"cached page {_LabHandler.last_xfh}".encode())
        elif path == "/admin":
            self._send(403, b"forbidden")
        elif path == "/admin/":
            body = ("<html><body><h1>Admin console</h1>"
                    "<p>Users: 42, roles: admin, billing: active.</p>"
                    "<p>Internal API key: sk-admin-1234567890abcdef</p></body></html>")
            self._send(200, body.encode())
        elif path == "/hpp":
            vals = [unquote_plus(v) for kv in query.split("&")
                    for v in [kv.split("=", 1)[1]] if "=" in kv and kv.split("=", 1)[0] == "p"]
            if len(vals) > 1:
                self._send(200, b"error: duplicate parameter")
            else:
                self._send(200, f"ok: {vals[0] if vals else ''}".encode())
        elif path == "/page":
            self._send(200, b"<html><body>plain page</body></html>")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        path, _, _ = self.path.partition("?")
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if path == "/nosql/login":
            try:
                data = json.loads(raw.decode() or "{}")
            except Exception:
                data = {}
            if isinstance(data.get("username"), dict):
                self._send(200, json.dumps({"success": True, "token": "abc"}).encode(),
                           "application/json")
            else:
                self._send(200, json.dumps({"success": False}).encode(), "application/json")
        else:
            self._send(404, b"")


class _FakeContext:
    """Minimal stand-in for core.orchestrator.Context — only what scanners touch."""

    def __init__(self, base_url: str) -> None:
        self.tmp = tempfile.mkdtemp()
        cfg = yaml.safe_load(
            (Path(__file__).resolve().parent.parent / "config" / "config.yaml")
            .read_text(encoding="utf-8"))
        cfg["stealth"]["rate_limit_rps"] = 50
        cfg["stealth"]["per_host_rps"] = 50
        cfg["stealth"]["jitter_ms"] = [0, 0]
        self.config = cfg
        self.target = base_url
        self.target_slug = slugify(base_url)
        self.http = StealthHttpClient(cfg)
        self.http2 = None
        self.memory = Memory(Path(self.tmp) / "m.sqlite")
        self.payloads = PayloadEngine(
            Path(__file__).resolve().parent.parent / "config" / "payloads",
            self.memory, cfg.get("waf_evasion", {}).get("techniques", []))
        self.dashboard = Dashboard(base_url, quiet=True)
        self.session = None
        self.scope = None
        self.oob = None
        self.extra_identities = []
        self.resume = False

    async def close(self) -> None:
        await self.http.close()


class TestScannerAccuracy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _run(self, coro):
        return asyncio.run(coro)

    async def _scan(self, scanner, path, params):
        ctx = _FakeContext(self.base)
        try:
            return await scanner(ctx, self.base + path, params, "GET", None)
        finally:
            await ctx.close()

    def test_sqli_error_detected(self):
        from scanners.sqli import scan
        findings = self._run(self._scan(scan, "/sqli", ["q"]))
        self.assertTrue(any(f["category"] == "sqli" for f in findings))

    def test_xss_detected_unencoded_only(self):
        from scanners.xss import scan
        found = self._run(self._scan(scan, "/xss", ["q"]))
        self.assertTrue(any(f["category"] == "xss" for f in found))
        not_found = self._run(self._scan(scan, "/xss-encoded", ["q"]))
        self.assertEqual(not_found, [])

    def test_lfi_detected(self):
        from scanners.lfi import scan
        findings = self._run(self._scan(scan, "/lfi", ["file"]))
        self.assertTrue(any(f["category"] == "lfi" for f in findings))

    def test_open_redirect_detected(self):
        from scanners.open_redirect import scan
        findings = self._run(self._scan(scan, "/redirect", ["url"]))
        self.assertTrue(any(f["category"] == "open_redirect" for f in findings))

    def test_host_header_detected(self):
        from scanners.host_header import scan
        findings = self._run(self._scan(scan, "/host", []))
        self.assertTrue(any(f["category"] == "host_header" for f in findings))

    def test_nosql_auth_bypass_detected(self):
        from scanners.nosqli import scan
        findings = self._run(self._scan(scan, "/nosql/login", []))
        self.assertTrue(any(f["category"] == "nosqli" for f in findings))

    def test_ssti_static_page_not_flagged(self):
        from scanners.rce import scan
        findings = self._run(self._scan(scan, "/static49", ["q"]))
        self.assertFalse(any(f["category"] == "ssti" for f in findings))

    def test_cors_reflection_detected(self):
        from scanners.cors import scan
        findings = self._run(self._scan(scan, "/cors", []))
        self.assertTrue(any(f["category"] == "cors" for f in findings))

    def test_ssrf_inband_metadata_detected(self):
        from scanners.ssrf import scan
        findings = self._run(self._scan(scan, "/fetch", ["url"]))
        self.assertTrue(any(f["category"] == "ssrf" for f in findings))

    def test_ssrf_echo_not_flagged(self):
        from scanners.ssrf import scan
        findings = self._run(self._scan(scan, "/echo-param", ["url"]))
        self.assertFalse(any(f["category"] == "ssrf" for f in findings))

    def test_cache_poisoning_header_detected(self):
        from scanners.cache_poisoning import scan
        _LabHandler.last_xfh = ""
        findings = self._run(self._scan(scan, "/cache", []))
        self.assertTrue(any(f["category"] == "cache_poisoning" for f in findings))

    def test_path_normalization_bypass_detected(self):
        from scanners.path_normalization import scan
        findings = self._run(self._scan(scan, "/admin", []))
        self.assertTrue(any(f["category"] == "broken_auth" for f in findings))

    def test_hpp_duplicate_parsing_detected(self):
        from scanners.hpp import scan
        findings = self._run(self._scan(scan, "/hpp", ["p"]))
        self.assertTrue(any(f["category"] == "hpp" for f in findings))

    def test_security_headers_missing_detected(self):
        from scanners.security_headers import scan
        findings = self._run(self._scan(scan, "/page", []))
        cats = {f["category"] for f in findings}
        self.assertIn("security_headers", cats)
        titles = " ".join(f["title"] for f in findings)
        self.assertIn("Strict Transport Security", titles)
        self.assertIn("Content Security Policy", titles)


if __name__ == "__main__":
    unittest.main()
