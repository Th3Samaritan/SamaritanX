"""Real-browser integration lab (plan §11.7).

Runs the actual DOM-XSS and stored-XSS scanners against local pages with a
REAL chromium — a browser distinguishes execution from encoded text in ways
replay fixtures cannot. Missing runtimes are reported as unexecuted coverage
(skipped with a reason), never as a passing result.
"""
from __future__ import annotations

import asyncio
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

STORED: list[str] = []


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, body: bytes, ctype: str = "text/html"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/dom-exec":
            # query param src lands in innerHTML — executable sink
            src = unquote_plus(parse_qs(query).get("src", [""])[0])
            page = ("<html><body><script>"
                    "const v = new URLSearchParams(location.search).get('src');"
                    "if (v) document.body.innerHTML = v;"
                    "</script></body></html>")
            self._send(page.encode())
        elif path == "/dom-safe":
            # same value, but textContent — encoded, must NOT fire
            page = ("<html><body><script>"
                    "const v = new URLSearchParams(location.search).get('src');"
                    "if (v) document.body.textContent = v;"
                    "</script></body></html>")
            self._send(page.encode())
        elif path == "/pm-vuln":
            page = ("<html><body><script>"
                    "window.addEventListener('message', e => {"
                    "  if (e.data && e.data.html) document.body.innerHTML = e.data.html; });"
                    "</script></body></html>")
            self._send(page.encode())
        elif path == "/pm-safe":
            page = ("<html><body><script>"
                    "window.addEventListener('message', e => { /* ignores content */ });"
                    "</script></body></html>")
            self._send(page.encode())
        elif path == "/store":
            page = ('<html><body><form action="/store" method="POST">'
                    '<input type="text" name="message" value="x"/>'
                    '<input type="submit" value="Go"/></form>'
                    f"board: {' '.join(STORED)}</body></html>")
            self._send(page.encode())
        elif path == "/":
            body = ("<html><body>home " + " ".join(STORED) +
                    ' <a href="/dom-exec">dom-exec</a> <a href="/dom-safe">dom-safe</a>'
                    ' <a href="/pm-vuln">pm-vuln</a> <a href="/store">store</a></body></html>')
            self._send(body.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path, _, _ = self.path.partition("?")
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if path == "/store":
            body = raw.decode(errors="replace")
            msg = unquote_plus(body.split("message=", 1)[1]) if "message=" in body else ""
            if msg:
                STORED.append(msg)
            self._send(b"saved")


def _browser_available() -> tuple[bool, str]:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            path = pw.chromium.executable_path
        if not path or not Path(path).exists():
            return False, "chromium executable not installed"
        return True, path
    except Exception as exc:
        return False, f"playwright unavailable: {exc}"


_AVAILABLE, _AVAILABLE_WHY = _browser_available()


class _FakeContext:
    def __init__(self, base: str):
        import tempfile
        import yaml
        from core.dashboard import Dashboard
        from core.http_client import StealthHttpClient
        from core.memory import Memory
        from core.payload_engine import PayloadEngine
        self.tmp = tempfile.mkdtemp()
        cfg = yaml.safe_load(
            (Path(__file__).resolve().parent.parent / "config" / "config.yaml")
            .read_text(encoding="utf-8"))
        cfg["stealth"]["rate_limit_rps"] = 50
        cfg["stealth"]["per_host_rps"] = 50
        cfg["stealth"]["jitter_ms"] = [0, 0]
        self.config = cfg
        self.target = base
        self.target_slug = "browserlab"
        self.http = StealthHttpClient(cfg)
        self.http2 = None
        self.memory = Memory(Path(self.tmp) / "m.sqlite")
        self.payloads = PayloadEngine(
            Path(__file__).resolve().parent.parent / "config" / "payloads",
            self.memory, cfg.get("waf_evasion", {}).get("techniques", []))
        self.dashboard = Dashboard(base, quiet=True)
        self.session = None
        self.scope = None
        self.oob = None
        self.extra_identities = []
        self.resume = False
        self.run_id = ""

    async def close(self):
        await self.http.close()


@unittest.skipUnless(_AVAILABLE, f"unexecuted coverage: {_AVAILABLE_WHY}")
class TestBrowserLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    async def _scan(self, scanner, path, params, form=None, method="GET"):
        ctx = _FakeContext(self.base)
        try:
            return await scanner(ctx, self.base + path, params, method, form)
        finally:
            await ctx.close()

    def test_dom_xss_real_browser_executes(self):
        from scanners.dom_xss import scan
        findings = asyncio.run(self._scan(scan, "/dom-exec", ["src"]))
        self.assertTrue(any(f["category"] == "xss" for f in findings),
                        "real browser must detect the innerHTML sink")

    def test_dom_xss_encoded_page_does_not_fire(self):
        from scanners.dom_xss import scan
        findings = asyncio.run(self._scan(scan, "/dom-safe", ["src"]))
        self.assertFalse(any(f["category"] == "xss" for f in findings),
                         "textContent (encoded) must NOT be reported as execution")

    def test_postmessage_vuln_detected(self):
        from scanners.dom_xss import scan
        findings = asyncio.run(self._scan(scan, "/pm-vuln", []))
        self.assertTrue(any(f["category"] == "xss" and "postMessage" in f["title"]
                            for f in findings))

    def test_postmessage_safe_not_flagged(self):
        from scanners.dom_xss import scan
        findings = asyncio.run(self._scan(scan, "/pm-safe", []))
        self.assertFalse(any(f["category"] == "xss" and "postMessage" in f["title"]
                             for f in findings))

    def test_stored_xss_full_flow_with_browser(self):
        from scanners.stored_xss import scan
        STORED.clear()
        form = {"action": self.base + "/store", "method": "POST",
                "inputs": [{"name": "message", "type": "text", "value": ""}]}
        findings = asyncio.run(self._scan(scan, "/store", ["message"], form, "POST"))
        # with a real browser the persisted payload must EXECUTE on the board
        self.assertTrue(any(f["category"] == "xss" and
                            f.get("severity") == "critical" and
                            "executes" in f["title"]
                            for f in findings))


if __name__ == "__main__":
    unittest.main()
