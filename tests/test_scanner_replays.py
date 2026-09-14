"""Paired observations exercise real scanners; these are not browser integration tests."""
import re
import unittest
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import unquote

from core.http_client import HttpEvidence


def context():
    evidence = HttpEvidence("GET", "http://fixture.test/", {}, None, 200, {}, "plain page", 0)
    return SimpleNamespace(config={}, session=None, oob=None, http=SimpleNamespace(get=AsyncMock(return_value=evidence)))


class PairedReplays(unittest.IsolatedAsyncioTestCase):
    async def test_csrf_form_observations(self):
        from scanners.csrf import scan
        for vulnerable in (True, False):
            for repeat in range(2):
                with self.subTest(vulnerable=vulnerable, repeat=repeat):
                    form = {"method": "POST", "action": "/save", "inputs":
                            [{"name": "name" if vulnerable else "csrf_token", "value": "fixture"}]}
                    found = await scan(context(), "http://fixture.test/", [], "POST", form)
                    self.assertEqual(bool(found), vulnerable)

    async def test_serialization_format_observations(self):
        from scanners.deserialization import scan
        for vulnerable in (True, False):
            for repeat in range(2):
                with self.subTest(vulnerable=vulnerable, repeat=repeat):
                    form = {"inputs": [{"name": "state", "value":
                            "!!python/object:Fixture {}" if vulnerable else "ordinary text"}]}
                    found = await scan(context(), "http://fixture.test/", [], "GET", form)
                    self.assertEqual(bool(found), vulnerable)

    async def test_dom_sink_observations(self):
        from scanners.dom_xss import scan

        for vulnerable in (True, False):
            for repeat in range(2):
                class Page:
                    source = ""
                    add_init_script = AsyncMock()
                    close = AsyncMock()

                    async def goto(self, url, **kwargs):
                        self.source = unquote(url)

                    async def evaluate(self, script):
                        if "window.postMessage" in script:
                            self.source = script
                            return None
                        tokens = re.findall(r"sx(?:dom|hash|pp|pm)[a-z0-9]+", self.source)
                        return [{"k": "alert", "v": token} for token in tokens] if vulnerable else []

                browser_context = SimpleNamespace(new_page=AsyncMock(side_effect=Page))
                browser = SimpleNamespace(new_context=AsyncMock(return_value=browser_context), close=AsyncMock())
                playwright = SimpleNamespace(chromium=SimpleNamespace(launch=AsyncMock(return_value=browser)))

                @asynccontextmanager
                async def runtime():
                    yield playwright

                with self.subTest(vulnerable=vulnerable, repeat=repeat), \
                     patch("playwright.async_api.async_playwright", runtime), \
                     patch("scanners.dom_xss.asyncio.sleep", new=AsyncMock()):
                    found = await scan(context(), "http://fixture.test/", ["q"])
                    self.assertEqual(bool(found), vulnerable)
                    browser.close.assert_awaited_once()

    async def test_websocket_message_transcripts(self):
        from scanners.websocket import scan
        for vulnerable in (True, False):
            for repeat in range(2):
                class Socket:
                    message = ""

                    async def send(self, message):
                        self.message = message

                    async def recv(self):
                        return "SQL syntax error" if vulnerable and "OR" in self.message else "pong"

                @asynccontextmanager
                async def connect(*args, **kwargs):
                    yield Socket()

                ctx = context()
                ctx.http.get.return_value.status = 101
                ctx.http.get.return_value.response_headers = {"sec-websocket-accept": "fixture"}
                with self.subTest(vulnerable=vulnerable, repeat=repeat), patch("core.transport.websocket_connect", connect):
                    found = await scan(ctx, "http://fixture.test/socket", [])
                    self.assertEqual(any("SQL injection over WebSocket" in f["title"] for f in found), vulnerable)
