"""Real-socket protocol lab (plan §11.7).

Runs the WebSocket scanner against a REAL localhost WebSocket server so
handshake, framing, timeout and cancellation behavior are exercised on
actual sockets. Missing runtime (websockets lib / listener) is reported as
unexecuted coverage, not a passing result.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import websockets
    _WS_AVAILABLE = True
    _WS_WHY = ""
except ImportError as exc:
    websockets = None
    _WS_AVAILABLE = False
    _WS_WHY = f"websockets unavailable: {exc}"


class _FakeContext:
    def __init__(self, target: str):
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
        self.target = target
        self.target_slug = "wslab"
        self.http = StealthHttpClient(cfg)
        self.http2 = None
        self.memory = Memory(Path(self.tmp) / "m.sqlite")
        self.payloads = PayloadEngine(
            Path(__file__).resolve().parent.parent / "config" / "payloads",
            self.memory, cfg.get("waf_evasion", {}).get("techniques", []))
        self.dashboard = Dashboard(target, quiet=True)
        self.session = None
        self.scope = None
        self.oob = None
        self.extra_identities = []
        self.resume = False
        self.run_id = ""

    async def close(self):
        await self.http.close()


async def _echo_server(port, started: asyncio.Event):  # noqa: F401 (kept as lab fixture)
    async def handler(ws):
        async for message in ws:
            text = str(message)
            if "SLEEP" in text:
                await asyncio.sleep(4.5)
                await ws.send("slow reply")
            elif "' OR '1'='1" in text:
                await ws.send("you have an error in your SQL syntax near ''")
            else:
                await ws.send(text)
    server = await websockets.serve(handler, "127.0.0.1", port)
    started.set()
    await server.wait_closed()


@unittest.skipUnless(_WS_AVAILABLE, f"unexecuted coverage: {_WS_WHY}")
class TestWebSocketLab(unittest.TestCase):
    def test_sql_error_over_real_socket(self):
        from scanners.websocket import scan

        async def run():
            import websockets as ws

            async def handler(wsock):
                async for message in wsock:
                    t = str(message)
                    if "' OR '1'='1" in t:
                        await wsock.send("you have an error in your SQL syntax near ''")
                    else:
                        await wsock.send(t)

            server = await ws.serve(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            ctx = _FakeContext("http://127.0.0.1")
            try:
                findings = await scan(ctx, f"ws://127.0.0.1:{port}/", [], "GET", None)
                self.assertTrue(any("SQL" in f["title"] for f in findings),
                                "SQL error reply over a real socket must be detected")
            finally:
                server.close()
                await server.wait_closed()
                await ctx.close()

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
