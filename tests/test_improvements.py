"""Unit tests for persistence, monitor-diff, LLM fallback, and H1 drafts."""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestSessionPersistence(unittest.TestCase):
    def test_roundtrip(self):
        from core.auth import SessionStore, save_session, load_persisted_session
        s = SessionStore()
        s.cookies = {"session": "abc123"}
        s.headers = {"X-Tenant": "acme"}
        s.same_site = "lax"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "session.json"
            self.assertTrue(save_session(s, p))
            s2 = load_persisted_session(p)
            self.assertIsNotNone(s2)
            self.assertEqual(s2.cookies, {"session": "abc123"})
            self.assertEqual(s2.headers, {"X-Tenant": "acme"})
            self.assertEqual(s2.same_site, "lax")
            self.assertTrue(s2.is_authed())

    def test_missing_file(self):
        from core.auth import load_persisted_session
        self.assertIsNone(load_persisted_session("/nonexistent/session.json"))


class TestMonitorDiff(unittest.TestCase):
    def test_findings_diff(self):
        from core.monitor import diff, _has_changes
        old = {"hosts": ["a.com"], "endpoints": ["https://a.com/"],
               "params": [], "finding_keys": ["fp1"], "findings": {"high": 1}}
        new = {"hosts": ["a.com", "b.com"], "endpoints": ["https://a.com/"],
               "params": [], "finding_keys": ["fp1", "fp2"], "findings": {"high": 1, "critical": 1}}
        delta = diff(old, new)
        self.assertEqual(delta["hosts"]["added"], ["b.com"])
        self.assertEqual(delta["findings"]["added"], ["fp2"])
        self.assertEqual(delta["findings"]["counts"]["new"]["critical"], 1)
        self.assertTrue(_has_changes(delta))

    def test_no_changes(self):
        from core.monitor import diff, _has_changes
        s = {"hosts": [], "endpoints": [], "params": [], "finding_keys": []}
        self.assertFalse(_has_changes(diff(s, dict(s))))


class TestLLM(unittest.TestCase):
    def test_fallback_without_key(self):
        from core.llm import available, _fallback_triage, triage_impact

        async def run():
            out = await triage_impact({"category": "sqli", "severity": "high",
                                       "title": "x", "url": "u", "evidence": "e"}, {})
            self.assertIn("impact", out)
            self.assertEqual(out["recommended_severity"], "high")
        self.assertFalse(available({}))
        self.assertIn("database", _fallback_triage({"category": "sqli"})["impact"])
        asyncio.run(run())

    def test_env_expansion(self):
        import os
        from core.llm import _api_key
        os.environ["SX_TEST_LLM_KEY"] = "secret123"
        try:
            self.assertEqual(_api_key({"llm": {"api_key": "{ENV:SX_TEST_LLM_KEY}"}}),
                             "secret123")
            self.assertIsNone(_api_key({}))
        finally:
            del os.environ["SX_TEST_LLM_KEY"]

    def test_provider_resolution(self):
        import os
        from core.llm import _api_key, _base_url, _model
        os.environ["DEEPSEEK_API_KEY"] = "sk-deep"
        os.environ["LLM_API_KEY"] = "sk-generic"
        try:
            self.assertEqual(_api_key({"llm": {"provider": "deepseek"}}), "sk-deep")
            self.assertEqual(_base_url({"llm": {"provider": "deepseek"}}, "deepseek"),
                             "https://api.deepseek.com/v1")
            self.assertEqual(_base_url({"llm": {"provider": "openai_compatible",
                                                "base_url": "https://api.groq.com/openai/v1"}},
                                       "openai_compatible"),
                             "https://api.groq.com/openai/v1")
            self.assertEqual(_api_key({"llm": {"provider": "openai_compatible"}}), "sk-generic")
            self.assertEqual(_model({"llm": {"provider": "deepseek"}}), "deepseek-chat")
        finally:
            del os.environ["DEEPSEEK_API_KEY"]
            del os.environ["LLM_API_KEY"]


class TestHackerOneDrafts(unittest.TestCase):
    def test_severity_rating(self):
        from core.hackerone_client import _severity_rating
        self.assertEqual(_severity_rating("critical"), "critical")
        self.assertEqual(_severity_rating("info"), "none")
        self.assertEqual(_severity_rating(None), "medium")

    def test_vuln_information_shape(self):
        from core.hackerone_client import _vuln_information, _fingerprint

        class FakeCtx:
            config = {"operator": {"handle": "op"}}

        f = {"category": "sqli", "title": "SQLi", "url": "https://a.com/?id=1",
             "parameter": "id", "evidence": "sql error",
             "request": "GET https://a.com/?id=1'",
             "metadata": {"poc": {"request": "GET https://a.com/?id=1'",
                                  "response_excerpt": "SQL syntax error"}}}
        info = _vuln_information(FakeCtx(), f, "op")
        self.assertIn("## Summary", info)
        self.assertIn("sql error", info)
        self.assertIn("curl", info)
        self.assertEqual(len(_fingerprint(f)), 40)

    def test_disabled_returns_skipped(self):
        from core.hackerone_client import submit_drafts

        class FakeCtx:
            class Dashboard:
                def event(self, *a, **k):
                    pass
            config = {"hackerone": {"enabled": False}, "operator": {"handle": "op"}}
            dashboard = Dashboard()
            workspace = Path(tempfile.mkdtemp())

        async def run():
            out = await submit_drafts(FakeCtx(), [{"category": "sqli", "title": "x"}])
            self.assertEqual(out["submitted"], 0)
        asyncio.run(run())


class TestProxyRotation(unittest.TestCase):
    def test_pool_builds(self):
        from core.http_client import StealthHttpClient

        async def run():
            c = StealthHttpClient({"proxy": {"enabled": True,
                                             "rotation": ["http://a:1", "http://b:2"]}})
            try:
                self.assertGreaterEqual(len(c._clients), 2)
            finally:
                await c.close()
            c2 = StealthHttpClient({})
            try:
                self.assertEqual(len(c2._clients), 1)
            finally:
                await c2.close()
        asyncio.run(run())


class TestPortScanServices(unittest.TestCase):
    """Port-scan service classification against a live socket."""

    @staticmethod
    def _redis_socket_server(replies: list[bytes]):
        import socket as _s
        srv = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def _serve():
            for _ in range(5):
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                try:
                    conn.recv(256)
                    for r in replies:
                        conn.sendall(r)
                except OSError:
                    pass
                finally:
                    conn.close()

        import threading
        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        return srv, port, t

    def test_redis_pong_classified_critical(self):
        from agents.recon_agent import ReconAgent

        class FakeCtx:
            def __init__(self):
                import tempfile
                from core.memory import Memory
                from core.dashboard import Dashboard
                self.tmp = tempfile.mkdtemp()
                self.memory = Memory(Path(self.tmp) / "m.sqlite")
                self.dashboard = Dashboard("x", quiet=True)
                self.target_slug = "t"
                self.workspace = Path(self.tmp)
                self.config = {}
                self.target = "127.0.0.1"

        srv, port, _thread = self._redis_socket_server([b"+PONG\r\n"])
        try:
            ctx = FakeCtx()
            agent = ReconAgent()
            agent._PORTS = [(port, "redis")]

            async def run():
                await agent._port_scan("127.0.0.1", ctx)
                rows = ctx.memory.list_findings("t")
                return rows
            rows = asyncio.run(run())
            self.assertTrue(any("Redis exposed" in r["title"] and
                                r["severity"] == "critical" for r in rows))
        finally:
            srv.close()

    def test_closed_port_yields_nothing(self):
        from agents.recon_agent import ReconAgent
        import socket
        # grab a port that is closed
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        class FakeCtx:
            def __init__(self):
                import tempfile
                from core.memory import Memory
                from core.dashboard import Dashboard
                self.tmp = tempfile.mkdtemp()
                self.memory = Memory(Path(self.tmp) / "m.sqlite")
                self.dashboard = Dashboard("x", quiet=True)
                self.target_slug = "t"
                self.workspace = Path(self.tmp)
                self.config = {}
                self.target = "127.0.0.1"

        ctx = FakeCtx()
        agent = ReconAgent()
        agent._PORTS = [(port, "test")]

        async def run():
            await agent._port_scan("127.0.0.1", ctx)
            return ctx.memory.list_findings("t")
        rows = asyncio.run(run())
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
