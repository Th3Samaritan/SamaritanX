"""Tests for PoC generation, exploitation oracle, and revalidation wiring."""
from __future__ import annotations

import asyncio
import unittest

from core.poc import build_curl, build_repro, is_auth_wall, is_static_asset
from core.exploitation import is_true_by_length
from core.revalidate import REVALIDATORS, _SKIP_REASON, _re_broken_auth


class TestPoC(unittest.TestCase):
    def test_query_get_curl(self):
        f = {"url": "https://x.test/search", "parameter": "q",
             "payload": "' OR 1=1-- -", "request": "GET https://x.test/search"}
        c = build_curl(f)
        self.assertTrue(c.startswith("curl"))
        self.assertIn("q=", c)

    def test_json_body_curl(self):
        f = {"url": "https://x.test/api/user", "parameter": "json:role",
             "payload": "admin", "request": "POST https://x.test/api/user"}
        c = build_curl(f)
        self.assertIn("--data", c)
        self.assertIn("application/json", c)
        self.assertIn("-X POST", c)

    def test_header_curl(self):
        f = {"url": "https://x.test/", "parameter": "header:X-Forwarded-For",
             "payload": "127.0.0.1", "request": "GET https://x.test/"}
        c = build_curl(f)
        self.assertIn("X-Forwarded-For: 127.0.0.1", c)

    def test_cors_repro_is_html(self):
        f = {"category": "cors", "url": "https://x.test/api/me"}
        r = build_repro(f)
        self.assertIn("credentials:'include'", r)
        self.assertIn("fetch(", r)

    def test_smuggling_poc_is_not_a_misleading_curl(self):
        # a plain curl proves nothing for a timing-oracle smuggle
        f = {"category": "smuggling", "request": "POST /api HTTP/1.1 ...",
             "url": "https://x.test/api", "metadata": {"kind": "CL.TE", "elapsed_s": 8.1}}
        c = build_curl(f)
        self.assertNotIn("curl ", c)          # no bogus curl command
        self.assertIn("raw socket", c.lower())
        self.assertIn("CL.TE", c)


class TestAuthWall(unittest.TestCase):
    """The false-positive killer: a login view served with 200 is not access."""

    def test_login_title_is_wall(self):
        wall, why = is_auth_wall(200, {"content-type": "text/html"},
                                 "<html><head><title>Acme - Login</title></head><body>x</body></html>")
        self.assertTrue(wall)
        self.assertIn("login", why.lower())

    def test_redirect_to_login_is_wall(self):
        self.assertTrue(is_auth_wall(302, {"location": "https://x/login"}, "")[0])

    def test_401_403_are_walls(self):
        self.assertTrue(is_auth_wall(401, {}, "")[0])
        self.assertTrue(is_auth_wall(403, {}, "")[0])

    def test_password_form_is_wall(self):
        body = '<form>Please sign in <input type="password" name="password"></form>'
        self.assertTrue(is_auth_wall(200, {}, body)[0])

    def test_real_privileged_page_is_not_wall(self):
        body = "<html><h1>Admin Dashboard</h1><table>secret records</table></html>" + "x" * 300
        self.assertFalse(is_auth_wall(200, {}, body)[0])

    def test_static_asset_detected(self):
        self.assertTrue(is_static_asset("https://x/assets/app.js", {}))
        self.assertTrue(is_static_asset("https://x/x", {"content-type": "text/css"}))
        self.assertFalse(is_static_asset("https://x/dashboard", {"content-type": "text/html"}))


class _FakeEvidence:
    def __init__(self, status, headers, body):
        self.status, self.response_headers, self.response_body = status, headers, body


class _FakeHTTP:
    def __init__(self, ev):
        self._ev = ev

    async def get(self, url, **kw):
        return self._ev


class _FakeCtx:
    def __init__(self, ev):
        self.http = _FakeHTTP(ev)


class TestBrokenAuthRevalidator(unittest.TestCase):
    def test_login_page_is_dropped(self):
        ev = _FakeEvidence(200, {"content-type": "text/html"},
                           "<html><head><title>Arewagate - Login</title></head><body>"
                           + "x" * 400 + "</body></html>")
        f = {"category": "broken_auth", "url": "https://x.test/dashboard/admin",
             "metadata": {}}
        result = asyncio.run(_re_broken_auth(_FakeCtx(ev), f))
        self.assertFalse(result)  # dropped as false positive
        self.assertIn("auth wall", f["metadata"]["revalidation_proof"])

    def test_real_unauth_access_is_proven(self):
        body = ("<html><h1>Admin</h1> owner: admin@corp.example "
                "id 550e8400-e29b-41d4-a716-446655440000 " + "data " * 80 + "</html>")
        ev = _FakeEvidence(200, {"content-type": "text/html"}, body)
        f = {"category": "broken_auth", "url": "https://x.test/dashboard/admin",
             "metadata": {}}
        result = asyncio.run(_re_broken_auth(_FakeCtx(ev), f))
        self.assertTrue(result)
        poc = f["metadata"]["poc"]
        self.assertTrue(poc["verified"])
        self.assertIn("no Cookie", poc["request"])

    def test_static_asset_is_dropped(self):
        ev = _FakeEvidence(200, {"content-type": "application/javascript"}, "var x=1;" * 100)
        f = {"category": "broken_auth", "url": "https://x.test/assets/dashboard.js",
             "metadata": {}}
        self.assertFalse(asyncio.run(_re_broken_auth(_FakeCtx(ev), f)))

    def test_bfla_cross_identity_is_skipped(self):
        ev = _FakeEvidence(200, {}, "x" * 400)
        f = {"category": "broken_auth", "url": "https://x.test/admin",
             "metadata": {"detection": "authz_matrix", "identity": "viewer"}}
        self.assertIsNone(asyncio.run(_re_broken_auth(_FakeCtx(ev), f)))


class _RecordingMemory:
    def __init__(self):
        self.recorded = []

    def record_finding(self, finding):
        self.recorded.append(finding)
        return len(self.recorded)


class _CountingDash:
    def add_count(self, *a, **k):
        pass

    def event(self, *a, **k):
        pass


class _AgentCtx:
    def __init__(self, ev):
        self.http = _FakeHTTP(ev)
        self.memory = _RecordingMemory()
        self.dashboard = _CountingDash()
        self.session = None
        self.target_slug = "x.test"


class TestAdminAnonPrecision(unittest.TestCase):
    """The detector itself must not emit the login-page / asset false positives."""

    def _run(self, ev, url="https://x.test/dashboard/admin"):
        from agents.logic_agent import LogicAgent
        ctx = _AgentCtx(ev)
        asyncio.run(LogicAgent()._admin_anon([url], ctx))
        return ctx.memory.recorded

    def test_login_page_not_reported(self):
        ev = _FakeEvidence(200, {"content-type": "text/html"},
                           "<html><head><title>Acme - Login</title></head><body>"
                           + "x" * 400 + "</body></html>")
        self.assertEqual(self._run(ev), [])

    def test_static_asset_not_reported(self):
        ev = _FakeEvidence(200, {"content-type": "application/javascript"}, "var x=1;" * 100)
        self.assertEqual(self._run(ev, "https://x.test/admin/app.js"), [])

    def test_no_markers_not_reported(self):
        ev = _FakeEvidence(200, {"content-type": "text/html"},
                           "<html><h1>Welcome</h1>" + "generic marketing copy " * 30 + "</html>")
        self.assertEqual(self._run(ev), [])

    def test_genuine_privileged_page_is_reported(self):
        body = ("<html><h1>Admin</h1> owner admin@corp.example "
                "id 550e8400-e29b-41d4-a716-446655440000 " + "data " * 80 + "</html>")
        ev = _FakeEvidence(200, {"content-type": "text/html"}, body)
        recorded = self._run(ev)
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["category"], "broken_auth")


class TestExploitationOracle(unittest.TestCase):
    def test_closer_to_true(self):
        self.assertTrue(is_true_by_length(1000, true_len=1000, false_len=400))
        self.assertFalse(is_true_by_length(420, true_len=1000, false_len=400))

    def test_tie_breaks_true(self):
        # equidistant → treated as true (>= in impl)
        self.assertTrue(is_true_by_length(700, true_len=1000, false_len=400))


class TestRevalidatorTable(unittest.TestCase):
    def test_core_categories_have_revalidators(self):
        for cat in ("sqli", "xss", "rce", "ssti", "cors", "open_redirect", "ssrf", "nosqli", "crlf"):
            self.assertIn(cat, REVALIDATORS)

    def test_hardproof_categories_skipped(self):
        for cat in ("chain", "secret_exposure", "takeover", "nuclei"):
            self.assertIn(cat, _SKIP_REASON)
            self.assertNotIn(cat, REVALIDATORS)


if __name__ == "__main__":
    unittest.main()
