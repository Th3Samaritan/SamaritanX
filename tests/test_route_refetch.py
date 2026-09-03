"""Tests for the authenticated route-refetch pass in the crawler.

The pass should visit JS/OpenAPI/browser-discovered routes the BFS never
fetched and turn their bodies into real injection surface (JSON points / forms),
instead of leaving param-less mined routes as dead-ended scan tasks.
"""
from __future__ import annotations

import asyncio
import unittest

from agents.crawler_agent import CrawlerAgent, CrawlState


class _Ev:
    def __init__(self, status, body="", ctype="application/json"):
        self.status = status
        self.response_body = body
        self.response_headers = {"content-type": ctype}
        self.error = None


class _HTTP:
    def __init__(self, responses):
        self._r = responses          # url -> _Ev
        self.fetched: list[str] = []

    async def get(self, url, **kw):
        self.fetched.append(url)
        return self._r.get(url, _Ev(404, ""))


class _Dash:
    def event(self, *a, **k): pass
    def add_count(self, *a, **k): pass


class _Ctx:
    def __init__(self, http, crawler_cfg=None):
        self.http = http
        self.dashboard = _Dash()
        self.config = {"crawler": crawler_cfg or {}}


SEED = "https://app.example.com/"


def _agent():
    a = CrawlerAgent()
    a._secret_rules = []             # skip secret scanning in the helper
    return a


def _run(agent, state, http, cfg=None):
    ctx = _Ctx(http, crawler_cfg=cfg)
    asyncio.run(agent._crawl_discovered_routes(SEED, state, ctx))
    return http


class TestRouteRefetch(unittest.TestCase):
    def test_paramless_mined_route_becomes_json_injection_surface(self):
        state = CrawlState()
        # a JS-mined privileged path with NO params — today it's dropped
        url = "https://app.example.com/api/account/settings"
        state.api_tasks.append({"url": url, "method": "GET", "params": [], "source": "js_priv"})
        http = _run(_agent(), state,
                    _HTTP({url: _Ev(200, '{"email":"me@x.com","role":"user"}')}))
        # the route was actually fetched (authenticated) and mined into json points
        self.assertIn(url, http.fetched)
        self.assertIn(url, state.json_points)
        self.assertIn("json:email", state.json_points[url])

    def test_browser_discovered_endpoint_is_fetched(self):
        state = CrawlState()
        url = "https://app.example.com/dashboard/orders"
        state.endpoints.append({"url": url, "status": -1, "ctype": "js-discovered"})
        http = _run(_agent(), state, _HTTP({url: _Ev(200, "{}")}))
        self.assertIn(url, http.fetched)
        # a real status now recorded for it
        self.assertTrue(any(e["url"] == url and e["status"] == 200 for e in state.endpoints))

    def test_offsite_route_is_not_fetched(self):
        state = CrawlState()
        state.api_tasks.append({"url": "https://evil.test/api/x", "method": "GET", "params": []})
        http = _run(_agent(), state, _HTTP({}))
        self.assertEqual(http.fetched, [])

    def test_cap_bounds_the_pass(self):
        state = CrawlState()
        for i in range(10):
            state.api_tasks.append({"url": f"https://app.example.com/r{i}",
                                    "method": "GET", "params": []})
        http = _run(_agent(), state,
                    _HTTP({f"https://app.example.com/r{i}": _Ev(200, "{}") for i in range(10)}),
                    cfg={"max_route_refetch": 3})
        self.assertEqual(len(http.fetched), 3)

    def test_non_get_tasks_are_skipped(self):
        state = CrawlState()
        state.api_tasks.append({"url": "https://app.example.com/api/write",
                                "method": "POST", "params": ["json:x"]})
        http = _run(_agent(), state, _HTTP({}))
        self.assertEqual(http.fetched, [])


if __name__ == "__main__":
    unittest.main()
