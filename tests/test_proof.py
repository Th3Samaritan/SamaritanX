"""Tests for PoC generation, exploitation oracle, and revalidation wiring."""
from __future__ import annotations

import unittest

from core.poc import build_curl, build_repro
from core.exploitation import is_true_by_length
from core.revalidate import REVALIDATORS, _SKIP_REASON


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
