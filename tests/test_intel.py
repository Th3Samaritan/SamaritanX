"""Tests for JS intelligence, monitoring diff, and the authz template logic."""
from __future__ import annotations

import json
import unittest

from core.js_intel import (extract_secrets, extract_graphql_ops, privileged_paths,
                           find_sourcemap_url, reconstruct_sources)
from core.monitor import diff
from agents.authz_agent import _template


class TestJSIntel(unittest.TestCase):
    def test_extract_secrets(self):
        # fixtures are constructed at runtime so no real-looking secret literal
        # ends up in source (avoids upstream secret-scanning false positives)
        gkey = "AIza" + "B" * 35           # Google API keys are AIza + 35 chars
        stripe = "sk_live_" + "a" * 24     # Stripe live key shape
        js = (f'var k="{gkey}";'
              f'const s="{stripe}";'
              'token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.aaaaaaaabbbbbbbb";')
        kinds = {k for k, _ in extract_secrets(js)}
        self.assertIn("google_api_key", kinds)
        self.assertIn("stripe_live_key", kinds)
        self.assertIn("jwt", kinds)

    def test_private_key_block(self):
        header = "-----BEGIN RSA " + "PRIVATE KEY-----"
        kinds = {k for k, _ in extract_secrets(header + "\nMII...")}
        self.assertIn("private_key_block", kinds)

    def test_no_false_positive(self):
        self.assertEqual(extract_secrets("const x = 1; function foo(){return 'hello';}"), [])

    def test_graphql_ops(self):
        js = "const Q = `query GetUser { me { id } }`; mutation DeleteUser(x){}"
        ops = extract_graphql_ops(js)
        self.assertIn("query GetUser", ops)
        self.assertIn("mutation DeleteUser", ops)

    def test_privileged_paths(self):
        js = 'fetch("/admin/users"); link("/internal/metrics"); img("/img/logo.png")'
        paths = privileged_paths(js)
        self.assertIn("/admin/users", paths)
        self.assertIn("/internal/metrics", paths)
        self.assertNotIn("/img/logo.png", paths)

    def test_sourcemap_url(self):
        js = "console.log(1)\n//# sourceMappingURL=app.min.js.map"
        self.assertEqual(find_sourcemap_url(js, "https://x.test/static/app.min.js"),
                         "https://x.test/static/app.min.js.map")
        self.assertIsNone(find_sourcemap_url("no map here", "https://x.test/a.js"))

    def test_reconstruct_sources(self):
        awskey = "AKIA" + "Z" * 16  # AWS access-key shape, built to avoid a literal
        m = json.dumps({"sources": ["src/secret.js", "src/app.js"],
                        "sourcesContent": [f"const KEY='{awskey}'", "x=1"]})
        rebuilt = reconstruct_sources(m)
        names = [n for n, _ in rebuilt]
        self.assertIn("src/secret.js", names)
        self.assertEqual(len(rebuilt), 2)
        # reconstructed content is searchable for secrets
        joined = "\n".join(c for _, c in rebuilt)
        self.assertIn("AKIA", joined)

    def test_reconstruct_no_content(self):
        self.assertEqual(reconstruct_sources('{"sources":["a.js"]}'), [])
        self.assertEqual(reconstruct_sources("not json"), [])


class TestMonitorDiff(unittest.TestCase):
    def test_added_and_removed(self):
        old = {"hosts": ["a.x.com"], "endpoints": ["https://x/1"], "params": []}
        new = {"hosts": ["a.x.com", "b.x.com"], "endpoints": [], "params": ["https://x/2 :: id"]}
        d = diff(old, new)
        self.assertEqual(d["hosts"]["added"], ["b.x.com"])
        self.assertEqual(d["endpoints"]["removed"], ["https://x/1"])
        self.assertIn("https://x/2 :: id", d["params"]["added"])

    def test_no_change(self):
        snap = {"hosts": ["a"], "endpoints": ["e"], "params": ["p"]}
        d = diff(snap, snap)
        self.assertTrue(all(not d[k]["added"] and not d[k]["removed"] for k in d))


class TestAuthzTemplate(unittest.TestCase):
    def test_id_segments_normalised(self):
        self.assertEqual(_template("https://api.x.com/v1/users/123/orders/9"),
                         "https://api.x.com/v1/users/{id}/orders/{id}")

    def test_uuid_normalised(self):
        t = _template("https://api.x.com/o/550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(t, "https://api.x.com/o/{id}")

    def test_distinct_objects_collapse(self):
        self.assertEqual(_template("https://x/u/1"), _template("https://x/u/2"))


class TestSessionParsing(unittest.TestCase):
    def test_label_path_default_rank(self):
        from samaritanx import _parse_sessions
        out = _parse_sessions(["userC=c.yaml"])
        self.assertEqual(out, [("userC", "c.yaml", 1)])

    def test_admin_label_infers_rank2(self):
        from samaritanx import _parse_sessions
        self.assertEqual(_parse_sessions(["admin=admin.yaml"])[0][2], 2)

    def test_explicit_rank(self):
        from samaritanx import _parse_sessions
        self.assertEqual(_parse_sessions(["staff=s.yaml:3"]), [("staff", "s.yaml", 3)])

    def test_malformed_ignored(self):
        from samaritanx import _parse_sessions
        self.assertEqual(_parse_sessions(["nonsense"]), [])


class TestRankAwareBFLA(unittest.TestCase):
    def test_lower_rank_reaches_admin_resource(self):
        import types
        from agents.authz_agent import AuthzAgent
        reported = []

        class A(AuthzAgent):
            def report_finding(self, ctx, f):
                reported.append(f)

        cells = {
            "userA": {"status": 200, "len": 600, "rank": 1, "markers": [], "sensitive": []},
            "admin": {"status": 200, "len": 600, "rank": 2, "markers": [], "sensitive": []},
        }
        A()._evaluate(types.SimpleNamespace(), "https://api.x.com/admin/users", cells)
        self.assertTrue(reported)
        self.assertIn("privilege escalation", reported[0]["title"].lower())
        self.assertEqual(reported[0]["metadata"]["owner"], "admin")

    def test_public_page_not_flagged(self):
        import types
        from agents.authz_agent import AuthzAgent
        reported = []

        class A(AuthzAgent):
            def report_finding(self, ctx, f):
                reported.append(f)

        # no admin baseline, non-privileged path → both 200 is fine, no finding
        cells = {
            "anon": {"status": 200, "len": 600, "rank": 0, "markers": [], "sensitive": []},
            "userA": {"status": 200, "len": 600, "rank": 1, "markers": [], "sensitive": []},
        }
        A()._evaluate(types.SimpleNamespace(), "https://x.com/about", cells)
        self.assertEqual(reported, [])


class TestDiffPrune(unittest.TestCase):
    def test_prune_keeps_newest(self):
        import tempfile, time
        from pathlib import Path
        from core.monitor import _prune_diffs
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            for i in range(5):
                f = p / f"diff_{1000+i}.json"
                f.write_text("{}", encoding="utf-8")
                time.sleep(0.01)
            _prune_diffs(p, keep=2)
            self.assertEqual(len(list(p.glob("diff_*.json"))), 2)


if __name__ == "__main__":
    unittest.main()
