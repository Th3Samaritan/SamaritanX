"""Tests for the depth/precision engine: baseline stats, correlation/dedup,
scope hardening, identity-matrix leak logic, browser-proof decision, LLM
fallback, and the benchmark scorer."""
from __future__ import annotations

import asyncio
import unittest

from core.baseline import TimingBaseline, ResponseBaseline
from core.correlate import deduplicate, root_cause_key, _path_template
from core.scope import ScopePolicy, is_third_party, registrable_domain
from core.identity_matrix import extract_identity_markers, find_leak
from core.browser_verify import execution_proven
from core import llm
from bench.scorer import score


class TestTimingBaseline(unittest.TestCase):
    def test_outlier_needs_robust_deviation(self):
        tb = TimingBaseline(k=6.0, min_delta_s=1.0)
        for v in (0.10, 0.11, 0.09, 0.12, 0.10):
            tb.add(v)
        self.assertFalse(tb.is_outlier(0.13))     # normal jitter
        self.assertTrue(tb.is_outlier(5.0))       # a real 5s sleep

    def test_single_slow_sample_does_not_poison(self):
        tb = TimingBaseline()
        for v in (0.1, 0.1, 0.1, 9.0):   # one fluke
            tb.add(v)
        # median stays ~0.1, so a subsequent 9s is still an outlier
        self.assertTrue(tb.is_outlier(9.0))

    def test_no_samples_never_outlier(self):
        self.assertFalse(TimingBaseline().is_outlier(100.0))


class TestResponseBaseline(unittest.TestCase):
    def test_status_change_is_significant(self):
        rb = ResponseBaseline()
        for _ in range(3):
            rb.add(200, "<html>" + "x" * 500 + "</html>")
        self.assertTrue(rb.is_significant(500, "error"))

    def test_similar_response_not_significant(self):
        rb = ResponseBaseline()
        for _ in range(3):
            rb.add(200, "<html>" + "x" * 500 + "</html>")
        self.assertFalse(rb.is_significant(200, "<html>" + "x" * 505 + "</html>"))

    def test_length_threshold_has_floor(self):
        rb = ResponseBaseline()
        for _ in range(3):
            rb.add(200, "x" * 1000)
        self.assertGreaterEqual(rb.length_threshold(), 200.0)


class TestScopeHardening(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("www.arewagate.com"), "arewagate.com")
        self.assertEqual(registrable_domain("a.b.example.co.uk"), "example.co.uk")

    def test_third_party_detected(self):
        self.assertTrue(is_third_party("api.segment.io"))
        self.assertTrue(is_third_party("sdk-api-v1.singular.net"))
        self.assertFalse(is_third_party("www.arewagate.com"))

    def test_active_allows_blocks_third_party(self):
        p = ScopePolicy(default_allow=True)
        ok, why = p.active_allows("https://api.segment.io/v1/t", "arewagate.com")
        self.assertFalse(ok)
        self.assertIn("third-party", why)

    def test_active_allows_blocks_offdomain(self):
        p = ScopePolicy(default_allow=True)
        ok, _ = p.active_allows("https://evil.example.org/x", "arewagate.com")
        self.assertFalse(ok)

    def test_active_allows_permits_same_domain(self):
        p = ScopePolicy(default_allow=True)
        ok, _ = p.active_allows("https://www.arewagate.com/airtime/purchase", "arewagate.com")
        self.assertTrue(ok)


class TestCorrelation(unittest.TestCase):
    def test_host_level_folds_all_paths(self):
        fs = [{"category": "smuggling", "url": f"https://x.test/p{i}",
               "metadata": {"kind": "CL.TE"}} for i in range(15)]
        out = deduplicate(fs)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["metadata"]["duplicate_count"], 15)

    def test_param_level_keeps_distinct_params(self):
        fs = [
            {"category": "sqli", "url": "https://x.test/u?id=1", "parameter": "id"},
            {"category": "sqli", "url": "https://x.test/u?id=2", "parameter": "id"},
            {"category": "sqli", "url": "https://x.test/u?name=a", "parameter": "name"},
        ]
        out = deduplicate(fs)
        self.assertEqual(len(out), 2)  # id folds, name separate

    def test_path_template_normalises_ids(self):
        self.assertEqual(_path_template("/users/12345/profile"), "/users/{n}/profile")

    def test_prefer_verified_representative(self):
        unproven = {"category": "cors", "url": "https://x.test/a", "confidence": 0.9}
        proven = {"category": "cors", "url": "https://x.test/b",
                  "metadata": {"poc": {"verified": True, "response_status": 200}}}
        out = deduplicate([unproven, proven])
        self.assertEqual(len(out), 1)
        self.assertIs(out[0], proven)


class TestIdentityMatrix(unittest.TestCase):
    def test_leak_detected(self):
        owner = {"victim@corp.example", "550e8400-e29b-41d4-a716-446655440000"}
        viewer_body = "account owner victim@corp.example balance 999"
        leaked = find_leak("alice", owner, "bob", viewer_body, public_markers=set())
        self.assertIn("victim@corp.example", leaked)

    def test_public_marker_not_a_leak(self):
        owner = {"support@corp.example"}
        viewer_body = "contact support@corp.example"
        leaked = find_leak("alice", owner, "bob", viewer_body,
                           public_markers={"support@corp.example"})
        self.assertEqual(leaked, set())

    def test_same_identity_no_leak(self):
        self.assertEqual(find_leak("a", {"x@y.com"}, "a", "x@y.com body", set()), set())

    def test_marker_extraction_skips_common(self):
        markers = extract_identity_markers("email noreply@x.com and real alice@corp.example")
        self.assertIn("alice@corp.example", markers)
        self.assertNotIn("noreply@x.com", markers)


class TestBrowserProofDecision(unittest.TestCase):
    def test_marker_in_dialog_proves(self):
        self.assertTrue(execution_proven([], ["hello sx9f3 world"], [], "sx9f3"))

    def test_marker_in_console_proves(self):
        self.assertTrue(execution_proven([], [], ["console: sx9f3"], "sx9f3"))

    def test_no_marker_no_proof(self):
        self.assertFalse(execution_proven(["alert:1"], ["nope"], ["other"], "sx9f3"))

    def test_empty_marker_never_proves(self):
        self.assertFalse(execution_proven(["x"], ["x"], ["x"], ""))


class TestLLMFallback(unittest.TestCase):
    def test_triage_fallback_is_deterministic(self):
        f = {"category": "sqli", "severity": "critical", "title": "SQLi", "url": "x"}
        out = asyncio.run(llm.triage_impact(f, cfg={}))  # no api key -> fallback
        self.assertIn("database", out["impact"].lower())
        self.assertEqual(out["recommended_severity"], "critical")

    def test_plan_fallback_prioritises_signals(self):
        order = asyncio.run(llm.plan_attack({"has_graphql": True}, cfg={}))
        self.assertEqual(order[0], "graphql")


class TestBenchScorer(unittest.TestCase):
    def test_tp_fp_fn_gated(self):
        answers = [
            {"id": "a", "target": "t", "category": "sqli", "match": "/login"},
            {"id": "b", "target": "t", "category": "xss", "match": "/search"},
            {"id": "c", "target": "t", "category": "ssrf", "match": "/stock"},
        ]
        findings = [   # verified/reported
            {"category": "sqli", "url": "https://t/login", "parameter": "email"},
            {"category": "cors", "url": "https://t/api"},   # false positive
        ]
        candidates = [  # quarantined
            {"category": "xss", "url": "https://t/search"},  # seen but not proven -> gated
        ]
        r = score(findings, candidates, answers)
        o = r["overall"]
        self.assertEqual(o["tp"], 1)     # sqli
        self.assertEqual(o["fp"], 1)     # cors
        self.assertEqual(o["fn"], 1)     # ssrf missed entirely
        self.assertEqual(o["gated"], 1)  # xss caught but not proven


if __name__ == "__main__":
    unittest.main()
