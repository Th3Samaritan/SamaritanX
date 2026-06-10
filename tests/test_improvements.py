"""Tests for the injection-surface, confidence, and self-containment upgrades."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestInjection(unittest.TestCase):
    def test_parse_point(self):
        from core.injection import parse_point
        self.assertEqual(parse_point("id"), ("query", "id"))
        self.assertEqual(parse_point("path:2"), ("path", "2"))
        self.assertEqual(parse_point("json:user.role"), ("json", "user.role"))
        self.assertEqual(parse_point("header:X-Test"), ("header", "X-Test"))
        self.assertEqual(parse_point("cookie:sid"), ("cookie", "sid"))

    def test_replace_path_segment(self):
        from core.injection import _replace_path_segment
        out = _replace_path_segment("https://x.com/v1/users/123", 2, "124")
        self.assertTrue(out.endswith("/users/124"))

    def test_candidate_points_focuses_on_ids(self):
        from core.injection import candidate_points
        pts = candidate_points("https://x.com/v1/users/123/orders/456", [])
        self.assertIn("path:2", pts)   # 123
        self.assertIn("path:4", pts)   # 456
        # word segments are not fuzzed
        self.assertNotIn("path:0", pts)
        self.assertNotIn("path:1", pts)

    def test_candidate_points_preserves_query_params(self):
        from core.injection import candidate_points
        pts = candidate_points("https://x.com/about", ["q", "page"])
        self.assertEqual(pts[:2], ["q", "page"])

    def test_set_dotted(self):
        from core.injection import _set_dotted
        body = {}
        _set_dotted(body, "user.role", "admin")
        self.assertEqual(body["user"]["role"], "admin")


class TestConfidence(unittest.TestCase):
    def test_hard_proof_scores_high(self):
        from core.confidence import assign, label
        score, _ = assign({"category": "rce", "metadata": {"detection": "marker"}})
        self.assertGreaterEqual(score, 0.9)
        self.assertEqual(label(score), "confirmed")

    def test_heuristic_scores_low(self):
        from core.confidence import assign, label
        score, _ = assign({"category": "idor", "metadata": {}})
        self.assertLess(score, 0.6)
        self.assertIn(label(score), ("tentative", "speculative"))

    def test_validated_secret_high_rejected_low(self):
        from core.confidence import assign
        hi, _ = assign({"category": "secret_exposure", "title": "[CONFIRMED LIVE] aws",
                        "metadata": {"validator_valid": True}})
        lo, _ = assign({"category": "secret_exposure", "title": "[FALSE POSITIVE] aws",
                        "metadata": {"validator_valid": False}})
        self.assertGreater(hi, 0.9)
        self.assertLess(lo, 0.2)

    def test_explicit_confidence_respected(self):
        from core.confidence import assign
        score, reason = assign({"category": "idor", "confidence": 0.99})
        self.assertEqual(score, 0.99)
        self.assertEqual(reason, "scanner-provided")


class TestMemoryConfidence(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "t.sqlite")

    def test_confidence_persisted(self):
        from core.memory import Memory
        m = Memory(self.db)
        m.record_finding({"target": "t", "category": "idor", "title": "h",
                          "severity": "high", "cvss": 7.0})
        m.record_finding({"target": "t", "category": "rce", "title": "r",
                          "severity": "critical", "cvss": 9.8, "confidence": 0.95})
        rows = {r["title"]: r for r in m.list_findings("t")}
        self.assertLess(rows["h"]["confidence"], 0.6)   # auto-scored
        self.assertGreaterEqual(rows["r"]["confidence"], 0.9)  # explicit


if __name__ == "__main__":
    unittest.main()
