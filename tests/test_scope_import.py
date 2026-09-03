"""Unit tests for the platform scope importer."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.scope_import import to_rules, parse_platform_scope, looks_like_platform_export

H1_JSON = json.dumps({
    "data": {
        "relationships": {
            "structured_scopes": {
                "data": [
                    {"attributes": {
                        "asset_type": "URL",
                        "asset_identifier": "https://*.example.com",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True}},
                    {"attributes": {
                        "asset_type": "WILDCARD",
                        "asset_identifier": "*.api.example.com",
                        "eligible_for_bounty": False,
                        "eligible_for_submission": False}},
                    {"attributes": {
                        "asset_type": "CIDR",
                        "asset_identifier": "10.10.0.0/24",
                        "eligible_for_submission": True}},
                    {"attributes": {
                        "asset_type": "URL",
                        "asset_identifier": "https://admin.example.com/internal",
                        "eligible_for_submission": True}},
                ]
            }
        }
    }
})

BUG_CROWD_CSV = """target_name,category,in_scope
*.bugcrowd-test.com,website,true
internal.bugcrowd-test.com,api,false
"""

INTIGRITI_JSON = json.dumps({
    "domains": [
        {"endpoint": "*.intigriti-test.com", "tier": 1},
        {"endpoint": "https://app.intigriti-test.com/login", "tier": 2},
    ]
})

CHAOS_JSON = json.dumps([
    {"subdomain": "*.chaos-test.com"},
    {"subdomain": "chaos-test.com"},
])


class TestScopeImport(unittest.TestCase):
    def test_hackerone_structured_scopes(self):
        rules = to_rules(H1_JSON)
        self.assertIn("*.example.com", rules)
        self.assertNotIn("*.api.example.com", rules)   # not bounty-eligible
        self.assertIn("!*.api.example.com", rules)     # -> deny rule instead
        self.assertIn("cidr:10.10.0.0/24", rules)
        self.assertTrue(any(r.startswith("re:^https?://admin\\.example\\.com/internal") for r in rules))

    def test_bugcrowd_csv(self):
        rules = to_rules(BUG_CROWD_CSV)
        self.assertIn("*.bugcrowd-test.com", rules)
        self.assertIn("!internal.bugcrowd-test.com", rules)

    def test_intigriti(self):
        rules = to_rules(INTIGRITI_JSON)
        self.assertIn("*.intigriti-test.com", rules)
        self.assertTrue(any(r.startswith("re:^https?://app\\.intigriti\\-test\\.com/login") for r in rules))

    def test_chaos(self):
        rules = to_rules(CHAOS_JSON)
        self.assertIn("*.chaos-test.com", rules)
        self.assertIn("chaos-test.com", rules)

    def test_detection(self):
        self.assertTrue(looks_like_platform_export(H1_JSON))
        self.assertTrue(looks_like_platform_export(BUG_CROWD_CSV))
        self.assertFalse(looks_like_platform_export("*.example.com\n!evil.example.com\n"))
        self.assertFalse(looks_like_platform_export(""))

    def test_plain_text(self):
        rules = to_rules("*.a.com\nre:^https://x\\.a\\.com/admin/\n!cidr:10.0.0.0/8")
        self.assertIn("*.a.com", rules)

    def test_scope_policy_autodetect(self):
        import tempfile, os
        from core.scope import ScopePolicy
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        Path(path).write_text(H1_JSON, encoding="utf-8")
        try:
            p = ScopePolicy.from_file(path, default_allow=False)
            ok, _ = p.allows("https://sub.example.com/x")
            self.assertTrue(ok)
            ok2, _ = p.allows("https://evil.com/")
            self.assertFalse(ok2)
        finally:
            os.unlink(path)

    def test_extract_roots(self):
        from core.scope_import import extract_roots
        rules = ["*.example.com", "api.example.com", "www.other.com",
                 "!internal.example.com", "cidr:10.0.0.0/8",
                 r"re:^https?://app\.third\.com/login.*$"]
        roots = extract_roots(rules)
        self.assertIn("example.com", roots)
        self.assertIn("other.com", roots)
        self.assertIn("third.com", roots)
        self.assertNotIn("internal.example.com", roots)
        self.assertNotIn("api.example.com", roots)  # collapsed into apex
        # wildcard + apex collapse
        self.assertEqual(extract_roots(["*.a.com", "a.com", "b.a.com"]), ["a.com"])


if __name__ == "__main__":
    unittest.main()
