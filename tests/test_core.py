"""Basic unit/integration test suite for SamaritanX.

Run with:  python -m pytest tests/  or  python -m unittest tests/test_core.py
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestMemory(unittest.TestCase):
    def setUp(self):
        import tempfile
        import os
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.sqlite")

    def tearDown(self):
        import shutil
        import os
        try:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        except Exception:
            pass

    def test_record_and_update_finding(self):
        from core.memory import Memory
        mem = Memory(self.db_path)

        fid = mem.record_finding({
            "target": "test_target",
            "category": "sqli",
            "title": "Test SQLi",
            "severity": "high",
            "cvss": 8.5,
            "url": "https://example.com/test?id=1",
            "parameter": "id",
        })
        self.assertGreater(fid, 0)

        fid2 = mem.record_finding({
            "target": "test_target",
            "category": "sqli",
            "title": "Test SQLi",
            "severity": "high",
            "cvss": 8.5,
            "url": "https://example.com/test?id=1",
            "parameter": "id",
        })
        self.assertEqual(fid, fid2)

        mem.update_finding(fid, severity="critical", cvss=9.5)
        findings = mem.list_findings("test_target")
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertAlmostEqual(float(findings[0]["cvss"]), 9.5)

    def test_asset_tracking(self):
        from core.memory import Memory
        mem = Memory(self.db_path)

        added = mem.add_asset("target_x", "subdomain", "api.target-x.com")
        self.assertTrue(added)
        added2 = mem.add_asset("target_x", "subdomain", "api.target-x.com")
        self.assertFalse(added2)

        assets = mem.list_assets("target_x", "subdomain")
        self.assertEqual(len(assets), 1)

    def test_scan_state(self):
        from core.memory import Memory
        mem = Memory(self.db_path)

        self.assertFalse(mem.is_completed("t1", "recon"))
        mem.mark_completed("t1", "recon")
        self.assertTrue(mem.is_completed("t1", "recon"))
        mem.reset_scan_state("t1")
        self.assertFalse(mem.is_completed("t1", "recon"))

    def test_processed_urls(self):
        from core.memory import Memory
        mem = Memory(self.db_path)

        self.assertFalse(mem.is_url_processed("t1", "https://x.com/a", "crawl"))
        mem.mark_url_processed("t1", "https://x.com/a", "crawl")
        self.assertTrue(mem.is_url_processed("t1", "https://x.com/a", "crawl"))
        # same url different phase => not processed
        self.assertFalse(mem.is_url_processed("t1", "https://x.com/a", "scan"))
        # clear only one phase
        mem.clear_processed_urls("t1", "crawl")
        self.assertFalse(mem.is_url_processed("t1", "https://x.com/a", "crawl"))


class TestTaskQueue(unittest.TestCase):
    async def _put_get_join(self):
        from core.task_queue import TaskQueue

        q = TaskQueue()
        await q.put("recon", {"target": "example.com"}, target="example_com")

        task = await q.get()
        self.assertEqual(task.kind, "recon")
        q.task_done()

        self.assertTrue(q.empty())
        await q.join()

    def test_put_get_join(self):
        import asyncio
        asyncio.run(self._put_get_join())


class TestUtils(unittest.TestCase):
    def test_root_domain(self):
        from core.utils import root_domain
        self.assertEqual(root_domain("api.example.com"), "example.com")
        self.assertEqual(root_domain("sub.api.example.co.uk"), "example.co.uk")
        self.assertEqual(root_domain("example.com"), "example.com")

    def test_slugify(self):
        from core.utils import slugify
        self.assertEqual(slugify("example.com"), "example.com")
        self.assertEqual(slugify("https://api.example.com:443/"), "https___api.example.com_443")

    def test_normalize_url(self):
        from core.utils import normalize_url
        self.assertEqual(normalize_url("example.com"), "http://example.com/")
        self.assertEqual(normalize_url("https://EXAMPLE.COM/Path"), "https://example.com/Path")

    def test_host_of(self):
        from core.utils import host_of
        self.assertEqual(host_of("https://api.example.com/test"), "api.example.com")


class TestScopePolicy(unittest.TestCase):
    def test_default_allow(self):
        from core.scope import ScopePolicy
        p = ScopePolicy(default_allow=True)
        ok, _ = p.allows("https://any-target.example.com/admin")
        self.assertTrue(ok)

    def test_glob_allow(self):
        from core.scope import ScopePolicy
        p = ScopePolicy(default_allow=False, allow_globs=["*.example.com", "example.com"])
        ok, _ = p.allows("https://api.example.com/test")
        self.assertTrue(ok)
        ok, _ = p.allows("https://evil.com/test")
        self.assertFalse(ok)

    def test_deny_precedence(self):
        from core.scope import ScopePolicy
        p = ScopePolicy(
            allow_globs=["*.example.com"],
            deny_globs=["!beta.example.com".lstrip("!")],
        )
        ok, _ = p.allows("https://beta.example.com/test")
        self.assertFalse(ok)


class TestConfigValidator(unittest.TestCase):
    def test_valid_config(self):
        from core.config_validator import validate_config
        cfg = {
            "workspace": {"root": "./ws"},
            "http": {"timeout": 20, "max_redirects": 5},
            "stealth": {"enabled": True, "rate_limit_rps": 6, "per_host_rps": 2},
            "concurrency": {"recon_workers": 8, "scanner_workers": 12, "crawler_workers": 4},
            "recon": {"passive_only": False},
            "crawler": {"max_depth": 3, "max_urls_per_host": 1000},
            "scanners": {"enabled": ["sqli", "xss", "ssrf"]},
            "reporting": {"format": ["markdown", "pdf"]},
            "memory": {},
        }
        issues = validate_config(cfg)
        self.assertEqual(issues, [])

    def test_missing_section(self):
        from core.config_validator import validate_config
        issues = validate_config({"scanners": {"enabled": ["sqli"]}})
        self.assertGreater(len(issues), 0)

    def test_unknown_scanner(self):
        from core.config_validator import validate_config
        cfg = {
            "workspace": {"root": "./ws"},
            "http": {"timeout": 20, "max_redirects": 5},
            "stealth": {"enabled": True, "rate_limit_rps": 6, "per_host_rps": 2},
            "concurrency": {"recon_workers": 8, "scanner_workers": 12, "crawler_workers": 4},
            "recon": {"passive_only": False},
            "crawler": {"max_depth": 3, "max_urls_per_host": 1000},
            "scanners": {"enabled": ["sqli", "nonexistent_scanner"]},
            "reporting": {"format": ["markdown"]},
            "memory": {},
        }
        issues = validate_config(cfg)
        self.assertTrue(any("nonexistent_scanner" in i for i in issues))


class TestConstants(unittest.TestCase):
    def test_task_kinds(self):
        from core.constants import TaskKind
        self.assertEqual(TaskKind.RECON, "recon")
        self.assertEqual(TaskKind.SCAN, "scan")

    def test_severity_levels(self):
        from core.constants import Severity, LEVEL_MAP
        self.assertEqual(Severity.CRITICAL, "critical")
        self.assertEqual(LEVEL_MAP[Severity.CRITICAL], "crit")
        self.assertEqual(LEVEL_MAP[Severity.HIGH], "high")


class TestTokenBucket(unittest.TestCase):
    async def _run(self):
        from core.http_client import _TokenBucket
        bucket = _TokenBucket(rate=10.0)
        self.assertAlmostEqual(bucket.rate, 10.0)
        self.assertAlmostEqual(bucket.error_fraction(), 0.0)

        bucket.record_error()
        bucket.record_error()
        bucket.record_success()
        # 2 errors, 3 total => 0.667 frac
        self.assertGreater(bucket.error_fraction(), 0.5)
        bucket.auto_scale()
        self.assertLess(bucket.rate, 10.0)

    def test_sync(self):
        import asyncio
        asyncio.run(self._run())


if __name__ == "__main__":
    unittest.main()
