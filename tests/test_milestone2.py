"""Milestone-2 acceptance tests: circuit breakers, migrations/recovery,
resumable template batches (plan 11.5/11.6/11.9)."""
from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class TestCircuitBreaker(unittest.TestCase):
    def _breaker(self, clock, **overrides):
        from core.circuit import CircuitBreaker, CircuitConfig
        cfg = CircuitConfig(failure_threshold=3, window_s=60, cooldown_s=30,
                            half_open_probes=2, **overrides)
        return CircuitBreaker(cfg, clock=clock)

    def test_opens_after_threshold_failures(self):
        clock = FakeClock()
        b = self._breaker(clock)
        self.assertTrue(b.allows("GET"))
        for _ in range(3):
            b.record_failure()
        self.assertFalse(b.allows("GET"))          # open: rejected fast
        self.assertFalse(b.allows("POST"))

    def test_half_open_recovery(self):
        clock = FakeClock()
        b = self._breaker(clock)
        for _ in range(3):
            b.record_failure()
        self.assertFalse(b.allows("GET"))
        clock.advance(31)                           # cooldown elapses
        self.assertTrue(b.allows("GET"))            # half-open: 1st probe
        b.record_success()                          # probe succeeds -> closed
        self.assertEqual(b.state, "closed")
        self.assertTrue(b.allows("GET"))

    def test_half_open_failure_reopens(self):
        clock = FakeClock()
        b = self._breaker(clock)
        for _ in range(3):
            b.record_failure()
        clock.advance(31)
        self.assertTrue(b.allows("GET"))
        b.record_failure()                          # probe fails
        self.assertEqual(b.state, "open")
        self.assertFalse(b.allows("GET"))

    def test_recovery_probes_are_read_only(self):
        clock = FakeClock()
        b = self._breaker(clock)
        for _ in range(3):
            b.record_failure()
        clock.advance(31)
        self.assertFalse(b.allows("POST"))          # mutations never allowed half-open
        self.assertTrue(b.allows("GET"))

    def test_probe_budget_exhausted(self):
        clock = FakeClock()
        b = self._breaker(clock)
        for _ in range(3):
            b.record_failure()
        clock.advance(31)
        self.assertTrue(b.allows("GET"))
        self.assertTrue(b.allows("GET"))
        self.assertFalse(b.allows("GET"))           # 2-probe budget consumed

    def test_high_latency_counts_as_failure(self):
        clock = FakeClock()
        b = self._breaker(clock)
        b.record_failure(latency_s=35.0)
        b.record_failure(latency_s=0.1)
        self.assertFalse(b.allows("GET"))           # 35s latency + 2 = threshold 3

    def test_healthy_origin_survives_isolated_timeouts(self):
        clock = FakeClock()
        b = self._breaker(clock)
        for _ in range(3):
            for _ in range(5):
                b.record_success()
            b.record_failure(reason="ReadTimeout")
        self.assertEqual(b.state, "closed")          # 3/18 failures < 50%
        self.assertEqual(b.last_failure, "ReadTimeout")
        self.assertTrue(b.allows("GET"))

    def test_predominantly_failing_origin_still_opens(self):
        clock = FakeClock()
        b = self._breaker(clock)
        for _ in range(3):
            b.record_failure(reason="status 503")
        b.record_success()                           # 3/4 failures >= 50%
        self.assertEqual(b.state, "open")

    def test_failing_origin_cannot_starve_healthy_one(self):
        from core.circuit import CircuitRegistry
        clock = FakeClock()
        reg = CircuitRegistry({"transport": {"circuit_breaker": {
            "failure_threshold": 2, "cooldown_s": 30}}}, clock=clock)
        bad, good = reg.breaker("bad.example.com"), reg.breaker("good.example.com")
        bad.record_failure(); bad.record_failure()
        self.assertFalse(bad.allows("GET"))
        self.assertTrue(good.allows("GET"))
        good.record_success()
        self.assertEqual(good.state, "closed")


class TestMigrations(unittest.TestCase):
    def test_migrate_sets_version_and_backs_up(self):
        from core.migrations import migrate, current_version, TARGET_VERSION
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            path = Path(td) / "m.sqlite"
            import sqlite3
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE scanner_executions (target TEXT, execution_key TEXT, "
                           "scanner TEXT, url TEXT, status TEXT, reason TEXT, attempts INT, "
                           "requests INT, updated REAL)")
                db.execute("PRAGMA user_version = 7")
            record = migrate(path)
            self.assertEqual(record["to"], TARGET_VERSION)
            self.assertEqual(current_version(path), TARGET_VERSION)
            backup = Path(record["backup"])
            self.assertTrue(backup.exists())
            # historical rows preserved
            with sqlite3.connect(path) as db:
                db.execute("INSERT INTO scanner_executions "
                           "(target, execution_key, scanner, url, status, reason, attempts, "
                           " requests, updated) VALUES "
                           "('t','k','s','u','completed','',1,1,0)")
                cols = [c[1] for c in db.execute("PRAGMA table_info(scanner_executions)")]
            self.assertIn("run_id", cols)

    def test_failed_migration_preserves_old_database(self):
        from core.migrations import MIGRATIONS, migrate, current_version
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            path = Path(td) / "m.sqlite"
            import sqlite3
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE keep_me (id INTEGER)")
                db.execute("INSERT INTO keep_me VALUES (1)")
                db.execute("PRAGMA user_version = 7")
            # simulate a broken future migration
            saved = dict(MIGRATIONS)
            try:
                MIGRATIONS[9] = ["ALTER TABLE does_not_exist ADD COLUMN x INTEGER"]
                with self.assertRaises(sqlite3.OperationalError):
                    migrate(path, target=9)
            finally:
                MIGRATIONS.clear(); MIGRATIONS.update(saved)
            self.assertEqual(current_version(path), 7)   # version unchanged
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM keep_me").fetchone()[0], 1)

    def test_integrity_report_recovers_expired_leases(self):
        from core.migrations import integrity_report
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            path = Path(td) / "m.sqlite"
            import sqlite3, time
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE jobs (key TEXT PRIMARY KEY, target TEXT, kind TEXT, "
                           "payload TEXT, priority INTEGER, status TEXT, owner TEXT, "
                           "expires REAL, attempts INTEGER, reason TEXT)")
                db.execute("INSERT INTO jobs VALUES ('j1','t','scan','{}',1,'running','o',0,1,'')")
                db.execute("PRAGMA user_version = 8")
            report = integrity_report(path)
            self.assertTrue(report["ok"])
            self.assertTrue(any("lease" in r for r in report["recoverable"]))

    def test_job_recovery_requeues_only_replay_safe(self):
        from core.job_store import JobStore
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            path = Path(td) / "jobs.db"
            store = JobStore(path)
            store.enqueue("safe", "t", "scan", {}, 1)
            store.enqueue("mut", "t", "upload", {}, 1)
            store.claim("safe", seconds=-1)   # immediately expired
            store.claim("mut", seconds=-1)
            queued = store.recover("t", replay_safe=("scan",))
            kinds = {q["key"] for q in queued}
            self.assertIn("safe", kinds)
            self.assertNotIn("mut", kinds)   # uncertain mutation -> review
            import sqlite3
            with sqlite3.connect(str(path)) as db:
                status = dict(db.execute("SELECT key, status FROM jobs"))
            self.assertEqual(status["safe"], "queued")
            self.assertEqual(status["mut"], "interrupted")

class TestResumableBatches(unittest.TestCase):
    def test_template_digest_changes_with_content(self):
        from core.run_manifest import template_selection_digest
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            root = Path(td) / "tpl"
            root.mkdir()
            (root / "a.yaml").write_text("id: a\ninfo:\n  name: A\n", encoding="utf-8")
            cfg = {"external_tools": {"nuclei_templates": str(root)}}
            d1 = template_selection_digest(cfg)
            (root / "a.yaml").write_text("id: a\ninfo:\n  name: A-changed\n", encoding="utf-8")
            d2 = template_selection_digest(cfg)
            self.assertNotEqual(d1, d2)
            (root / "b.yaml").write_text("id: b\n", encoding="utf-8")
            d3 = template_selection_digest(cfg)
            self.assertNotEqual(d2, d3)


if __name__ == "__main__":
    unittest.main()
