"""Milestone-1 acceptance tests: readiness, run manifests, execution states,
credential boundaries (plan 11.1-11.4)."""
from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestReadiness(unittest.TestCase):
    def _cfg(self, tmp):
        return {
            "workspace": {"root": str(tmp)},
            "memory": {"db_path": str(Path(tmp) / "m.sqlite")},
            "external_tools": {"enabled": True,
                               "binary_dir": str(Path(tmp) / "nobin"),
                               "nuclei_templates": str(Path(tmp) / "notemplates")},
            "llm": {"enabled": False},
        }

    def test_missing_binary_and_catalog_are_actionable(self):
        from core.readiness import run_checks
        with tempfile.TemporaryDirectory() as td:
            results = run_checks(self._cfg(td))
            by_cap = {r["capability"]: r for r in results}
            self.assertEqual(by_cap["external_tool:nuclei"]["status"], "missing")
            self.assertIn("nuclei adapter scans", by_cap["external_tool:nuclei"]["affects"])
            self.assertEqual(by_cap["nuclei_catalog"]["status"], "invalid")
            self.assertEqual(by_cap["workspace"]["status"], "ok")
            self.assertEqual(by_cap["database"]["status"], "ok")

    def test_unwritable_workspace_reported(self):
        from core.readiness import run_checks
        import os
        with tempfile.TemporaryDirectory() as td:
            ro = Path(td) / "ro"
            ro.mkdir()
            cfg = self._cfg(td)
            cfg["workspace"]["root"] = str(ro)
            if os.name != "nt":
                os.chmod(ro, 0o555)
                results = run_checks(cfg)
                self.assertEqual(
                    next(r for r in results if r["capability"] == "workspace")["status"],
                    "unavailable")
            else:
                results = run_checks(cfg)
                self.assertIn(
                    next(r for r in results if r["capability"] == "workspace")["status"],
                    ("ok", "unavailable"))

    def test_offline_checks_make_no_network_requests(self):
        from core.readiness import run_checks
        import unittest.mock as mock
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(td)
            with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network!")):
                with mock.patch("httpx.AsyncClient", side_effect=AssertionError("network!")):
                    run_checks(cfg, probe_binaries=False)  # must not raise


class TestRunManifest(unittest.TestCase):
    def _cfg(self, tmp):
        return {"external_tools": {"enabled": True, "binary_dir": str(Path(tmp) / "bin"),
                                   "nuclei_templates": str(Path(tmp) / "tpl")},
                "operator": {"handle": "t"}}

    def test_identical_inputs_identical_digest(self):
        from core.run_manifest import create_run_manifest
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(td)
            m1 = create_run_manifest(cfg, "example.com")
            m2 = create_run_manifest(cfg, "example.com")
            self.assertEqual(m1["input_digest"], m2["input_digest"])

    def test_changed_config_changes_digest(self):
        from core.run_manifest import create_run_manifest
        with tempfile.TemporaryDirectory() as td:
            cfg1 = self._cfg(td)
            cfg2 = self._cfg(td)
            cfg2["operator"] = {"handle": "someone-else"}
            m1 = create_run_manifest(cfg1, "example.com")
            m2 = create_run_manifest(cfg2, "example.com")
            self.assertNotEqual(m1["input_digest"], m2["input_digest"])

    def test_redaction_strips_secrets(self):
        from core.run_manifest import redacted_config, config_digest
        cfg = {"hackerone": {"api_token": "super-secret-token-value"},
               "llm": {"api_key": "sk-1234567890abcdef"},
               "plain": "visible"}
        red = redacted_config(cfg)
        self.assertNotIn("super-secret-token-value", str(red))
        self.assertNotIn("sk-1234567890abcdef", str(red))
        self.assertIn("visible", str(red))
        self.assertEqual(len(config_digest(cfg)), 64)

    def test_compare_manifests_explains_changes(self):
        from core.run_manifest import create_run_manifest, compare_manifests
        with tempfile.TemporaryDirectory() as td:
            cfg1 = self._cfg(td)
            cfg2 = self._cfg(td)
            cfg2["operator"] = {"handle": "other"}
            m1 = create_run_manifest(cfg1, "x")
            m2 = create_run_manifest(cfg2, "x")
            self.assertIn("config_digest", compare_manifests(m1, m2))


class TestExecutionStates(unittest.TestCase):
    def test_reason_codes(self):
        from core.scan_execution import REASON_CODES, STATUSES
        for code in ("scope_denied", "request_budget_exhausted", "dependency_missing",
                     "output_parse_error", "timed_out", "cancelled"):
            self.assertIn(code, REASON_CODES)
        for status in ("completed", "skipped", "blocked", "timed_out", "cancelled",
                       "failed", "partial"):
            self.assertIn(status, STATUSES)

    def test_execution_summary_counts(self):
        from core.memory import Memory
        with tempfile.TemporaryDirectory() as td:
            m = Memory(Path(td) / "m.sqlite")
            m.record_execution("t", "k1", "sqli", "u", "completed", run_id="r1",
                               duration_s=1.0)
            m.record_execution("t", "k2", "sqli", "u", "timed_out",
                               "scanner deadline exceeded", run_id="r1")
            m.record_execution("t", "k3", "sqli", "u", "failed", "ValueError",
                               run_id="r1", exit_code=1, diagnostics="boom")
            summary = m.execution_summary("t")
            self.assertEqual(summary["attempted"], 3)
            self.assertEqual(summary["completed"], 1)
            self.assertEqual(summary["incomplete"], 2)


class TestCredentialBoundaries(unittest.TestCase):
    def test_session_origin_stored(self):
        from core.auth import SessionStore
        s = SessionStore()
        s.origin = "arewagate.com"
        self.assertEqual(s.origin, "arewagate.com")

    def test_same_origin_check(self):
        from core.http_client import _same_credential_origin
        self.assertTrue(_same_credential_origin("arewagate.com", "arewagate.com"))
        self.assertTrue(_same_credential_origin("api.arewagate.com", "arewagate.com"))
        self.assertFalse(_same_credential_origin("evil.com", "arewagate.com"))
        self.assertFalse(_same_credential_origin("arewagate.com.evil.com", "arewagate.com"))
        self.assertTrue(_same_credential_origin("any", None))

    def test_headers_stripped_cross_origin(self):
        from core.http_client import StealthHttpClient
        from core.auth import SessionStore

        async def run():
            client = StealthHttpClient({})
            try:
                s = SessionStore()
                s.origin = "target.com"
                s.headers = {"Authorization": "Bearer abc", "X-Tenant": "acme"}
                client.attach(session=s)
                hdrs = client._build_headers(None, "evil.com")
                self.assertNotIn("Authorization", hdrs)   # credential stripped
                self.assertIn("X-Tenant", hdrs)           # non-secret survives
                hdrs2 = client._build_headers(None, "target.com")
                self.assertIn("Authorization", hdrs2)     # same origin keeps it
                c1 = client._cookies({}, "evil.com")
                s.cookies = {"session": "abc"}
                c2 = client._cookies({}, "evil.com")
                self.assertEqual(c2, {})
                c3 = client._cookies({}, "api.target.com")
                self.assertEqual(c3.get("session"), "abc")
            finally:
                await client.close()
        asyncio.run(run())

    def test_mutation_policy_on_off(self):
        from core.transport import TransportController, TransportBlocked

        async def run():
            base = {"transport": {"strict_mutations": True},
                    "external_tools": {"enabled": True},
                    "safety": {"aggressive": False}}
            ctrl = TransportController(base)
            # non-mutating passes
            await ctrl.admit("http://target.com/", "http", mutating=False)
            # unclassified mutation blocked
            with self.assertRaises(TransportBlocked):
                await ctrl.admit("http://target.com/", "http", mutating=True)
            # sanctioned mutation allowed
            await ctrl.admit("http://target.com/", "http", mutating=True, sanctioned=True)
            # aggressive allows unclassified
            base["safety"]["aggressive"] = True
            ctrl2 = TransportController(base)
            await ctrl2.admit("http://target.com/", "http", mutating=True)
            # strict off -> allowed
            base["safety"]["aggressive"] = False
            base["transport"]["strict_mutations"] = False
            ctrl3 = TransportController(base)
            await ctrl3.admit("http://target.com/", "http", mutating=True)
        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
