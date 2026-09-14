"""Regression coverage for failed scans, checkpoint invalidation and budgets."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from agents.vuln_agent import VulnerabilityAgent
from core.memory import Memory
from core.scan_execution import execution_key, request_budget, applicability
from core.benchmark import summarize
from core.identity_matrix import cross_access_check
from core.proof_gate import is_verified
from unittest.mock import patch, AsyncMock


class ExecutionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ctx = SimpleNamespace(memory=Memory(Path(self.tmp.name) / "test.db"),
            target_slug="lab", config={"scan": {"scanner_retries": 1, "scanner_request_budget": 2}},
            dashboard=SimpleNamespace(event=lambda *args: None), session=None)
        self.agent = VulnerabilityAgent()

    async def test_failure_then_retry_is_completed(self):
        calls = []
        async def scanner(*args):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("temporary")
            return []
        await self.agent._safe("lab", scanner, self.ctx, "http://lab/", [], "GET", None)
        row = self.ctx.memory.execution_coverage("lab")["records"][0]
        self.assertEqual((row["status"], row["attempts"]), ("completed", 2))

    async def test_anonymous_scan_runs_but_failed_required_auth_skips(self):
        from core.auth import SessionStore
        from core.task_queue import Task
        self.ctx.session = SessionStore()
        self.ctx.config["scanners"] = {"enabled": ["rce"], "nuclei": False}
        scanner = AsyncMock(return_value=[])
        task = Task(1, 1, "scan", "lab", {"url": "http://lab/", "params": ["q"]})
        with patch.dict("agents.vuln_agent.REGISTRY", {"rce": scanner}):
            await self.agent.handle(task, self.ctx)
            scanner.assert_awaited_once()
            self.ctx.auth_required = True
            await self.agent.handle(task, self.ctx)
            scanner.assert_awaited_once()
        self.assertEqual(self.ctx.memory.execution_coverage("lab")["records"][0]["reason"], "authentication preflight failed")

    async def test_failed_mutation_is_not_retried_or_reusable(self):
        async def scanner(*args):
            raise RuntimeError()
        key = execution_key(self.ctx, "lab", scanner, "http://lab/", [], "POST", {})
        await self.agent._safe("lab", scanner, self.ctx, "http://lab/", [], "POST", {}, key)
        row = self.ctx.memory.execution_coverage("lab")["records"][0]
        self.assertEqual((row["status"], row["attempts"]), ("failed", 1))
        self.assertFalse(self.ctx.memory.execution_reusable("lab", key, 86400))

    async def test_swallowed_budget_exception_still_incomplete(self):
        async def scanner(*args):
            for _ in range(3):
                try:
                    request_budget.get().take()
                except RuntimeError:
                    pass
            return []
        await self.agent._safe("lab", scanner, self.ctx, "http://lab/", [], "GET", None)
        self.assertEqual(self.ctx.memory.execution_coverage("lab")["records"][0]["status"], "budget_exhausted")
        self.assertIsNone(request_budget.get())

    async def test_timeout_is_not_completed(self):
        self.ctx.config["scan"].update(scanner_timeout_seconds=0.001, scanner_retries=0)
        async def scanner(*args):
            await asyncio.sleep(1)
        await self.agent._safe("lab", scanner, self.ctx, "http://lab/", [], "GET", None)
        self.assertEqual(self.ctx.memory.execution_coverage("lab")["records"][0]["status"], "timed_out")

    async def test_cancellation_remains_resumable(self):
        started = asyncio.Event()
        async def scanner(*args):
            started.set()
            await asyncio.Event().wait()
        task = asyncio.create_task(self.agent._safe("lab", scanner, self.ctx, "http://lab/", [], "GET", None))
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.ctx.memory.execution_coverage("lab")["records"][0]["status"], "interrupted")

    async def test_identity_sharing_needs_expected_denial(self):
        class Client:
            async def get(self, url, **kwargs):
                return SimpleNamespace(status=200, error=None,
                    response_body="public" if kwargs.get("no_session") else "alice@owned.test")
        self.ctx.http = Client()
        self.ctx.http2 = Client()
        self.ctx.scope = None
        finding = await cross_access_check(self.ctx, "http://lab/object")
        self.assertFalse(is_verified(finding))
        self.ctx.config["authorization"] = {"objects": [{
            "url": "http://lab/object", "owner": "primary", "tenant": "a",
            "role": "member", "denied_viewers": ["second"],
            "private_markers": ["alice@owned.test"]}]}
        finding = await cross_access_check(self.ctx, "http://lab/object")
        self.assertTrue(is_verified(finding))
        self.assertEqual(finding["metadata"]["authorization_context"]["tenant"], "a")

    async def test_unavailable_public_baseline_cannot_verify(self):
        class Client:
            async def get(self, url, **kwargs):
                return SimpleNamespace(status=0, error="offline", response_body="")
        self.ctx.http = self.ctx.http2 = Client()
        self.ctx.scope = None
        self.assertIsNone(await cross_access_check(self.ctx, "http://lab/object"))

    def test_checkpoint_context_and_expiry(self):
        def scanner():
            pass
        def key(method="GET"):
            return execution_key(self.ctx, "lab", scanner, "http://lab/", [], method, None)
        original = key()
        self.assertNotEqual(original, key("POST"))
        self.ctx.session = SimpleNamespace(label="bob", headers={}, cookies={})
        self.assertNotEqual(original, key())
        primary_key = key()
        self.ctx.http2 = SimpleNamespace(session=SimpleNamespace(label="second", headers={"Authorization": "fixture"}, cookies={}))
        self.assertNotEqual(primary_key, key())
        self.ctx.memory.record_execution("lab", original, "lab", "http://lab/", "completed")
        self.assertTrue(self.ctx.memory.execution_reusable("lab", original, 86400))
        self.assertFalse(self.ctx.memory.execution_reusable("lab", original, 0))

    def test_resume_preserves_request_method_and_body(self):
        payload = {"url": "http://lab/object", "method": "POST", "params": ["name"],
                   "form": {"name": "fixture"}}
        self.ctx.memory.remember_scan_task("lab", "scan", payload)
        reopened = Memory(self.ctx.memory.db_path)
        self.assertEqual(reopened.remembered_scan_tasks("lab"), [("scan", payload)])

    def test_selection_unknown_stays_eligible(self):
        self.assertTrue(applicability("dom_xss", [], None, "")[0])
        self.assertFalse(applicability("dom_xss", [], None, "application/json")[0])

    def test_benchmark_counts_false_positives_and_misses(self):
        metrics = summarize([
            dict(vulnerable=True, detected=True, reproduced=True, requests=5),
            dict(vulnerable=False, detected=True, reproduced=False, requests=3),
            dict(vulnerable=True, detected=False, reproduced=False, requests=2)])
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["requests_per_verified_finding"], 10)
