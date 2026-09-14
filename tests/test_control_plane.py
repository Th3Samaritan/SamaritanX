"""Offline regression tests for scheduling, transports, evidence and lifecycle."""
import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from core.evidence import redact, write_bundle, verify_bundle
from core.job_store import JobStore
from core.memory import Memory
from core.task_queue import TaskQueue
from core.transport import TransportController, TransportBlocked, current_transport, guard_browser, create_subprocess_exec, BudgetedWriter
from core.scan_execution import RequestBudget, request_budget
from core.verification import report_freshness, fresh_check
from core.workflow_policy import evaluate
from core.proof_gate import is_verified


class ControlPlaneTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.cfg = {"stealth": {"rate_limit_rps": 100000, "per_host_rps": 100000},
                    "transport": {"operation_budget": 3}}

    async def test_queue_suppresses_pending_duplicates(self):
        queue = TaskQueue(JobStore(self.path / "jobs.db"))
        await queue.put("scan", {"url": "http://lab/"}, target="lab")
        await queue.put("scan", {"url": "http://lab/"}, target="lab")
        self.assertEqual(queue.qsize(), 1)
        task = await queue.get()
        await queue.put("scan", task.payload, target="lab")
        self.assertTrue(queue.empty())
        queue.task_done("failed", "fixture")
        await queue.join()
        self.assertEqual(queue.store.list("lab")[0]["status"], "failed")

    async def test_queued_jobs_survive_restart(self):
        store = JobStore(self.path / "jobs.db")
        queue = TaskQueue(store)
        await queue.put("scan", {"url": "http://lab/", "method": "POST"}, target="lab")
        recovered = TaskQueue(JobStore(self.path / "jobs.db"))
        await recovered.restore("lab")
        task = await recovered.get()
        self.assertEqual(task.payload["method"], "POST")
        recovered.task_done()
        await recovered.join()

    def test_lease_fencing_and_conservative_recovery(self):
        store = JobStore(self.path / "jobs.db")
        store.enqueue("a", "lab", "scan", {}, 1)
        old_owner = store.claim("a", -1)
        self.assertFalse(store.renew("a", old_owner, 60))
        self.assertFalse(store.finish("a", old_owner, "completed"))
        self.assertEqual(store.recover("lab"), [])
        self.assertEqual(store.list("lab")[0]["status"], "interrupted")
        store.enqueue("a", "lab", "scan", {}, 1)
        owner = store.claim("a", 60)
        self.assertFalse(store.finish("a", old_owner, "completed"))
        self.assertTrue(store.finish("a", owner, "completed"))

    async def test_lease_heartbeat_prevents_recovery(self):
        store = JobStore(self.path / "jobs.db")
        queue = TaskQueue(store, lease_seconds=0.09)
        await queue.put("scan", {}, target="lab")
        task = await queue.get()
        execution = asyncio.create_task(asyncio.sleep(0.15))
        heartbeat = asyncio.create_task(queue.maintain_lease(task, execution))
        await execution
        self.assertEqual(store.recover("lab"), [])
        heartbeat.cancel()
        await asyncio.gather(heartbeat, return_exceptions=True)
        queue.task_done()

    async def test_budget_is_shared_across_transport_types(self):
        controller = TransportController(self.cfg)
        token = request_budget.set(RequestBudget(2))
        try:
            await controller.admit("http://lab/", "http")
            await controller.admit("http://lab/", "browser")
            with self.assertRaises(RuntimeError):
                await controller.admit("http://lab/", "raw_write")
            self.assertTrue(request_budget.get().exhausted)
        finally:
            request_budget.reset(token)
        self.assertEqual(controller.used, 2)

    async def test_scope_denial_consumes_no_operation(self):
        scope = SimpleNamespace(allows=lambda url: (False, "fixture"))
        controller = TransportController(self.cfg, scope)
        with self.assertRaises(TransportBlocked):
            await controller.admit("http://outside/")
        self.assertEqual(controller.used, 0)

    async def test_external_tool_never_starts_unmetered(self):
        controller = TransportController(self.cfg)
        token = current_transport.set(controller)
        try:
            with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as spawn:
                with self.assertRaises(TransportBlocked):
                    await create_subprocess_exec("nuclei", "-u", "http://lab/")
                spawn.assert_not_called()
        finally:
            current_transport.reset(token)

    async def test_browser_routes_share_budget_and_abort(self):
        controller = TransportController(self.cfg)
        context = SimpleNamespace(route=AsyncMock(), route_web_socket=AsyncMock())
        token = current_transport.set(controller)
        try:
            await guard_browser(context)
            handler = context.route.call_args.args[1]
            route = SimpleNamespace(request=SimpleNamespace(url="http://lab/"),
                                    continue_=AsyncMock(), abort=AsyncMock())
            controller.cancel()
            await handler(route)
            route.abort.assert_awaited_once()
            route.continue_.assert_not_called()
        finally:
            current_transport.reset(token)

    async def test_raw_write_waits_for_budget_before_sending(self):
        controller = TransportController(self.cfg)
        writer = SimpleNamespace(write=lambda data: self.fail("must not send"), drain=AsyncMock())
        guarded = BudgetedWriter(writer, controller, "http://lab/")
        guarded.write(b"fixture")
        controller.cancel()
        with self.assertRaises(TransportBlocked):
            await guarded.drain()

    async def test_websocket_send_is_metered(self):
        from core.transport import BudgetedWebSocket
        controller = TransportController(self.cfg)
        socket = SimpleNamespace(send=AsyncMock())
        managed = BudgetedWebSocket(socket, controller, "ws://lab/")
        await managed.send("fixture")
        controller.cancel()
        with self.assertRaises(TransportBlocked):
            await managed.send("blocked")
        socket.send.assert_awaited_once_with("fixture")

    async def test_redirect_hop_uses_another_budget_unit(self):
        from core.http_client import StealthHttpClient
        cfg = dict(self.cfg, transport={"operation_budget": 1})
        http = StealthHttpClient(cfg)
        http.transport = TransportController(cfg)
        visited = []
        def handler(request):
            visited.append(request.url.path)
            return httpx.Response(302, headers={"location": "/next"})
        for client in http._clients:
            await client.aclose()
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler),
            event_hooks={"request": [http._transport_request_guard]}, follow_redirects=True)
        try:
            with self.assertRaises(TransportBlocked):
                await client.get("http://lab/start")
            self.assertEqual(visited, ["/start"])
        finally:
            await client.aclose()

    def test_evidence_redaction_and_integrity(self):
        finding = {"category": "fixture", "request": "GET /?token=abcd\nAuthorization: Bearer very-secret",
                   "metadata": {"poc": {"verified": True, "response_excerpt": "session-secret"}}}
        artifact = write_bundle(self.path, finding, secrets=["session-secret"])
        raw = Path(artifact["file"]).read_text(encoding="utf-8")
        for secret in ("abcd", "very-secret", "session-secret"):
            self.assertNotIn(secret, raw)
        self.assertTrue(verify_bundle(artifact["file"], artifact["sha256"]))
        Path(artifact["file"]).write_text("tampered", encoding="utf-8")
        self.assertFalse(verify_bundle(artifact["file"], artifact["sha256"]))
        self.assertEqual(redact({"password": "hidden"})["password"], "[REDACTED]")

    def test_refresh_keeps_history_and_reopens_fixed(self):
        memory = Memory(self.path / "memory.db")
        finding = {"target": "lab", "category": "xss", "title": "fixture", "url": "http://lab/",
                   "metadata": {"poc": {"verified": True, "response_excerpt": "old"}}}
        fid = memory.record_finding(finding)
        memory.set_finding_state(fid, "fixed", "patched in fixture")
        finding["metadata"]["poc"]["response_excerpt"] = "new"
        self.assertEqual(memory.record_finding(finding), fid)
        self.assertEqual(memory.finding_states("lab")[fid], "reopened")
        self.assertIn("old", json.dumps(memory.finding_history(fid)))
        self.assertEqual(memory.list_findings("lab")[0]["metadata"]["poc"]["response_excerpt"], "new")

    def test_expired_evidence_cannot_report(self):
        finding = {"metadata": {"poc": {"verified": True, "captured_at": 10, "response_excerpt": "fixture"}}}
        self.assertFalse(report_freshness(finding, max_age=10, now=30))
        self.assertFalse(is_verified(finding))

    async def test_failed_baseline_is_inconclusive(self):
        ctx = SimpleNamespace(http=SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(status=503, error=None))))
        checker = AsyncMock(return_value=True)
        self.assertIsNone(await fresh_check(ctx, {"url": "http://lab/"}, checker))
        checker.assert_not_called()

    async def test_static_marker_baseline_cannot_verify(self):
        ctx = SimpleNamespace(http=SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(
            status=200, error=None, response_body="documentation SX_abcd_OK"))))
        checker = AsyncMock(return_value=True)
        self.assertIsNone(await fresh_check(ctx, {"category": "rce", "url": "http://lab/"}, checker))
        checker.assert_not_called()

    async def test_expired_session_cannot_verify(self):
        ctx = SimpleNamespace(session=SimpleNamespace(is_authed=lambda: True),
            http=SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(status=401, error=None, response_body="login"))))
        checker = AsyncMock(return_value=True)
        self.assertIsNone(await fresh_check(ctx, {"url": "http://lab/"}, checker))
        checker.assert_not_called()

    async def test_inconsistent_replays_remain_inconclusive(self):
        from core.revalidate import revalidate, REVALIDATORS
        memory = Memory(self.path / "memory.db")
        fid = memory.record_finding({"target": "lab", "category": "fixture", "title": "fixture",
            "url": "http://lab/", "request": "GET http://lab/",
            "metadata": {"poc": {"verified": True, "response_excerpt": "old proof"}}})
        ctx = SimpleNamespace(memory=memory, target_slug="lab", workspace=self.path, config={}, session=None,
            dashboard=SimpleNamespace(event=lambda *args: None),
            http=SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(status=200, error=None, response_body="baseline"))))
        with patch.dict(REVALIDATORS, {"fixture": AsyncMock(side_effect=[True, False])}):
            result = await revalidate(ctx, memory.list_findings("lab"))
        self.assertEqual(result["skipped"], 1)
        self.assertFalse(is_verified(memory.list_findings("lab")[0]))
        self.assertEqual(memory.finding_states("lab")[fid], "inconclusive")

    async def test_reporting_integrates_coverage_and_evidence(self):
        from agents.reporting_agent import ReportingAgent
        from core.task_queue import Task
        from core.review import snapshot, render
        from rich.console import Console
        from io import StringIO
        memory = Memory(self.path / "memory.db")
        fid = memory.record_finding({"target": "lab", "category": "xss", "title": "Local fixture",
            "url": "http://lab/", "request": "GET http://lab/",
            "metadata": {"poc": {"verified": True, "response_excerpt": "captured local fixture"}}})
        memory.record_execution("lab", "key", "sqli", "http://lab/", "timed_out", "fixture timeout")
        memory.record_execution_context("lab", "key", {"method": "GET", "identity": "alice", "inputs": ["id"]})
        (self.path / "reports").mkdir()
        ctx = SimpleNamespace(memory=memory, target_slug="lab", target="lab", workspace=self.path,
            config={"reporting": {"format": ["markdown"]}}, session=None, http=SimpleNamespace(),
            dashboard=SimpleNamespace(_counters={}, event=lambda *args: None))
        with patch("core.llm.triage_impact", new=AsyncMock(return_value={})):
            await ReportingAgent().handle(Task(1, 1, "report", "lab"), ctx)
        report = (self.path / "reports" / "report.md").read_text(encoding="utf-8")
        self.assertIn("Scan coverage", report)
        self.assertIn("Evidence bundle SHA-256", report)
        data = snapshot(memory, "lab", fid)
        self.assertEqual(data["findings"][0]["evidence_integrity"], "valid")
        output = StringIO()
        render(Console(file=output, width=160), data)
        self.assertIn("alice", output.getvalue())
        self.assertIn("timed_out", output.getvalue())
        artifact = memory.list_findings("lab")[0]["metadata"]["evidence_bundle"]
        Path(artifact["file"]).write_text("tampered", encoding="utf-8")
        self.assertEqual(snapshot(memory, "lab", fid)["findings"][0]["proof"][0], "candidate")

    def test_workflow_owner_role_and_state(self):
        policy = [{"action": "approve", "roles": ["reviewer"], "from_states": ["pending"],
                   "to_states": ["approved"], "owner_only": True}]
        observation = dict(action="approve", role="reviewer", actor="a", owner="a",
                           before="pending", after="approved", evidence="fixture before and after")
        self.assertEqual(evaluate(policy, observation)["result"], "allowed")
        observation["actor"] = "b"
        self.assertEqual(evaluate(policy, observation)["result"], "violation")
        observation["after"] = "pending"
        self.assertEqual(evaluate(policy, observation)["result"], "inconclusive")
