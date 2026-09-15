"""Offline acceptance tests for version selection, fair dispatch and durable budgets."""
import asyncio
import hashlib
import io
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from core.operation_ledger import OperationLedger
from core.task_queue import TaskQueue
from core.transport import TransportController, TransportBlocked, operation_purpose
from core.tool_installation import install_archive, active_binary, rollback


class VersionTests(unittest.TestCase):
    def test_versions_rollback_checksum_and_interrupted_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def archive(body):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as bundle:
                    bundle.writestr("ffuf.exe", body)
                data = buffer.getvalue()
                return data, hashlib.sha256(data).hexdigest()
            first, sha = archive(b"fixture one")
            install_archive(root, "ffuf", "v1", first, sha)
            second, sha2 = archive(b"fixture two")
            with self.assertRaises(ValueError):
                install_archive(root, "ffuf", "v2", second, sha)
            self.assertEqual(active_binary(root, "ffuf").read_bytes(), b"fixture one")
            install_archive(root, "ffuf", "v2", second, sha2, activate_now=False)
            from core.tool_installation import activate
            with patch("core.tool_installation.os.replace", side_effect=OSError("interrupted")):
                with self.assertRaises(OSError):
                    activate(root, "ffuf", "v2")
            self.assertEqual(active_binary(root, "ffuf").read_bytes(), b"fixture one")
            activate(root, "ffuf", "v2")
            self.assertEqual(active_binary(root, "ffuf").read_bytes(), b"fixture two")
            self.assertEqual(rollback(root, "ffuf"), "v1")
            active_binary(root, "ffuf").write_bytes(b"corrupted")
            with self.assertRaises(ValueError):
                active_binary(root, "ffuf")

    def test_partial_archive_never_activates(self):
        with tempfile.TemporaryDirectory() as directory:
            data = b"interrupted download"
            with self.assertRaises(zipfile.BadZipFile):
                install_archive(directory, "ffuf", "v1", data, hashlib.sha256(data).hexdigest())
            self.assertFalse((Path(directory) / "active.json").exists())

    def test_concurrent_durable_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.sqlite"
            stores = [OperationLedger(path, "run", 7, {"baseline": 1, "verification": 1}) for _ in range(4)]
            with ThreadPoolExecutor(max_workers=4) as executor:
                results = list(executor.map(lambda i: stores[i % 4].take("active"), range(30)))
            self.assertEqual(sum(r is not None for r in results), 5)
            resumed = OperationLedger(path, "run", 100, {"baseline": 0, "verification": 0})
            self.assertEqual(resumed.limit, 7)
            self.assertIsNone(resumed.take("active"))
            self.assertEqual(resumed.take("baseline"), 6)
            self.assertEqual(resumed.take("verification"), 7)
            self.assertIsNone(resumed.take("verification"))


class SchedulingTests(unittest.IsolatedAsyncioTestCase):
    async def test_busy_origin_and_scanner_cannot_starve_others(self):
        queue = TaskQueue()
        for i in range(10):
            await queue.put("scan.a", {"url": f"http://one.test/{i}"}, priority=1)
        await queue.put("scan.b", {"url": "http://one.test/"}, priority=9)
        await queue.put("scan.a", {"url": "http://two.test/"}, priority=9)
        first = await queue.get(); queue.task_done()
        second = await queue.get(); queue.task_done()
        third = await queue.get(); queue.task_done()
        self.assertEqual(first.kind, "scan.a")
        self.assertIn("two.test", second.payload["url"])
        self.assertEqual(third.kind, "scan.b")

    async def test_cancelled_admission_stays_charged_on_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.sqlite"
            cfg = {"transport": {"operation_budget": 3, "baseline_reserve": 1, "verification_reserve": 1},
                   "stealth": {"rate_limit_rps": 100, "per_host_rps": 100}}
            controller = TransportController(cfg)
            controller.bind_ledger(path, "run")
            with patch("core.transport.asyncio.sleep", side_effect=asyncio.CancelledError):
                with self.assertRaises(asyncio.CancelledError):
                    await controller.admit("http://fixture.test/")
            resumed = TransportController(cfg)
            resumed.bind_ledger(path, "run", resume=True)
            self.assertEqual(resumed.used, 1)
            with self.assertRaises(TransportBlocked):
                await resumed.admit("http://fixture.test/")
            for purpose in ("baseline", "verification"):
                token = operation_purpose.set(purpose)
                try:
                    await resumed.admit("http://fixture.test/")
                finally:
                    operation_purpose.reset(token)
            self.assertEqual(resumed.used, 3)


class ResumeAndSlotTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_waiter_returns_slot(self):
        from core.task_queue import FairSlots
        slots = FairSlots(1)
        entered = asyncio.Event()
        release = asyncio.Event()
        async def holder():
            async with slots.slot("http://one.test", "a"):
                entered.set()
                await release.wait()
        async def waiter():
            async with slots.slot("http://two.test", "b"):
                pass
        first = asyncio.create_task(holder())
        await entered.wait()
        cancelled = asyncio.create_task(waiter())
        await asyncio.sleep(0)
        cancelled.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await cancelled
        release.set()
        await first
        await asyncio.wait_for(waiter(), 1)
        self.assertEqual(slots.available, 1)
        self.assertFalse(slots.waiters)

    def test_resume_keeps_run_identity_and_manifest_write_fails_closed(self):
        from core.run_manifest import write_manifest
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = write_manifest({}, "fixture", root)
            second = write_manifest({}, "fixture", root, resume=True)
            self.assertEqual(first["run_id"], second["run_id"])
            with self.assertRaises(ValueError):
                write_manifest({}, "other", root, resume=True)
            with patch("core.tool_installation.os.replace", side_effect=OSError("interrupted")):
                with self.assertRaises(OSError):
                    write_manifest({}, "fixture", root)
            import json
            self.assertEqual(json.loads((root / "run_manifest.json").read_text())["run_id"], first["run_id"])

    def test_pinned_template_installation_rejects_bad_checksum(self):
        from bench.install_smoke_tools import main
        with tempfile.TemporaryDirectory() as directory:
            args = ["install", "--templates-only", "--template-version", "v1", "--template-sha256", "0" * 64, "--destination", directory]
            with patch("sys.argv", args), patch("bench.install_smoke_tools.fetch", return_value=b"bad archive"):
                with self.assertRaises(ValueError):
                    main()
            self.assertFalse((Path(directory) / "nuclei-template-versions").exists())


class LegacyResumeTests(unittest.TestCase):
    def test_missing_ledger_cannot_silently_reset_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                OperationLedger(Path(directory) / "ledger.sqlite", "old-run", 100,
                                {"baseline": 0, "verification": 0}, resume=True)
