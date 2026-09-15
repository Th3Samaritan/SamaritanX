"""Regression tests for local isolation and honest assessment outcomes."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
import yaml
from core.assessment_profile import load_profile
from core.assessment_runner import run_profile
from core.scope import ScopePolicy
from core.transport import TransportController, TransportBlocked
from bench.juice_shop_score import catalog, score
from bench.lab_runtime import DockerLab


class ProfileTests(unittest.TestCase):
    def test_invalid_profile_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "profile.yaml"
            p.write_text(yaml.safe_dump({"version": 1, "phases": [{"kind": "local-audit", "id": "../escape", "collect": True}]}))
            with self.assertRaises(ValueError): load_profile(p)
            self.assertEqual(list(Path(d).iterdir()), [p])

    def test_phases_keep_partial_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "profile.yaml"
            p.write_text(yaml.safe_dump({"version": 1, "output": "runs", "phases": [{"kind": "local-audit", "id": "local", "collect": True}]}))
            with patch("core.assessment_runner.execute_phase", return_value={"status": "partial"}):
                result, code = run_profile(p)
            self.assertEqual(code, 2)
            self.assertEqual(result["status"], "partial")
            self.assertTrue((Path(result["output"]) / "assessment-run.json").is_file())

    def test_offline_snapshot_workflow(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "profile.yaml"
            (Path(d) / "snapshot.json").write_text(json.dumps({"platform": "linux", "files": []}))
            p.write_text(yaml.safe_dump({"version": 1, "output": "runs", "phases": [{"kind": "local-audit", "id": "local", "snapshot": "snapshot.json"}]}))
            result, code = run_profile(p)
            self.assertEqual(code, 0)
            self.assertEqual(result["phases"][0]["candidates"], 0)


class IsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_local_provider_bypass_denied(self):
        controller = TransportController({"recon": {"local_only": True}}, ScopePolicy(allow_globs=["127.0.0.1"]), "http://127.0.0.1:3100")
        await controller.check_scope("http://127.0.0.1:3100/test")
        for url in ("https://api.github.com/user", "http://127.0.0.1:3200", "https://127.0.0.1:3100"):
            with self.assertRaises(TransportBlocked): await controller.check_scope(url, "external_provider")

    async def test_local_recon_keeps_port_and_skips_collectors(self):
        from agents.recon_agent import ReconAgent
        from core.task_queue import Task
        agent = ReconAgent()
        with tempfile.TemporaryDirectory() as d:
            ctx = SimpleNamespace(target="http://127.0.0.1:3100", target_slug="lab", resume=False,
                config={"recon": {"local_only": True}}, dashboard=Mock(), memory=Mock(), queue=SimpleNamespace(put=AsyncMock()),
                http=SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(error=None, status=200, response_body="lab", response_headers={}))), workspace=Path(d))
            with patch.object(agent, "_passive_http", new=AsyncMock()) as passive:
                await agent.handle(SimpleNamespace(payload={}), ctx)
            passive.assert_not_called()
            ctx.http.get.assert_awaited_once_with("http://127.0.0.1:3100")
            self.assertEqual(ctx.queue.put.await_count, 2)


class BenchmarkTests(unittest.TestCase):
    def test_candidates_and_presolved_not_progress(self):
        before = catalog({"data": [{"id": 1, "solved": True}, {"id": 2, "solved": False}]})
        after = catalog({"data": [{"id": 1, "solved": True}, {"id": 2, "solved": True}]})
        result = score(before, after, [{"category": "sqli"}], [])
        self.assertEqual(result["newly_solved"], ["2"])
        self.assertEqual(result["verified_findings"], 0)
        self.assertEqual(result["candidates"], 1)
        self.assertEqual(score(after, before, [], [])["status"], "invalid")
        self.assertEqual(score(before, before, [], [], healthy=False)["status"], "invalid")

    def test_missing_inventory_not_green(self):
        for payload in ({}, {"data": []}, {"data": [{"id": 1, "solved": "false"}]}):
            with self.assertRaises(ValueError): catalog(payload)

    def test_cleanup_requires_ownership(self):
        lab = DockerLab(Path("unused"))
        lab.created = True
        with patch("bench.lab_runtime.command", return_value=json.dumps([{"Config": {"Labels": {}}}])) as command:
            with self.assertRaises(RuntimeError): lab.close()
        self.assertEqual(command.call_count, 1)


class MobileExtensionTests(unittest.TestCase):
    def test_macho_metadata_and_invalid_bounds(self):
        import struct
        from assessments.mobile_metadata import macho
        safe = struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0x200000, 0)
        self.assertTrue(macho(safe)["pie_flag"])
        self.assertEqual(macho(safe)["signature_validity"], "unavailable")
        bad = struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 1, 999, 0, 0)
        with self.assertRaises(ValueError): macho(bad)

    def test_android_policy_pair(self):
        import zipfile
        from assessments.mobile_static import assess
        with tempfile.TemporaryDirectory() as d:
            for allowed in ("true", "false"):
                apk = Path(d) / (allowed + ".apk")
                with zipfile.ZipFile(apk, "w") as archive:
                    archive.writestr("AndroidManifest.xml", '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.app"><application android:allowBackup="false" android:networkSecurityConfig="@xml/network"/></manifest>')
                    archive.writestr("res/xml/network.xml", '<network-security-config><base-config cleartextTrafficPermitted="' + allowed + '"/></network-security-config>')
                report = assess(apk)
                self.assertEqual(any(c["category"] == "android_network_policy" for c in report["candidates"]), allowed == "true")


class OwnedSessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_created_session_closed_for_both_platforms(self):
        import httpx
        from assessments.mobile_runtime import assess_owned
        for platform in ("android", "ios"):
            requests = []
            def handler(request):
                requests.append((request.method, request.url.path))
                path = request.url.path
                if path == "/session": value = {"sessionId": "owned", "capabilities": {"platformName": platform}}
                elif path.endswith("current_package"): value = "test.app"
                elif path.endswith("execute/sync"): value = {"bundleId": "test.app"}
                elif path.endswith("source"): value = "<hierarchy/>"
                elif path.endswith("contexts"): value = ["NATIVE_APP"]
                else: value = None
                return httpx.Response(200, json={"value": value})
            report = await assess_owned("http://127.0.0.1:4723", platform, "test.app", "device-1", aggressive=True, transport=httpx.MockTransport(handler))
            self.assertEqual(report["cleanup"], "completed")
            self.assertIn(("DELETE", "/session/owned"), requests)
            self.assertEqual(report["status"], "completed")

    async def test_create_requires_explicit_mutation_policy(self):
        from assessments.mobile_runtime import assess_owned
        with self.assertRaises(ValueError):
            await assess_owned("http://127.0.0.1:4723", "android", "test.app", "device-1")


class RuntimeDecodingTests(unittest.TestCase):
    def test_command_decodes_utf8_and_survives_missing_stderr(self):
        from bench import lab_runtime
        seen = {}

        def fake_run(args, **kwargs):
            seen.update(kwargs)
            return SimpleNamespace(returncode=1, stdout="", stderr=None)

        with patch("bench.lab_runtime.subprocess.run", side_effect=fake_run):
            with self.assertRaises(RuntimeError):
                lab_runtime.command("docker", "info", timeout=5)
        self.assertEqual(seen.get("encoding"), "utf-8")
        self.assertEqual(seen.get("errors"), "replace")

    def test_command_returns_stdout_when_present(self):
        from bench import lab_runtime
        with patch("bench.lab_runtime.subprocess.run",
                   return_value=SimpleNamespace(returncode=0, stdout="29.1.3\n", stderr="")):
            self.assertEqual(lab_runtime.command("docker", "info"), "29.1.3")
