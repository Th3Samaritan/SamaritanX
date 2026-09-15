"""Exercise the real local proxy with mocked upstream HTTP, never remote targets."""
import asyncio
import ssl
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock

import httpx

from core.external_tools import Gateway, ManagedProcess, command
from core.transport import TransportBlocked, TransportController, external_tool_path
from pathlib import Path
import os


class AdapterCommands(unittest.TestCase):
    def test_workspace_binary_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ("ffuf.exe" if os.name == "nt" else "ffuf")
            path.touch()
            self.assertEqual(external_tool_path("ffuf", {"external_tools": {"binary_dir": directory}}), str(path.resolve()))

    def test_remote_template_paths_are_rejected(self):
        with self.assertRaises(TransportBlocked):
            command(["nuclei", "-u", "http://lab", "-o", "out", "-t", "https://outside.test/template.yaml"], "http://localhost:1")

    def test_supported_commands_have_mandatory_proxy_flags(self):
        proxy = "http://localhost:1234"
        self.assertIn("-x", command(["ffuf", "-u", "http://lab/FUZZ", "-w", "words", "-o", "out"], proxy))
        argv = command(["nuclei", "-u", "http://lab/", "-o", "out"], proxy)
        self.assertIn("-proxy-internal", argv)
        self.assertEqual(argv[argv.index("-type") + 1], "http")
        self.assertIn("-proxy", command(["subfinder", "-d", "lab"], proxy))

    def test_subfinder_defaults_to_reviewed_http_source(self):
        argv = command(["subfinder", "-d", "fixture.test"], "http://localhost:1")
        self.assertEqual(argv[argv.index("-s") + 1], "hackertarget")
        explicit = command(["subfinder", "-d", "fixture.test", "-s", "hackertarget"], "http://localhost:1")
        self.assertEqual(explicit.count("-s"), 1)

    def test_subfinder_blocks_direct_database_and_unreviewed_sources(self):
        for source in ("crtsh", "crtsh,hackertarget", "hackertarget,crtsh", "all", "sources.txt", "", "hackertarget,"):
            with self.subTest(source=source), self.assertRaises(TransportBlocked):
                command(["subfinder", "-d", "fixture.test", "-s", source], "http://localhost:1")

    def test_unsupported_commands_fail_closed(self):
        for argv in ([], ["python", "script.py"], ["amass", "enum", "-passive", "-norecursive", "-d", "lab"],
                     ["nuclei", "-u", "http://lab"],
                     ["nuclei", "-u", "http://lab", "-o", "out", "-code"],
                     ["subfinder", "-d", "lab", "-d", "other"]):
            with self.subTest(argv=argv), self.assertRaises(TransportBlocked):
                command(argv, "http://localhost:1")


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.controller = TransportController({"stealth": {"rate_limit_rps": 10000, "per_host_rps": 10000}})
        self.gateway = Gateway(self.controller, "ffuf", self.tmp.name)
        await self.gateway.upstream.aclose()
        self.requests = []

        def respond(request):
            self.requests.append(request)
            class Body(httpx.AsyncByteStream):
                async def __aiter__(self):
                    yield b"local fixture"
            return httpx.Response(200, stream=Body())

        self.gateway.upstream = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        self.proxy = await self.gateway.start()

    async def asyncTearDown(self):
        await self.gateway.close()
        self.tmp.cleanup()

    async def test_http_and_https_are_counted_and_forwarded(self):
        context = ssl.create_default_context(cafile=str(self.gateway.ca_path))
        async with httpx.AsyncClient(proxy=self.proxy, verify=context, trust_env=False) as client:
            for scheme in ("http", "https"):
                response = await client.get(f"{scheme}://lab.test/resource")
                self.assertEqual(response.status_code, 200, self.gateway.failure)
                self.assertEqual(response.text, "local fixture")
        self.assertEqual(self.controller.used, 2)
        self.assertEqual(self.gateway.budget.used, 2)
        self.assertTrue(all("proxy-authorization" not in r.headers for r in self.requests))

    async def test_budget_prevents_second_forward(self):
        self.gateway.budget.limit = 1
        async with httpx.AsyncClient(proxy=self.proxy, trust_env=False) as client:
            self.assertEqual((await client.get("http://lab.test/")).status_code, 200)
            self.assertEqual((await client.get("http://lab.test/")).status_code, 502)
        self.assertEqual(len(self.requests), 1)
        self.assertTrue(self.gateway.budget.exhausted)

    async def test_scope_denial_never_reaches_upstream(self):
        self.controller.check_scope = AsyncMock(side_effect=TransportBlocked("scope denied"))
        async with httpx.AsyncClient(proxy=self.proxy, trust_env=False) as client:
            self.assertEqual((await client.get("http://outside.test/")).status_code, 502)
        self.assertEqual(self.requests, [])

    async def test_redirect_destination_is_checked_separately(self):
        def respond(request):
            self.requests.append(request)
            return httpx.Response(302, headers={"Location": "http://outside.test/"},
                                  stream=httpx.ByteStream(b""))

        async def check(url, kind):
            if "outside.test" in url:
                raise TransportBlocked("scope denied")

        await self.gateway.upstream.aclose()
        self.gateway.upstream = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        self.controller.check_scope = AsyncMock(side_effect=check)
        async with httpx.AsyncClient(proxy=self.proxy, trust_env=False, follow_redirects=True) as client:
            self.assertEqual((await client.get("http://lab.test/")).status_code, 502)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.controller.check_scope.await_count, 2)

    async def test_cancellation_kills_process_and_releases_resources(self):
        finished = asyncio.Event()
        process = Mock(returncode=None)

        async def wait():
            await finished.wait()
            return process.returncode

        def kill():
            process.returncode = -9
            finished.set()

        process.wait = wait
        process.kill = Mock(side_effect=kill)
        managed = ManagedProcess(process, self.gateway, self.tmp)
        self.controller.external_processes.add(managed)
        self.controller.cancel()
        await managed._finish()
        process.kill.assert_called_once()
        self.assertFalse(self.gateway.server.is_serving())
        self.assertFalse(self.controller.external_processes)

    async def test_mutation_requires_aggressive(self):
        async with httpx.AsyncClient(proxy=self.proxy, trust_env=False) as client:
            self.assertEqual((await client.post("http://lab.test/", content="test")).status_code, 502)
        self.assertEqual(self.requests, [])

    async def test_authentication_and_host_mismatch(self):
        port = self.gateway.server.sockets[0].getsockname()[1]
        for auth, status in (("", b"407"), (f"Proxy-Authorization: {self.gateway.auth}\r\n", b"502")):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"GET http://lab.test/ HTTP/1.1\r\nHost: other.test\r\n{auth}\r\n".encode())
            await writer.drain()
            self.assertIn(status, await reader.read())
            writer.close()
            await writer.wait_closed()
        self.assertEqual(self.requests, [])

    async def test_finished_process_releases_gateway_and_files(self):
        process = AsyncMock()
        process.returncode = 0
        process.wait.return_value = 0
        managed = ManagedProcess(process, self.gateway, self.tmp)
        self.controller.external_processes.add(managed)
        self.assertEqual(await managed.wait(), 0)
        self.assertFalse(self.gateway.server.is_serving())
        self.assertNotIn(managed, self.controller.external_processes)


class SmokeDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    async def test_timeout_preserves_partial_output_and_reaps_process(self):
        from bench.adapter_smoke import collect_output, SmokeTimeout
        import sys
        process = await asyncio.create_subprocess_exec(sys.executable, "-u", "-c",
            "import sys,time; print('starting', flush=True); print('waiting for fixture',file=sys.stderr,flush=True); time.sleep(30)",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            with self.assertRaises(SmokeTimeout) as caught:
                await collect_output(process, 1)
            self.assertIn("starting", caught.exception.stdout)
            self.assertIn("waiting for fixture", caught.exception.stderr)
            self.assertIsNotNone(process.returncode)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
