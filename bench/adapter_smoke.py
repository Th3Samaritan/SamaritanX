"""Run actual adapter binaries against localhost and an in-process passive-provider stub."""
import asyncio
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
from unittest.mock import patch

import httpx

from core.external_tools import Gateway
from core.transport import TransportController, current_transport, create_subprocess_exec


class LocalHandler(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.hits.append(self.path)
        body = b"SX_LOCAL_ADAPTER_SMOKE" if self.path == "/hit" else b"missing"
        self.send_response(200 if self.path == "/hit" else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


async def run():
    root = Path(__file__).resolve().parents[1]
    tools = root / "workspace" / "tools"
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    results = {}
    try:
        with tempfile.TemporaryDirectory(prefix="sx-smoke-") as directory:
            directory = Path(directory)
            words = directory / "words.txt"
            words.write_text("hit\nmissing\n")
            template = directory / "local.yaml"
            template.write_text('''id: sx-local-adapter-smoke
info:
  name: Local adapter fixture
  author: samaritanx
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/hit"
    matchers:
      - type: word
        words:
          - "SX_LOCAL_ADAPTER_SMOKE"
''')
            output = directory / "output"
            commands = {
                "ffuf": ["ffuf", "-u", base + "/FUZZ", "-w", str(words), "-o", str(output), "-of", "json", "-s"],
                "nuclei": ["nuclei", "-u", base, "-t", str(template), "-o", str(output), "-jsonl", "-silent"],
                "subfinder": ["subfinder", "-d", "fixture.test", "-s", "crtsh", "-silent"],
            }
            for name, args in commands.items():
                output.unlink(missing_ok=True)
                controller = TransportController({"external_tools": {"enabled": True, "binary_dir": str(tools)},
                                                   "stealth": {"rate_limit_rps": 100, "per_host_rps": 100}})
                upstream_requests = []

                def provider(request):
                    upstream_requests.append(str(request.url))
                    # All subfinder traffic ends here, including unexpected endpoints.
                    if request.url.host == "crt.sh":
                        return httpx.Response(200, stream=httpx.ByteStream(b'[{"name_value":"found.fixture.test"}]'),
                                              headers={"content-type": "application/json"})
                    return httpx.Response(403, stream=httpx.ByteStream(b"outside local fixture"))

                original_start = Gateway.start

                async def start(gateway):
                    if name == "subfinder":
                        await gateway.upstream.aclose()
                        gateway.upstream = httpx.AsyncClient(transport=httpx.MockTransport(provider))
                    return await original_start(gateway)

                token = current_transport.set(controller)
                try:
                    with patch.object(Gateway, "start", start):
                        process = await create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                               stderr=asyncio.subprocess.PIPE)
                        stdout, stderr = await asyncio.wait_for(process.communicate(), 90)
                    artifact = output.read_text(encoding="utf-8") if output.exists() else stdout.decode(errors="replace")
                    expected = {"ffuf": "/hit", "nuclei": "sx-local-adapter-smoke", "subfinder": "found.fixture.test"}[name]
                    passed = process.returncode == 0 and controller.used > 0 and expected in artifact
                    results[name] = {"passed": passed, "exit_code": process.returncode,
                                     "operations": controller.used, "upstream_requests": upstream_requests,
                                     "stdout": stdout.decode(errors="replace")[-3000:],
                                     "stderr": stderr.decode(errors="replace")[-3000:]}
                except Exception as exc:
                    results[name] = {"passed": False, "error": str(exc), "operations": controller.used,
                                     "upstream_requests": upstream_requests}
                finally:
                    current_transport.reset(token)
                print(name, json.dumps(results[name]), flush=True)
    finally:
        server.shutdown()
        server.server_close()
    path = root / "workspace" / "adapter-smoke.json"
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return all(result["passed"] for result in results.values())


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(run()) else 1)
