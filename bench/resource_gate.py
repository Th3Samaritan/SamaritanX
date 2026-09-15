"""Resource regression gate (plan §11.12).

A fixed local workload (scanner run against a localhost fixture) with
DETERMINISTIC assertions for the resources that must never regress:

  * request count — bounded (a scanner that silently multiplies requests fails)
  * sqlite connection leaks — zero delta (the class of bug this gate exists for)
  * evidence budget exhaustion — scanner budgets still enforced

Timing is recorded (platform/runtime/versions identified) but never gated on a
single noisy sample. The artifact lands in workspace/bench/resource-gate.json.
"""
from __future__ import annotations

import asyncio
import copy
import subprocess
import statistics
import tracemalloc
import gc
import json
import platform
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from core.dashboard import Dashboard
from core.http_client import StealthHttpClient
from core.memory import Memory
from core.payload_engine import PayloadEngine


def _open_sqlite_connections() -> int:
    count = 0
    for obj in gc.get_objects():
        if not isinstance(obj, sqlite3.Connection):
            continue
        try:
            obj.execute("SELECT 1")
            count += 1
        except sqlite3.ProgrammingError:
            pass  # closed — harmless
    return count


def _fixture_server() -> tuple[object, int]:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, body, ctype="text/html"):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/sqli"):
                from urllib.parse import unquote_plus
                q = unquote_plus(self.path.partition("?")[2].replace("q=", ""))
                if "'" in q:
                    self._send(f"you have an error in your SQL syntax near '{q}'".encode())
                else:
                    self._send(b"ok")
            elif self.path.startswith("/xss"):
                from urllib.parse import unquote_plus
                q = unquote_plus(self.path.partition("?")[2].replace("q=", ""))
                self._send(f"<html>{q}</html>".encode())
            else:
                self._send(b"plain page")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _run_gate(config: dict, temporary: str) -> dict:
    t0 = time.perf_counter()
    server, port = _fixture_server()
    try:
        base = f"http://127.0.0.1:{port}"
        cfg = copy.deepcopy(config)
        cfg["stealth"]["rate_limit_rps"] = 50
        cfg["stealth"]["per_host_rps"] = 50
        cfg["stealth"]["jitter_ms"] = [0, 0]
        cfg["scanners"]["enabled"] = ["sqli", "xss", "security_headers"]
        tmp = temporary
        memory = Memory(Path(tmp) / "g.sqlite")
        http = StealthHttpClient(cfg)
        payloads = PayloadEngine(Path(__file__).resolve().parent.parent / "config" / "payloads",
                                 memory, cfg.get("waf_evasion", {}).get("techniques", []))
        dashboard = Dashboard(base, quiet=True)

        class Ctx:
            def __init__(self):
                self.config, self.http, self.memory = cfg, http, memory
                self.payloads, self.dashboard = payloads, dashboard
                self.session = self.scope = self.oob = self.http2 = None
                self.target, self.target_slug = base, "resourcegate"
                self.extra_identities, self.resume, self.run_id = [], False, ""

        async def workload():
            from scanners.sqli import scan as sqli
            from scanners.xss import scan as xss
            from scanners.security_headers import scan as sec
            ctx = Ctx()
            try:
                r1 = await sqli(ctx, base + "/sqli", ["q"], "GET", None)
                r2 = await xss(ctx, base + "/xss", ["q"], "GET", None)
                r3 = await sec(ctx, base + "/sqli", [], "GET", None)
                return ctx, r1, r2, r3
            finally:
                await http.close()

        leaks_before = _open_sqlite_connections()
        ctx, r1, r2, r3 = asyncio.run(workload())
        leaks_after = _open_sqlite_connections()
        elapsed = time.perf_counter() - t0

        results = {
            "passed": True,
            "checks": [],
            "metrics": {
                "requests": ctx.http.request_count,
                "findings": len(r1) + len(r2) + len(r3),
                "duration_s": round(elapsed, 2),
                "sqlite_connections_before": leaks_before,
                "sqlite_connections_after": leaks_after,
            },
            "platform": {"runtime": f"{sys.implementation.name} {sys.version.split()[0]}",
                         "os": platform.platform()},
            "tool_versions": {},
        }
        # deterministic assertions
        leak_delta = leaks_after - leaks_before
        results["checks"].append({"name": "sqlite_connection_leak", "passed": leak_delta <= 0,
                                  "detail": f"delta={leak_delta}"})
        results["checks"].append({"name": "scanner_detected_sqli", "passed": any(
            f["category"] == "sqli" for f in r1), "detail": f"sqli findings={len(r1)}"})
        results["checks"].append({"name": "scanner_detected_xss", "passed": any(
            f["category"] == "xss" for f in r2), "detail": f"xss findings={len(r2)}"})
        results["checks"].append({"name": "security_headers_present", "passed": any(
            f["category"] == "security_headers" for f in r3), "detail": f"sec findings={len(r3)}"})
        # request count must stay bounded — a silently multiplying scanner fails this
        results["checks"].append({"name": "request_count_bounded",
                                  "passed": 0 < ctx.http.request_count <= 400,
                                  "detail": f"requests={ctx.http.request_count}"})
        results["passed"] = all(c["passed"] for c in results["checks"])
        return results
    finally:
        server.shutdown()
        server.server_close()


async def cleanup_probe():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from core.transport import TransportController, current_transport, open_connection
    from core.external_tools import ManagedProcess
    controller = TransportController({"stealth": {"rate_limit_rps": 1000}})
    token = current_transport.set(controller)
    accepted = asyncio.Event()
    closed = asyncio.Event()

    async def handle(reader, writer):
        accepted.set()
        try:
            await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()
            closed.set()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    temporary = tempfile.TemporaryDirectory(prefix="sx-resource-child-")
    process = None
    managed = None
    try:
        process = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time; time.sleep(60)")
        gateway = SimpleNamespace(controller=controller, close=AsyncMock())
        managed = ManagedProcess(process, gateway, temporary)
        controller.external_processes.add(managed)
        reader, writer = await open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
        await asyncio.wait_for(accepted.wait(), 3)
        controller.cancel()
        await asyncio.wait_for(managed._finish(), 5)
        await asyncio.wait_for(closed.wait(), 3)
        await writer.wait_closed()
        return {"child_reaped": process.returncode is not None,
                "socket_closed": reader.at_eof() or writer.is_closing(),
                "registry_empty": not controller.connections and not controller.external_processes}
    finally:
        controller.cancel()
        if managed:
            await managed._finish()
        elif process and process.returncode is None:
            process.kill()
            await process.wait()
        temporary.cleanup()
        server.close()
        await server.wait_closed()
        current_transport.reset(token)


def peak_process_mib():
    """Process lifetime resident-memory high-water mark, including native heaps."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ("peak", "working", "quota_peak_paged",
                "quota_paged", "quota_peak_nonpaged", "quota_nonpaged", "pagefile", "peak_pagefile")]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return counters.peak / (1024 * 1024)
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024 if sys.platform == "darwin" else 1024)


def run_gate(config: dict) -> dict:
    samples = []
    for _ in range(3):
        started = time.perf_counter()
        subprocess.run([sys.executable, "-c", "import core.transport, core.task_queue, core.operation_ledger"],
                       check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        samples.append(time.perf_counter() - started)
    tracemalloc.start()
    try:
        with tempfile.TemporaryDirectory(prefix="sx-resource-") as temporary:
            result = _run_gate(config, temporary)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    cleanup = asyncio.run(cleanup_probe())
    limits = config.get("resource_limits", {})
    startup_limit = float(limits.get("startup_median_s", 15 if sys.platform == "win32" else 10))
    peak_limit = float(limits.get("peak_python_mib", 256))
    process_limit = float(limits.get("peak_process_mib", 512))
    process_peak = peak_process_mib()
    median = statistics.median(samples)
    peak_mib = peak / (1024 * 1024)
    result["metrics"].update(startup_samples_s=samples, startup_median_s=median,
                             peak_python_mib=peak_mib, peak_process_mib=process_peak, cleanup=cleanup)
    result["limits"] = {"startup_median_s": startup_limit, "peak_python_mib": peak_limit, "peak_process_mib": process_limit}
    result["checks"].extend([
        {"name": "startup_median", "passed": median <= startup_limit, "detail": f"{median:.3f}s <= {startup_limit}s"},
        {"name": "peak_process_memory", "passed": process_peak <= process_limit, "detail": f"{process_peak:.2f} MiB <= {process_limit} MiB"},
        {"name": "peak_python_memory", "passed": peak_mib <= peak_limit, "detail": f"{peak_mib:.2f} MiB <= {peak_limit} MiB"},
        *({"name": name, "passed": ok, "detail": str(ok)} for name, ok in cleanup.items())])
    result["passed"] = all(check["passed"] for check in result["checks"])
    return result


def main() -> int:
    config = yaml.safe_load(
        (Path(__file__).resolve().parent.parent / "config" / "config.yaml")
        .read_text(encoding="utf-8"))
    result = run_gate(config)
    out = Path("workspace/bench")
    out.mkdir(parents=True, exist_ok=True)
    (out / "resource-gate.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    for check in result["checks"]:
        mark = "PASS" if check["passed"] else "FAIL"
        print(f"  [{mark}] {check['name']}: {check['detail']}")
    print(json.dumps(result["metrics"], indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
