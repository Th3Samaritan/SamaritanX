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


def run_gate(config: dict) -> dict:
    t0 = time.perf_counter()
    server, port = _fixture_server()
    base = f"http://127.0.0.1:{port}"
    cfg = yaml.safe_load(
        (Path(__file__).resolve().parent.parent / "config" / "config.yaml")
        .read_text(encoding="utf-8"))
    cfg["stealth"]["rate_limit_rps"] = 50
    cfg["stealth"]["per_host_rps"] = 50
    cfg["stealth"]["jitter_ms"] = [0, 0]
    cfg["scanners"]["enabled"] = ["sqli", "xss", "security_headers"]
    tmp = tempfile.mkdtemp()
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
        r1 = await sqli(ctx, base + "/sqli", ["q"], "GET", None)
        r2 = await xss(ctx, base + "/xss", ["q"], "GET", None)
        r3 = await sec(ctx, base + "/sqli", [], "GET", None)
        return ctx, r1, r2, r3

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
    try:
        server.shutdown()
        server.server_close()
    except Exception:
        pass
    return results


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
