"""Vulnerability Agent — dispatches each (url, params) tuple emitted by the
crawler to every enabled scanner concurrently, plus an optional nuclei pass
on the host root for off-the-shelf templates.

The agent is intentionally thin: scanners hold the detection logic, this
class just orchestrates fan-out, deduplicates findings, and persists them.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import TYPE_CHECKING

from core.task_queue import Task
from core.utils import host_of
from scanners import REGISTRY
from scanners.subdomain_takeover import scan_takeover
from .base import BaseAgent

if TYPE_CHECKING:
    from core.orchestrator import Context


class VulnerabilityAgent(BaseAgent):
    name = "vuln"
    handles = ("scan", "scan.graphql", "scan.takeover")

    def __init__(self) -> None:
        super().__init__()
        self._nuclei_done: set[str] = set()

    async def handle(self, task: Task, ctx: "Context") -> None:
        if task.kind == "scan.takeover":
            await scan_takeover(ctx, task)
            return

        url = task.payload["url"]
        params = task.payload.get("params", []) or []
        method = task.payload.get("method", "GET")
        form = task.payload.get("form")

        enabled = ctx.config.get("scanners", {}).get("enabled", [])
        runners = [(name, REGISTRY[name]) for name in enabled if name in REGISTRY]
        if task.kind == "scan.graphql":
            runners = [(n, f) for n, f in runners if n in ("api", "sqli", "rce", "prompt_injection")]

        results = await asyncio.gather(
            *[self._safe(name, fn, ctx, url, params, method, form) for name, fn in runners]
        )

        seen_keys: set[tuple] = set()
        for batch in results:
            for finding in batch:
                key = (finding.get("category"), finding.get("url"),
                       finding.get("parameter"), finding.get("title"))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                self.report_finding(ctx, finding)

        # one-shot nuclei sweep per host
        host = host_of(url)
        if host not in self._nuclei_done and ctx.config.get("scanners", {}).get("nuclei", True):
            self._nuclei_done.add(host)
            await self._run_nuclei(host, ctx)

    async def _safe(self, name, fn, ctx, url, params, method, form):
        try:
            return await fn(ctx, url, params, method, form)
        except Exception as exc:  # noqa: BLE001
            self.log.exception("scanner %s crashed on %s: %s", name, url, exc)
            ctx.dashboard.event("err", f"{name} crashed on {url}: {exc}")
            return []

    async def _run_nuclei(self, host: str, ctx: "Context") -> None:
        if not shutil.which("nuclei"):
            return
        out_path = ctx.workspace / "vulns" / f"{host}_nuclei.jsonl"
        sev = ctx.config.get("scanners", {}).get("nuclei_severity", "medium,high,critical")
        ctx.dashboard.event("info", f"nuclei: scanning {host} (sev={sev})")
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-u", f"https://{host}", "-silent", "-jsonl",
            "-severity", sev, "-o", str(out_path),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        if not out_path.exists():
            return
        for line in out_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            info = d.get("info", {}) or {}
            self.report_finding(ctx, {
                "category": "nuclei",
                "title": f"[nuclei] {info.get('name') or d.get('template-id')}",
                "severity": (info.get("severity") or "info").lower(),
                "cvss": float(info.get("classification", {}).get("cvss-score") or 0),
                "url": d.get("matched-at") or d.get("host"),
                "evidence": (info.get("description") or "")[:600],
                "metadata": {"template": d.get("template-id"), "tags": info.get("tags")},
            })
