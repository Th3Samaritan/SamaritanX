"""Top-level coordinator: builds shared services, registers agents, and
drains the task queue until every agent reports idle.

Agents implement BaseAgent (see agents/base.py) and declare which `kind` of
task they handle. The orchestrator routes tasks from the queue to the
correct agent, manages the worker pool, and exposes shared services
(stealth HTTP client, memory, payload engine, dashboard, workspace path)
through a Context object.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .dashboard import Dashboard
from .http_client import StealthHttpClient
from .logger import get_logger
from .memory import Memory
from .payload_engine import PayloadEngine
from .task_queue import Task, TaskQueue
from .utils import ensure_dir, root_domain, slugify

log = get_logger("orchestrator")


@dataclass
class Context:
    config: dict[str, Any]
    target: str
    target_slug: str
    workspace: Path
    queue: TaskQueue
    http: StealthHttpClient
    memory: Memory
    payloads: PayloadEngine
    dashboard: Dashboard


class Orchestrator:
    def __init__(self, config: dict[str, Any], target: str) -> None:
        self.config = config
        self.target = target
        self.target_slug = slugify(target)
        self.root = root_domain(target)

        ws_root = Path(config.get("workspace", {}).get("root", "./workspace"))
        self.workspace = ensure_dir(ws_root / self.target_slug)
        for sub in ("recon", "crawl", "vulns", "reports", "raw"):
            ensure_dir(self.workspace / sub)

        self.queue = TaskQueue()
        self.http = StealthHttpClient(config)
        self.memory = Memory(config.get("memory", {}).get("db_path") or (ws_root / ".samaritanx.sqlite"))
        self.payloads = PayloadEngine(
            payload_dir=Path(__file__).resolve().parent.parent / "config" / "payloads",
            memory=self.memory,
            evasion_techniques=config.get("waf_evasion", {}).get("techniques", []),
        )
        self.dashboard = Dashboard(target=self.target,
                                   operator=config.get("operator", {}).get("handle", "th3Samaritan"))

        self.memory.upsert_target(self.target_slug, self.root, {"input": target})

        # name -> agent instance
        self._agents: dict[str, "BaseAgent"] = {}
        # routing: task.kind -> agent name
        self._routes: dict[str, str] = {}

    @property
    def context(self) -> Context:
        return Context(
            config=self.config,
            target=self.target,
            target_slug=self.target_slug,
            workspace=self.workspace,
            queue=self.queue,
            http=self.http,
            memory=self.memory,
            payloads=self.payloads,
            dashboard=self.dashboard,
        )

    def register(self, agent: "BaseAgent") -> None:
        self._agents[agent.name] = agent
        for kind in agent.handles:
            self._routes[kind] = agent.name
        self.dashboard.update_agent(agent.name, "idle", "registered")

    async def _worker(self, worker_id: int) -> None:
        ctx = self.context
        while True:
            task: Task = await self.queue.get()
            agent_name = self._routes.get(task.kind)
            if not agent_name:
                # Drop tasks with no handler
                self.queue.task_done()
                continue
            agent = self._agents[agent_name]
            self.dashboard.update_agent(agent.name, "running", task.kind)
            try:
                await agent.handle(task, ctx)
            except Exception as exc:  # noqa: BLE001 — agents must not crash the worker
                log.exception("agent %s failed on %s: %s", agent.name, task.kind, exc)
                self.dashboard.event("err", f"{agent.name} crash on {task.kind}: {exc}")
            finally:
                self.queue.task_done()
                self.dashboard.update_agent(agent.name, "idle", "")

    async def run(self, *, initial_kind: str = "recon") -> None:
        n_workers = sum([
            int(self.config.get("concurrency", {}).get("recon_workers", 4)),
            int(self.config.get("concurrency", {}).get("crawler_workers", 4)),
            int(self.config.get("concurrency", {}).get("scanner_workers", 8)),
        ])
        n_workers = max(4, min(n_workers, 32))

        # seed the pipeline
        await self.queue.put(initial_kind, {"target": self.target}, target=self.target_slug, priority=1)

        with self.dashboard:
            workers = [asyncio.create_task(self._worker(i)) for i in range(n_workers)]
            try:
                # Phase 1: recon -> crawl -> scan -> logic
                await self.queue.join()
                # Phase 2: exploit synthesis (reads findings, emits 'report')
                self.dashboard.event("info", "queue drained — entering finalize phase")
                await self.queue.put("exploit", {}, target=self.target_slug,
                                     priority=1, producer="orchestrator")
                await self.queue.join()
            finally:
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
                await self.http.close()
        n = len(self.memory.list_findings(self.target_slug))
        self.dashboard.event("ok", f"run complete — {n} findings")
