"""Top-level coordinator: builds shared services, registers agents, and
drains the task queue until every agent reports idle.

Agents implement BaseAgent (see agents/base.py) and declare which `kind` of
task they handle. The orchestrator routes tasks from the queue to the
correct agent, manages the worker pool, and exposes shared services
(stealth HTTP client, memory, payload engine, dashboard, workspace path,
auth session, scope policy, OOB client, optional second-session client)
through a Context object.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auth import SessionStore, load_session
from .dashboard import Dashboard
from .http_client import StealthHttpClient
from .logger import get_logger
from .memory import Memory
from .oob import OOBClient
from .payload_engine import PayloadEngine
from .scope import ScopePolicy
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
    http2: StealthHttpClient | None  # second authenticated session (IDOR/BOLA)
    memory: Memory
    payloads: PayloadEngine
    dashboard: Dashboard
    session: SessionStore
    scope: ScopePolicy
    oob: OOBClient


class Orchestrator:
    def __init__(self, config: dict[str, Any], target: str, *,
                 auth_recipe: str | None = None,
                 second_auth_recipe: str | None = None,
                 scope_file: str | None = None,
                 resume: bool = False) -> None:
        self.config = config
        self.target = target
        self.target_slug = slugify(target)
        self.root = root_domain(target)
        self.auth_recipe = auth_recipe
        self.second_auth_recipe = second_auth_recipe
        self.scope_file = scope_file
        self.resume = resume

        ws_root = Path(config.get("workspace", {}).get("root", "./workspace"))
        self.workspace = ensure_dir(ws_root / self.target_slug)
        for sub in ("recon", "crawl", "vulns", "reports", "raw", "screenshots", "discovery"):
            ensure_dir(self.workspace / sub)

        self.queue = TaskQueue()
        self.http = StealthHttpClient(config)
        self.http2: StealthHttpClient | None = None
        self.memory = Memory(config.get("memory", {}).get("db_path") or (ws_root / ".samaritanx.sqlite"))
        self.payloads = PayloadEngine(
            payload_dir=Path(__file__).resolve().parent.parent / "config" / "payloads",
            memory=self.memory,
            evasion_techniques=config.get("waf_evasion", {}).get("techniques", []),
        )
        self.dashboard = Dashboard(target=self.target,
                                   operator=config.get("operator", {}).get("handle", "th3Samaritan"))

        # populated by run() — async setup
        self.session: SessionStore | None = None
        self.session2: SessionStore | None = None
        self.scope: ScopePolicy | None = None
        self.oob: OOBClient | None = None

        self.memory.upsert_target(self.target_slug, self.root, {"input": target})
        if not resume:
            # fresh run — clear scan_state so completed-task gates don't skip work
            self.memory.reset_scan_state(self.target_slug)

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
            http2=self.http2,
            memory=self.memory,
            payloads=self.payloads,
            dashboard=self.dashboard,
            session=self.session,
            scope=self.scope,
            oob=self.oob,
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
                self.queue.task_done()
                continue
            agent = self._agents[agent_name]
            self.dashboard.update_agent(agent.name, "running", task.kind)
            try:
                await agent.handle(task, ctx)
            except Exception as exc:
                log.exception("agent %s failed on %s: %s", agent.name, task.kind, exc)
                self.dashboard.event("err", f"{agent.name} crash on {task.kind}: {exc}")
            finally:
                self.queue.task_done()
                self.dashboard.update_agent(agent.name, "idle", "")

    async def _async_setup(self) -> None:
        # 1) scope policy
        self.scope = ScopePolicy.from_file(self.scope_file, default_allow=self.scope_file is None)
        # apply auto-derived scope when no file is given:
        if self.scope_file is None and self.root:
            self.scope.allow_globs.append(f"*.{self.root}")
            self.scope.allow_globs.append(self.root)
            self.scope.default_allow = False
        self.http.attach(scope=self.scope, dashboard=self.dashboard)

        # 2) primary auth session (login uses the un-authed http client first)
        try:
            self.session = await load_session(self.auth_recipe, self.http)
        except Exception as exc:
            self.session = SessionStore()
            self.dashboard.event("err", f"auth recipe failed: {exc}")
        self.http.attach(session=self.session)
        if self.session.is_authed():
            self.dashboard.event("ok", f"auth: session loaded ({self.session.label})")

        # 3) second auth session (for IDOR / BOLA cross-tenant checks)
        if self.second_auth_recipe:
            self.http2 = StealthHttpClient(self.config)
            self.http2.attach(scope=self.scope, dashboard=self.dashboard)
            try:
                self.session2 = await load_session(self.second_auth_recipe, self.http2)
                self.http2.attach(session=self.session2)
                self.dashboard.event("ok", f"auth: second session loaded ({self.session2.label})")
            except Exception as exc:
                self.dashboard.event("err", f"second auth recipe failed: {exc}")
                await self.http2.close()
                self.http2 = None

        # 4) OOB collaborator
        self.oob = await OOBClient.create(self.config)
        self.dashboard.event("info", f"oob: backend={self.oob.kind} "
                                     f"{'registered' if self.oob.registered else 'unavailable'}")

    async def run(self, *, initial_kind: str = "recon") -> None:
        n_workers = sum([
            int(self.config.get("concurrency", {}).get("recon_workers", 4)),
            int(self.config.get("concurrency", {}).get("crawler_workers", 4)),
            int(self.config.get("concurrency", {}).get("scanner_workers", 8)),
        ])
        n_workers = max(4, min(n_workers, 32))

        with self.dashboard:
            await self._async_setup()
            await self.queue.put(initial_kind, {"target": self.target},
                                 target=self.target_slug, priority=1)

            workers = [asyncio.create_task(self._worker(i)) for i in range(n_workers)]
            try:
                # Phase 1: recon -> discovery -> crawl -> scan -> logic
                await self.queue.join()
                self.dashboard.event("info", "queue drained — entering finalize phase")
                # Phase 2: exploit synthesis (reads findings, emits 'report')
                await self.queue.put("exploit", {}, target=self.target_slug,
                                     priority=1, producer="orchestrator")
                await self.queue.join()
            finally:
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
                if self.oob:
                    await self.oob.close()
                if self.http2:
                    await self.http2.close()
                await self.http.close()
        n = len(self.memory.list_findings(self.target_slug))
        self.dashboard.event("ok",
            f"run complete — {n} findings, {self.http.request_count} requests, "
            f"{self.http.scoped_out} scope-blocked")
