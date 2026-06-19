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
from dataclasses import dataclass, field
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

# A sentinel task that signals workers to stop gracefully.
SENTINEL_KIND = "__sentinel__"


@dataclass
class Context:
    config: dict[str, Any]
    target: str
    target_slug: str
    workspace: Path
    queue: TaskQueue
    http: StealthHttpClient
    http2: StealthHttpClient | None
    memory: Memory
    payloads: PayloadEngine
    dashboard: Dashboard
    session: SessionStore | None
    scope: ScopePolicy | None
    oob: OOBClient | None
    # Extra labeled identities for the authorization matrix (e.g. an admin row).
    # Each: {"label": str, "client": StealthHttpClient, "rank": int}.
    extra_identities: list[dict[str, Any]] = field(default_factory=list)
    # Dynamic rate control — updated by http_client and readable by scanners
    error_rate: float = 0.0
    global_deadline: float = 0.0



class Orchestrator:
    def __init__(self, config: dict[str, Any], target: str, *,
                 auth_recipe: str | None = None,
                 second_auth_recipe: str | None = None,
                 extra_sessions: list[tuple[str, str, int]] | None = None,
                 scope_file: str | None = None,
                 resume: bool = False,
                 deadline: float = 0.0,
                 task_timeout: float = 60.0) -> None:
        self.config = config
        self.target = target
        self.target_slug = slugify(target)
        self.root = root_domain(target)
        self.auth_recipe = auth_recipe
        self.second_auth_recipe = second_auth_recipe
        self.extra_session_specs = extra_sessions or []
        self.scope_file = scope_file
        self.resume = resume
        self.deadline = deadline or float(config.get("scan", {}).get("deadline_seconds", 0))
        self.task_timeout = task_timeout or float(config.get("scan", {}).get("task_timeout_seconds", 60))

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
        self.extra_identities: list[dict[str, Any]] = []  # {label, client, rank}

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
            extra_identities=self.extra_identities,
        )

    def register(self, agent: "BaseAgent") -> None:
        self._agents[agent.name] = agent
        for kind in agent.handles:
            self._routes[kind] = agent.name
        self.dashboard.update_agent(agent.name, "idle", "registered")

    # Long fan-out phases legitimately run longer than a single scanner probe.
    # Capping them at the scanner timeout (default 60s) would kill recon/crawl
    # mid-sweep before they emit downstream work.
    _LONG_PHASES = {"recon", "crawl", "discover", "authz"}

    def _timeout_for(self, kind: str) -> float:
        if kind in self._LONG_PHASES:
            return max(self.task_timeout, float(
                self.config.get("scan", {}).get("long_phase_timeout_seconds", 600)))
        return self.task_timeout

    async def _worker(self, worker_id: int) -> None:
        """Pull tasks from the queue in a loop until cancelled or sentinel.

        Each task gets a per-task timeout (default 60s) to prevent a single
        hung scanner from blocking a worker forever.  When the global
        deadline fires, the worker stops after finishing its current task.
        """
        _worker_name = f"w{worker_id:02d}"
        try:
            while True:
                task: Task = await self.queue.get()
                if task.kind == SENTINEL_KIND:
                    self.queue.task_done()
                    return
                ctx = self.context
                agent_name = self._routes.get(task.kind)
                if not agent_name:
                    log.debug("worker %s: no route for kind %s", _worker_name, task.kind)
                    self.queue.task_done()
                    continue
                agent = self._agents[agent_name]
                self.dashboard.update_agent(agent.name, "running", task.kind)
                try:
                    await asyncio.wait_for(
                        agent.handle(task, ctx),
                        timeout=self._timeout_for(task.kind),
                    )
                except asyncio.TimeoutError:
                    log.warning("worker %s: task %s timed out after %.0fs",
                                _worker_name, task.kind, self.task_timeout)
                    self.dashboard.event("err",
                        f"{agent.name} timed out on {task.kind} ({self.task_timeout:.0f}s)")
                except Exception as exc:
                    log.exception("agent %s failed on %s: %s", agent.name, task.kind, exc)
                    self.dashboard.event("err", f"{agent.name} crash on {task.kind}: {exc}")
                finally:
                    self.queue.task_done()
                    self.dashboard.update_agent(agent.name, "idle", "")
        except asyncio.CancelledError:
            pass

    async def _async_setup(self) -> None:
        # 1) scope policy
        self.scope = ScopePolicy.from_file(self.scope_file, default_allow=self.scope_file is None)
        # apply auto-derived scope when no file is given:
        # Keep default_allow=True so external OSINT/passive API calls (crt.sh,
        # hackertarget, wayback, etc.) are never silently blocked. The globs act
        # as an *allow-list hint* for active-scanning URL selection, not a hard
        # deny-everything-else gate. When an explicit scope file is supplied the
        # user controls exactly what is in-scope.
        if self.scope_file is None and self.root:
            self.scope.allow_globs.append(f"*.{self.root}")
            self.scope.allow_globs.append(self.root)
            # default_allow stays True — without a scope file we should not
            # block access to external recon/passive-intel services.
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

        # 3b) extra labeled sessions (admin row etc.) for the authz matrix
        for label, path, rank in self.extra_session_specs:
            client = StealthHttpClient(self.config)
            client.attach(scope=self.scope, dashboard=self.dashboard)
            try:
                store = await load_session(path, client)
                client.attach(session=store)
                self.extra_identities.append({"label": label, "client": client, "rank": rank})
                self.dashboard.event("ok",
                    f"auth: extra session '{label}' loaded (rank {rank})")
            except Exception as exc:
                self.dashboard.event("err", f"extra session '{label}' failed: {exc}")
                await client.close()

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
            # seed the initial recon task
            await self.queue.put(initial_kind, {"target": self.target},
                                  target=self.target_slug, priority=1)

            workers = [asyncio.create_task(self._worker(i)) for i in range(n_workers)]
            try:
                # Phase 1: recon -> discovery -> crawl -> scan -> logic
                await self._join_with_deadline("phase1")
                self.dashboard.event("info", "queue drained — entering finalize phase")
                # Phase 2: exploit synthesis (reads findings, emits 'report')
                await self.queue.put("exploit", {}, target=self.target_slug,
                                      priority=1, producer="orchestrator")
                await self._join_with_deadline("phase2")
            except asyncio.TimeoutError:
                self.dashboard.event("err", "global scan deadline reached — stopping")
            finally:
                await self._shutdown_workers(workers)
        n = len(self.memory.list_findings(self.target_slug))
        self.dashboard.event("ok",
            f"run complete — {n} findings, {self.http.request_count} requests, "
            f"{self.http.scoped_out} scope-blocked")

    async def _join_with_deadline(self, phase: str) -> None:
        """Block until the task queue is fully drained or the global deadline
        fires.  Periodically checkpoints scan_state so a crashed mid-phase
        scan can be resumed from this phase boundary."""
        start = asyncio.get_running_loop().time()
        while True:
            remaining = self.deadline - (asyncio.get_running_loop().time() - start) if self.deadline else None
            join_task = asyncio.create_task(self.queue.join())
            try:
                if remaining is not None and remaining <= 0:
                    raise asyncio.TimeoutError("deadline exceeded")
                await asyncio.wait_for(join_task, timeout=remaining)
                # checkpoint: mark this phase as completed for resume
                self.memory.mark_completed(self.target_slug, phase)
                return
            except asyncio.TimeoutError:
                join_task.cancel()
                try:
                    await join_task
                except (asyncio.CancelledError, Exception):
                    pass
                # checkpoint what we have so far
                self.memory.mark_completed(self.target_slug, phase + "_partial")
                raise

    async def _shutdown_workers(self, workers: list[asyncio.Task]) -> None:
        """Gracefully stop all workers: inject one sentinel per worker, then
        await them with a 10-second grace period."""
        for _ in workers:
            try:
                self._q_sentinel = Task(
                    priority=99999, seq=0, kind=SENTINEL_KIND,
                    target=self.target_slug, payload={}, producer="orchestrator",
                )
                await self.queue._q.put(self._q_sentinel)
            except Exception:
                pass
        # give workers 10s to finish their current task
        try:
            await asyncio.wait_for(asyncio.gather(*workers, return_exceptions=True), timeout=10.0)
        except asyncio.TimeoutError:
            pass
        for w in workers:
            if not w.done():
                w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        if self.oob:
            try:
                await self.oob.close()
            except Exception:
                pass
        if self.http2:
            try:
                await self.http2.close()
            except Exception:
                pass
        for ident in self.extra_identities:
            try:
                await ident["client"].close()
            except Exception:
                pass
        try:
            await self.http.close()
        except Exception:
            pass
