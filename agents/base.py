"""Base class every SamaritanX agent inherits from.

Each agent declares the task `kinds` it handles via the `handles` class
attribute and implements `handle(task, ctx)`. It can publish follow-up
tasks via `ctx.queue.put(...)` to feed downstream agents.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from core.constants import LEVEL_MAP, Severity
from core.logger import get_logger
from core.task_queue import Task

if TYPE_CHECKING:
    from core.orchestrator import Context


class BaseAgent(ABC):
    name: ClassVar[str] = "base"
    handles: ClassVar[tuple[str, ...]] = ()

    def __init__(self) -> None:
        self.log = get_logger(self.name)

    @abstractmethod
    async def handle(self, task: Task, ctx: "Context") -> None:
        ...

    # ---------- helpers shared across agents ----------
    def report_finding(self, ctx: "Context", finding: dict) -> None:
        from core.confidence import annotate
        finding.setdefault("target", ctx.target_slug)
        annotate(finding)
        fid = ctx.memory.record_finding(finding)
        ctx.dashboard.add_count("findings")
        sev = finding.get("severity", Severity.INFO).lower()
        if sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            ctx.dashboard.add_count(sev)
        ctx.dashboard.event(LEVEL_MAP.get(sev, "info"),
                            f"[{sev.upper()}] {finding.get('title')} "
                            f"({finding.get('url') or finding.get('parameter') or ''})")
        finding["_id"] = fid
