"""Async priority task queue used to route work between agents.

Lower priority value = higher importance (1 = highest). Each task carries:
    - kind        : routing key (e.g. 'crawl', 'scan.sqli', 'recon')
    - payload     : opaque dict consumed by the agent that subscribes to the kind
    - producer    : agent name that produced it (for telemetry)
    - target      : target slug for grouping / dashboard

The queue is the *only* way agents talk to each other so the architecture
stays loosely coupled and easy to extend with new agent types.
"""
from __future__ import annotations

import asyncio
import itertools
from dataclasses import dataclass, field
from typing import Any


@dataclass(order=True)
class Task:
    priority: int
    seq: int = field(compare=True)
    kind: str = field(compare=False)
    target: str = field(compare=False)
    payload: dict[str, Any] = field(default_factory=dict, compare=False)
    producer: str = field(default="orchestrator", compare=False)


class TaskQueue:
    """An async priority queue with simple per-kind subscription routing."""

    def __init__(self) -> None:
        self._q: asyncio.PriorityQueue[Task] = asyncio.PriorityQueue()
        self._counter = itertools.count()
        self._stats: dict[str, int] = {}

    async def put(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        target: str = "",
        priority: int = 5,
        producer: str = "orchestrator",
    ) -> None:
        task = Task(
            priority=priority,
            seq=next(self._counter),
            kind=kind,
            target=target,
            payload=payload,
            producer=producer,
        )
        await self._q.put(task)
        self._stats[kind] = self._stats.get(kind, 0) + 1

    async def get(self) -> Task:
        return await self._q.get()

    def task_done(self) -> None:
        self._q.task_done()

    async def join(self) -> None:
        await self._q.join()

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def empty(self) -> bool:
        return self._q.empty()

    def qsize(self) -> int:
        return self._q.qsize()
