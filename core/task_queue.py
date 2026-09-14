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
import hashlib
import json
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
    key: str = field(default="", compare=False)
    owner: str = field(default="", compare=False)


class TaskQueue:
    """An async priority queue with simple per-kind subscription routing."""

    def __init__(self, store=None, lease_seconds=60) -> None:
        self._q: asyncio.PriorityQueue[Task] = asyncio.PriorityQueue()
        self._counter = itertools.count()
        self._stats: dict[str, int] = {}
        self.store = store
        self.lease_seconds = lease_seconds
        self._pending = set()
        self._consumers = {}

    async def put(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        target: str = "",
        priority: int = 5,
        producer: str = "orchestrator",
    ) -> None:
        key = hashlib.sha256(json.dumps([target, kind, payload], sort_keys=True).encode()).hexdigest()
        if key in self._pending:
            return
        if self.store and not self.store.enqueue(key, target, kind, payload, priority):
            return
        self._pending.add(key)
        task = Task(
            priority=priority,
            seq=next(self._counter),
            kind=kind,
            target=target,
            payload=payload,
            producer=producer,
            key=key,
        )
        await self._q.put(task)
        self._stats[kind] = self._stats.get(kind, 0) + 1

    async def get(self) -> Task:
        while True:
            task = await self._q.get()
            if self.store and task.key:
                task.owner = self.store.claim(task.key, self.lease_seconds)
                if not task.owner:
                    self._pending.discard(task.key)
                    self._q.task_done()
                    continue
            self._consumers[asyncio.current_task()] = task
            return task

    def task_done(self, status="completed", reason="") -> None:
        task = self._consumers.pop(asyncio.current_task(), None)
        if task:
            self._pending.discard(task.key)
            if self.store and task.key:
                self.store.finish(task.key, task.owner, status, reason)
        self._q.task_done()

    async def restore(self, target, replay_safe=()):
        if not self.store:
            return
        for row in self.store.recover(target, replay_safe):
            if row["key"] not in self._pending:
                self._pending.add(row["key"])
                await self._q.put(Task(row["priority"], next(self._counter), row["kind"],
                                       target, row["payload"], key=row["key"]))

    async def maintain_lease(self, task, execution):
        if not self.store or not task.key:
            return
        while True:
            await asyncio.sleep(self.lease_seconds / 3)
            if not self.store.renew(task.key, task.owner, self.lease_seconds):
                execution.cancel()
                return

    async def join(self) -> None:
        await self._q.join()

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def empty(self) -> bool:
        return self._q.empty()

    def qsize(self) -> int:
        return self._q.qsize()
