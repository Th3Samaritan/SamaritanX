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
from urllib.parse import urlsplit
from contextlib import asynccontextmanager


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


class FairPriorityQueue(asyncio.Queue):
    """Round-robin origins and scanner kinds; priority orders each lane.

    Newly ready lanes receive a turn before recently served lanes. A busy
    origin cannot monopolize workers by flooding the queue with one scanner.
    """
    def _init(self, maxsize):
        self._queue = []
        self._origins, self._lanes = {}, {}
        self._turn = 0

    @staticmethod
    def lane(task):
        url = task.payload.get("url") or task.payload.get("target") or task.target
        parsed = urlsplit(str(url) if "://" in str(url) else "http://" + str(url))
        return (parsed.netloc.lower(), task.kind)

    def _put(self, task):
        self._queue.append(task)

    def _get(self):
        def rank(task):
            origin, kind = self.lane(task)
            return (task.priority >= 99999, self._origins.get(origin, 0),
                    self._lanes.get((origin, kind), 0), task.priority, task.seq)
        index = min(range(len(self._queue)), key=lambda i: rank(self._queue[i]))
        task = self._queue.pop(index)
        origin, kind = self.lane(task)
        self._turn += 1
        self._origins[origin] = self._turn
        self._lanes[(origin, kind)] = self._turn
        if not self._queue:
            self._origins.clear()
            self._lanes.clear()
        return task


class FairSlots:
    """Bounded execution slots shared fairly by origin and scanner."""
    def __init__(self, capacity):
        self.capacity = capacity
        self.available = capacity
        self.queue = FairPriorityQueue()
        self.waiters = {}
        self.sequence = itertools.count()

    def _dispatch(self):
        while self.available and not self.queue.empty():
            task = self.queue.get_nowait()
            self.queue.task_done()
            future = self.waiters.pop(task.seq)
            if future.cancelled():
                continue
            self.available -= 1
            future.set_result(True)

    @asynccontextmanager
    async def slot(self, url, scanner):
        sequence = next(self.sequence)
        future = asyncio.get_running_loop().create_future()
        self.waiters[sequence] = future
        self.queue.put_nowait(Task(5, sequence, scanner, "", {"url": url}))
        asyncio.get_running_loop().call_soon(self._dispatch)
        acquired = False
        try:
            await future
            acquired = True
            yield
        finally:
            if acquired or (future.done() and not future.cancelled()):
                self.available += 1
            future.cancel()
            self._dispatch()


class TaskQueue:
    """An async priority queue with simple per-kind subscription routing."""

    def __init__(self, store=None, lease_seconds=60) -> None:
        self._q: asyncio.Queue[Task] = FairPriorityQueue()
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
