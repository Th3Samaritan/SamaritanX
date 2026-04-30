"""Global Playwright concurrency cap.

Every agent that spawns Chromium (DOM XSS scanner, crawler JS render,
ScreenshotAgent) acquires a slot from this single semaphore so the
peak concurrent browser context count is bounded — Chromium is
~150-300MB per context and OOM-kills are devastating mid-scan on
small VPS instances.

Configurable via `concurrency.browser_contexts` in config.yaml; default 2.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any


_GLOBAL: dict[str, asyncio.Semaphore] = {}


def get_browser_semaphore(cfg: dict[str, Any]) -> asyncio.Semaphore:
    """Lazy-create a single semaphore per Python process keyed on config size."""
    cap = int((cfg.get("concurrency") or {}).get("browser_contexts", 2))
    cap = max(1, min(cap, 8))
    key = f"browsers:{cap}"
    sem = _GLOBAL.get(key)
    if sem is None:
        sem = asyncio.Semaphore(cap)
        _GLOBAL[key] = sem
    return sem


@asynccontextmanager
async def browser_slot(cfg: dict[str, Any]):
    sem = get_browser_semaphore(cfg)
    await sem.acquire()
    try:
        yield
    finally:
        sem.release()
