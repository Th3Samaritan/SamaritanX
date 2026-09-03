"""Shared baseline-request cache — de-duplicates the clean GETs every scanner
makes against the same URL.

In one scan task a single endpoint gets baseline-fetched by eight or more
scanners (sqli timing/response baselines, rce baseline, ssrf baseline,
version_bypass, host_header, security_headers, cache-poisoning clean fetch,
nosqli base…). All of them want the same thing: one clean GET of the URL.
This cache serves that one fetch to every caller for a short TTL.

Deliberately conservative:
  * GET only, 2xx-ish only, allow_redirects=False defaults to True semantics
    preserved per-call
  * a short TTL so scanners that run minutes apart re-fetch honestly
  * timing-sensitive probes and payload requests NEVER go through it —
    scanners only use it for clean baselines
"""
from __future__ import annotations

import time
from typing import Any


class BaselineCache:
    def __init__(self, ttl: float = 45.0) -> None:
        self._ttl = ttl
        self._entries: dict[tuple, tuple[float, Any]] = {}

    @staticmethod
    def _key(method: str, url: str, headers: dict | None, cookies: dict | None) -> tuple:
        h = tuple(sorted((headers or {}).items()))
        c = tuple(sorted((cookies or {}).items()))
        return (method.upper(), url, h, c)

    async def fetch(self, http, url: str, *, method: str = "GET",
                    headers: dict | None = None, cookies: dict | None = None,
                    allow_redirects: bool = True) -> Any:
        """Return a cached HttpEvidence for a clean baseline GET, or perform
        and cache it. Cache misses transparently fall through to the client."""
        key = self._key(method, url, headers, cookies)
        now = time.monotonic()
        hit = self._entries.get(key)
        if hit and now - hit[0] <= self._ttl:
            return hit[1]
        fn = getattr(http, "request", None)
        if fn is None:
            return None
        ev = await fn(method.upper(), url, headers=headers, cookies=cookies,
                      allow_redirects=allow_redirects)
        # only cache clean, successful, error-free responses
        if ev is not None and not getattr(ev, "error", None) and \
                200 <= (getattr(ev, "status", 0) or 0) < 400:
            self._entries[key] = (now, ev)
            # bound the cache size — one scan task rarely exceeds 200 URLs
            if len(self._entries) > 512:
                oldest = min(self._entries, key=lambda k: self._entries[k][0])
                self._entries.pop(oldest, None)
        return ev

    def clear(self) -> None:
        self._entries.clear()
