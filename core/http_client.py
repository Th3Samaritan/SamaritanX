"""Stealth-aware async HTTP client.

Wraps httpx.AsyncClient with:
    * global + per-host token bucket rate limiting
    * randomized User-Agent / Referer rotation
    * configurable jitter to mimic human cadence
    * proxy / Tor (socks5h://127.0.0.1:9050) support
    * detailed request/response capture for evidence in reports
"""
from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from .logger import get_logger

log = get_logger("http")


@dataclass
class HttpEvidence:
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str | None
    status: int
    response_headers: dict[str, str]
    response_body: str
    elapsed_ms: float
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "request_headers": dict(self.request_headers),
            "request_body": self.request_body,
            "status": self.status,
            "response_headers": dict(self.response_headers),
            "response_body": (self.response_body or "")[:8000],
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "extra": self.extra,
        }


class _TokenBucket:
    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = max(rate, 0.1)
        self.capacity = capacity if capacity is not None else max(self.rate, 1.0)
        self.tokens = self.capacity
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= 1


class StealthHttpClient:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        http_cfg = cfg.get("http", {}) or {}
        stealth = cfg.get("stealth", {}) or {}
        proxy_cfg = cfg.get("proxy", {}) or {}

        self.user_agents: list[str] = http_cfg.get("user_agents") or [
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0"
        ]
        self.default_headers = dict(http_cfg.get("default_headers") or {})
        self.timeout = float(http_cfg.get("timeout", 20))
        self.verify = bool(http_cfg.get("verify_tls", False))
        self.max_redirects = int(http_cfg.get("max_redirects", 5))

        self.stealth_enabled = bool(stealth.get("enabled", True))
        self.jitter_ms = stealth.get("jitter_ms", [50, 200])
        self.rotate_ua = bool(stealth.get("rotate_user_agent", True))
        self.rotate_referer = bool(stealth.get("rotate_referer", True))

        self._global_bucket = _TokenBucket(float(stealth.get("rate_limit_rps", 6)))
        self._per_host_rps = float(stealth.get("per_host_rps", 2))
        self._host_buckets: dict[str, _TokenBucket] = defaultdict(
            lambda: _TokenBucket(self._per_host_rps)
        )

        proxy_url = None
        if proxy_cfg.get("tor"):
            proxy_url = "socks5h://127.0.0.1:9050"
        elif proxy_cfg.get("enabled") and proxy_cfg.get("url"):
            proxy_url = proxy_cfg["url"]

        transport = httpx.AsyncHTTPTransport(retries=1, verify=self.verify)
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=self.timeout,
            verify=self.verify,
            follow_redirects=True,
            max_redirects=self.max_redirects,
            proxy=proxy_url,
            http2=True,
        )

    async def __aenter__(self) -> "StealthHttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    def _build_headers(self, extra: dict[str, str] | None, target_host: str) -> dict[str, str]:
        h = dict(self.default_headers)
        if self.rotate_ua:
            h["User-Agent"] = random.choice(self.user_agents)
        if self.rotate_referer:
            h.setdefault("Referer", f"https://{target_host}/")
        if extra:
            h.update(extra)
        return h

    async def _stealth_pause(self, host: str) -> None:
        if not self.stealth_enabled:
            return
        await self._global_bucket.take()
        await self._host_buckets[host].take()
        lo, hi = self.jitter_ms
        if hi > 0:
            await asyncio.sleep(random.uniform(lo, hi) / 1000.0)

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: Any | None = None,
        json_body: Any | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> HttpEvidence:
        host = urlparse(url).netloc or "unknown"
        await self._stealth_pause(host)
        hdrs = self._build_headers(headers, host)
        start = time.perf_counter()
        try:
            resp = await self._client.request(
                method.upper(),
                url,
                params=params,
                data=data,
                json=json_body,
                headers=hdrs,
                cookies=cookies,
                follow_redirects=allow_redirects,
            )
            body = ""
            try:
                body = resp.text
            except Exception:
                body = ""
            return HttpEvidence(
                method=method.upper(),
                url=str(resp.url),
                request_headers=hdrs,
                request_body=str(data or json_body or ""),
                status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=body,
                elapsed_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as exc:
            return HttpEvidence(
                method=method.upper(),
                url=url,
                request_headers=hdrs,
                request_body=str(data or json_body or ""),
                status=0,
                response_headers={},
                response_body="",
                elapsed_ms=(time.perf_counter() - start) * 1000,
                error=f"{type(exc).__name__}: {exc}",
            )

    async def get(self, url: str, **kw) -> HttpEvidence:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> HttpEvidence:
        return await self.request("POST", url, **kw)
