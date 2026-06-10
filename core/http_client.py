"""Stealth-aware async HTTP client.

Wraps httpx.AsyncClient with:
    * scope enforcement (request blocked before egress if out of scope)
    * session injection (cookies + headers from SessionStore)
    * global + per-host token bucket rate limiting
    * reactive backoff on 429 / 503 (Retry-After honored, host bucket
      temporarily slowed for the duration)
    * randomized User-Agent / Referer rotation
    * configurable jitter to mimic human cadence
    * proxy / Tor (socks5h://127.0.0.1:9050) support
    * detailed request/response capture for evidence in reports
    * request counter wired to Dashboard
"""
from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from .logger import get_logger

if TYPE_CHECKING:
    from .auth import SessionStore
    from .scope import ScopePolicy

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
        self.base_rate = self.rate
        self.capacity = capacity if capacity is not None else max(self.rate, 1.0)
        self.tokens = self.capacity
        self.last = time.monotonic()
        self.cooldown_until = 0.0
        self._lock = asyncio.Lock()
        # error-rate tracking for dynamic rate scaling
        self._recent_errors = 0
        self._recent_total = 0
        self._error_window_start = time.monotonic()

    def slow_down(self, seconds: float, factor: float = 0.25) -> None:
        """React to rate-limit responses by halving (default x0.25) the effective rate
        until `seconds` elapse."""
        self.cooldown_until = time.monotonic() + seconds
        self.rate = max(0.1, self.base_rate * factor)

    def record_error(self) -> None:
        """Call on 429/503/5xx so the bucket can scale down proactively."""
        self._recent_errors += 1
        self._recent_total += 1

    def record_success(self) -> None:
        self._recent_total += 1

    def error_fraction(self) -> float:
        """Fraction of requests in the last window that errored."""
        now = time.monotonic()
        if now - self._error_window_start > 30.0:
            self._recent_errors = max(0, self._recent_errors / 2)
            self._recent_total = max(self._recent_total, 1)
            self._error_window_start = now
        if self._recent_total == 0:
            return 0.0
        return self._recent_errors / max(self._recent_total, 1)

    def auto_scale(self) -> None:
        """Adjust rate based on error fraction. High errors -> slower."""
        frac = self.error_fraction()
        if frac > 0.3:
            self.rate = max(0.5, self.base_rate * 0.5)
        elif frac > 0.15:
            self.rate = max(1.0, self.base_rate * 0.75)
        elif frac < 0.02 and self.rate < self.base_rate:
            self.rate = min(self.base_rate, self.rate * 1.25)

    async def take(self) -> None:
        async with self._lock:
            self.auto_scale()
            now = time.monotonic()
            if now > self.cooldown_until and self.rate != self.base_rate:
                self.rate = self.base_rate
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

        # injected by orchestrator after construction
        self.session: "SessionStore | None" = None
        self.scope: "ScopePolicy | None" = None
        self.dashboard = None  # set by orchestrator
        self.request_count = 0
        self.scoped_out = 0

    async def __aenter__(self) -> "StealthHttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    def attach(self, *, session=None, scope=None, dashboard=None) -> None:
        if session is not None:
            self.session = session
        if scope is not None:
            self.scope = scope
        if dashboard is not None:
            self.dashboard = dashboard

    def _build_headers(self, extra: dict[str, str] | None, target_host: str) -> dict[str, str]:
        h = dict(self.default_headers)
        if self.rotate_ua:
            h["User-Agent"] = random.choice(self.user_agents)
        if self.rotate_referer:
            h.setdefault("Referer", f"https://{target_host}/")
        # session-attached headers (auth, tenant, etc.)
        if self.session and self.session.headers:
            h.update(self.session.headers)
        if extra:
            h.update(extra)
        return h

    def _cookies(self, extra: dict[str, str] | None) -> dict[str, str]:
        c: dict[str, str] = {}
        if self.session and self.session.cookies:
            c.update(self.session.cookies)
        if extra:
            c.update(extra)
        return c

    async def _stealth_pause(self, host: str) -> None:
        if not self.stealth_enabled:
            return
        await self._global_bucket.take()
        await self._host_buckets[host].take()
        lo, hi = self.jitter_ms
        if hi > 0:
            await asyncio.sleep(random.uniform(lo, hi) / 1000.0)

    def host_bucket(self, host: str) -> "_TokenBucket":
        """Expose the per-host bucket so non-httpx code (raw sockets, Playwright)
        can take a token before sending — keeps stealth posture honest."""
        return self._host_buckets[host]

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: Any | None = None,
        json_body: Any | None = None,
        files: Any | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        allow_redirects: bool = True,
        bypass_scope: bool = False,
    ) -> HttpEvidence:
        # 1) scope check
        if self.scope and not bypass_scope:
            ok, reason = self.scope.allows(url)
            if not ok:
                self.scoped_out += 1
                if self.dashboard:
                    self.dashboard.event("info", f"scope-block: {url} ({reason})")
                return HttpEvidence(
                    method=method.upper(), url=url, request_headers={},
                    request_body=None, status=0, response_headers={},
                    response_body="", elapsed_ms=0.0,
                    error=f"scope-block: {reason}",
                )

        # 2) refresh session if needed
        if self.session:
            try:
                await self.session.maybe_refresh()
            except Exception as exc:
                if self.dashboard:
                    self.dashboard.event("err", f"auth refresh failed: {exc}")

        host = urlparse(url).netloc or "unknown"
        await self._stealth_pause(host)
        hdrs = self._build_headers(headers, host)
        cookies = self._cookies(cookies)

        start = time.perf_counter()
        try:
            resp = await self._client.request(
                method.upper(),
                url,
                params=params,
                data=data,
                json=json_body,
                files=files,
                headers=hdrs,
                cookies=cookies,
                follow_redirects=allow_redirects,
            )
            body = ""
            try:
                body = resp.text
            except Exception:
                body = ""
            self.request_count += 1
            if self.dashboard:
                self.dashboard.add_count("requests")

            # 3) reactive backoff on 429 / 503
            if resp.status_code in (429, 503):
                retry = resp.headers.get("retry-after")
                wait = 30.0
                if retry:
                    try:
                        wait = float(retry)
                    except ValueError:
                        wait = 30.0
                wait = min(wait, 120.0)
                self._host_buckets[host].slow_down(wait, factor=0.2)
                self._host_buckets[host].record_error()
                if self.dashboard:
                    self.dashboard.event("info",
                        f"backoff: host={host} status={resp.status_code} cooldown={wait:.0f}s")
            elif resp.status_code >= 500:
                self._host_buckets[host].record_error()
            elif resp.status_code < 400:
                self._host_buckets[host].record_success()

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
