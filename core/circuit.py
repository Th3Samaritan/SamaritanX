"""Per-origin circuit breakers (plan §11.5).

A failing origin must not consume the whole run. Each origin tracks a bounded
rolling window of failures (5xx, 429, transport errors) and latency, with the
classic three states:

  * closed    — normal operation
  * open      — requests to this origin are rejected fast with a stable
                reason (`circuit_open`), counted, never billed to the budget
  * half-open — a small number of read-only recovery probes may pass; success
                closes, failure re-opens with a fresh cooldown

Deterministic: the clock is injectable, so tests drive failure/recovery
sequences exactly. Recovery probes are read-only by construction — callers
must only send GET/HEAD while half-open.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class CircuitConfig:
    enabled: bool = True
    failure_threshold: int = 5        # failures inside the window that trip the breaker
    window_s: float = 60.0            # rolling failure window
    cooldown_s: float = 30.0          # open duration before half-open
    half_open_probes: int = 2         # max recovery probes while half-open
    latency_high_s: float = 30.0      # a single response this slow also counts
    probe_policy: str = "read_only"   # recovery probes must be GET/HEAD
    # A mostly-healthy origin must not trip on a few isolated timeouts: opening
    # additionally requires the failures to be at least this share of the
    # window's outcomes. 0 disables the rate condition (pure count threshold).
    min_failure_rate: float = 0.5


class CircuitOpen(Exception):
    def __init__(self, host: str) -> None:
        super().__init__(f"circuit-open: {host}")
        self.host = host


class CircuitBreaker:
    def __init__(self, cfg: CircuitConfig, *, clock=None) -> None:
        self.cfg = cfg
        self.clock = clock or time.monotonic
        self.state = "closed"
        self.last_failure = ""
        self._failures: deque[float] = deque()
        self._successes: deque[float] = deque()
        self._opened_at = 0.0
        self._half_open_used = 0

    # ---- state queries ----
    def allows(self, method: str) -> bool:
        """Atomic check-and-consume: returning True for a half-open probe
        also consumes one probe slot."""
        if not self.cfg.enabled:
            return True
        now = self.clock()
        if self.state == "open":
            if now - self._opened_at >= self.cfg.cooldown_s:
                self.state = "half_open"
                self._half_open_used = 0
            else:
                return False
        if self.state == "half_open":
            if self._half_open_used >= self.cfg.half_open_probes:
                return False
            if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
                return False  # recovery probes are read-only by construction
            self._half_open_used += 1
        return True

    # ---- outcomes ----
    def record_failure(self, latency_s: float | None = None, reason: str = "") -> None:
        now = self.clock()
        self._trim(now)
        self._failures.append(now)
        if reason:
            self.last_failure = reason
        if latency_s is not None and latency_s >= self.cfg.latency_high_s:
            self._failures.append(now)
            self.last_failure = f"high latency {latency_s:.1f}s"
        if self.state == "half_open" or self._should_open():
            self._open(now)

    def record_success(self) -> None:
        now = self.clock()
        if self.state == "half_open":
            self.state = "closed"
            self._failures.clear()
            self._successes.clear()
            return
        # successes do not shorten the failure window; they widen the
        # denominator so a healthy origin cannot trip on isolated failures
        self._successes.append(now)
        self._trim(now)

    def _should_open(self) -> bool:
        failures = len(self._failures)
        if failures < self.cfg.failure_threshold:
            return False
        rate = self.cfg.min_failure_rate
        if rate <= 0:
            return True
        total = failures + len(self._successes)
        return failures / total >= rate

    def _trim(self, now: float) -> None:
        cutoff = now - self.cfg.window_s
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()
        while self._successes and self._successes[0] < cutoff:
            self._successes.popleft()

    def _open(self, now: float) -> None:
        self.state = "open"
        self._opened_at = now
        self._half_open_used = 0

    def _consume_probe(self) -> None:
        if self.state == "half_open":
            self._half_open_used += 1

    def snapshot(self) -> dict:
        return {"state": self.state,
                "failures_in_window": len(self._failures),
                "opened_at": getattr(self, "_opened_at", 0.0),
                "last_failure": getattr(self, "last_failure", "")}


class CircuitRegistry:
    """One breaker per origin; creates on demand."""

    def __init__(self, config: dict, *, clock=None) -> None:
        cfg = config.get("transport", {}).get("circuit_breaker", {}) or {}
        self.circuit_cfg = CircuitConfig(
            enabled=bool(cfg.get("enabled", True)),
            failure_threshold=int(cfg.get("failure_threshold", 5)),
            window_s=float(cfg.get("window_s", 60)),
            cooldown_s=float(cfg.get("cooldown_s", 30)),
            half_open_probes=int(cfg.get("half_open_probes", 2)),
            latency_high_s=float(cfg.get("latency_high_s", 30)),
            min_failure_rate=float(cfg.get("min_failure_rate", 0.5)),
        )
        self._clock = clock
        self._breakers: dict[str, CircuitBreaker] = {}

    def breaker(self, host: str) -> CircuitBreaker:
        host = (host or "").lower()
        if host not in self._breakers:
            self._breakers[host] = CircuitBreaker(self.circuit_cfg, clock=self._clock)
        return self._breakers[host]

    def snapshot(self) -> dict:
        return {h: b.snapshot() for h, b in self._breakers.items()
                if b.state != "closed" or b.snapshot()["failures_in_window"]}
