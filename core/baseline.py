"""Differential baseline engine — the shared FP-killer for oracle-style bugs.

Most false positives in this class of tool come from judging a single response
in isolation: "the request took 5s" or "the page was 8 KB, must be the true
branch." Both are meaningless without a *baseline* — what does this exact
endpoint normally do?

This module captures a baseline (a control request repeated a few times) and
then decides whether a payload response is a real, significant deviation:

  * ``TimingBaseline`` — models normal latency as a distribution and only calls
    a response "slow" when it is a robust statistical outlier (median + k·MAD),
    never a hard 5-second constant. This is what tells a genuine time-based
    injection apart from a jittery CDN or an origin waiting for a body.
  * ``ResponseBaseline`` — models the normal response (status, length,
    structural shape) and scores how far a payload response deviates, so a
    boolean-injection / IDOR "different response" claim is measured against the
    real control instead of a guess.

Everything here is pure and deterministic given its inputs, so it unit-tests
offline. Scanners feed it timings / responses they already collect.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from statistics import median
from typing import Sequence


# --------------------------------------------------------------------------- #
# Timing
# --------------------------------------------------------------------------- #
@dataclass
class TimingBaseline:
    """A robust model of an endpoint's normal latency.

    Uses the median and MAD (median absolute deviation) rather than mean/stddev
    so a single slow sample can't poison the model. A payload latency is a
    genuine outlier only when it exceeds ``median + k*MAD_scaled`` AND clears an
    absolute floor (so sub-millisecond noise on a fast endpoint doesn't fire).
    """
    samples: list[float] = field(default_factory=list)
    k: float = 6.0                 # how many robust-sigmas past the median counts as slow
    min_delta_s: float = 1.0       # absolute floor: ignore deviations smaller than this

    def add(self, seconds: float) -> None:
        if seconds is not None and seconds >= 0:
            self.samples.append(float(seconds))

    @property
    def median(self) -> float:
        return median(self.samples) if self.samples else 0.0

    @property
    def mad(self) -> float:
        """Median absolute deviation, scaled to be a consistent estimator of σ."""
        if len(self.samples) < 2:
            return 0.0
        med = self.median
        devs = [abs(s - med) for s in self.samples]
        return 1.4826 * median(devs)

    def threshold(self) -> float:
        """The latency past which a response is considered a real outlier."""
        # when MAD is ~0 (very stable endpoint) fall back to a relative margin
        spread = self.mad if self.mad > 1e-6 else max(0.25 * self.median, 0.1)
        return self.median + max(self.k * spread, self.min_delta_s)

    def is_outlier(self, seconds: float) -> bool:
        if not self.samples or seconds is None:
            return False
        return seconds >= self.threshold()

    def describe(self, seconds: float) -> str:
        return (f"payload latency {seconds:.2f}s vs baseline median "
                f"{self.median:.2f}s (threshold {self.threshold():.2f}s, "
                f"n={len(self.samples)})")


# --------------------------------------------------------------------------- #
# Response shape
# --------------------------------------------------------------------------- #
def _shape(status: int, body: str) -> tuple[int, int, int]:
    """A cheap structural fingerprint of a response: (status, length, tag-count).

    tag-count (number of '<' in the body) approximates DOM structure so two
    pages of similar length but different structure still differ."""
    body = body or ""
    return (int(status or 0), len(body), body.count("<"))


@dataclass
class ResponseBaseline:
    """A model of an endpoint's normal response, for boolean/IDOR-style diffs."""
    statuses: list[int] = field(default_factory=list)
    lengths: list[int] = field(default_factory=list)
    tagcounts: list[int] = field(default_factory=list)

    def add(self, status: int, body: str) -> None:
        st, ln, tg = _shape(status, body)
        self.statuses.append(st)
        self.lengths.append(ln)
        self.tagcounts.append(tg)

    @property
    def n(self) -> int:
        return len(self.statuses)

    def _len_median(self) -> float:
        return median(self.lengths) if self.lengths else 0.0

    def length_threshold(self, k: float = 5.0, floor: float = 200.0) -> float:
        """A robust noise floor for response-length deltas (boolean injection).

        Uses length MAD so normal page jitter (CSRF tokens, timestamps) doesn't
        read as a true/false branch difference."""
        if len(self.lengths) < 2:
            return floor
        med = self._len_median()
        mad = 1.4826 * median([abs(l - med) for l in self.lengths])
        spread = mad if mad > 1e-6 else 0.25 * med
        return max(floor, k * spread)

    def deviation(self, status: int, body: str) -> float:
        """Score how far a response deviates from baseline, in [0, 1].

        1.0 = completely different (status changed, or length wildly off);
        0.0 = indistinguishable from the control."""
        if self.n == 0:
            return 0.0
        st, ln, tg = _shape(status, body)
        score = 0.0
        # status class change is the strongest signal
        base_status = median(self.statuses)
        if st != base_status:
            score += 0.6 if (st // 100) != (int(base_status) // 100) else 0.3
        # length deviation, normalised against the baseline magnitude
        base_len = self._len_median()
        denom = max(base_len, 1.0)
        len_dev = abs(ln - base_len) / denom
        score += min(0.4, len_dev)  # cap length's contribution
        return min(1.0, score)

    def is_significant(self, status: int, body: str, threshold: float = 0.4) -> bool:
        return self.deviation(status, body) >= threshold

    def describe(self, status: int, body: str) -> str:
        st, ln, _ = _shape(status, body)
        return (f"response status={st} len={ln} vs baseline status~{int(median(self.statuses))} "
                f"len~{int(self._len_median())} (deviation "
                f"{self.deviation(status, body):.2f}, n={self.n})")


# --------------------------------------------------------------------------- #
# Async helpers that drive the HTTP client (thin, so scanners stay small)
# --------------------------------------------------------------------------- #
async def capture_timing(http, url: str, *, rounds: int = 4, method: str = "GET",
                         **kw) -> TimingBaseline:
    """Fire ``rounds`` clean requests and build a TimingBaseline from them."""
    tb = TimingBaseline()
    for _ in range(max(1, rounds)):
        ev = await _fire(http, url, method, **kw)
        if ev is not None and getattr(ev, "error", None) is None:
            tb.add((getattr(ev, "elapsed_ms", 0.0) or 0.0) / 1000.0)
    return tb


async def capture_response(http, url: str, *, rounds: int = 3, method: str = "GET",
                           **kw) -> ResponseBaseline:
    rb = ResponseBaseline()
    for _ in range(max(1, rounds)):
        ev = await _fire(http, url, method, **kw)
        if ev is not None and getattr(ev, "error", None) is None:
            rb.add(getattr(ev, "status", 0), getattr(ev, "response_body", "") or "")
    return rb


async def _fire(http, url: str, method: str, **kw):
    method = (method or "GET").upper()
    fn = getattr(http, method.lower(), None)
    try:
        if fn is not None:
            return await fn(url, **kw)
        return await http.get(url, **kw)
    except Exception:
        return None
