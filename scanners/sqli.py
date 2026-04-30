"""SQL Injection scanner — error / boolean / time-based.

Boolean-based detection now does **baseline variance sampling**:
    1. Hit the original URL N times to measure the natural σ of response size
       across consecutive requests (caches, timestamps, CSRF tokens, ads ...).
    2. Compute the noise floor: max(N × σ, 200 bytes).
    3. Only flag a TRUE/FALSE pair when |len(true) - len(false)| > noise_floor
       AND the difference is consistent on a re-shoot.

Time-based blind detection uses a **per-host baseline RTT** rather than a
hardcoded 5-second threshold:
    delay_payload_rtt > baseline_rtt + 5 × baseline_σ_rtt
"""
from __future__ import annotations

import asyncio
import re
import statistics
import time
from typing import TYPE_CHECKING

from core.utils import merge_query, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"sqlite3\.OperationalError",
    r"ORA-\d{5}",
    r"sqlstate\[\w+\]",
    r"odbc.*driver",
    r"microsoft.*odbc.*sql",
    r"syntax error at or near",
]
ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.I)


async def _baseline(ctx, url: str, n: int = 4) -> tuple[float, float, float, float]:
    """Return (mean_size, sigma_size, mean_rtt, sigma_rtt) of N legit GETs."""
    sizes: list[int] = []
    rtts: list[float] = []
    for _ in range(n):
        ev = await ctx.http.get(url)
        if ev.error or ev.status == 0:
            continue
        sizes.append(len(ev.response_body or ""))
        rtts.append(ev.elapsed_ms / 1000.0)
    if len(sizes) < 2:
        return 0.0, 0.0, 0.0, 0.0
    return (statistics.mean(sizes), statistics.pstdev(sizes),
            statistics.mean(rtts),  statistics.pstdev(rtts))


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    payloads = ctx.payloads.for_category("sqli", limit=24)
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    base_size, base_sigma_size, base_rtt, base_sigma_rtt = await _baseline(ctx, url)
    # noise floor: 5σ of natural variance, but never less than 200 bytes
    size_threshold = max(200.0, 5 * base_sigma_size)
    rtt_threshold  = base_rtt + max(2.0, 5 * base_sigma_rtt)  # seconds

    async def test_param(param: str) -> None:
        # ----- error-based -----
        for p in payloads:
            async with sem:
                ev = await _request(ctx, url, method, param, p, form)
            if ev.error:
                continue
            if ERROR_RE.search(ev.response_body or ""):
                findings.append(_finding(url, param, p, "error", ev,
                                         "SQL error string returned in response body"))
                ctx.memory.record_payload_result(p, "sqli", True)
                return
            ctx.memory.record_payload_result(p, "sqli", False)

        # ----- boolean-based with baseline variance -----
        async def fire_pair(true_p, false_p):
            async with sem:
                a = await _request(ctx, url, method, param, true_p, form)
                b = await _request(ctx, url, method, param, false_p, form)
            return a, b

        true_p, false_p = "' AND 1=1-- -", "' AND 1=2-- -"
        ev_t, ev_f = await fire_pair(true_p, false_p)
        if ev_t.status and ev_t.status == ev_f.status and ev_t.response_body and ev_f.response_body:
            delta = abs(len(ev_t.response_body) - len(ev_f.response_body))
            if delta > size_threshold:
                # confirm on a second shot to rule out flakiness
                ev_t2, ev_f2 = await fire_pair(true_p, false_p)
                delta2 = abs(len(ev_t2.response_body or "") - len(ev_f2.response_body or ""))
                if delta2 > size_threshold:
                    findings.append(_finding(
                        url, param, f"{true_p} / {false_p}", "boolean", ev_t,
                        f"true/false response length deltas {delta:.0f} and {delta2:.0f} "
                        f"both exceed the {size_threshold:.0f}B noise floor "
                        f"(baseline σ={base_sigma_size:.0f}B)"))
                    ctx.memory.record_payload_result(true_p, "sqli", True)
                    return

        # ----- time-based blind with baseline RTT -----
        time_payloads = [
            "1' AND SLEEP(5)-- -",
            "1' AND (SELECT 1 FROM PG_SLEEP(5))-- -",
            "1; WAITFOR DELAY '0:0:5'-- -",
        ]
        for p in time_payloads:
            t0 = time.perf_counter()
            async with sem:
                ev = await _request(ctx, url, method, param, p, form)
            elapsed = time.perf_counter() - t0
            if elapsed >= rtt_threshold and ev.status:
                # re-confirm to defeat coincidental network jitter
                t0 = time.perf_counter()
                async with sem:
                    await _request(ctx, url, method, param, p, form)
                elapsed2 = time.perf_counter() - t0
                if elapsed2 >= rtt_threshold:
                    findings.append(_finding(
                        url, param, p, "time", ev,
                        f"Two consecutive responses delayed {elapsed:.2f}s and {elapsed2:.2f}s "
                        f"(baseline RTT {base_rtt:.2f}s ± {base_sigma_rtt:.2f}s, "
                        f"threshold {rtt_threshold:.2f}s) — confirms time-based SQLi"))
                    ctx.memory.record_payload_result(p, "sqli", True)
                    return

    await asyncio.gather(*(test_param(p) for p in params))
    return findings


async def _request(ctx, url, method, param, value, form):
    if method.upper() == "GET":
        return await ctx.http.get(merge_query(url, {param: value}))
    data = {i["name"]: i.get("value") or random_token(4) for i in (form or {}).get("inputs", [])}
    data[param] = value
    return await ctx.http.post(url, data=data)


def _finding(url, param, payload, kind, ev, evidence):
    sev_map = {"error": ("high", 8.1), "boolean": ("high", 7.5), "time": ("high", 7.5)}
    sev, cvss = sev_map.get(kind, ("medium", 6.0))
    return {
        "category": "sqli",
        "title": f"SQL injection ({kind}-based) in `{param}`",
        "severity": sev, "cvss": cvss,
        "url": url, "parameter": param, "payload": payload, "evidence": evidence,
        "request": f"{ev.method} {ev.url}",
        "response": (ev.response_body or "")[:1500],
        "metadata": {"detection": kind},
    }
