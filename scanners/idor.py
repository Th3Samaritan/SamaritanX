"""Lightweight IDOR detector.

Heuristics: for any parameter whose value looks like a numeric or UUID
identifier, flip neighbouring values (n-1, n+1) and compare responses.
Real IDOR validation requires a second authenticated identity; this
scanner only flags strong candidates for the LogicAgent / human reviewer.
"""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse, parse_qsl

from core.utils import merge_query

if TYPE_CHECKING:
    from core.orchestrator import Context

NUMERIC_RE = re.compile(r"^\d{1,12}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    qs = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    async def test(param: str) -> None:
        original = qs.get(param)
        if not original:
            return
        if NUMERIC_RE.match(original):
            candidates = [str(int(original) - 1), str(int(original) + 1)]
        elif UUID_RE.match(original):
            # flip last hex char — usually returns 404 unless IDOR
            candidates = [original[:-1] + ("0" if original[-1] != "0" else "1")]
        else:
            return
        async with sem:
            ev_orig = await ctx.http.get(url)
        if ev_orig.status == 0:
            return
        for c in candidates:
            async with sem:
                ev_alt = await ctx.http.get(merge_query(url, {param: c}))
            # If altered identifier returns equally rich content -> likely IDOR
            if ev_alt.status == ev_orig.status and ev_alt.status == 200:
                if ev_alt.response_body and len(ev_alt.response_body) > 200 \
                        and abs(len(ev_alt.response_body) - len(ev_orig.response_body)) < 200:
                    findings.append({
                        "category": "idor",
                        "title": f"Possible IDOR / broken object-level authorization on `{param}`",
                        "severity": "high", "cvss": 7.7,
                        "url": url, "parameter": param,
                        "payload": f"{original} -> {c}",
                        "evidence": "Altered identifier returns a response of similar size and 200 status without authorization context change",
                        "request": f"GET {ev_alt.url}",
                        "response": (ev_alt.response_body or "")[:1500],
                        "metadata": {"original": original, "altered": c},
                    })
                    return

    await asyncio.gather(*(test(p) for p in params))
    return findings
