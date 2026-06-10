"""Lightweight IDOR detector.

Heuristics: for any parameter whose value looks like a numeric or UUID
identifier, flip neighbouring values (n-1, n+1) and compare responses.
Now also covers path-segment identifiers (`/users/123`), where IDOR most
often lives. Real IDOR validation requires a second authenticated identity;
this scanner only flags strong candidates for the LogicAgent / human reviewer.
"""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse, parse_qsl

from core.injection import send, parse_point, describe, candidate_points

if TYPE_CHECKING:
    from core.orchestrator import Context

NUMERIC_RE = re.compile(r"^\d{1,12}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _current_value(url: str, param: str):
    """The existing identifier at an injection point — query value or path segment."""
    kind, loc = parse_point(param)
    if kind == "query":
        return dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).get(loc)
    if kind == "path":
        segs = [s for s in urlparse(url).path.split("/") if s != ""]
        try:
            return segs[int(loc)]
        except (ValueError, IndexError):
            return None
    return None


async def scan(ctx: "Context", url: str, params: list, method: str = "GET", form=None):
    findings: list = []
    points = candidate_points(url, params, form, method)
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    async def test(param: str) -> None:
        original = _current_value(url, param)
        if not original:
            return
        if NUMERIC_RE.match(original):
            candidates = [str(int(original) - 1), str(int(original) + 1)]
        elif UUID_RE.match(original):
            candidates = [original[:-1] + ("0" if original[-1] != "0" else "1")]
        else:
            return
        async with sem:
            ev_orig = await ctx.http.get(url)
        if ev_orig.status == 0:
            return
        for c in candidates:
            async with sem:
                ev_alt = await send(ctx, url, method, param, c, form)
            if ev_alt.status == ev_orig.status and ev_alt.status == 200:
                if ev_alt.response_body and len(ev_alt.response_body) > 200 \
                        and abs(len(ev_alt.response_body) - len(ev_orig.response_body)) < 200:
                    findings.append({
                        "category": "idor",
                        "title": f"Possible IDOR / broken object-level authorization on {describe(param)}",
                        "severity": "high", "cvss": 7.7,
                        "url": url, "parameter": param,
                        "payload": f"{original} -> {c}",
                        "evidence": "Altered identifier returns a response of similar size and 200 status without authorization context change",
                        "request": f"{ev_alt.method} {ev_alt.url}",
                        "response": (ev_alt.response_body or "")[:1500],
                        "metadata": {"original": original, "altered": c, "point": param},
                    })
                    return

    await asyncio.gather(*(test(p) for p in points))
    return findings
