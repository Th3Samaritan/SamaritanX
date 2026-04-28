"""Open redirect scanner — replaces redirect-style params and checks Location header."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from core.utils import merge_query

if TYPE_CHECKING:
    from core.orchestrator import Context

REDIRECT_PARAM_HINTS = ("url", "redirect", "next", "return", "returnto", "redir",
                        "continue", "dest", "destination", "rurl", "callback")


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    payloads = ctx.payloads.for_category("redirect", limit=10)
    candidates = [p for p in params if any(h in p.lower() for h in REDIRECT_PARAM_HINTS)]
    if not candidates:
        return findings

    async def test(param: str) -> None:
        for p in payloads:
            ev = await ctx.http.get(merge_query(url, {param: p}), allow_redirects=False)
            loc = ev.response_headers.get("location") or ev.response_headers.get("Location")
            if not loc:
                continue
            host = urlparse(loc).netloc.lower()
            if "samaritanx.test" in host or "evil." in host or host.startswith("evil"):
                findings.append({
                    "category": "open_redirect",
                    "title": f"Open redirect in `{param}`",
                    "severity": "medium", "cvss": 6.1,
                    "url": url, "parameter": param, "payload": p,
                    "evidence": f"Location header points to attacker-controlled host: {loc}",
                    "request": f"GET {ev.url}",
                    "response": loc,
                    "metadata": {"location": loc},
                })
                ctx.memory.record_payload_result(p, "redirect", True)
                return
            ctx.memory.record_payload_result(p, "redirect", False)

    await asyncio.gather(*(test(p) for p in candidates))
    return findings
