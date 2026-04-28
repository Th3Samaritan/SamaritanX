"""Reflected XSS scanner.

Strategy:
  * inject token-bearing payloads into each parameter
  * detect raw reflection of payload (reflected XSS)
  * detect reflection of marker without HTML encoding (likely DOM XSS)
Stored XSS detection requires multi-step flows — that's left to the
ExploitationAssistant when it reviews the findings list.
"""
from __future__ import annotations

import asyncio
import html
from typing import TYPE_CHECKING

from core.utils import merge_query, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    payloads = ctx.payloads.for_category("xss", limit=20)
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    async def test_param(param: str) -> None:
        marker = random_token(8)
        # 1) probe reflection with a benign marker first
        probe = f"sx{marker}"
        ev = await _request(ctx, url, method, param, probe, form)
        if not ev.response_body or probe not in ev.response_body:
            return  # parameter doesn't reflect — skip XSS payloads to save bandwidth
        # 2) try real payloads
        for p in payloads:
            async with sem:
                ev = await _request(ctx, url, method, param, p, form)
            body = ev.response_body or ""
            if not body:
                continue
            # raw payload present (unencoded)
            if p in body and html.escape(p) not in body.replace(p, ""):
                findings.append({
                    "category": "xss",
                    "title": f"Reflected XSS in `{param}`",
                    "severity": "high", "cvss": 6.1,
                    "url": url, "parameter": param, "payload": p,
                    "evidence": "Payload reflected without HTML encoding",
                    "request": f"{ev.method} {ev.url}",
                    "response": body[:1500],
                    "metadata": {"detection": "reflection-unencoded"},
                })
                ctx.memory.record_payload_result(p, "xss", True)
                return
            ctx.memory.record_payload_result(p, "xss", False)

    await asyncio.gather(*(test_param(p) for p in params))
    return findings


async def _request(ctx, url, method, param, value, form):
    if method.upper() == "GET":
        return await ctx.http.get(merge_query(url, {param: value}))
    data = {i["name"]: i.get("value") or random_token(4) for i in (form or {}).get("inputs", [])}
    data[param] = value
    return await ctx.http.post(url, data=data)
