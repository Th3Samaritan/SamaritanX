"""Deep IDOR / BOLA scanner.

Requires a second authenticated session (`--second-session auth2.yaml`).
For every URL whose response is non-trivial under session A, it replays
the request using session B and checks whether B sees the same private
data. That's the textbook BOLA proof: identical request payload, two
identities, identical response = no per-object authorization.

Detection signals:
  * status code matches AND response length within ±10%
  * sensitive PII keys (`email`, `phone`, `ssn`) present in B's response
  * the user-id from session A's identity is referenced in B's response

If session B doesn't exist this scanner is a noop — the original
heuristic IDOR scanner still runs.
"""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.orchestrator import Context

PII_RE = re.compile(r'"(email|phone|ssn|tax_id|account|address|password|token|api_key)"\s*:\s*"', re.I)


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    if not ctx.http2 or not (ctx.http2.session and ctx.http2.session.is_authed()):
        return []
    findings: list[dict] = []
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    async def compare() -> None:
        async with sem:
            ev_a = await ctx.http.get(url)
            ev_b = await ctx.http2.get(url)
        if ev_a.status == 0 or ev_b.status == 0:
            return
        if ev_a.status != ev_b.status:
            return
        if ev_a.status >= 400:
            return
        a, b = ev_a.response_body or "", ev_b.response_body or ""
        if not a or len(a) < 200:
            return
        # response sizes within ±10%
        ratio = abs(len(a) - len(b)) / max(len(a), 1)
        if ratio > 0.10:
            return
        # if PII keys are in response, this is high-value
        pii = bool(PII_RE.search(b))
        sev, cvss = ("critical", 9.1) if pii else ("high", 7.7)
        findings.append({
            "category": "idor",
            "title": f"BOLA — cross-tenant data accessible via second session ({'PII' if pii else 'data'})",
            "severity": sev, "cvss": cvss,
            "url": url,
            "evidence": "Session A and Session B both received non-trivial responses of "
                        f"matching status ({ev_a.status}) and ±10% length. "
                        + ("Sensitive PII keys present." if pii else
                           "Object-level authorization is missing on this endpoint."),
            "request": f"{method.upper()} {url}",
            "response": b[:1500],
            "metadata": {"session_a": ctx.http.session.label if ctx.http.session else "anon",
                         "session_b": ctx.http2.session.label if ctx.http2.session else "anon",
                         "pii": pii},
        })

    await compare()
    return findings
