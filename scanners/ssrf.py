"""SSRF scanner.

Heuristics:
  * inject internal / cloud-metadata / file:// URLs into each parameter
  * detect:
        - direct response containing 'iam', 'ami-id', 'computeMetadata', etc.
        - leaked file:// content (root:x:0:0:)
        - **out-of-band callbacks** via interactsh — proves blind SSRF
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from core.utils import merge_query, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

INDICATORS = [
    ("aws_metadata", "ami-id"),
    ("aws_metadata", "iam/security-credentials"),
    ("gcp_metadata", "computeMetadata"),
    ("azure_metadata", "metadata/instance"),
    ("file_etc_passwd", "root:x:0:0:"),
    ("redis_info", "redis_version"),
    ("memcached_stats", "STAT pid"),
]


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    payloads = ctx.payloads.for_category("ssrf", limit=18)
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    candidate_params = [p for p in params if any(k in p.lower() for k in
        ("url", "uri", "src", "dest", "redirect", "next", "image",
         "callback", "webhook", "feed", "site", "domain", "host", "target"))]
    if not candidate_params:
        candidate_params = params

    # fire OOB payloads in parallel with in-band probes — each parameter gets
    # a unique token so the polling result can be attributed back to it
    oob_tokens: dict[str, tuple[str, str]] = {}    # param -> (token, oob_url)

    async def test_param(param: str) -> None:
        # 1) in-band cloud-metadata / file:// indicators
        for p in payloads:
            async with sem:
                ev = await _request(ctx, url, method, param, p, form)
            body = (ev.response_body or "").lower()
            for label, marker in INDICATORS:
                if marker.lower() in body:
                    findings.append(_finding(url, param, p, "in-band", ev,
                        f"Response includes '{marker}' — internal resource reachable",
                        label=label))
                    ctx.memory.record_payload_result(p, "ssrf", True)
                    return
            ctx.memory.record_payload_result(p, "ssrf", False)

        # 2) out-of-band — only if collaborator is registered
        if ctx.oob and ctx.oob.registered:
            token = ctx.oob.token()
            oob_url = ctx.oob.url_for(token)
            oob_tokens[param] = (token, oob_url)
            async with sem:
                await _request(ctx, url, method, param, oob_url, form)

    await asyncio.gather(*(test_param(p) for p in candidate_params))

    # poll the OOB server once after firing — single round-trip is fine,
    # interactsh keeps interactions for ~10 minutes
    if ctx.oob and ctx.oob.registered and oob_tokens:
        await asyncio.sleep(2.0)  # let DNS hops settle
        for param, (token, oob_url) in oob_tokens.items():
            events = await ctx.oob.poll(token)
            if events:
                kinds = sorted({(e.get("protocol") or "?").lower() for e in events})
                findings.append(_finding(
                    url, param, oob_url, "oob",
                    type("E", (), {"method": method.upper(), "url": url,
                                   "response_body": ""})(),
                    f"OOB callback received via {kinds} — confirms blind SSRF "
                    f"({len(events)} interactions)",
                    label="oob"))
    return findings


async def _request(ctx, url, method, param, value, form):
    if method.upper() == "GET":
        return await ctx.http.get(merge_query(url, {param: value}))
    data = {i["name"]: i.get("value") or random_token(4) for i in (form or {}).get("inputs", [])}
    data[param] = value
    return await ctx.http.post(url, data=data)


def _finding(url, param, payload, kind, ev, evidence, *, label="") -> dict:
    sev, cvss = ("critical", 9.1) if kind in ("in-band", "oob") else ("high", 8.1)
    return {
        "category": "ssrf",
        "title": f"Server-Side Request Forgery in `{param}` "
                 f"({label or kind})",
        "severity": sev, "cvss": cvss,
        "url": url, "parameter": param, "payload": payload,
        "evidence": evidence,
        "request": f"{ev.method} {ev.url}",
        "response": (getattr(ev, 'response_body', '') or "")[:1500],
        "metadata": {"detection": kind, "indicator": label},
    }
