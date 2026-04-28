"""SSRF scanner.

Heuristics:
  * inject internal / cloud-metadata / file:// URLs into each parameter
  * detect:
        - direct response containing 'iam', 'ami-id', 'computeMetadata', etc.
        - leaked file:// content (root:x:0:0:)
        - server-side timeouts (DNS to fake host) — informational
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

    # filter for params likely to be SSRF sinks
    candidate_params = [p for p in params if any(k in p.lower() for k in
        ("url", "uri", "src", "dest", "redirect", "next", "image",
         "callback", "webhook", "feed", "site", "domain", "host", "target"))]
    if not candidate_params:
        candidate_params = params  # still try them all but lower priority

    async def test_param(param: str) -> None:
        for p in payloads:
            async with sem:
                ev = await _request(ctx, url, method, param, p, form)
            body = (ev.response_body or "").lower()
            for label, marker in INDICATORS:
                if marker.lower() in body:
                    findings.append({
                        "category": "ssrf",
                        "title": f"Server-Side Request Forgery in `{param}` ({label})",
                        "severity": "critical", "cvss": 9.1,
                        "url": url, "parameter": param, "payload": p,
                        "evidence": f"Response includes '{marker}' — internal resource reachable",
                        "request": f"{ev.method} {ev.url}",
                        "response": (ev.response_body or "")[:1500],
                        "metadata": {"indicator": label},
                    })
                    ctx.memory.record_payload_result(p, "ssrf", True)
                    return
            ctx.memory.record_payload_result(p, "ssrf", False)

    await asyncio.gather(*(test_param(p) for p in candidate_params))
    return findings


async def _request(ctx, url, method, param, value, form):
    if method.upper() == "GET":
        return await ctx.http.get(merge_query(url, {param: value}))
    data = {i["name"]: i.get("value") or random_token(4) for i in (form or {}).get("inputs", [])}
    data[param] = value
    return await ctx.http.post(url, data=data)
