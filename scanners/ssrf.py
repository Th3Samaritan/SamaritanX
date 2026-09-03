"""SSRF scanner — broader parameter set + header-based SSRF + OOB.

Coverage:
  * **expanded candidate parameter list** — also includes endpoint, path,
    file, resource, link, proxy, forward, load, fetch, ref, data, content,
    template, render, source, target, location, host_url
  * in-band cloud-metadata / file:// / Redis / Memcached indicators
  * **header-based SSRF** — injects internal/OOB targets via the headers
    proxies and routers most often re-emit:
        X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Server,
        X-Original-URL, X-Rewrite-URL, X-Custom-IP-Authorization,
        Forwarded, Referer, X-Real-IP, X-Host, Client-IP
  * out-of-band callbacks via interactsh — proves blind SSRF
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

CANDIDATE_PARAM_HINTS = (
    # url-shaped
    "url", "uri", "src", "dest", "redirect", "next", "image", "callback",
    "webhook", "feed", "site", "domain", "host", "host_url", "target",
    # alternative names that also commonly drive server-side fetchers
    "endpoint", "path", "file", "resource", "link", "proxy", "forward",
    "load", "fetch", "ref", "data", "content", "template", "render",
    "source", "location", "remote", "page",
)

# headers worth abusing for header-based SSRF — the value gets fetched
# server-side by the proxy / router in many architectures
SSRF_HEADERS = (
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server",
    "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
    "Forwarded", "Referer", "X-Real-IP", "X-Host", "Client-IP",
    "True-Client-IP", "X-Originating-IP", "X-Backend-Server",
    "X-Forwarded-Proto",
)


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    payloads = ctx.payloads.for_category("ssrf", limit=18)
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    # candidate filter — score every param, keep those with hints, fall back
    # to the full list if nothing scores
    scored = [p for p in params if any(k in p.lower() for k in CANDIDATE_PARAM_HINTS)]
    candidate_params = scored or params
    oob_param_tokens: dict[str, tuple[str, str]] = {}

    # baseline body — an indicator that is already present on the clean page
    # (docs page mentioning "ami-id" etc.) is not evidence of SSRF
    base_ev = await ctx.http.get(url)
    base_body = (base_ev.response_body or "").lower() if base_ev.status else ""

    async def test_param(param: str) -> None:
        # 1) in-band cloud-metadata / file:// indicators
        for p in payloads:
            async with sem:
                ev = await _request(ctx, url, method, param, p, form)
            body = (ev.response_body or "").lower()
            for label, marker in INDICATORS:
                if marker.lower() in body and marker.lower() not in base_body:
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
            oob_param_tokens[param] = (token, oob_url)
            ctx.oob.register(token, {
                "category": "ssrf",
                "title": "Blind SSRF — out-of-band callback",
                "severity": "high", "cvss": 8.6,
                "url": url, "parameter": param, "payload": oob_url,
                "evidence": f"The {param} parameter caused the server to make an out-of-band "
                            "request to our controlled host (blind SSRF).",
                "_detection": "oob", "_method": method.upper(),
                "_request": f"{method.upper()} {url}\n{param}={oob_url}",
                "_oob_ref": oob_url,
            })
            async with sem:
                await _request(ctx, url, method, param, oob_url, form)

    await asyncio.gather(*(test_param(p) for p in candidate_params))

    # 3) header-based SSRF — fire OOB tokens through every headers we expect
    #    intermediaries to consume
    oob_header_tokens: dict[str, tuple[str, str]] = {}
    if ctx.oob and ctx.oob.registered:
        for header in SSRF_HEADERS:
            token = ctx.oob.token()
            target = ctx.oob.host_for(token)  # raw host — most proxies want a host:port
            oob_header_tokens[header] = (token, target)
            ctx.oob.register(token, {
                "category": "ssrf",
                "title": f"Blind SSRF via {header} header — out-of-band callback",
                "severity": "high", "cvss": 8.6,
                "url": url, "parameter": f"header:{header}", "payload": target,
                "evidence": f"The {header} request header caused an out-of-band callback — an "
                            "intermediary or the origin fetched the attacker-supplied host.",
                "_detection": "oob-header", "_method": "GET",
                "_request": f"GET {url}\n{header}: {target}",
                "_oob_ref": target,
            })
            async with sem:
                await ctx.http.get(url, headers={header: target})

    # OOB callbacks: both param- and header-based tokens are registered with
    # the OOB client above — the background poller plus the finalize sweep
    # emit them via oob.pending_findings(). We must NOT also self-report here;
    # doing so recorded the same callback twice with two different titles.
    return findings


async def _request(ctx, url, method, param, value, form):
    from core.injection import send
    return await send(ctx, url, method, param, value, form)


def _finding(url, param, payload, kind, ev, evidence, *, label="") -> dict:
    sev, cvss = ("critical", 9.1)
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
