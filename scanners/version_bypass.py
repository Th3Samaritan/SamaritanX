"""API version-bypass scanner.

When `/api/v1/admin/users` returns 401/403, a real-world bug class is the
sibling-version oversight: the same endpoint at `/api/v2/`, `/internal/`,
`/api/v1.1/`, `/api/admin/`, `/api/_legacy/` returning 200 with the
admin-only data.

For every URL whose response code is 401/403, this scanner generates
sibling URLs by substituting the version segment (and adding common
internal/admin prefixes) and reports the first one that returns 200
with non-trivial body.
"""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

if TYPE_CHECKING:
    from core.orchestrator import Context

VERSION_RE = re.compile(r"/(v\d+(?:\.\d+)?)(/|$)", re.I)
SIBLING_VERSIONS = ["v1", "v1.1", "v2", "v3", "v4",
                    "internal", "private", "admin", "_legacy", "_dev"]


def _siblings(url: str) -> list[str]:
    p = urlparse(url)
    out: set[str] = set()
    if not p.path:
        return []
    m = VERSION_RE.search(p.path)
    if m:
        for sib in SIBLING_VERSIONS:
            new_path = p.path[:m.start(1)] + sib + p.path[m.end(1):]
            out.add(urlunparse(p._replace(path=new_path)))
    # also try injecting an /internal/ prefix after /api/
    if "/api/" in p.path and "/internal/" not in p.path:
        new_path = p.path.replace("/api/", "/api/internal/", 1)
        out.add(urlunparse(p._replace(path=new_path)))
        new_path = p.path.replace("/api/", "/api/admin/", 1)
        out.add(urlunparse(p._replace(path=new_path)))
    return sorted(out - {url})


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    # only fire when the canonical URL refuses us
    ev = await ctx.http.get(url)
    if ev.status not in (401, 403):
        return findings
    siblings = _siblings(url)
    if not siblings:
        return findings
    sem = asyncio.Semaphore(8)

    async def probe(sib: str) -> None:
        async with sem:
            e = await ctx.http.get(sib)
        body = e.response_body or ""
        if e.status != 200 or len(body) <= 200:
            return
        # a 200 can be a login page / SPA catch-all / error page — require real
        # privileged-looking content, not just "something answered 200"
        from core.poc import is_auth_wall, is_static_asset
        wall, why = is_auth_wall(e.status, e.response_headers, body, sib)
        if wall or is_static_asset(sib, e.response_headers):
            return
        from scanners.idor_deep import identity_markers
        from core.escalation import sensitive_hits
        markers = identity_markers(body)
        sensitive = [k for k, _ in sensitive_hits(body, e.response_headers)]
        if not markers and not sensitive:
            return
        findings.append({
            "category": "broken_auth",
            "title": f"API version-bypass: privileged data via sibling URL {sib}",
            "severity": "critical", "cvss": 9.0,
            "url": sib,
            "evidence": f"Original {url} returned {ev.status}, but {sib} returned 200 "
                        f"with {len(body)} bytes of privileged content "
                        f"(identity markers={sorted(markers)[:5]}, sensitive={sensitive}) — "
                        "sibling endpoint exposes data the canonical version protects.",
            "request": f"GET {sib}",
            "response": body[:1500],
            "metadata": {"original": url, "sibling": sib,
                         "original_status": ev.status,
                         "markers": sorted(markers)[:6], "sensitive": sensitive},
        })

    await asyncio.gather(*(probe(s) for s in siblings))
    return findings
