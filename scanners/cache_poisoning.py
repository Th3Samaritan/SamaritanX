"""Web cache poisoning probe.

Sends an unkeyed header (X-Forwarded-Host, X-Forwarded-Scheme, X-Host)
with an attacker-controlled value, then re-fetches the URL clean and
checks whether the poisoned value persisted in the response (Location,
absolute links inside HTML, etc.).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from core.utils import random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

POISON_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
]


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    marker = f"sx-{random_token(6)}.evil.tld"
    for h in POISON_HEADERS:
        # 1) prime cache with poison
        await ctx.http.get(url, headers={h: marker})
        # 2) clean request — see if marker leaks into the cached response
        ev = await ctx.http.get(url)
        body = ev.response_body or ""
        loc = ev.response_headers.get("location", "") + " " + ev.response_headers.get("link", "")
        if marker in body or marker in loc:
            from core.poc import proof_record
            poc = proof_record(
                verified=True, method="GET", url=url,
                request=f"GET {url}\n{h}: {marker}\nthen GET {url} (clean)",
                status=ev.status, excerpt=body,
                rationale=(f"A clean re-fetch of {url} (no poison headers) returned the "
                           f"attacker-controlled marker `{marker}` — the unkeyed `{h}` "
                           "header value was cached and served to other clients."))
            findings.append({
                "category": "cache_poisoning",
                "title": f"Web cache poisoning via `{h}` header",
                "severity": "high", "cvss": 7.5,
                "url": url,
                "evidence": f"Poison marker '{marker}' surfaced in cached clean response — "
                            f"unkeyed header `{h}` is reflected and cached.",
                "request": f"GET {url}\n{h}: {marker}",
                "response": body[:1500],
                "metadata": {"header": h, "poc": poc},
            })
            return findings  # one confirmed channel is enough
    return findings
