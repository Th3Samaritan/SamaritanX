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

    # unkeyed-query probe: when the cache ignores the query string, a
    # reflected query value is a poisoning primitive and distinct query
    # values sharing one cached response is the tell
    findings.extend(await _unkeyed_query(ctx, url))
    return findings


async def _unkeyed_query(ctx, url):
    """Detect query strings that the cache does not key on."""
    from core.utils import merge_query
    marker1 = f"sxcq{random_token(6)}"
    marker2 = f"sxcq{random_token(6)}"
    ev1 = await ctx.http.get(merge_query(url, {"sxcachebust": marker1}))
    ev2 = await ctx.http.get(merge_query(url, {"sxcachebust": marker2}))
    body2 = ev2.response_body or ""
    # poisoning proof: the second distinct query value still returns the
    # FIRST marker — the cached response was built from a different request
    if marker1 in body2 and marker2 not in body2:
        from core.poc import proof_record
        poc = proof_record(
            verified=True, method="GET", url=url,
            request=(f"GET {url}?sxcachebust={marker1}\nthen GET "
                     f"{url}?sxcachebust={marker2}"),
            status=ev2.status, excerpt=body2,
            rationale=(f"A request for a fresh cache-buster ({marker2}) returned the response "
                       f"built from a DIFFERENT query ({marker1}) — the cache ignores the query "
                       "string, so any reflected query parameter poisons every visitor's response."))
        return [{
            "category": "cache_poisoning",
            "title": "Web cache poisoning via unkeyed query string",
            "severity": "high", "cvss": 7.5,
            "url": url,
            "evidence": f"Query `?sxcachebust={marker2}` returned the response cached for "
                        f"`?sxcachebust={marker1}` — the query string is unkeyed.",
            "request": f"GET {url}?sxcachebust={marker1}",
            "response": body2[:1500],
            "metadata": {"unkeyed_query": True, "poc": poc},
        }]
    # cache-hit on distinct query values without reflection -> unkeyed, low signal
    from scanners.web_cache_deception import _is_cache_hit
    if _is_cache_hit(ev2.response_headers):
        return [{
            "category": "cache_poisoning",
            "title": "Cache ignores query string (unkeyed) — poisoning surface",
            "severity": "low", "cvss": 3.7,
            "url": url,
            "evidence": "Two requests with different query values both served from cache — "
                        "the query string is not part of the cache key.",
            "request": f"GET {url}?sxcachebust={marker1}",
            "metadata": {"unkeyed_query": True},
        }]
    return []
