"""Host-header injection scanner.

Probes whether the application trusts the ``Host`` / ``X-Forwarded-Host``
header to build absolute URLs, canonical links, or redirects. That trust is
the primitive behind password-reset-link poisoning, SSO callback hijacking,
and cache poisoning:

  * request with ``Host: <unique-marker>.evil.samaritanx.test``
  * the response body / Link+Location headers are scanned for the marker
  * only a marker that is **absent from the clean baseline** counts —
    static page content can never false-fire
  * the finding carries a captured proof record (the poisoned response)

Reported conservatively: the reflection itself proves the trust boundary;
exploitability depends on the flow (reset link / SSO), which the finding
evidence explains.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from core.utils import random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

POISON_HEADERS = ("Host", "X-Forwarded-Host", "X-Forwarded-Server", "Forwarded")


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    if method.upper() != "GET":
        return findings
    marker_host = f"sx-{random_token(8)}.evil.samaritanx.test"
    cache = getattr(ctx, "cache", None)
    base = await cache.fetch(ctx.http, url, allow_redirects=False) if cache \
        else await ctx.http.get(url, allow_redirects=False)
    base_blob = ((base.response_body or "") + " "
                 + base.response_headers.get("location", "") + " "
                 + base.response_headers.get("link", "")).lower()

    for header in POISON_HEADERS:
        value = marker_host if header != "Forwarded" else f"host={marker_host}"
        ev = await ctx.http.get(url, headers={header: value}, allow_redirects=False)
        if not ev.status:
            continue
        body = ev.response_body or ""
        loc = ev.response_headers.get("location", "")
        link = ev.response_headers.get("link", "")
        blob = (body + " " + loc + " " + link).lower()
        if marker_host in blob and marker_host not in base_blob:
            where = "Location header" if marker_host in (loc or "").lower() else \
                    "Link header" if marker_host in (link or "").lower() else "response body"
            from core.poc import proof_record
            poc = proof_record(
                verified=True, method="GET", url=url,
                request=f"GET {url}\n{header}: {value}",
                status=ev.status, excerpt=body,
                rationale=(f"The attacker-controlled host `{marker_host}` sent in `{header}` "
                           f"was reflected into the {where}. The application builds URLs from "
                           "an unvalidated Host header — poisonable reset links / SSO callbacks "
                           "are the exploitable consequences."))
            findings.append({
                "category": "host_header",
                "title": f"Host-header injection — trusted `{header}` reflected ({urlparse(url).path})",
                "severity": "medium", "cvss": 6.1,
                "url": url, "parameter": f"header:{header}", "payload": value,
                "evidence": f"`{header}: {value}` surfaced in the {where} while absent from the "
                            "clean baseline — absolute URLs are built from an attacker-controlled "
                            "host (password-reset / SSO poisoning primitive).",
                "request": f"GET {url}\n{header}: {value}",
                "response": body[:1500],
                "metadata": {"detection": "marker", "header": header,
                             "marker": marker_host, "poc": poc},
            })
            return findings  # one confirmed channel is enough
    return findings
