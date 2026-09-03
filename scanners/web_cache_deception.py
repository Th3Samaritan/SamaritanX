"""Web Cache Deception scanner.

Different bug from cache *poisoning*. WCD abuses the gap between how the CDN
decides what to cache (often: file extension) and how the origin routes the
request (often: ignores the trailing `/foo.css`). The attacker tricks the
victim into loading `https://target/account/settings/foo.css`; the origin
serves the victim's *private* account page, the CDN sees `.css` and caches it
publicly — now the attacker fetches the same URL unauthenticated and reads the
victim's data straight from the cache.

The check is self-escalating: it only reports when the anonymous fetch actually
returns the authenticated user's private data, so severity reflects real
impact. Read-only (GET) — always safe to run.
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

from core.escalation import sensitive_hits, severity_for
from core.utils import random_token
from scanners.idor_deep import identity_markers

if TYPE_CHECKING:
    from core.orchestrator import Context

CACHE_HEADERS = ("x-cache", "cf-cache-status", "x-cache-hits", "age",
                 "x-served-by", "x-drupal-cache", "cache-control", "x-proxy-cache")


def _deception_urls(url: str) -> list[tuple[str, str]]:
    """(technique, crafted_url) for the common path-confusion styles."""
    p = urlparse(url)
    path = p.path.rstrip("/")
    tok = random_token(6)
    out: list[tuple[str, str]] = []
    for ext in (".css", ".js", ".jpg", ".ico"):
        out.append((f"path_append{ext}", urlunparse(p._replace(path=f"{path}/{tok}{ext}"))))
        out.append((f"semicolon{ext}", urlunparse(p._replace(path=f"{path};{tok}{ext}"))))
        out.append((f"pathparam{ext}", urlunparse(p._replace(path=f"{path}%2f{tok}{ext}"))))
    out.append(("encoded_newline.css", urlunparse(p._replace(path=f"{path}%0a{tok}.css"))))
    out.append(("double_slash.css", urlunparse(p._replace(path=f"{path}//{tok}.css"))))
    return out


def _cache_evidence(headers: dict) -> str:
    bits = {k: v for k, v in (headers or {}).items() if k.lower() in CACHE_HEADERS}
    return ", ".join(f"{k}={v}" for k, v in bits.items()) or "no explicit cache headers"


def _is_cache_hit(headers: dict) -> bool:
    h = {k.lower(): (v or "").lower() for k, v in (headers or {}).items()}
    if "hit" in h.get("x-cache", "") or h.get("cf-cache-status", "") in ("hit",):
        return True
    if h.get("x-proxy-cache", "") == "hit" or h.get("x-drupal-cache", "") == "hit":
        return True
    try:
        if int(h.get("age", "0")) > 0:
            return True
    except ValueError:
        pass
    return False


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    # WCD only matters on authenticated, user-specific responses.
    if not (ctx.http.session and ctx.http.session.is_authed()):
        return findings

    # Baseline: the genuine authenticated page must itself be private/dynamic.
    base = await ctx.http.get(url)
    if base.status >= 400 or not base.response_body:
        return findings
    base_markers = identity_markers(base.response_body) | {
        s for _, s in sensitive_hits(base.response_body, base.response_headers)}
    if not base_markers:
        return findings  # nothing private to leak — skip

    for technique, durl in _deception_urls(url):
        # 1) authenticated fetch of the crafted URL — does the origin still
        #    serve the victim's private page (extension ignored by routing)?
        authed = await ctx.http.get(durl)
        if authed.status >= 400 or not authed.response_body:
            continue
        authed_markers = identity_markers(authed.response_body) | {
            s for _, s in sensitive_hits(authed.response_body, authed.response_headers)}
        private_leak = base_markers & authed_markers
        if not private_leak:
            continue  # crafted URL didn't return private content

        # 2) anonymous fetch of the SAME URL — is the private response cached
        #    and served without the victim's credentials?
        anon = await ctx.http.get(durl, no_session=True)
        if anon.status >= 400 or not anon.response_body:
            continue
        anon_markers = identity_markers(anon.response_body) | {
            s for _, s in sensitive_hits(anon.response_body, anon.response_headers)}
        leaked = private_leak & anon_markers
        if not leaked:
            continue  # not served to anonymous user → no deception

        # confirmed: victim's private data reachable anonymously via cache
        hits = sensitive_hits(anon.response_body, anon.response_headers)
        esc = severity_for(hits)
        sev, cvss = esc if esc else ("high", 8.2)
        cache_ev = _cache_evidence(anon.response_headers)
        from core.poc import proof_record
        poc = proof_record(
            verified=True, method="GET", url=durl,
            request=f"victim: GET {durl} (authenticated)\nattacker: GET {durl} (no cookies)",
            status=anon.status, excerpt=anon.response_body,
            rationale=(f"The origin served the authenticated user's private page at the "
                       f"cacheable URL {durl}; an anonymous re-fetch of the same URL returned "
                       f"that private data ({sorted(leaked)[:3]}) — private content is cached "
                       "and served without credentials."))
        findings.append({
            "category": "web_cache_deception",
            "title": f"Web cache deception — private response cached publicly ({technique})",
            "severity": sev, "cvss": cvss,
            "url": durl, "parameter": technique,
            "evidence": (f"`{technique}` made the origin serve the authenticated user's private "
                         f"page at a cacheable URL; an anonymous request to the same URL returned "
                         f"the victim's data ({sorted(leaked)[:3]}). Cache signals: {cache_ev}."),
            "request": f"victim: GET {durl} (authenticated)\nattacker: GET {durl} (no cookies)",
            "response": anon.response_body[:1500],
            "metadata": {"technique": technique, "leaked": sorted(leaked)[:5],
                         "cache_hit": _is_cache_hit(anon.response_headers),
                         "original": url, "poc": poc},
        })
        return findings  # one solid PoC is enough
    return findings
