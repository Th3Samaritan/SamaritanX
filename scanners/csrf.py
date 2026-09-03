"""CSRF detector — flags state-changing forms missing anti-CSRF tokens or SameSite cookies."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.orchestrator import Context

TOKEN_HINTS = ("csrf", "xsrf", "authenticity", "_token", "nonce")


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    if form is None:
        return findings
    if form.get("method", "GET").upper() not in ("POST", "PUT", "DELETE", "PATCH"):
        return findings

    inputs = form.get("inputs", [])
    has_token = any(any(h in (i.get("name") or "").lower() for h in TOKEN_HINTS) for i in inputs)

    # SameSite is a property of the *session* cookies (issued at login), not of
    # whatever cookie the form page happens to set. Consult the session store
    # first, then fall back to any Set-Cookie observed on the form page itself.
    samesite: str | None = None
    session = getattr(ctx, "session", None)
    if session is not None:
        samesite = getattr(session, "same_site", None)
    if samesite is None:
        cache = getattr(ctx, "cache", None)
        ev = await cache.fetch(ctx.http, url) if cache else await ctx.http.get(url)
        raw = [v for v in ((ev.extra or {}).get("set_cookie_headers") or [])]
        blob = " ".join(raw).lower()
        if "samesite=strict" in blob:
            samesite = "strict"
        elif "samesite=lax" in blob:
            samesite = "lax"
        elif "samesite=none" in blob:
            samesite = "none"

    if has_token or samesite in ("strict", "lax"):
        return findings

    # No token field and no observed SameSite hardening. If a session cookie
    # exists but its SameSite attribute was never observed, say so honestly —
    # don't claim the app is unprotected.
    if session is not None and session.is_authed() and samesite is None:
        evidence = ("Form accepts a state-changing method without an anti-CSRF token. "
                    "The session cookie's SameSite attribute could not be observed — "
                    "verify manually whether the cookie enforces SameSite.")
    else:
        evidence = ("Form accepts a state-changing method without an anti-CSRF token field "
                    "and no SameSite=Strict/Lax hardening was observed on the session cookies.")
    findings.append({
        "category": "csrf",
        "title": f"State-changing form missing CSRF protection: {form.get('action')}",
        "severity": "medium", "cvss": 5.4,
        "url": form.get("action"),
        "evidence": evidence,
        "request": f"{form.get('method')} {form.get('action')}",
        "metadata": {"inputs": [i.get("name") for i in inputs], "same_site_observed": samesite},
    })
    return findings
