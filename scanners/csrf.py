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

    # also probe Set-Cookie for SameSite hardening
    ev = await ctx.http.get(url)
    samesite_strict = False
    cookie = ev.response_headers.get("set-cookie", "") or ""
    if "samesite=strict" in cookie.lower() or "samesite=lax" in cookie.lower():
        samesite_strict = True

    if not has_token and not samesite_strict:
        findings.append({
            "category": "csrf",
            "title": f"State-changing form missing CSRF protection: {form.get('action')}",
            "severity": "medium", "cvss": 5.4,
            "url": form.get("action"),
            "evidence": "Form accepts POST/PUT/DELETE without an anti-CSRF token field "
                        "and the host's cookies do not enforce SameSite=Strict/Lax.",
            "request": f"{form.get('method')} {form.get('action')}",
            "metadata": {"inputs": [i.get("name") for i in inputs]},
        })
    return findings
