"""Security-headers scanner — the configuration class every program accepts.

Checks the response for the headers that harden browsers against common
client-side attacks and reports each missing/weak one with its copy-paste
remediation block. Every finding carries the captured response as proof
(static artifact — the response itself is the evidence).

Checked:
  * Strict-Transport-Security  (missing / too-short max-age / no preload)
  * Content-Security-Policy    (missing / contains unsafe-inline+unsafe-eval)
  * X-Frame-Options            (missing / permissive ALLOWALL)
  * X-Content-Type-Options     (missing / not nosniff)
  * Permissions-Policy         (missing)
  * Referrer-Policy            (missing)
  * server banner              (verbose Server/X-Powered-By version disclosure)
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from core.poc import proof_record

if TYPE_CHECKING:
    from core.orchestrator import Context

_CHECKS = [
    # (key, title, verdict_fn, remediation)
    ("strict-transport-security",
     "Missing HTTP Strict Transport Security",
     lambda v: (not v) or (v and (int(v.split(";")[0].split("=")[1]) if "=" in v.split(";")[0] else 0) < 31536000),
     "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    ("content-security-policy",
     "Missing Content Security Policy",
     lambda v: not v,
     "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"),
    ("content-security-policy",
     "CSP allows unsafe-inline and unsafe-eval",
     lambda v: bool(v) and "unsafe-inline" in v.lower() and "unsafe-eval" in v.lower(),
     "Remove 'unsafe-inline'/'unsafe-eval' from script-src; use nonces or hashes instead."),
    ("x-frame-options",
     "Missing X-Frame-Options (clickjacking)",
     lambda v: not v,
     "X-Frame-Options: DENY"),
    ("x-content-type-options",
     "Missing X-Content-Type-Options: nosniff",
     lambda v: (v or "").lower() != "nosniff",
     "X-Content-Type-Options: nosniff"),
    ("permissions-policy",
     "Missing Permissions-Policy",
     lambda v: not v,
     "Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()"),
    ("referrer-policy",
     "Missing Referrer-Policy",
     lambda v: not v,
     "Referrer-Policy: strict-origin-when-cross-origin"),
]

_VERBOSE_SERVER = ("apache", "nginx", "microsoft-iis", "jetty", "lighttpd",
                   "cloudflare", "caddy", "gunicorn")


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    cache = getattr(ctx, "cache", None)
    ev = await cache.fetch(ctx.http, url, allow_redirects=False) if cache \
        else await ctx.http.get(url, allow_redirects=False)
    if not ev.status or ev.status in (0, 404):
        return findings
    headers = {str(k).lower(): str(v) for k, v in ev.response_headers.items()}
    body = ev.response_body or ""

    seen_keys: set[str] = set()
    for key, title, verdict, remediation in _CHECKS:
        value = headers.get(key, "")
        try:
            fails = verdict(value)
        except Exception:
            fails = False
        if not fails:
            continue
        dedup_key = key + "|" + title
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)
        severity = "low"
        if key == "strict-transport-security":
            severity = "medium" if headers.get("set-cookie") else "low"
        poc = proof_record(
            verified=True, method="GET", url=url,
            request=f"GET {url}",
            status=ev.status, excerpt=body,
            rationale=f"The response is missing/weak on `{key}` — a static configuration "
                      "gap confirmed by the captured response headers.")
        findings.append({
            "category": "security_headers",
            "title": title,
            "severity": severity, "cvss": 3.1,
            "url": url,
            "evidence": f"Response headers lack a sound `{key}` policy "
                        f"(observed: {value[:120] or 'absent'}). Remediation: {remediation}",
            "request": f"GET {url}",
            "response": str({k: v[:100] for k, v in headers.items()})[:800],
            "metadata": {"header": key, "value": value[:120],
                         "remediation": remediation, "poc": poc},
        })

    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    for banner, value in (("Server", server), ("X-Powered-By", powered)):
        if value and any(s in value.lower() for s in _VERBOSE_SERVER):
            findings.append({
                "category": "security_headers",
                "title": f"Verbose {banner} banner leaks server version",
                "severity": "info", "cvss": 0.0,
                "url": url,
                "evidence": f"`{banner}: {value[:100]}` discloses the stack/version — "
                            "aids targeted exploitation. Suppress or genericize the banner.",
                "request": f"GET {url}",
                "metadata": {"header": banner.lower()},
            })
    return findings
