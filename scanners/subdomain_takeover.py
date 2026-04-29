"""Subdomain takeover detector.

Resolves CNAME for each host, checks whether it points at a known SaaS
service whose unclaimed-subdomain fingerprint matches the response body.

Fingerprints sourced from the projectdiscovery / EdOverflow lists —
trimmed to the 25 services that pay out most often in bug bounty programs.
"""
from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING

from core.task_queue import Task

if TYPE_CHECKING:
    from core.orchestrator import Context

# (service, cname-substring, fingerprint-string)
FINGERPRINTS = [
    ("github_pages",  ".github.io",                "There isn't a GitHub Pages site here."),
    ("heroku",        ".herokuapp.com",            "No such app"),
    ("aws_s3",        ".s3.amazonaws.com",         "NoSuchBucket"),
    ("aws_s3_west",   ".s3-website",               "NoSuchBucket"),
    ("azure_cdn",     ".azureedge.net",            "Web Site Not Found"),
    ("azure_blob",    ".blob.core.windows.net",    "BlobNotFound"),
    ("azure_app",     ".azurewebsites.net",        "404 Web Site not found"),
    ("azure_traffic", ".trafficmanager.net",       "azure-traffic-manager"),
    ("shopify",       "myshopify.com",             "Sorry, this shop is currently unavailable."),
    ("squarespace",   ".squarespace.com",          "No Such Account"),
    ("tumblr",        ".tumblr.com",               "Whatever you were looking for doesn't currently exist"),
    ("webflow",       ".webflow.io",               "The page you are looking for doesn't exist or has been moved"),
    ("readme",        ".readme.io",                "Project doesnt exist... yet!"),
    ("strikingly",    ".s.strikinglydns.com",      "PAGE NOT FOUND"),
    ("zendesk",       ".zendesk.com",              "Help Center Closed"),
    ("freshdesk",     ".freshdesk.com",            "There is no helpdesk here"),
    ("ghost",         ".ghost.io",                 "The thing you were looking for is no longer here"),
    ("statuspage",    ".statuspage.io",            "You are being redirected"),
    ("uservoice",     ".uservoice.com",            "This UserVoice subdomain is currently available"),
    ("cargo",         "subdomain.cargocollective.com", "404 Not Found"),
    ("kinsta",        "kinsta.cloud",              "No Site For Domain"),
    ("netlify",       ".netlify.app",              "Not Found - Request ID"),
    ("pantheon",      ".pantheonsite.io",          "The gods are wise"),
    ("vercel",        ".vercel.app",               "DEPLOYMENT_NOT_FOUND"),
    ("fastly",        ".fastly.net",               "Fastly error: unknown domain"),
]


def _resolve_cname(host: str) -> str | None:
    try:
        import dns.resolver
        ans = dns.resolver.resolve(host, "CNAME", lifetime=4)
        return str(ans[0].target).rstrip(".")
    except Exception:
        return None


async def scan_takeover(ctx: "Context", task: Task) -> None:
    hosts = task.payload.get("hosts") or []
    sem = asyncio.Semaphore(8)
    findings = 0

    async def check(host: str) -> None:
        nonlocal findings
        cname = await asyncio.get_event_loop().run_in_executor(None, _resolve_cname, host)
        if not cname:
            return
        match = next((f for f in FINGERPRINTS if f[1] in cname), None)
        if not match:
            return
        service, _, fingerprint = match
        async with sem:
            ev = await ctx.http.get(f"https://{host}", bypass_scope=True)
        if fingerprint.lower() in (ev.response_body or "").lower():
            from agents.base import BaseAgent  # noqa
            ctx.memory.record_finding({
                "target": ctx.target_slug,
                "category": "takeover",
                "title": f"Subdomain takeover candidate: {host} -> {service}",
                "severity": "critical", "cvss": 8.8,
                "url": f"https://{host}",
                "payload": cname,
                "evidence": f"CNAME points to unclaimed {service} service: '{fingerprint}' in body",
                "request": f"GET https://{host}",
                "response": (ev.response_body or "")[:1500],
                "metadata": {"cname": cname, "service": service},
            })
            ctx.dashboard.add_count("findings")
            ctx.dashboard.add_count("critical")
            ctx.dashboard.event("crit",
                f"[CRITICAL] Subdomain takeover ({service}) on {host}")
            findings += 1

    await asyncio.gather(*(check(h) for h in hosts))
    ctx.dashboard.event("ok" if findings else "info",
                        f"takeover: {findings} candidates across {len(hosts)} hosts")


async def scan(ctx, url, params, method="GET", form=None):
    """Per-URL noop — takeover is run from the dedicated 'scan.takeover' kind."""
    return []
