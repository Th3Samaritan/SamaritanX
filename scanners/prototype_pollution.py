"""Prototype pollution — client-side (confirmed in a real browser) + server-side.

Client-side: navigate to `?__proto__[sx]=POLLUTED` (and the `constructor.
prototype` form) in a headless browser and read back `Object.prototype.sx`. If
the polluted property is set on the global prototype, it's confirmed — a strong,
low-false-positive signal and a common gadget into DOM XSS.

Server-side: POST `{"__proto__": {...}}` / `{"constructor": {"prototype": {...}}}`
and look for a reflected polluted key or a pollution-induced error the baseline
didn't produce. Reported conservatively (needs manual confirmation).
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from core.utils import merge_query, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

POLLUTED = "sxpolluted1"


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    findings.extend(await _client_side(ctx, url))
    findings.extend(await _server_side(ctx, url))
    return findings


async def _client_side(ctx: "Context", url: str):
    prop = "sx" + random_token(5)
    vectors = [
        f"__proto__[{prop}]={POLLUTED}",
        f"constructor[prototype][{prop}]={POLLUTED}",
    ]
    try:
        from playwright.async_api import async_playwright
        from core.browser_pool import browser_slot
    except ImportError:
        return []
    for vec in vectors:
        target = url + ("&" if urlparse(url).query else "?") + vec
        try:
            async with browser_slot(ctx.config), async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
                page = await (await browser.new_context(ignore_https_errors=True)).new_page()
                try:
                    await page.goto(target, wait_until="networkidle", timeout=20000)
                except Exception:
                    pass
                polluted = await page.evaluate(f"() => Object.prototype.{prop} || null")
                await browser.close()
        except Exception:
            continue
        if polluted == POLLUTED:
            return [{
                "category": "prototype_pollution",
                "title": f"Client-side prototype pollution via `{vec.split('[')[0]}`",
                "severity": "high", "cvss": 8.1,
                "url": target, "parameter": vec,
                "evidence": f"After loading the URL, `Object.prototype.{prop}` === "
                            f"'{POLLUTED}'. The global prototype is attacker-controllable — "
                            "a gadget can escalate this to DOM XSS / logic bypass.",
                "request": f"GET {target}",
                "metadata": {"detection": "client_proto", "vector": vec},
            }]
    return []


async def _server_side(ctx: "Context", url: str):
    prop = "sx" + random_token(5)
    base = await ctx.http.get(url)
    base_status = base.status
    bodies = [
        {"__proto__": {prop: POLLUTED}},
        {"constructor": {"prototype": {prop: POLLUTED}}},
    ]
    for body in bodies:
        ev = await ctx.http.request("POST", url, json_body=body,
                                    headers={"Content-Type": "application/json"})
        resp = ev.response_body or ""
        # strong-ish signals only: polluted key reflected, or a 500 the clean
        # request didn't trigger (classic pollution crash)
        if POLLUTED in resp and prop in resp:
            return [_ss_finding(url, body, "medium", 6.1,
                "Server reflected the injected prototype property — input merges into an "
                "object prototype. Confirm a concrete gadget (e.g. status/isAdmin) manually.")]
        if ev.status >= 500 and base_status and base_status < 500:
            return [_ss_finding(url, body, "medium", 5.8,
                f"Prototype-pollution payload caused a {ev.status} where the clean request "
                f"returned {base_status} — likely unsafe recursive merge. Confirm manually.")]
    return []


def _ss_finding(url, body, sev, cvss, evidence):
    import json
    return {
        "category": "prototype_pollution",
        "title": "Server-side prototype pollution (candidate)",
        "severity": sev, "cvss": cvss,
        "url": url, "parameter": "__proto__",
        "payload": json.dumps(body),
        "evidence": evidence,
        "request": f"POST {url}\n\n{json.dumps(body)}",
        "metadata": {"detection": "server_proto"},
    }
