"""Prototype pollution — server-side probe.

Client-side prototype pollution is already detected by the DOM-XSS scanner,
which loads each page in a real browser and reports when `__proto__` /
`constructor.prototype` URL params mutate `Object.prototype` (its `proto.
pollution` sink hook). Launching a second browser here just duplicated that
work and — at one browser per URL — blew the per-scanner time budget on
API-heavy targets, so this scanner now focuses on the cheap, browser-free
*server-side* case the DOM scanner can't see:

    POST `{"__proto__": {...}}` / `{"constructor": {"prototype": {...}}}` and
    flag a reflected polluted key or a pollution-induced 5xx the clean request
    didn't produce (unsafe recursive merge on the server).

Reported conservatively — server-side PP usually needs a concrete gadget to
weaponise, so findings are flagged for manual confirmation.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from core.utils import random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

POLLUTED = "sxpolluted1"


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
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
