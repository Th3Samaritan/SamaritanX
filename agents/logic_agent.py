"""Business-logic / multi-step abuse analysis.

Pure HTTP scanners can't see workflows — this agent looks at the corpus the
crawler collected and reasons about chain abuse:

    * authentication bypass: hit /admin/* and protected paths anonymously
    * forced browsing: enumerate known sensitive paths
    * privilege escalation: replay admin-shaped paths with no auth header
    * payment / pricing tampering: forms with `price`/`amount`/`total` fields
    * race-condition candidates: endpoints with `transfer`, `redeem`,
      `apply`, `coupon`, `vote` in the path — fire 25 concurrent requests
      and report when more than one succeeds for the same nominal action
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from core.task_queue import Task
from .base import BaseAgent

if TYPE_CHECKING:
    from core.orchestrator import Context

SENSITIVE_PATHS = (
    "/.env", "/.git/config", "/.git/HEAD", "/.aws/credentials",
    "/admin", "/admin/", "/administrator", "/wp-admin",
    "/server-status", "/actuator", "/actuator/env", "/actuator/heapdump",
    "/console", "/h2-console", "/debug", "/_debug/", "/swagger.json",
    "/openapi.json", "/api-docs", "/.well-known/security.txt",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/phpinfo.php", "/info.php", "/status",
)
ADMIN_HINTS = ("admin", "manage", "internal", "private", "console", "dashboard")
PRICING_HINTS = ("price", "amount", "total", "cost", "discount", "coupon", "balance")
RACE_HINTS = ("transfer", "withdraw", "redeem", "apply", "coupon",
              "vote", "purchase", "checkout", "claim", "reward")


class LogicAgent(BaseAgent):
    name = "logic"
    handles = ("logic",)

    async def handle(self, task: Task, ctx: "Context") -> None:
        endpoints: list[str] = task.payload.get("endpoints", [])
        forms: list[dict] = task.payload.get("forms", [])
        if not endpoints:
            return
        host = urlparse(endpoints[0]).netloc
        base = f"{urlparse(endpoints[0]).scheme}://{host}"

        await asyncio.gather(
            self._sensitive_paths(base, ctx),
            self._admin_anon(endpoints, ctx),
            self._pricing_tamper(forms, ctx),
            self._race_conditions(endpoints, ctx),
        )

    async def _sensitive_paths(self, base: str, ctx: "Context") -> None:
        for path in SENSITIVE_PATHS:
            url = urljoin(base, path)
            ev = await ctx.http.get(url)
            if ev.status not in (200, 401, 403):
                continue
            body = (ev.response_body or "")[:400]
            if ev.status == 200 and len(ev.response_body or "") > 50:
                self.report_finding(ctx, {
                    "category": "exposure",
                    "title": f"Sensitive path publicly accessible: {path}",
                    "severity": "high", "cvss": 7.5,
                    "url": url,
                    "evidence": f"HTTP 200 returned with {len(ev.response_body or '')} bytes",
                    "request": f"GET {url}",
                    "response": body,
                })
            elif ev.status in (401, 403):
                ctx.dashboard.event("info", f"logic: protected path discovered {url} ({ev.status})")

    async def _admin_anon(self, endpoints: list[str], ctx: "Context") -> None:
        for url in endpoints:
            if not any(h in url.lower() for h in ADMIN_HINTS):
                continue
            ev = await ctx.http.get(url, headers={"Cookie": "", "Authorization": ""})
            if ev.status == 200 and len(ev.response_body or "") > 200:
                self.report_finding(ctx, {
                    "category": "broken_auth",
                    "title": f"Privileged page reachable without authentication: {url}",
                    "severity": "critical", "cvss": 9.0,
                    "url": url,
                    "evidence": "Admin-shaped path returned 200 with substantive body without any auth header.",
                    "request": f"GET {url}",
                    "response": (ev.response_body or "")[:1500],
                })

    async def _pricing_tamper(self, forms: list[dict], ctx: "Context") -> None:
        for form in forms:
            inputs = form.get("inputs", [])
            tamperable = [i["name"] for i in inputs if any(h in (i.get("name") or "").lower() for h in PRICING_HINTS)]
            if not tamperable:
                continue
            data = {i["name"]: i.get("value") or "1" for i in inputs}
            for k in tamperable:
                data[k] = "0.01"
            method = form.get("method", "POST").upper()
            url = form["action"]
            ev = await (ctx.http.post(url, data=data) if method != "GET" else ctx.http.get(url, params=data))
            if ev.status in (200, 201, 202):
                body = (ev.response_body or "").lower()
                if any(k in body for k in ("success", "ok", "created", "thank", "order")):
                    self.report_finding(ctx, {
                        "category": "logic",
                        "title": f"Possible pricing/amount tampering on {url}",
                        "severity": "high", "cvss": 7.4,
                        "url": url, "parameter": ",".join(tamperable),
                        "payload": "0.01",
                        "evidence": "Server accepted attacker-controlled price/amount field with success-shaped response.",
                        "request": f"{method} {url}\n{data}",
                        "response": (ev.response_body or "")[:1500],
                    })

    async def _race_conditions(self, endpoints: list[str], ctx: "Context") -> None:
        for url in endpoints:
            if not any(h in url.lower() for h in RACE_HINTS):
                continue
            results = await asyncio.gather(*[ctx.http.post(url) for _ in range(25)],
                                           return_exceptions=True)
            ok = [r for r in results if hasattr(r, "status") and r.status in (200, 201, 202)]
            if len(ok) > 1:
                self.report_finding(ctx, {
                    "category": "race_condition",
                    "title": f"Possible race condition on {url}",
                    "severity": "high", "cvss": 7.5,
                    "url": url,
                    "evidence": f"25 concurrent POSTs produced {len(ok)} success responses — endpoint lacks idempotency.",
                    "metadata": {"successes": len(ok)},
                })
                return
