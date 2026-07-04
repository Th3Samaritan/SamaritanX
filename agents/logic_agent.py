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
            self._coupon_reuse(forms, ctx),
            self._step_skip(endpoints, ctx),
            self._race_conditions(endpoints, ctx),
        )

    async def _sensitive_paths(self, base: str, ctx: "Context") -> None:
        from core.poc import is_auth_wall
        for path in SENSITIVE_PATHS:
            url = urljoin(base, path)
            ev = await ctx.http.get(url)
            if ev.status not in (200, 401, 403):
                continue
            body = (ev.response_body or "")[:400]
            if ev.status == 200 and len(ev.response_body or "") > 50:
                # an app that 200s its login view for /admin, /console, … is not
                # an exposure — only report when it isn't an auth wall.
                wall, why = is_auth_wall(ev.status, ev.response_headers, ev.response_body, url)
                if wall:
                    ctx.dashboard.event("info", f"logic: {url} is an auth wall ({why}), not an exposure")
                    continue
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
        from core.poc import is_auth_wall, is_static_asset
        from core.escalation import sensitive_hits
        from scanners.idor_deep import identity_markers
        for url in endpoints:
            if not any(h in url.lower() for h in ADMIN_HINTS):
                continue
            anon_cookies = {k: "" for k in (ctx.session.cookies if ctx.session else {})}
            ev = await ctx.http.get(url, headers={"Authorization": ""}, cookies=anon_cookies)
            if ev.status != 200 or len(ev.response_body or "") <= 200:
                continue
            # The classic false positive: an app that 200s its *login page*
            # (Laravel/SPA) or serves a static asset on an admin-shaped path.
            # Require genuine privileged content, not a 200-shaped auth wall.
            wall, why = is_auth_wall(ev.status, ev.response_headers, ev.response_body, url)
            if wall or is_static_asset(url, ev.response_headers):
                ctx.dashboard.event("info",
                    f"logic: {url} not privileged content ({why or 'static asset'}) — skipped")
                continue
            body = ev.response_body or ""
            markers = sorted(identity_markers(body))[:6]
            sensitive = [k for k, _ in sensitive_hits(body, ev.response_headers)]
            if not markers and not sensitive:
                ctx.dashboard.event("info",
                    f"logic: {url} reachable anon but no identity/sensitive markers — not reported")
                continue
            self.report_finding(ctx, {
                "category": "broken_auth",
                "title": f"Privileged page reachable without authentication: {url}",
                "severity": "critical", "cvss": 9.0,
                "url": url,
                "evidence": f"Admin-shaped path returned 200 with privileged content and no "
                            f"auth header (identity markers={markers}, sensitive={sensitive}).",
                "request": f"GET {url}",
                "response": body[:1500],
                "metadata": {"detection": "admin_anon", "markers": markers, "sensitive": sensitive},
            })

    async def _pricing_tamper(self, forms: list[dict], ctx: "Context") -> None:
        if not ctx.config.get("safety", {}).get("aggressive"):
            return  # mutating check — requires --aggressive
        from core.logic_sequences import run_price_tamper
        for form in forms:
            form = {**form, "action": form.get("action") or form.get("url")}
            f = await run_price_tamper(ctx, form)
            if f:  # only returns a finding when the charged total actually dropped
                self.report_finding(ctx, f)

    async def _coupon_reuse(self, forms: list[dict], ctx: "Context") -> None:
        if not ctx.config.get("safety", {}).get("aggressive"):
            return
        from core.logic_sequences import run_coupon_reuse
        for form in forms:
            inputs = form.get("inputs", [])
            code_field = next((i["name"] for i in inputs
                               if any(h in (i.get("name") or "").lower()
                                      for h in ("coupon", "promo", "voucher", "discount", "code"))),
                              None)
            if not code_field:
                continue
            data = {i["name"]: i.get("value") or "1" for i in inputs}
            apply = {"url": form.get("action") or form.get("url"),
                     "method": form.get("method", "POST"), "data": data,
                     "code_field": code_field, "code": data.get(code_field) or "SAVE10"}
            f = await run_coupon_reuse(ctx, apply)
            if f:
                self.report_finding(ctx, f)

    async def _step_skip(self, endpoints: list[str], ctx: "Context") -> None:
        if not ctx.config.get("safety", {}).get("aggressive"):
            return
        from core.logic_sequences import run_step_skip
        late_stage = ("confirm", "complete", "finalize", "finalise", "ship",
                      "fulfill", "approve", "activate")
        for url in endpoints:
            name = next((h for h in late_stage if h in url.lower()), None)
            if not name:
                continue
            f = await run_step_skip(ctx, {"url": url, "method": "POST", "name": name})
            if f:
                self.report_finding(ctx, f)

    async def _race_conditions(self, endpoints: list[str], ctx: "Context") -> None:
        if not ctx.config.get("safety", {}).get("aggressive"):
            return  # fires concurrent real POSTs — requires --aggressive
        from core.logic_sequences import run_race
        for url in endpoints:
            if not any(h in url.lower() for h in RACE_HINTS):
                continue
            # observe the endpoint's own state via GET before/after; the oracle
            # only fires when a metered value actually over-moves, not on 2xx counts
            f = await run_race(ctx, {"url": url, "method": "POST", "state_url": url})
            if f:
                self.report_finding(ctx, f)
                return
