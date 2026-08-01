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
import re
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

# Content signatures that prove a 200 is the actual sensitive artifact, not an
# SPA/catch-all index that 200s for every path (the #1 exposure false positive).
_ARTIFACT_SIGNS = {
    "/.env": re.compile(r"(?mi)^\s*[A-Z][A-Z0-9_]{2,}\s*="),          # KEY=VALUE lines
    "/.git/config": re.compile(r"\[core\]|repositoryformatversion", re.I),
    "/.git/HEAD": re.compile(r"(?mi)^ref:\s*refs/"),
    "/.aws/credentials": re.compile(r"aws_access_key_id|aws_secret_access_key", re.I),
    "/server-status": re.compile(r"Apache Server Status|Server uptime", re.I),
    "/actuator": re.compile(r'"_links"|"status"\s*:', re.I),
    "/actuator/env": re.compile(r'"propertySources"|"activeProfiles"', re.I),
    "/console": re.compile(r"H2 Console|jdbc:", re.I),
    "/h2-console": re.compile(r"H2 Console|jdbc:", re.I),
    "/swagger.json": re.compile(r'"swagger"|"openapi"', re.I),
    "/openapi.json": re.compile(r'"openapi"|"swagger"', re.I),
    "/api-docs": re.compile(r'"swagger"|"openapi"|"paths"', re.I),
    "/phpinfo.php": re.compile(r"phpinfo\(\)|PHP Version", re.I),
    "/info.php": re.compile(r"phpinfo\(\)|PHP Version", re.I),
    "/.well-known/security.txt": re.compile(r"(?mi)^\s*Contact\s*:"),
}
# Paths whose artifact is a binary blob / archive / dump — proven by a non-HTML
# body rather than a text signature.
_BINARY_ARTIFACT_SUFFIXES = (".zip", ".tar.gz", ".sql", "heapdump")


def _sensitive_artifact(path: str, ev) -> tuple[bool | None, str]:
    """Decide whether a 200 response really is the sensitive artifact at ``path``.

    Returns (verdict, reason): True = confirmed artifact, False = a 200 that is
    NOT the artifact (SPA/catch-all index — the dominant false positive), None =
    no signature known for this path (caller falls back to leaked-secret checks).
    """
    body = ev.response_body or ""
    try:
        ct = (ev.response_headers.get("content-type")
              or ev.response_headers.get("Content-Type") or "").lower()
    except Exception:
        ct = ""
    if path.endswith(_BINARY_ARTIFACT_SUFFIXES):
        if body and "text/html" not in ct:
            return True, f"non-HTML body ({ct or 'unknown content-type'}) served for {path}"
        return False, "served an HTML page, not the binary/archive artifact"
    sig = _ARTIFACT_SIGNS.get(path)
    if sig is not None:
        if sig.search(body):
            return True, f"response body matches the {path} artifact signature"
        return False, f"200 body does not match the {path} signature (likely a catch-all page)"
    return None, "no artifact signature for this path"


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
        from core.poc import is_auth_wall, proof_record
        from core.escalation import sensitive_hits
        for path in SENSITIVE_PATHS:
            url = urljoin(base, path)
            ev = await ctx.http.get(url)
            if ev.status in (401, 403):
                ctx.dashboard.event("info", f"logic: protected path discovered {url} ({ev.status})")
                continue
            if ev.status != 200 or len(ev.response_body or "") <= 50:
                continue
            # an app that 200s its login view for /admin, /console, … is not an
            # exposure — only proceed when it isn't an auth wall.
            wall, why = is_auth_wall(ev.status, ev.response_headers, ev.response_body, url)
            if wall:
                ctx.dashboard.event("info", f"logic: {url} is an auth wall ({why}), not an exposure")
                continue
            # A 200 is meaningless on its own: SPA/catch-all apps 200 their index
            # for ANY path, /.env included. Require the body to actually be the
            # sensitive artifact (content signature) or to leak secrets.
            is_art, reason = _sensitive_artifact(path, ev)
            sensitive = [k for k, _ in sensitive_hits(ev.response_body or "", ev.response_headers)]
            if is_art is False:
                ctx.dashboard.event("info", f"logic: {url} {reason} — skipped")
                continue
            if is_art is None and not sensitive:
                ctx.dashboard.event("info",
                    f"logic: {url} 200 but no artifact signature and no leaked secrets — skipped")
                continue
            # Reproducible confirmation: re-fetch and require the same outcome
            # (still 200, still not an auth wall, still the artifact / same secrets).
            ev2 = await ctx.http.get(url)
            wall2, _ = (is_auth_wall(ev2.status, ev2.response_headers, ev2.response_body, url)
                        if ev2 else (True, ""))
            if not ev2 or ev2.status != 200 or wall2:
                ctx.dashboard.event("info", f"logic: {url} did not reproduce as an exposure — not reported")
                continue
            is_art2, _ = _sensitive_artifact(path, ev2)
            sensitive2 = [k for k, _ in sensitive_hits(ev2.response_body or "", ev2.response_headers)]
            stable_secrets = sorted(set(sensitive) & set(sensitive2))
            if is_art2 is False or (is_art is None and not stable_secrets):
                ctx.dashboard.event("info", f"logic: {url} exposure not stable across re-fetch — not reported")
                continue
            body2 = ev2.response_body or ""
            detail = reason if is_art else f"secrets leaked: {stable_secrets}"
            poc = proof_record(
                verified=True, method="GET", url=url,
                request=f"GET {url}\n(sent twice, with no credentials)",
                status=ev2.status, excerpt=body2,
                rationale=(f"Two independent unauthenticated GETs returned HTTP 200 and the body is "
                           f"the sensitive artifact, not an app/login page ({detail})."))
            self.report_finding(ctx, {
                "category": "exposure",
                "title": f"Sensitive path publicly accessible: {path}",
                "severity": "high", "cvss": 7.5, "confidence": 0.8,
                "url": url,
                "evidence": (f"HTTP 200 with {len(body2)} bytes, reproduced across two requests; "
                             f"content confirmed as the artifact ({detail})."),
                "request": f"GET {url}",
                "response": body2[:400],
                "metadata": {"detection": "sensitive_path", "artifact": bool(is_art),
                             "sensitive": stable_secrets, "poc": poc, "revalidated": True},
            })

    async def _admin_anon(self, endpoints: list[str], ctx: "Context") -> None:
        from core.poc import is_auth_wall, is_static_asset, proof_record
        from core.escalation import sensitive_hits
        from scanners.idor_deep import identity_markers

        async def _anon_get(u: str):
            # zero credentials: no loaded session, no Cookie, no Authorization
            return await ctx.http.get(u, no_session=True,
                                      headers={"Authorization": "", "Cookie": ""})

        def _privileged(ev) -> tuple[bool, list, list, str]:
            """(is_privileged_content, identity_markers, sensitive_keys, reason)."""
            if not ev or ev.status != 200 or len(ev.response_body or "") <= 200:
                return False, [], [], f"status {getattr(ev, 'status', '?')} / too short"
            wall, why = is_auth_wall(ev.status, ev.response_headers, ev.response_body, u_url)
            if wall:
                return False, [], [], why or "auth wall"
            if is_static_asset(u_url, ev.response_headers):
                return False, [], [], "static asset"
            body = ev.response_body or ""
            mk = sorted(identity_markers(body))[:6]
            sv = [k for k, _ in sensitive_hits(body, ev.response_headers)]
            if not mk and not sv:
                return False, [], [], "no identity/sensitive markers"
            return True, mk, sv, ""

        seen: set[str] = set()
        for url in endpoints:
            if not any(h in url.lower() for h in ADMIN_HINTS) or url in seen:
                continue
            seen.add(url)
            u_url = url

            ev = await _anon_get(url)
            ok, markers, sensitive, why = _privileged(ev)
            if not ok:
                ctx.dashboard.event("info", f"logic: {url} not privileged anon ({why}) — skipped")
                continue

            # Reproducible confirmation: one 200 is a *candidate*, not a finding.
            # The privileged content must hold up on a fresh, independent
            # anonymous re-fetch (and still not be an auth wall) before we report
            # it. This is what a triager will do, done up front — so nothing is
            # emitted without a re-tested, captured proof.
            ev2 = await _anon_get(url)
            ok2, markers2, sensitive2, why2 = _privileged(ev2)
            if not ok2:
                ctx.dashboard.event("info",
                    f"logic: {url} did not reproduce anonymously ({why2}) — not reported")
                continue
            stable_markers = sorted(set(markers) & set(markers2))
            stable_sensitive = sorted(set(sensitive) & set(sensitive2))
            if not stable_markers and not stable_sensitive:
                ctx.dashboard.event("info",
                    f"logic: {url} privileged markers not stable across re-fetch — not reported")
                continue

            body2 = ev2.response_body or ""
            poc = proof_record(
                verified=True, method="GET", url=url,
                request=f"GET {url}\n(sent twice, each with no Cookie and no Authorization header)",
                status=ev2.status, excerpt=body2,
                rationale=(f"Two independent requests carrying zero credentials each returned "
                           f"HTTP 200 with the same privileged content (identity markers="
                           f"{stable_markers}, sensitive={stable_sensitive}); neither response was "
                           "a login, redirect, or deny page — the endpoint enforces no "
                           "authentication."))
            self.report_finding(ctx, {
                "category": "broken_auth",
                "title": f"Privileged page reachable without authentication: {url}",
                "severity": "critical", "cvss": 9.0, "confidence": 0.85,
                "url": url,
                "evidence": (f"Admin-shaped path returned 200 with privileged content and no auth "
                             f"header, reproduced across two fresh anonymous requests "
                             f"(markers={stable_markers}, sensitive={stable_sensitive})."),
                "request": f"GET {url}",
                "response": body2[:1500],
                "metadata": {"detection": "admin_anon", "markers": stable_markers,
                             "sensitive": stable_sensitive, "poc": poc, "revalidated": True},
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
