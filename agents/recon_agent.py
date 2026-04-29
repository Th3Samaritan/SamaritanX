"""Recon Agent — passive + active asset discovery.

Pipeline:
    1. seed root domain  ->  collect subdomains (subfinder, amass passive,
       crt.sh / hackertarget passive APIs, DNS brute-force fallback)
    2. resolve every subdomain to A/AAAA records
    3. probe with httpx (or built-in async probe fallback) to discover live
       HTTP(S) endpoints + status, title, and tech fingerprint
    4. enqueue every live endpoint for the Crawler Agent
"""
from __future__ import annotations

import asyncio
import json
import shutil
import socket
from pathlib import Path
from typing import TYPE_CHECKING

from core.logger import get_logger
from core.task_queue import Task
from core.utils import host_of, normalize_url, root_domain
from .base import BaseAgent

if TYPE_CHECKING:
    from core.orchestrator import Context

log = get_logger("recon")

# Passive sources that work without an API key.
PASSIVE_HTTP_SOURCES = [
    ("crtsh", "https://crt.sh/?q=%25.{root}&output=json"),
    ("hackertarget", "https://api.hackertarget.com/hostsearch/?q={root}"),
    ("certspotter", "https://api.certspotter.com/v1/issuances?domain={root}&include_subdomains=true&expand=dns_names"),
]


class ReconAgent(BaseAgent):
    name = "recon"
    handles = ("recon",)

    async def handle(self, task: Task, ctx: "Context") -> None:
        target = task.payload.get("target", ctx.target)
        root = root_domain(host_of(target if "://" in target else f"http://{target}"))
        ctx.dashboard.event("info", f"recon: starting on root={root}")

        subs: set[str] = {root}
        # 1) external CLI tools when present
        subs.update(await self._run_subfinder(root, ctx))
        if not ctx.config.get("recon", {}).get("passive_only"):
            subs.update(await self._run_amass(root, ctx))

        # 2) passive HTTP sources (always run — no API key required)
        subs.update(await self._passive_http(root, ctx))

        # 3) light DNS brute force
        subs.update(await self._dns_bruteforce(root, ctx))

        ctx.dashboard.task("subdomain probe", len(subs))
        ctx.dashboard.event("info", f"recon: {len(subs)} unique hosts collected")

        # 4) probe live endpoints
        live: list[dict] = await self._probe_live(sorted(subs), ctx)

        # persist + emit
        (ctx.workspace / "recon" / "subdomains.txt").write_text(
            "\n".join(sorted(subs)), encoding="utf-8")
        (ctx.workspace / "recon" / "live.json").write_text(
            json.dumps(live, indent=2), encoding="utf-8")

        for host in subs:
            if ctx.memory.add_asset(ctx.target_slug, "subdomain", host):
                ctx.dashboard.add_count("subdomains")

        # subdomain takeover scan against all collected hosts
        await ctx.queue.put(
            "scan.takeover", {"hosts": sorted(subs)},
            target=ctx.target_slug, priority=2, producer=self.name,
        )

        for entry in live:
            ctx.memory.add_asset(ctx.target_slug, "endpoint", entry["url"], metadata=entry)
            await ctx.queue.put(
                "crawl",
                {"url": entry["url"], "tech": entry.get("tech", []), "host": entry["host"]},
                target=ctx.target_slug,
                priority=3,
                producer=self.name,
            )
            await ctx.queue.put(
                "discover",
                {"host": entry["host"], "base": entry["url"]},
                target=ctx.target_slug, priority=3, producer=self.name,
            )
        ctx.dashboard.event("ok", f"recon: emitted {len(live)} hosts to crawler + discovery")

    # ---------- collectors ----------
    async def _run_subfinder(self, root: str, ctx: "Context") -> set[str]:
        if not shutil.which("subfinder") or not ctx.config.get("recon", {}).get("subfinder", True):
            return set()
        ctx.dashboard.event("info", "recon: invoking subfinder")
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-silent", "-d", root,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await proc.communicate()
        return {l.strip() for l in out.decode("utf-8", "ignore").splitlines() if l.strip()}

    async def _run_amass(self, root: str, ctx: "Context") -> set[str]:
        if not shutil.which("amass") or not ctx.config.get("recon", {}).get("amass", True):
            return set()
        timeout = int(ctx.config.get("recon", {}).get("amass_timeout", 600))
        ctx.dashboard.event("info", f"recon: invoking amass (≤{timeout}s)")
        try:
            proc = await asyncio.create_subprocess_exec(
                "amass", "enum", "-passive", "-norecursive", "-d", root,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {l.strip() for l in out.decode("utf-8", "ignore").splitlines() if l.strip()}
        except asyncio.TimeoutError:
            ctx.dashboard.event("err", "amass timed out")
            return set()

    async def _passive_http(self, root: str, ctx: "Context") -> set[str]:
        found: set[str] = set()
        for name, url_tpl in PASSIVE_HTTP_SOURCES:
            url = url_tpl.format(root=root)
            ev = await ctx.http.get(url)
            if ev.error or ev.status >= 400:
                continue
            try:
                if name == "crtsh":
                    data = json.loads(ev.response_body)
                    for row in data:
                        for h in (row.get("name_value") or "").split("\n"):
                            h = h.strip().lower().lstrip("*.")
                            if h.endswith(root):
                                found.add(h)
                elif name == "hackertarget":
                    for line in ev.response_body.splitlines():
                        h = line.split(",", 1)[0].strip().lower()
                        if h.endswith(root):
                            found.add(h)
                elif name == "certspotter":
                    data = json.loads(ev.response_body)
                    for row in data:
                        for h in row.get("dns_names") or []:
                            h = h.lower().lstrip("*.")
                            if h.endswith(root):
                                found.add(h)
            except Exception as exc:
                log.debug("passive source %s parse error: %s", name, exc)
        return found

    async def _dns_bruteforce(self, root: str, ctx: "Context") -> set[str]:
        wordlist = [
            "www", "api", "dev", "staging", "stage", "test", "qa", "uat",
            "admin", "portal", "secure", "vpn", "mail", "email", "smtp",
            "imap", "pop", "ftp", "sftp", "git", "gitlab", "jira",
            "jenkins", "ci", "build", "docker", "k8s", "kube", "monitor",
            "grafana", "kibana", "prometheus", "metrics", "status",
            "store", "shop", "checkout", "payment", "billing", "auth",
            "sso", "login", "oauth", "id", "identity", "graphql", "ws",
            "cdn", "static", "media", "assets", "files", "upload",
            "internal", "intranet", "corp", "partner", "support",
        ]
        found: set[str] = set()
        loop = asyncio.get_event_loop()

        async def resolve(name: str) -> None:
            host = f"{name}.{root}"
            try:
                await loop.run_in_executor(None, socket.gethostbyname, host)
                found.add(host)
            except Exception:
                return

        await asyncio.gather(*(resolve(w) for w in wordlist))
        return found

    async def _probe_live(self, hosts: list[str], ctx: "Context") -> list[dict]:
        sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("recon_workers", 8)))
        live: list[dict] = []

        async def probe(host: str) -> None:
            async with sem:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}"
                    ev = await ctx.http.get(url)
                    ctx.dashboard.advance("subdomain probe")
                    if ev.error or ev.status == 0:
                        continue
                    title = self._extract_title(ev.response_body)
                    tech = self._fingerprint(ev.response_headers, ev.response_body)
                    live.append({
                        "url": normalize_url(url),
                        "host": host,
                        "status": ev.status,
                        "title": title,
                        "tech": tech,
                        "server": ev.response_headers.get("server", ""),
                    })
                    return

        await asyncio.gather(*(probe(h) for h in hosts))
        return live

    @staticmethod
    def _extract_title(body: str) -> str:
        if not body:
            return ""
        lo = body.lower()
        i = lo.find("<title")
        if i == -1:
            return ""
        j = lo.find(">", i)
        k = lo.find("</title", j)
        if j == -1 or k == -1:
            return ""
        return body[j + 1 : k].strip()[:120]

    @staticmethod
    def _fingerprint(headers: dict, body: str) -> list[str]:
        tech: list[str] = []
        h = {k.lower(): v for k, v in headers.items()}
        body_low = (body or "").lower()
        signals = [
            ("WordPress", "wp-content" in body_low or "x-pingback" in h),
            ("Drupal", "drupal" in body_low or "x-drupal-cache" in h),
            ("Joomla", "joomla" in body_low),
            ("React", "_next/static" in body_low or "react" in body_low),
            ("Next.js", "_next/static" in body_low),
            ("Angular", "ng-version=" in body_low),
            ("Vue", "vue.runtime" in body_low),
            ("Laravel", "laravel_session" in (h.get("set-cookie") or "")),
            ("Django", "csrftoken" in (h.get("set-cookie") or "")),
            ("Express", h.get("x-powered-by", "").lower().startswith("express")),
            ("ASP.NET", "x-aspnet-version" in h or "asp.net" in h.get("x-powered-by", "").lower()),
            ("PHP", "x-powered-by" in h and "php" in h["x-powered-by"].lower()),
            ("Cloudflare", "cf-ray" in h or h.get("server", "").lower() == "cloudflare"),
            ("AWS CloudFront", "x-amz-cf-id" in h),
            ("Akamai", any("akamai" in v.lower() for v in h.values() if isinstance(v, str))),
            ("nginx", h.get("server", "").lower().startswith("nginx")),
            ("Apache", h.get("server", "").lower().startswith("apache")),
            ("GraphQL", "graphql" in body_low),
        ]
        for label, present in signals:
            if present:
                tech.append(label)
        return tech
