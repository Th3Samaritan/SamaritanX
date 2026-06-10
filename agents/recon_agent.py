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
import re
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
    ("anubis", "https://jldc.me/anubis/subdomains/{root}"),
    ("rapiddns", "https://rapiddns.io/subdomain/{root}?full=1#result"),
]


class ReconAgent(BaseAgent):
    name = "recon"
    handles = ("recon",)

    async def handle(self, task: Task, ctx: "Context") -> None:
        target = task.payload.get("target", ctx.target)
        target_url = target if "://" in target else f"http://{target}"
        target_host = host_of(target_url)
        root = root_domain(target_host)
        ctx.dashboard.event("info", f"recon: starting on root={root}")

        live: list[dict] = []
        emitted: set[str] = set()

        async def emit_live(entry: dict) -> None:
            """Queue a live host to the crawler + discovery as soon as it's
            found, so the rest of the pipeline starts immediately instead of
            waiting for the whole (slow) probe sweep to finish."""
            if entry["host"] in emitted:
                return
            emitted.add(entry["host"])
            live.append(entry)
            ctx.memory.add_asset(ctx.target_slug, "endpoint", entry["url"], metadata=entry)
            await ctx.queue.put(
                "crawl",
                {"url": entry["url"], "tech": entry.get("tech", []), "host": entry["host"]},
                target=ctx.target_slug, priority=3, producer=self.name,
            )
            await ctx.queue.put(
                "discover",
                {"host": entry["host"], "base": entry["url"]},
                target=ctx.target_slug, priority=3, producer=self.name,
            )
            ctx.dashboard.event("ok", f"recon: live {entry['url']} -> crawler + discovery")

        # 0) Probe the target host FIRST and emit immediately. This guarantees
        #    the pipeline progresses to crawl/scan within seconds even if
        #    subdomain enumeration is slow or finds nothing.
        seed = await self._probe_host(target_host, ctx)
        if seed:
            await emit_live(seed)

        # 1) Collect subdomains — run every collector concurrently (not
        #    sequentially) so a slow tool can't stall the others.
        subs: set[str] = {root, target_host}
        passive_only = ctx.config.get("recon", {}).get("passive_only")
        collectors = [
            self._run_subfinder(root, ctx),
            self._passive_http(root, ctx),
            self._dns_bruteforce(root, ctx),
        ]
        if not passive_only:
            collectors.append(self._run_amass(root, ctx))
        for result in await asyncio.gather(*collectors, return_exceptions=True):
            if isinstance(result, set):
                subs.update(result)

        # persist the full candidate list + record assets
        (ctx.workspace / "recon" / "subdomains.txt").write_text(
            "\n".join(sorted(subs)), encoding="utf-8")
        for host in subs:
            if ctx.memory.add_asset(ctx.target_slug, "subdomain", host):
                ctx.dashboard.add_count("subdomains")

        # subdomain takeover scan against all collected hosts (host-level, cheap)
        await ctx.queue.put(
            "scan.takeover", {"hosts": sorted(subs)},
            target=ctx.target_slug, priority=2, producer=self.name,
        )

        # 2) Resolve DNS *before* probing so the thousands of dead hosts that
        #    crt.sh/certspotter return are dropped cheaply instead of each
        #    costing a full HTTP timeout. Then cap the probe set.
        ctx.dashboard.event("info", f"recon: {len(subs)} candidates — resolving DNS")
        resolvable = await self._resolve_hosts(sorted(subs), ctx)
        max_probe = int(ctx.config.get("recon", {}).get("max_probe_hosts", 750))
        to_probe = [h for h in resolvable if h not in emitted][:max_probe]
        ctx.dashboard.task("subdomain probe", len(to_probe))
        ctx.dashboard.event(
            "info",
            f"recon: {len(resolvable)}/{len(subs)} resolve — probing {len(to_probe)}")

        # 3) Probe live endpoints, emitting each one to the crawler as found.
        await self._probe_live(to_probe, ctx, on_live=emit_live)

        (ctx.workspace / "recon" / "live.json").write_text(
            json.dumps(live, indent=2), encoding="utf-8")

        if not emitted:
            ctx.dashboard.event("err", "recon: no live hosts found — pipeline stops here")
            return
        ctx.dashboard.event("ok", f"recon: {len(emitted)} live hosts emitted to crawler + discovery")

    # ---------- collectors ----------
    async def _run_subfinder(self, root: str, ctx: "Context") -> set[str]:
        if not shutil.which("subfinder") or not ctx.config.get("recon", {}).get("subfinder", True):
            return set()
        timeout = float(ctx.config.get("recon", {}).get("subfinder_timeout", 120))
        ctx.dashboard.event("info", f"recon: invoking subfinder (≤{timeout:.0f}s)")
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-silent", "-d", root,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {l.strip() for l in out.decode("utf-8", "ignore").splitlines() if l.strip()}
        except Exception as exc:
            ctx.dashboard.event("err", f"subfinder failed: {exc}")
            self._kill(proc)
            return set()

    async def _run_amass(self, root: str, ctx: "Context") -> set[str]:
        if not shutil.which("amass") or not ctx.config.get("recon", {}).get("amass", True):
            return set()
        timeout = int(ctx.config.get("recon", {}).get("amass_timeout", 180))
        ctx.dashboard.event("info", f"recon: invoking amass (≤{timeout}s)")
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "amass", "enum", "-passive", "-norecursive", "-d", root,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {l.strip() for l in out.decode("utf-8", "ignore").splitlines() if l.strip()}
        except Exception as exc:
            ctx.dashboard.event("err", f"amass timed out/failed: {exc}")
            self._kill(proc)
            return set()

    async def _passive_http(self, root: str, ctx: "Context") -> set[str]:
        found: set[str] = set()
        for name, url_tpl in PASSIVE_HTTP_SOURCES:
            url = url_tpl.format(root=root)
            # bypass_scope=True — these are external OSINT APIs, not the target;
            # they must never be blocked by the scope policy.
            ev = await ctx.http.get(url, bypass_scope=True)
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
                elif name == "anubis":
                    for h in json.loads(ev.response_body) or []:
                        h = (h or "").strip().lower().lstrip("*.")
                        if h.endswith(root):
                            found.add(h)
                elif name == "rapiddns":
                    for h in re.findall(r"[A-Za-z0-9._-]+\.%s" % re.escape(root),
                                        ev.response_body or ""):
                        h = h.strip().lower().lstrip("*.")
                        if h.endswith(root):
                            found.add(h)
            except Exception as exc:
                log.debug("passive source %s parse error: %s", name, exc)
        return found

    @staticmethod
    def _load_wordlist() -> list:
        """Load the bundled subdomain wordlist; fall back to a small inline set
        so recon stays fully self-contained even if the file is missing."""
        from pathlib import Path
        wl_path = Path(__file__).resolve().parent.parent / "config" / "payloads" / "subdomains.txt"
        if wl_path.exists():
            words = [w.strip() for w in wl_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                     if w.strip() and not w.startswith("#")]
            if words:
                return words
        return ["www", "api", "dev", "staging", "test", "admin", "portal", "vpn",
                "mail", "git", "jenkins", "grafana", "status", "auth", "sso",
                "login", "cdn", "static", "internal", "corp", "support"]

    async def _dns_bruteforce(self, root: str, ctx: "Context") -> set:
        wordlist = self._load_wordlist()
        found: set[str] = set()
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(20)  # limit concurrent DNS lookups

        async def resolve(name: str) -> None:
            host = f"{name}.{root}"
            async with sem:
                try:
                    await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, host),
                        timeout=5.0,
                    )
                    found.add(host)
                except Exception:
                    return

        await asyncio.gather(*(resolve(w) for w in wordlist))
        return found

    async def _resolve_hosts(self, hosts: list[str], ctx: "Context") -> list[str]:
        """Keep only hosts whose DNS resolves. This drops the large tail of
        dead historical hostnames returned by crt.sh / certspotter before the
        expensive HTTP probe, which is the main reason recon used to run for
        hours."""
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(50)
        alive: list[str] = []

        async def resolve(host: str) -> None:
            async with sem:
                try:
                    await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, host),
                        timeout=3.0,
                    )
                    alive.append(host)
                except Exception:
                    return

        await asyncio.gather(*(resolve(h) for h in hosts))
        return alive

    async def _probe_live(self, hosts: list[str], ctx: "Context", on_live=None) -> list[dict]:
        sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("recon_workers", 8)))
        probe_timeout = float(ctx.config.get("recon", {}).get("probe_timeout", 8.0))
        live: list[dict] = []

        async def probe(host: str) -> None:
            async with sem:
                try:
                    for scheme in ("https", "http"):
                        url = f"{scheme}://{host}"
                        try:
                            ev = await asyncio.wait_for(ctx.http.get(url), timeout=probe_timeout)
                        except asyncio.TimeoutError:
                            continue
                        if ev.error or ev.status == 0:
                            continue
                        title = self._extract_title(ev.response_body)
                        tech = self._fingerprint(ev.response_headers, ev.response_body)
                        entry = {
                            "url": normalize_url(url),
                            "host": host,
                            "status": ev.status,
                            "title": title,
                            "tech": tech,
                            "server": ev.response_headers.get("server", ""),
                        }
                        live.append(entry)
                        if on_live is not None:
                            await on_live(entry)
                        return
                finally:
                    ctx.dashboard.advance("subdomain probe")

        await asyncio.gather(*(probe(h) for h in hosts))
        return live

    async def _probe_host(self, host: str, ctx: "Context") -> dict | None:
        probe_timeout = float(ctx.config.get("recon", {}).get("probe_timeout", 8.0))
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                ev = await asyncio.wait_for(ctx.http.get(url), timeout=probe_timeout)
            except asyncio.TimeoutError:
                continue
            if ev.error or ev.status == 0:
                continue
            title = self._extract_title(ev.response_body)
            tech = self._fingerprint(ev.response_headers, ev.response_body)
            return {
                "url": normalize_url(url),
                "host": host,
                "status": ev.status,
                "title": title,
                "tech": tech,
                "server": ev.response_headers.get("server", ""),
            }
        return None

    @staticmethod
    def _kill(proc) -> None:
        """Terminate an orphaned subprocess so a timed-out subfinder/amass
        doesn't keep running in the background after we've moved on."""
        if proc is None:
            return
        try:
            proc.kill()
        except Exception:
            pass

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
