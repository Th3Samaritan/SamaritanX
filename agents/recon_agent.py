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
from core.utils import host_of, normalize_url, random_token, root_domain, slugify
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

# Optional key-based enrichments — only collected when the API key is present
# in the environment. Shodan/VirusTotal/SecurityTrails all expose domain →
# subdomains endpoints.
def _keyed_sources() -> list[tuple[str, str, dict]]:
    import os
    out: list[tuple[str, str, dict]] = []
    if os.environ.get("SHODAN_API_KEY"):
        out.append(("shodan",
                    "https://api.shodan.io/dns/domain/{root}?key=" + os.environ["SHODAN_API_KEY"],
                    {}))
    if os.environ.get("VT_API_KEY"):
        out.append(("virustotal",
                    "https://www.virustotal.com/api/v3/domains/{root}/subdomains?limit=200",
                    {"x-apikey": os.environ["VT_API_KEY"]}))
    if os.environ.get("SECURITYTRAILS_API_KEY"):
        out.append(("securitytrails",
                    "https://api.securitytrails.com/v1/domain/{root}/subdomains",
                    {"APIKEY": os.environ["SECURITYTRAILS_API_KEY"]}))
    return out


class ReconAgent(BaseAgent):
    name = "recon"
    handles = ("recon",)

    async def handle(self, task: Task, ctx: "Context") -> None:
        target = task.payload.get("target", ctx.target)
        target_url = target if "://" in target else f"http://{target}"
        target_host = host_of(target_url)
        root = root_domain(target_host)

        # resume: recon already completed in a prior run — re-hydrate the
        # persisted results instead of repeating every network source
        if ctx.resume and ctx.memory.is_completed(ctx.target_slug, "recon"):
            await self._resume_from_disk(target_host, ctx)
            return

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

        # 0b) DNS zone transfer (AXFR) — cheap, occasionally yields the entire
        #     zone when the nameserver is misconfigured
        if ctx.config.get("recon", {}).get("zone_transfer", True):
            zone_names = await self._zone_transfer(root, ctx)
            if zone_names:
                ctx.dashboard.event("ok",
                    f"recon: AXFR enabled on {root} — {len(zone_names)} zone record(s)")

        # wildcard DNS detection: a target with *.root -> one IP would turn
        # the brute-force into thousands of phantom hosts. Resolve random
        # names FIRST and drop brute-force results resolving to wildcard IPs.
        wildcard_ips: set[str] = set()
        if ctx.config.get("recon", {}).get("detect_wildcard", True):
            wildcard_ips = await self._detect_wildcard(root, ctx)
            if wildcard_ips:
                ctx.dashboard.event("info",
                    f"recon: wildcard DNS detected ({len(wildcard_ips)} ip) — filtering phantom hosts")

        # 1) Collect subdomains — run every collector concurrently (not
        #    sequentially) so a slow tool can't stall the others.
        subs: set[str] = {root, target_host}
        passive_only = ctx.config.get("recon", {}).get("passive_only")
        collectors = [
            self._run_subfinder(root, ctx),
            self._passive_http(root, ctx),
            self._dns_bruteforce(root, ctx, wildcard_ips),
        ]
        if not passive_only:
            collectors.append(self._run_amass(root, ctx))
        for result in await asyncio.gather(*collectors, return_exceptions=True):
            if isinstance(result, set):
                subs.update(result)

        # subdomain permutations (alt-dns style) — prefixes/suffixes/number
        # swaps seeded from every discovered name, capped and re-resolved
        if ctx.config.get("recon", {}).get("permutations", True):
            perms = self._permutate(root, subs)
            if perms:
                ctx.dashboard.event("info", f"recon: generated {len(perms)} permutation candidate(s)")
                subs.update(perms)

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
        if wildcard_ips:
            before = len(resolvable)
            resolvable = [h for h in resolvable
                          if await self._resolves_to(h, ctx) not in wildcard_ips]
            if before != len(resolvable):
                ctx.dashboard.event("info",
                    f"recon: dropped {before - len(resolvable)} wildcard-resolving host(s)")
        max_probe = int(ctx.config.get("recon", {}).get("max_probe_hosts", 750))
        to_probe = [h for h in resolvable if h not in emitted][:max_probe]
        ctx.dashboard.task("subdomain probe", len(to_probe))
        ctx.dashboard.event(
            "info",
            f"recon: {len(resolvable)}/{len(subs)} resolve — probing {len(to_probe)}")

        # 3) Probe live endpoints, emitting each one to the crawler as found.
        await self._probe_live(to_probe, ctx, on_live=emit_live)

        # 4) virtual-host discovery — fuzz Host headers against the resolved IP
        #    (names that exist only as vhosts never resolve publicly)
        if ctx.config.get("recon", {}).get("vhost_brute", True):
            await self._vhost_brute(target_host, root, ctx, emit_live)

        # 5) TCP port scan + service banners on a bounded set of live hosts
        #    (read-only probes: banners, HTTP GET, Redis PING, Mongo isMaster)
        if ctx.config.get("recon", {}).get("port_scan", False):
            hosts_to_scan = list(dict.fromkeys(
                [h for h in [target_host] + [e["host"] for e in live[:4]] if h]))[:5]
            for h in hosts_to_scan:
                await self._port_scan(h, ctx)

        (ctx.workspace / "recon" / "live.json").write_text(
            json.dumps(live, indent=2), encoding="utf-8")

        if not emitted:
            ctx.dashboard.event("err", "recon: no live hosts found — pipeline stops here")
            return
        ctx.memory.mark_completed(ctx.target_slug, "recon")
        ctx.dashboard.event("ok", f"recon: {len(emitted)} live hosts emitted to crawler + discovery")

    async def _resume_from_disk(self, target_host: str, ctx: "Context") -> None:
        """--resume path: reload persisted recon output and re-emit crawl /
        discovery tasks without hitting any network source."""
        live_path = ctx.workspace / "recon" / "live.json"
        live: list[dict] = []
        if live_path.exists():
            try:
                live = json.loads(live_path.read_text(encoding="utf-8"))
            except Exception:
                live = []
        if not live:
            # nothing persisted — fall through to a fresh recon
            ctx.dashboard.event("info", "recon: no persisted live hosts — running fresh")
            return await self.handle_resume_fallback(target_host, ctx)
        emitted = 0
        for entry in live:
            if not entry.get("host"):
                continue
            ctx.memory.add_asset(ctx.target_slug, "endpoint", entry.get("url", ""),
                                 metadata=entry)
            await ctx.queue.put(
                "crawl",
                {"url": entry.get("url"), "tech": entry.get("tech", []),
                 "host": entry["host"]},
                target=ctx.target_slug, priority=3, producer=self.name,
            )
            await ctx.queue.put(
                "discover",
                {"host": entry["host"], "base": entry.get("url")},
                target=ctx.target_slug, priority=3, producer=self.name,
            )
            emitted += 1
        ctx.dashboard.event("ok",
            f"recon: resumed from disk — {emitted} live host(s) re-emitted")

    async def handle_resume_fallback(self, target_host: str, ctx: "Context") -> None:
        """Fresh recon when resume found nothing persisted (rare)."""
        seed = await self._probe_host(target_host, ctx)
        if seed:
            await ctx.queue.put(
                "crawl",
                {"url": seed["url"], "tech": seed.get("tech", []), "host": seed["host"]},
                target=ctx.target_slug, priority=3, producer=self.name,
            )
            await ctx.queue.put(
                "discover",
                {"host": seed["host"], "base": seed["url"]},
                target=ctx.target_slug, priority=3, producer=self.name,
            )
            (ctx.workspace / "recon" / "live.json").write_text(
                json.dumps([seed], indent=2), encoding="utf-8")
        ctx.memory.mark_completed(ctx.target_slug, "recon")

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
        sources = list(PASSIVE_HTTP_SOURCES)
        if ctx.config.get("recon", {}).get("keyed_sources", True):
            sources += [(n, u, h) for n, u, h in _keyed_sources()]
        for name, url_tpl, extra_headers in sources:
            url = url_tpl.format(root=root)
            # bypass_scope=True — these are external OSINT APIs, not the target;
            # they must never be blocked by the scope policy.
            ev = await ctx.http.get(url, headers=extra_headers or None, bypass_scope=True)
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
                elif name == "shodan":
                    data = json.loads(ev.response_body)
                    for h in data.get("subdomains") or []:
                        if h:
                            found.add(f"{h}.{root}")
                elif name == "virustotal":
                    data = json.loads(ev.response_body)
                    for item in data.get("data") or []:
                        h = (item.get("id") or "").lower()
                        if h.endswith(root):
                            found.add(h)
                elif name == "securitytrails":
                    data = json.loads(ev.response_body)
                    for h in data.get("subdomains") or []:
                        if h:
                            found.add(f"{h}.{root}")
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

    async def _dns_bruteforce(self, root: str, ctx: "Context",
                              wildcard_ips: set[str] | None = None) -> set:
        wordlist = self._load_wordlist()
        found: set[str] = set()
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(20)  # limit concurrent DNS lookups
        wildcard_ips = wildcard_ips or set()

        async def resolve(name: str) -> None:
            host = f"{name}.{root}"
            async with sem:
                try:
                    ip = await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, host),
                        timeout=5.0,
                    )
                    if ip not in wildcard_ips:
                        found.add(host)
                except Exception:
                    return

        await asyncio.gather(*(resolve(w) for w in wordlist))
        return found

    # ------------------------------------------------------------------ #
    # wildcard DNS + permutations
    # ------------------------------------------------------------------ #
    _PERM_PREFIXES = ("www", "api", "dev", "staging", "test", "app", "admin",
                      "mail", "portal", "vpn", "m", "docs", "assets", "static",
                      "int", "status", "blog", "cdn", "dashboard", "beta")
    _PERM_SUFFIXES = ("-dev", "-staging", "-test", "-api", "-admin", "-old",
                      "-internal", "-backup", "-new")

    async def _detect_wildcard(self, root: str, ctx: "Context") -> set[str]:
        """Resolve random names under the root; if they all resolve to the same
        small IP set, the zone is wildcarded. Returns the wildcard IPs."""
        loop = asyncio.get_running_loop()
        ips: set[str] = set()

        async def probe(i: int) -> None:
            host = f"sxw-{random_token(8)}.{root}"
            try:
                ip = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, host),
                    timeout=5.0,
                )
                ips.add(ip)
            except Exception:
                pass

        await asyncio.gather(*(probe(i) for i in range(3)))
        # 3 distinct answers = NOT a wildcard; 1-2 shared IPs = wildcard
        return ips if 0 < len(ips) <= 2 else set()

    def _permutate(self, root: str, subs: set[str]) -> set[str]:
        """alt-dns style mutations of discovered subdomains (bounded)."""
        cap = 250
        out: set[str] = set()
        base_names: set[str] = set()
        for s in subs:
            s = s.strip().lower().lstrip("*.")
            if not s or s == root:
                continue
            if s.endswith("." + root):
                s = s[: -(len(root) + 1)]
            base_names.add(s.split(".")[0])
        for name in list(base_names)[:40]:
            if len(out) >= cap:
                break
            for p in self._PERM_PREFIXES:
                out.add(f"{p}-{name}.{root}")
                out.add(f"{p}.{name}.{root}")
            for suf in self._PERM_SUFFIXES:
                out.add(f"{name}{suf}.{root}")
            for n in ("01", "02", "1", "2", "3"):
                out.add(f"{name}{n}.{root}")
                out.add(f"{name}-{n}.{root}")
            stripped = name.rstrip("0123456789")
            if stripped and stripped != name:
                for n in ("01", "02", "1", "2"):
                    out.add(f"{stripped}{n}.{root}")
        return {s for s in out if s not in subs}

    async def _resolves_to(self, host: str, ctx: "Context") -> str | None:
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, host),
                timeout=3.0,
            )
        except Exception:
            return None

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
        retries = int(ctx.config.get("recon", {}).get("probe_retries", 1))
        live: list[dict] = []

        async def probe(host: str) -> None:
            async with sem:
                try:
                    for scheme in ("https", "http"):
                        url = f"{scheme}://{host}"
                        ev = None
                        for attempt in range(retries + 1):
                            try:
                                ev = await asyncio.wait_for(ctx.http.get(url),
                                                            timeout=probe_timeout)
                                break
                            except asyncio.TimeoutError:
                                continue  # transient stall — retry once
                        if ev is None or ev.error or ev.status == 0:
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

    async def _vhost_brute(self, target_host: str, root: str, ctx: "Context",
                           on_live) -> None:
        """Virtual-host discovery: names that exist only as HTTP Host-header
        vhosts never resolve publicly, so we connect to the target IP and send
        candidate Host names. A response that differs from a random-Host
        baseline is a distinct vhost — emitted like any other live host.

        Scope note: the connection goes to the resolved IP (bypass_scope so
        the IP itself can't be blocked by a domain allow-list), but every
        candidate Host name is checked against the scope policy FIRST.
        """
        loop = asyncio.get_running_loop()
        from urllib.parse import urlparse as _urlparse
        netloc = _urlparse(target_host if "://" in target_host
                           else f"http://{target_host}").netloc or target_host
        ip = None
        for h in (root, netloc.split(":")[0]):
            try:
                ip = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, h), timeout=5.0)
                break
            except Exception:
                continue
        if not ip:
            return
        # baseline signature from a hostname that can never exist
        base_host = f"sxv-{random_token(10)}.invalid"
        base_url = f"https://{netloc}"
        base_ev = await ctx.http.get(base_url, headers={"Host": base_host},
                                     bypass_scope=True, allow_redirects=False)
        if not base_ev.status:
            base_url = f"http://{netloc}"
            base_ev = await ctx.http.get(base_url, headers={"Host": base_host},
                                         bypass_scope=True, allow_redirects=False)
        if not base_ev.status:
            return
        base_sig = self._vhost_sig(base_ev)
        probe_url = base_url
        scheme = "https" if base_url.startswith("https://") else "http"

        words = self._load_wordlist()[:int(ctx.config.get("recon", {}).get("vhost_words", 60))]
        sem = asyncio.Semaphore(8)
        seen_sigs: set = {base_sig}
        found = 0
        cap = int(ctx.config.get("recon", {}).get("vhost_cap", 25))

        async def probe(word: str) -> None:
            nonlocal found
            # subdomain-shaped candidates only — bare words (intranet search
            # domains) create nonsense hosts like "31337" and pollute the crawl
            for candidate in (f"{word}.{root}",):
                if found >= cap:
                    return
                # the candidate hostname must be in scope before we touch it
                if ctx.scope:
                    ok, _reason = ctx.scope.allows(f"{scheme}://{candidate}")
                    if not ok:
                        continue
                async with sem:
                    ev = await ctx.http.get(probe_url,
                                             headers={"Host": candidate},
                                             bypass_scope=True,
                                             allow_redirects=False)
                if not ev.status:
                    continue
                sig = self._vhost_sig(ev)
                if sig in seen_sigs:
                    continue
                seen_sigs.add(sig)
                found += 1
                title = self._extract_title(ev.response_body)
                entry = {
                    "url": normalize_url(f"{scheme}://{candidate}"),
                    "host": candidate,
                    "status": ev.status,
                    "title": title,
                    "tech": self._fingerprint(ev.response_headers, ev.response_body),
                    "server": ev.response_headers.get("server", ""),
                }
                ctx.dashboard.event("ok", f"recon: vhost discovered — {candidate} "
                                          f"({ev.status}, {len(ev.response_body or '')}B)")
                if on_live is not None:
                    await on_live(entry)

        await asyncio.gather(*(probe(w) for w in words))
        if found:
            ctx.dashboard.event("ok", f"recon: vhost brute-force found {found} distinct virtual host(s)")

    # ------------------------------------------------------------------ #
    # zone transfer + port scan
    # ------------------------------------------------------------------ #
    _PORTS = (
        (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
        (110, "pop3"), (143, "imap"), (389, "ldap"),
        (3306, "mysql"), (5432, "postgresql"), (6379, "redis"),
        (27017, "mongodb"), (9200, "elasticsearch"), (11211, "memcached"),
        (8080, "http-alt"), (8443, "https-alt"), (2375, "docker"),
        (8500, "consul"), (8200, "vault"), (9090, "prometheus"),
        (15672, "rabbitmq-mgmt"), (10000, "webmin"), (5000, "app-dev"),
        (3000, "node-dev"), (8000, "http-dev"),
    )
    _MONGO_ISMASTER = (
        b"\x4f\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
        b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00"
        b"\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"
    )

    async def _zone_transfer(self, root: str, ctx: "Context") -> set[str]:
        """Attempt an AXFR against the root's own nameservers (read-only)."""
        try:
            import dns.resolver
        except Exception:
            return set()
        loop = asyncio.get_running_loop()

        def _attempt():
            try:
                ns = [str(r).rstrip(".") for r in dns.resolver.resolve(root, "NS")]
            except Exception:
                return set()
            import dns.query
            names: set[str] = set()
            for server in ns[:4]:
                try:
                    for msg in dns.query.xfr(server, root, timeout=6, lifetime=12):
                        for rrset in msg.answer:
                            names.add(str(rrset.name).rstrip("."))
                            for rdata in rrset:
                                if getattr(rdata, "rdtype", None) == 5:
                                    names.add(str(rdata.target).rstrip("."))
                    if names:
                        break
                except Exception:
                    continue
            return names

        names = await asyncio.wait_for(loop.run_in_executor(None, _attempt),
                                       timeout=30.0)
        if names:
            from core.poc import proof_record
            excerpt = "\n".join(sorted(names))[:1500]
            poc = proof_record(
                verified=True, method="AXFR", url=f"dns:{root}",
                request=f"dig AXFR {root}",
                excerpt=excerpt,
                rationale=(f"The zone {root} allows unrestricted AXFR — the complete DNS "
                           f"zone ({len(names)} names) was transferred, exposing internal "
                           "hostnames, IPs and network topology."))
            self.report_finding(ctx, {
                "category": "exposure",
                "title": f"DNS zone transfer (AXFR) enabled on {root}",
                "severity": "high", "cvss": 7.5,
                "url": f"dns:{root}",
                "evidence": f"AXFR against the authoritative nameserver returned "
                            f"{len(names)} zone records — full internal DNS enumeration.",
                "request": f"dig AXFR {root}",
                "response": excerpt,
                "metadata": {"poc": poc, "zone": root, "records": len(names)},
            })
        return names

    async def _port_scan(self, host: str, ctx: "Context") -> None:
        """Read-only TCP port sweep + banner grab. Reports unauthenticated
        management services (Redis/Mongo/ES/Docker) as verified exposures."""
        ctx.dashboard.event("info", f"recon: port scan {host} ({len(self._PORTS)} ports)")
        results: list[dict] = []

        async def probe(port: int, label: str) -> None:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=2.0)
            except Exception:
                return
            banner = ""
            try:
                if label in ("http-alt", "https-alt", "http-dev", "node-dev",
                             "app-dev", "rabbitmq-mgmt", "prometheus", "consul",
                             "vault", "webmin", "docker", "elasticsearch"):
                    req = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                    writer.write(req)
                    await writer.drain()
                    try:
                        data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                        banner = data.decode("utf-8", "ignore")
                    except Exception:
                        pass
                elif label == "redis":
                    writer.write(b"PING\r\n")
                    await writer.drain()
                    try:
                        banner = (await asyncio.wait_for(reader.read(128),
                                                         timeout=2.0)).decode("utf-8", "ignore")
                    except Exception:
                        pass
                elif label == "mongodb":
                    writer.write(self._MONGO_ISMASTER)
                    await writer.drain()
                    try:
                        banner = (await asyncio.wait_for(reader.read(512),
                                                         timeout=2.0)).decode("utf-8", "ignore")
                    except Exception:
                        pass
                else:
                    try:
                        banner = (await asyncio.wait_for(reader.read(256),
                                                         timeout=2.0)).decode("utf-8", "ignore")
                    except Exception:
                        pass
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass
            results.append({"port": port, "service": label, "banner": banner[:400]})
            await self._service_finding(host, port, label, banner, ctx)

        await asyncio.gather(*(probe(p, l) for p, l in self._PORTS))
        out = ctx.workspace / "recon" / f"{slugify(host)}_ports.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        open_ports = [r["port"] for r in results]
        if open_ports:
            ctx.dashboard.event("ok",
                f"recon: {host} open ports: {', '.join(map(str, open_ports))}")

    async def _service_finding(self, host: str, port: int, label: str,
                               banner: str, ctx: "Context") -> None:
        """Classify an open port's banner into a finding (proof = the banner)."""
        from core.poc import proof_record
        title, sev, cvss, evidence = None, None, None, None
        if label == "redis" and banner.strip().upper().startswith("+PONG"):
            title = f"Redis exposed without authentication ({host}:{port})"
            sev, cvss = "critical", 9.0
            evidence = ("Redis answered PING without auth — anonymous clients can read/"
                        "write keys, and via CONFIG/SLAVEOF escalate to the host.")
        elif label == "mongodb" and "ismaster" in banner.lower():
            title = f"MongoDB exposed without authentication ({host}:{port})"
            sev, cvss = "critical", 9.0
            evidence = ("The isMaster handshake succeeded anonymously — unauthenticated "
                        "read/write access to every database.")
        elif label == "elasticsearch" and ("cluster_name" in banner or "lucene" in banner):
            title = f"Elasticsearch exposed without authentication ({host}:{port})"
            sev, cvss = "critical", 9.0
            evidence = ("The cluster root answered anonymously — indices and data are "
                        "readable by anyone who can reach the port.")
        elif label == "docker" and ("Docker" in banner or "ApiVersion" in banner):
            title = f"Docker API exposed without authentication ({host}:{port})"
            sev, cvss = "critical", 9.8
            evidence = ("The Docker daemon API answered without TLS/auth — equivalent to "
                        "root on the host (mount /, exec, deploy containers).")
        elif label in ("mysql", "postgresql") and banner and not banner.startswith("HTTP"):
            title = f"Database banner disclosure ({label} on {host}:{port})"
            sev, cvss = "medium", 5.3
            evidence = (f"The {label} greeting exposed its version string — fingerprinting "
                        "aid; confirm authentication posture manually.")
        elif banner and label not in ("http", "https"):
            title = f"Service banner disclosure ({label} on {host}:{port})"
            sev, cvss = "low", 3.7
            evidence = f"Open {label} port advertised: {banner[:120]}"
        if not title:
            return
        poc = proof_record(
            verified=True, method="TCP", url=f"{host}:{port}",
            request=f"connect {host}:{port}\n{('PING' if port == 6379 else 'banner read')}",
            excerpt=banner,
            rationale=evidence)
        self.report_finding(ctx, {
            "category": "exposure",
            "title": title, "severity": sev, "cvss": cvss,
            "url": f"{host}:{port}",
            "evidence": evidence,
            "request": f"connect {host}:{port}",
            "response": banner[:800],
            "metadata": {"port": port, "service": label, "poc": poc},
        })

    @staticmethod
    def _vhost_sig(ev) -> tuple:
        body = ev.response_body or ""
        title = ""
        lo = body.lower()
        i = lo.find("<title")
        if i != -1:
            j = lo.find(">", i)
            k = lo.find("</title", j)
            if j != -1 and k != -1:
                title = body[j + 1:k].strip()[:80]
        return (ev.status, len(body), title, ev.response_headers.get("server", ""))

    async def _probe_host(self, host: str, ctx: "Context") -> dict | None:
        probe_timeout = float(ctx.config.get("recon", {}).get("probe_timeout", 8.0))
        retries = int(ctx.config.get("recon", {}).get("probe_retries", 1))
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            ev = None
            for _attempt in range(retries + 1):
                try:
                    ev = await asyncio.wait_for(ctx.http.get(url), timeout=probe_timeout)
                    break
                except asyncio.TimeoutError:
                    continue  # transient stall — retry once
            if ev is None or ev.error or ev.status == 0:
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
