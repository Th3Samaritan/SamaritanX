"""Discovery Agent.

Runs in parallel with the crawler to widen the attack surface:

    * content discovery — ffuf if available, otherwise a built-in async
      wordlist scan against the wordlist at config/payloads/wordlist_paths.txt
    * historical URLs — Wayback Machine + URLScan + AlienVault OTX, all
      passive (no API key required)
    * cloud buckets — try common S3 / GCS / Azure naming conventions
      derived from the target's root domain
    * GitHub code search — public dork against github.com to surface
      leaked secrets / configs (no API key, low-volume scrape via the
      search HTML endpoint)
    * JS endpoint extraction — pull every script and run a LinkFinder-
      style regex sweep for hidden API paths
    * OpenAPI / Swagger ingestion — when found, parse the spec and
      enqueue scan tasks for every operation
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from core.task_queue import Task
from core.utils import host_of, normalize_url, root_domain
from .base import BaseAgent

if TYPE_CHECKING:
    from core.orchestrator import Context


# LinkFinder-style regex: pulls relative + absolute paths out of JS bundles.
LINKFINDER_RE = re.compile(
    r"""(?:"|')                              # opening quote
        (
          ((?:[a-zA-Z]{1,10}://|//)          # absolute scheme
            [^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})
          |
          ((?:/|\.\./|\./)                   # relative path
            [^"'><,;| *()(%%$^/\\\[\]]
            [^"'><,;|()]{1,})
          |
          ([a-zA-Z0-9_\-/]{1,}\.[a-zA-Z]{1,4}(?:\?[^"|']{0,}|))
        )
        (?:"|')""", re.VERBOSE,
)

S3_TEMPLATES = [
    "{name}", "{name}-prod", "{name}-staging", "{name}-dev",
    "{name}-backup", "{name}-uploads", "{name}-assets", "{name}-private",
    "{name}-files", "{name}-public", "{name}-media", "{name}-data",
    "{name}.assets", "{name}.media", "assets.{name}", "static.{name}",
]


class DiscoveryAgent(BaseAgent):
    name = "discovery"
    handles = ("discover",)

    async def handle(self, task: Task, ctx: "Context") -> None:
        host = task.payload["host"]
        base = task.payload.get("base") or f"https://{host}"
        ctx.dashboard.event("info", f"discovery: {host}")

        await asyncio.gather(
            self._content_discovery(base, host, ctx),
            self._historical_urls(host, ctx),
            self._cloud_buckets(ctx),
            self._github_dorks(ctx),
            self._js_endpoints(base, ctx),
            self._openapi(base, host, ctx),
        )

    # ---------- content discovery ----------
    async def _content_discovery(self, base: str, host: str, ctx: "Context") -> None:
        if shutil.which("ffuf"):
            try:
                await self._run_ffuf(base, host, ctx)
                return
            except Exception:
                ctx.dashboard.event("err", f"discovery: ffuf failed on {host}, falling back to async wordlist")
        wordlist = Path(__file__).resolve().parent.parent / "config" / "payloads" / "wordlist_paths.txt"
        if not wordlist.exists():
            ctx.dashboard.event("err", f"discovery: wordlist not found at {wordlist} — skipping path discovery")
            return
        words = [w.strip() for w in wordlist.read_text(encoding="utf-8").splitlines()
                 if w.strip() and not w.startswith("#")]
        ctx.dashboard.task(f"discovery:{host}", len(words))
        sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))
        hits: list[dict] = []

        async def probe(word: str) -> None:
            url = urljoin(base + "/", word)
            async with sem:
                ev = await ctx.http.get(url, allow_redirects=False)
            ctx.dashboard.advance(f"discovery:{host}")
            if ev.status in (200, 201, 204, 301, 302, 401, 403):
                hits.append({"url": url, "status": ev.status,
                             "size": len(ev.response_body or ""),
                             "ctype": ev.response_headers.get("content-type", "")})
                if ev.status == 200 and len(ev.response_body or "") > 50:
                    await ctx.queue.put("crawl", {"url": url, "host": host},
                                        target=ctx.target_slug, priority=4,
                                        producer=self.name)

        await asyncio.gather(*(probe(w) for w in words))
        out = ctx.workspace / "discovery" / f"{host}_paths.json"
        out.write_text(json.dumps(hits, indent=2), encoding="utf-8")
        ctx.dashboard.event("ok", f"discovery: {host} -> {len(hits)} paths found")

    async def _run_ffuf(self, base: str, host: str, ctx: "Context") -> None:
        wordlist = Path(__file__).resolve().parent.parent / "config" / "payloads" / "wordlist_paths.txt"
        out_path = ctx.workspace / "discovery" / f"{host}_ffuf.json"
        try:
            proc = await asyncio.create_subprocess_exec(
                "ffuf", "-u", f"{base}/FUZZ", "-w", str(wordlist),
                "-mc", "200,201,204,301,302,401,403", "-fs", "0",
                "-of", "json", "-o", str(out_path), "-t", "20", "-s",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=600.0)
        except asyncio.TimeoutError:
            ctx.dashboard.event("err", f"ffuf timed out on {host}")
            try:
                proc.kill()
            except Exception:
                pass
            return
        if not out_path.exists():
            return
        try:
            data = json.loads(out_path.read_text(encoding="utf-8"))
        except Exception:
            return
        hits = data.get("results") or []
        ctx.dashboard.event("ok", f"ffuf: {host} -> {len(hits)} hits")
        for h in hits:
            url = h.get("url")
            if h.get("status") == 200 and h.get("length", 0) > 50:
                await ctx.queue.put("crawl", {"url": url, "host": host},
                                    target=ctx.target_slug, priority=4,
                                    producer=self.name)

    # ---------- historical URLs ----------
    async def _historical_urls(self, host: str, ctx: "Context") -> None:
        sources = [
            f"https://web.archive.org/cdx/search/cdx?url=*.{host}/*&output=json&fl=original&collapse=urlkey&limit=2000",
            f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=100",
            f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/url_list?limit=500",
        ]
        seen: set[str] = set()
        for src in sources:
            ev = await ctx.http.get(src, bypass_scope=True)
            if ev.error or ev.status >= 400:
                continue
            try:
                data = json.loads(ev.response_body)
            except Exception:
                continue
            urls: list[str] = []
            if "web.archive.org" in src:
                urls = [row[0] for row in data[1:]] if isinstance(data, list) else []
            elif "urlscan.io" in src:
                urls = [r.get("page", {}).get("url") for r in data.get("results", [])]
            elif "otx.alienvault.com" in src:
                urls = [u.get("url") for u in data.get("url_list", [])]
            for u in urls:
                if not u:
                    continue
                u = normalize_url(u)
                if u in seen:
                    continue
                seen.add(u)
        if seen:
            (ctx.workspace / "discovery" / f"{host}_historical.txt").write_text(
                "\n".join(sorted(seen)), encoding="utf-8")
            ctx.dashboard.event("ok", f"historical: {host} -> {len(seen)} URLs")
            # enqueue a sample for the crawler
            for u in list(seen)[:200]:
                if host_of(u).endswith(host.split(":", 1)[0]):
                    await ctx.queue.put("crawl", {"url": u, "host": host},
                                        target=ctx.target_slug, priority=5,
                                        producer=self.name)

    # ---------- cloud buckets ----------
    async def _cloud_buckets(self, ctx: "Context") -> None:
        root = root_domain(ctx.target)
        name = root.split(".")[0]
        if not name:
            return
        candidates: list[tuple[str, str]] = []
        for tpl in S3_TEMPLATES:
            n = tpl.format(name=name)
            candidates.extend([
                ("s3", f"https://{n}.s3.amazonaws.com/"),
                ("gcs", f"https://storage.googleapis.com/{n}/"),
                ("azure", f"https://{n.replace('.', '')}.blob.core.windows.net/"),
            ])
        sem = asyncio.Semaphore(8)
        hits: list[dict] = []

        async def probe(provider: str, url: str) -> None:
            async with sem:
                ev = await ctx.http.get(url, bypass_scope=True)
            if ev.status in (200, 403):
                # 200 with ListBucketResult body -> open bucket
                body = (ev.response_body or "")[:600]
                if "<ListBucketResult" in body or "AccessDenied" in body or "<EnumerationResults" in body:
                    severity, cvss = ("critical", 9.1) if "<ListBucketResult" in body else ("info", 0)
                    hits.append({"provider": provider, "url": url, "status": ev.status,
                                 "open": "<ListBucketResult" in body})
                    if severity == "critical":
                        self.report_finding(ctx, {
                            "category": "exposure",
                            "title": f"Open {provider.upper()} bucket: {url}",
                            "severity": severity, "cvss": cvss,
                            "url": url,
                            "evidence": "Bucket lists contents anonymously.",
                            "request": f"GET {url}",
                            "response": body,
                        })

        await asyncio.gather(*(probe(p, u) for p, u in candidates))
        if hits:
            (ctx.workspace / "discovery" / "cloud_buckets.json").write_text(
                json.dumps(hits, indent=2), encoding="utf-8")

    # ---------- GitHub dorking ----------
    async def _github_dorks(self, ctx: "Context") -> None:
        root = root_domain(ctx.target)
        if not root:
            return
        dorks = [
            f'"{root}" password',
            f'"{root}" api_key',
            f'"{root}" "BEGIN RSA PRIVATE KEY"',
            f'"{root}" AKIA',
            f'"{root}" "client_secret"',
            f'"{root}" filename:.env',
            f'"{root}" filename:.npmrc',
        ]
        results: list[dict] = []
        for q in dorks:
            url = "https://github.com/search?type=code&q=" + q.replace(" ", "+").replace('"', "%22")
            ev = await ctx.http.get(url, bypass_scope=True)
            # GitHub requires auth for code search now — anonymously this gives a soft-block page,
            # but issue / commit search still surface via the unified search:
            url2 = "https://github.com/search?type=issues&q=" + q.replace(" ", "+").replace('"', "%22")
            ev2 = await ctx.http.get(url2, bypass_scope=True)
            for ev_ in (ev, ev2):
                if ev_.status == 200 and ("results" in ev_.response_body.lower()
                                          or "<a class=\"Link\"" in ev_.response_body):
                    results.append({"query": q, "url": ev_.url, "status": ev_.status})
        if results:
            (ctx.workspace / "discovery" / "github_dorks.json").write_text(
                json.dumps(results, indent=2), encoding="utf-8")
            ctx.dashboard.event("info", f"github: {len(results)} candidate dork hits — review manually")

    # ---------- JS endpoint extraction ----------
    async def _js_endpoints(self, base: str, ctx: "Context") -> None:
        ev = await ctx.http.get(base)
        if ev.status >= 400 or not ev.response_body:
            return
        # collect <script src=...>
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', ev.response_body)
        scripts = [urljoin(base, s) for s in scripts][:60]
        endpoints: set[str] = set()
        sem = asyncio.Semaphore(8)

        async def fetch(s: str) -> None:
            async with sem:
                e = await ctx.http.get(s)
            if e.status >= 400:
                return
            for m in LINKFINDER_RE.finditer(e.response_body or ""):
                hit = m.group(1)
                if not hit or len(hit) > 300:
                    continue
                if hit.startswith(("//", "http")):
                    endpoints.add(hit)
                elif hit.startswith(("/", "./", "../")):
                    endpoints.add(urljoin(base, hit))

        await asyncio.gather(*(fetch(s) for s in scripts))
        if not endpoints:
            return
        (ctx.workspace / "discovery" / "js_endpoints.txt").write_text(
            "\n".join(sorted(endpoints)), encoding="utf-8")
        ctx.dashboard.event("ok", f"js: {len(endpoints)} endpoints extracted from JS bundles")
        for u in list(endpoints)[:300]:
            await ctx.queue.put("crawl", {"url": u, "host": host_of(u)},
                                target=ctx.target_slug, priority=5, producer=self.name)

    # ---------- OpenAPI / Swagger ingestion ----------
    async def _openapi(self, base: str, host: str, ctx: "Context") -> None:
        candidates = [
            "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
            "/v3/api-docs", "/v2/api-docs", "/api-docs",
            "/docs/openapi.json", "/docs/swagger.json",
        ]
        spec_url, spec = None, None
        for c in candidates:
            url = urljoin(base, c)
            ev = await ctx.http.get(url)
            if ev.status != 200 or not ev.response_body:
                continue
            try:
                data = json.loads(ev.response_body)
                if isinstance(data, dict) and ("openapi" in data or "swagger" in data or "paths" in data):
                    spec_url, spec = url, data
                    break
            except Exception:
                continue
        if not spec:
            return
        (ctx.workspace / "discovery" / f"{host}_openapi.json").write_text(
            json.dumps(spec, indent=2), encoding="utf-8")
        self.report_finding(ctx, {
            "category": "exposure",
            "title": f"OpenAPI / Swagger spec exposed: {spec_url}",
            "severity": "low", "cvss": 4.3,
            "url": spec_url,
            "evidence": "Full API contract published anonymously — accelerates attack-surface discovery.",
        })
        # enqueue every operation as a scan task
        servers = [s.get("url") for s in (spec.get("servers") or [])] or [base]
        ops = 0
        for path, methods in (spec.get("paths") or {}).items():
            for method, op in (methods or {}).items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue
                params = [p.get("name") for p in (op.get("parameters") or []) if p.get("name")]
                # body parameters
                rb = (op.get("requestBody") or {}).get("content") or {}
                for ctype, body in rb.items():
                    schema = body.get("schema") or {}
                    for k in (schema.get("properties") or {}):
                        params.append(k)
                full = urljoin(servers[0].rstrip("/") + "/", path.lstrip("/"))
                await ctx.queue.put(
                    "scan",
                    {"url": full, "method": method.upper(), "params": params,
                     "openapi": True},
                    target=ctx.target_slug, priority=2, producer=self.name,
                )
                ops += 1
        ctx.dashboard.event("ok", f"openapi: enqueued {ops} operations from {spec_url}")
