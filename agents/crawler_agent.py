"""Crawler Agent — deep crawl with optional headless JS rendering.

For each live endpoint received from the Recon Agent it:
    * walks links / forms up to max_depth
    * optionally drives a Playwright browser to harvest XHR endpoints,
      JS-injected anchors, and parameters that don't appear in raw HTML
    * extracts URL parameters, form parameters, and JSON keys -> "params"
    * scans response bodies for inline secrets (regex from secrets_regex.txt)
    * detects API surfaces (REST + GraphQL introspection probe)
    * emits one `scan` task per (url, params) tuple to the Vulnerability Agent
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse, parse_qsl

from bs4 import BeautifulSoup

from core.logger import get_logger
from core.task_queue import Task
from core.utils import normalize_url, host_of, root_domain
from .base import BaseAgent

if TYPE_CHECKING:
    from core.orchestrator import Context

log = get_logger("crawler")


@dataclass
class CrawlState:
    queued: set[str] = field(default_factory=set)
    visited: set[str] = field(default_factory=set)
    endpoints: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    params: set[tuple[str, str]] = field(default_factory=set)  # (url, param)
    secrets: list[dict] = field(default_factory=list)


class CrawlerAgent(BaseAgent):
    name = "crawler"
    handles = ("crawl",)

    def __init__(self) -> None:
        super().__init__()
        self._secret_rules: list[tuple[str, re.Pattern]] = []

    async def handle(self, task: Task, ctx: "Context") -> None:
        if not self._secret_rules:
            self._load_secret_rules(ctx)

        seed_url = normalize_url(task.payload["url"])
        host = host_of(seed_url)
        max_depth = int(ctx.config.get("crawler", {}).get("max_depth", 3))
        max_urls = int(ctx.config.get("crawler", {}).get("max_urls_per_host", 1000))
        follow_subs = bool(ctx.config.get("crawler", {}).get("follow_subdomains", True))
        parse_js = bool(ctx.config.get("crawler", {}).get("parse_javascript", True))

        state = CrawlState()
        state.queued.add(seed_url)

        ctx.dashboard.task(f"crawl:{host}", max_urls)

        # static HTML BFS
        depth = 0
        frontier = [seed_url]
        while frontier and len(state.visited) < max_urls and depth <= max_depth:
            next_frontier: list[str] = []
            for url in frontier:
                if url in state.visited or len(state.visited) >= max_urls:
                    continue
                # resumability: skip URLs already processed in a prior run
                if ctx.memory.is_url_processed(ctx.target_slug, url, "crawl"):
                    state.visited.add(url)
                    ctx.dashboard.advance(f"crawl:{host}")
                    continue
                state.visited.add(url)
                ctx.memory.mark_url_processed(ctx.target_slug, url, "crawl")
                ctx.dashboard.advance(f"crawl:{host}")
                ev = await ctx.http.get(url)
                if ev.error or ev.status == 0:
                    continue
                state.endpoints.append({"url": url, "status": ev.status,
                                        "ctype": ev.response_headers.get("content-type", "")})
                ctx.dashboard.add_count("endpoints")
                self._scan_secrets(url, ev.response_body, state, ctx)

                if "html" in ev.response_headers.get("content-type", "").lower():
                    new_links, forms = self._parse_html(url, ev.response_body)
                    for link in new_links:
                        if link in state.queued:
                            continue
                        if not follow_subs and host_of(link) != host:
                            continue
                        # keep links inside the same registered domain (e.g.
                        # both example.com and api.example.com pass; evil.com
                        # does not).
                        link_root = root_domain(host_of(link))
                        seed_root = root_domain(host)
                        if link_root != seed_root:
                            continue
                        state.queued.add(link)
                        next_frontier.append(link)
                    state.forms.extend(forms)

                # extract URL parameters from the URL itself
                self._extract_url_params(url, state, ctx)

            frontier = next_frontier
            depth += 1

        # optional headless JS render
        if parse_js:
            await self._render_with_browser(seed_url, state, ctx)

        # GraphQL introspection probe
        await self._probe_graphql(seed_url, ctx)

        # persist findings
        out_dir = ctx.workspace / "crawl"
        (out_dir / f"{host}_endpoints.json").write_text(
            json.dumps(state.endpoints, indent=2), encoding="utf-8")
        (out_dir / f"{host}_forms.json").write_text(
            json.dumps(state.forms, indent=2), encoding="utf-8")
        (out_dir / f"{host}_params.txt").write_text(
            "\n".join(sorted(f"{u} :: {p}" for u, p in state.params)), encoding="utf-8")
        if state.secrets:
            (out_dir / f"{host}_secrets.json").write_text(
                json.dumps(state.secrets, indent=2), encoding="utf-8")

        # emit scanning tasks
        await self._emit_scan_tasks(state, ctx)

        ctx.dashboard.event("ok",
            f"crawler[{host}]: {len(state.endpoints)} endpoints, "
            f"{len(state.forms)} forms, {len(state.params)} params")

    # ---------- helpers ----------
    def _load_secret_rules(self, ctx: "Context") -> None:
        path = Path(ctx.payloads.payload_dir) / "secrets_regex.txt"
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or "|" not in line:
                continue
            name, pattern = line.split("|", 1)
            try:
                self._secret_rules.append((name.strip(), re.compile(pattern.strip())))
            except re.error:
                continue

    def _parse_html(self, base: str, body: str) -> tuple[list[str], list[dict]]:
        soup = BeautifulSoup(body or "", "lxml")
        links: list[str] = []
        for tag in soup.find_all(["a", "link", "script", "iframe"], href=True):
            href = tag.get("href")
            if href and not href.startswith(("javascript:", "mailto:", "tel:")):
                links.append(normalize_url(urljoin(base, href)))
        for tag in soup.find_all("script", src=True):
            links.append(normalize_url(urljoin(base, tag["src"])))
        forms: list[dict] = []
        for f in soup.find_all("form"):
            action = normalize_url(urljoin(base, f.get("action") or base))
            method = (f.get("method") or "get").upper()
            inputs = []
            for inp in f.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name") or "",
                    "type": inp.get("type") or "text",
                    "value": inp.get("value") or "",
                })
            forms.append({"action": action, "method": method, "inputs": inputs, "discovered_at": base})
        return links, forms

    def _extract_url_params(self, url: str, state: CrawlState, ctx: "Context") -> None:
        for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
            state.params.add((url, k))
            ctx.dashboard.add_count("params")

    def _scan_secrets(self, url: str, body: str, state: CrawlState, ctx: "Context") -> None:
        if not body or not self._secret_rules:
            return
        for name, pat in self._secret_rules:
            m = pat.search(body)
            if m:
                hit = {"url": url, "rule": name, "match": m.group(0)[:200]}
                state.secrets.append(hit)
                self.report_finding(ctx, {
                    "category": "secret_exposure",
                    "title": f"Sensitive data exposure ({name})",
                    "severity": "high",
                    "cvss": 7.5,
                    "url": url,
                    "evidence": hit["match"],
                    "metadata": {"rule": name},
                })

    async def _render_with_browser(self, seed_url: str, state: CrawlState, ctx: "Context") -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            log.debug("playwright not installed — skipping JS render")
            return
        from core.browser_pool import browser_slot
        try:
            async with browser_slot(ctx.config), async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                xhr_endpoints: list[str] = []

                async def on_request(req):
                    if req.resource_type in ("xhr", "fetch"):
                        xhr_endpoints.append(req.url)

                page.on("request", on_request)
                try:
                    await page.goto(seed_url, wait_until="networkidle", timeout=20000)
                except Exception:
                    pass
                # harvest anchors injected post-load
                hrefs = await page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)")
                await browser.close()
                for href in hrefs + xhr_endpoints:
                    href = normalize_url(href)
                    if href not in state.queued:
                        state.queued.add(href)
                        state.endpoints.append({"url": href, "status": -1, "ctype": "js-discovered"})
                        ctx.dashboard.add_count("endpoints")
                        self._extract_url_params(href, state, ctx)
        except Exception as exc:
            log.debug("browser render failed: %s", exc)

    async def _probe_graphql(self, seed_url: str, ctx: "Context") -> None:
        candidates = [
            urljoin(seed_url, "/graphql"),
            urljoin(seed_url, "/api/graphql"),
            urljoin(seed_url, "/v1/graphql"),
        ]
        introspection = {"query": "{__schema{types{name}}}"}
        for url in candidates:
            ev = await ctx.http.post(url, json_body=introspection,
                                     headers={"Content-Type": "application/json"})
            if ev.status == 200 and "__schema" in ev.response_body:
                self.report_finding(ctx, {
                    "category": "graphql_introspection",
                    "title": "GraphQL introspection enabled in production",
                    "severity": "medium",
                    "cvss": 5.3,
                    "url": url,
                    "evidence": ev.response_body[:400],
                    "request": json.dumps(introspection),
                    "response": ev.response_body[:1000],
                })
                # also enqueue for vuln agent (logic checks)
                await ctx.queue.put("scan.graphql", {"url": url}, target=ctx.target_slug,
                                    priority=2, producer=self.name)

    async def _emit_scan_tasks(self, state: CrawlState, ctx: "Context") -> None:
        from core.injection import candidate_points
        # Group query params by URL
        by_url: dict[str, list[str]] = {}
        for url, p in state.params:
            by_url.setdefault(url, []).append(p)
        # Also consider every discovered endpoint for path-segment injection,
        # even ones with no query string — that's where REST IDOR / SQLi lives.
        for ep in state.endpoints:
            by_url.setdefault(ep["url"], by_url.get(ep["url"], []))
        for url, params in by_url.items():
            points = candidate_points(url, params)
            if not points:
                continue
            await ctx.queue.put(
                "scan",
                {"url": url, "method": "GET", "params": points},
                target=ctx.target_slug, priority=3, producer=self.name,
            )
        for form in state.forms:
            param_names = [i["name"] for i in form["inputs"] if i["name"]]
            if not param_names:
                continue
            await ctx.queue.put(
                "scan",
                {"url": form["action"], "method": form["method"], "params": param_names,
                 "form": form},
                target=ctx.target_slug, priority=2, producer=self.name,
            )
        # logic / IDOR analysis -- fire once per host
        await ctx.queue.put(
            "logic",
            {"endpoints": [e["url"] for e in state.endpoints],
             "forms": state.forms},
            target=ctx.target_slug, priority=4, producer=self.name,
        )
