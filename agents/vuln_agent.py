"""Vulnerability Agent — dispatches each (url, params) tuple emitted by the
crawler to every enabled scanner concurrently, plus an optional nuclei pass
on the host root for off-the-shelf templates.

The agent is intentionally thin: scanners hold the detection logic, this
class just orchestrates fan-out, deduplicates findings, and persists them.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import TYPE_CHECKING

from core.task_queue import Task
from core.utils import host_of
from scanners import REGISTRY, HIGH_VALUE
from scanners.subdomain_takeover import scan_takeover
from .base import BaseAgent

if TYPE_CHECKING:
    from core.orchestrator import Context


class VulnerabilityAgent(BaseAgent):
    name = "vuln"
    handles = ("scan", "scan.graphql", "scan.takeover")

    def __init__(self) -> None:
        super().__init__()
        self._nuclei_done: set[str] = set()

    async def handle(self, task: Task, ctx: "Context") -> None:
        if task.kind == "scan.takeover":
            await scan_takeover(ctx, task)
            return

        url = task.payload["url"]
        params = task.payload.get("params", []) or []
        method = task.payload.get("method", "GET")
        form = task.payload.get("form")

        # resume: skip URLs whose scan phase already completed in a prior run
        host = host_of(url)
        if ctx.resume and ctx.memory.is_url_processed(ctx.target_slug, url, "scan"):
            self._nuclei_done.add(host)
            return

        # incremental scanning: if the endpoint's content hash is unchanged
        # since the last completed scan, the scanners would replay the same
        # probes against the same surface — skip them (huge request savings
        # on scheduled re-runs, zero loss of coverage)
        incremental = bool(ctx.config.get("scan", {}).get("incremental", True))
        if incremental:
            cache = getattr(ctx, "cache", None)
            probe = await cache.fetch(ctx.http, url, allow_redirects=False) if cache \
                else await ctx.http.get(url, allow_redirects=False)
            if probe.status and not probe.error:
                import hashlib
                fp = hashlib.sha1(
                    f"{probe.status}|{len(probe.response_body or '')}|"
                    f"{hashlib.sha1((probe.response_body or '')[:8192].encode('utf-8', 'ignore')).hexdigest()}"
                    .encode()).hexdigest()
                prev = ctx.memory.get_url_fingerprint(ctx.target_slug, url)
                if prev == fp:
                    self._nuclei_done.add(host)
                    ctx.memory.mark_url_processed(ctx.target_slug, url, "scan")
                    return
                # store when the scan completes below (checkpoint)

        enabled = ctx.config.get("scanners", {}).get("enabled", [])
        runners = [(name, REGISTRY[name]) for name in enabled if name in REGISTRY]
        if task.kind == "scan.graphql":
            runners = [(n, f) for n, f in runners
                       if n in ("graphql", "api", "sqli", "rce", "prompt_injection")]

        # Pre-flight: if any high-value scanner is in this batch and we have
        # an auth session, refresh + validate it before firing — guarantees
        # the critical payloads aren't wasted on an expired token.
        if ctx.session and ctx.session.is_authed() \
                and any(n in HIGH_VALUE for n, _ in runners):
            try:
                ok = await ctx.session.preflight(ctx.http, validate_url=url)
                if not ok:
                    ctx.dashboard.event("err",
                        f"auth pre-flight FAILED on {url} — skipping high-value scanners")
                    runners = [(n, f) for n, f in runners if n not in HIGH_VALUE]
            except Exception as exc:
                ctx.dashboard.event("err", f"auth pre-flight error: {exc}")

        results = await asyncio.gather(
            *[self._safe(name, fn, ctx, url, params, method, form) for name, fn in runners]
        )

        seen_keys: set[tuple] = set()
        for batch in results:
            for finding in (batch or []):
                if not isinstance(finding, dict):
                    continue
                key = (finding.get("category"), finding.get("url"),
                       finding.get("parameter"), finding.get("title"))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                self.report_finding(ctx, finding)

        # one-shot nuclei sweep per host
        host = host_of(url)
        if host not in self._nuclei_done and ctx.config.get("scanners", {}).get("nuclei", True):
            self._nuclei_done.add(host)
            await self._run_nuclei(host, url, ctx)

        # checkpoint: this URL's scan phase is complete (resume skips it next run)
        ctx.memory.mark_url_processed(ctx.target_slug, url, "scan")
        if incremental:
            try:
                import hashlib
                cache = getattr(ctx, "cache", None)
                ev0 = await cache.fetch(ctx.http, url, allow_redirects=False) if cache \
                    else await ctx.http.get(url, allow_redirects=False)
                if ev0.status and not ev0.error:
                    fp = hashlib.sha1(
                        f"{ev0.status}|{len(ev0.response_body or '')}|"
                        f"{hashlib.sha1((ev0.response_body or '')[:8192].encode('utf-8', 'ignore')).hexdigest()}"
                        .encode()).hexdigest()
                    ctx.memory.set_url_fingerprint(ctx.target_slug, url, fp)
            except Exception:
                pass

    async def _safe(self, name, fn, ctx, url, params, method, form):
        # Scanners make dozens of throttled requests (baseline + payloads) and
        # dozens of scan tasks run concurrently, so every scanner competes for
        # the global token bucket — a short deadline kills them mid-sweep
        # before they can complete. Give them a realistic budget; smuggling
        # probes (raw sockets + timing oracles) get more.
        deadline = 180.0 if name in ("smuggling", "h2_smuggling", "request_smuggling") else 120.0
        try:
            return await asyncio.wait_for(
                fn(ctx, url, params, method, form),
                timeout=deadline,
            )
        except asyncio.TimeoutError:
            self.log.warning("scanner %s timed out on %s (%.0fs)", name, url, deadline)
            ctx.dashboard.event("err", f"{name} timed out on {url}")
            return []
        except Exception as exc:  # noqa: BLE001
            self.log.exception("scanner %s crashed on %s: %s", name, url, exc)
            ctx.dashboard.event("err", f"{name} crashed on {url}: {exc}")
            return []

    async def _run_nuclei(self, host: str, url: str, ctx: "Context") -> None:
        if not shutil.which("nuclei"):
            return
        from core.utils import slugify
        out_path = ctx.workspace / "vulns" / f"{slugify(host)}_nuclei.jsonl"
        sev = ctx.config.get("scanners", {}).get("nuclei_severity", "medium,high,critical")
        from urllib.parse import urlparse
        scheme = urlparse(url).scheme or "https"
        ctx.dashboard.event("info", f"nuclei: scanning {host} (sev={sev}, scheme={scheme})")
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-u", f"{scheme}://{host}", "-silent", "-jsonl",
                "-severity", sev, "-o", str(out_path),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=600.0)
        except asyncio.TimeoutError:
            ctx.dashboard.event("err", f"nuclei timed out on {host}")
            return
        except asyncio.CancelledError:
            raise
        finally:
            if proc is not None and proc.returncode is None:
                try:
                    proc.kill()
                except Exception:
                    pass
        if not out_path.exists():
            return
        for line in out_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            info = d.get("info", {}) or {}
            self.report_finding(ctx, {
                "category": "nuclei",
                "title": f"[nuclei] {info.get('name') or d.get('template-id')}",
                "severity": (info.get("severity") or "info").lower(),
                "cvss": float(info.get("classification", {}).get("cvss-score") or 0),
                "url": d.get("matched-at") or d.get("host"),
                "evidence": (info.get("description") or "")[:600],
                "metadata": {"template": d.get("template-id"), "tags": info.get("tags")},
            })
