"""Vulnerability Agent — dispatches each (url, params) tuple emitted by the
crawler to every enabled scanner concurrently, plus an optional nuclei pass
on the host root for off-the-shelf templates.

The agent is intentionally thin: scanners hold the detection logic, this
class just orchestrates fan-out, deduplicates findings, and persists them.
"""
from __future__ import annotations

from core.transport import external_tool_path, TransportBlocked, create_subprocess_exec as managed_create_subprocess_exec

import asyncio
import json
import shutil
import time
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
        self._scanner_slots = None

    async def handle(self, task: Task, ctx: "Context") -> None:
        if task.kind == "scan.takeover":
            await scan_takeover(ctx, task)
            return

        url = task.payload["url"]
        params = task.payload.get("params", []) or []
        method = task.payload.get("method", "GET")
        form = task.payload.get("form")
        ctx.memory.remember_scan_task(ctx.target_slug, task.kind, task.payload)

        host = host_of(url)
        content_type = task.payload.get("content_type", "")

        enabled = ctx.config.get("scanners", {}).get("enabled", [])
        runners = [(name, REGISTRY[name]) for name in enabled if name in REGISTRY]
        if task.kind == "scan.graphql":
            runners = [(n, f) for n, f in runners
                       if n in ("graphql", "api", "sqli", "rce", "prompt_injection")]

        from core.scan_execution import applicability, execution_key
        auth_ok = True
        needs_auth = getattr(ctx, "auth_required", False) or bool(ctx.session and ctx.session.is_authed())
        if needs_auth and any(n in HIGH_VALUE for n, _ in runners):
            try:
                auth_ok = bool(ctx.session and ctx.session.is_authed()) and await ctx.session.preflight(ctx.http, validate_url=url)
            except Exception:
                auth_ok = False
        scan_cfg = ctx.config.get("scan", {})
        selected = []
        for name, fn in runners:
            key = execution_key(ctx, name, fn, url, params, method, form)
            ctx.memory.record_execution_context(ctx.target_slug, key, {
                "method": method.upper(), "inputs": sorted(params),
                "identity": getattr(ctx.session, "label", "anonymous"),
                "second_identity": getattr(getattr(getattr(ctx, "http2", None), "session", None), "label", None),
                "additional_identities": [i.get("label") for i in getattr(ctx, "extra_identities", [])],
                "content_type": content_type})
            applies, reason = applicability(name, params, form, content_type)
            if not auth_ok and name in HIGH_VALUE:
                applies, reason = False, "authentication preflight failed"
            if not applies:
                ctx.memory.record_execution(ctx.target_slug, key, name, url, "skipped", reason)
                continue
            # Incremental reuse is opt-in: a stable page is not proof of a stable backend.
            reuse = getattr(ctx, "resume", False) or scan_cfg.get("incremental", False)
            if reuse and ctx.memory.execution_reusable(ctx.target_slug, key, float(scan_cfg.get("recheck_after_seconds", 86400))):
                continue
            selected.append((name, fn, key))
            ctx.memory.record_execution(ctx.target_slug, key, name, url, "queued", "waiting for scanner slot")
        await asyncio.gather(*[
            self._safe(name, fn, ctx, url, params, method, form, key)
            for name, fn, key in selected])

        # one-shot nuclei sweep per host
        host = host_of(url)
        if host not in self._nuclei_done and ctx.config.get("scanners", {}).get("nuclei", True):
            self._nuclei_done.add(host)
            await self._run_nuclei(host, url, ctx)

    async def _safe(self, name, fn, ctx, url, params, method, form, key=None):
        if self._scanner_slots is None:
            cap = max(1, min(128, int(ctx.config.get("concurrency", {}).get("scanner_workers", 12))))
            self._scanner_slots = asyncio.Semaphore(cap)
        async with self._scanner_slots:
            return await self._execute(name, fn, ctx, url, params, method, form, key)

    async def _execute(self, name, fn, ctx, url, params, method, form, key=None):
        from core.scan_execution import (RequestBudget, RequestBudgetExceeded,
                                         request_budget, execution_key, REASON_CODES)
        key = key or execution_key(ctx, name, fn, url, params, method, form)
        run_id = getattr(ctx, "run_id", "") or ""
        cfg = ctx.config.get("scan", {})
        deadline = float(cfg.get("scanner_timeout_seconds", 180 if name in {"smuggling", "h2_smuggling"} else 120))
        # Retrying state-changing probes can duplicate side effects.
        retries = min(2, max(0, int(cfg.get("scanner_retries", 1))))
        if form or method.upper() not in {"GET", "HEAD"} or ctx.config.get("safety", {}).get("aggressive"):
            retries = 0
        budget = RequestBudget(max(1, int(cfg.get("scanner_request_budget", 250))))
        token = request_budget.set(budget)
        from core.evidence import capture
        evidence_token = capture.set([])
        try:
            for attempt in range(1, retries + 2):
                ctx.memory.record_execution(ctx.target_slug, key, name, url, "running",
                                            attempts=attempt, run_id=run_id)
                t0 = time.perf_counter()
                circuit_before = getattr(getattr(ctx, "http", None), "circuit_blocked_count", 0)
                try:
                    results = await asyncio.wait_for(fn(ctx, url, params, method, form), timeout=deadline)
                    if budget.exhausted:
                        raise RequestBudgetExceeded()
                    if not isinstance(results, list):
                        raise TypeError("scanner must return a list")
                    for finding in results:
                        if not isinstance(finding, dict):
                            raise TypeError("scanner finding must be a mapping")
                        self.report_finding(ctx, finding)
                    # a scanner that produced nothing because the circuit was
                    # open must not read as a clean "no vulnerabilities"
                    if not results and budget.used == 0 \
                            and getattr(getattr(ctx, "http", None), "circuit_blocked_count", 0) > circuit_before:
                        ctx.memory.record_execution(ctx.target_slug, key, name, url, "blocked",
                                                    REASON_CODES["circuit_open"],
                                                    attempts=attempt, requests=0,
                                                    run_id=run_id,
                                                    duration_s=round(time.perf_counter() - t0, 3))
                        return results
                    ctx.memory.record_execution(ctx.target_slug, key, name, url, "completed",
                                                "enabled; applicability checks passed",
                                                attempts=attempt, requests=budget.used,
                                                run_id=run_id,
                                                duration_s=round(time.perf_counter() - t0, 3))
                    return results
                except asyncio.CancelledError:
                    ctx.memory.record_execution(ctx.target_slug, key, name, url, "interrupted",
                                                REASON_CODES["cancelled"],
                                                attempts=attempt, requests=budget.used,
                                                run_id=run_id)
                    raise
                except TransportBlocked as exc:
                    status, reason = "skipped", str(exc)
                except RequestBudgetExceeded:
                    status, reason = "budget_exhausted", REASON_CODES["request_budget_exhausted"]
                except asyncio.TimeoutError:
                    status, reason = "timed_out", REASON_CODES["timed_out"]
                except Exception as exc:
                    status, reason = "failed", type(exc).__name__
                ctx.memory.record_execution(ctx.target_slug, key, name, url, status, reason,
                                            attempts=attempt, requests=budget.used,
                                            run_id=run_id,
                                            duration_s=round(time.perf_counter() - t0, 3))
                if status in {"budget_exhausted", "skipped"}:
                    break
            ctx.dashboard.event("err", f"{name}: {status} on {url}")
            return []
        finally:
            capture.reset(evidence_token)
            request_budget.reset(token)

    async def _run_nuclei(self, host: str, url: str, ctx: "Context") -> None:
        if not external_tool_path("nuclei", ctx.config):
            return
        from pathlib import Path
        from core.utils import slugify
        out_path = ctx.workspace / "vulns" / f"{slugify(host)}_nuclei.jsonl"
        sev = ctx.config.get("scanners", {}).get("nuclei_severity", "medium,high,critical")
        from urllib.parse import urlparse
        scheme = urlparse(url).scheme or "https"
        ctx.dashboard.event("info", f"nuclei: scanning {host} (sev={sev}, scheme={scheme})")
        templates = ctx.config.get("external_tools", {}).get("nuclei_templates")

        # Deterministic batch selection (plan section 8): the catalog LOADS
        # fast (~26s measured for 11,245 templates) but EXECUTES slowly against
        # a live target — one unbounded invocation is indistinguishable from a
        # hang and loses all coverage on timeout. Run each top-level template
        # directory as its own managed invocation with its own recorded state,
        # so partial coverage is honest and a slow group can't sink the rest.
        tpl_path = Path(templates) if templates else None
        groups: list[tuple[str, str]] = []
        if tpl_path and tpl_path.is_dir():
            subdirs = sorted(p for p in tpl_path.iterdir() if p.is_dir())
            groups = [(p.name, str(p)) for p in subdirs] or [("catalog", str(tpl_path))]
        elif templates:
            groups = [("catalog", str(templates))]
        per_group_timeout = float(ctx.config.get("external_tools", {}).get("nuclei_group_timeout", 120))

        for label, template_arg in groups:
            batch_out = ctx.workspace / "vulns" / f"{slugify(host)}_nuclei_{label}.jsonl"
            key = f"external:nuclei:{host}:{label}"
            run_id = getattr(ctx, "run_id", "") or ""

            # resumable batches (plan 11.6): a completed group with an
            # unchanged template digest is skipped on resume; changed templates
            # invalidate the resume decision
            from core.run_manifest import template_selection_digest
            group_cfg = dict(ctx.config)
            group_cfg.setdefault("external_tools", {})["nuclei_templates"] = template_arg
            group_digest = template_selection_digest(group_cfg)
            if ctx.resume:
                prev_ctx = {}
                try:
                    with ctx.memory._connect() as conn:
                        r = conn.execute(
                            "SELECT context FROM execution_contexts WHERE target=? AND execution_key=?",
                            (ctx.target_slug, key)).fetchone()
                        prev_ctx = json.loads(r["context"]) if r and r["context"] else {}
                except Exception:
                    prev_ctx = {}
                if prev_ctx.get("template_digest") == group_digest:
                    ex = ctx.memory.execution_reusable(ctx.target_slug, key, 86400)
                    if ex:
                        ctx.memory.record_execution(ctx.target_slug, key, "nuclei", url,
                                                    "skipped", "batch completed — resume (template digest unchanged)",
                                                    run_id=run_id, phase="scan.external")
                        continue
            ctx.memory.record_execution_context(ctx.target_slug, key,
                                                {"template_digest": group_digest,
                                                 "label": label, "host": host})
            # unique output per attempt: stale output from a previous attempt
            # must never be imported
            try:
                batch_out.unlink(missing_ok=True)
            except Exception:
                pass

            proc = None
            t0 = time.perf_counter()
            try:
                proc = await managed_create_subprocess_exec(
                    "nuclei", "-u", f"{scheme}://{host}", "-silent", "-jsonl",
                    "-severity", sev, "-o", str(batch_out),
                    "-t", template_arg,
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                code = await asyncio.wait_for(proc.wait(), timeout=per_group_timeout)
                if code != 0:
                    ctx.memory.record_execution(ctx.target_slug, key, "nuclei", url,
                                                "failed", f"exit code {code}",
                                                run_id=run_id, exit_code=code,
                                                phase="scan.external",
                                                duration_s=round(time.perf_counter() - t0, 3))
                    continue
                parsed, total = self._import_nuclei_output(ctx, batch_out, out_path)
                if parsed < total:
                    from core.scan_execution import REASON_CODES
                    ctx.memory.record_execution(ctx.target_slug, key, "nuclei", url,
                                                "partial", REASON_CODES["output_parse_error"],
                                                run_id=run_id, exit_code=code,
                                                phase="scan.external",
                                                diagnostics=f"{total - parsed} unparseable output line(s)",
                                                duration_s=round(time.perf_counter() - t0, 3))
                else:
                    ctx.memory.record_execution(ctx.target_slug, key, "nuclei", url,
                                                "completed", "managed proxy adapter completed",
                                                run_id=run_id, exit_code=code,
                                                phase="scan.external",
                                                duration_s=round(time.perf_counter() - t0, 3))
            except TransportBlocked as exc:
                ctx.memory.record_execution(ctx.target_slug, key, "nuclei", url,
                                            "skipped", str(exc), run_id=run_id,
                                            phase="scan.external")
                ctx.dashboard.event("info", f"nuclei adapter blocked: {exc}")
                return
            except asyncio.TimeoutError:
                ctx.memory.record_execution(ctx.target_slug, key, "nuclei", url,
                                            "timed_out",
                                            f"group exceeded {per_group_timeout:.0f}s",
                                            run_id=run_id, phase="scan.external",
                                            diagnostics=f"catalog group {label} did not finish in "
                                                        f"{per_group_timeout:.0f}s")
                ctx.dashboard.event("err", f"nuclei group {label} timed out on {host}")
                continue
            except asyncio.CancelledError:
                ctx.memory.record_execution(ctx.target_slug, key, "nuclei", url,
                                            "cancelled", "run cancelled",
                                            run_id=run_id, phase="scan.external")
                raise
            finally:
                if proc is not None and proc.returncode is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass

    def _import_nuclei_output(self, ctx: "Context", batch_out, out_path) -> tuple[int, int]:
        """Import a finished group's output. Returns (parsed_lines, total_lines);
        unparseable lines are reported, never silently swallowed."""
        if not batch_out.exists():
            return 0, 0
        lines = batch_out.read_text(encoding="utf-8", errors="ignore").splitlines()
        parsed = 0
        for line in lines:
            try:
                d = json.loads(line)
            except Exception:
                continue
            parsed += 1
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
        # aggregate for the classic single-file view
        with out_path.open("a", encoding="utf-8") as fh:
            fh.write(batch_out.read_text(encoding="utf-8", errors="ignore"))
        return parsed, len(lines)
