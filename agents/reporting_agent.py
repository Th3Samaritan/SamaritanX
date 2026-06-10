"""ReportingAgent — assembles the final Markdown + PDF deliverables and
emits per-finding HackerOne-style submissions ready to paste."""
from __future__ import annotations

import json
from collections import Counter
from typing import TYPE_CHECKING

from core.task_queue import Task
from reporting.markdown_report import render_markdown, render_hackerone
from reporting.pdf_report import render_pdf
from . import walkthrough_agent
from core.confidence import label as conf_label
from .base import BaseAgent

if TYPE_CHECKING:
    from core.orchestrator import Context


class ReportingAgent(BaseAgent):
    name = "report"
    handles = ("report",)

    async def handle(self, task: Task, ctx: "Context") -> None:
        findings = ctx.memory.list_findings(ctx.target_slug)
        for f in findings:
            f.setdefault("confidence", 0.5)
            f["confidence_label"] = conf_label(float(f["confidence"]))
        findings.sort(key=lambda f: (float(f.get("confidence", 0)), f.get("cvss", 0)), reverse=True)
        confirmed = [f for f in findings if float(f.get("confidence", 0)) >= 0.6]
        candidates = [f for f in findings if float(f.get("confidence", 0)) < 0.6]
        exploit_path = ctx.workspace / "reports" / "exploitation.json"
        playbooks = {}
        chains: list[dict] = []
        priority: list[dict] = []
        if exploit_path.exists():
            data = json.loads(exploit_path.read_text(encoding="utf-8"))
            playbooks = {pb["finding_id"]: pb["steps"] for pb in data.get("playbooks", [])}
            chains = data.get("chains", [])
            priority = data.get("priority", [])

        # annotate every finding with walkthrough + impact + remediation
        for f in findings:
            walkthrough_agent.annotate(f, playbooks.get(f["id"]))

        # severity counts
        sev_count = Counter([f.get("severity", "info").lower() for f in findings])
        severity_counts = {k: sev_count.get(k, 0) for k in
                           ("critical", "high", "medium", "low", "info")}

        # executive summary
        n = len(findings)
        if n == 0:
            exec_summary = "No findings were produced by the automated pipeline. " \
                           "The asset surface and crawled corpus are still in /recon and /crawl."
        else:
            top = sorted(findings, key=lambda f: f.get("cvss", 0), reverse=True)[:3]
            top_titles = "; ".join(f["title"] for f in top)
            exec_summary = (
                f"SamaritanX produced **{n} findings** against `{ctx.target}` "
                f"({severity_counts['critical']} critical, {severity_counts['high']} high, "
                f"{severity_counts['medium']} medium, {severity_counts['low']} low). "
                f"**{len(confirmed)} are high-confidence** (verify and submit); "
                f"**{len(candidates)} are lower-confidence candidates** that need manual "
                f"confirmation before submission. Highest-CVSS issues: {top_titles}."
            )

        proxy_cfg = ctx.config.get("proxy", {}) or {}
        proxy_label = ""
        if proxy_cfg.get("tor"):
            proxy_label = "Tor (socks5://127.0.0.1:9050)"
        elif proxy_cfg.get("enabled") and proxy_cfg.get("url"):
            proxy_label = proxy_cfg["url"]

        bundle = {
            "target": ctx.target,
            "operator": ctx.config.get("operator", {}).get("handle", "th3Samaritan"),
            "findings": findings,
            "severity_counts": severity_counts,
            "executive_summary": exec_summary,
            "chains": chains,
            "priority": priority or [
                {"title": f["title"], "category": f["category"],
                 "severity": f["severity"], "cvss": f["cvss"]}
                for f in sorted(findings, key=lambda f: f.get("cvss", 0), reverse=True)[:10]
            ],
            "confirmed_count": len(confirmed),
            "candidate_count": len(candidates),
            "scanner_count": len(ctx.config.get("scanners", {}).get("enabled", []) or []),
            "rate_limit": ctx.config.get("stealth", {}).get("rate_limit_rps", 6),
            "proxy": proxy_label,
            "walkthrough": ctx.config.get("reporting", {}).get("include_walkthrough", True),
            "counters": {
                "subdomains": ctx.dashboard._counters.get("subdomains", 0),
                "endpoints": ctx.dashboard._counters.get("endpoints", 0),
                "params": ctx.dashboard._counters.get("params", 0),
                "requests": ctx.dashboard._counters.get("requests", 0),
            },
        }

        md_out = render_markdown(bundle)
        md_path = ctx.workspace / "reports" / "report.md"
        md_path.write_text(md_out, encoding="utf-8")
        ctx.dashboard.event("ok", f"report: markdown -> {md_path}")

        if "pdf" in (ctx.config.get("reporting", {}).get("format") or []):
            pdf_path = ctx.workspace / "reports" / "report.pdf"
            ok = render_pdf(md_out, pdf_path)
            if ok:
                ctx.dashboard.event("ok", f"report: pdf -> {pdf_path}")
            else:
                ctx.dashboard.event("err", "report: pdf rendering unavailable "
                                            "(install weasyprint + GTK / pango)")

        # also drop a machine-readable bundle
        (ctx.workspace / "reports" / "findings.json").write_text(
            json.dumps(findings, indent=2, default=str), encoding="utf-8")

        # per-finding HackerOne submissions
        h1_dir = ctx.workspace / "reports" / "hackerone"
        h1_dir.mkdir(parents=True, exist_ok=True)
        operator = ctx.config.get("operator", {}).get("handle", "th3Samaritan")
        for f in findings:
            md = render_hackerone(f, operator)
            slug = f"{f['id']:04d}_{f['category']}_{(f.get('severity') or 'info')}.md"
            (h1_dir / slug).write_text(md, encoding="utf-8")
        ctx.dashboard.event("ok", f"report: {len(findings)} HackerOne submissions -> {h1_dir}")
