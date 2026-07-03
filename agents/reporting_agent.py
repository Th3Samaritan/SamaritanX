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
        all_findings = ctx.memory.list_findings(ctx.target_slug)
        for f in all_findings:
            f.setdefault("confidence", 0.5)
            f["confidence_label"] = conf_label(float(f["confidence"]))
        all_findings.sort(key=lambda f: (float(f.get("confidence", 0)), f.get("cvss", 0)), reverse=True)

        # HARD PROOF-GATE: only findings that carry a captured, re-tested PoC are
        # reported. Everything else is quarantined to candidates.json and never
        # presented as a finding. This is the false-positive kill-switch.
        from core.proof_gate import partition
        findings, candidates = partition(all_findings)
        confirmed = findings  # every reported finding is, by definition, proven
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
            exec_summary = (
                f"No **proven** findings against `{ctx.target}`. "
                f"{len(candidates)} candidate signal(s) were produced but none carried a "
                "captured, re-tested proof, so all were quarantined to `candidates.json` for "
                "manual review rather than reported. The asset surface and crawled corpus are "
                "in /recon and /crawl."
            )
        else:
            top = sorted(findings, key=lambda f: f.get("cvss", 0), reverse=True)[:3]
            top_titles = "; ".join(f["title"] for f in top)
            exec_summary = (
                f"SamaritanX **proved {n} finding(s)** against `{ctx.target}` "
                f"({severity_counts['critical']} critical, {severity_counts['high']} high, "
                f"{severity_counts['medium']} medium, {severity_counts['low']} low). "
                f"Every reported finding ships a captured request+response PoC and re-tested "
                f"clean. A further **{len(candidates)} unproven candidate(s)** were quarantined "
                f"to `candidates.json` (not reported). Highest-CVSS proven issues: {top_titles}."
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

        # machine-readable bundle: ONLY proven findings go in findings.json
        (ctx.workspace / "reports" / "findings.json").write_text(
            json.dumps(findings, indent=2, default=str), encoding="utf-8")

        # quarantined candidates — unproven signals, kept out of the report but
        # retained (with the reason each was held back) for manual review
        candidates_out = [{
            "id": c.get("id"), "category": c.get("category"), "title": c.get("title"),
            "severity": c.get("severity"), "url": c.get("url"),
            "confidence": c.get("confidence"),
            "quarantine_reason": (c.get("metadata") or {}).get("quarantine_reason",
                                                               "no captured proof"),
        } for c in candidates]
        (ctx.workspace / "reports" / "candidates.json").write_text(
            json.dumps(candidates_out, indent=2, default=str), encoding="utf-8")
        if candidates:
            ctx.dashboard.event("info",
                f"proof-gate: {len(findings)} proven, {len(candidates)} quarantined "
                f"-> candidates.json")

        # per-finding HackerOne submissions
        h1_dir = ctx.workspace / "reports" / "hackerone"
        h1_dir.mkdir(parents=True, exist_ok=True)
        operator = ctx.config.get("operator", {}).get("handle", "th3Samaritan")
        for f in findings:
            md = render_hackerone(f, operator)
            slug = f"{f['id']:04d}_{f['category']}_{(f.get('severity') or 'info')}.md"
            (h1_dir / slug).write_text(md, encoding="utf-8")
        ctx.dashboard.event("ok", f"report: {len(findings)} HackerOne submissions -> {h1_dir}")
