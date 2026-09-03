"""HackerOne draft submission (opt-in, never publishes).

When ``hackerone.enabled: true`` and a v1 API token + username are configured,
the reporting agent creates a **draft** report for each verified finding via
``POST /v1/hackers/reports/drafts``. Drafts are private to the hacker account —
nothing is ever submitted to the program automatically. The operator reviews
drafts in the HackerOne UI and submits manually.

Design constraints honoured here:
  * opt-in only (off by default),
  * one draft per finding fingerprint (re-runs don't duplicate),
  * any API error is logged and swallowed — reporting never fails because
    of HackerOne,
  * the submission ledger lives in
    ``workspace/<target>/reports/hackerone/drafts.json``.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from .poc import build_curl, build_repro

if TYPE_CHECKING:
    from .orchestrator import Context

H1_DRAFTS_URL = "https://api.hackerone.com/v1/hackers/reports/drafts"


def _config(ctx: "Context") -> dict:
    return ctx.config.get("hackerone", {}) or {}


def _expand_env(value) -> str:
    v = str(value or "")
    if v.startswith("{ENV:") and v.endswith("}"):
        import os
        return os.environ.get(v[5:-1], "")
    return v


def _title(finding: dict) -> str:
    t = (finding.get("title") or "Security vulnerability").strip()
    return t[:200] or "Security vulnerability"


def _vuln_information(ctx: "Context", finding: dict, operator: str) -> str:
    """Build the vulnerability_information body (Markdown) for a draft."""
    impact = (finding.get("metadata") or {}).get("impact_assessment")
    if isinstance(impact, dict):
        impact = impact.get("impact", "")
    impact_text = str(impact or "").strip() or "Confirmed by captured PoC."
    lines = [
        "## Summary",
        "",
        (finding.get("evidence") or "")[:2000],
        "",
        "## Steps to reproduce",
        "",
        "```http",
        (finding.get("request") or "")[:2000],
        "```",
        "",
        "## Impact",
        "",
        impact_text[:2000],
    ]
    poc = (finding.get("metadata") or {}).get("poc")
    if isinstance(poc, dict) and poc.get("request"):
        lines += ["", "## Proof", "", "```http", str(poc["request"])[:2000], "```"]
        if poc.get("response_excerpt"):
            lines += ["", "Response excerpt:", "", "```",
                      str(poc["response_excerpt"])[:1500], "```"]
    curl = build_curl(finding)
    if curl:
        lines += ["", "## curl repro", "", "```bash", curl, "```"]
    repro = build_repro(finding)
    if repro and repro != curl:
        lines += ["", "## Repro", "", repro[:1500]]
    lines += ["", f"_Found by {operator} using SamaritanX._"]
    return "\n".join(lines)


def _severity_rating(sev: str | None) -> str:
    """H1 severity enum: none, low, medium, high, critical."""
    sev = (sev or "medium").lower()
    if sev in ("critical", "high", "medium", "low"):
        return sev
    return "none"


def _cwe(category: str) -> tuple[str, str]:
    from .constants import CWE_MAP
    return CWE_MAP.get(category or "", ("", ""))


def load_ledger(path: Path) -> dict[str, dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_ledger(path: Path, ledger: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    except Exception:
        pass


def _fingerprint(finding: dict) -> str:
    import hashlib
    key = "||".join([
        finding.get("category") or "",
        finding.get("url") or "",
        finding.get("parameter") or "",
        (finding.get("title") or "").lower(),
    ])
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


async def submit_drafts(ctx: "Context", findings: list[dict]) -> dict:
    """Create draft reports for verified findings. Returns {submitted, skipped,
    failed, draft_ids: [...]}."""
    cfg = _config(ctx)
    token = _expand_env(cfg.get("api_token"))
    username = cfg.get("username") or "samaritanx-operator"
    if not cfg.get("enabled") or not token:
        return {"submitted": 0, "skipped": len(findings), "failed": 0,
                "reason": "hackerone.enabled=false or no api_token"}
    out_dir = ctx.workspace / "reports" / "hackerone"
    ledger_path = out_dir / "drafts.json"
    ledger = load_ledger(ledger_path)
    operator = ctx.config.get("operator", {}).get("handle", "th3Samaritan")

    submitted = failed = 0
    for f in findings:
        fp = _fingerprint(f)
        if fp in ledger and ledger[fp].get("draft_id"):
            continue
        sev = f.get("severity")
        if cfg.get("weak_only") and sev not in ("low", "medium", "info"):
            continue
        body: dict = {
            "data": {
                "type": "draft_report",
                "attributes": {
                    "title": _title(f),
                    "vulnerability_information": _vuln_information(ctx, f, operator),
                    "severity_rating": _severity_rating(sev),
                },
            }
        }
        # attach the CWE weakness when the category maps to one — triagers
        # see a categorized draft instead of a blank weakness field
        cwe_id, _cwe_name = _cwe(f.get("category") or "")
        if cwe_id:
            body["data"]["relationships"] = {
                "weakness": {"data": {"type": "weakness",
                                      "attributes": {"external_id": cwe_id}}},
            }
        # link the draft to the program when a handle is configured
        program = cfg.get("program") or cfg.get("program_handle")
        if program:
            body["data"].setdefault("relationships", {})["program"] = {
                "data": {"type": "program", "attributes": {"handle": str(program)}}}
        try:
            ev = await ctx.http.request(
                "POST", H1_DRAFTS_URL, json_body=body, bypass_scope=True,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": str(username)[:120],
                })
            if ev.status in (200, 201):
                draft_id = ""
                try:
                    data = json.loads(ev.response_body or "{}")
                    draft_id = str(data.get("data", {}).get("id", "") or "")
                except Exception:
                    pass
                ledger[fp] = {"draft_id": draft_id, "title": _title(f),
                              "severity": sev, "url": f.get("url")}
                submitted += 1
                ctx.dashboard.event("ok",
                    f"hackerone: draft created ({draft_id or 'id-unknown'}) — {_title(f)[:60]}")
            else:
                failed += 1
                ctx.dashboard.event("err",
                    f"hackerone: draft failed HTTP {ev.status}: {(ev.response_body or '')[:160]}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            ctx.dashboard.event("err", f"hackerone: draft failed: {exc}")
    save_ledger(ledger_path, ledger)
    return {"submitted": submitted, "skipped": len(findings) - submitted - failed,
            "failed": failed}
