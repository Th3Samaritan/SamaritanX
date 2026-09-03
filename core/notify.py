"""Notification integrations — Slack / Discord / Telegram.

One dispatcher for every alert class SamaritanX emits:

  * ``new_findings``   — monitor detected findings that didn't exist last run
  * ``new_surface``    — monitor detected new hosts/endpoints/params
  * ``scan_complete``  — run finished (finding + request summary)

Config (all optional, env-expanded):

    notify:
      enabled: true
      on: ["new_findings", "scan_complete"]
      slack_webhook:  "{ENV:SX_SLACK_WEBHOOK}"
      discord_webhook: "{ENV:SX_DISCORD_WEBHOOK}"
      telegram:
        bot_token: "{ENV:SX_TG_BOT_TOKEN}"
        chat_id: "{ENV:SX_TG_CHAT_ID}"

Every send is best-effort: a failing webhook is logged and never breaks the
scan. Slack/Discord get a severity-coloured summary; Telegram gets compact
Markdown text.
"""
from __future__ import annotations

import json
import os
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .orchestrator import Context

# Discord embed colour by severity
_COLORS = {
    "critical": 0xE74C3C,
    "high": 0xE67E22,
    "medium": 0xF1C40F,
    "low": 0x3498DB,
    "info": 0x95A5A6,
}


def _env(v: Any) -> str:
    v = str(v or "")
    if v.startswith("{ENV:") and v.endswith("}"):
        return os.environ.get(v[5:-1], "")
    return v


def _cfg(ctx: "Context") -> dict:
    return ctx.config.get("notify", {}) or {}


def _wants(notify_cfg: dict, event: str) -> bool:
    if not notify_cfg.get("enabled"):
        return False
    on = notify_cfg.get("on") or ["new_findings", "new_surface", "scan_complete"]
    return event in on


def _slack_payload(target: str, title: str, lines: list[str], color: str) -> dict:
    return {
        "text": f"*SamaritanX* — {title} — `{target}`",
        "attachments": [{
            "color": {"critical": "danger", "high": "warning", "medium": "good",
                      "low": "good", "info": "#95A5A6"}.get(color, "good"),
            "fields": [{"title": title, "value": "\n".join(lines)[:3000],
                        "short": False}],
        }],
    }


def _discord_payload(target: str, title: str, lines: list[str], color: str) -> dict:
    return {
        "content": f"**SamaritanX** — {title} — `{target}`",
        "embeds": [{
            "title": title,
            "description": "\n".join(lines)[:3000],
            "color": _COLORS.get(color, 0x95A5A6),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }


def _telegram_text(target: str, title: str, lines: list[str]) -> str:
    text = f"*SamaritanX* — {title}\n`{target}`\n\n" + "\n".join(lines)
    return text[:3900]


def _line_for(finding: dict) -> str:
    return (f"[{str(finding.get('severity', 'info')).upper()}] "
            f"{str(finding.get('title'))[:90]} — {str(finding.get('url'))[:70]}")


async def _post(ctx: "Context", url: str, payload: dict) -> bool:
    try:
        ev = await ctx.http.request("POST", url, json_body=payload,
                                    bypass_scope=True,
                                    headers={"Content-Type": "application/json"})
        return ev.status in (200, 201, 202, 204)
    except Exception:
        return False


async def notify(ctx: "Context", event: str, *, title: str = "", lines: list[str] | None = None,
                 findings: list[dict] | None = None, color: str = "info") -> None:
    """Fan an alert out to every configured channel (best-effort)."""
    ncfg = _cfg(ctx)
    if not _wants(ncfg, event):
        return
    lines = list(lines or [])
    for f in findings or []:
        lines.append(_line_for(f))
    lines = lines[:20] or ["(no detail)"]
    color = color or "info"

    slack = _env(ncfg.get("slack_webhook"))
    discord = _env(ncfg.get("discord_webhook"))
    tg = ncfg.get("telegram") or {}
    tg_token, tg_chat = _env(tg.get("bot_token")), _env(tg.get("chat_id"))

    sent = 0
    if slack:
        if await _post(ctx, slack, _slack_payload(ctx.target, title or event, lines, color)):
            sent += 1
        else:
            ctx.dashboard.event("err", "notify: slack webhook failed")
    if discord:
        if await _post(ctx, discord, _discord_payload(ctx.target, title or event, lines, color)):
            sent += 1
        else:
            ctx.dashboard.event("err", "notify: discord webhook failed")
    if tg_token and tg_chat:
        url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
        payload = {"chat_id": tg_chat, "text": _telegram_text(ctx.target, title or event, lines),
                   "parse_mode": "Markdown"}
        if await _post(ctx, url, payload):
            sent += 1
        else:
            ctx.dashboard.event("err", "notify: telegram send failed")
    if sent:
        ctx.dashboard.event("ok", f"notify: '{event}' -> {sent} channel(s)")


# --------------------------------------------------------------------------- #
# Pre-built alert bundles
# --------------------------------------------------------------------------- #
async def scan_complete(ctx: "Context") -> None:
    """Run-finished summary (findings by severity + request count)."""
    findings = ctx.memory.list_findings(ctx.target_slug)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    lines = [
        f"Findings: {len(findings)}  "
        f"(critical {counts.get('critical', 0)}, high {counts.get('high', 0)}, "
        f"medium {counts.get('medium', 0)}, low {counts.get('low', 0)})",
        f"Requests: {ctx.http.request_count}  scope-blocked: {ctx.http.scoped_out}",
        f"Workspace: {ctx.workspace}",
    ]
    color = "critical" if counts.get("critical") else ("high" if counts.get("high") else "info")
    await notify(ctx, "scan_complete", title="scan complete", lines=lines, color=color)


async def new_findings(ctx: "Context", new_details: list[dict]) -> None:
    """Monitor alert: findings that did not exist in the previous run."""
    if not new_details:
        return
    color = "critical" if any(d.get("severity") == "critical" for d in new_details) else \
            "high" if any(d.get("severity") == "high" for d in new_details) else "medium"
    await notify(ctx, "new_findings", title=f"{len(new_details)} new finding(s)",
                 findings=new_details, color=color)


async def new_surface(ctx: "Context", added_hosts: list[str],
                      added_endpoints: list[str], added_params: list[str]) -> None:
    """Monitor alert: new attack surface."""
    lines = ([f"+{len(added_hosts)} hosts: {', '.join(added_hosts[:10])}"] if added_hosts else []) + \
            ([f"+{len(added_endpoints)} endpoints: {', '.join(added_endpoints[:10])}"] if added_endpoints else []) + \
            ([f"+{len(added_params)} params"] if added_params else [])
    if not lines:
        return
    await notify(ctx, "new_surface", title="new attack surface", lines=lines, color="info")
