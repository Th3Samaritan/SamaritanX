"""Continuous monitoring + diff.

Bounty income is dominated by being *first* on new attack surface. This module
turns SamaritanX's one-shot recon/crawl into a watchtower: it snapshots the
attack surface each run, diffs against the previous baseline, and reports what
is *new* — new subdomains, new endpoints, new parameters — so a scheduled run
(via `--monitor` + cron / `/schedule`) pages you the moment a target ships
something fresh.

Enable with `--monitor` or `monitor.enabled: true`. A diff artifact is written
to `workspace/<target>/monitor/diff_<ts>.json`, new-surface events hit the
dashboard, and (if `monitor.webhook` is set) a compact JSON alert is POSTed.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from .orchestrator import Context


def _snapshot(ctx: "Context") -> dict:
    """Build the current attack-surface snapshot from workspace artifacts."""
    crawl = ctx.workspace / "crawl"
    endpoints: set[str] = set()
    params: set[str] = set()
    hosts: set[str] = set()

    for ep_file in crawl.glob("*_endpoints.json"):
        try:
            for e in json.loads(ep_file.read_text(encoding="utf-8")):
                u = e.get("url") if isinstance(e, dict) else None
                if u:
                    endpoints.add(u)
                    hosts.add(urlparse(u).netloc)
        except Exception:
            continue
    for pf in crawl.glob("*_params.txt"):
        try:
            for line in pf.read_text(encoding="utf-8").splitlines():
                if "::" in line:
                    url, p = line.split("::", 1)
                    params.add(f"{url.strip()} :: {p.strip()}")
        except Exception:
            continue

    # subdomains from recon, if present
    for rf in (ctx.workspace / "recon").glob("*.txt"):
        try:
            for line in rf.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and "." in line and " " not in line:
                    hosts.add(urlparse(line if "//" in line else "//" + line).netloc or line)
        except Exception:
            continue

    findings = ctx.memory.list_findings(ctx.target_slug)
    sev_counts: dict[str, int] = {}
    finding_keys: list[str] = []
    for f in findings:
        sev = f.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        # stable fingerprint for cross-run diffing (None-fingerprint fallback)
        key = f.get("fingerprint") or f"{f.get('category','')}||{f.get('url','')}||" \
              f"{f.get('parameter','')}||{(f.get('title') or '').lower()}"
        finding_keys.append(key)

    return {
        "ts": int(time.time()),
        "hosts": sorted(h for h in hosts if h),
        "endpoints": sorted(endpoints),
        "params": sorted(params),
        "findings": sev_counts,
        "finding_keys": sorted(finding_keys),
    }


def diff(old: dict, new: dict) -> dict:
    """Set-diff the two snapshots into added/removed buckets."""
    def d(key):
        o, n = set(old.get(key, [])), set(new.get(key, []))
        return {"added": sorted(n - o), "removed": sorted(o - n)}
    delta = {k: d(k) for k in ("hosts", "endpoints", "params")}
    delta["findings"] = d("finding_keys")
    delta["findings"]["counts"] = {"old": old.get("findings", {}),
                                   "new": new.get("findings", {})}
    return delta


def _has_changes(delta: dict) -> bool:
    return any(delta[k]["added"] or delta[k]["removed"] for k in
               ("hosts", "endpoints", "params", "findings"))


def _prune_diffs(out_dir: Path, keep: int) -> None:
    """Keep only the newest `keep` diff artifacts so scheduled runs don't
    accumulate them forever. keep <= 0 disables pruning."""
    if keep <= 0:
        return
    diffs = sorted(out_dir.glob("diff_*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    for stale in diffs[keep:]:
        try:
            stale.unlink()
        except Exception:
            pass


async def run(ctx: "Context") -> dict | None:
    """Snapshot, diff against the stored baseline, persist, and alert. Returns
    the diff (or None on first run / when disabled)."""
    mon_cfg = ctx.config.get("monitor", {}) or {}
    if not mon_cfg.get("enabled"):
        return None

    out_dir = ctx.workspace / "monitor"
    out_dir.mkdir(parents=True, exist_ok=True)
    baseline_path = out_dir / "baseline.json"

    new = _snapshot(ctx)
    if not baseline_path.exists():
        baseline_path.write_text(json.dumps(new, indent=2), encoding="utf-8")
        (out_dir / f"snap_{new['ts']}.json").write_text(json.dumps(new, indent=2),
                                                        encoding="utf-8")
        ctx.dashboard.event("info", "monitor: baseline established (first run — no diff)")
        return None

    try:
        old = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception:
        old = {}

    delta = diff(old, new)
    ts = new["ts"]
    (out_dir / f"diff_{ts}.json").write_text(json.dumps(delta, indent=2), encoding="utf-8")
    (out_dir / f"snap_{ts}.json").write_text(json.dumps(new, indent=2), encoding="utf-8")
    baseline_path.write_text(json.dumps(new, indent=2), encoding="utf-8")
    _prune_diffs(out_dir, int(mon_cfg.get("keep_diffs", 30)))

    if _has_changes(delta):
        nh, ne, npar = (len(delta["hosts"]["added"]), len(delta["endpoints"]["added"]),
                        len(delta["params"]["added"]))
        ctx.dashboard.event("ok",
            f"monitor: NEW surface — +{nh} hosts, +{ne} endpoints, +{npar} params "
            f"(diff_{ts}.json)")
        for h in delta["hosts"]["added"][:10]:
            ctx.dashboard.event("info", f"monitor: new host {h}")
        # new FINDINGS deserve the loudest alert — a new bug class on the
        # target is the thing a hunter wants paged about first
        new_fps = delta["findings"]["added"]
        new_details = _finding_details(ctx, new_fps)
        if new_details:
            for d_ in new_details:
                ctx.dashboard.event("crit",
                    f"monitor: NEW finding [{d_['severity']}] {d_['title'][:70]} — {d_['url'][:60]}")
        # legacy webhook + structured Slack/Discord/Telegram notifications
        await _notify(ctx, mon_cfg.get("webhook"), new["ts"], delta, new_details)
        try:
            from .notify import new_findings, new_surface
            await new_findings(ctx, new_details)
            await new_surface(ctx, delta["hosts"]["added"],
                              delta["endpoints"]["added"], delta["params"]["added"])
        except Exception:  # noqa: BLE001
            pass
    else:
        ctx.dashboard.event("info", "monitor: no attack-surface change since last run")
    return delta


def _finding_details(ctx: "Context", fingerprints: list[str]) -> list[dict]:
    """Map snapshot fingerprints back to finding dicts for alerts."""
    out: list[dict] = []
    try:
        for f in ctx.memory.list_findings(ctx.target_slug):
            key = f.get("fingerprint") or f"{f.get('category','')}||{f.get('url','')}||" \
                  f"{f.get('parameter','')}||{(f.get('title') or '').lower()}"
            if key in fingerprints:
                out.append({"severity": f.get("severity", "info"),
                            "title": f.get("title", ""),
                            "url": f.get("url", ""),
                            "category": f.get("category", "")})
    except Exception:
        pass
    return out


async def _notify(ctx: "Context", webhook: str | None, ts: int, delta: dict,
                  new_findings: list[dict] | None = None) -> None:
    if not webhook:
        return
    payload = {
        "text": f"SamaritanX monitor [{ctx.target}]: "
                f"+{len(delta['hosts']['added'])} hosts, "
                f"+{len(delta['endpoints']['added'])} endpoints, "
                f"+{len(delta['params']['added'])} params, "
                f"+{len(delta['findings']['added'])} findings",
        "target": ctx.target,
        "ts": ts,
        "new_hosts": delta["hosts"]["added"][:25],
        "new_endpoints": delta["endpoints"]["added"][:50],
        "new_findings": new_findings[:20],
        "finding_counts": delta.get("findings", {}).get("counts", {}),
    }
    try:
        await ctx.http.request("POST", webhook, json_body=payload, bypass_scope=True)
        ctx.dashboard.event("ok", "monitor: webhook alert sent")
    except Exception as exc:  # noqa: BLE001
        ctx.dashboard.event("err", f"monitor: webhook failed: {exc}")
