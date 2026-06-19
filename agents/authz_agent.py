"""Authorization Matrix Agent — broken access control at scale.

Where `idor_deep` replays a single URL with two sessions, this agent tests the
whole discovered surface against every identity we hold and builds a
role × endpoint matrix. For each endpoint it fires the request as:

    * anon      — no credentials at all
    * userA     — the primary --auth session
    * userB     — the --second-session (a different tenant), when present

and classifies each response. Three families of finding fall out of the matrix:

  1. **Unauthenticated access** — anon receives an authenticated, data-bearing
     response (broken authentication / data exposure).
  2. **BOLA / cross-tenant** — userB receives a response carrying userA's
     identity markers (object-level authorization missing).
  3. **BFLA / function-level** — a non-privileged identity reaches an
     admin/privileged-shaped endpoint with a 2xx instead of 401/403.

Endpoints are collapsed to path *templates* (id-shaped segments normalised) so
`/users/1`, `/users/2`, … are tested once. GET-only by default; state-changing
verbs require `--aggressive`. The full matrix is written to
`workspace/<target>/authz/matrix.json`.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

from core.escalation import sensitive_hits, severity_for
from core.task_queue import Task
from scanners.idor_deep import identity_markers
from .base import BaseAgent

if TYPE_CHECKING:
    from core.orchestrator import Context

PRIVILEGED_RE = re.compile(r"/(admin|administrator|manage|management|internal|"
                           r"console|dashboard|staff|operator|superuser|root|"
                           r"settings/users|moderat|backoffice)\b", re.I)
PRIVATE_HINT_RE = re.compile(r"/(api|account|me|profile|user|users|orders?|"
                             r"invoice|billing|payment|settings|wallet|messages?)\b", re.I)
_ID_SEG = re.compile(r"^(\d{1,12}|[0-9a-fA-F-]{8,36})$")


def _template(url: str) -> str:
    p = urlparse(url)
    segs = p.path.split("/")
    norm = ["{id}" if _ID_SEG.match(s) else s for s in segs]
    return urlunparse(p._replace(path="/".join(norm), query="", fragment=""))


class AuthzAgent(BaseAgent):
    name = "authz"
    handles = ("authz",)

    async def handle(self, task: Task, ctx: "Context") -> None:
        endpoints: list[str] = task.payload.get("endpoints", [])
        if not endpoints:
            return
        cfg = ctx.config.get("authz", {}) or {}
        max_eps = int(cfg.get("max_endpoints", 120))

        # collapse to templates, keep one concrete url per template
        by_template: dict[str, str] = {}
        for u in endpoints:
            by_template.setdefault(_template(u), u)
        targets = list(by_template.values())[:max_eps]

        # identities: (label, client, no_session, rank)
        identities = [("anon", ctx.http, True, 0)]
        if ctx.http.session and ctx.http.session.is_authed():
            identities.append(("userA", ctx.http, False, 1))
        if ctx.http2 and ctx.http2.session and ctx.http2.session.is_authed():
            identities.append(("userB", ctx.http2, False, 1))
        # extra labeled sessions (e.g. an admin row) — lifts the privilege
        # ceiling so BFLA/priv-esc can be confirmed against a real baseline.
        for ident in getattr(ctx, "extra_identities", []) or []:
            identities.append((ident["label"], ident["client"], False, int(ident.get("rank", 1))))
        # nothing to compare against → let idor_deep / logic handle it
        if len(identities) < 2:
            return

        sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))
        matrix: list[dict] = []
        ctx.dashboard.task(f"authz:{urlparse(targets[0]).netloc}", len(targets))

        async def probe(url: str) -> None:
            row = {"url": url, "template": _template(url), "cells": {}}
            cells = row["cells"]
            for label, client, no_sess, rank in identities:
                async with sem:
                    ev = await client.get(url, no_session=no_sess) if no_sess \
                        else await client.get(url)
                body = ev.response_body or ""
                cells[label] = {
                    "status": ev.status, "len": len(body), "rank": rank,
                    "markers": sorted(identity_markers(body))[:6],
                    "sensitive": [k for k, _ in sensitive_hits(body, ev.response_headers)],
                }
            matrix.append(row)
            self._evaluate(ctx, url, cells)
            ctx.dashboard.advance(f"authz:{urlparse(targets[0]).netloc}")

        await asyncio.gather(*(probe(u) for u in targets))

        out = ctx.workspace / "authz"
        out.mkdir(parents=True, exist_ok=True)
        (out / "matrix.json").write_text(json.dumps(matrix, indent=2), encoding="utf-8")
        ctx.dashboard.event("ok", f"authz: matrix over {len(targets)} endpoints × "
                                  f"{len(identities)} identities")

    def _evaluate(self, ctx: "Context", url: str, cells: dict) -> None:
        path = url.split("?")[0]
        anon = cells.get("anon")

        # 1) unauthenticated access to a private, data-bearing endpoint
        authed_with_markers = any(c["rank"] >= 1 and c["markers"] for c in cells.values())
        if anon and _ok(anon["status"]) and (anon["markers"] or anon["sensitive"]):
            if PRIVATE_HINT_RE.search(url) or authed_with_markers:
                sev, cvss = _sev_from_sensitive(anon["sensitive"])
                self.report_finding(ctx, {
                    "category": "broken_auth",
                    "title": f"Unauthenticated access to authenticated resource ({path})",
                    "severity": sev, "cvss": cvss,
                    "url": url, "parameter": "(no credentials)",
                    "evidence": f"Anonymous request returned {anon['status']} with "
                                f"private data (markers={anon['markers'][:3]}, "
                                f"sensitive={anon['sensitive']}). No authentication enforced.",
                    "metadata": {"identity": "anon", "detection": "authz_matrix",
                                 "sensitive": anon["sensitive"]},
                })
                return

        # 2) BOLA / cross-tenant — one regular user sees another's identity markers
        regulars = [(lbl, c) for lbl, c in cells.items() if c["rank"] == 1 and _ok(c["status"])]
        for i in range(len(regulars)):
            for j in range(len(regulars)):
                if i == j:
                    continue
                (la, ca), (lb, cb) = regulars[i], regulars[j]
                if not ca["markers"]:
                    continue
                shared = set(ca["markers"]) & set(cb["markers"])
                if shared:
                    pii = bool(cb["sensitive"])
                    self.report_finding(ctx, {
                        "category": "idor",
                        "title": f"BOLA — {lb} reads {la}'s object ({path})",
                        "severity": "critical" if pii else "high",
                        "cvss": 9.1 if pii else 8.1,
                        "url": url, "parameter": "(cross-identity matrix)",
                        "evidence": f"{lb} request returned {la}'s identity markers "
                                    f"{sorted(shared)[:4]} — object-level authorization missing.",
                        "metadata": {"identity": lb, "owner": la, "detection": "authz_matrix",
                                     "shared": sorted(shared)[:6]},
                    })
                    return

        # 3) BFLA / privilege escalation — rank-aware. Establish the privilege
        #    level that *legitimately* reaches this endpoint (highest rank with a
        #    substantive 2xx), then flag any strictly-lower identity that also
        #    gets in. Requires either a privileged-shaped path or a real
        #    higher-privilege (admin) baseline, so public pages don't trip it.
        substantive = {lbl: c for lbl, c in cells.items() if _ok(c["status"]) and c["len"] > 80}
        if substantive:
            owner_rank = max(c["rank"] for c in substantive.values())
            has_admin_baseline = owner_rank >= 2
            if PRIVILEGED_RE.search(url) or has_admin_baseline:
                for lbl, c in sorted(substantive.items(), key=lambda kv: kv[1]["rank"]):
                    if c["rank"] < owner_rank:
                        owner = next(l for l, cc in substantive.items() if cc["rank"] == owner_rank)
                        self.report_finding(ctx, {
                            "category": "broken_auth",
                            "title": f"BFLA / privilege escalation — '{lbl}' reaches "
                                     f"rank-{owner_rank} resource ({path})",
                            "severity": "high", "cvss": 8.2,
                            "url": url, "parameter": f"(identity={lbl})",
                            "evidence": f"Endpoint legitimately served identity '{owner}' "
                                        f"(rank {owner_rank}); lower-privilege identity '{lbl}' "
                                        f"(rank {c['rank']}) also got {c['status']} ({c['len']}B) "
                                        "instead of 401/403.",
                            "metadata": {"identity": lbl, "owner": owner,
                                         "owner_rank": owner_rank, "detection": "authz_matrix"},
                        })
                        return


def _ok(status: int) -> bool:
    return bool(status) and 200 <= status < 300


def _sev_from_sensitive(sensitive: list[str]) -> tuple[str, float]:
    if any(k in sensitive for k in ("jwt", "bearer_token", "aws_key", "api_key", "session_cookie")):
        return "critical", 9.1
    if "pii" in sensitive:
        return "high", 7.5
    return "high", 7.2
