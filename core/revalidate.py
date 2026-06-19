"""Pre-submission auto-revalidation — the false-positive killer.

Auto-scanners flap: a reflection that was there at 02:00 is gone at 02:05, a
timing oracle was just jitter. Submitting those gets a hunter signal-banned and
uninvited from private programs. Before the report is written, this re-fires
each finding *fresh* and applies a category-specific reproduce check:

  * reproduced     → confidence nudged up, flagged `revalidated`.
  * not reproduced → confidence cut hard (×0.4) and relabelled, so the report
    sinks it below the firm/confirmed line instead of presenting it as solid.
  * not re-checkable (OOB hard proof, chains, static secrets, oracle-only) →
    left as-is and marked skipped, with the reason.

It is read-only — same request class the scanner already sent — so it always
runs (no `--aggressive` needed). A summary lands in
`workspace/<target>/reports/revalidation.json`.
"""
from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Optional

from .confidence import label as conf_label
from .injection import send, parse_point

if TYPE_CHECKING:
    from .orchestrator import Context

_SQL_ERR = re.compile(r"(sql syntax|mysql|unclosed quotation|ORA-\d{5}|sqlstate|"
                      r"syntax error at or near|odbc)", re.I)
_NOSQL_ERR = re.compile(r"(MongoError|BSONObj|E11000|MongoServerError|unknown operator|CastError)", re.I)
_RCE_MARKER = re.compile(r"SX_[a-z0-9]{4,12}_OK")
_SSRF_INDICATORS = ("ami-id", "iam/security-credentials", "computemetadata",
                    "metadata/instance", "root:x:0:0:", "redis_version", "stat pid")


async def _refire(ctx, finding, *, value=None):
    """Re-send the recorded request and return HttpEvidence (or None)."""
    url = finding.get("url")
    param = finding.get("parameter") or ""
    payload = value if value is not None else (finding.get("payload") or "")
    method = (finding.get("request") or "GET").split(None, 1)[0].upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        method = "GET"
    if not url:
        return None
    if param and ":" in param and parse_point(param)[0] != "query":
        return await send(ctx, url, method, param, payload, None)
    if param and payload and not param.startswith("("):
        return await send(ctx, url, method, param, payload, None)
    return await ctx.http.get(url)


# ---- per-category reproduce checks: return True/False, or None if skipped ----
async def _re_cors(ctx, f):
    ev = await ctx.http.get(f.get("url", ""), headers={"Origin": "https://evil.samaritanx.test"})
    aco = ev.response_headers.get("access-control-allow-origin", "")
    if "credential" in (f.get("title") or "").lower():
        acc = (ev.response_headers.get("access-control-allow-credentials") or "").lower() == "true"
        return ("evil.samaritanx.test" in aco) and acc
    return "evil.samaritanx.test" in aco


async def _re_reflect(ctx, f):
    payload = f.get("payload") or ""
    if not payload:
        return None
    ev = await _refire(ctx, f)
    return bool(ev and payload in (ev.response_body or ""))


async def _re_rce(ctx, f):
    if (f.get("metadata") or {}).get("detection") == "oob":
        return None
    ev = await _refire(ctx, f)
    return bool(ev and _RCE_MARKER.search(ev.response_body or ""))


async def _re_ssti(ctx, f):
    ev = await _refire(ctx, f)
    body = (ev.response_body or "") if ev else ""
    return ("49" in body) and ("{{7*7}}" not in body)


async def _re_open_redirect(ctx, f):
    ev = await _refire(ctx, f)
    if not ev:
        return False
    loc = ev.response_headers.get("location", "")
    return ev.status in (301, 302, 303, 307, 308) and ("//" in loc) and "samaritanx" in (f.get("payload") or "").lower() or \
        (ev.status in (301, 302, 303, 307, 308) and bool(loc))


async def _re_sql_error(ctx, f):
    if (f.get("metadata") or {}).get("detection") not in ("error", None):
        return None  # boolean/time oracles aren't single-shot re-checkable
    ev = await _refire(ctx, f)
    return bool(ev and _SQL_ERR.search(ev.response_body or ""))


async def _re_nosql(ctx, f):
    if (f.get("metadata") or {}).get("detection") != "error":
        return None
    ev = await _refire(ctx, f)
    return bool(ev and _NOSQL_ERR.search(ev.response_body or ""))


async def _re_ssrf(ctx, f):
    if (f.get("metadata") or {}).get("detection") in ("oob", "oob-header"):
        return None  # callback proof — can't replay collaborator here
    ev = await _refire(ctx, f)
    body = (ev.response_body or "").lower() if ev else ""
    return any(m in body for m in _SSRF_INDICATORS)


async def _re_crlf(ctx, f):
    ev = await _refire(ctx, f)
    if not ev:
        return False
    hdr_blob = " ".join(f"{k}:{v}" for k, v in (ev.response_headers or {}).items()).lower()
    return "samaritanx" in hdr_blob or "sx-" in hdr_blob


REVALIDATORS = {
    "cors": _re_cors,
    "xss": _re_reflect, "stored_xss": _re_reflect,
    "rce": _re_rce, "ssti": _re_ssti,
    "open_redirect": _re_open_redirect,
    "sqli": _re_sql_error, "nosqli": _re_nosql,
    "ssrf": _re_ssrf, "crlf": _re_crlf,
}

# categories we deliberately never auto-revalidate (hard proof or not single-shot)
_SKIP_REASON = {
    "chain": "depends on component findings", "secret_exposure": "static artifact",
    "exposure": "static artifact", "takeover": "hard proof (CNAME fingerprint)",
    "subdomain_takeover": "hard proof", "nuclei": "external template",
    "web_cache_deception": "multi-step proof (already confirmed)",
    "account_takeover": "side-effecting flow", "graphql_introspection": "schema dump",
    "idor": "stateful comparison", "api": "mixed signals", "csrf": "missing-token heuristic",
}


async def revalidate(ctx: "Context", findings: list[dict]) -> dict:
    reproduced = dropped = skipped = 0
    details: list[dict] = []

    for f in findings:
        cat = (f.get("category") or "").lower()
        fid = f.get("id") or f.get("_id")
        conf = float(f.get("confidence", 0.5) or 0.5)
        checker = REVALIDATORS.get(cat)
        result: Optional[bool]
        if not checker:
            result = None
            reason = _SKIP_REASON.get(cat, "no single-shot re-check")
        else:
            try:
                result = await checker(ctx, f)
            except Exception as exc:  # noqa: BLE001
                result = None
                reason = f"recheck error: {exc}"
            else:
                reason = "oracle/replay not applicable" if result is None else ""

        meta = f.get("metadata") or {}
        if result is True:
            reproduced += 1
            new_conf = round(min(1.0, conf + 0.1), 2)
            meta["revalidated"] = True
            ctx.memory.update_finding(fid, confidence=new_conf, metadata=meta)
        elif result is False:
            dropped += 1
            new_conf = round(conf * 0.4, 2)
            meta["revalidated"] = False
            meta["revalidation_note"] = "did NOT reproduce on fresh re-test — likely false positive"
            ctx.memory.update_finding(fid, confidence=new_conf, metadata=meta,
                                      title=f.get("title"))
        else:
            skipped += 1
            meta["revalidation"] = f"skipped: {reason}"
            ctx.memory.update_finding(fid, metadata=meta)
        details.append({"id": fid, "category": cat,
                        "result": {True: "reproduced", False: "dropped"}.get(result, "skipped"),
                        "confidence_label": conf_label(float(meta.get("_c", conf)))})

    summary = {"reproduced": reproduced, "dropped": dropped, "skipped": skipped,
               "total": len(findings), "details": details}
    try:
        (ctx.workspace / "reports").mkdir(parents=True, exist_ok=True)
        (ctx.workspace / "reports" / "revalidation.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8")
    except Exception:
        pass
    ctx.dashboard.event("ok",
        f"revalidation: {reproduced} reproduced, {dropped} dropped (likely FP), {skipped} skipped")
    return summary
