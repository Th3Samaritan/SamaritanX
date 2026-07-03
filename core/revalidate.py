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
from .poc import is_auth_wall, is_static_asset, proof_record

if TYPE_CHECKING:
    from .orchestrator import Context

_SQL_ERR = re.compile(r"(sql syntax|mysql|unclosed quotation|ORA-\d{5}|sqlstate|"
                      r"syntax error at or near|odbc)", re.I)
_NOSQL_ERR = re.compile(r"(MongoError|BSONObj|E11000|MongoServerError|unknown operator|CastError)", re.I)
_RCE_MARKER = re.compile(r"SX_[a-z0-9]{4,12}_OK")
_SSRF_INDICATORS = ("ami-id", "iam/security-credentials", "computemetadata",
                    "metadata/instance", "root:x:0:0:", "redis_version", "stat pid")


def _capture(f: dict, ev, *, method: str, rationale: str, request: str | None = None) -> bool:
    """Attach a captured, verified proof to a finding and return True.

    Called from a revalidator's reproduce-True path so the finding carries the
    actual request + response that proves it — the artifact the proof-gate
    requires before anything reaches the report."""
    meta = f.setdefault("metadata", {})
    if isinstance(meta, dict):
        meta["poc"] = proof_record(
            verified=True, method=method, url=f.get("url", ""),
            request=request or (f.get("request") or f"{method} {f.get('url','')}"),
            status=getattr(ev, "status", None),
            excerpt=getattr(ev, "response_body", "") or "",
            rationale=rationale,
        )
    return True


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
        if ("evil.samaritanx.test" in aco) and acc:
            return _capture(f, ev, method="GET",
                            request=f"GET {f.get('url','')}\nOrigin: https://evil.samaritanx.test",
                            rationale="Cross-origin request from an arbitrary Origin was reflected "
                                      "into Access-Control-Allow-Origin with "
                                      "Access-Control-Allow-Credentials: true — a credentialed "
                                      "cross-origin read of this response is possible.")
        return False
    if "evil.samaritanx.test" in aco:
        return _capture(f, ev, method="GET",
                        request=f"GET {f.get('url','')}\nOrigin: https://evil.samaritanx.test",
                        rationale="An arbitrary Origin was reflected into "
                                  "Access-Control-Allow-Origin.")
    return False


async def _re_reflect(ctx, f):
    payload = f.get("payload") or ""
    if not payload:
        return None
    ev = await _refire(ctx, f)
    if ev and payload in (ev.response_body or ""):
        return _capture(f, ev, method=_re_method(f),
                        rationale=f"The payload {payload!r} was reflected unencoded in the "
                                  "response body on a fresh re-fire.")
    return False


async def _re_rce(ctx, f):
    if (f.get("metadata") or {}).get("detection") == "oob":
        return None
    ev = await _refire(ctx, f)
    if ev and _RCE_MARKER.search(ev.response_body or ""):
        return _capture(f, ev, method=_re_method(f),
                        rationale="The command-execution marker was echoed in the response — "
                                  "the injected command ran.")
    return False


async def _re_ssti(ctx, f):
    ev = await _refire(ctx, f)
    body = (ev.response_body or "") if ev else ""
    if ("49" in body) and ("{{7*7}}" not in body):
        return _capture(f, ev, method=_re_method(f),
                        rationale="The template expression {{7*7}} evaluated to 49 in the "
                                  "response — server-side template injection is confirmed.")
    return False


async def _re_open_redirect(ctx, f):
    ev = await _refire(ctx, f)
    if not ev:
        return False
    loc = ev.response_headers.get("location", "")
    if ev.status not in (301, 302, 303, 307, 308) or not loc:
        return False
    # Real proof: the payload we injected actually appears in the redirect target
    # (host or full URL). A bare 3xx with some Location is not open redirect.
    payload = (f.get("payload") or "").strip()
    from urllib.parse import urlparse as _up
    pay_host = _up(payload if "//" in payload else "//" + payload).netloc.lower()
    loc_l = loc.lower()
    controlled = bool(payload) and (payload.lower() in loc_l or (pay_host and pay_host in loc_l))
    if controlled:
        return _capture(f, ev, method=_re_method(f),
                        request=f"{_re_method(f)} {f.get('url','')}",
                        rationale=f"Server issued a {ev.status} redirect to Location: {loc[:120]} "
                                  "— the destination host came from our payload.")
    return False


async def _re_sql_error(ctx, f):
    if (f.get("metadata") or {}).get("detection") not in ("error", None):
        return None  # boolean/time oracles aren't single-shot re-checkable
    ev = await _refire(ctx, f)
    if ev and _SQL_ERR.search(ev.response_body or ""):
        return _capture(f, ev, method=_re_method(f),
                        rationale="A SQL error string surfaced in the response when the payload "
                                  "was re-sent — the input reaches an unparameterised query.")
    return False


async def _re_nosql(ctx, f):
    if (f.get("metadata") or {}).get("detection") != "error":
        return None
    ev = await _refire(ctx, f)
    if ev and _NOSQL_ERR.search(ev.response_body or ""):
        return _capture(f, ev, method=_re_method(f),
                        rationale="A NoSQL driver error surfaced in the response when the "
                                  "operator payload was re-sent.")
    return False


async def _re_ssrf(ctx, f):
    if (f.get("metadata") or {}).get("detection") in ("oob", "oob-header"):
        return None  # callback proof — can't replay collaborator here
    ev = await _refire(ctx, f)
    body = (ev.response_body or "").lower() if ev else ""
    if any(m in body for m in _SSRF_INDICATORS):
        return _capture(f, ev, method=_re_method(f),
                        rationale="The response contained an internal-resource indicator "
                                  "(cloud metadata / internal service banner) fetched via the "
                                  "SSRF sink.")
    return False


async def _re_crlf(ctx, f):
    ev = await _refire(ctx, f)
    if not ev:
        return False
    hdr_blob = " ".join(f"{k}:{v}" for k, v in (ev.response_headers or {}).items()).lower()
    if "samaritanx" in hdr_blob or "sx-" in hdr_blob:
        return _capture(f, ev, method=_re_method(f),
                        rationale="An injected header appeared in the response headers — CRLF "
                                  "injection lets the payload split the header section.")
    return False


def _re_method(f: dict) -> str:
    m = (f.get("request") or "GET").split(None, 1)[0].upper()
    return m if m in ("GET", "POST", "PUT", "PATCH", "DELETE") else "GET"


async def _re_broken_auth(ctx, f):
    """Prove (or drop) a 'reachable without authentication' finding.

    The dominant false positive here is an app that 200s its *login page* — the
    naive detector reads "200 + body" as privileged access. We re-fetch with no
    credentials at all and decide:
      * auth wall (login page / redirect / 401-403) → False  (drop the FP)
      * static asset                                → False  (not a page at all)
      * substantive page with identity/sensitive markers → True + captured PoC
      * reachable but unprovable as privileged      → None   (skip, manual check)
    Cross-identity / BFLA findings need a stateful identity replay we can't do
    single-shot, so they are skipped honestly.
    """
    meta = f.get("metadata") or {}
    if meta.get("detection") == "authz_matrix" and meta.get("identity") not in (None, "anon"):
        return None  # BFLA/BOLA — needs per-identity sessions, not single-shot
    url = f.get("url")
    if not url:
        return None
    ev = await ctx.http.get(url, no_session=True,
                            headers={"Authorization": "", "Cookie": ""})
    if not ev or not ev.status:
        return None
    wall, why = is_auth_wall(ev.status, ev.response_headers, ev.response_body, url)
    if wall:
        meta["revalidation_proof"] = f"unauth re-fetch hit an auth wall — {why} (HTTP {ev.status})"
        f["metadata"] = meta
        return False
    if is_static_asset(url, ev.response_headers):
        meta["revalidation_proof"] = "URL serves a static asset, not privileged content"
        f["metadata"] = meta
        return False
    body = ev.response_body or ""
    if ev.status != 200 or len(body) < 200:
        return False
    from scanners.idor_deep import identity_markers
    from .escalation import sensitive_hits
    markers = sorted(identity_markers(body))[:6]
    sensitive = [k for k, _ in sensitive_hits(body, ev.response_headers)]
    if not markers and not sensitive:
        meta["revalidation_proof"] = (
            "reachable unauthenticated and not a login page, but no identity / "
            "sensitive markers were found — confirm privileged content manually")
        f["metadata"] = meta
        return None
    meta["poc"] = proof_record(
        verified=True, method="GET", url=url,
        request=f"GET {url}\n(sent with no Cookie and no Authorization header)",
        status=ev.status, excerpt=body,
        rationale=(f"Fetched with zero credentials and received privileged content "
                   f"(identity markers={markers}, sensitive={sensitive}); the response "
                   "is not a login, redirect, or deny page — authentication is not enforced."))
    f["metadata"] = meta
    return True


async def _re_smuggling(ctx, f):
    """Confirm a timing-oracle smuggle is reproducible, not a one-off fluke.

    Delegates to the scanner's raw-socket re-probe (it owns the byte-level
    payloads). Confirms only when the flagged shape is consistently slow and its
    inverse consistently fast across repeats; drops when the differential is
    clearly gone; skips when the network is too noisy to decide."""
    kind = (f.get("metadata") or {}).get("kind")
    try:
        if kind in ("CL.TE", "TE.CL"):
            from scanners.request_smuggling import reprobe
        elif kind == "h2_crlf_path":
            from scanners.h2_smuggling import reprobe
        else:
            return None  # continuation flood / h2c: no single-shot timing oracle
        result, proof = await reprobe(ctx, f)
    except Exception:  # noqa: BLE001
        return None
    if result is True and proof:
        meta = f.get("metadata") or {}
        meta["poc"] = proof
        f["metadata"] = meta
    return result


REVALIDATORS = {
    "cors": _re_cors,
    "xss": _re_reflect, "stored_xss": _re_reflect,
    "rce": _re_rce, "ssti": _re_ssti,
    "open_redirect": _re_open_redirect,
    "sqli": _re_sql_error, "nosqli": _re_nosql,
    "ssrf": _re_ssrf, "crlf": _re_crlf,
    "broken_auth": _re_broken_auth,
    "smuggling": _re_smuggling,
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
