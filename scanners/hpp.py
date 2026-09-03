"""HTTP Parameter Pollution (HPP) scanner.

Duplicate-parameter semantics differ per stack (PHP takes the last, ASP.NET
concatenates with a comma, Node/qs builds an array), and WAFs frequently
parse differently from the backend. This scanner fires two conservative
probes per parameter:

  1. duplicate key with a benign + an error-triggering value
     (`p=ok&p=<quote>`) — a status/error change vs the single-value control
     shows backend parsing of duplicates
  2. array notation (`p[]=marker`) — reflection of the marker confirms
     array-style parsing

Reported as candidates (no captured exploitation proof — HPP needs a
flow-specific gadget), so they land in candidates.json for manual triage.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from core.utils import merge_query, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

_ERROR_TRIGGERS = ("'", '"', "[", "\\")
_ERROR_HINTS = ("error", "exception", "syntax", "unterminated", "invalid",
                "warning", "stack", "traceback")


def _dupe_url(url: str, param: str, v1: str, v2: str) -> str:
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    pairs = [(k, v) for k, v in pairs if k != param]
    pairs.append((param, v1))
    pairs.append((param, v2))
    return urlunsplit(parts._replace(query=urlencode(pairs)))


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    if method.upper() != "GET" or not params:
        return findings
    plain = [p for p in params if ":" not in p and not p.startswith("(")]
    sem = asyncio.Semaphore(8)

    async def probe(param: str) -> None:
        marker = f"sxhpp{random_token(6)}"
        # control: single benign value
        async with sem:
            ctrl = await ctx.http.get(merge_query(url, {param: "ok"}))
        # 1) duplicate with an error trigger
        for trig in _ERROR_TRIGGERS:
            async with sem:
                ev = await ctx.http.get(_dupe_url(url, param, "ok", trig))
            body = ev.response_body or ""
            low = body.lower()
            changed_status = ev.status != ctrl.status and ev.status >= 400
            error_text = any(h in low for h in _ERROR_HINTS) and \
                not any(h in (ctrl.response_body or "").lower() for h in _ERROR_HINTS)
            if (changed_status or error_text) and len(body) != len(ctrl.response_body or ""):
                findings.append({
                    "category": "hpp",
                    "title": f"HTTP parameter pollution — duplicate `{param}` changes server parsing",
                    "severity": "medium", "cvss": 5.3,
                    "url": url, "parameter": param,
                    "payload": f"{param}=ok&{param}={trig}",
                    "evidence": f"Sending `{param}` twice (ok + {trig!r}) changed the response "
                                f"(status {ctrl.status}->{ev.status}, {len(body)}B) where the "
                                "single-value control did not — the stack parses duplicate "
                                "parameters (WAF-vs-backend divergence likely).",
                    "request": f"GET {ev.url}",
                    "response": body[:1500],
                    "metadata": {"detection": "hpp_duplicate",
                                 "control_status": ctrl.status},
                })
                return
        # 2) array notation reflection
        async with sem:
            arr = await ctx.http.get(merge_query(url, {f"{param}[]": marker}))
        abody = arr.response_body or ""
        if marker in abody and f"{param}[]" not in abody:
            findings.append({
                "category": "hpp",
                "title": f"Array-style parameter parsing — `{param}[]` value reflected",
                "severity": "low", "cvss": 3.7,
                "url": url, "parameter": f"{param}[]",
                "payload": marker,
                "evidence": f"The value sent as `{param}[]` was reflected unencoded — the "
                            "backend parses array notation (pollution/overwrite surface).",
                "request": f"GET {arr.url}",
                "response": abody[:1500],
                "metadata": {"detection": "hpp_array"},
            })

    await asyncio.gather(*(probe(p) for p in plain[:10]))
    return findings
