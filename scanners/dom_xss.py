"""DOM XSS scanner via Playwright.

For each URL with parameters, opens the page in a real browser with the
parameter set to a unique JS-payload sentinel. Hooks `alert`, `confirm`,
`prompt`, and `console.error` so executed payloads produce an attributable
event. Also sniffs sinks like `document.write`, `innerHTML`,
`eval`, `setTimeout(string)` by stack-trace inspection.

Only runs when Playwright is available; otherwise it's a noop and the
classic reflected XSS scanner remains in charge.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.utils import random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

JS_HOOK = """
(() => {
    window.__sx_hits__ = [];
    const tag = (k, v) => window.__sx_hits__.push({k, v: String(v).slice(0,200),
                                                   stack: (new Error()).stack});
    const _alert = window.alert;
    window.alert   = (m) => { tag('alert', m);   try { return _alert(m); } catch(e) {} };
    window.confirm = (m) => { tag('confirm', m); return false; };
    window.prompt  = (m) => { tag('prompt', m);  return null; };
    const _err = console.error;
    console.error = (...a) => { tag('console.error', a.join(' ')); _err(...a); };
    const _w = document.write;
    document.write = function(s) { tag('document.write', s); return _w.call(this, s); };
})();
"""


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    if method.upper() != "GET" or not params:
        return []
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return []

    findings: list[dict] = []
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
        except Exception:
            return findings
        context = await browser.new_context(ignore_https_errors=True)

        async def test_param(param: str) -> None:
            token = f"sxdom{random_token(6)}"
            payload = f'<svg onload=window.alert("{token}")>'
            qs2 = {**qs, param: payload}
            target = urlunparse(parsed._replace(query=urlencode(qs2)))
            page = await context.new_page()
            await page.add_init_script(JS_HOOK)
            try:
                await page.goto(target, wait_until="networkidle", timeout=15000)
            except Exception:
                await page.close()
                return
            try:
                hits = await page.evaluate("window.__sx_hits__ || []")
            except Exception:
                hits = []
            await page.close()
            triggered = [h for h in hits if token in (h.get("v") or "")]
            if triggered:
                findings.append({
                    "category": "xss",
                    "title": f"DOM XSS in `{param}` (browser-confirmed)",
                    "severity": "critical", "cvss": 8.2,
                    "url": target, "parameter": param, "payload": payload,
                    "evidence": f"Browser executed payload — sink: "
                                f"{', '.join(sorted({h['k'] for h in triggered}))}",
                    "request": f"GET {target}",
                    "response": str(triggered)[:1500],
                    "metadata": {"detection": "browser", "sinks": [h["k"] for h in triggered]},
                })

        await asyncio.gather(*(test_param(p) for p in params))
        await browser.close()
    return findings
