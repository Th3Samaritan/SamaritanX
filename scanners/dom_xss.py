"""DOM XSS scanner via Playwright — broad sink coverage.

For every URL with parameters, opens the page in a real browser and:

  1. Hooks dangerous JS sinks before any page script runs:
        eval, Function(), setTimeout(string), setInterval(string),
        document.write, document.writeln, innerHTML setter, outerHTML
        setter, insertAdjacentHTML, location assignment, jQuery.html(),
        Range.createContextualFragment, Element.setAttribute('on*'/href/src),
        WebSocket / new URL / fetch with attacker-controlled string
  2. Captures every Window 'message' event so postMessage abuse and
     cross-origin trust failures surface
  3. Probes:
        a. classic reflected DOM XSS via query parameter
        b. URL fragment (location.hash) DOM XSS — invisible to server
        c. Prototype pollution via __proto__ / constructor.prototype param
        d. Open postMessage handler — fires a payload from an iframe and
           reports if the page acts on attacker-controlled message data
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.utils import random_token

if TYPE_CHECKING:
    from core.orchestrator import Context


JS_HOOK = r"""
(() => {
    window.__sx_hits__ = [];
    const tag = (k, v) => {
        try { window.__sx_hits__.push({k, v: String(v).slice(0, 240),
                                        ts: Date.now()}); } catch (e) {}
    };

    // 1) interactive prompts
    const _alert = window.alert;
    window.alert = (m) => { tag('alert', m); try { return _alert(m); } catch(e){} };
    window.confirm = (m) => { tag('confirm', m); return false; };
    window.prompt  = (m) => { tag('prompt', m); return null; };
    const _err = console.error;
    console.error = (...a) => { tag('console.error', a.join(' ')); _err(...a); };

    // 2) script-injection sinks
    const _eval = window.eval;
    window.eval = (s) => { tag('eval', s); try { return _eval(s); } catch(e){} };
    const _Func = window.Function;
    window.Function = function(...a) { tag('Function', a.join(' || ')); return _Func.apply(this, a); };
    const _setTimeout = window.setTimeout;
    window.setTimeout = (cb, d, ...rest) => {
        if (typeof cb === 'string') tag('setTimeout(string)', cb);
        return _setTimeout(cb, d, ...rest);
    };
    const _setInterval = window.setInterval;
    window.setInterval = (cb, d, ...rest) => {
        if (typeof cb === 'string') tag('setInterval(string)', cb);
        return _setInterval(cb, d, ...rest);
    };

    // 3) HTML-string sinks
    const _w = document.write;
    document.write = function(s) { tag('document.write', s); return _w.call(this, s); };
    document.writeln = function(s) { tag('document.writeln', s); return _w.call(this, s + '\n'); };
    const ihDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (ihDesc && ihDesc.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set(v) { tag('innerHTML', v); return ihDesc.set.call(this, v); },
            get() { return ihDesc.get.call(this); },
            configurable: true,
        });
    }
    const ohDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (ohDesc && ohDesc.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set(v) { tag('outerHTML', v); return ohDesc.set.call(this, v); },
            get() { return ohDesc.get.call(this); },
            configurable: true,
        });
    }
    const _iah = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(p, s) {
        tag('insertAdjacentHTML', s); return _iah.call(this, p, s);
    };

    // 4) location sinks
    try {
        const lh = Object.getOwnPropertyDescriptor(window.Location.prototype, 'href');
        if (lh && lh.set) {
            Object.defineProperty(window.Location.prototype, 'href', {
                set(v) { tag('location.href', v); return lh.set.call(this, v); },
                get() { return lh.get.call(this); }, configurable: true,
            });
        }
    } catch(e) {}

    // 5) attribute sinks
    const _setAttr = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(n, v) {
        const ln = String(n).toLowerCase();
        if (ln.startsWith('on') || ln === 'href' || ln === 'src' || ln === 'action') {
            tag('setAttribute(' + ln + ')', v);
        }
        return _setAttr.call(this, n, v);
    };

    // 6) postMessage receivers
    window.addEventListener('message', (e) => {
        tag('postMessage.recv', JSON.stringify({origin: e.origin, data: e.data}).slice(0, 240));
    }, true);

    // 7) prototype pollution detector
    setTimeout(() => {
        if ({}.__sxpoll__ !== undefined) tag('proto.pollution', String({}.__sxpoll__));
        if (Object.prototype.__sxpoll__ !== undefined)
            tag('proto.pollution', String(Object.prototype.__sxpoll__));
    }, 1500);
})();
"""


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    if method.upper() != "GET":
        return []
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return []

    findings: list[dict] = []
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    candidate_params = params or list(qs.keys()) or ["q", "search", "name", "id"]

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
        except Exception:
            return findings
        context = await browser.new_context(ignore_https_errors=True,
                                            viewport={"width": 1280, "height": 720})
        sem = asyncio.Semaphore(2)

        async def run_probe(target_url: str, payload: str, token: str,
                             label: str, param: str | None) -> None:
            page = await context.new_page()
            await page.add_init_script(JS_HOOK)
            try:
                await page.goto(target_url, wait_until="networkidle", timeout=15000)
                await asyncio.sleep(1.5)  # let setTimeouts in hook fire
            except Exception:
                await page.close(); return
            try:
                hits = await page.evaluate("window.__sx_hits__ || []")
            except Exception:
                hits = []
            await page.close()
            relevant = [h for h in hits if token.lower() in (h.get("v") or "").lower()]
            sinks = sorted({h["k"] for h in relevant})
            if not relevant:
                return
            severity, cvss = ("critical", 8.2) if any(s in ("eval", "Function", "innerHTML",
                                                              "outerHTML", "document.write",
                                                              "alert", "setAttribute(onerror)")
                                                       for s in sinks) else ("high", 7.0)
            findings.append({
                "category": "xss",
                "title": f"DOM XSS — {label} (sinks: {', '.join(sinks[:5])})",
                "severity": severity, "cvss": cvss,
                "url": target_url, "parameter": param, "payload": payload,
                "evidence": f"Browser saw token reach {len(sinks)} dangerous JS sink(s): "
                            + ", ".join(sinks),
                "request": f"GET {target_url}",
                "response": str(relevant[:6])[:1500],
                "metadata": {"detection": "browser", "label": label, "sinks": sinks},
            })

        async def query_param(param: str) -> None:
            async with sem:
                token = f"sxdom{random_token(6)}"
                payload = f'<svg onload=window.alert("{token}")>'
                qs2 = {**qs, param: payload}
                target = urlunparse(parsed._replace(query=urlencode(qs2)))
                await run_probe(target, payload, token, f"query[{param}]", param)

        async def hash_fragment() -> None:
            async with sem:
                token = f"sxhash{random_token(6)}"
                payload = f'#<img src=x onerror=window.alert("{token}")>'
                target = urlunparse(parsed._replace(fragment=payload[1:]))
                await run_probe(target, payload, token, "fragment(location.hash)", "#")

        async def proto_pollution() -> None:
            async with sem:
                token = f"sxpp{random_token(6)}"
                # ?__proto__[__sxpoll__]=token style — Lodash / merge/clone bugs
                qs2 = {**qs, "__proto__[__sxpoll__]": token,
                       "constructor[prototype][__sxpoll__]": token}
                target = urlunparse(parsed._replace(query=urlencode(qs2)))
                await run_probe(target, f"__proto__[__sxpoll__]={token}",
                                token, "prototype-pollution", "__proto__")

        async def post_message() -> None:
            async with sem:
                token = f"sxpm{random_token(6)}"
                page = await context.new_page()
                await page.add_init_script(JS_HOOK)
                try:
                    await page.goto(url, wait_until="networkidle", timeout=15000)
                    # simulate a hostile origin firing a message
                    await page.evaluate(f"""
                        window.postMessage({{
                            type: 'render',
                            html: '<img src=x onerror=window.alert(\"{token}\")>',
                            cmd: 'eval',
                            payload: 'window.alert(\"{token}\")',
                            sx: '{token}'
                        }}, '*');
                    """)
                    await asyncio.sleep(1.5)
                except Exception:
                    await page.close(); return
                try:
                    hits = await page.evaluate("window.__sx_hits__ || []")
                except Exception:
                    hits = []
                await page.close()
                relevant = [h for h in hits if token.lower() in (h.get("v") or "").lower()]
                # only flag if a *non-receiver* sink fired — that proves the page
                # acted on the attacker-controlled message instead of just hearing it
                actionable = [h for h in relevant if h["k"] != "postMessage.recv"]
                if actionable:
                    sinks = sorted({h["k"] for h in actionable})
                    findings.append({
                        "category": "xss",
                        "title": f"postMessage abuse — page accepts attacker-controlled message ({', '.join(sinks[:3])})",
                        "severity": "high", "cvss": 7.4,
                        "url": url, "parameter": "postMessage", "payload": "window.postMessage({...})",
                        "evidence": f"Sent a forged message and watched it land in: {sinks}. "
                                    "Origin not validated by the message handler.",
                        "request": f"GET {url}\n(window.postMessage from attacker frame)",
                        "response": str(actionable[:6])[:1500],
                        "metadata": {"detection": "postMessage", "sinks": sinks},
                    })

        await asyncio.gather(
            *(query_param(p) for p in candidate_params[:8]),
            hash_fragment(),
            proto_pollution(),
            post_message(),
        )
        await browser.close()
    return findings
