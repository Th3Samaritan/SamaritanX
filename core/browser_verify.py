"""Headless-browser proof channel for client-side bugs.

String reflection does not prove XSS — the payload might land in a context where
it never executes, or be neutralised by CSP. The only proof a triager (and the
proof-gate) should accept is *the sink actually firing in a real browser*. This
module loads the payload URL in Chromium, watches for genuine execution, and
captures a screenshot + console trail as the artifact.

Execution is detected three ways, any of which is conclusive:
  * a ``dialog`` event (alert/confirm/prompt) whose text carries our marker,
  * a console message carrying our marker (payloads use ``console.log(marker)``),
  * a DOM/global flag our injected hook sets when the sink runs.

If Playwright isn't installed the module degrades gracefully (returns ``None``),
so the finding simply stays an unproven candidate rather than crashing the run.

The pure decision function ``execution_proven()`` is separated out so it can be
unit-tested without a browser.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from .browser_pool import browser_slot
from .poc import proof_record

# Injected before any page script: neutralises nothing, just records whether our
# marker-bearing sink fired, and mirrors dialogs to a flag we can read back.
_HOOK = """
(() => {
  window.__sx_fired__ = window.__sx_fired__ || [];
  const rec = (how, val) => { try { window.__sx_fired__.push(how + ':' + val); } catch(e){} };
  for (const k of ['alert','confirm','prompt']) {
    const orig = window[k];
    window[k] = function(v){ rec(k, v); return orig ? undefined : undefined; };
  }
  const _log = console.log;
  console.log = function(){ try{ rec('console', Array.from(arguments).join(' ')); }catch(e){}
                            return _log.apply(console, arguments); };
})();
"""


def available() -> bool:
    try:
        import playwright.async_api  # noqa: F401
        return True
    except Exception:
        return False


def execution_proven(fired: list[str], dialogs: list[str], console: list[str],
                     marker: str) -> bool:
    """True iff the marker shows up in any real execution channel."""
    marker = (marker or "").strip()
    if not marker:
        return False
    for bucket in (fired, dialogs, console):
        for entry in bucket or []:
            if marker in (entry or ""):
                return True
    return False


async def verify_xss(cfg: dict[str, Any], url: str, *, marker: str,
                     workspace=None, timeout_ms: int = 15000) -> Optional[dict]:
    """Load ``url`` in Chromium and return a verified proof_record iff the XSS
    sink fires (marker observed in a dialog / console / hook). Else None.

    ``url`` should already contain the payload. Payloads that call
    ``console.log('<marker>')`` or ``alert('<marker>')`` are detected."""
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return None

    dialogs: list[str] = []
    console: list[str] = []
    fired: list[str] = []
    shot_path = None

    try:
        async with browser_slot(cfg), async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True,
                                               args=["--no-sandbox", "--disable-dev-shm-usage"])
            page = await browser.new_page()
            await page.add_init_script(_HOOK)

            def _on_dialog(d):
                try:
                    dialogs.append(d.message or "")
                except Exception:
                    pass
                # dismiss so navigation isn't blocked
                import asyncio as _a
                _a.ensure_future(d.dismiss())

            page.on("dialog", _on_dialog)
            page.on("console", lambda m: console.append(m.text if hasattr(m, "text") else str(m)))

            try:
                await page.goto(url, wait_until="load", timeout=timeout_ms)
                await page.wait_for_timeout(800)  # let deferred sinks run
                try:
                    fired = await page.evaluate("window.__sx_fired__ || []")
                except Exception:
                    fired = []
            except Exception:
                await browser.close()
                return None

            proven = execution_proven(fired, dialogs, console, marker)
            if proven and workspace is not None:
                try:
                    shots = workspace / "screenshots"
                    shots.mkdir(parents=True, exist_ok=True)
                    shot_path = str(shots / f"xss_{marker}_{int(time.time())}.png")
                    await page.screenshot(path=shot_path, full_page=False)
                except Exception:
                    shot_path = None
            await browser.close()
    except Exception:
        return None

    if not execution_proven(fired, dialogs, console, marker):
        return None

    channel = ("dialog" if any(marker in d for d in dialogs)
               else "console" if any(marker in c for c in console)
               else "hook")
    rec = proof_record(
        verified=True, method="BROWSER", url=url,
        request=f"GET {url}   (rendered in headless Chromium)",
        excerpt=f"marker {marker!r} observed via {channel}; "
                f"dialogs={dialogs[:3]} console={console[:3]}",
        rationale=(f"The payload executed in a real browser — the marker {marker!r} fired "
                   f"through the {channel} channel. This is confirmed script execution, not "
                   "mere reflection."),
    )
    if shot_path:
        rec["screenshot"] = shot_path
    return rec
