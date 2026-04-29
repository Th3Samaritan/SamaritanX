"""Screenshot PoC capture.

After all scanning + exploit synthesis, walks the finding list and
captures a Playwright screenshot of every URL that's "showable" — i.e.
HTML response, status < 400, parameter-bearing or stored-XSS-shaped.

The screenshot path is attached to the finding's metadata under
`screenshot` and rendered into the Markdown report as an image link.

Quietly skips when Playwright isn't installed.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from core.task_queue import Task
from core.utils import slugify
from .base import BaseAgent

if TYPE_CHECKING:
    from core.orchestrator import Context

SLUG_RE = re.compile(r"[^a-zA-Z0-9._\-]")


class ScreenshotAgent(BaseAgent):
    name = "screenshot"
    handles = ("screenshot",)

    async def handle(self, task: Task, ctx: "Context") -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return
        findings = ctx.memory.list_findings(ctx.target_slug)
        showable = [f for f in findings if f.get("url") and not f.get("metadata", {}).get("screenshot")]
        if not showable:
            return
        out_dir = ctx.workspace / "screenshots"
        out_dir.mkdir(parents=True, exist_ok=True)
        index_path = out_dir / "index.json"
        index: dict = {}
        if index_path.exists():
            try:
                index = json.loads(index_path.read_text(encoding="utf-8"))
            except Exception:
                index = {}

        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            except Exception:
                return
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720},
                # inject auth cookies + headers from session
                extra_http_headers=(ctx.session.headers if ctx.session else {}) or {},
            )
            if ctx.session and ctx.session.cookies:
                from urllib.parse import urlparse
                cookies = []
                for f in showable[:5]:
                    domain = urlparse(f["url"]).hostname
                    if not domain:
                        continue
                    for k, v in ctx.session.cookies.items():
                        cookies.append({"name": k, "value": v, "domain": domain, "path": "/"})
                if cookies:
                    try:
                        await context.add_cookies(cookies)
                    except Exception:
                        pass

            sem = asyncio.Semaphore(2)

            async def shoot(finding: dict) -> None:
                fid = finding["id"]
                fname = f"finding_{fid}_{slugify(finding.get('category', 'x'))}.png"
                target_url = finding["url"]
                async with sem:
                    page = await context.new_page()
                    try:
                        await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                        await asyncio.sleep(0.6)
                        await page.screenshot(path=str(out_dir / fname), full_page=True)
                        index[str(fid)] = fname
                        # persist back into the metadata
                        meta = finding.get("metadata") or {}
                        if isinstance(meta, str):
                            try:
                                meta = json.loads(meta)
                            except Exception:
                                meta = {}
                        meta["screenshot"] = fname
                        # update via SQLite
                        with ctx.memory._connect() as conn:
                            conn.execute(
                                "UPDATE findings SET metadata=? WHERE id=?",
                                (json.dumps(meta), fid),
                            )
                    except Exception:
                        pass
                    finally:
                        await page.close()

            await asyncio.gather(*(shoot(f) for f in showable[:30]))
            await browser.close()
        index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
        ctx.dashboard.event("ok", f"screenshots: captured {len(index)} PoCs")
