"""Hidden parameter discovery (Arjun-style).

Specs and JS reveal *documented* params; the bugs live in the *undocumented*
ones — `debug=true`, `admin=1`, `is_internal`, `redirect=`. This probes a
wordlist of candidate names and detects the ones the server actually processes,
by either reflecting the injected marker or changing the response shape vs a
baseline. Confirmed params are reported and re-queued as `scan` tasks so the
injection scanners (SQLi/XSS/SSRF/redirect/…) test them.

Batched with binary-split isolation to keep request volume sane.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse, parse_qsl

from core.utils import merge_query, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

_BATCH = 20
_MAX_PARAMS = 128
_wordlist_cache: list[str] | None = None


def _load_words(ctx) -> list[str]:
    global _wordlist_cache
    if _wordlist_cache is not None:
        return _wordlist_cache
    path = Path(ctx.payloads.payload_dir) / "params.txt"
    words: list[str] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                words.append(line)
    _wordlist_cache = words[:_MAX_PARAMS]
    return _wordlist_cache


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    # only mine GET endpoints; skip if the URL already exposes many params
    if method.upper() != "GET":
        return []
    existing = {k for k, _ in parse_qsl(urlparse(url).query)}
    words = [w for w in _load_words(ctx) if w not in existing]
    if not words:
        return []

    base = await ctx.http.get(url)
    if base.status == 0:
        return []
    base_len = len(base.response_body or "")
    base_status = base.status
    threshold = max(60, int(0.05 * max(base_len, 1)))

    discovered: list[tuple[str, str]] = []  # (param, why)

    async def changed(batch: list[str]) -> tuple[bool, str]:
        marker = random_token(8)
        ev = await ctx.http.get(merge_query(url, {p: marker for p in batch}))
        body = ev.response_body or ""
        if marker in body:
            return True, "reflected"
        if ev.status != base_status:
            return True, f"status {base_status}->{ev.status}"
        if abs(len(body) - base_len) > threshold:
            return True, f"length delta {abs(len(body) - base_len)}B"
        return False, ""

    async def bisect(batch: list[str], depth: int = 0) -> None:
        if not batch or depth > 6:
            return
        hit, why = await changed(batch)
        if not hit:
            return
        if len(batch) == 1:
            discovered.append((batch[0], why))
            return
        mid = len(batch) // 2
        await bisect(batch[:mid], depth + 1)
        await bisect(batch[mid:], depth + 1)

    for i in range(0, len(words), _BATCH):
        await bisect(words[i:i + _BATCH])

    findings: list[dict] = []
    if discovered:
        names = [p for p, _ in discovered]
        findings.append({
            "category": "param_discovery",
            "title": f"{len(names)} hidden parameter(s) accepted by {urlparse(url).path}",
            "severity": "info", "cvss": 0.0,
            "url": url, "parameter": ", ".join(names[:12]),
            "evidence": "Server processes undocumented parameters: "
                        + ", ".join(f"{p} ({why})" for p, why in discovered[:12]),
            "metadata": {"params": names, "detection": "param_miner"},
        })
        # re-queue the discovered params so injection scanners test them
        try:
            await ctx.queue.put(
                "scan", {"url": url, "method": "GET", "params": names},
                target=ctx.target_slug, priority=3, producer="param_miner")
        except Exception:
            pass
    return findings
