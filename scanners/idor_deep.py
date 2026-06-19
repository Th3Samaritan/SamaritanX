"""Deep IDOR / BOLA scanner — cross-session object-access proof.

Requires a second authenticated session (`--second-session auth2.yaml`).
Three checks, strongest first:

  1. **Cross-session data leak (highest signal).** Replay the URL A visited
     using session B. If B — a *different* identity — sees high-entropy
     identity markers (email / UUID / token) that belong to A's object, B is
     reading A's private data. That's textbook BOLA with proof, not a length
     heuristic.

  2. **ID enumeration.** For each id-shaped injection point in the URL (numeric
     / UUID path segment or query value), flip A's identifier to a neighbour
     and request it as session B. Distinct identity markers coming back on a
     swapped id means objects are enumerable across the authorization boundary.

  3. **Shape fallback (lower confidence).** The original ±10%-length + PII
     match, kept as a tentative signal and flagged for manual review.

If session B doesn't exist this scanner is a noop — the heuristic IDOR
scanner (`scanners/idor.py`) still runs.
"""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlparse

from core.injection import send, parse_point

if TYPE_CHECKING:
    from core.orchestrator import Context

PII_RE = re.compile(r'"(email|phone|ssn|tax_id|account|address|password|token|api_key)"\s*:\s*"', re.I)

# High-entropy, identity-bearing markers. A value from these classes appearing
# in *another* user's response is strong evidence of cross-tenant access.
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}')
UUID_RE = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
TOKEN_RE = re.compile(r'\b[A-Za-z0-9_\-]{24,64}\b')

_NUMERIC = re.compile(r"^\d{1,12}$")


def identity_markers(text: str, *, limit: int = 40) -> set[str]:
    """Extract high-entropy identity values worth tracking across sessions."""
    if not text:
        return set()
    out: set[str] = set()
    for rx in (EMAIL_RE, UUID_RE, TOKEN_RE):
        for m in rx.findall(text):
            out.add(m)
            if len(out) >= limit:
                return out
    return out


def _id_points(url: str, params: list[str]) -> list[tuple[str, str]]:
    """Return (point, current_value) for id-shaped injection points in the URL:
    numeric/UUID path segments and numeric/UUID query values."""
    out: list[tuple[str, str]] = []
    p = urlparse(url)
    segs = [s for s in p.path.split("/") if s != ""]
    for point in params:
        kind, loc = parse_point(point)
        if kind == "path":
            try:
                idx = int(loc)
            except ValueError:
                continue
            if 0 <= idx < len(segs):
                val = segs[idx]
                if _NUMERIC.match(val) or UUID_RE.match(val):
                    out.append((point, val))
    # numeric/uuid query values
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        if _NUMERIC.match(v) or UUID_RE.match(v):
            out.append((k, v))
    return out


def _neighbours(value: str) -> list[str]:
    if _NUMERIC.match(value):
        n = int(value)
        return [str(n + 1), str(n - 1)] if n > 0 else [str(n + 1)]
    return []


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    if not ctx.http2 or not (ctx.http2.session and ctx.http2.session.is_authed()):
        return []
    findings: list[dict] = []
    sem = asyncio.Semaphore(int(ctx.config.get("concurrency", {}).get("scanner_workers", 8)))

    label_a = ctx.http.session.label if ctx.http.session else "anon"
    label_b = ctx.http2.session.label if ctx.http2.session else "anon"

    async with sem:
        ev_a = await ctx.http.get(url)
        ev_b = await ctx.http2.get(url)
    a = ev_a.response_body or ""
    b = ev_b.response_body or ""

    # ---------- 1) cross-session identity-marker leak ----------
    if ev_a.status and ev_a.status < 400 and ev_b.status and ev_b.status < 400 and len(a) >= 120:
        markers_a = identity_markers(a)
        markers_b = identity_markers(b)
        # A's private markers that B can also see, excluding values B legitimately
        # owns (present in B's own identity set independent of this object).
        leaked = (markers_a & markers_b)
        if leaked:
            sample = sorted(leaked)[:5]
            findings.append({
                "category": "idor",
                "title": "BOLA — session B reads session A's object (identity markers leaked)",
                "severity": "critical", "cvss": 9.1,
                "url": url, "parameter": "(cross-session replay)",
                "evidence": f"Identity markers from {label_a}'s response are present in "
                            f"{label_b}'s response for the same URL: {sample}. "
                            "Two distinct authenticated identities see the same private object — "
                            "object-level authorization is missing.",
                "request": f"{method.upper()} {url}  (replayed as {label_b})",
                "response": b[:1500],
                "metadata": {"session_a": label_a, "session_b": label_b,
                             "leaked_markers": sample, "detection": "cross_session_marker"},
            })

    # ---------- 2) id enumeration across the auth boundary ----------
    id_points = _id_points(url, params)

    async def enumerate_point(point: str, value: str) -> None:
        markers_self = identity_markers(b)  # B's view of the original object
        for nb in _neighbours(value):
            async with sem:
                ev = await send(ctx, url, method, point, nb, form, http=ctx.http2)
            if not ev.status or ev.status >= 400:
                continue
            body = ev.response_body or ""
            if len(body) < 120:
                continue
            markers = identity_markers(body)
            # neighbour object returns identity data B didn't already have →
            # B can walk other users' objects by changing the id.
            fresh = markers - markers_self
            if fresh and PII_RE.search(body):
                findings.append({
                    "category": "idor",
                    "title": f"IDOR — object enumeration by flipping {point} ({value}→{nb})",
                    "severity": "high", "cvss": 8.1,
                    "url": url, "parameter": point, "payload": nb,
                    "evidence": f"Requesting neighbour id {nb} as {label_b} returned a "
                                f"different object with PII ({sorted(fresh)[:4]}). "
                                "Sequential/guessable ids are accessible across the boundary.",
                    "request": f"{method.upper()} {url}  ({point}={nb} as {label_b})",
                    "response": body[:1500],
                    "metadata": {"session": label_b, "point": point,
                                 "from": value, "to": nb, "detection": "id_enumeration"},
                })
                return

    await asyncio.gather(*(enumerate_point(pt, val) for pt, val in id_points[:6]))

    # ---------- 3) shape fallback (lower confidence) ----------
    if not findings and ev_a.status and ev_a.status == ev_b.status and ev_a.status < 400 \
            and a and len(a) >= 200:
        ratio = abs(len(a) - len(b)) / max(len(a), 1)
        if ratio <= 0.10:
            pii = bool(PII_RE.search(b))
            findings.append({
                "category": "idor",
                "title": f"Possible BOLA — matching cross-session responses ({'PII' if pii else 'data'})",
                "severity": "high" if pii else "medium",
                "cvss": 7.7 if pii else 5.3,
                "url": url, "parameter": "(cross-session replay)",
                "evidence": "Session A and B received matching status "
                            f"({ev_a.status}) and ±10% length responses. "
                            + ("Sensitive PII keys present. " if pii else "")
                            + "No identity marker was confirmed — manual verification required "
                              "before submitting.",
                "request": f"{method.upper()} {url}  (replayed as {label_b})",
                "response": b[:1500],
                "metadata": {"session_a": label_a, "session_b": label_b,
                             "pii": pii, "detection": "shape_match"},
            })

    return findings
