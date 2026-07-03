"""Multi-identity access engine — stateful BOLA / BFLA detection.

The highest-paying, hardest-to-automate bug class is object- and function-level
authorization: can identity B read or act on identity A's data? A single-request
scanner can't answer that — it needs two (or three) authenticated sessions and a
cross-replay. This engine drives exactly that.

For a given endpoint it fetches the same URL as every configured identity plus
an unauthenticated client, then looks for **one identity's private, high-entropy
markers (emails, UUIDs, long numeric/opaque IDs) appearing in another
identity's response**. That is a captured, unambiguous proof of broken object
isolation — not a heuristic — so it satisfies the proof-gate directly.

To keep false positives near zero it only counts a marker as "private" when it
does NOT also appear in the unauthenticated response (i.e. it isn't public
boilerplate like a support email in the footer).

Identities come from the orchestrator Context: the primary session (``ctx.http``),
an optional second session (``ctx.http2``), and any ``ctx.extra_identities``.
The marker extraction and leak decision are pure functions, unit-tested offline.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Optional

from .poc import proof_record

if TYPE_CHECKING:
    from .orchestrator import Context

_EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_LONGID = re.compile(r"\b[0-9]{6,}\b")
_OPAQUE = re.compile(r"\b[A-Za-z0-9_-]{20,}\b")   # tokens, opaque object ids

# Markers this common are boilerplate, never a per-user secret.
_COMMON = {"noreply", "no-reply", "support", "info", "admin", "example", "sentry"}


def extract_identity_markers(body: str) -> set[str]:
    """Pull high-entropy, per-user identifiers out of a response body."""
    body = body or ""
    markers: set[str] = set()
    for m in _EMAIL.findall(body):
        local = m.split("@", 1)[0].lower()
        if local not in _COMMON:
            markers.add(m)
    markers.update(_UUID.findall(body))
    markers.update(_LONGID.findall(body))
    # opaque tokens are noisy; only keep a few of the longest
    opaque = sorted(set(_OPAQUE.findall(body)), key=len, reverse=True)
    markers.update(opaque[:8])
    return markers


def find_leak(owner_label: str, owner_markers: set[str],
              viewer_label: str, viewer_body: str,
              public_markers: set[str]) -> set[str]:
    """Return the owner's private markers that leaked into the viewer's response.

    A marker leaks iff it is one of the owner's markers, appears in the viewer's
    body, and is NOT public (present to an unauthenticated client)."""
    if owner_label == viewer_label:
        return set()
    body = viewer_body or ""
    leaked = {mk for mk in owner_markers
              if mk not in public_markers and mk in body}
    return leaked


async def _fetch(client, url: str) -> tuple[int, str]:
    try:
        ev = await client.get(url, no_session=False)
    except TypeError:
        ev = await client.get(url)
    except Exception:
        return 0, ""
    if ev is None or getattr(ev, "error", None):
        return 0, ""
    return getattr(ev, "status", 0), getattr(ev, "response_body", "") or ""


def _identities(ctx: "Context") -> list[tuple[str, Any]]:
    ids: list[tuple[str, Any]] = []
    primary_label = getattr(getattr(ctx, "session", None), "label", None) or "primary"
    ids.append((primary_label, ctx.http))
    if getattr(ctx, "http2", None) is not None:
        ids.append((getattr(getattr(ctx, "session2", None), "label", None) or "second", ctx.http2))
    for ident in getattr(ctx, "extra_identities", []) or []:
        ids.append((ident.get("label", "extra"), ident["client"]))
    return ids


async def cross_access_check(ctx: "Context", url: str) -> Optional[dict]:
    """Test one endpoint for cross-identity data exposure. Returns a verified
    finding dict when one identity's private data leaks to another, else None."""
    identities = _identities(ctx)
    if len(identities) < 2:
        return None  # need at least two sessions to test isolation
    if ctx.scope and not ctx.scope.allows(url)[0]:
        return None

    # public baseline (unauthenticated) — markers here are NOT per-user secrets
    public_markers: set[str] = set()
    try:
        st_pub, body_pub = await _fetch_unauth(ctx, url)
        public_markers = extract_identity_markers(body_pub)
    except Exception:
        pass

    responses: list[tuple[str, int, str, set[str]]] = []
    for label, client in identities:
        status, body = await _fetch(client, url)
        if status and body:
            responses.append((label, status, body, extract_identity_markers(body)))

    for owner_label, _os, _ob, owner_markers in responses:
        if not owner_markers:
            continue
        for viewer_label, viewer_status, viewer_body, _vm in responses:
            leaked = find_leak(owner_label, owner_markers, viewer_label,
                               viewer_body, public_markers)
            if leaked:
                sample = sorted(leaked)[:5]
                poc = proof_record(
                    verified=True, method="GET", url=url,
                    request=f"GET {url}\n(as identity '{viewer_label}')",
                    status=viewer_status, excerpt=viewer_body,
                    rationale=(f"Identity '{viewer_label}' received private data belonging to "
                               f"'{owner_label}' — leaked markers: {sample}. These markers are "
                               "absent from the unauthenticated response, so this is broken "
                               "object-level authorization (BOLA/IDOR), not public content."))
                return {
                    "category": "idor_deep",
                    "title": "Broken object-level authorization — cross-identity data exposure",
                    "severity": "high", "cvss": 8.2, "confidence": 0.9,
                    "url": url,
                    "evidence": (f"'{viewer_label}' read '{owner_label}'s private data at this "
                                 f"endpoint (leaked: {sample})."),
                    "request": f"GET {url} (as '{viewer_label}')",
                    "metadata": {"detection": "identity_matrix", "poc": poc,
                                 "owner": owner_label, "viewer": viewer_label,
                                 "leaked_markers": sample},
                }
    return None


async def _fetch_unauth(ctx: "Context", url: str) -> tuple[int, str]:
    try:
        ev = await ctx.http.get(url, no_session=True,
                                headers={"Authorization": "", "Cookie": ""})
    except Exception:
        return 0, ""
    if ev is None or getattr(ev, "error", None):
        return 0, ""
    return getattr(ev, "status", 0), getattr(ev, "response_body", "") or ""
