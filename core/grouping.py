"""Conservative cross-tool finding grouping (plan §11.11).

Grouping never deletes an observation: every record stays independently stored
and a group only *relates* findings to a canonical review item. The
fingerprint is deliberately conservative — family, origin, method, path, input
location, identity boundary and proof boundary must all agree before two
records are treated as the same issue. Parameter names and positions are never
normalised away, and ambiguous similarities are offered as suggestions for a
human to accept or reject, never merged automatically.

Persistence (manual groups) lives in :mod:`core.memory`; grouping here is pure
and deterministic so it can be unit-tested offline.
"""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

from .correlate import _path_template
from .proof_gate import poc_status

# dimensions that must match for an *exact* group; anything else is ambiguous
_DIMENSIONS = ("family", "origin", "method", "path", "parameter", "identity", "proof")

# the dimensions that define a "related" (near) cluster — everything else is
# surfaced as ambiguity for review
_NEAR = ("family", "origin", "path")


def _origin(url: str) -> str:
    text = url or ""
    parts = urlsplit(text if "://" in text else f"http://{text}")
    host = (parts.hostname or "").lower()
    scheme = (parts.scheme or "http").lower()
    default = 80 if scheme == "http" else 443
    port = parts.port
    suffix = f":{port}" if port and port != default else ""
    return f"{scheme}://{host}{suffix}"


def _identity(finding: dict) -> str:
    meta = finding.get("metadata") or {}
    return str(meta.get("identity") or meta.get("session")
               or meta.get("session_a") or "anonymous")


def _proof(finding: dict) -> str:
    return poc_status(finding)[0]


def fingerprint(finding: dict) -> dict:
    """Conservative identity of a finding across tools and runs."""
    meta = finding.get("metadata") or {}
    return {
        "family": (finding.get("category") or "unknown").lower(),
        "origin": _origin(finding.get("url") or ""),
        "method": str(meta.get("method") or finding.get("method") or "GET").upper(),
        "path": _path_template(urlsplit(finding.get("url") or "").path),
        "parameter": str(finding.get("parameter") or ""),
        "identity": _identity(finding),
        "proof": _proof(finding),
    }


def group_key(finding: dict) -> tuple:
    fp = fingerprint(finding)
    return tuple((dim, fp[dim]) for dim in _DIMENSIONS)


def _near_key(finding: dict) -> tuple:
    fp = fingerprint(finding)
    return tuple((dim, fp[dim]) for dim in _NEAR)


def _group_id(key) -> str:
    material = json.dumps(list(key), sort_keys=True, default=str)
    return "g" + hashlib.sha1(material.encode("utf-8")).hexdigest()[:12]


def _ids(findings) -> list:
    return sorted(f["id"] for f in findings if f.get("id") is not None)


def _ambiguity(members: list[dict]) -> list[str]:
    base = fingerprint(members[0])
    dims: set[str] = set()
    for other in members[1:]:
        fp = fingerprint(other)
        dims.update(dim for dim in _DIMENSIONS if fp[dim] != base[dim])
    return [d for d in _DIMENSIONS if d in dims]


def suggest(findings: list[dict]) -> list[dict]:
    """Exact groups plus ambiguous near-clusters — suggestions, not merges.

    ``confidence`` is ``exact`` when every dimension agrees, ``suggested`` when
    findings share family/origin/path but differ in method, input location,
    identity or proof boundary (``ambiguous_on`` lists which).
    """
    exact: dict[tuple, list[dict]] = {}
    near: dict[tuple, list[dict]] = {}
    for finding in findings:
        exact.setdefault(group_key(finding), []).append(finding)
        near.setdefault(_near_key(finding), []).append(finding)

    out: list[dict] = []
    for key, members in exact.items():
        if len(members) < 2:
            continue
        out.append({
            "group_id": _group_id(key),
            "confidence": "exact",
            "fingerprint": dict(key),
            "ambiguous_on": [],
            "finding_ids": _ids(members),
        })
    for key, members in near.items():
        if len(members) < 2:
            continue
        if len({group_key(m) for m in members}) < 2:
            continue  # a single exact group — already reported as exact
        out.append({
            "group_id": _group_id(key),
            "confidence": "suggested",
            "fingerprint": dict(key),
            "ambiguous_on": _ambiguity(members),
            "finding_ids": _ids(members),
        })
    out.sort(key=lambda g: (g["confidence"] != "exact", g["group_id"]))
    return out


def annotate(findings: list[dict], groups: list[dict]) -> list[dict]:
    """Return copies carrying ``metadata.groups`` — no record is removed."""
    lookup: dict = {}
    for group in groups:
        ids = group.get("finding_ids") or []
        canonical = ids[0] if ids else None
        for fid in ids:
            lookup.setdefault(fid, []).append({
                "group_id": group["group_id"],
                "confidence": group["confidence"],
                "ambiguous_on": group.get("ambiguous_on", []),
                "role": "canonical" if fid == canonical else "member",
            })
    out: list[dict] = []
    for finding in findings:
        copy = dict(finding)
        meta = dict(copy.get("metadata") or {})
        memberships = lookup.get(copy.get("id"))
        if memberships:
            meta["groups"] = memberships
        copy["metadata"] = meta
        out.append(copy)
    return out
