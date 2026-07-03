"""Finding correlation / de-duplication.

A single root cause often surfaces as dozens of near-identical findings — the
old run reported the same CL.TE smuggling "bug" 15 times, once per crawled URL
on the same host. That inflates the report, buries the real signal, and reads as
noise to a triager.

This collapses findings that share a root cause into one representative finding
with an ``affected`` list, so the report shows *N distinct issues*, not *N URLs*.

Grouping key = (registrable domain, category, root-cause signature). The
root-cause signature is category-aware: for host-level bugs (smuggling, cors,
takeover) it is just the host+class, so every affected path folds together; for
parameter-level bugs (sqli, xss, idor) it is the (path-template, parameter),
so genuinely distinct injection points stay separate while the same parameter
across ?id=1 / ?id=2 folds together.

Pure and deterministic — unit-tested offline.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from .scope import registrable_domain

# Categories where the bug lives at the host/service level: one finding per host,
# every path is just another affected endpoint.
_HOST_LEVEL = {
    "smuggling", "h2_smuggling", "cors", "cache_poisoning", "web_cache_deception",
    "takeover", "subdomain_takeover", "crlf", "version_bypass",
}

# Categories where the bug lives at a specific parameter/injection point.
_PARAM_LEVEL = {
    "sqli", "nosqli", "xss", "stored_xss", "dom_xss", "ssrf", "rce", "ssti",
    "open_redirect", "idor", "idor_deep", "api", "xxe", "prototype_pollution",
}

_NUM = re.compile(r"\d+")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_HEXID = re.compile(r"\b[0-9a-f]{16,}\b", re.I)


def _path_template(path: str) -> str:
    """Normalise a path so /users/1/x and /users/2/x share a template."""
    p = _UUID.sub("{id}", path or "/")
    p = _HEXID.sub("{id}", p)
    p = _NUM.sub("{n}", p)
    return p or "/"


def root_cause_key(finding: dict) -> tuple:
    cat = (finding.get("category") or "").lower()
    url = finding.get("url") or ""
    host = (urlparse(url if "://" in url else f"http://{url}").hostname or "").lower()
    reg = registrable_domain(host)
    if cat in _HOST_LEVEL:
        # kind (CL.TE vs TE.CL etc.) distinguishes distinct host-level bugs
        kind = (finding.get("metadata") or {}).get("kind") or ""
        return (reg, cat, kind)
    if cat in _PARAM_LEVEL:
        tmpl = _path_template(urlparse(url).path)
        param = finding.get("parameter") or ""
        return (reg, cat, tmpl, param)
    # default: dedup exact (host, category, title)
    return (reg, cat, (finding.get("title") or "").lower())


def _prefer(a: dict, b: dict) -> dict:
    """Pick the better representative of two duplicate findings.

    Prefer a verified one, then higher confidence, then higher CVSS."""
    from .proof_gate import is_verified
    av, bv = is_verified(a), is_verified(b)
    if av != bv:
        return a if av else b
    ac, bc = float(a.get("confidence", 0) or 0), float(b.get("confidence", 0) or 0)
    if ac != bc:
        return a if ac >= bc else b
    return a if float(a.get("cvss", 0) or 0) >= float(b.get("cvss", 0) or 0) else b


def deduplicate(findings: list[dict]) -> list[dict]:
    """Collapse duplicate findings by root cause.

    Returns one representative per root cause, each carrying
    ``metadata.affected`` = the list of URLs that shared the cause and
    ``metadata.duplicate_count``. Order of first appearance is preserved.
    """
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []
    members: dict[tuple, list[str]] = {}
    for f in findings:
        key = root_cause_key(f)
        url = f.get("url") or ""
        if key not in groups:
            groups[key] = f
            order.append(key)
            members[key] = [url] if url else []
        else:
            groups[key] = _prefer(groups[key], f)
            if url and url not in members[key]:
                members[key].append(url)

    out: list[dict] = []
    for key in order:
        rep = groups[key]
        affected = members[key]
        if len(affected) > 1:
            meta = rep.setdefault("metadata", {})
            if isinstance(meta, dict):
                meta["affected"] = affected
                meta["duplicate_count"] = len(affected)
        out.append(rep)
    return out
