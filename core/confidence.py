"""Per-finding confidence scoring.

The scanners are breadth-first: some fire on hard proof (an OOB callback, a
reflected marker, a DBMS error string, a forged-JWT 200 where anon got 401),
others on soft heuristics (an IDOR guessed from response-size similarity, an
"admin page returned 200", a race condition inferred from two 2xx responses).

Submitting the soft ones unverified is how hunters get signal-banned from
programs. This module assigns every finding a confidence score in [0, 1] and a
label, so the report can separate "high-confidence, ready to verify-and-submit"
from "candidates that need a human before they go anywhere".

`assign()` is intentionally conservative: when in doubt it scores *lower*, so a
finding has to earn its confidence. Scanners may set `finding["confidence"]`
explicitly to override.
"""
from __future__ import annotations

from typing import Any

# Detection signatures that constitute hard, low-false-positive proof.
_STRONG_DETECTIONS = {
    "marker",          # reflected command/echo marker (RCE)
    "oob", "oob-header",  # interactsh callback (blind SSRF/RCE/XXE)
    "ssti-product",    # template engine evaluated 7*7 -> 49
}

# Categories whose *default* detection is strong proof.
_STRONG_CATEGORIES = {
    "takeover",        # CNAME fingerprint match + live body fingerprint
}

# Categories that are heuristic by nature — score low unless proof says otherwise.
_HEURISTIC_CATEGORIES = {
    "idor": 0.45,          # response-size similarity
    "logic": 0.40,         # pricing tamper by success-word match
    "race_condition": 0.40,
    "deserialization": 0.40,  # format match only, no exploitation
    "csrf": 0.45,          # missing-token heuristic
    "broken_auth": 0.50,   # admin-anon / version sibling (mixed)
}

_LABELS = (
    (0.85, "confirmed"),
    (0.60, "firm"),
    (0.40, "tentative"),
    (0.0,  "speculative"),
)


def label(score: float) -> str:
    for threshold, name in _LABELS:
        if score >= threshold:
            return name
    return "speculative"


def assign(finding: dict[str, Any]) -> tuple[float, str]:
    """Return (score, reason). Higher = more likely a true positive."""
    if isinstance(finding.get("confidence"), (int, float)):
        s = max(0.0, min(1.0, float(finding["confidence"])))
        return s, "scanner-provided"

    cat = (finding.get("category") or "").lower()
    meta = finding.get("metadata") or {}
    detection = str(meta.get("detection") or "").lower()
    title = (finding.get("title") or "").lower()

    # 1) hardest proof: OOB callbacks / reflected markers / template eval
    if detection in _STRONG_DETECTIONS:
        return 0.95, f"hard proof: {detection}"

    # 2) live-validated secret (the validator confirmed it against the provider)
    if meta.get("validator_valid") is True or "confirmed live" in title:
        return 0.97, "provider-validated credential"
    if meta.get("validator_valid") is False or "false positive" in title:
        return 0.10, "provider rejected credential"

    # 3) category-specific strong signals
    if cat == "sqli":
        return (0.9, "DBMS error / time oracle") if detection in ("error", "time") \
            else (0.6, "boolean response-delta")
    if cat == "xss":
        # token survived unencoded (reflected) or browser saw a sink fire (DOM)
        return 0.85, "unencoded reflection / browser sink"
    if cat in ("rce", "ssti", "xxe"):
        return 0.9, "in-band exploitation evidence"
    if cat == "ssrf":
        return 0.9, "internal resource indicator"
    if cat == "open_redirect":
        return 0.85, "Location header to attacker host"
    if cat == "cors":
        return (0.85, "origin reflected with credentials") if "credential" in title \
            else (0.5, "permissive ACAO without credentials")
    if cat == "cache_poisoning":
        return 0.7, "unkeyed header reflected into cached response"
    if cat in ("smuggling", "h2_smuggling"):
        return 0.6, "front/back-end timing disagreement (verify manually)"
    if cat == "websocket":
        if "hijack" in title or "injection" in title:
            return 0.8, "CSWH handshake / message-channel proof"
        return 0.6, "unauthenticated handshake"
    if cat == "oauth":
        return (0.85, "redirect_uri lands on attacker host") if "open redirect" in title \
            else (0.55, "OAuth hardening gap (manual confirm)")
    if cat == "graphql":
        return (0.7, "anonymous mutation / CSRF channel") if ("without auth" in title
            or "csrf" in title) else (0.55, "schema/limit weakness")
    if cat == "graphql_introspection":
        return 0.8, "schema returned"
    if cat == "prompt_injection":
        return (0.75, "sentinel leaked") if "override" in title else (0.45, "prompt-leak heuristic")
    if cat == "api":
        if "mass assignment" in title or "privilege escalation" in title:
            return 0.85, "privileged field honored / forged token accepted"
        if "jwt" in title and "none" in title:
            return 0.8, "alg=none accepted"
        return 0.5, "API hardening signal"
    if cat == "secret_exposure":
        return 0.4, "regex match, not provider-validated"
    if cat == "exposure":
        return (0.85, "open bucket / spec exposed") if ("bucket" in title or "openapi" in title
            or "swagger" in title) else (0.6, "sensitive path 200")
    if cat == "subdomain_takeover" or cat == "takeover" or cat in _STRONG_CATEGORIES:
        return 0.9, "dangling CNAME + service fingerprint"
    if cat == "nuclei":
        return 0.75, "community template match"

    # 4) heuristic categories
    if cat in _HEURISTIC_CATEGORIES:
        return _HEURISTIC_CATEGORIES[cat], "heuristic — manual verification required"

    # 5) unknown — be conservative
    return 0.5, "default"


def annotate(finding: dict[str, Any]) -> float:
    """Set finding['confidence'] and finding['confidence_label'] in place; return score."""
    score, reason = assign(finding)
    finding["confidence"] = round(score, 2)
    finding["confidence_label"] = label(score)
    finding.setdefault("metadata", {})
    if isinstance(finding["metadata"], dict):
        finding["metadata"].setdefault("confidence_reason", reason)
    return score
