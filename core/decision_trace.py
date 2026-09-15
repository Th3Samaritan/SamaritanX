"""Proof decision traces (plan §11.8).

Every finding gets a versioned, evidence-referencing trace that lets a
reviewer locate the baseline reference, the decisive observation, the
verification attempts, the expiry result, the policy outcome and the final
gate decision — without reconstructing the whole run and without raw
credentials. Transport observations (captured hashes) are separated from
detector interpretations (detection labels); the gate decision comes from
`proof_gate.poc_status` and can never be overridden by a scanner narrative.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .proof_gate import poc_status
from .run_manifest import _redact

TRACE_VERSION = 1


def evidence_hash(text: str | None) -> str | None:
    if not text:
        return None
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()


def build_trace(finding: dict[str, Any]) -> dict[str, Any]:
    """Versioned decision trace for a finding. References hashes, not bodies."""
    meta = finding.get("metadata") or {}
    poc = meta.get("poc") if isinstance(meta.get("poc"), dict) else {}
    status, reason = poc_status(finding)
    baseline = meta.get("verification_baseline") or {}
    if not isinstance(baseline, dict):
        baseline = {}
    excerpt = baseline.get("response_excerpt")
    trace = {
        "version": TRACE_VERSION,
        "gate_decision": status,          # verified | candidate (from the gate)
        "gate_reason": reason,            # stable reason code/explanation
        "baseline": {
            "response_captured": excerpt is not None,
            "baseline_hash": evidence_hash(excerpt),
            "hash_scope": "response_excerpt" if excerpt is not None else None,
            "source": "verification_baseline" if excerpt is not None else None,
        },
        "observation": {
            "detection": meta.get("detection"),
            "category": finding.get("category"),
            "parameter": finding.get("parameter"),
            "evidence_hash": evidence_hash(finding.get("evidence")),
            "response_hash": evidence_hash(finding.get("response")),
        },
        "verification": {
            "revalidated": meta.get("revalidated"),
            "note": meta.get("revalidation_note") or meta.get("revalidation"),
            "poc_verified": poc.get("verified"),
            "poc_status": poc.get("response_status"),
            "poc_excerpt_hash": evidence_hash(poc.get("response_excerpt")),
            "poc_samples": len(poc.get("samples") or []),
        },
        "identity": {
            "session": meta.get("session") or meta.get("session_a"),
            "viewer": meta.get("identity") or meta.get("owner"),
        },
        "policy": {
            "quarantine_reason": meta.get("quarantine_reason"),
            "triage": meta.get("triage"),
            "lifecycle_state": meta.get("lifecycle_state"),
            "evidence_integrity": meta.get("evidence_integrity"),
        },
    }
    return _redact(trace)


def render_trace(trace: dict[str, Any]) -> str:
    """A concise human-readable timeline for offline review."""
    lines = [f"gate      : {trace.get('gate_decision')} — {trace.get('gate_reason')}"]
    obs = trace.get("observation") or {}
    lines.append(f"observation: detection={obs.get('detection')}, "
                 f"evidence sha256={str(obs.get('evidence_hash'))[:12]}…")
    base = trace.get("baseline") or {}
    lines.append(f"baseline   : {'captured' if base.get('response_captured') else 'none'}"
                 f"{' sha256=' + str(base.get('baseline_hash'))[:12] + '…' if base.get('baseline_hash') else ''}")
    ver = trace.get("verification") or {}
    lines.append(f"verification: revalidated={ver.get('revalidated')}, "
                 f"poc.verified={ver.get('poc_verified')}, "
                 f"poc excerpt sha256={str(ver.get('poc_excerpt_hash'))[:12]}…")
    pol = trace.get("policy") or {}
    bits = [f"{k}={v}" for k, v in pol.items() if v]
    lines.append(f"policy     : {' '.join(bits) if bits else '-'}")
    ident = trace.get("identity") or {}
    ibits = [f"{k}={v}" for k, v in ident.items() if v]
    lines.append(f"identity   : {' '.join(ibits) if ibits else 'anonymous'}")
    return "\n".join(lines)
