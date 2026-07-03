"""The hard proof-gate — the single place that decides whether a finding has
earned a spot in the report.

The rule the whole pipeline now enforces: **a finding is only reported if it
carries a captured, re-tested proof.** Not a reconstructed `curl` string, not a
timing hunch, not "the page returned 200" — an actual artifact that a triager
can look at and agree the bug is real:

  * a captured server *response* that demonstrates the bug (the dominant case,
    produced by the revalidators when they re-fire a finding and it reproduces),
  * an out-of-band callback that fired during the scan (blind SSRF/RCE/XXE),
  * a provider-validated secret,
  * a dangling-CNAME + service-fingerprint takeover,
  * a chain whose escalation step was actively reproduced.

Everything else is a *candidate*: possibly real, but unproven, so it is
quarantined to `candidates.json` and never presented as a finding. This is what
kills the false-positive flood — an unsound detector (timing-only smuggling was
the worst offender) simply can never produce the artifact, so it can never reach
the report.

`poc.py` builds *reconstructed* repros (curl / HTML) for triager convenience.
Those live under `metadata.poc_curl` / `metadata.poc_repro` and are explicitly
NOT accepted as proof here — they reproduce nothing on their own.
"""
from __future__ import annotations

from typing import Any

# Detection signatures that are themselves hard proof, captured at scan time and
# not replayable single-shot (so the revalidators legitimately skip them).
_HARDPROOF_DETECTIONS = {
    "oob", "oob-header",   # interactsh / collaborator callback fired
    "marker",              # reflected command/echo marker (in-band RCE)
    "ssti-product",        # template engine evaluated 7*7 -> 49
    "client_proto",        # Object.prototype mutated in a real browser
}

# Categories whose finding is a captured hard artifact by construction.
_HARDPROOF_CATEGORIES = {
    "takeover",            # dangling CNAME + live service fingerprint
    "subdomain_takeover",
}


def _poc_has_response(poc: dict[str, Any]) -> bool:
    """True when a proof record carries a captured response artifact.

    A verified proof must show what the server *did*, not just what we sent.
    Timing `samples` alone are not a response — a hang proves nothing on its own
    (an origin waiting for a promised Content-Length body hangs identically), so
    they only count when paired with a captured response body/status.
    """
    if not isinstance(poc, dict):
        return False
    if poc.get("response_excerpt"):
        return True
    if poc.get("response_status") is not None:
        return True
    # timing samples count only if a sample also captured a response artifact
    samples = poc.get("samples")
    if isinstance(samples, list):
        return any(
            isinstance(s, dict) and (s.get("response_excerpt") or s.get("captured_response"))
            for s in samples
        )
    return False


def poc_status(finding: dict[str, Any]) -> tuple[str, str]:
    """Classify a finding's proof: ('verified' | 'candidate', reason).

    ``verified`` means it ships an artifact a triager can act on. ``candidate``
    means it does not (yet) — quarantine it, don't report it.
    """
    meta = finding.get("metadata") or {}
    cat = (finding.get("category") or "").lower()
    detection = str(meta.get("detection") or "").lower()

    # 1) a captured, verified proof record with a real response artifact
    poc = meta.get("poc")
    if isinstance(poc, dict) and poc.get("verified") is True and _poc_has_response(poc):
        return "verified", "captured verified proof (request + response)"

    # 2) provider-validated secret
    if meta.get("validator_valid") is True:
        return "verified", "credential validated against its provider"
    if meta.get("validator_valid") is False:
        return "candidate", "provider rejected the credential"

    # 3) out-of-band / in-band hard proof captured at scan time
    if detection in _HARDPROOF_DETECTIONS:
        if finding.get("evidence") or finding.get("response") or finding.get("request"):
            return "verified", f"hard proof captured at scan time ({detection})"
        return "candidate", f"{detection} claimed but no artifact captured"

    # 4) categories that are a hard artifact by construction
    if cat in _HARDPROOF_CATEGORIES:
        return "verified", "dangling CNAME + service fingerprint"

    # 5) a chain is only proof if its escalation step was actively reproduced
    if cat == "chain":
        if meta.get("verified") is True:
            return "verified", "chain escalation step reproduced"
        return "candidate", "chain components co-located but escalation not reproduced"

    # 6) revalidation explicitly dropped it → definitely a candidate (likely FP)
    if meta.get("revalidated") is False:
        return "candidate", "did not reproduce on fresh re-test — likely false positive"

    # 7) anything else has no captured proof
    return "candidate", "no captured proof — needs manual confirmation"


def is_verified(finding: dict[str, Any]) -> bool:
    return poc_status(finding)[0] == "verified"


def partition(findings: list[dict[str, Any]]) -> tuple[list[dict], list[dict]]:
    """Split findings into (verified, candidates).

    Each candidate is annotated in place with ``metadata.quarantine_reason`` so
    the quarantine file explains why it was held back.
    """
    verified: list[dict] = []
    candidates: list[dict] = []
    for f in findings:
        status, reason = poc_status(f)
        if status == "verified":
            verified.append(f)
        else:
            meta = f.setdefault("metadata", {})
            if isinstance(meta, dict):
                meta["quarantine_reason"] = reason
            candidates.append(f)
    return verified, candidates
