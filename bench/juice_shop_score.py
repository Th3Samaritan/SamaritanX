"""Separate proof-gated findings from application-observed challenge progress."""
from core.proof_gate import poc_status


def catalog(payload):
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows or len(rows) > 2000:
        raise ValueError("invalid challenge inventory")
    output = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), int) or type(row.get("solved")) is not bool:
            raise ValueError("invalid challenge state")
        key = str(row["id"])
        if key in output:
            raise ValueError("duplicate challenge ID")
        output[key] = {k: row.get(k) for k in ("id", "name", "category", "difficulty", "solved")}
    return output


def score(before, after, findings, candidates, *, healthy=True, execution=None):
    if set(before) != set(after):
        raise ValueError("challenge inventory changed during run")
    if not isinstance(findings, list) or not isinstance(candidates, list):
        raise ValueError("reports must be arrays")
    verified = [f for f in findings if poc_status(f)[0] == "verified"]
    pre = {k for k, r in before.items() if r["solved"]}
    post = {k for k, r in after.items() if r["solved"]}
    reset = bool(pre - post) or not healthy
    return {"status": "invalid" if reset else "measured", "challenge_total": len(after),
            "pre_solved": sorted(pre), "newly_solved": sorted(post - pre) if not reset else [],
            "remaining": sorted(set(after) - post), "reset_detected": reset,
            "verified_findings": len(verified), "candidates": len(candidates) + len(findings) - len(verified),
            "execution": execution or {}, "remaining_cause": "unknown; requires adjudication",
            "limitations": ["Challenge progress is not vulnerability recall.",
                            "Unmatched findings are not automatically false positives.",
                            "No complete answer key has been adjudicated for this version."]}
