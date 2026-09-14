"""Evaluate captured workflow transitions against explicit operator expectations.

This evaluator performs no network activity. A successful response alone cannot
prove a forbidden action occurred; a captured state change must accompany it.
"""


def evaluate(policy, observation):
    required = ("action", "role", "actor", "owner", "before", "after", "evidence")
    if any(k not in observation for k in required) or not observation["evidence"]:
        return {"result": "inconclusive", "reason": "missing transition evidence or identity context"}
    rules = [r for r in policy if r.get("action") == observation["action"]]
    if not rules:
        return {"result": "inconclusive", "reason": "no expectation configured for action"}
    changed = observation["before"] != observation["after"]
    permitted = any(
        observation["role"] in rule.get("roles", [])
        and observation["before"] in rule.get("from_states", [])
        and observation["after"] in rule.get("to_states", [])
        and (not rule.get("owner_only", True) or observation["actor"] == observation["owner"])
        for rule in rules)
    if permitted:
        return {"result": "allowed", "reason": "captured transition matches an explicit expectation"}
    if changed:
        return {"result": "violation", "reason": "captured state change violates role, ownership, or state expectation"}
    return {"result": "inconclusive", "reason": "no forbidden state change demonstrated"}
