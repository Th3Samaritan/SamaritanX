"""Accuracy metrics for labeled local-lab results, including replay stability."""
from __future__ import annotations


def summarize(cases):
    """Each case supplies vulnerable, detected, reproduced, and requests."""
    tp = sum(bool(c["vulnerable"] and c["detected"]) for c in cases)
    fp = sum(bool(not c["vulnerable"] and c["detected"]) for c in cases)
    fn = sum(bool(c["vulnerable"] and not c["detected"]) for c in cases)
    verified = sum(bool(c["vulnerable"] and c["detected"] and c.get("reproduced")) for c in cases)
    return {"cases": len(cases), "true_positives": tp, "false_positives": fp,
            "false_negatives": fn, "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "reproducibility": verified / (tp + fp) if tp + fp else None,
            "requests_per_verified_finding": sum(c.get("requests", 0) for c in cases) / verified if verified else None}
