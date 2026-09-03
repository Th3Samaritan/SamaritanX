"""Score a scan's output against a ground-truth answer key.

Pure and deterministic. Given the ``findings`` a run reported (verified),
the ``candidates`` it quarantined, and an answer key of expected vulnerabilities,
it computes per-category:

  * TP  — an expected vuln that a *verified* finding matched
  * FP  — a verified finding that matched no expected vuln
  * FN  — an expected vuln nothing verified matched
  * gated — an expected vuln that only a *candidate* matched (the detector saw
    it but couldn't prove it; recall lost to the proof-gate, not to the detector)

…and precision / recall from those. This is the number that tells you whether a
change actually improved things.

Answer-key entry (JSON):
    {"id": "juice-sqli-login", "target": "juice.local", "category": "sqli",
     "match": "/rest/user/login", "severity": "critical"}
``match`` is a case-insensitive substring tested against a finding's url +
parameter. ``category`` must equal the finding's category.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _matches(expected: dict, finding: dict) -> bool:
    if (expected.get("category") or "").lower() != (finding.get("category") or "").lower():
        return False
    needle = (expected.get("match") or "").lower()
    if not needle:
        return True
    # url, parameter AND title are all fair haystacks (titles matter for
    # configuration-class findings like security headers)
    hay = (f"{finding.get('url','')} {finding.get('parameter','')} "
           f"{finding.get('title','')}").lower()
    return needle in hay


@dataclass
class CategoryScore:
    category: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    gated: int = 0
    matched_expected: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn + self.gated
        return self.tp / denom if denom else 1.0

    def as_dict(self) -> dict[str, Any]:
        return {"category": self.category, "tp": self.tp, "fp": self.fp,
                "fn": self.fn, "gated": self.gated,
                "precision": round(self.precision, 3), "recall": round(self.recall, 3),
                "false_positives": self.false_positives[:10]}


def score(findings: list[dict], candidates: list[dict],
          answer_key: list[dict]) -> dict[str, Any]:
    """Return a per-category and overall scoreboard."""
    cats: dict[str, CategoryScore] = {}

    def cs(cat: str) -> CategoryScore:
        return cats.setdefault(cat, CategoryScore(category=cat))

    verified_used: set[int] = set()

    # true positives + gated (candidate-only) recall
    for exp in answer_key:
        cat = (exp.get("category") or "").lower()
        hit = None
        for i, f in enumerate(findings):
            if i in verified_used:
                continue
            if _matches(exp, f):
                hit = i
                break
        if hit is not None:
            verified_used.add(hit)
            c = cs(cat)
            c.tp += 1
            c.matched_expected.append(exp.get("id", exp.get("match", "?")))
        elif any(_matches(exp, c_) for c_ in candidates):
            cs(cat).gated += 1
        else:
            cs(cat).fn += 1

    # false positives: verified findings that matched no expected vuln
    for i, f in enumerate(findings):
        if i in verified_used:
            continue
        cat = (f.get("category") or "").lower()
        c = cs(cat)
        c.fp += 1
        c.false_positives.append(f.get("title") or f.get("url") or "?")

    total_tp = sum(c.tp for c in cats.values())
    total_fp = sum(c.fp for c in cats.values())
    total_fn = sum(c.fn for c in cats.values())
    total_gated = sum(c.gated for c in cats.values())
    prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 1.0
    rec = total_tp / (total_tp + total_fn + total_gated) if (total_tp + total_fn + total_gated) else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

    return {
        "overall": {"tp": total_tp, "fp": total_fp, "fn": total_fn, "gated": total_gated,
                    "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3)},
        "by_category": {cat: c.as_dict() for cat, c in sorted(cats.items())},
    }


def format_scoreboard(result: dict[str, Any]) -> str:
    """Render the score dict as a readable table."""
    o = result["overall"]
    lines = [
        "SamaritanX benchmark scoreboard",
        "=" * 64,
        f"{'category':<18}{'TP':>4}{'FP':>4}{'FN':>4}{'gate':>5}{'prec':>7}{'rec':>7}",
        "-" * 64,
    ]
    for cat, c in result["by_category"].items():
        lines.append(f"{cat:<18}{c['tp']:>4}{c['fp']:>4}{c['fn']:>4}{c['gated']:>5}"
                     f"{c['precision']:>7.2f}{c['recall']:>7.2f}")
    lines.append("-" * 64)
    lines.append(f"{'OVERALL':<18}{o['tp']:>4}{o['fp']:>4}{o['fn']:>4}{o['gated']:>5}"
                 f"{o['precision']:>7.2f}{o['recall']:>7.2f}")
    lines.append(f"F1 = {o['f1']:.3f}   (gate = expected bug seen but not proven)")
    return "\n".join(lines)
