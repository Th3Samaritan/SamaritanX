"""Bounded inputs and candidate-only assessment outputs."""
import hashlib
import json
from pathlib import Path


def read_limited(path, limit=16 * 1024 * 1024):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("assessment input exceeds size limit")
    return data


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def result(kind, target):
    return {"schema_version": 1, "assessment": kind, "target": str(target),
            "status": "completed", "checks": [], "candidates": [], "limitations": []}


def candidate(report, code, title, evidence, remediation):
    report["candidates"].append({"category": code, "title": title, "evidence": evidence,
        "remediation": remediation, "metadata": {"assessment_only": True,
        "verification_required": True, "detection": "configuration_review"}})


def write_report(report, directory):
    from core.tool_installation import _atomic
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    _atomic(directory / "assessment.json", report)
    _atomic(directory / "candidates.json", report["candidates"])
    lines = ["# Assessment", "", f"Type: {report['assessment']}", f"Status: {report['status']}",
             "", "Observations are candidates, not proof of escalation or exploitability.", ""]
    def literal(text):
        return str(text).replace("<", "&lt;").replace(">", "&gt;").replace("[", "\\[").replace("]", "\\]").replace("`", "\\`")
    for row in report["candidates"]:
        lines.extend(["## " + literal(row["title"]), "", literal(row["evidence"]), "", "Remediation: " + literal(row["remediation"]), ""])
    lines.extend(["## Coverage", "", "```json", json.dumps(report['checks'], indent=2), "```", ""])
    lines.extend("- " + limitation for limitation in report["limitations"])
    (directory / "assessment.md").write_text("\n".join(lines), encoding="utf-8")
    return directory / "assessment.json"
