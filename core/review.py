"""Read-only operator review snapshots joining findings, coverage and evidence."""
from .evidence import redact, verify_bundle
from .proof_gate import poc_status


def snapshot(memory, target, finding_id=None):
    states = memory.finding_states(target)
    findings = memory.list_findings(target)
    if finding_id is not None:
        findings = [f for f in findings if f["id"] == finding_id]
    rows = []
    for finding in findings:
        from .verification import report_freshness
        report_freshness(finding)
        finding.setdefault("metadata", {})["lifecycle_state"] = states.get(finding["id"], "new")
        finding.setdefault("metadata", {})["groups"] = memory.groups_for_finding(finding["id"])
        artifact = (finding.get("metadata") or {}).get("evidence_bundle")
        if (finding.get("metadata") or {}).get("evidence_removed") is True:
            integrity = "removed"
        else:
            integrity = "unavailable"
            if artifact:
                try:
                    integrity = "valid" if verify_bundle(artifact["file"], artifact["sha256"]) else "mismatch"
                except (OSError, KeyError):
                    integrity = "missing"
        finding.setdefault("metadata", {})["evidence_integrity"] = integrity
        from .decision_trace import build_trace
        trace = (finding.get("metadata") or {}).get("proof_trace") or build_trace(finding)
        finding.setdefault("metadata", {})["proof_trace"] = trace
        rows.append({"finding": redact(finding), "state": states.get(finding["id"], "new"),
                     "proof": poc_status(finding), "evidence_integrity": integrity,
                     "trace": trace})
    coverage = memory.execution_coverage(target)
    return {"findings": rows, "coverage": redact(coverage),
            "gaps": [redact(r) for r in coverage["records"] if r["status"] != "completed"]}


def render(console, data, *, gaps_only=False, detail=False):
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    import json

    if not gaps_only:
        table = Table(title="Findings and evidence")
        for column in ("ID", "Category", "Lifecycle", "Proof", "Integrity", "URL"):
            table.add_column(column)
        for row in data["findings"]:
            f = row["finding"]
            table.add_row(*[Text(str(value)) for value in (
                f["id"], f["category"], row["state"], row["proof"][0], row["evidence_integrity"], f.get("url", ""))])
        console.print(table)
    gaps = Table(title=f"Incomplete coverage ({len(data['gaps'])} persisted executions)")
    for column in ("Scanner", "Method", "Identity", "Inputs", "State", "Reason"):
        gaps.add_column(column)
    for row in data["gaps"][:50]:
        context = row.get("context") or {}
        gaps.add_row(*[Text(str(value)) for value in (
            row["scanner"], context.get("method", "unknown"), context.get("identity", "unknown"),
            ", ".join(context.get("inputs", [])), row["status"], row["reason"])])
    console.print(gaps)
    console.print(Text(data["coverage"]["scope"]))
    if len(data["gaps"]) > 50:
        console.print("Showing the first 50 gaps; use --json for the full list.")
    if detail:
        from .decision_trace import render_trace
        for row in data["findings"]:
            f = row["finding"]
            evidence = {"reason": row["proof"][1], "request": f.get("request"),
                        "response": f.get("response"), "metadata": f.get("metadata")}
            console.print(Panel(Text(json.dumps(evidence, indent=2)), title="Evidence details"))
            console.print(Panel(Text(render_trace(row.get("trace") or {})), title="Proof decision trace"))
