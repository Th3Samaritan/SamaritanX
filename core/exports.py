"""Interchange-format exports for verified findings.

Writes three widely-ingestible formats next to findings.json:

  * ``findings.sarif.json`` — SARIF 2.1.0 (GitHub code scanning, VS Code,
    DefectDojo, most static-analysis pipelines)
  * ``findings.csv``      — one row per finding (spreadsheets, program triage)
  * ``findings.jsonl``    — one JSON object per line (data pipelines)

Pure and deterministic given the findings list.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any


def to_sarif(findings: list[dict], *, tool_name: str = "SamaritanX") -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from verified findings."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        cat = (f.get("category") or "unknown").lower()
        if cat not in rules:
            rules[cat] = {
                "id": cat,
                "name": cat.replace("_", " ").title(),
                "shortDescription": {"text": f"SamaritanX {cat} detector"},
                "defaultConfiguration": {
                    "level": "warning",
                },
            }
        sev = (f.get("severity") or "info").lower()
        level = {"critical": "error", "high": "warning", "medium": "warning",
                 "low": "note", "info": "note"}.get(sev, "note")
        results.append({
            "ruleId": cat,
            "level": level,
            "message": {
                "text": f"{f.get('title')} — {(f.get('evidence') or '')[:400]}",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.get("url") or "",
                        "uriBaseId": "%SRCROOT%",
                    },
                },
            }],
            "partialFingerprints": {
                "samaritanx/v1": f"{cat}::{f.get('url','')}::{f.get('parameter','')}",
            },
            "properties": {
                "severity": sev,
                "cvss": f.get("cvss"),
                "confidence": f.get("confidence"),
                "parameter": f.get("parameter"),
                "payload": (f.get("payload") or "")[:2000],
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/anomalyco/opencode",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }


_CSV_COLUMNS = ["id", "severity", "cvss", "confidence", "category", "title",
                "url", "parameter", "payload", "evidence"]


def to_csv(findings: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV_COLUMNS)
    for f in findings:
        w.writerow([f.get(c, "") for c in _CSV_COLUMNS])
    return buf.getvalue()


def write_exports(findings: list[dict], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    if not findings:
        return
    sarif = to_sarif(findings)
    (out_dir / "findings.sarif.json").write_text(
        json.dumps(sarif, indent=2, default=str), encoding="utf-8")
    (out_dir / "findings.csv").write_text(to_csv(findings), encoding="utf-8")
    with (out_dir / "findings.jsonl").open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f, default=str) + "\n")
