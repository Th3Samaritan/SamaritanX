"""Shareable export packages (plan §11.10).

Internal history stays private: only the allowlisted fields of the chosen
profile leave the workspace, excerpts are bounded, and a redaction pass runs
again with the caller's known session secrets before anything is written.
Every file in the package is hashed into ``manifest.json`` so a recipient can
verify exactly what they received, and the package is written separately from
the internal ``reports/`` tree.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import time
from pathlib import Path

from .evidence import redact

_SECRET_HEADER = re.compile(r"authorization|cookie|password|passwd|secret|token|api[_-]?key", re.I)

PROFILES: dict[str, dict] = {
    # "shareable": triager-safe. No raw request/response bodies, bounded
    # narrative, identifiers only.
    "shareable": {
        "fields": ["id", "severity", "cvss", "confidence", "category", "title",
                   "url", "parameter", "evidence"],
        "excerpt": 800,
        "include_http": False,
    },
    # "internal": full evidence for internal review — still redacted and bounded.
    "internal": {
        "fields": ["id", "severity", "cvss", "confidence", "category", "title",
                   "url", "parameter", "payload", "evidence", "request", "response"],
        "excerpt": 4000,
        "include_http": True,
    },
}

_BOUNDED = {"evidence", "request", "response"}

_CSV_COLUMNS = ["id", "severity", "cvss", "confidence", "category", "title",
                "url", "parameter", "evidence"]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def session_secrets(workspace) -> list[str]:
    """Known session credentials recovered from the persisted session file."""
    path = Path(workspace) / "session" / "session.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    secrets: list[str] = []
    cookies = payload.get("cookies") or {}
    if isinstance(cookies, dict):
        secrets.extend(str(v) for v in cookies.values() if v)
    headers = payload.get("headers") or {}
    if isinstance(headers, dict):
        secrets.extend(str(v) for k, v in headers.items()
                       if v and _SECRET_HEADER.search(str(k)))
    return [s for s in secrets if s]


def project(finding: dict, profile: str = "shareable", *, secrets=()) -> dict:
    """Allowlisted, bounded, redacted projection of one finding."""
    spec = PROFILES.get(profile) or PROFILES["shareable"]
    excerpt = spec["excerpt"]
    out: dict = {}
    for key in spec["fields"]:
        if key not in finding:
            continue
        value = finding.get(key)
        if key in _BOUNDED and isinstance(value, str):
            value = value[:excerpt]
        out[key] = value
    return redact(out, secrets)


def _csv(payload: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_COLUMNS)
    for row in payload:
        writer.writerow([row.get(c, "") for c in _CSV_COLUMNS])
    return buf.getvalue()


def build_package(findings: list[dict], out_dir, *, profile: str = "shareable",
                  secrets=(), target: str = "") -> dict:
    """Write a verified export package and return its manifest."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = [project(f, profile, secrets=secrets) for f in findings]
    # second redaction pass over the assembled package
    payload = redact(payload, secrets)

    files: dict[str, str] = {}

    body = json.dumps(payload, indent=2, default=str).encode("utf-8")
    (out_dir / "findings.json").write_bytes(body)
    files["findings.json"] = _sha256(body)

    csv_text = _csv(payload).encode("utf-8")
    (out_dir / "findings.csv").write_bytes(csv_text)
    files["findings.csv"] = _sha256(csv_text)

    jsonl = "\n".join(json.dumps(row, default=str) for row in payload).encode("utf-8")
    (out_dir / "findings.jsonl").write_bytes(jsonl)
    files["findings.jsonl"] = _sha256(jsonl)

    manifest = {
        "package_version": 1,
        "profile": profile,
        "target": target,
        "generated_at": time.time(),
        "finding_count": len(payload),
        "secrets_redacted": len([s for s in secrets if s]),
        "files": files,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def verify_package(out_dir) -> bool:
    """True when every manifest hash matches the file on disk."""
    out_dir = Path(out_dir)
    try:
        manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    for name, digest in (manifest.get("files") or {}).items():
        path = out_dir / name
        try:
            if _sha256(path.read_bytes()) != digest:
                return False
        except OSError:
            return False
    return True
