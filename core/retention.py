"""Evidence retention controls (plan §11.10).

Retention is inventory-first: the default operation reports what *would* be
removed and touches nothing. A cleanup only happens when the operator both
asks for it explicitly and has deliberately enabled retention in
configuration. Every removal is recorded in ``retention/removals.jsonl`` with
its reason, content hash and (where known) the affected finding, and findings
whose bundle was removed are flagged ``evidence_removed`` — so a missing
artifact can never be read as proof that the bug was fixed.

Logs, raw response traces, verified bundles and lifecycle metadata carry
independent age limits; the longest-lived class is lifecycle metadata.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

CLASSES = ("logs", "traces", "bundles", "lifecycle")

# class -> policy key holding its age threshold (0/None = keep indefinitely)
_AGE_KEYS = {"logs": "logs_days", "traces": "traces_days",
             "bundles": "bundles_days", "lifecycle": "lifecycle_days"}

# per-target workspace subdirectory -> retention class
_DIR_CLASSES = {
    "recon": "traces", "crawl": "traces", "discovery": "traces",
    "vulns": "traces", "authz": "traces", "monitor": "traces",
    "screenshots": "traces",
    "evidence": "bundles",
    "reports": "lifecycle", "session": "lifecycle", "retention": "lifecycle",
}

_ROOT_FILES = {"run_manifest.json": "lifecycle"}

_DEFAULT_POLICY = {"enabled": False, "logs_days": 30, "traces_days": 14,
                   "bundles_days": 90, "lifecycle_days": 365}

REMOVALS_FILE = "removals.jsonl"


def policy(config: dict | None) -> dict:
    """Effective retention policy: defaults overlaid with config values."""
    out = dict(_DEFAULT_POLICY)
    section = (config or {}).get("retention") or {}
    if isinstance(section, dict):
        if "enabled" in section:
            out["enabled"] = bool(section["enabled"])
        for key in _AGE_KEYS.values():
            value = section.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                out[key] = value
    return out


def classify(path: Path, workspace: Path) -> str | None:
    """Map a workspace file to its retention class, or None if unmanaged."""
    rel = Path(path)
    try:
        rel = rel.relative_to(Path(workspace))
    except ValueError:
        return None
    parts = rel.parts
    if not parts:
        return None
    if len(parts) == 1:
        if parts[0].endswith(".log"):
            return "logs"
        return _ROOT_FILES.get(parts[0])
    if rel.suffix == ".log":
        return "logs"
    return _DIR_CLASSES.get(parts[0])


def _iter_files(workspace: Path):
    if not workspace.exists():
        return
    removals = (Path(workspace) / "retention" / REMOVALS_FILE).resolve()
    for path in sorted(workspace.rglob("*")):
        if not path.is_file():
            continue
        try:
            if path.resolve() == removals:
                continue
        except OSError:
            continue
        yield path


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def inventory(workspace, config=None, *, target: str = "", now: float | None = None) -> dict:
    """Non-destructive per-class inventory with expired candidates."""
    workspace = Path(workspace)
    now = time.time() if now is None else now
    pol = policy(config)
    classes = {name: {"class": name, "files": 0, "bytes": 0, "oldest": None,
                      "newest": None, "age_days": pol[_AGE_KEYS[name]],
                      "expired": []} for name in CLASSES}
    for path in _iter_files(workspace):
        name = classify(path, workspace)
        if name is None:
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        info = classes[name]
        info["files"] += 1
        info["bytes"] += stat.st_size
        info["oldest"] = stat.st_mtime if info["oldest"] is None else min(info["oldest"], stat.st_mtime)
        info["newest"] = stat.st_mtime if info["newest"] is None else max(info["newest"], stat.st_mtime)
        days = pol[_AGE_KEYS[name]]
        if days and now - stat.st_mtime > days * 86400:
            info["expired"].append({
                "path": str(path), "bytes": stat.st_size,
                "age_days": round((now - stat.st_mtime) / 86400, 2),
            })
    return {"target": target, "workspace": str(workspace), "now": now,
            "policy": pol, "classes": classes}


def plan(workspace, config=None, *, target: str = "", now: float | None = None) -> dict:
    """Dry-run cleanup plan. Never touches the filesystem."""
    inv = inventory(workspace, config, target=target, now=now)
    actions: list[dict] = []
    for name, info in inv["classes"].items():
        for item in info["expired"]:
            action = {
                "class": name, "path": item["path"], "bytes": item["bytes"],
                "age_days": item["age_days"],
                "reason": f"{name} older than {info['age_days']} day(s)",
            }
            if name == "bundles":
                action["sha256"] = _sha256(Path(item["path"]))
            actions.append(action)
    return {**inv, "actions": actions,
            "total_bytes": sum(a["bytes"] for a in actions)}


def _removals_path(workspace: Path) -> Path:
    return Path(workspace) / "retention" / REMOVALS_FILE


def apply(plan_dict: dict, *, confirm: bool = False, memory=None) -> dict:
    """Execute a plan. Refuses unless explicitly confirmed AND policy enabled."""
    if not confirm:
        return {"applied": False, "deleted": [], "records": [],
                "reason": "dry run — no files removed (pass confirm/--apply)"}
    pol = plan_dict.get("policy") or {}
    if not pol.get("enabled"):
        return {"applied": False, "deleted": [], "records": [],
                "reason": "retention disabled — set retention.enabled: true to delete"}
    records: list[dict] = []
    deleted: list[str] = []
    for action in plan_dict.get("actions", []):
        path = Path(action["path"])
        raw = None
        try:
            raw = path.read_bytes()
            path.unlink()
        except OSError:
            continue
        records.append({
            "removed_at": time.time(),
            "class": action["class"],
            "path": str(path),
            "reason": action["reason"],
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
        deleted.append(str(path))
    if records:
        out = _removals_path(Path(plan_dict["workspace"]))
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("a", encoding="utf-8") as fh:
                for record in records:
                    fh.write(json.dumps(record) + "\n")
        except OSError:
            pass
    marked = mark_removed_bundles(plan_dict, memory)
    return {"applied": True, "deleted": deleted, "records": records,
            "findings_marked": marked, "reason": "cleanup applied"}


def mark_removed_bundles(plan_dict: dict, memory) -> int:
    """Flag findings whose evidence bundle was removed — absence is not a fix."""
    if memory is None:
        return 0
    removed = {a["path"] for a in plan_dict.get("actions", []) if a["class"] == "bundles"}
    if not removed:
        return 0
    marked = 0
    for finding in memory.list_findings(plan_dict.get("target")):
        artifact = (finding.get("metadata") or {}).get("evidence_bundle") or {}
        if artifact.get("file") not in removed:
            continue
        meta = dict(finding.get("metadata") or {})
        meta["evidence_removed"] = True
        meta["evidence_removed_at"] = time.time()
        meta["evidence_integrity"] = "missing"
        memory.update_finding(finding["id"], metadata=meta)
        marked += 1
    return marked


def removal_records(workspace) -> list[dict]:
    path = _removals_path(Path(workspace))
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def evidence_available(finding: dict, workspace=None) -> bool:
    """False when a finding's proof artifact is known-removed or absent."""
    meta = finding.get("metadata") or {}
    if meta.get("evidence_removed") is True:
        return False
    artifact = meta.get("evidence_bundle") or {}
    if not artifact:
        return bool(finding.get("response"))
    path = artifact.get("file")
    if not path:
        return False
    return Path(path).exists()
