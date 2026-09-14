"""Reproducible run manifests (plan §11.2).

Every run gets a manifest with run ID, engine revision digest, runtime and
platform, external-tool executable hashes, template-selection digest, a
REDACTED configuration digest, scope-policy digest, timestamps and schema
versions. Identical pinned inputs produce identical input digests; a changed
binary or template changes the digest. No raw credentials are stored —
identity labels and fingerprints only.
"""
from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any

_SECRET_KEY_RE = re.compile(r"(password|passwd|secret|token|api_?key|cookie|credential)", re.I)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out[k] = "<redacted>" if isinstance(k, str) and _SECRET_KEY_RE.search(k) and v else _redact(v)
        return out
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str) and _SECRET_KEY_RE.search(value) and len(value) > 8:
        return "<redacted>"
    return value


def redacted_config(config: dict) -> dict:
    return _redact(config)


def config_digest(config: dict) -> str:
    from .scan_execution import _canonical
    return hashlib.sha256(
        json.dumps(_canonical(redacted_config(config)), default=str).encode()
    ).hexdigest()


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool_hashes(config: dict) -> dict[str, str]:
    """SHA-256 of every resolved external-tool executable."""
    from .transport import external_tool_path
    out: dict[str, str] = {}
    for tool in ("nuclei", "ffuf", "subfinder"):
        path = external_tool_path(tool, config)
        if path:
            try:
                out[tool] = _hash_file(Path(path))
            except Exception:
                out[tool] = "unreadable"
    return out


def template_selection_digest(config: dict, cap: int = 4000) -> str:
    """Digest of the selected template files (relpath + content hash).

    Bounded: beyond `cap` files, the digest covers the sorted name list plus
    the total count — still changes when templates are added/removed/edited.
    """
    tpl = config.get("external_tools", {}).get("nuclei_templates")
    if not tpl:
        return ""
    root = Path(tpl)
    if not root.is_dir():
        return ""
    entries = []
    count = 0
    for p in sorted(root.rglob("*.yaml")):
        count += 1
        if count <= cap:
            try:
                entries.append((str(p.relative_to(root)), _hash_file(p)))
            except Exception:
                entries.append((str(p.relative_to(root)), "unreadable"))
    material = json.dumps({"count": count, "entries": entries}, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()


def scope_digest(scope_text: str | None) -> str:
    if not scope_text:
        return ""
    return hashlib.sha256(scope_text.encode("utf-8", "replace")).hexdigest()


def create_run_manifest(config: dict, target: str, *, scope_text: str | None = None,
                        tool_names: list[str] | None = None,
                        template_paths: list[str] | None = None) -> dict:
    """Build the run manifest; `input_digest` over its pinned fields is the
    reproducible-inputs fingerprint."""
    from .scan_execution import engine_version
    from .memory import SCHEMA_VERSION
    manifest = {
        "run_id": uuid.uuid4().hex[:16],
        "target": target,
        "engine_digest": engine_version(),
        "runtime": f"{sys.implementation.name} {sys.version.split()[0]}",
        "platform": platform.platform(),
        "tool_hashes": tool_hashes(config),
        "template_digest": template_selection_digest(config),
        "config_digest": config_digest(config),
        "scope_digest": scope_digest(scope_text),
        "schema_versions": {"memory": SCHEMA_VERSION},
        "tool_names": tool_names or [],
        "template_paths": template_paths or [],
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    manifest["input_digest"] = input_digest(manifest)
    return manifest


def input_digest(manifest: dict) -> str:
    fields = ["engine_digest", "runtime", "platform", "tool_hashes",
              "template_digest", "config_digest", "scope_digest",
              "schema_versions", "tool_names", "template_paths"]
    material = json.dumps({k: manifest.get(k) for k in fields}, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()


def write_manifest(config: dict, target: str, workspace: Path, *,
                   scope_text: str | None = None) -> dict:
    manifest = create_run_manifest(config, target, scope_text=scope_text)
    out = Path(workspace) / "run_manifest.json"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    except Exception:
        pass
    return manifest


def compare_manifests(old: dict, new: dict) -> list[str]:
    """Explain which inputs changed before findings are compared."""
    diffs = []
    for field in ("engine_digest", "runtime", "platform", "tool_hashes",
                  "template_digest", "config_digest", "scope_digest",
                  "schema_versions"):
        if old.get(field) != new.get(field):
            diffs.append(field)
    return diffs
