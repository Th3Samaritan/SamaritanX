"""Strict assessment profiles keep required capabilities and inputs explicit."""
import hashlib
import json
import math
from pathlib import Path
from urllib.parse import urlsplit
import yaml

FIELDS = {"version", "output", "phases"}
KINDS = {
    "web": {"target", "scope", "config", "deadline", "auth", "second_auth"},
    "mobile-static": {"artifact"},
    "local-audit": {"snapshot", "collect"},
    "mobile-traffic": {"har", "scope_hosts"},
    "mobile-dynamic": {"platform", "app_id", "server", "session_id", "device_id", "flow", "aggressive"},
}
PATHS = {"scope", "config", "auth", "second_auth", "artifact", "snapshot", "har", "flow"}


def load_profile(path):
    path = Path(path).resolve()
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("profile exceeds 1 MiB")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) - FIELDS or data.get("version") != 1:
        raise ValueError("expected version 1 assessment profile with known fields")
    phases = data.get("phases")
    if not isinstance(phases, list) or not 1 <= len(phases) <= 30:
        raise ValueError("provide 1-30 phases")
    seen = set()
    for phase in phases:
        if not isinstance(phase, dict):
            raise ValueError("phase must be a mapping")
        kind = phase.get("kind")
        name = phase.get("id", "")
        if kind not in KINDS or set(phase) - (KINDS[kind] | {"kind", "id", "required"}):
            raise ValueError("unknown phase kind or field")
        if not isinstance(name, str) or not name or len(name) > 64 or not all(c.isalnum() or c in "-_" for c in name) or name in seen:
            raise ValueError("phase IDs must be unique simple names")
        seen.add(name)
        for key in ("required", "collect", "aggressive"):
            if key in phase and not isinstance(phase[key], bool):
                raise ValueError(f"{key} must be boolean")
        for key in PATHS & phase.keys():
            value = (path.parent / phase[key]).resolve()
            if not value.is_file():
                raise ValueError(f"missing {key} file in phase {name}")
            phase[key] = str(value)
        if kind == "web":
            parsed = urlsplit(phase.get("target", ""))
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.query or parsed.fragment or not phase.get("scope"):
                raise ValueError("web phase requires an HTTP target without credentials/query and an explicit scope")
            from .scope import ScopePolicy
            if not ScopePolicy.from_file(phase["scope"]).allows(phase["target"])[0]:
                raise ValueError("target is outside declared scope")
            budget = phase.setdefault("deadline", 600)
            if isinstance(budget, bool) or not isinstance(budget, (int, float)) or not math.isfinite(budget) or not 1 <= budget <= 86400:
                raise ValueError("deadline must be 1-86400 seconds")
        if kind == "local-audit" and bool(phase.get("snapshot")) == bool(phase.get("collect")):
            raise ValueError("local-audit requires snapshot or collect, exclusively")
        for key in {"mobile-static": ["artifact"], "mobile-traffic": ["har", "scope_hosts"], "mobile-dynamic": ["platform", "app_id"]}.get(kind, []):
            if not phase.get(key):
                raise ValueError(f"{kind} requires {key}")
        if kind == "mobile-dynamic":
            if bool(phase.get("session_id")) == bool(phase.get("device_id")):
                raise ValueError("choose session_id to attach or device_id to create, exclusively")
            if phase.get("device_id") and not phase.get("aggressive", False):
                raise ValueError("session creation requires aggressive: true")
            if phase["platform"] not in {"android", "ios"}:
                raise ValueError("platform must be android or ios")
            u = urlsplit(phase.setdefault("server", "http://127.0.0.1:4723"))
            if u.scheme not in {"http", "https"} or not u.hostname or u.username or u.query or u.fragment:
                raise ValueError("invalid Appium endpoint")
            if phase.get("flow") and not phase.get("aggressive", False):
                raise ValueError("UI flows require aggressive: true")
        if kind == "mobile-traffic":
            hosts = phase["scope_hosts"]
            if not isinstance(hosts, list) or not hosts or any(not isinstance(h, str) or not h or any(c in h for c in "/:*@") for h in hosts):
                raise ValueError("scope_hosts must be exact host names")
    data["output"] = str((path.parent / data.get("output", "../workspace/assessments")).resolve())
    return data


def profile_hash(profile):
    return hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()
