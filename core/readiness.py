"""Offline readiness checks — explain missing tooling before work is scheduled.

`doctor` separates cheap filesystem/import checks from optional bounded
process checks. It NEVER contacts providers, downloads dependencies, or scans
targets. Expensive successful checks (binary version probes) are cached by
executable hash + relevant config digest with an expiry; scope/permission
decisions are never cached here.

Each result identifies which operation an unavailable dependency affects, so
"nuclei missing" is actionable rather than a silent empty scan.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any

_CACHE_TTL = 86400  # 24h


def _cache_dir() -> Path:
    return Path("workspace") / "readiness"


def _digest(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _cached(key: str) -> dict | None:
    path = _cache_dir() / f"{key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - data.get("ts", 0) > _CACHE_TTL:
            return None
        return data.get("result")
    except Exception:
        return None


def _store(key: str, result: dict) -> None:
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        (_cache_dir() / f"{key}.json").write_text(
            json.dumps({"ts": time.time(), "result": result}), encoding="utf-8")
    except Exception:
        pass


def _check_workspace(root: str) -> dict:
    try:
        p = Path(root)
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".sx-readiness-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return {"capability": "workspace", "status": "ok",
                "detail": str(p), "affects": "every phase"}
    except Exception as exc:
        return {"capability": "workspace", "status": "unavailable",
                "detail": f"{type(exc).__name__}: {exc}",
                "affects": "every phase (no output can be written)"}


def _check_database(db_path: str) -> dict:
    try:
        from .memory import Memory
        m = Memory(db_path)
        m.list_findings("__readiness__")
        from .migrations import integrity_report
        report = integrity_report(m.db_path)
        if report["ok"]:
            return {"capability": "database", "status": "ok",
                    "detail": str(db_path), "affects": "memory, resume, incremental",
                    "integrity": report}
        return {"capability": "database", "status": "unavailable",
                "detail": "; ".join(report["manual"][:2]) or "integrity check failed",
                "affects": "memory, resume, incremental", "integrity": report}
    except Exception as exc:
        return {"capability": "database", "status": "unavailable",
                "detail": f"{type(exc).__name__}: {exc}",
                "affects": "memory, resume, incremental"}


def _check_browser(config: dict) -> dict:
    """Import-level + executable-path check only — no launch, no network."""
    try:
        from playwright.async_api import async_playwright  # noqa: F401
    except Exception as exc:
        return {"capability": "browser_interception", "status": "missing",
                "detail": f"playwright import failed: {exc}",
                "affects": "dom_xss, stored_xss execution proof, authenticated XHR capture"}
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            path = pw.chromium.executable_path
        if not path or not Path(path).exists():
            return {"capability": "browser_interception", "status": "missing",
                    "detail": f"chromium executable not found at {path}",
                    "affects": "dom_xss, stored_xss execution proof, authenticated XHR capture"}
        return {"capability": "browser_interception", "status": "ok",
                "detail": path, "affects": "dom_xss, stored_xss, authenticated XHR"}
    except Exception as exc:
        return {"capability": "browser_interception", "status": "unavailable",
                "detail": f"{type(exc).__name__}: {exc}",
                "affects": "dom_xss, stored_xss execution proof, authenticated XHR capture"}


def _binary_probe(config: dict, tool: str) -> dict:
    """Bounded local version probe (cached by executable hash)."""
    from .transport import external_tool_path
    path = external_tool_path(tool, config)
    if not path:
        return {"capability": f"external_tool:{tool}", "status": "missing",
                "detail": f"{tool} not found in binary_dir or PATH",
                "affects": f"{tool} adapter scans"}
    try:
        exe_hash = _digest(Path(path).read_bytes())
    except Exception:
        exe_hash = "unreadable"
    cfg_digest = _digest(json.dumps(config.get("external_tools", {}), sort_keys=True, default=str))
    key = f"{tool}-{exe_hash}-{cfg_digest}"
    cached = _cached(key)
    if cached:
        return cached
    version_args = {
        "nuclei": ["-version", "-duc", "-disable-update-check"],
        "ffuf": ["-V"],
        "subfinder": ["-version", "-duc"],
    }
    try:
        import subprocess
        proc = subprocess.run([path, *version_args[tool]], capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=20)
        detail = ((proc.stdout or "").strip() or (proc.stderr or "").strip())[:200]
        if proc.returncode != 0:
            result = {"capability": f"external_tool:{tool}", "status": "failed",
                      "detail": f"exit {proc.returncode}: {detail}",
                      "affects": f"{tool} adapter scans"}
            return result
        result = {"capability": f"external_tool:{tool}", "status": "ok",
                  "detail": detail, "affects": f"{tool} adapter scans",
                  "version_probe": detail}
        _store(key, result)
        return result
    except FileNotFoundError:
        return {"capability": f"external_tool:{tool}", "status": "missing",
                "detail": f"{tool} binary not found",
                "affects": f"{tool} adapter scans"}
    except Exception as exc:
        return {"capability": f"external_tool:{tool}", "status": "failed",
                "detail": f"{type(exc).__name__}: {exc}",
                "affects": f"{tool} adapter scans"}


def _check_templates(config: dict) -> dict:
    tpl = config.get("external_tools", {}).get("nuclei_templates")
    if not tpl:
        return {"capability": "nuclei_catalog", "status": "disabled",
                "detail": "no nuclei_templates configured", "affects": "nuclei adapter scans"}
    path = Path(tpl)
    if not path.exists():
        return {"capability": "nuclei_catalog", "status": "invalid",
                "detail": f"catalog path does not exist: {path}",
                "affects": "nuclei adapter scans"}
    if not path.is_dir():
        return {"capability": "nuclei_catalog", "status": "invalid",
                "detail": f"catalog path is not a directory: {path}",
                "affects": "nuclei adapter scans"}
    yamls = list(path.rglob("*.yaml"))
    # one sample template must PARSE — this is not whole-catalog validation
    if not yamls:
        return {"capability": "nuclei_catalog", "status": "invalid",
                "detail": "catalog contains no .yaml templates",
                "affects": "nuclei adapter scans"}
    try:
        import yaml as _yaml
        _yaml.safe_load(yamls[0].read_text(encoding="utf-8", errors="replace"))
        return {"capability": "nuclei_catalog", "status": "ok",
                "detail": f"{len(yamls)} templates; one sample parsed successfully "
                          "(sample validity is not whole-catalog validity)",
                "affects": "nuclei adapter scans", "template_count": len(yamls)}
    except Exception as exc:
        return {"capability": "nuclei_catalog", "status": "failed",
                "detail": f"sample template failed to parse: {type(exc).__name__}: {exc}",
                "affects": "nuclei adapter scans"}


def _check_llm(config: dict) -> dict:
    from .llm import available, _provider
    if not (config.get("llm") or {}).get("enabled"):
        return {"capability": "llm_triage", "status": "disabled",
                "detail": "llm.enabled is false", "affects": "AI impact narratives"}
    if available(config):
        return {"capability": "llm_triage", "status": "ok",
                "detail": f"provider {_provider(config)} key configured (no network check performed)",
                "affects": "AI impact narratives"}
    return {"capability": "llm_triage", "status": "missing",
            "detail": "no API key for the configured provider",
            "affects": "AI impact narratives (template fallback will run)"}


def _check_scope(config: dict, scope_file: str | None) -> dict:
    if not scope_file:
        return {"capability": "scope_policy", "status": "ok",
                "detail": "no scope file — auto-derived target scope", "affects": "egress scope"}
    path = Path(scope_file)
    if not path.exists():
        return {"capability": "scope_policy", "status": "invalid",
                "detail": f"scope file not found: {path}", "affects": "egress scope"}
    try:
        from .scope import ScopePolicy
        policy = ScopePolicy.from_file(path, default_allow=False)
        n = len(policy.allow_globs) + len(policy.allow_regex) + len(policy.allow_cidr) + \
            len(policy.deny_globs) + len(policy.deny_regex) + len(policy.deny_cidr)
        return {"capability": "scope_policy", "status": "ok",
                "detail": f"{n} rule(s) parsed", "affects": "egress scope"}
    except Exception as exc:
        return {"capability": "scope_policy", "status": "invalid",
                "detail": f"{type(exc).__name__}: {exc}", "affects": "egress scope"}


def run_checks(config: dict, *, scope_file: str | None = None,
               probe_binaries: bool = True) -> list[dict]:
    """All readiness checks. No network I/O is performed by design."""
    results: list[dict] = [
        _check_workspace(config.get("workspace", {}).get("root", "./workspace")),
        _check_database(config.get("memory", {}).get("db_path")
                        or Path(config.get("workspace", {}).get("root", "./workspace"))
                        / ".samaritanx.sqlite"),
        _check_browser(config),
        _check_templates(config),
        _check_llm(config),
        _check_scope(config, scope_file),
    ]
    if probe_binaries and config.get("external_tools", {}).get("enabled", True):
        for tool in ("nuclei", "ffuf", "subfinder"):
            results.append(_binary_probe(config, tool))
    return results


def format_checks(results: list[dict]) -> str:
    lines = ["SamaritanX readiness"]
    for r in results:
        mark = {"ok": "OK  ", "disabled": "OFF "}.get(r["status"], "FAIL")
        lines.append(f"  [{mark}] {r['capability']}: {r['detail'][:140]}")
        if r["status"] not in ("ok", "disabled"):
            lines.append(f"         affects: {r['affects']}")
    return "\n".join(lines)
