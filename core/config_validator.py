"""Schema validation for config.yaml.

Runs at startup to ensure the configuration has all required sections with
sane values before the orchestrator spins up agents.  Catches typos, missing
sections, and obviously broken values early.
"""
from __future__ import annotations

from typing import Any

REQUIRED_SECTIONS: dict[str, dict[str, type]] = {
    "workspace": {"root": (str,)},
    "http": {"timeout": (int, float), "max_redirects": (int,)},
    "stealth": {"enabled": (bool,), "rate_limit_rps": (int, float),
                "per_host_rps": (int, float)},
    "concurrency": {"recon_workers": (int,), "scanner_workers": (int,)},
    "recon": {"passive_only": (bool,)},
    "crawler": {"max_depth": (int,), "max_urls_per_host": (int,)},
    "scanners": {"enabled": (list,)},
    "reporting": {"format": (list,)},
    "memory": {},
}


def validate_config(cfg: dict[str, Any]) -> list[str]:
    """Return list of human-readable warnings/errors. Empty list = valid."""
    messages: list[str] = []

    for section, fields in REQUIRED_SECTIONS.items():
        if section not in cfg:
            messages.append(f"missing config section: [{section}]")
            continue
        sec = cfg[section]
        for field, expected_types in fields.items():
            if field not in sec:
                messages.append(f"[{section}].{field}: missing")
                continue
            val = sec[field]
            if not isinstance(val, expected_types):
                messages.append(
                    f"[{section}].{field}: expected {expected_types}, got {type(val).__name__}"
                )
                continue

    stealth = cfg.get("stealth", {})
    if stealth.get("rate_limit_rps", 6) <= 0:
        messages.append("[stealth].rate_limit_rps must be > 0")
    if stealth.get("per_host_rps", 2) <= 0:
        messages.append("[stealth].per_host_rps must be > 0")

    http = cfg.get("http", {})
    timeout = http.get("timeout", 20)
    if timeout < 1 or timeout > 120:
        messages.append(f"[http].timeout should be 1-120, got {timeout}")

    crawler = cfg.get("crawler", {})
    if crawler.get("max_depth", 3) < 0:
        messages.append("[crawler].max_depth must be >= 0")
    if crawler.get("max_urls_per_host", 1000) < 10:
        messages.append("[crawler].max_urls_per_host must be >= 10")

    scanners = cfg.get("scanners", {})
    enabled = scanners.get("enabled", [])
    from scanners import REGISTRY  # noqa: E402
    known = set(REGISTRY)
    unknown = [s for s in enabled if s not in known]
    if unknown:
        messages.append(f"[scanners].enabled: unknown scanners: {unknown}")

    reporting = cfg.get("reporting", {})
    fmt = reporting.get("format", [])
    for f in fmt:
        if f not in ("markdown", "pdf"):
            messages.append(f"[reporting].format: unknown format '{f}'")

    concurrency = cfg.get("concurrency", {})
    for key in ("recon_workers", "crawler_workers", "scanner_workers"):
        v = concurrency.get(key, 0)
        if v < 1 or v > 128:
            messages.append(f"[concurrency].{key} should be 1-128, got {v}")

    scan = cfg.get("scan", {})
    for key in ("scanner_timeout_seconds", "scanner_request_budget", "recheck_after_seconds"):
        value = scan.get(key, 1)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            messages.append(f"[scan].{key} must be a positive number")
    retries = scan.get("scanner_retries", 1)
    if type(retries) is not int or not 0 <= retries <= 2:
        messages.append("[scan].scanner_retries must be an integer from 0 to 2")
    limit = cfg.get("transport", {}).get("operation_budget", 100000)
    if type(limit) is not int or limit < 1:
        messages.append("[transport].operation_budget must be a positive integer")
    external = cfg.get("external_tools", {})
    for key in ("enabled", "verify_tls"):
        if key in external and type(external[key]) is not bool:
            messages.append(f"[external_tools].{key} must be a boolean")
    external_limit = external.get("request_budget", 250)
    for key in ("binary_dir", "nuclei_templates"):
        if key in external and not isinstance(external[key], str):
            messages.append(f"[external_tools].{key} must be a path string")
    if type(external_limit) is not int or external_limit < 1:
        messages.append("[external_tools].request_budget must be a positive integer")
    age = cfg.get("reporting", {}).get("evidence_max_age_seconds", 86400)
    if type(age) not in (int, float) or age <= 0:
        messages.append("[reporting].evidence_max_age_seconds must be positive")
    return messages
