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

    return messages
