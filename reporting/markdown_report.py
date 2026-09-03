"""Render finding bundles to Markdown via Jinja2.

Two templates ship out of the box:
    * `report.md.j2`     — full SamaritanX report (executive + appendices)
    * `hackerone.md.j2`  — single-finding HackerOne-style submission
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.constants import CWE_MAP


_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def cwe_for(category: str) -> tuple[str, str]:
    """(CWE id, weakness name) for a finding category."""
    return CWE_MAP.get(category or "", ("", ""))


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape([]),
        trim_blocks=True, lstrip_blocks=True,
    )


def render_markdown(bundle: dict[str, Any]) -> str:
    tpl = _env().get_template("report.md.j2")
    bundle.setdefault("generated_at", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
    return tpl.render(**bundle)


def render_hackerone(finding: dict[str, Any], operator: str) -> str:
    tpl = _env().get_template("hackerone.md.j2")
    cwe, weakness = cwe_for(finding.get("category", ""))
    summary = finding.get("evidence") or finding.get("title") or ""
    if cwe:
        weakness = f"{weakness} ({cwe})"
    return tpl.render(
        f=finding, operator=operator, weakness=weakness, summary=summary,
        generated_at=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    )
