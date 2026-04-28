"""Render a finding bundle to Markdown via Jinja2."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def render_markdown(bundle: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape([]),  # markdown — escaping interferes
        trim_blocks=True, lstrip_blocks=True,
    )
    tpl = env.get_template("report.md.j2")
    bundle.setdefault("generated_at", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
    return tpl.render(**bundle)
