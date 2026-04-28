"""Markdown -> HTML -> PDF rendering.

Uses python-markdown for HTML conversion and weasyprint for PDF. Falls back
gracefully when weasyprint can't load its native dependencies (common on
Windows without GTK) — the markdown report is always written even if PDF
fails so the operator never loses output.
"""
from __future__ import annotations

from pathlib import Path

import markdown as md


PDF_CSS = """
@page { size: A4; margin: 18mm 14mm; }
body  { font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
        font-size: 10pt; line-height: 1.45; color: #16161d; }
h1, h2, h3 { color: #0a3d62; page-break-after: avoid; }
h1 { border-bottom: 2px solid #0a3d62; padding-bottom: 4px; }
h2 { border-bottom: 1px solid #ccc; padding-bottom: 2px; margin-top: 22pt; }
code, pre { font-family: "JetBrains Mono", Menlo, Consolas, monospace;
            font-size: 9pt; background: #f6f8fa; }
pre { padding: 8px; border-radius: 4px; overflow-x: auto;
      page-break-inside: avoid; white-space: pre-wrap; word-break: break-word; }
table { border-collapse: collapse; width: 100%; margin: 8pt 0; }
th, td { border: 1px solid #cdd0d4; padding: 4px 8px; text-align: left; }
th { background: #eef3f8; }
"""


def render_pdf(markdown_text: str, output_path: str | Path) -> bool:
    try:
        from weasyprint import HTML, CSS
    except Exception:
        return False
    html = md.markdown(markdown_text, extensions=["tables", "fenced_code", "toc"])
    html_doc = f"<!doctype html><html><body>{html}</body></html>"
    try:
        HTML(string=html_doc).write_pdf(str(output_path), stylesheets=[CSS(string=PDF_CSS)])
        return True
    except Exception:
        return False
