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


_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

CWE_MAP = {
    "sqli": ("CWE-89", "SQL Injection"),
    "xss": ("CWE-79", "Cross-site Scripting"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "rce": ("CWE-78", "OS Command Injection"),
    "ssti": ("CWE-94", "Code Injection / SSTI"),
    "idor": ("CWE-639", "Authorization Bypass / BOLA"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery"),
    "upload": ("CWE-434", "Unrestricted File Upload"),
    "open_redirect": ("CWE-601", "URL Redirection to Untrusted Site"),
    "cors": ("CWE-942", "Permissive Cross-domain Policy"),
    "cache_poisoning": ("CWE-444", "Inconsistent Interpretation of HTTP Requests"),
    "smuggling": ("CWE-444", "HTTP Request Smuggling"),
    "websocket": ("CWE-1385", "Cross-Site WebSocket Hijacking"),
    "api": ("CWE-285", "Improper Authorization"),
    "prompt_injection": ("CWE-1039", "Inadequate Detection or Handling of AI Manipulation"),
    "takeover": ("CWE-350", "Reliance on Reverse DNS for Authorization"),
    "exposure": ("CWE-200", "Exposure of Sensitive Information"),
    "secret_exposure": ("CWE-798", "Use of Hard-coded Credentials"),
    "broken_auth": ("CWE-287", "Improper Authentication"),
    "race_condition": ("CWE-362", "Concurrent Execution / Race"),
    "graphql_introspection": ("CWE-200", "Information Exposure via GraphQL"),
    "graphql": ("CWE-770", "Allocation of Resources Without Limits / GraphQL"),
    "oauth": ("CWE-601", "OAuth / OIDC Misconfiguration"),
    "logic": ("CWE-840", "Business Logic Errors"),
    "nosqli": ("CWE-943", "NoSQL Injection"),
    "web_cache_deception": ("CWE-525", "Web Cache Deception"),
    "account_takeover": ("CWE-640", "Weak Password Recovery / Account Takeover"),
    "chain": ("CWE-693", "Protection Mechanism Failure (vulnerability chain)"),
    "prototype_pollution": ("CWE-1321", "Prototype Pollution"),
}


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
    cwe, weakness = CWE_MAP.get(finding.get("category", ""), ("", finding.get("category", "")))
    summary = finding.get("evidence") or finding.get("title") or ""
    if cwe:
        weakness = f"{weakness} ({cwe})"
    return tpl.render(
        f=finding, operator=operator, weakness=weakness, summary=summary,
        generated_at=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    )
