"""Manual-escalation handoff files for SQL-class findings.

For every verified SQLi / NoSQLi finding the reporting agent writes two
copy-paste artifacts into ``reports/handoff/``:

  * ``<category>_<id>.sqlmap.txt`` — a ready sqlmap command (GET or POST,
    risk level tuned to the detection oracle)
  * ``<category>_<id>.request``  — the raw HTTP request in Burp Repeater
    format (request line, headers, blank line, body) with the payload in place

Pure string builders — unit-tested offline.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .injection import parse_point
from .utils import merge_query


def _method(finding: dict[str, Any]) -> str:
    req = (finding.get("request") or "").strip()
    if req:
        head = req.split(None, 1)[0].upper()
        if head in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
            return head
    return (finding.get("metadata") or {}).get("method") or "GET"


def _target_url(finding: dict[str, Any]) -> str:
    url = finding.get("url") or ""
    param = finding.get("parameter") or ""
    payload = finding.get("payload") or ""
    kind, loc = parse_point(param) if ":" in param else ("query", param)
    if kind == "query" and loc and payload and not loc.startswith("("):
        return merge_query(url, {loc: payload})
    return url


def build_burp_request(finding: dict[str, Any]) -> str:
    """Raw HTTP/1.1 request with the payload injected (Burp-pasteable)."""
    method = _method(finding)
    url = _target_url(finding)
    p = urlparse(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    host = p.netloc
    param = finding.get("parameter") or ""
    payload = finding.get("payload") or ""
    kind, loc = parse_point(param) if ":" in param else ("query", param)

    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    body = ""
    if method in ("POST", "PUT", "PATCH") and kind == "query" and loc and payload:
        body = f"{loc}={payload}"
        lines += ["Content-Type: application/x-www-form-urlencoded"]
    elif kind == "json" and payload:
        from .injection import _set_dotted
        import json as _json
        nested: dict = {}
        _set_dotted(nested, loc, payload)
        body = _json.dumps(nested)
        lines += ["Content-Type: application/json"]
    extra = (finding.get("request") or "").splitlines()[1:]
    seen = {l.split(":", 1)[0].lower() for l in lines if ":" in l}
    for h in extra:
        if ":" in h and not h.startswith(("GET ", "POST ", "PUT ")):
            name = h.split(":", 1)[0].lower()
            if name not in seen:
                lines.append(h)
                seen.add(name)
    if body:
        lines += ["Content-Length: " + str(len(body.encode()))]
    lines += ["", body]
    return "\r\n".join(lines)


def build_sqlmap_command(finding: dict[str, Any]) -> str:
    """A ready-to-run sqlmap command matching the recorded injection point."""
    method = _method(finding)
    url = finding.get("url") or ""
    param = finding.get("parameter") or ""
    payload = finding.get("payload") or ""
    kind, loc = parse_point(param) if ":" in param else ("query", param)
    detection = (finding.get("metadata") or {}).get("detection") or ""
    risk = "3" if detection == "time" else "2"

    parts = ["sqlmap", "-u", f'"{url}"', "--batch"]
    if method in ("POST", "PUT", "PATCH") and kind == "query" and loc and payload:
        parts += ["--data", f'"{loc}={payload}*"', "-p", loc]
    elif method == "GET" and kind == "query" and loc and payload:
        parts += ["-p", loc]
    elif kind == "json":
        parts += ["--data", f'"{payload}"', "--prefix=", "--suffix="]
    parts += [f"--level=5 --risk={risk}", "--random-agent"]
    if detection == "time":
        parts += ["--time-sec=10"]
    return " ".join(parts)


def write_handoffs(findings: list[dict[str, Any]], out_dir: Path) -> int:
    """Write handoff artifacts for verified SQL-class findings. Returns count."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for f in findings:
        cat = (f.get("category") or "").lower()
        if cat not in ("sqli", "nosqli"):
            continue
        fid = f.get("id", n)
        base = out_dir / f"{cat}_{fid}"
        try:
            (out_dir / f"{cat}_{fid}.sqlmap.txt").write_text(
                build_sqlmap_command(f) + "\n", encoding="utf-8")
            (out_dir / f"{cat}_{fid}.request").write_text(
                build_burp_request(f) + "\r\n", encoding="utf-8")
            n += 1
        except Exception:
            continue
    return n
