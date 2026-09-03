"""Insecure deserialization probe.

Detection-only — never sends an actual RCE gadget at a real target. The
goal is to surface candidates for *manual* gadget chain construction.

Signals:
  * any Cookie / form parameter / hidden input value that looks like a
    serialized blob:
        - PHP serialize:  starts with `O:`, `a:`, `s:`, `i:`
        - Java serialize: base64 begins `rO0AB`, raw begins `\\xac\\xed`
        - Python pickle:  base64 begins `gASV` / `gAJ` (0x80,0x04 / 0x80,0x02)
        - Ruby Marshal:   begins `\\x04\\x08`
        - .NET BinaryFormatter: base64 begins `AAEAAAD/////`
        - YAML w/ Python tags: contains `!!python/object`
        - Phar:           magic `__HALT_COMPILER` near end of file
  * an HTTP response header named `X-Sucuri-Cache` / `X-Powered-By: Express`
    that hints at frameworks notorious for RCE-via-deserialization
"""
from __future__ import annotations

import base64
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.orchestrator import Context

PHP_SER_RE   = re.compile(r"^[Oa]:\d+:\"")
JAVA_B64_RE  = re.compile(r"^rO0AB[A-Za-z0-9+/=]{20,}")
JAVA_RAW_RE  = re.compile(rb"\xac\xed\x00\x05")
# protocol 0/1: gAJx… (0x80 0x02), protocol 4: gASV (0x80 0x04),
# protocol 5: gAV (0x80 0x05)
PY_PKL_B64   = re.compile(r"^gA(?:Jx|J[A-Za-z0-9+/=]|SV|V)[A-Za-z0-9+/=]{8,}")
RUBY_RE      = re.compile(rb"\x04\x08")
NET_BF_RE    = re.compile(r"^AAEAAAD/////[A-Za-z0-9+/=]{20,}")
YAML_PY_RE   = re.compile(r"!!python/object")
PHAR_RE      = re.compile(rb"__HALT_COMPILER")


def _classify(value: str) -> str | None:
    if not value:
        return None
    raw = value
    if PHP_SER_RE.match(value):
        return "php_serialize"
    if JAVA_B64_RE.match(value):
        return "java_serialize_b64"
    if PY_PKL_B64.match(value):
        return "python_pickle_b64"
    if NET_BF_RE.match(value):
        return "net_binaryformatter_b64"
    if YAML_PY_RE.search(value):
        return "yaml_python_tag"
    # try base64-decode for raw java / ruby / phar
    try:
        decoded = base64.b64decode(value, validate=False)
        if JAVA_RAW_RE.match(decoded):
            return "java_serialize_raw"
        if decoded.startswith(b"\x04\x08"):
            return "ruby_marshal"
        if PHAR_RE.search(decoded):
            return "phar_payload"
    except Exception:
        pass
    return None


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    seen: set[str] = set()

    # 1) inspect the live response — cookies + headers + body fragments
    ev = await ctx.http.get(url)
    sources: list[tuple[str, str]] = []
    for k, v in (ev.response_headers or {}).items():
        if k.lower() == "set-cookie":
            for piece in str(v).split(";"):
                if "=" in piece:
                    name, val = piece.strip().split("=", 1)
                    sources.append((f"cookie:{name}", val))
    for inp in (form or {}).get("inputs", []):
        v = inp.get("value")
        if v:
            sources.append((f"form:{inp.get('name')}", v))

    for where, value in sources:
        kind = _classify(value)
        if not kind:
            continue
        key = f"{where}|{kind}"
        if key in seen:
            continue
        seen.add(key)
        # Severity is medium (not critical) — we only detect a likely sink,
        # not exploitation. RCE confirmation requires gadget chains.
        findings.append({
            "category": "deserialization",
            "title": f"Suspected serialized payload in {where} ({kind})",
            "severity": "medium", "cvss": 6.5,
            "url": url, "parameter": where, "payload": value[:120],
            "evidence": f"Value matches a {kind} format. Manual gadget-chain crafting "
                        "(e.g. ysoserial / phpggc / pickle.loads RCE) is required to confirm "
                        "exploitability — flag for human review.",
            "request": f"GET {url}",
            "response": (ev.response_body or "")[:600],
            "metadata": {"format": kind, "where": where},
        })
    return findings
