"""Versioned redacted evidence bundles with integrity hashes and bounded traces.

Digests detect modification; they do not certify that a detector's claim is true.
Raw response content remains private runtime data until explicitly exported.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from contextvars import ContextVar
from pathlib import Path
from urllib.parse import quote


capture = ContextVar("evidence_capture", default=None)
_SECRET_KEY = re.compile(r"authorization|cookie|password|passwd|secret|token|api[_-]?key", re.I)
_INLINE = re.compile(r'(?im)((?:authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+')
_VALUE = re.compile(r'''(?i)((?:password|passwd|secret|access_token|refresh_token|api_key|token)["']?\s*[:=]\s*["']?)[^&\s"'<>,}]+''')


def _secret_variants(secrets) -> list[str]:
    """Known secrets plus their supported encoded forms (percent single/double)."""
    variants: set[str] = set()
    for secret in secrets:
        text = str(secret)
        if not text or len(text) < 4:
            continue
        variants.add(text)
        encoded = quote(text, safe="")
        variants.add(encoded)
        variants.add(quote(encoded, safe=""))
    return sorted(variants, key=len, reverse=True)


def redact(value, secrets=()):
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if _SECRET_KEY.search(str(k)) else redact(v, secrets)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        value = _INLINE.sub(r"\1[REDACTED]", value)
        value = _VALUE.sub(r"\1[REDACTED]", value)
        value = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", value)
        for secret in _secret_variants(secrets):
            value = value.replace(secret, "[REDACTED]")
    return value


def observe(ev):
    trace = capture.get()
    if trace is None:
        return
    trace.append({"captured_at": time.time(), "method": ev.method, "url": ev.url,
                  "identity": ev.extra.get("identity", "unknown"),
                  "request_headers": ev.request_headers, "request_body": ev.request_body,
                  "status": ev.status, "response_headers": ev.response_headers,
                  "response_excerpt": (ev.response_body or "")[:4000], "error": ev.error})
    if len(trace) > 64:
        del trace[8:-56]


def write_bundle(directory, finding, *, trace=(), identity=None, secrets=()):
    content = redact({"schema_version": 1, "recorded_at": time.time(),
                      "finding_id": finding.get("id") or finding.get("_id"),
                      "category": finding.get("category"), "url": finding.get("url"),
                      "identity": identity, "proof": (finding.get("metadata") or {}).get("poc"),
                      "request": finding.get("request"), "response": finding.get("response"),
                      "observations": list(trace),
                      "rationale": finding.get("evidence")}, secrets)
    raw = json.dumps(content, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    digest = hashlib.sha256(raw).hexdigest()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (digest + ".json")
    with path.open("xb") as stream:
        stream.write(raw)
    return {"schema_version": 1, "sha256": digest, "file": str(path),
            "recorded_at": content["recorded_at"], "redacted": True}


def verify_bundle(path, expected):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected


def capture_finding(ctx, finding):
    sessions = [getattr(ctx, "session", None)]
    sessions += [getattr(getattr(ctx, "http2", None), "session", None)]
    secrets = []
    for session in sessions:
        if session:
            secrets.extend(getattr(session, "cookies", {}).values())
            secrets.extend(v for k, v in getattr(session, "headers", {}).items() if _SECRET_KEY.search(k))
    return write_bundle(ctx.workspace / "evidence", finding, trace=capture.get() or [],
                        identity=getattr(sessions[0], "label", "anonymous"), secrets=secrets)
