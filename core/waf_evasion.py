"""WAF evasion transformations applied to payloads at scan time."""
from __future__ import annotations

import random
import urllib.parse
from typing import Callable, Iterable


def _case_swap(payload: str) -> str:
    return "".join(c.swapcase() if c.isalpha() and random.random() < 0.4 else c for c in payload)


def _comment_injection(payload: str) -> str:
    # Insert SQL/HTML-style inline comments to break naive signature matches.
    if "SELECT" in payload.upper():
        return payload.replace("SELECT", "SE/**/LECT").replace("UNION", "UNI/**/ON")
    if "<script" in payload.lower():
        return payload.replace("<script", "<scr/**/ipt", 1)
    return payload


def _unicode_encoding(payload: str) -> str:
    out = []
    for c in payload:
        if c.isascii() and c.isalpha() and random.random() < 0.2:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(c)
    return "".join(out)


def _double_url_encoding(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def _parameter_pollution_marker(payload: str) -> str:
    # Encoded as a hint — actual pollution is inserted by the scanner that
    # consumes this transform via pollute_params() below.
    return payload + "&__sx=1"


def _chunked_marker(payload: str) -> str:
    # Hint to the HTTP layer to send Transfer-Encoding: chunked when supported.
    return payload  # the actual chunking is handled at transport level


_TECHNIQUES: dict[str, Callable[[str], str]] = {
    "case_swap": _case_swap,
    "comment_injection": _comment_injection,
    "unicode_encoding": _unicode_encoding,
    "double_url_encoding": _double_url_encoding,
    "parameter_pollution": _parameter_pollution_marker,
    "chunked_transfer": _chunked_marker,
}


def evade(payload: str, techniques: Iterable[str]) -> list[str]:
    """Yield evasion variants of *payload* using the configured techniques."""
    variants = {payload}
    for name in techniques:
        fn = _TECHNIQUES.get(name)
        if not fn:
            continue
        try:
            variants.add(fn(payload))
        except Exception:
            continue
    return list(variants)


def pollute_params(params: dict[str, str], target_key: str, value: str) -> list[tuple[str, str]]:
    """Build a parameter-pollution variant: the same key appearing twice."""
    out = [(k, v) for k, v in params.items() if k != target_key]
    out.append((target_key, "ok"))
    out.append((target_key, value))
    return out
