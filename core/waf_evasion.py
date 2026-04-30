"""WAF evasion transformations applied to payloads at scan time.

Covers two classes of evasion:

  * **Payload-level transforms** (case_swap, comment_injection,
    unicode_encoding, double_url_encoding, encoding_chain, ...) — these
    mutate the *string* that lands in a parameter / header value.

  * **Transport-level mutations** (content_type_confusion,
    json_in_get, h2_pseudo_header, multipart_boundary) — these change
    *how* the payload is delivered. Scanners that opt-in receive a list
    of (payload, transport_hints) tuples and pick the best transport
    available to them.

The transport layer matters because modern WAFs (Cloudflare Workers,
AWS WAF Advanced, Akamai Kona) inspect the parsed body shape — not the
raw bytes — so the same payload behaves differently when wrapped in a
multipart boundary vs sent as JSON in a GET query parameter.
"""
from __future__ import annotations

import html
import random
import urllib.parse
from typing import Callable, Iterable


# ---------- payload-level transforms --------------------------------------

def _case_swap(payload: str) -> str:
    return "".join(c.swapcase() if c.isalpha() and random.random() < 0.4 else c for c in payload)


def _comment_injection(payload: str) -> str:
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


def _encoding_chain(payload: str) -> str:
    """URL-encode → Unicode escape → HTML entity, applied in sequence.

    This three-stage chain often slips through WAFs that decode each layer
    once but only inspect the result of a single layer of decoding."""
    # Stage 1 — URL encode every non-alphanumeric byte
    s1 = "".join(f"%{ord(c):02X}" if not c.isalnum() else c for c in payload)
    # Stage 2 — for selected chars, swap to Unicode escape
    s2 = []
    for c in s1:
        if c == "<":
            s2.append("\\u003c")
        elif c == ">":
            s2.append("\\u003e")
        elif c == '"':
            s2.append("\\u0022")
        else:
            s2.append(c)
    s2_str = "".join(s2)
    # Stage 3 — HTML-entity-encode any < or > that survived
    return s2_str.replace("<", "&lt;").replace(">", "&gt;")


def _parameter_pollution_marker(payload: str) -> str:
    return payload + "&__sx=1"


def _chunked_marker(payload: str) -> str:
    return payload  # transport-layer hint, handled by smuggling code


def _utf16_overlong(payload: str) -> str:
    """Encode `<`, `>`, `"`, `'` as UTF-8 over-long sequences. Most WAFs
    decode UTF-8 correctly but some still don't normalize over-long forms."""
    out = []
    for c in payload:
        if c == "<":
            out.append("%C0%BC")
        elif c == ">":
            out.append("%C0%BE")
        elif c == '"':
            out.append("%C0%A2")
        elif c == "'":
            out.append("%C0%A7")
        else:
            out.append(c)
    return "".join(out)


_TECHNIQUES: dict[str, Callable[[str], str]] = {
    "case_swap": _case_swap,
    "comment_injection": _comment_injection,
    "unicode_encoding": _unicode_encoding,
    "double_url_encoding": _double_url_encoding,
    "encoding_chain": _encoding_chain,
    "utf8_overlong": _utf16_overlong,
    "parameter_pollution": _parameter_pollution_marker,
    "chunked_transfer": _chunked_marker,
}


def evade(payload: str, techniques: Iterable[str]) -> list[str]:
    """Yield evasion variants of *payload* using configured payload-level transforms."""
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


# ---------- transport-level mutations -------------------------------------

def transport_variants(payload: str, *, param: str = "q") -> list[dict]:
    """Return a list of {payload, headers, body_kind, body, query} dicts
    describing alternative HTTP transport shapes that smuggle the same
    payload past content-aware WAFs.

    Scanners receive these as *hints* — not every endpoint accepts every
    transport, so the scanner picks the ones that fit (e.g. only swap to
    JSON if the original content-type was JSON / form-urlencoded)."""
    variants: list[dict] = []

    # 1) JSON-in-GET — wrap the value in a JSON object inside the query string.
    #    Some Express / Fastify routers happily JSON-decode this.
    variants.append({
        "name": "json_in_get",
        "method": "GET",
        "headers": {"Content-Type": "application/json"},
        "query": {param: '{"v":"' + payload.replace('"', '\\"') + '"}'},
        "body": None,
    })

    # 2) Multipart with attacker-controlled boundary tricks.
    #    Some WAFs inspect only the first part; others mishandle CRLF in
    #    the boundary value.
    boundary = "----SXBoundary"
    body = (f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"{param}\"\r\n\r\n"
            f"benign\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"{param}\"\r\n"
            f"Content-Type: text/plain\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--\r\n")
    variants.append({
        "name": "multipart_boundary_dual",
        "method": "POST",
        "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        "body": body,
        "query": None,
    })

    # 3) Content-Type confusion — send the JSON-shaped payload but with
    #    text/plain header, or vice versa. Some WAFs select the parser
    #    based on header alone, missing the actual injection vector.
    variants.append({
        "name": "content_type_text_plain_json",
        "method": "POST",
        "headers": {"Content-Type": "text/plain"},
        "body": '{"' + param + '":"' + payload.replace('"', '\\"') + '"}',
        "query": None,
    })

    # 4) HTTP/2 pseudo-header injection hint — instructs the scanner to
    #    deliver the payload via a forged :path / :authority pseudo-header.
    #    The scanner that consumes this needs an h2-capable transport.
    variants.append({
        "name": "h2_pseudo_header",
        "method": "GET",
        "headers": {":path": payload, ":authority": "evil.samaritanx.test"},
        "body": None,
        "query": None,
        "h2_only": True,
    })

    # 5) Trailing-header smuggling — some intermediaries drop trailers
    #    and the upstream parses them as request headers
    variants.append({
        "name": "trailer_smuggling",
        "method": "POST",
        "headers": {"Transfer-Encoding": "chunked",
                    "Trailer": f"X-SX-{param}",
                    "Content-Type": "text/plain"},
        "body": f"5\r\nhello\r\n0\r\nX-SX-{param}: {payload}\r\n\r\n",
        "query": None,
    })
    return variants


def pollute_params(params: dict[str, str], target_key: str, value: str) -> list[tuple[str, str]]:
    """Build a parameter-pollution variant: the same key appearing twice."""
    out = [(k, v) for k, v in params.items() if k != target_key]
    out.append((target_key, "ok"))
    out.append((target_key, value))
    return out
