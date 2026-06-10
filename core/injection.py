"""Centralized injection-point request builder.

Every param-injecting scanner used to re-implement the same two-line helper:
GET -> merge into the query string, POST -> stuff into form data. That meant
the tool only ever tested query params and form fields. Real targets carry
injectable data in path segments (`/users/123`), JSON request bodies, headers
and cookies too.

This module makes all of those first-class. A scanner asks to place `value`
at an injection point named `param`; the point's *kind* is encoded as a prefix
on the param string:

    "name"            query-string param (GET) or form/body field   [default]
    "path:N"          replace the Nth (0-indexed) URL path segment
    "json:a.b.c"      set a dotted key inside a JSON request body
    "header:X-Name"   inject into a request header
    "cookie:name"     inject into a request cookie

Plain names keep the original query/form behaviour, so existing scanners that
pass bare parameter names are unaffected. `send()` returns the same
HttpEvidence object `ctx.http` produces, so detection logic doesn't change.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlparse, urlunparse, quote

from .utils import merge_query, random_token

if TYPE_CHECKING:
    from .orchestrator import Context

_NUMERIC = re.compile(r"^\d{1,12}$")
_UUID = re.compile(r"^[0-9a-fA-F-]{8,36}$")
_HEXID = re.compile(r"^[0-9a-fA-F]{8,40}$")  # hashes / hex ids


def parse_point(param: str) -> tuple[str, str]:
    """Return (kind, locator). kind in {query, path, json, header, cookie}."""
    for prefix, kind in (("path:", "path"), ("json:", "json"),
                         ("header:", "header"), ("cookie:", "cookie")):
        if param.startswith(prefix):
            return kind, param[len(prefix):]
    return "query", param


def describe(param: str) -> str:
    """Human-readable label for reports."""
    kind, loc = parse_point(param)
    if kind == "query":
        return f"`{loc}`"
    return f"{kind} `{loc}`"


def _set_dotted(obj: dict, dotted: str, value: Any) -> None:
    cur = obj
    parts = dotted.split(".")
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _replace_path_segment(url: str, index: int, value: str) -> str:
    p = urlparse(url)
    segs = p.path.split("/")
    real = [i for i, s in enumerate(segs) if s != ""]
    if index >= len(real):
        return url
    segs[real[index]] = quote(value, safe="")
    return urlunparse(p._replace(path="/".join(segs)))


def _form_data(form: dict | None, override_param: str, value: str) -> dict:
    data = {i["name"]: i.get("value") or random_token(4)
            for i in (form or {}).get("inputs", []) if i.get("name")}
    data[override_param] = value
    return data


async def send(ctx: "Context", url: str, method: str, param: str, value: str,
               form: dict | None = None, *, http=None, **extra: Any) -> Any:
    """Inject *value* at injection point *param* and return HttpEvidence.

    *http* lets a caller route through the second session client (ctx.http2)
    for cross-tenant tests; defaults to ctx.http. Extra kwargs (e.g.
    ``allow_redirects=False``) are forwarded to the underlying request.
    """
    client = http or ctx.http
    kind, loc = parse_point(param)
    m = method.upper()

    if kind == "path":
        try:
            target = _replace_path_segment(url, int(loc), value)
        except (ValueError, TypeError):
            target = url
        return await client.request(m if m != "POST" else "GET", target, **extra)

    if kind == "json":
        body: dict = {}
        for i in (form or {}).get("inputs", []):
            if i.get("name"):
                body[i["name"]] = i.get("value") or ""
        _set_dotted(body, loc, value)
        verb = m if m in ("POST", "PUT", "PATCH", "DELETE") else "POST"
        return await client.request(verb, url, json_body=body,
                                    headers={"Content-Type": "application/json"}, **extra)

    if kind == "header":
        return await client.request(m, url, headers={loc: value}, **extra)

    if kind == "cookie":
        return await client.request(m, url, cookies={loc: value}, **extra)

    if m == "GET":
        return await client.get(merge_query(url, {loc: value}), **extra)
    return await client.request(m, url, data=_form_data(form, loc, value), **extra)


def candidate_points(url: str, params: list, form: dict | None = None,
                     method: str = "GET", *, max_path: int = 6) -> list:
    """Expand a base param list with path-segment injection points the crawler
    can't see as query params. Query/form params are returned unchanged;
    id-shaped path segments are appended as `path:N`. Order-preserving, deduped.
    """
    out = list(dict.fromkeys(params))
    p = urlparse(url)
    real_segs = [s for s in p.path.split("/") if s != ""]
    added = 0
    for idx, seg in enumerate(real_segs):
        if added >= max_path:
            break
        if "." in seg:
            continue
        # only id-shaped segments — numeric, UUID, or hex hash. Fuzzing
        # word segments like "users"/"v1" rarely pays and multiplies load.
        if _NUMERIC.match(seg) or _UUID.match(seg) or _HEXID.match(seg):
            out.append(f"path:{idx}")
            added += 1
    return out


def looks_numeric_or_id(value: str) -> bool:
    return bool(_NUMERIC.match(value) or _UUID.match(value))
