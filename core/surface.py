"""API surface discovery — turn OpenAPI/Swagger specs, JavaScript bundles,
and JSON response shapes into concrete injection points.

The crawler only ever sees query params, HTML forms, and id-shaped path
segments. The targets that pay *critical* (JSON APIs, SPAs, mobile backends)
carry their injectable data in request **bodies** and reference their
endpoints only from JavaScript — so those endpoints reach the scanners with
zero injection points and the SSRF / SQLi / RCE / BOLA logic never fires. This
module closes that gap.

Everything here is best-effort and bounded. The pure parsers
(`parse_openapi`, `mine_js_text`, `synthesize_json_points`) take strings and
return plain data so they can be unit-tested offline; the `discover_*`
coroutines wrap them with network I/O. Injection-point strings use the same
prefix grammar as :mod:`core.injection` — ``json:a.b``, ``path:N``, or a bare
query/form name.
"""
from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse, urlunparse

from .utils import host_of, normalize_url, root_domain

if TYPE_CHECKING:
    from .orchestrator import Context

# Spec locations worth probing on an unknown host. Ordered cheap → rich.
SPEC_PATHS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger/v1/swagger.json",
    "/api/swagger.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/openapi.json", "/api/v1/openapi.json", "/.well-known/openapi.json",
    "/swagger/v1/swagger.yaml",
)

# A path template placeholder gets a concrete dummy so the URL is requestable.
_PLACEHOLDER = re.compile(r"^\{.+\}$")
# String literals that look like server paths inside a JS bundle. The optional
# trailing group keeps any ?query=... so param names can be harvested.
_QS = r"""(?:\?[A-Za-z0-9_=&%.+\-]{0,200})?"""
_JS_PATH = re.compile(
    r"""['"`](/(?:api|v\d|graphql|rest|internal|auth|users?|account|admin)"""
    r"""[A-Za-z0-9_./{}\-]{0,118}""" + _QS + r""")['"`]""")
# Generic absolute-path literals (broader net, filtered hard afterwards).
_JS_ANY_PATH = re.compile(
    r"""['"`](/[A-Za-z0-9_\-]+(?:/[A-Za-z0-9_./{}\-]+){1,8}""" + _QS + r""")['"`]""")
_JS_QUERY_KEY = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,30})=")
_STATIC_EXT = re.compile(r"\.(?:js|mjs|css|png|jpe?g|gif|svg|woff2?|ttf|ico|map|webp|mp4|json)(?:$|[?#])", re.I)
_BORING = re.compile(r"^/(?:assets?|static|dist|build|fonts?|images?|img|css|js|node_modules)/", re.I)


# --------------------------------------------------------------------------- #
# OpenAPI / Swagger
# --------------------------------------------------------------------------- #
def _spec_base(spec: dict, doc_url: str) -> str:
    """Resolve the base URL operations hang off, for both v3 and v2 specs."""
    # OpenAPI v3
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        su = (servers[0].get("url") or "").strip()
        if su:
            return urljoin(doc_url, su).rstrip("/")
    # Swagger v2
    if spec.get("swagger"):
        host = spec.get("host")
        base_path = spec.get("basePath") or ""
        schemes = spec.get("schemes") or [urlparse(doc_url).scheme or "https"]
        if host:
            return f"{schemes[0]}://{host}{base_path}".rstrip("/")
        return urljoin(doc_url, base_path or "/").rstrip("/")
    # Fall back to the document's own origin.
    p = urlparse(doc_url)
    return urlunparse((p.scheme, p.netloc, "", "", "", "")).rstrip("/")


def _body_props(spec: dict, operation: dict) -> list[str]:
    """Extract request-body property names (v3 requestBody or v2 in:body)."""
    props: list[str] = []
    # OpenAPI v3
    rb = operation.get("requestBody")
    if isinstance(rb, dict):
        for ctype, media in (rb.get("content") or {}).items():
            if not isinstance(media, dict):
                continue
            schema = media.get("schema") or {}
            props.extend(_schema_props(schema))
    # Swagger v2 — a parameter with in:body carries the schema
    for param in operation.get("parameters") or []:
        if isinstance(param, dict) and param.get("in") == "body":
            props.extend(_schema_props(param.get("schema") or {}))
    # de-dup, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for p in props:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out[:12]


def _schema_props(schema: dict) -> list[str]:
    if not isinstance(schema, dict):
        return []
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        schema = schema["items"]
    props = schema.get("properties")
    if isinstance(props, dict):
        return [k for k in props.keys() if isinstance(k, str)]
    return []


def _concrete_path(template: str) -> tuple[str, list[int]]:
    """Turn '/users/{id}/posts/{pid}' into ('/users/1/posts/1', [0-based path
    indices of the placeholders])."""
    segs = [s for s in template.split("/") if s != ""]
    path_indices: list[int] = []
    concrete: list[str] = []
    for i, s in enumerate(segs):
        if _PLACEHOLDER.match(s):
            path_indices.append(i)
            concrete.append("1")
        else:
            concrete.append(s)
    return "/" + "/".join(concrete), path_indices


def parse_openapi(spec: dict, doc_url: str, *, max_ops: int = 80) -> list[dict]:
    """Pure parser: OpenAPI v3 / Swagger v2 dict -> list of scan-task dicts.

    Each operation yields up to two tasks: a GET task carrying query + path
    injection points, and (when the operation has a request body) a task using
    the operation's verb carrying ``json:`` body points. Bounded by *max_ops*.
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _spec_base(spec, doc_url)
    tasks: list[dict] = []
    ops = 0
    for template, item in paths.items():
        if ops >= max_ops or not isinstance(item, dict) or not isinstance(template, str):
            continue
        concrete, path_indices = _concrete_path(template)
        full_url = normalize_url(base + concrete)
        for verb, operation in item.items():
            if verb.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if not isinstance(operation, dict):
                continue
            ops += 1
            verb_u = verb.upper()
            query_pts = [p["name"] for p in (operation.get("parameters") or [])
                         if isinstance(p, dict) and p.get("in") == "query" and p.get("name")]
            path_pts = [f"path:{i}" for i in path_indices]
            body_pts = [f"json:{p}" for p in _body_props(spec, operation)]

            get_pts = query_pts + path_pts
            if get_pts:
                tasks.append({"url": full_url, "method": "GET", "params": get_pts,
                              "source": "openapi"})
            if body_pts and verb_u in ("POST", "PUT", "PATCH", "DELETE"):
                tasks.append({"url": full_url, "method": verb_u, "params": body_pts,
                              "source": "openapi"})
            if ops >= max_ops:
                break
    return tasks


async def discover_openapi(ctx: "Context", base_url: str) -> list[dict]:
    """Probe well-known spec locations under the host and parse the first hit."""
    origin = _origin(base_url)
    seen_root = root_domain(host_of(base_url))
    for rel in SPEC_PATHS:
        probe = origin + rel
        ev = await ctx.http.get(probe)
        if ev.status != 200 or not ev.response_body:
            continue
        body = ev.response_body.strip()
        spec = _load_spec(body)
        if not spec or "paths" not in spec:
            continue
        tasks = parse_openapi(spec, probe)
        # keep everything inside the registered domain
        tasks = [t for t in tasks if root_domain(host_of(t["url"])) == seen_root]
        if tasks:
            ctx.dashboard.event("ok",
                f"surface: OpenAPI at {probe} -> {len(tasks)} injectable operations")
            return tasks
    return []


def _load_spec(body: str) -> dict | None:
    try:
        return json.loads(body)
    except Exception:
        pass
    try:
        import yaml
        data = yaml.safe_load(body)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# JavaScript endpoint mining
# --------------------------------------------------------------------------- #
def mine_js_text(js: str, base_url: str, *, max_endpoints: int = 60) -> list[tuple[str, list[str]]]:
    """Pure miner: extract (absolute_url, query_param_names) tuples from a JS
    bundle. Filters out static-asset and obviously-cosmetic paths so the
    scanners only get plausible server endpoints."""
    if not js:
        return []
    seed_root = root_domain(host_of(base_url))
    found: dict[str, list[str]] = {}
    candidates = set()
    for m in _JS_PATH.finditer(js):
        candidates.add(m.group(1))
    for m in _JS_ANY_PATH.finditer(js):
        candidates.add(m.group(1))

    for path in candidates:
        if len(found) >= max_endpoints:
            break
        raw = path.split("#", 1)[0]
        clean = raw.split("?", 1)[0]
        if not clean or _STATIC_EXT.search(raw) or _BORING.match(clean):
            continue
        # require an api-ish shape or an embedded query to be worth testing
        api_ish = bool(re.search(r"/(api|v\d|graphql|rest|internal|auth)/", clean)
                       or re.search(r"/\d+(?:/|$)", clean))
        qkeys = _JS_QUERY_KEY.findall(raw)
        if not api_ish and not qkeys:
            continue
        url = normalize_url(urljoin(base_url, clean))
        if root_domain(host_of(url)) != seed_root:
            continue
        # de-dup query keys, preserve order
        seen: set[str] = set()
        qp = [k for k in qkeys if not (k in seen or seen.add(k))]
        found[url] = qp
    return list(found.items())


async def discover_js_endpoints(ctx: "Context", script_urls: list[str], base_url: str,
                                *, max_scripts: int = 25) -> list[dict]:
    """Fetch (a bounded set of) JS bundles, mine endpoints, return scan tasks."""
    from .injection import candidate_points
    tasks: list[dict] = []
    emitted: set[str] = set()
    for src in list(dict.fromkeys(script_urls))[:max_scripts]:
        ev = await ctx.http.get(src)
        if ev.status != 200 or not ev.response_body:
            continue
        for url, qkeys in mine_js_text(ev.response_body, base_url):
            points = candidate_points(url, qkeys)
            if not points:
                continue
            key = url + "|" + ",".join(points)
            if key in emitted:
                continue
            emitted.add(key)
            tasks.append({"url": url, "method": "GET", "params": points, "source": "js"})
    if tasks:
        ctx.dashboard.event("ok",
            f"surface: mined {len(tasks)} endpoint(s) from {min(len(script_urls), max_scripts)} JS bundle(s)")
    return tasks


# --------------------------------------------------------------------------- #
# JSON response-shape synthesis
# --------------------------------------------------------------------------- #
def synthesize_json_points(body_text: str, *, max_keys: int = 15) -> list[str]:
    """Given a JSON object response, return ``json:`` injection points for its
    top-level scalar keys. A REST endpoint that *returns* a model usually
    *accepts* the same fields on POST/PUT — so its response shape is a free map
    of the request body's injectable fields."""
    if not body_text:
        return []
    try:
        data = json.loads(body_text)
    except Exception:
        return []
    if isinstance(data, list):
        data = next((x for x in data if isinstance(x, dict)), None)
    if not isinstance(data, dict):
        return []
    points: list[str] = []
    for k, v in data.items():
        if not isinstance(k, str):
            continue
        if isinstance(v, (str, int, float, bool)) or v is None:
            points.append(f"json:{k}")
        if len(points) >= max_keys:
            break
    return points


# --------------------------------------------------------------------------- #
def _origin(url: str) -> str:
    p = urlparse(normalize_url(url))
    return urlunparse((p.scheme, p.netloc, "", "", "", ""))
