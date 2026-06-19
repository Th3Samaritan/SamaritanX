"""JavaScript intelligence — mine bundles for what hunters actually want.

The crawler harvests endpoints from JS (see core.surface). This goes deeper into
the highest-signal JS artifacts:

  * **Source maps.** A `//# sourceMappingURL=app.js.map` in production is a gift:
    its `sourcesContent` reconstructs the original, un-minified source — exposing
    hidden admin routes, internal API shapes, and comments. We fetch and rebuild
    it, then re-mine the reconstructed source for endpoints.
  * **Hardcoded secrets.** Google/Stripe/Slack/AWS keys, JWTs, private-key blocks
    embedded in the bundle.
  * **Embedded GraphQL operations** and **privileged route literals** for manual
    follow-up.

`harvest_js` is the async entry point used by the crawler; the parsing helpers
are pure so they unit-test offline.
"""
from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .escalation import _redact
from .surface import mine_js_text
from .utils import host_of, root_domain

if TYPE_CHECKING:
    from .orchestrator import Context

_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_GRAPHQL_OP_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z][A-Za-z0-9_]*)\s*[({]")
_PRIV_PATH_RE = re.compile(r"""['"`](/(?:admin|internal|manage|console|staff|"""
                           r"""superuser|debug|_next/internal|api/admin)"""
                           r"""[A-Za-z0-9_./\-]{0,80})['"`]""")

# Secret patterns — label, regex. Ordered most-severe first.
_SECRET_PATTERNS = [
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google_oauth_id", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{20,}\.apps\.googleusercontent\.com\b")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("firebase_db", re.compile(r"\b[a-z0-9-]+\.firebaseio\.com\b")),
    ("generic_secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
]

# Severity per secret kind.
_SECRET_SEV = {
    "private_key_block": ("critical", 9.4), "aws_access_key": ("critical", 9.3),
    "stripe_live_key": ("critical", 9.3), "google_api_key": ("high", 7.5),
    "slack_token": ("high", 7.5), "google_oauth_id": ("medium", 5.3),
    "jwt": ("high", 7.0), "firebase_db": ("medium", 5.3),
    "generic_secret": ("medium", 6.0),
}


def extract_secrets(text: str) -> list[tuple[str, str]]:
    """Return [(kind, redacted_sample)] of secrets embedded in JS/source."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for kind, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text or ""):
            sample = m.group(0)
            key = kind + sample[:12]
            if key in seen:
                continue
            seen.add(key)
            out.append((kind, _redact(sample)))
            if len(out) >= 40:
                return out
    return out


def extract_graphql_ops(text: str) -> list[str]:
    ops = []
    seen = set()
    for m in _GRAPHQL_OP_RE.finditer(text or ""):
        name = f"{m.group(1)} {m.group(2)}"
        if name not in seen:
            seen.add(name)
            ops.append(name)
        if len(ops) >= 30:
            break
    return ops


def privileged_paths(text: str) -> list[str]:
    out, seen = [], set()
    for m in _PRIV_PATH_RE.finditer(text or ""):
        p = m.group(1)
        if p not in seen:
            seen.add(p)
            out.append(p)
        if len(out) >= 25:
            break
    return out


def find_sourcemap_url(js: str, js_url: str) -> str | None:
    m = _SOURCEMAP_RE.search(js or "")
    if not m:
        return None
    ref = m.group(1).strip()
    if ref.startswith("data:"):       # inline map — caller handles separately
        return ref
    return urljoin(js_url, ref)


def reconstruct_sources(map_text: str, *, max_files: int = 200) -> list[tuple[str, str]]:
    """Rebuild original (path, content) pairs from a source map's
    sourcesContent. Returns [] if the map has no embedded content."""
    try:
        data = json.loads(map_text)
    except Exception:
        return []
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    out: list[tuple[str, str]] = []
    for i, content in enumerate(contents[:max_files]):
        if not content:
            continue
        name = sources[i] if i < len(sources) else f"source_{i}.js"
        out.append((str(name), content))
    return out


async def harvest_js(ctx: "Context", script_urls: list[str], base_url: str,
                     *, max_scripts: int = 25) -> dict:
    """Fetch bundles once; return endpoint tasks + secret/sourcemap/graphql
    intel. Reconstructed source-map content is re-mined for endpoints/secrets."""
    from .injection import candidate_points
    seed_root = root_domain(host_of(base_url))
    tasks: list[dict] = []
    secrets: list[dict] = []         # {url, kind, sample}
    sourcemaps: list[str] = []
    graphql_ops: set[str] = set()
    priv_paths: set[str] = set()
    emitted: set[str] = set()

    def _add_endpoints(text: str, origin_url: str) -> None:
        for url, qkeys in mine_js_text(text, base_url):
            pts = candidate_points(url, qkeys)
            if not pts:
                continue
            key = url + "|" + ",".join(pts)
            if key not in emitted:
                emitted.add(key)
                tasks.append({"url": url, "method": "GET", "params": pts, "source": "js"})

    def _add_secrets(text: str, origin_url: str) -> None:
        for kind, sample in extract_secrets(text):
            secrets.append({"url": origin_url, "kind": kind, "sample": sample})

    for src in list(dict.fromkeys(script_urls))[:max_scripts]:
        ev = await ctx.http.get(src)
        if ev.status != 200 or not ev.response_body:
            continue
        body = ev.response_body
        _add_endpoints(body, src)
        _add_secrets(body, src)
        graphql_ops.update(extract_graphql_ops(body))
        priv_paths.update(privileged_paths(body))

        # source map reconstruction
        smap = find_sourcemap_url(body, src)
        if smap and not smap.startswith("data:"):
            mev = await ctx.http.get(smap)
            if mev.status == 200 and mev.response_body:
                rebuilt = reconstruct_sources(mev.response_body)
                if rebuilt:
                    sourcemaps.append(smap)
                    for _name, content in rebuilt:
                        _add_endpoints(content, smap)
                        _add_secrets(content, smap)
                        graphql_ops.update(extract_graphql_ops(content))
                        priv_paths.update(privileged_paths(content))

    # keep mined privileged paths in-scope and turn them into scan tasks
    for p in priv_paths:
        url = urljoin(base_url, p)
        if root_domain(host_of(url)) == seed_root and url not in emitted:
            emitted.add(url)
            tasks.append({"url": url, "method": "GET", "params": [], "source": "js_priv"})

    return {"tasks": tasks, "secrets": secrets, "sourcemaps": sourcemaps,
            "graphql_ops": sorted(graphql_ops)[:30], "priv_paths": sorted(priv_paths)[:25]}
