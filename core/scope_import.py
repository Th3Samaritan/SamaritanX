"""Scope importer — convert bug-bounty platform scope exports into SamaritanX
scope rules.

Platforms export scope in wildly different JSON shapes. This module detects the
shape and normalizes every asset into the rule grammar `core.scope` already
understands:

    *.example.com          allow glob (host)
    example.com            exact host
    !internal.example.com  deny
    re:^https://x[.]example[.]com/admin/   regex against the full URL
    cidr:10.0.0.0/8        CIDR block
    !cidr:192.168.0.0/16   deny CIDR

Supported inputs (auto-detected):
  * HackerOne  structured_scopes JSON (api.hackerone.com/v1/hackers/programs/
    {handle}/structured_scopes or the graph wrapper)
  * Bugcrowd    target JSON (`content[].target_groups[].targets[]`) or CSV
  * Intigriti   domains JSON (`domains[].endpoint`) / `records` wrapper
  * Chaos       (projectdiscovery) JSON: `{subdomain: "*.example.com", ...}`
  * Generic     list of domains / URLs / wildcards / CIDRs (JSON array or text)

All matching is tolerant: the extractor walks any dict/list tree and collects
asset-bearing entries, so minor API shape changes don't break the import.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from typing import Any, Iterable

# keys that carry an asset string in the various platform shapes
_ASSET_KEYS = (
    "asset_identifier",   # HackerOne
    "endpoint",           # Intigriti / Chaos
    "subdomain",          # Chaos
    "target",             # generic
    "name",               # Bugcrowd / generic
    "asset",              # generic
    "domain",             # generic
)
_OUT_OF_SCOPE_KEYS = ("eligible_for_submission", "eligible_for_bounty", "in_scope")
_TYPE_KEYS = ("asset_type", "category", "type")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")


def _iter_assets(node: Any) -> Iterable[dict]:
    """Walk a JSON tree and yield dicts that look like scope entries."""
    if isinstance(node, dict):
        if any(k in node for k in _ASSET_KEYS):
            yield node
        for v in node.values():
            yield from _iter_assets(v)
    elif isinstance(node, list):
        for v in node:
            yield from _iter_assets(v)


def _in_scope(entry: dict) -> bool:
    """Decide whether an entry is in-scope. Absent flags default to in-scope
    (most platform exports only include in-scope assets)."""
    for k in _OUT_OF_SCOPE_KEYS:
        if k in entry:
            v = entry[k]
            if isinstance(v, bool) and not v:
                return False
            if isinstance(v, str) and v.strip().lower() in ("false", "out_of_scope", "out of scope"):
                return False
    if "in_scope" in entry:
        v = entry["in_scope"]
        if isinstance(v, bool) and not v:
            return False
    return True


def _asset_string(entry: dict) -> str | None:
    for k in _ASSET_KEYS:
        v = entry.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _normalize(asset: str) -> str:
    a = asset.strip()
    if a.startswith(("http://", "https://")):
        a = a.split("://", 1)[1]
    a = a.rstrip("/")
    return a


def _rule_for(asset: str, allow: bool) -> list[str]:
    """Map one asset to scope-file rule lines."""
    a = _normalize(asset)
    if not a:
        return []
    prefix = "" if allow else "!"
    # CIDR / bare IP
    if _IP_RE.match(a):
        net = a if "/" in a else a + "/32"
        try:
            ipaddress.ip_network(net, strict=False)
            return [f"{prefix}cidr:{net}"]
        except ValueError:
            return []
    # a URL with a path → regex against the full URL (allow only)
    if "/" in a and not a.startswith(("*", ".")):
        host, _, path = a.partition("/")
        if allow:
            pattern = re.escape(f"{host}/{path}")
            pattern = pattern.replace(re.escape("*"), ".*")
            return [f"re:^https?://{pattern}.*$"]
        return [f"!{host}"]  # deny the whole host for an out-of-scope URL
    # wildcard / plain domain
    return [f"{prefix}{a.lower()}"]


def _from_csv(text: str) -> list[dict]:
    rows: list[dict] = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        asset = (row.get("target_name") or row.get("target") or row.get("asset")
                 or row.get("domain") or "")
        if asset:
            rows.append({"asset_identifier": asset,
                         "eligible_for_submission":
                             row.get("in_scope", "true").lower() not in ("false", "no")})
    return rows


def parse_platform_scope(text: str, *, fmt: str = "auto") -> list[dict]:
    """Return a list of {'asset': str, 'allow': bool, 'kind': str} entries."""
    stripped = text.strip()
    data: Any = None
    # JSON (platform exports are almost always JSON) — commas inside JSON must
    # NOT route into the CSV parser
    if stripped.startswith(("{", "[")):
        try:
            data = json.loads(stripped)
        except Exception:
            data = None
    # CSV — only when it actually has a CSV header row
    if data is None and fmt in ("auto", "csv") and \
            re.search(r"^\s*(target_name|target|asset|domain|name)\s*[,;]", stripped, re.I):
        try:
            data = _from_csv(stripped)
        except Exception:
            data = None
    if data is None:
        # plain text: one asset per line
        data = [{"asset_identifier": line.strip()} for line in stripped.splitlines()
                if line.strip() and not line.strip().startswith("#")]
    entries: list[dict] = []
    for entry in _iter_assets(data):
        asset = _asset_string(entry)
        if not asset:
            continue
        entries.append({"asset": asset, "allow": _in_scope(entry),
                        "kind": _type_of(entry)})
    # dedupe, keep order
    seen: set[str] = set()
    out: list[dict] = []
    for e in entries:
        key = ("!" if not e["allow"] else "") + e["asset"]
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def _type_of(entry: dict) -> str:
    for k in _TYPE_KEYS:
        v = entry.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def to_rules(text: str, *, fmt: str = "auto") -> list[str]:
    """Convert a platform scope export into scope-file rule lines."""
    rules: list[str] = []
    for e in parse_platform_scope(text, fmt=fmt):
        rules.extend(_rule_for(e["asset"], e["allow"]))
    return rules


def looks_like_platform_export(text: str) -> bool:
    """True when the file content is a JSON/CSV platform export rather than a
    plain SamaritanX scope file."""
    stripped = text.strip()
    if not stripped:
        return False
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except Exception:
            return False
        return bool(list(_iter_assets(data)))
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except Exception:
            return False
        return bool(data)
    # CSV with a recognised header row
    if re.search(r"^\s*(target_name|target|asset|domain|name)\s*[,;]", stripped, re.I):
        return True
    return False


# --------------------------------------------------------------------------- #
# Live platform scope fetching (no manual export needed)
# --------------------------------------------------------------------------- #
_H1_STRUCTURED_SCOPES_URL = "https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes"
_H1_GRAPHQL = "https://hackerone.com/graphql"
_H1_GRAPHQL_QUERY = """
query TeamScope($handle: String!) {
  team(handle: $handle) {
    handle
    structured_scopes(first: 200) {
      edges { node { asset_identifier asset_type eligible_for_bounty eligible_for_submission } }
    }
  }
}
"""


async def fetch_program_scope(program: str, *, platform: str = "hackerone",
                              api_token: str = "") -> tuple[str, str]:
    """Fetch a program's scope export from a platform.

    Returns (scope_text, source_label) where scope_text is JSON/CSV parseable
    by :func:`to_rules`. Raises RuntimeError with a helpful message when the
    program can't be fetched.
    """
    import httpx
    platform = (platform or "").lower()
    if platform == "hackerone":
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 1) authenticated API (full fidelity) when a token is available
            if api_token:
                r = await client.get(
                    _H1_STRUCTURED_SCOPES_URL.format(handle=program),
                    headers={"Authorization": f"Bearer {api_token}",
                             "Accept": "application/json",
                             "User-Agent": "samaritanx-scope-import"},
                )
                if r.status_code == 200:
                    try:
                        data = r.json()
                        if _iter_assets(data):
                            return json.dumps(data), f"hackerone api ({program})"
                    except Exception:
                        pass
            # 2) public graphql (anonymous)
            try:
                r = await client.post(
                    _H1_GRAPHQL,
                    json={"query": _H1_GRAPHQL_QUERY, "variables": {"handle": program}},
                    headers={"Content-Type": "application/json",
                             "User-Agent": "Mozilla/5.0"},
                )
                if r.status_code == 200:
                    data = r.json()
                    team = (data.get("data") or {}).get("team")
                    if team:
                        edges = (team.get("structured_scopes") or {}).get("edges") or []
                        entries = [
                            {"attributes": (e.get("node") or {})} for e in edges
                        ]
                        return json.dumps(entries), f"hackerone public graphql ({program})"
            except Exception:
                pass
    elif platform == "bugcrowd":
        # public program.json embed: target_groups[].targets[].name + in_scope
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                f"https://bugcrowd.com/{program}/program.json",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code == 200:
                try:
                    data = r.json()
                    entries = []
                    for group in (data.get("target_groups") or []):
                        for t in (group.get("targets") or []):
                            entries.append({
                                "asset_identifier": t.get("name"),
                                "category": t.get("category") or "",
                                "in_scope": t.get("in_scope", True),
                            })
                    if entries:
                        return json.dumps(entries), f"bugcrowd public json ({program})"
                except Exception:
                    pass
    elif platform == "intigriti":
        # public researcher API
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                f"https://api.intigriti.com/external/researcher/v1/programs/{program}",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code == 200:
                try:
                    data = r.json()
                    domains = data.get("domains") or []
                    entries = [{"asset_identifier": d.get("endpoint"),
                                "in_scope": True} for d in domains
                               if d.get("endpoint")]
                    if entries:
                        return json.dumps(entries), f"intigriti public api ({program})"
                except Exception:
                    pass
    raise RuntimeError(
        f"could not fetch {platform} program '{program}' — "
        "check the handle, set the platform API token if required, or export "
        "the scope manually and use scope-import <file>")


def extract_roots(rules: list[str]) -> list[str]:
    """Derive scannable roots (apex domains / hosts) from generated scope rules.

    Wildcards (`*.example.com`) and exact hosts are collapsed to their
    registrable domain; URL-regex rules contribute their host; deny rules and
    CIDRs are ignored."""
    from .utils import root_domain
    hosts: set[str] = set()
    for line in rules:
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        if line.startswith("re:"):
            m = re.search(r"https\?://([^\\/.]+(?:\\.[^\\/.]+)+)", line)
            if m:
                hosts.add(root_domain(m.group(1).replace("\\.", ".")))
            continue
        if line.startswith("cidr:"):
            continue
        host = line.lower().strip().lstrip("*.")
        if host and "." in host:
            hosts.add(root_domain(host))
    return sorted(h for h in hosts if h)
