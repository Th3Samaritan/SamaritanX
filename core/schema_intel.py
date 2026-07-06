"""Schema-driven surface discovery for GraphQL (and typed REST specs).

The crawler already *flags* that GraphQL introspection is enabled, but it throws
the schema away. That schema is a map of the entire API — every query, mutation,
argument and field. Mining it turns "introspection is on" (a medium) into real
coverage: concrete operations to test and a list of sensitive fields an
unauthenticated client can pull.

Two things here:

  * ``parse_schema`` (pure, unit-tested) turns an introspection result into
    ``queries`` / ``mutations`` (each with argument names) and flags
    ``sensitive_fields`` — fields named like ``password`` / ``token`` / ``ssn``.
  * ``discover`` (async) runs full introspection against an endpoint, emits scan
    targets for the discovered operations, and — for sensitive fields — actually
    *queries them unauthenticated* and only reports when data comes back
    (captured proof of excessive data exposure), so nothing unproven ships.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.orchestrator import Context

# The standard full-introspection query (trimmed to what we consume).
INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { "
    "queryType { name } mutationType { name } "
    "types { name kind fields { name args { name type { name kind ofType { name } } } "
    "type { name kind ofType { name kind } } } } } }"
)

_SENSITIVE_FIELD = ("password", "passwd", "secret", "token", "apikey", "api_key",
                    "ssn", "social", "creditcard", "credit_card", "cvv", "pin",
                    "private", "sessionid", "session_id", "otp", "mfa", "seed",
                    "salt", "hash", "recovery")


def _type_name(t: dict | None) -> str:
    """Unwrap a possibly-wrapped GraphQL type ref to its base name."""
    while isinstance(t, dict):
        if t.get("name"):
            return t["name"]
        t = t.get("ofType")
    return ""


def parse_schema(introspection: dict[str, Any]) -> dict[str, Any]:
    """Turn an introspection JSON result into a structured summary.

    Accepts either the full ``{"data": {"__schema": …}}`` envelope or a bare
    ``{"__schema": …}``."""
    data = introspection.get("data", introspection)
    schema = data.get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return {"queries": [], "mutations": [], "sensitive_fields": [], "types": 0}

    query_type = (schema.get("queryType") or {}).get("name")
    mutation_type = (schema.get("mutationType") or {}).get("name")
    queries: list[dict] = []
    mutations: list[dict] = []
    sensitive: list[dict] = []

    for t in schema.get("types") or []:
        tname = t.get("name") or ""
        if tname.startswith("__"):
            continue
        fields = t.get("fields") or []
        for f in fields:
            fname = f.get("name") or ""
            entry = {"name": fname,
                     "args": [a.get("name") for a in (f.get("args") or [])],
                     "returns": _type_name(f.get("type"))}
            if tname == query_type:
                queries.append(entry)
            elif tname == mutation_type:
                mutations.append(entry)
            # sensitive-field flag on ANY object type
            low = fname.lower()
            if any(s in low for s in _SENSITIVE_FIELD):
                sensitive.append({"type": tname, "field": fname})

    return {"queries": queries, "mutations": mutations,
            "sensitive_fields": sensitive,
            "types": len([t for t in (schema.get("types") or [])
                          if not (t.get("name") or "").startswith("__")])}


def build_probe_query(field: dict) -> str:
    """A minimal GraphQL document that selects one query field (best-effort)."""
    name = field.get("name")
    ret = field.get("returns") or ""
    # scalar-ish return -> select it directly; object -> ask for __typename
    scalar = ret in ("String", "Int", "Boolean", "Float", "ID", "") or ret.endswith("Scalar")
    selection = "" if scalar else " { __typename }"
    return f"{{ {name}{selection} }}"


async def discover(ctx: "Context", url: str) -> dict[str, Any]:
    """Introspect ``url``, emit scan tasks for operations, and prove any
    unauthenticated sensitive-field exposure. Returns {tasks, findings}."""
    tasks: list[dict] = []
    findings: list[dict] = []
    try:
        ev = await ctx.http.post(url, json_body={"query": INTROSPECTION_QUERY},
                                 headers={"Content-Type": "application/json"})
    except Exception:
        return {"tasks": tasks, "findings": findings}
    if not ev or ev.status != 200 or "__schema" not in (ev.response_body or ""):
        return {"tasks": tasks, "findings": findings}

    import json as _json
    try:
        parsed = parse_schema(_json.loads(ev.response_body))
    except Exception:
        return {"tasks": tasks, "findings": findings}

    # scan targets: one graphql operation probe per query/mutation
    for op in parsed["queries"] + parsed["mutations"]:
        if op["args"]:
            tasks.append({"url": url, "method": "POST",
                          "params": [f"json:variables.{a}" for a in op["args"]],
                          "source": "graphql_schema", "operation": op["name"]})

    # excessive data exposure: actually pull a sensitive field unauthenticated
    for sf in parsed["sensitive_fields"][:8]:
        q = "{ %s }" % sf["field"] if not sf.get("type") else None
        probe = build_probe_query({"name": sf["field"], "returns": ""})
        try:
            r = await ctx.http.post(url, json_body={"query": probe}, no_session=True,
                                    headers={"Content-Type": "application/json",
                                             "Authorization": "", "Cookie": ""})
        except Exception:
            continue
        body = (r.response_body or "") if r else ""
        # data returned (not an auth error) => the sensitive field is exposed
        if r and r.status == 200 and '"data"' in body and sf["field"] in body \
                and '"errors"' not in body:
            from .poc import proof_record
            findings.append({
                "category": "graphql",
                "title": f"GraphQL excessive data exposure — unauthenticated `{sf['field']}`",
                "severity": "high", "cvss": 7.5, "confidence": 0.9,
                "url": url, "parameter": sf["field"], "payload": probe,
                "evidence": f"Unauthenticated introspection revealed `{sf['type']}.{sf['field']}` "
                            "and an anonymous query returned data for it.",
                "request": f"POST {url}\n{{\"query\":\"{probe}\"}}  (no auth)",
                "response": body[:1500],
                "metadata": {"detection": "graphql_schema", "poc": proof_record(
                    verified=True, method="POST", url=url,
                    request=f"POST {url}  {probe}  (no Cookie/Authorization)",
                    status=r.status, excerpt=body,
                    rationale=(f"The sensitive field `{sf['field']}` was both introspectable and "
                               "returned data to an unauthenticated query — sensitive schema and "
                               "data are exposed without access control."))},
            })
    return {"tasks": tasks, "findings": findings}
