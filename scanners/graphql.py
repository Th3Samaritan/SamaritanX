"""GraphQL deep-scan.

Hits a discovered GraphQL endpoint with the focused checks bug bounty
hunters care about:

  1. Introspection — schema dumped (already covered by crawler, here we
     also classify exposed mutations / sensitive fields)
  2. Field-level authorization — try every mutation anonymously and
     report ones that don't return an auth-shaped error
  3. Alias-based brute force — fire 100 aliases of `login(password: ...)`
     in a single request to bypass rate limits
  4. Query-depth / nested expansion — eg. `me { posts { author { posts { ... } } } }`
     to detect missing depth limits (DoS class)
  5. CSRF via GET / form-encoded query — the endpoint accepts
     `?query=mutation{...}` without an auth header
  6. Suggestion attacks — submit `{ usrs }` and inspect the typo suggestion
     in the error reply ("Did you mean 'users'?") to leak the schema
     even when introspection is disabled
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import TYPE_CHECKING

from core.utils import host_of, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context


SENSITIVE_FIELD_RE = re.compile(
    r"^(password|secret|token|api_?key|credit_?card|ssn|"
    r"private|adminPanel|impersonate|deleteUser|grantRole|"
    r"setRole|elevatePermission|setEmail|resetPassword)$",
    re.I,
)
SUGGESTION_RE = re.compile(r"Did you mean ['\"]?([\w]+)['\"]?", re.I)


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    """Triggered on `scan.graphql` URLs from the crawler. Skips non-GraphQL."""
    findings: list[dict] = []

    # Heuristic: only accept obvious GraphQL paths
    lower = url.lower()
    if not any(s in lower for s in ("/graphql", "/api/graphql", "/v1/graphql", "/query")):
        return findings

    # ---------- 1+2: introspect, classify mutations + try anon ----------
    schema = await _introspect(ctx, url)
    if schema:
        await _classify_schema(ctx, url, schema, findings)
        await _anonymous_mutations(ctx, url, schema, findings)

    # ---------- 3: alias brute force ----------
    await _alias_brute(ctx, url, findings)

    # ---------- 4: nested query / depth bomb ----------
    await _depth_bomb(ctx, url, findings)

    # ---------- 5: CSRF via GET ----------
    await _csrf_via_get(ctx, url, findings)

    # ---------- 6: suggestion-based schema leak ----------
    await _suggestion_leak(ctx, url, findings)

    return findings


# ---------- 1+2 ---------------------------------------------------------------

async def _introspect(ctx, url):
    q = {"query": "{__schema{types{name fields{name args{name}}}"
                  " queryType{name} mutationType{name}"
                  " subscriptionType{name}}}"}
    ev = await ctx.http.post(url, json_body=q,
                             headers={"Content-Type": "application/json"})
    if ev.status != 200 or "__schema" not in (ev.response_body or ""):
        return None
    try:
        return json.loads(ev.response_body)["data"]["__schema"]
    except Exception:
        return None


async def _classify_schema(ctx, url, schema, findings):
    sensitive: list[tuple[str, str]] = []
    mutations: list[str] = []
    for t in schema.get("types") or []:
        name = t.get("name") or ""
        for f in t.get("fields") or []:
            fname = f.get("name") or ""
            if SENSITIVE_FIELD_RE.match(fname):
                sensitive.append((name, fname))
        if name == (schema.get("mutationType") or {}).get("name"):
            mutations = [f.get("name") for f in (t.get("fields") or [])]
    if sensitive:
        findings.append({
            "category": "graphql",
            "title": f"GraphQL exposes {len(sensitive)} sensitive-shaped field(s)",
            "severity": "medium", "cvss": 5.5,
            "url": url,
            "evidence": "Fields matching sensitive patterns: "
                        + ", ".join(f"{t}.{f}" for t, f in sensitive[:10]),
            "metadata": {"fields": [f"{t}.{f}" for t, f in sensitive]},
        })
    if mutations:
        ctx.dashboard.event("info", f"graphql: {len(mutations)} mutations exposed at {url}")


async def _anonymous_mutations(ctx, url, schema, findings):
    """For each known mutation, fire it with stub args sans auth and check
    for an auth-shaped error. Anything that doesn't refuse is suspicious.

    This executes real mutation fields against the live API — on a
    misconfigured endpoint a stub like `deleteUser` actually runs. Gated
    behind --aggressive."""
    if not ctx.config.get("safety", {}).get("aggressive"):
        return
    mname = (schema.get("mutationType") or {}).get("name")
    if not mname:
        return
    mtype = next((t for t in (schema.get("types") or [])
                  if t.get("name") == mname), None)
    if not mtype:
        return
    sem = asyncio.Semaphore(4)

    async def try_mutation(field):
        fname = field.get("name") or ""
        # build a minimal valid syntax — even if args are wrong, the auth
        # check usually fires first
        args = field.get("args") or []
        arg_str = ""
        if args:
            arg_str = "(" + ", ".join(f'{a["name"]}: "x"' for a in args[:3]) + ")"
        q = {"query": f"mutation {{ {fname}{arg_str} }}"}
        async with sem:
            ev = await ctx.http.post(
                url, json_body=q,
                headers={"Content-Type": "application/json", "Authorization": ""},
                cookies={"session": ""},
            )
        body = (ev.response_body or "").lower()
        if ev.status != 200:
            return
        # auth-shaped errors -> good
        if any(k in body for k in ("unauthorized", "unauthenticated", "forbidden",
                                    "not authenticated", "must be logged in", "401", "403")):
            return
        # actual errors with non-auth shape -> still suspicious
        if '"errors"' in body and "permission" not in body:
            findings.append({
                "category": "graphql",
                "title": f"GraphQL mutation `{fname}` accessible without auth refusal",
                "severity": "high", "cvss": 7.5,
                "url": url, "parameter": fname,
                "payload": q["query"],
                "evidence": "Anonymous request to a mutation did not return an auth-shaped error. "
                            "Manual confirmation of impact required.",
                "request": f"POST {url}\n\n{json.dumps(q)}",
                "response": (ev.response_body or "")[:1500],
                "metadata": {"mutation": fname},
            })

    await asyncio.gather(*(try_mutation(f) for f in (mtype.get("fields") or [])[:30]))


# ---------- 3: alias brute force ---------------------------------------------

async def _alias_brute(ctx, url, findings):
    """A single request with 100 aliases of the same field. Used for:
    * password brute force without tripping rate limits
    * billable-action amplification (each alias counts once for the user
      but costs the platform N times)"""
    aliases = ", ".join(
        f'a{i}: __typename' for i in range(100)
    )
    q = {"query": "{ " + aliases + " }"}
    t0 = time.perf_counter()
    ev = await ctx.http.post(url, json_body=q,
                             headers={"Content-Type": "application/json"})
    elapsed = time.perf_counter() - t0
    if ev.status == 200 and ev.response_body and ev.response_body.count('"a99"') >= 1:
        findings.append({
            "category": "graphql",
            "title": "GraphQL accepts 100-alias single-request batches (no alias limit)",
            "severity": "medium", "cvss": 6.5,
            "url": url,
            "evidence": f"Server resolved 100 aliases in one request (elapsed {elapsed:.2f}s). "
                        "Brute-force-grade rate limit bypass and amplification risk.",
            "request": f"POST {url}\n\n{q['query'][:200]}…",
            "response": (ev.response_body or "")[:1000],
            "metadata": {"aliases": 100, "elapsed_s": elapsed},
        })


# ---------- 4: depth bomb ----------------------------------------------------

async def _depth_bomb(ctx, url, findings):
    """Self-referencing query — only succeeds when depth-limit middleware is missing.
    Capped at 10 levels (kept benign — anything deeper risks DoS)."""
    inner = "id"
    for _ in range(10):
        inner = "user { " + inner + " }"
    q = {"query": "{ me { " + inner + " } }"}
    t0 = time.perf_counter()
    ev = await ctx.http.post(url, json_body=q,
                             headers={"Content-Type": "application/json"})
    elapsed = time.perf_counter() - t0
    body = (ev.response_body or "").lower()
    if ev.status == 200 and "data" in body and "errors" not in body:
        findings.append({
            "category": "graphql",
            "title": "GraphQL accepts 10-level nested query (no depth limit)",
            "severity": "medium", "cvss": 5.3,
            "url": url,
            "evidence": f"Server resolved a 10-level self-referencing query in {elapsed:.2f}s. "
                        "Without depth limits, attackers can craft DoS queries.",
            "request": f"POST {url}\n\n{q['query']}",
            "response": (ev.response_body or "")[:1000],
            "metadata": {"depth": 10, "elapsed_s": elapsed},
        })
    elif elapsed > 5.0:
        findings.append({
            "category": "graphql",
            "title": f"GraphQL nested query took {elapsed:.1f}s — possible DoS surface",
            "severity": "medium", "cvss": 5.3,
            "url": url,
            "evidence": f"Even when error-rejected, the server took {elapsed:.2f}s on a "
                        "10-level query — investigate cost-analysis posture.",
        })


# ---------- 5: CSRF via GET --------------------------------------------------

async def _csrf_via_get(ctx, url, findings):
    """If GraphQL accepts mutations over GET / form-encoded, a CSRF
    payload can change state via a victim's session — the endpoint must
    refuse that."""
    token = random_token(6)
    # benign mutation-shaped query — doesn't do anything but tells us the
    # parser ran
    sentinel_query = "{ __typename @sx_" + token + " }"
    ev_get = await ctx.http.get(f"{url}?query={sentinel_query}")
    ev_form = await ctx.http.post(
        url, data={"query": sentinel_query},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    issues = []
    if ev_get.status == 200 and "__typename" in (ev_get.response_body or ""):
        issues.append("GET")
    if ev_form.status == 200 and "__typename" in (ev_form.response_body or ""):
        issues.append("application/x-www-form-urlencoded")
    if issues:
        findings.append({
            "category": "graphql",
            "title": f"GraphQL CSRF — accepts queries via {', '.join(issues)}",
            "severity": "high", "cvss": 7.4,
            "url": url,
            "evidence": "Endpoint executed a query over a non-JSON content type. Combined "
                        "with a victim's authenticated cookie, an attacker page can fire "
                        "mutations cross-origin.",
            "request": f"{','.join(issues)} {url}\nquery={sentinel_query}",
            "response": (ev_get.response_body or ev_form.response_body or "")[:1000],
            "metadata": {"channels": issues},
        })


# ---------- 6: suggestion leak -----------------------------------------------

async def _suggestion_leak(ctx, url, findings):
    """When introspection is disabled, error messages often still leak
    schema info via 'Did you mean ...' suggestions."""
    q = {"query": "{ usr { id } }"}
    ev = await ctx.http.post(url, json_body=q,
                             headers={"Content-Type": "application/json"})
    if ev.status not in (200, 400):
        return
    suggestions = SUGGESTION_RE.findall(ev.response_body or "")
    if suggestions:
        findings.append({
            "category": "graphql",
            "title": "GraphQL leaks schema via 'Did you mean' error suggestions",
            "severity": "low", "cvss": 4.3,
            "url": url,
            "evidence": "Introspection-style schema discovery still possible: "
                        f"server suggested {sorted(set(suggestions))[:8]}",
            "request": f"POST {url}\n\n{json.dumps(q)}",
            "response": (ev.response_body or "")[:1000],
            "metadata": {"suggestions": sorted(set(suggestions))},
        })
