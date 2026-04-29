"""OAuth 2.0 / OIDC / SSO scanner.

The high-payout OAuth bug classes:

  * **redirect_uri** open-redirect — manipulate the authorize endpoint's
    redirect_uri to land an authorization code on attacker.tld
  * **state parameter missing** — exposes the OAuth dance to CSRF / login
    fixation
  * **PKCE absence on a public client** — code interception attacks
  * **implicit flow (response_type=token) returning a token in the URL** —
    deprecated, leaks via Referer / browser history
  * **scope escalation** — request a higher scope than the client should
    have and observe whether the consent screen / tokens still issue
  * **OIDC well-known discovery** — fetch /.well-known/openid-configuration
    and inspect for permissive flows / endpoints
  * **JWKS exposure / weakness** — fetch jwks_uri and check for empty
    keys, RSA/HMAC confusion (kid traversal)

The scanner runs **only** on URLs that look like OAuth endpoints —
detected by path heuristics and by a `/authorize` endpoint discovered
through OIDC discovery.
"""
from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

if TYPE_CHECKING:
    from core.orchestrator import Context

OAUTH_PATH_HINTS = ("/oauth/authorize", "/authorize", "/connect/authorize",
                    "/oauth2/authorize", "/oauth/v2/authorize",
                    "/sso/authorize", "/openid/authorize", "/auth/realms")
EVIL_REDIRECTS = [
    "https://evil.samaritanx.test/cb",
    "https://attacker.tld/cb",
    # path-traversal / fragment / userinfo tricks against permissive validators
    "https://target.tld/.evil.samaritanx.test/cb",
    "https://target.tld@evil.samaritanx.test/cb",
    "https://target.tld#@evil.samaritanx.test/cb",
    "/\\evil.samaritanx.test/cb",
    "//evil.samaritanx.test/cb",
]


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    parsed = urlparse(url)
    path_lower = (parsed.path or "").lower()

    # 1) discovery — try OIDC well-known on the URL's host (always cheap)
    base = f"{parsed.scheme}://{parsed.netloc}"
    discovery = await _oidc_discovery(ctx, base)
    if discovery:
        findings.extend(await _audit_discovery(ctx, base, discovery))
        # use the discovery's authorization_endpoint if the URL itself
        # isn't already obviously OAuth
        ae = discovery.get("authorization_endpoint")
        if ae and not any(h in path_lower for h in OAUTH_PATH_HINTS):
            url = ae
            parsed = urlparse(url)
            path_lower = parsed.path.lower()

    # 2) only run further checks if we are actually on an OAuth authorize endpoint
    if not any(h in path_lower for h in OAUTH_PATH_HINTS):
        return findings

    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    client_id = qs.get("client_id") or "test_client"
    response_type = qs.get("response_type") or "code"
    scope = qs.get("scope") or "openid profile email"
    original_redirect = qs.get("redirect_uri")

    # 3) redirect_uri open-redirect probe
    findings.extend(await _redirect_uri_probe(ctx, parsed, qs,
                                              client_id, response_type, scope,
                                              original_redirect))

    # 4) state parameter required check
    findings.extend(await _state_required(ctx, parsed, qs,
                                          client_id, response_type, scope))

    # 5) implicit flow — token in URL fragment
    findings.extend(await _implicit_flow(ctx, parsed, qs,
                                         client_id, scope, original_redirect))

    # 6) PKCE missing — for public clients, code flow without code_challenge
    findings.extend(await _pkce_missing(ctx, parsed, qs,
                                        client_id, scope, original_redirect))

    # 7) scope escalation
    findings.extend(await _scope_escalation(ctx, parsed, qs,
                                            client_id, response_type,
                                            original_redirect))
    return findings


# ---------- OIDC discovery ----------------------------------------------------

async def _oidc_discovery(ctx, base):
    for path in ("/.well-known/openid-configuration",
                 "/.well-known/oauth-authorization-server"):
        ev = await ctx.http.get(urljoin(base, path))
        if ev.status != 200 or "json" not in (ev.response_headers.get("content-type") or "").lower():
            continue
        try:
            return json.loads(ev.response_body)
        except Exception:
            continue
    return None


async def _audit_discovery(ctx, base, doc):
    out = []
    grant_types = [g.lower() for g in (doc.get("grant_types_supported") or [])]
    response_types = [r.lower() for r in (doc.get("response_types_supported") or [])]
    if "implicit" in grant_types or "token" in response_types:
        out.append({
            "category": "oauth",
            "title": "OIDC discovery advertises deprecated implicit flow",
            "severity": "medium", "cvss": 5.3,
            "url": base + "/.well-known/openid-configuration",
            "evidence": f"response_types_supported includes 'token' / grant_types_supported includes 'implicit' "
                        f"({response_types}, {grant_types})",
        })
    if not (doc.get("code_challenge_methods_supported") or []):
        out.append({
            "category": "oauth",
            "title": "OIDC discovery does not advertise PKCE support",
            "severity": "low", "cvss": 4.0,
            "url": base + "/.well-known/openid-configuration",
            "evidence": "Missing 'code_challenge_methods_supported'. Public clients are vulnerable to "
                        "authorization-code interception.",
        })
    # JWKS
    jwks_uri = doc.get("jwks_uri")
    if jwks_uri:
        ev = await ctx.http.get(jwks_uri)
        if ev.status == 200:
            try:
                jwks = json.loads(ev.response_body or "{}")
                keys = jwks.get("keys") or []
                if not keys:
                    out.append({
                        "category": "oauth",
                        "title": "JWKS endpoint returns empty key set",
                        "severity": "high", "cvss": 7.5,
                        "url": jwks_uri,
                        "evidence": "Empty 'keys' array — token signature verification likely "
                                    "no-ops or relies on alg confusion.",
                    })
            except Exception:
                pass
    return out


# ---------- helpers ---------------------------------------------------------

def _build_authorize(parsed, qs_overrides):
    qs = {k: v for k, v in (qs_overrides or {}).items() if v is not None}
    return urlunparse(parsed._replace(query=urlencode(qs)))


async def _redirect_uri_probe(ctx, parsed, qs, client_id, response_type, scope, original):
    findings = []
    for evil in EVIL_REDIRECTS:
        url = _build_authorize(parsed, {
            "client_id": client_id, "response_type": response_type,
            "scope": scope, "redirect_uri": evil, "state": "sx_state",
        })
        ev = await ctx.http.get(url, allow_redirects=False)
        loc = ev.response_headers.get("location") or ev.response_headers.get("Location") or ""
        if not loc:
            continue
        host = (urlparse(loc).netloc or "").lower()
        if "evil.samaritanx.test" in host or "attacker.tld" in host:
            findings.append({
                "category": "oauth",
                "title": "Open redirect on OAuth `redirect_uri` (auth-code theft surface)",
                "severity": "critical", "cvss": 9.6,
                "url": parsed.geturl(), "parameter": "redirect_uri", "payload": evil,
                "evidence": f"authorize endpoint forwarded the user to attacker host: {loc}. "
                            "An attacker can craft a link that delivers the victim's authorization "
                            "code (or token in implicit flow) to evil.tld.",
                "request": f"GET {url}",
                "response": loc,
                "metadata": {"location": loc, "original_redirect": original},
            })
            return findings
    return findings


async def _state_required(ctx, parsed, qs, client_id, response_type, scope):
    redirect = qs.get("redirect_uri") or "https://target.example/cb"
    url = _build_authorize(parsed, {
        "client_id": client_id, "response_type": response_type,
        "scope": scope, "redirect_uri": redirect,
        # deliberately omit state
    })
    ev = await ctx.http.get(url, allow_redirects=False)
    body = (ev.response_body or "").lower()
    loc = ev.response_headers.get("location") or ""
    # if the IdP issued a code without state being present -> flow accepts
    # stateless requests, opening login-CSRF
    if (loc and "code=" in loc and "state=" not in loc) or \
       (ev.status == 200 and "consent" in body and "state" not in body):
        return [{
            "category": "oauth",
            "title": "OAuth `state` parameter not required by authorize endpoint",
            "severity": "high", "cvss": 7.1,
            "url": parsed.geturl(), "parameter": "state",
            "evidence": "Authorization request without `state` was accepted — login-CSRF and "
                        "session-fixation become trivial.",
            "request": f"GET {url}",
            "response": loc or body[:600],
        }]
    return []


async def _implicit_flow(ctx, parsed, qs, client_id, scope, original):
    redirect = original or "https://target.example/cb"
    url = _build_authorize(parsed, {
        "client_id": client_id, "response_type": "token",
        "scope": scope, "redirect_uri": redirect, "state": "sx_state",
    })
    ev = await ctx.http.get(url, allow_redirects=False)
    loc = ev.response_headers.get("location") or ""
    if "#access_token=" in loc:
        return [{
            "category": "oauth",
            "title": "OAuth implicit flow (response_type=token) still enabled",
            "severity": "medium", "cvss": 6.1,
            "url": parsed.geturl(), "parameter": "response_type", "payload": "token",
            "evidence": "Endpoint returned `access_token` in the URL fragment — deprecated "
                        "implicit flow exposes tokens to Referer leakage and browser history.",
            "request": f"GET {url}",
            "response": loc,
        }]
    return []


async def _pkce_missing(ctx, parsed, qs, client_id, scope, original):
    """If a public client / SPA can complete the flow without code_challenge, PKCE is optional."""
    redirect = original or "https://target.example/cb"
    url = _build_authorize(parsed, {
        "client_id": client_id, "response_type": "code",
        "scope": scope, "redirect_uri": redirect, "state": "sx_state",
        # deliberately no code_challenge / code_challenge_method
    })
    ev = await ctx.http.get(url, allow_redirects=False)
    loc = ev.response_headers.get("location") or ""
    body = (ev.response_body or "")
    # Heuristic — only fire if the IdP looks happy (consent or code) and
    # didn't error out asking for PKCE
    if "code_challenge" in body.lower():
        return []
    if "code=" in loc or ("consent" in body.lower() and "code_challenge" not in body.lower()):
        return [{
            "category": "oauth",
            "title": "PKCE not enforced on authorization-code flow",
            "severity": "medium", "cvss": 5.4,
            "url": parsed.geturl(), "parameter": "code_challenge",
            "evidence": "Authorize request with no `code_challenge` succeeded — public clients "
                        "(SPAs / mobile apps) are exposed to authorization-code interception.",
            "request": f"GET {url}",
            "response": (loc or body[:600]),
        }]
    return []


async def _scope_escalation(ctx, parsed, qs, client_id, response_type, original):
    redirect = original or "https://target.example/cb"
    big_scope = "openid profile email admin offline_access full_access write:all read:all"
    url = _build_authorize(parsed, {
        "client_id": client_id, "response_type": response_type,
        "scope": big_scope, "redirect_uri": redirect, "state": "sx_state",
    })
    ev = await ctx.http.get(url, allow_redirects=False)
    loc = ev.response_headers.get("location") or ""
    body = (ev.response_body or "").lower()
    # consent UI lists admin/full scopes -> insufficient client whitelist
    if any(s in body for s in ("admin", "full_access", "write:all")) and "consent" in body:
        return [{
            "category": "oauth",
            "title": "OAuth scope escalation possible — consent UI offers admin/* scopes",
            "severity": "high", "cvss": 7.6,
            "url": parsed.geturl(), "parameter": "scope", "payload": big_scope,
            "evidence": "Authorize endpoint rendered a consent screen listing privileged scopes "
                        "even though the client should not be entitled to them. Manual confirm.",
            "request": f"GET {url}",
            "response": body[:1200],
        }]
    return []
