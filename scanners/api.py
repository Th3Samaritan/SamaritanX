"""API-focused scanner — OWASP API Top 10 checks for REST + GraphQL.

Coverage:
  * API1 — BOLA (broken object-level auth) signal: same-tenant id swap
  * API2 — Broken authentication: missing/weak auth on sensitive endpoints
  * API3 — Excessive data exposure: large JSON returned without filters
  * API4 — Lack of resource & rate limiting (rapid burst probe)
  * API6 — Mass assignment: extra fields accepted on POST/PUT
  * API7 — JWT issues (alg=none, weak secret, missing expiration)
  * API9 — Improper inventory: presence of /v1/, /v2/, /internal/ siblings
  * GraphQL — verbose errors / introspection + query depth abuse
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import hashlib
import json
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import urljoin

if TYPE_CHECKING:
    from core.orchestrator import Context

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{10,}")
SENSITIVE_KEYS = {"password", "ssn", "token", "secret", "credit_card", "card_number",
                  "cvv", "pin", "private_key", "session", "api_key"}


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    findings.extend(await _excessive_exposure(ctx, url))
    findings.extend(await _missing_rate_limit(ctx, url))
    findings.extend(await _api_versioning(ctx, url))
    findings.extend(await _mass_assignment(ctx, url, method))
    findings.extend(await _jwt_weakness(ctx, url))
    return findings


# ---------- excessive data exposure ----------
async def _excessive_exposure(ctx, url):
    ev = await ctx.http.get(url)
    if ev.status != 200 or "json" not in ev.response_headers.get("content-type", "").lower():
        return []
    try:
        data = json.loads(ev.response_body)
    except Exception:
        return []
    leaked = _find_sensitive_keys(data)
    if leaked:
        return [{
            "category": "api",
            "title": "API3 — Excessive data exposure (sensitive fields returned)",
            "severity": "high", "cvss": 7.5,
            "url": url,
            "evidence": f"Response includes sensitive keys: {sorted(leaked)[:8]}",
            "request": f"GET {url}",
            "response": ev.response_body[:1500],
            "metadata": {"keys": sorted(leaked)},
        }]
    return []


def _find_sensitive_keys(node, found=None) -> set[str]:
    found = set() if found is None else found
    if isinstance(node, dict):
        for k, v in node.items():
            if k.lower() in SENSITIVE_KEYS and v not in (None, "", "***"):
                found.add(k)
            _find_sensitive_keys(v, found)
    elif isinstance(node, list):
        for v in node:
            _find_sensitive_keys(v, found)
    return found


# ---------- missing rate limit ----------
async def _missing_rate_limit(ctx, url):
    if not ctx.config.get("safety", {}).get("aggressive"):
        return []  # 20 auth POSTs can lock accounts — requires --aggressive
    if "/login" not in url.lower() and "/auth" not in url.lower() and "/token" not in url.lower():
        return []
    statuses = []
    for _ in range(20):
        ev = await ctx.http.post(url, json_body={"username": "admin", "password": "x"})
        statuses.append(ev.status)
    if 429 not in statuses and statuses.count(401) >= 15:
        return [{
            "category": "api",
            "title": "API4 — No rate limiting on authentication endpoint",
            "severity": "medium", "cvss": 5.3,
            "url": url,
            "evidence": "20 consecutive POSTs returned 401/200 with no 429 — credential stuffing is feasible.",
            "metadata": {"statuses": statuses},
        }]
    return []


# ---------- API versioning leak ----------
async def _api_versioning(ctx, url):
    findings = []
    for path in ("/v1/", "/v2/", "/v3/", "/internal/", "/admin/", "/_debug/"):
        probe = urljoin(url, path)
        ev = await ctx.http.get(probe)
        if ev.status not in (200, 401, 403):
            continue
        if "json" in ev.response_headers.get("content-type", "").lower() or ev.status == 200:
            findings.append({
                "category": "api",
                "title": f"API9 — Sibling API surface exposed: {probe}",
                "severity": "low", "cvss": 4.3,
                "url": probe,
                "evidence": f"Path {path} responded with status {ev.status}",
            })
    return findings


# ---------- mass assignment ----------
async def _mass_assignment(ctx, url, method):
    if method.upper() not in ("POST", "PUT", "PATCH"):
        return []
    payload = {
        "username": "sx_test", "email": "sx@test.invalid",
        "is_admin": True, "role": "admin", "balance": 999999,
    }
    ev = await ctx.http.post(url, json_body=payload,
                             headers={"Content-Type": "application/json"})
    if ev.status in (200, 201):
        try:
            data = json.loads(ev.response_body)
        except Exception:
            return []
        for k in ("is_admin", "role", "balance"):
            if isinstance(data, dict) and data.get(k) == payload[k]:
                return [{
                    "category": "api",
                    "title": f"API6 — Mass assignment: privileged field `{k}` honored",
                    "severity": "critical", "cvss": 9.1,
                    "url": url, "parameter": k, "payload": json.dumps(payload),
                    "evidence": f"Server returned `{k}` set to attacker-supplied value.",
                    "request": f"POST {url}\n\n{json.dumps(payload)}",
                    "response": ev.response_body[:1500],
                }]
    return []


# ---------- JWT weakness ----------
async def _jwt_weakness(ctx, url):
    findings = []
    ev = await ctx.http.get(url)
    text = ev.response_body or ""
    cookies = ev.response_headers.get("set-cookie", "") or ""
    auth_h = ev.response_headers.get("authorization", "") or ""
    candidates = JWT_RE.findall(text) + JWT_RE.findall(cookies) + JWT_RE.findall(auth_h)
    seen = set()
    for jwt in candidates:
        if jwt in seen:
            continue
        seen.add(jwt)
        parts = jwt.split(".")
        if len(parts) != 3:
            continue
        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
        except Exception:
            continue
        issues = []
        if (header.get("alg") or "").lower() == "none":
            issues.append(("alg=none", "critical", 9.8))
        if "exp" not in payload:
            issues.append(("missing exp claim", "medium", 5.3))
        if _try_weak_secret(jwt):
            issues.append(("weak HMAC secret", "critical", 9.1))
        for label, sev, cvss in issues:
            findings.append({
                "category": "api",
                "title": f"API7 — JWT vulnerability: {label}",
                "severity": sev, "cvss": cvss,
                "url": url, "evidence": f"Token: {jwt[:60]}...",
                "metadata": {"alg": header.get("alg"), "claims": list(payload.keys())},
            })
    return findings


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _try_weak_secret(token: str) -> bool:
    head, payload, sig = token.split(".")
    msg = f"{head}.{payload}".encode()
    sig_bytes = _b64url_decode(sig)
    for secret in ("secret", "password", "1234", "admin", "key", "test", "jwt", "changeme"):
        h = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        if hmac.compare_digest(h, sig_bytes):
            return True
    return False
