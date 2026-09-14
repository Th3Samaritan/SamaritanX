"""Scanner execution identities and budgets for reproducible coverage records.

Only successful, recent executions may be reused. Response similarity alone
cannot establish that authorization or application behavior is unchanged.
"""
from __future__ import annotations

import hashlib
import inspect
import json
from functools import lru_cache
from pathlib import Path
from contextvars import ContextVar
from dataclasses import dataclass


class RequestBudgetExceeded(RuntimeError):
    pass


@dataclass
class RequestBudget:
    limit: int
    used: int = 0
    exhausted: bool = False

    def take(self):
        if self.used >= self.limit:
            self.exhausted = True
            raise RequestBudgetExceeded("scanner request budget exhausted")
        self.used += 1


request_budget: ContextVar[RequestBudget | None] = ContextVar("scan_budget", default=None)

# Shared execution states + stable reason codes (plan §11.3). Empty output is
# only "clean" after successful execution AND parsing — every other outcome
# stays distinct and can never be read as "no vulnerabilities found".
STATUSES = ("completed", "skipped", "blocked", "timed_out", "cancelled",
            "failed", "partial", "queued", "interrupted", "budget_exhausted")

REASON_CODES = {
    "scope_denied": "request denied by the scope policy",
    "request_budget_exhausted": "scanner request budget exhausted",
    "catalog_startup_timeout": "catalog selection did not start in time",
    "dependency_missing": "required executable or runtime unavailable",
    "output_parse_error": "tool output could not be parsed",
    "timed_out": "scanner deadline exceeded",
    "cancelled": "run cancelled",
    "mutation_blocked": "state-changing operation blocked (safety.aggressive off)",
    "credential_boundary": "credentials withheld crossing an origin boundary",
    "circuit_open": "origin circuit breaker open — requests rejected fast",
    "provider_denied": "host not in the external-provider allowlist",
    "transport_failed": "network or transport error",
}


@lru_cache(maxsize=1)
def engine_version():
    root = Path(__file__).resolve().parent.parent
    digest = hashlib.sha256()
    for folder in ("core", "scanners", "agents"):
        for path in sorted((root / folder).glob("*.py")):
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def _canonical(obj):
    """Deterministic JSON-able form: dict keys coerced to strings and sorted,
    so mixed key types (e.g. config values that survived a merge as bools)
    cannot crash the digest builder."""
    if isinstance(obj, dict):
        return {str(k): _canonical(v)
                for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, (list, tuple)):
        return [_canonical(v) for v in obj]
    return obj


def execution_key(ctx, name, fn, url, params, method, form):
    identities = []
    sessions = [getattr(ctx, "session", None),
                getattr(getattr(ctx, "http2", None), "session", None)]
    extras = getattr(ctx, "extra_identities", None) or []
    sessions.extend(getattr(i.get("client"), "session", None) for i in extras)
    for session in sessions:
        identities.append({k: getattr(session, k, None) for k in
                           ("label", "headers", "cookies")})
    try:
        version = inspect.getsource(fn)
    except (OSError, TypeError):
        version = repr(fn)
    # Persist only a digest: config and session material may contain credentials.
    material = [engine_version(), name, version, url, sorted(params), method.upper(), form,
                ctx.config, identities, [{"label": i.get("label"), "rank": i.get("rank")} for i in extras]]
    return hashlib.sha256(json.dumps(_canonical(material), default=str).encode()).hexdigest()


def applicability(name, params, form, content_type):
    """Conservative rules; unknown surfaces stay eligible for testing."""
    if name in {"dom_xss", "prototype_pollution"} and "/" in content_type:
        if not any(t in content_type.lower() for t in ("html", "javascript")):
            return False, "response is not HTML or JavaScript"
    return True, "enabled; no conclusive applicability exclusion"
