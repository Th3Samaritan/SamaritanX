"""Fresh verification contexts and report-time evidence expiration checks."""
import copy
import time

from .auth import SessionStore
from .http_client import StealthHttpClient
from .req_cache import BaselineCache


async def fresh_check(ctx, finding, checker):
    fresh = copy.copy(ctx)
    fresh.cache = BaselineCache(ttl=0)
    clients = []
    try:
        for attr in ("http", "http2"):
            original = getattr(ctx, attr, None)
            if not isinstance(original, StealthHttpClient):
                continue
            client = StealthHttpClient(ctx.config)
            clients.append(client)
            session = SessionStore()
            source = getattr(original, "session", None)
            if source:
                session.cookies.update(source.cookies)
                session.headers.update(source.headers)
                session.label = source.label
            client.attach(session=session, scope=getattr(ctx, "scope", None))
            client.transport = getattr(original, "transport", None)
            setattr(fresh, attr, client)
            if attr == "http":
                fresh.session = session
        url = finding.get("url")
        if url:
            baseline = await fresh.http.get(url, allow_redirects=False)
            if getattr(baseline, "error", None) or not baseline.status or baseline.status >= 500:
                return None
            finding.setdefault("metadata", {})["verification_baseline"] = {
                "status": baseline.status, "response_excerpt": baseline.response_body[:1200]}
            from .revalidate import _SQL_ERR, _NOSQL_ERR, _RCE_MARKER
            static_signal = {"sqli": _SQL_ERR, "nosqli": _NOSQL_ERR, "rce": _RCE_MARKER}.get(finding.get("category"))
            if static_signal and static_signal.search(baseline.response_body or ""):
                return None
            if getattr(fresh, "session", None) and fresh.session.is_authed() and baseline.status in (401, 403):
                return None
        return await checker(fresh, finding)
    finally:
        for client in clients:
            await client.close()


def report_freshness(finding, max_age=86400, now=None):
    now = time.time() if now is None else now
    meta = finding.setdefault("metadata", {})
    proof = meta.get("poc") or {}
    stamp = meta.get("verified_at") or proof.get("captured_at") or finding.get("discovered")
    valid = isinstance(stamp, (int, float)) and 0 <= now - stamp <= max_age
    meta["evidence_expired"] = not valid
    return valid
