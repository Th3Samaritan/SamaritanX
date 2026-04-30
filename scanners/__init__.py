"""Vulnerability scanners — each implements
    `async def scan(ctx, target_url, params, method, form=None) -> list[dict]`
and returns findings matching the memory.record_finding schema.

`subdomain_takeover.scan_takeover(ctx, task)` is a host-level scanner
invoked once per run from the `scan.takeover` task kind.
`graphql.scan(...)` runs on its own `scan.graphql` task kind.
"""

from .sqli import scan as scan_sqli
from .xss import scan as scan_xss
from .stored_xss import scan as scan_stored_xss
from .ssrf import scan as scan_ssrf
from .idor import scan as scan_idor
from .idor_deep import scan as scan_idor_deep
from .csrf import scan as scan_csrf
from .upload import scan as scan_upload
from .open_redirect import scan as scan_open_redirect
from .cors import scan as scan_cors
from .cache_poisoning import scan as scan_cache_poisoning
from .rce import scan as scan_rce
from .api import scan as scan_api
from .prompt_injection import scan as scan_prompt_injection
from .dom_xss import scan as scan_dom_xss
from .request_smuggling import scan as scan_request_smuggling
from .h2_smuggling import scan as scan_h2_smuggling
from .websocket import scan as scan_websocket
from .oauth import scan as scan_oauth
from .graphql import scan as scan_graphql
from .crlf import scan as scan_crlf
from .xxe import scan as scan_xxe
from .deserialization import scan as scan_deserialization
from .version_bypass import scan as scan_version_bypass
from .jwt_priv_esc import scan as scan_jwt_priv_esc
from .subdomain_takeover import scan_takeover

REGISTRY = {
    "sqli": scan_sqli,
    "xss": scan_xss,
    "stored_xss": scan_stored_xss,
    "dom_xss": scan_dom_xss,
    "ssrf": scan_ssrf,
    "idor": scan_idor,
    "idor_deep": scan_idor_deep,
    "csrf": scan_csrf,
    "upload": scan_upload,
    "open_redirect": scan_open_redirect,
    "cors": scan_cors,
    "cache_poisoning": scan_cache_poisoning,
    "rce": scan_rce,
    "api": scan_api,
    "prompt_injection": scan_prompt_injection,
    "smuggling": scan_request_smuggling,
    "h2_smuggling": scan_h2_smuggling,
    "websocket": scan_websocket,
    "oauth": scan_oauth,
    "graphql": scan_graphql,
    "crlf": scan_crlf,
    "xxe": scan_xxe,
    "deserialization": scan_deserialization,
    "version_bypass": scan_version_bypass,
    "jwt_priv_esc": scan_jwt_priv_esc,
}

# Scanners that justify an auth pre-flight before firing — high CVSS, slow,
# or with side-effects expensive enough that we want a fresh session.
HIGH_VALUE = {"rce", "ssrf", "idor_deep", "upload", "smuggling", "h2_smuggling",
              "xxe", "jwt_priv_esc", "version_bypass", "oauth", "stored_xss"}
