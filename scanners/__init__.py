"""Vulnerability scanners — each implements
    `async def scan(ctx, target_url, params, method, form=None) -> list[dict]`
and returns findings matching the memory.record_finding schema.

`subdomain_takeover.scan_takeover(ctx, task)` is a host-level scanner
invoked once per run from the `scan.takeover` task kind.
"""

from .sqli import scan as scan_sqli
from .xss import scan as scan_xss
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
from .websocket import scan as scan_websocket
from .subdomain_takeover import scan_takeover

REGISTRY = {
    "sqli": scan_sqli,
    "xss": scan_xss,
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
    "websocket": scan_websocket,
}
