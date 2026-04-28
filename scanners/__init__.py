"""Vulnerability scanners — each implements
    `async def scan(ctx, target_url, params, method, form=None) -> list[dict]`
and returns findings matching the memory.record_finding schema.
"""

from .sqli import scan as scan_sqli
from .xss import scan as scan_xss
from .ssrf import scan as scan_ssrf
from .idor import scan as scan_idor
from .csrf import scan as scan_csrf
from .upload import scan as scan_upload
from .open_redirect import scan as scan_open_redirect
from .cors import scan as scan_cors
from .cache_poisoning import scan as scan_cache_poisoning
from .rce import scan as scan_rce
from .api import scan as scan_api
from .prompt_injection import scan as scan_prompt_injection

REGISTRY = {
    "sqli": scan_sqli,
    "xss": scan_xss,
    "ssrf": scan_ssrf,
    "idor": scan_idor,
    "csrf": scan_csrf,
    "upload": scan_upload,
    "open_redirect": scan_open_redirect,
    "cors": scan_cors,
    "cache_poisoning": scan_cache_poisoning,
    "rce": scan_rce,
    "api": scan_api,
    "prompt_injection": scan_prompt_injection,
}
