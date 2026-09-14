"""Expose benchmark gaps instead of treating an untested scanner as accurate."""

# name, vulnerable route, clean route, inputs, expected category
HTTP_FIXTURES = [
    ("sqli", "/sqli", "/page", ["q"], "sqli"),
    ("xss", "/xss", "/xss-encoded", ["q"], "xss"),
    ("lfi", "/lfi", "/page", ["file"], "lfi"),
    ("ssrf", "/fetch", "/echo-param", ["url"], "ssrf"),
    ("open_redirect", "/redirect", "/page", ["url"], "open_redirect"),
    ("hpp", "/hpp", "/page", ["p"], "hpp"),
    ("host_header", "/host", "/page", [], "host_header"),
    ("cors", "/cors", "/page", [], "cors"),
    ("cache_poisoning", "/cache", "/page", [], "cache_poisoning"),
    ("path_normalization", "/admin", "/denied", [], "broken_auth"),
    ("version_bypass", "/api/v1/admin", "/api/v1/denied", [], "broken_auth"),
    ("idor", "/obj?id=1", "/page?id=1", ["id"], "idor"),
    ("nosqli", "/nosql/login", "/nosql/clean/login", [], "nosqli"),
    ("xxe", "/vulnerable.xml", "/clean.xml", [], "xxe"),
    ("crlf", "/crlf", "/page", ["q"], "crlf"),
    ("security_headers", "/page", "/hardened", [], "security_headers"),
]
REPLAY_FIXTURES = {"csrf": "form observation", "deserialization": "format observation",
                   "dom_xss": "browser observation", "websocket": "message transcript"}
REPLAY_FIXTURES.update({name: "HTTP response replay" for name in (
    "api", "graphql", "oauth", "idor_deep", "jwt_priv_esc", "rce", "prompt_injection",
    "upload", "prototype_pollution", "param_miner", "account_takeover", "web_cache_deception")})
REPLAY_FIXTURES.update({"smuggling": "timing/HTTP transcript", "h2_smuggling": "downgrade transcript",
                        "stored_xss": "browser observation"})
PAIRED_SCANNERS = {case[0] for case in HTTP_FIXTURES} | set(REPLAY_FIXTURES)


def inventory():
    from scanners import REGISTRY
    return {name: {"paired_local_fixture": name in PAIRED_SCANNERS,
                   "fixture_kind": REPLAY_FIXTURES.get(name, "local HTTP" if name in PAIRED_SCANNERS else None),
                   "status": "paired regression" if name in PAIRED_SCANNERS else "needs paired fixture"}
            for name in sorted(REGISTRY)}
