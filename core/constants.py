"""Shared constants for task kinds, finding categories, and severities.

Replaces magic strings scattered across agents and scanners so the codebase
is easier to maintain and refactoring-friendly.
"""
from __future__ import annotations

from enum import Enum


class TaskKind(str, Enum):
    RECON = "recon"
    DISCOVER = "discover"
    CRAWL = "crawl"
    SCAN = "scan"
    SCAN_GRAPHQL = "scan.graphql"
    SCAN_TAKEOVER = "scan.takeover"
    LOGIC = "logic"
    EXPLOIT = "exploit"
    VALIDATE_SECRETS = "validate_secrets"
    SCREENSHOT = "screenshot"
    REPORT = "report"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    STORED_XSS = "stored_xss"
    DOM_XSS = "dom_xss"
    SSRF = "ssrf"
    IDOR = "idor"
    IDOR_DEEP = "idor_deep"
    CSRF = "csrf"
    UPLOAD = "upload"
    OPEN_REDIRECT = "open_redirect"
    CORS = "cors"
    CACHE_POISONING = "cache_poisoning"
    CRLF = "crlf"
    RCE = "rce"
    API = "api"
    PROMPT_INJECTION = "prompt_injection"
    SMUGGLING = "smuggling"
    H2_SMUGGLING = "h2_smuggling"
    WEBSOCKET = "websocket"
    OAUTH = "oauth"
    GRAPHQL = "graphql"
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    VERSION_BYPASS = "version_bypass"
    JWT_PRIV_ESC = "jwt_priv_esc"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    EXPOSURE = "exposure"
    BROKEN_AUTH = "broken_auth"
    LOGIC = "logic"
    RACE_CONDITION = "race_condition"
    SECRET_EXPOSURE = "secret_exposure"
    NUCLEI = "nuclei"


LEVEL_MAP: dict[str, str] = {
    Severity.CRITICAL: "crit",
    Severity.HIGH: "high",
    Severity.MEDIUM: "med",
    Severity.LOW: "low",
    Severity.INFO: "info",
}

# CWE mapping for finding categories — used by reports and HackerOne drafts.
CWE_MAP: dict[str, tuple[str, str]] = {
    "sqli": ("CWE-89", "SQL Injection"),
    "lfi": ("CWE-98", "Improper Control of Filename for Include/Require"),
    "xss": ("CWE-79", "Cross-site Scripting"),
    "stored_xss": ("CWE-79", "Cross-site Scripting"),
    "dom_xss": ("CWE-79", "Cross-site Scripting"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "rce": ("CWE-78", "OS Command Injection"),
    "ssti": ("CWE-94", "Code Injection / SSTI"),
    "idor": ("CWE-639", "Authorization Bypass / BOLA"),
    "idor_deep": ("CWE-639", "Authorization Bypass / BOLA"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery"),
    "upload": ("CWE-434", "Unrestricted File Upload"),
    "open_redirect": ("CWE-601", "URL Redirection to Untrusted Site"),
    "cors": ("CWE-942", "Permissive Cross-domain Policy"),
    "cache_poisoning": ("CWE-444", "Inconsistent Interpretation of HTTP Requests"),
    "smuggling": ("CWE-444", "HTTP Request Smuggling"),
    "h2_smuggling": ("CWE-444", "HTTP Request Smuggling"),
    "websocket": ("CWE-1385", "Cross-Site WebSocket Hijacking"),
    "api": ("CWE-285", "Improper Authorization"),
    "prompt_injection": ("CWE-1039", "Inadequate Detection or Handling of AI Manipulation"),
    "takeover": ("CWE-350", "Reliance on Reverse DNS for Authorization"),
    "subdomain_takeover": ("CWE-350", "Reliance on Reverse DNS for Authorization"),
    "exposure": ("CWE-200", "Exposure of Sensitive Information"),
    "secret_exposure": ("CWE-798", "Use of Hard-coded Credentials"),
    "broken_auth": ("CWE-287", "Improper Authentication"),
    "race_condition": ("CWE-362", "Concurrent Execution / Race"),
    "graphql_introspection": ("CWE-200", "Information Exposure via GraphQL"),
    "graphql": ("CWE-770", "Allocation of Resources Without Limits / GraphQL"),
    "oauth": ("CWE-601", "OAuth / OIDC Misconfiguration"),
    "logic": ("CWE-840", "Business Logic Errors"),
    "nosqli": ("CWE-943", "NoSQL Injection"),
    "web_cache_deception": ("CWE-525", "Web Cache Deception"),
    "account_takeover": ("CWE-640", "Weak Password Recovery / Account Takeover"),
    "chain": ("CWE-693", "Protection Mechanism Failure (vulnerability chain)"),
    "prototype_pollution": ("CWE-1321", "Prototype Pollution"),
    "host_header": ("CWE-644", "Improper Neutralization of HTTP Headers"),
    "hpp": ("CWE-235", "Improper Handling of Extra Parameters"),
    "path_normalization": ("CWE-178", "Improper Handling of Case Sensitivity / URL Parsing"),
    "security_headers": ("CWE-16", "Configuration"),
    "crlf": ("CWE-93", "Improper Neutralization of CRLF Sequences"),
    "xxe": ("CWE-611", "Improper Restriction of XML External Entity Reference"),
    "jwt_priv_esc": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "version_bypass": ("CWE-285", "Improper Authorization"),
    "deserialization": ("CWE-502", "Deserialization of Untrusted Data"),
    "nuclei": ("", ""),
}
