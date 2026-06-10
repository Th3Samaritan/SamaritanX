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
