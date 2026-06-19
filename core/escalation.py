"""Impact detection — the difference between a closed-as-informative report
and a paid one.

A finding's *severity* should reflect what an attacker can actually read or do,
not just that a misconfiguration exists. These helpers inspect a response body
and headers for concrete, exfiltratable sensitive data (auth tokens, CSRF
tokens, PII, secrets) so scanners can escalate a primitive (CORS reflection,
cache deception) to the severity its proven impact warrants — and so the chain
engine can confirm a leak end to end.
"""
from __future__ import annotations

import re

# High-value secrets — leaking any of these is escalation-worthy on its own.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}", re.I)
APIKEY_RE = re.compile(r"\b(?:sk|pk|api|key|token|secret)[_\-][A-Za-z0-9]{16,}\b", re.I)
AWSKEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
# Session / CSRF tokens commonly embedded in authenticated pages + JSON.
CSRF_RE = re.compile(r'["\']?(?:csrf|xsrf|_token|authenticity_token)["\']?\s*[:=]\s*["\']([A-Za-z0-9._\-]{8,})', re.I)
SESSION_COOKIE_RE = re.compile(r"\b(?:session|sessionid|sid|jsessionid|phpsessid|auth|access_token)=", re.I)
# PII — confirms the response is private/user-specific.
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
PII_KEY_RE = re.compile(r'"(email|phone|ssn|tax_id|address|first_?name|last_?name|dob|date_of_birth|full_?name)"\s*:', re.I)


# (kind, weight) — weight drives the escalated severity.
def sensitive_hits(body: str, headers: dict | None = None) -> list[tuple[str, str]]:
    """Return [(kind, sample)] of sensitive data present in a response.

    `kind` is a short label; `sample` is a redacted snippet for evidence.
    Ordered most-severe first so callers can take the top hit for severity.
    """
    body = body or ""
    headers = headers or {}
    hits: list[tuple[str, str]] = []

    for label, rx in (("jwt", JWT_RE), ("bearer_token", BEARER_RE),
                      ("aws_key", AWSKEY_RE), ("api_key", APIKEY_RE)):
        m = rx.search(body)
        if m:
            hits.append((label, _redact(m.group(0))))

    m = CSRF_RE.search(body)
    if m:
        hits.append(("csrf_token", _redact(m.group(0))))

    # Set-Cookie that hands out a session is exfiltratable via credentialed CORS
    sc = headers.get("set-cookie", "") if headers else ""
    if SESSION_COOKIE_RE.search(sc):
        hits.append(("session_cookie", _redact(sc.split(";", 1)[0])))

    if PII_KEY_RE.search(body):
        m = PII_KEY_RE.search(body)
        hits.append(("pii", m.group(0)))
    else:
        m = EMAIL_RE.search(body)
        if m:
            hits.append(("email", _redact(m.group(0))))

    # de-dup by kind, keep first (most severe) occurrence
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for k, s in hits:
        if k not in seen:
            seen.add(k)
            out.append((k, s))
    return out


# severity escalation map: the strongest leaked artifact decides the ceiling.
_SEVERITY = {
    "jwt": ("critical", 9.1), "bearer_token": ("critical", 9.1),
    "aws_key": ("critical", 9.3), "api_key": ("critical", 9.0),
    "session_cookie": ("critical", 9.1), "csrf_token": ("high", 8.1),
    "pii": ("high", 7.5), "email": ("medium", 6.1),
}


def severity_for(hits: list[tuple[str, str]]) -> tuple[str, float] | None:
    """Pick the highest severity warranted by the leaked artifacts."""
    if not hits:
        return None
    ranked = sorted(hits, key=lambda h: _SEVERITY.get(h[0], ("info", 0.0))[1], reverse=True)
    return _SEVERITY.get(ranked[0][0], ("medium", 5.0))


def _redact(s: str, keep: int = 6) -> str:
    s = s.strip()
    if len(s) <= keep * 2:
        return s[:keep] + "…"
    return f"{s[:keep]}…{s[-keep:]} (len={len(s)})"
