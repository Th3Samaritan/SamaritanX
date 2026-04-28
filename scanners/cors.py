"""CORS misconfiguration scanner."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.orchestrator import Context


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    evil = "https://evil.samaritanx.test"
    ev = await ctx.http.get(url, headers={"Origin": evil})
    aco = ev.response_headers.get("access-control-allow-origin")
    acc = (ev.response_headers.get("access-control-allow-credentials") or "").lower() == "true"
    if not aco:
        return findings
    if aco == evil and acc:
        findings.append({
            "category": "cors",
            "title": "CORS misconfig: arbitrary origin reflected with credentials",
            "severity": "high", "cvss": 7.4,
            "url": url,
            "evidence": f"ACAO reflected attacker origin '{evil}' AND ACA-Credentials=true — "
                        "any origin can read authenticated responses.",
            "request": f"GET {url}\nOrigin: {evil}",
            "response": str({k: v for k, v in ev.response_headers.items() if k.lower().startswith("access-")}),
        })
    elif aco == "*" and acc:
        # Browsers reject this combination, but it indicates intent — flag low
        findings.append({
            "category": "cors",
            "title": "CORS: wildcard origin with credentials (browser-blocked but suspicious)",
            "severity": "low", "cvss": 3.7,
            "url": url,
            "evidence": "ACAO=* with credentials=true is explicitly blocked by browsers, "
                        "but suggests insecure intent.",
        })
    elif aco and aco != "null" and aco != "*":
        # arbitrary reflection without credentials still leaks unauthenticated data
        if aco == evil:
            findings.append({
                "category": "cors",
                "title": "CORS: arbitrary origin reflected (no credentials)",
                "severity": "medium", "cvss": 5.3,
                "url": url,
                "evidence": f"ACAO reflected attacker origin '{evil}' without ACA-Credentials. "
                            "Sensitive unauthenticated data may still be exposed cross-origin.",
            })
    return findings
