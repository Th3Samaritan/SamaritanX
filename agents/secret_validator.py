"""Live secret validator.

Crawler raises secret-exposure findings on regex matches. Most are false
positives (example keys in JS bundles, doc snippets). This agent walks
the recorded findings, attempts a *benign* read-only API call against
the originating provider, and updates the finding's severity / metadata
based on whether the credential is live.

Validators implemented (all benign ΓÇö no destructive verbs, no billable
operations beyond a single auth-test):

    aws_access_key + aws_secret_key   -> sts.GetCallerIdentity
    slack_token                       -> auth.test
    github_pat / github_oauth         -> /user
    stripe_live (sk_live_*)           -> /v1/balance
    sendgrid                          -> /v3/scopes
    mailgun                           -> /v3/domains
    npm_token                         -> /-/whoami
    cloudflare_api                    -> /user/tokens/verify
    digitalocean_pat                  -> /v2/account

Findings the validator could not match a rule for are left unchanged.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING

from core.task_queue import Task
from .base import BaseAgent

if TYPE_CHECKING:
    from core.orchestrator import Context

AKIA_RE = re.compile(r"AKIA[0-9A-Z]{16}")
AWS_SECRET_RE = re.compile(r"(?i)(?<![A-Za-z0-9/])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/])")
SLACK_RE = re.compile(r"xox[baprs]-[A-Za-z0-9-]+")
GH_PAT_RE = re.compile(r"gh[ops]_[A-Za-z0-9]{36}")
GH_FINE_RE = re.compile(r"github_pat_[A-Za-z0-9_]{22,}")
GL_PAT_RE = re.compile(r"glpat-[A-Za-z0-9_\-]{20,}")
ANTHROPIC_RE = re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")
OPENAI_RE = re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")
TWILIO_SID_RE = re.compile(r"AC[0-9a-fA-F]{32}")
TWILIO_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])([0-9a-fA-F]{32})(?![A-Za-z0-9])")
HEROKU_RE = re.compile(r"(?<![A-Za-z0-9])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![A-Za-z0-9])")
STRIPE_RE = re.compile(r"sk_live_[0-9a-zA-Z]{24,}")
SENDGRID_RE = re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")
MAILGUN_RE = re.compile(r"key-[0-9a-f]{32}")
CF_API_RE = re.compile(r"[A-Za-z0-9_-]{37,40}")
NPM_RE = re.compile(r"npm_[A-Za-z0-9]{36}")
DO_RE = re.compile(r"dop_v1_[A-Za-z0-9]{64}")


class SecretValidatorAgent(BaseAgent):
    name = "secret_validator"
    handles = ("validate_secrets",)

    async def handle(self, task: Task, ctx: "Context") -> None:
        findings = ctx.memory.list_findings(ctx.target_slug)
        targets = [f for f in findings if f.get("category") == "secret_exposure"]
        if not targets:
            return
        ctx.dashboard.event("info", f"validator: checking {len(targets)} candidate secrets")

        live = 0
        dead = 0
        for f in targets:
            evidence = (f.get("evidence") or "") + " " + (f.get("response") or "")
            kind, valid, meta = await self._validate(evidence, ctx)
            updated_meta = dict(f.get("metadata") or {})
            if isinstance(updated_meta, str):
                try:
                    updated_meta = json.loads(updated_meta)
                except Exception:
                    updated_meta = {}
            updated_meta["validator_kind"] = kind
            updated_meta["validator_valid"] = valid
            updated_meta["validator_meta"] = meta
            new_severity = f["severity"]
            new_cvss = f["cvss"]
            new_title = f["title"]
            if valid is True:
                new_severity = "critical"
                new_cvss = max(float(f.get("cvss", 0)), 9.5)
                new_title = f"[CONFIRMED LIVE] {f['title']}"
                live += 1
            elif valid is False:
                new_severity = "info"
                new_cvss = 0.0
                new_title = f"[FALSE POSITIVE ΓÇö rejected by provider] {f['title']}"
                dead += 1
            ctx.memory.update_finding(
                f["id"],
                severity=new_severity,
                cvss=new_cvss,
                title=new_title,
                metadata=updated_meta,
            )
        ctx.dashboard.event("ok",
            f"validator: {live} live secrets confirmed, {dead} demoted as false positives")

    async def _validate(self, blob: str, ctx) -> tuple[str, bool | None, dict]:
        # AWS ΓÇö needs both access + secret to verify; we look for them together
        ak = AKIA_RE.search(blob)
        if ak:
            sk_match = AWS_SECRET_RE.search(blob.replace(ak.group(0), "", 1))
            if sk_match:
                ok, meta = await self._aws_sts(ak.group(0), sk_match.group(0), ctx)
                return "aws", ok, meta
            return "aws", None, {"reason": "secret_not_found_alongside_AKIA"}

        m = SLACK_RE.search(blob)
        if m:
            ev = await ctx.http.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {m.group(0)}"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "slack", None, {"reason": "transport_error"}
            # Slack returns {"ok": true|false, ...} — a *space* after the colon,
            # so a naive '"ok":true' substring never matches.
            ok = False
            try:
                data = json.loads(ev.response_body or "{}")
                if isinstance(data, dict):
                    ok = data.get("ok") is True
            except Exception:
                body = (ev.response_body or "").lower()
                ok = '"ok": true' in body or '"ok":true' in body
            return "slack", bool(ok), {"body": (ev.response_body or "")[:200]}

        m = GH_PAT_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {m.group(0)}",
                         "Accept": "application/vnd.github+json"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "github", None, {"reason": "transport_error"}
            return "github", ev.status == 200, {"login_present": '"login"' in (ev.response_body or "")}

        m = GH_FINE_RE.search(blob)
        if m:
            # fine-grained PATs often lack the /user scope — /user 401 may
            # still be a live token, so fall back to the rate-limit endpoint
            ev = await ctx.http.get(
                "https://api.github.com/rate_limit",
                headers={"Authorization": f"token {m.group(0)}",
                         "Accept": "application/vnd.github+json"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "github_fine_grained", None, {"reason": "transport_error"}
            ok = ev.status == 200 and '"resources"' in (ev.response_body or "")
            return "github_fine_grained", ok, {"status": ev.status}

        m = ANTHROPIC_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": m.group(0), "anthropic-version": "2023-06-01"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "anthropic", None, {"reason": "transport_error"}
            return "anthropic", ev.status == 200, {"status": ev.status}

        m = OPENAI_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {m.group(0)}"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "openai", None, {"reason": "transport_error"}
            return "openai", ev.status == 200, {"status": ev.status}

        # Twilio: account SID + auth token pair
        tsid = TWILIO_SID_RE.search(blob)
        if tsid:
            ttok = TWILIO_TOKEN_RE.search(blob.replace(tsid.group(0), "", 1))
            if ttok:
                import base64 as _b64
                cred = _b64.b64encode(f"{tsid.group(0)}:{ttok.group(0)}".encode()).decode()
                ev = await ctx.http.get(
                    f"https://api.twilio.com/2010-04-01/Accounts/{tsid.group(0)}.json",
                    headers={"Authorization": f"Basic {cred}"},
                    bypass_scope=True,
                )
                if _transport_failed(ev):
                    return "twilio", None, {"reason": "transport_error"}
                return "twilio", ev.status == 200, {"status": ev.status}
            return "twilio", None, {"reason": "token_not_found_alongside_SID"}

        m = HEROKU_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.heroku.com/account",
                headers={"Authorization": f"Bearer {m.group(0)}",
                         "Accept": "application/vnd.heroku+json; version=3"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "heroku", None, {"reason": "transport_error"}
            return "heroku", ev.status == 200, {"email_present": '"email"' in (ev.response_body or "")}

        m = GL_PAT_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://gitlab.com/api/v4/user",
                headers={"PRIVATE-TOKEN": m.group(0)},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "gitlab", None, {"reason": "transport_error"}
            return "gitlab", ev.status == 200, {"username_present": '"username"' in (ev.response_body or "")}

        m = MAILGUN_RE.search(blob)
        if m:
            import base64 as _b64
            cred = _b64.b64encode(f"api:{m.group(0)}".encode()).decode()
            ev = await ctx.http.get(
                "https://api.mailgun.net/v3/domains",
                headers={"Authorization": f"Basic {cred}"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "mailgun", None, {"reason": "transport_error"}
            return "mailgun", ev.status == 200, {"status": ev.status}

        # Cloudflare tokens carry no distinctive prefix, so only attempt when
        # the evidence itself mentions cloudflare
        if re.search(r"cloudflare", blob, re.I):
            m = CF_API_RE.search(blob)
            if m:
                ev = await ctx.http.get(
                    "https://api.cloudflare.com/client/v4/user/tokens/verify",
                    headers={"Authorization": f"Bearer {m.group(0)}"},
                    bypass_scope=True,
                )
                if _transport_failed(ev):
                    return "cloudflare_api", None, {"reason": "transport_error"}
                ok = ev.status == 200 and '"success": true' in (ev.response_body or "")
                return "cloudflare_api", ok, {"status": ev.status}

        m = STRIPE_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.stripe.com/v1/balance",
                headers={"Authorization": f"Bearer {m.group(0)}"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "stripe", None, {"reason": "transport_error"}
            return "stripe", ev.status == 200, {"status": ev.status}

        m = SENDGRID_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {m.group(0)}"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "sendgrid", None, {"reason": "transport_error"}
            return "sendgrid", ev.status == 200, {"status": ev.status}

        m = NPM_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://registry.npmjs.org/-/whoami",
                headers={"Authorization": f"Bearer {m.group(0)}"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "npm", None, {"reason": "transport_error"}
            return "npm", ev.status == 200, {"status": ev.status}

        m = DO_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.digitalocean.com/v2/account",
                headers={"Authorization": f"Bearer {m.group(0)}"},
                bypass_scope=True,
            )
            if _transport_failed(ev):
                return "digitalocean", None, {"reason": "transport_error"}
            return "digitalocean", ev.status == 200, {"status": ev.status}

        return "unmatched", None, {}

    async def _aws_sts(self, akid: str, secret: str, ctx) -> tuple[bool | None, dict]:
        # AWS SigV4 signing in pure Python is verbose ΓÇö try the import path first
        try:
            import datetime, hashlib, hmac
            t = datetime.datetime.now(datetime.timezone.utc)
            amzdate = t.strftime("%Y%m%dT%H%M%SZ")
            datestamp = t.strftime("%Y%m%d")
            region, service, host = "us-east-1", "sts", "sts.amazonaws.com"
            canonical_qs = "Action=GetCallerIdentity&Version=2011-06-15"
            payload_hash = hashlib.sha256(b"").hexdigest()
            canonical_headers = f"host:{host}\nx-amz-date:{amzdate}\n"
            signed_headers = "host;x-amz-date"
            canonical_request = "\n".join([
                "GET", "/", canonical_qs,
                canonical_headers, signed_headers, payload_hash,
            ])
            credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
            string_to_sign = "\n".join([
                "AWS4-HMAC-SHA256", amzdate, credential_scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            ])
            def sign(key, msg): return hmac.new(key, msg.encode(), hashlib.sha256).digest()
            kdate = sign(("AWS4" + secret).encode(), datestamp)
            kreg = sign(kdate, region)
            ksvc = sign(kreg, service)
            ksig = sign(ksvc, "aws4_request")
            signature = hmac.new(ksig, string_to_sign.encode(), hashlib.sha256).hexdigest()
            auth = (f"AWS4-HMAC-SHA256 Credential={akid}/{credential_scope}, "
                    f"SignedHeaders={signed_headers}, Signature={signature}")
            url = f"https://{host}/?{canonical_qs}"
            ev = await ctx.http.get(url,
                headers={"x-amz-date": amzdate, "Authorization": auth, "host": host},
                bypass_scope=True)
            ok = ev.status == 200 and "<UserId>" in (ev.response_body or "")
            return bool(ok), {"status": ev.status,
                              "snippet": (ev.response_body or "")[:300]}
        except Exception as exc:
            return None, {"error": str(exc)}


def _transport_failed(ev) -> bool:
    """True when the provider call never completed (network/timeout/DNS) — in
    that case we learned nothing about the credential and must leave the
    finding untouched instead of demoting it as rejected."""
    return bool(getattr(ev, "error", None)) or (getattr(ev, "status", 0) or 0) == 0
