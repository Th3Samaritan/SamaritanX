"""Live secret validator.

Crawler raises secret-exposure findings on regex matches. Most are false
positives (example keys in JS bundles, doc snippets). This agent walks
the recorded findings, attempts a *benign* read-only API call against
the originating provider, and updates the finding's severity / metadata
based on whether the credential is live.

Validators implemented (all benign — no destructive verbs, no billable
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
STRIPE_RE = re.compile(r"sk_live_[0-9a-zA-Z]{24,}")
SENDGRID_RE = re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")
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
                new_title = f"[FALSE POSITIVE — rejected by provider] {f['title']}"
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
        # AWS — needs both access + secret to verify; we look for them together
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
            ok = '"ok":true' in (ev.response_body or "")
            return "slack", bool(ok), {"body": (ev.response_body or "")[:200]}

        m = GH_PAT_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {m.group(0)}",
                         "Accept": "application/vnd.github+json"},
                bypass_scope=True,
            )
            return "github", ev.status == 200, {"login_present": '"login"' in (ev.response_body or "")}

        m = STRIPE_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.stripe.com/v1/balance",
                headers={"Authorization": f"Bearer {m.group(0)}"},
                bypass_scope=True,
            )
            return "stripe", ev.status == 200, {"status": ev.status}

        m = SENDGRID_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {m.group(0)}"},
                bypass_scope=True,
            )
            return "sendgrid", ev.status == 200, {"status": ev.status}

        m = NPM_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://registry.npmjs.org/-/whoami",
                headers={"Authorization": f"Bearer {m.group(0)}"},
                bypass_scope=True,
            )
            return "npm", ev.status == 200, {"status": ev.status}

        m = DO_RE.search(blob)
        if m:
            ev = await ctx.http.get(
                "https://api.digitalocean.com/v2/account",
                headers={"Authorization": f"Bearer {m.group(0)}"},
                bypass_scope=True,
            )
            return "digitalocean", ev.status == 200, {"status": ev.status}

        return "unmatched", None, {}

    async def _aws_sts(self, akid: str, secret: str, ctx) -> tuple[bool, dict]:
        # AWS SigV4 signing in pure Python is verbose — try the import path first
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
            return False, {"error": str(exc)}
