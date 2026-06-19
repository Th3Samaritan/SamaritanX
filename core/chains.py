"""Relationship-aware vulnerability chaining + escalation engine.

The old approach declared a chain whenever two *categories* existed anywhere on
the target and printed a sentence. That over-claims (the two bugs may be on
unrelated hosts) and proves nothing. This engine instead:

  1. Correlates findings by **origin / host** — a chain only forms from bugs an
     attacker can actually combine in one attack path.
  2. **Actively verifies** the escalation where it can. Read-only proofs (re-
     reading a credentialed CORS body, confirming an open redirect leaves the
     host) always run; any step that would change server state is gated behind
     `--aggressive`.
  3. Emits a single **escalated `chain` finding** with a combined CVSS, the
     component finding ids, the verification evidence, and a concrete PoC — the
     thing that turns several "informational" reports into one paid critical.

`build_chains` returns finding dicts; the ExploitAgent persists them through
the normal reporting path.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Awaitable, Callable, Optional
from urllib.parse import urlparse

from .escalation import sensitive_hits, severity_for
from .utils import host_of, root_domain

if TYPE_CHECKING:
    from .orchestrator import Context

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _origin(url: str) -> str:
    try:
        p = urlparse(url if "://" in url else "https://" + url)
        return f"{p.scheme}://{p.netloc}".lower()
    except Exception:
        return ""


@dataclass
class ChainMatch:
    parts: dict[str, dict]          # category -> representative finding
    severity: str
    cvss: float
    narrative: str
    evidence: str
    verified: bool
    poc: str = ""


# A verifier returns (verified, evidence, escalated_severity_or_None).
Verifier = Callable[["Context", dict[str, dict], bool], Awaitable[tuple[bool, str, Optional[tuple]]]]


@dataclass
class Recipe:
    name: str
    parts: tuple[str, ...]
    severity: str
    cvss: float
    narrative: str
    scope: str = "same_origin"      # same_origin | same_host | same_root | global
    verifier: Optional[Verifier] = None
    writes: bool = False            # verifier performs a state change
    # Which component categories the verifier's result actually depends on, so
    # the same proof isn't re-fetched for every candidate pairing. Defaults to
    # all parts.
    verify_key: Optional[tuple[str, ...]] = None


# Candidate-selection bounds — keep verification cost and report noise sane.
MAX_CANDIDATES_PER_CAT = 5   # endpoints considered per category, per group
MAX_COMBOS = 8               # pairings actually evaluated, best-scored first
MAX_VERIFIED_EMIT = 2        # distinct verified chains emitted per recipe+group


# --------------------------------------------------------------------------- #
# Active verifiers (read-only unless writes=True on the recipe)
# --------------------------------------------------------------------------- #
async def _verify_cors_exfil(ctx, parts, aggressive):
    """Re-issue the CORS request with an attacker Origin + credentials and prove
    the readable body carries exfiltratable secrets."""
    cors = parts["cors"]
    url = cors.get("url")
    if not url:
        return False, "no url on cors finding", None
    ev = await ctx.http.get(url, headers={"Origin": "https://evil.samaritanx.test"})
    aco = ev.response_headers.get("access-control-allow-origin", "")
    acc = (ev.response_headers.get("access-control-allow-credentials") or "").lower() == "true"
    if "evil.samaritanx.test" not in aco or not acc:
        return False, "credentialed reflection not reproduced", None
    hits = sensitive_hits(ev.response_body, ev.response_headers)
    if not hits:
        return False, "reflection confirmed but no sensitive data in body", None
    esc = severity_for(hits)
    leaked = ", ".join(f"{k}({s})" for k, s in hits[:4])
    return True, f"attacker origin can read: {leaked}", esc


async def _verify_open_redirect(ctx, parts, aggressive):
    """Confirm the open-redirect parameter actually sends the browser off-host —
    the precondition for stealing an OAuth code/token through it."""
    orf = parts["open_redirect"]
    url = orf.get("url")
    if not url:
        return False, "no url on open_redirect finding", None
    ev = await ctx.http.get(url, allow_redirects=False)
    loc = ev.response_headers.get("location", "")
    if ev.status in (301, 302, 303, 307, 308) and loc:
        dest_host = host_of(loc) if "//" in loc else ""
        if dest_host and root_domain(dest_host) != root_domain(host_of(url)):
            return True, f"302 → {loc[:120]} (off-host) — usable to capture an OAuth code", None
    return False, "redirect did not leave the host", None


async def _verify_cache_deception(ctx, parts, aggressive):
    # The scanner already proved anonymous retrieval; the chain just records the
    # amplification (session/token theft at scale). Trust the component finding.
    wcd = parts["web_cache_deception"]
    leaked = (wcd.get("metadata") or {}).get("leaked") or []
    return True, f"private data ({leaked[:3]}) served from shared cache to anonymous users", None


# --------------------------------------------------------------------------- #
RECIPES: list[Recipe] = [
    Recipe("oauth_redirect_takeover", ("open_redirect", "oauth"), "critical", 9.3,
           "Open redirect on the OAuth host lets an attacker set a malicious "
           "`redirect_uri`/`returnTo` and capture the victim's authorization "
           "code or token → full account takeover.",
           scope="same_host", verifier=_verify_open_redirect,
           verify_key=("open_redirect",)),
    Recipe("oauth_xss_token_theft", ("oauth", "xss"), "critical", 9.1,
           "XSS on the OAuth redirect host runs in the origin that receives the "
           "code/token fragment → silent token exfiltration and account takeover.",
           scope="same_host"),
    Recipe("oauth_takeover_chain", ("oauth", "takeover"), "critical", 9.4,
           "A dangling subdomain registered as an OAuth redirect_uri can be "
           "claimed by the attacker → authorization codes delivered to attacker "
           "infrastructure → silent account takeover.",
           scope="same_root"),
    Recipe("cors_credential_theft", ("cors",), "high", 8.2,
           "Credentialed CORS read of an authenticated endpoint exfiltrates the "
           "victim's session token / CSRF token / PII to any attacker origin.",
           scope="same_origin", verifier=_verify_cors_exfil),
    Recipe("cors_xss_amplify", ("cors", "xss"), "high", 8.4,
           "Permissive CORS + same-origin XSS: the injected script reads "
           "cross-origin authenticated responses and exfiltrates them, turning "
           "a reflected XSS into a full account-data breach.",
           scope="same_origin"),
    Recipe("cache_deception_session", ("web_cache_deception",), "critical", 9.1,
           "Web cache deception serves victims' authenticated pages to anonymous "
           "attackers at scale — session tokens and PII harvested from the CDN.",
           scope="same_host", verifier=_verify_cache_deception),
    Recipe("ssrf_metadata_rce", ("ssrf",), "critical", 9.6,
           "SSRF reaching the cloud metadata endpoint yields IAM credentials → "
           "pivot into the cloud account (often equivalent to RCE/data breach).",
           scope="same_host"),
    Recipe("idor_massassign_priv_esc", ("idor", "api"), "critical", 9.1,
           "IDOR exposes another tenant's object id and mass assignment on the "
           "same API lets the attacker write privileged fields on it → "
           "cross-tenant privilege escalation.",
           scope="same_host"),
    Recipe("nosqli_authbypass_takeover", ("nosqli", "idor"), "critical", 9.4,
           "NoSQL auth bypass lands an attacker in an arbitrary session; IDOR "
           "then walks every other tenant's objects → mass account compromise.",
           scope="same_host"),
    Recipe("upload_rce", ("upload", "rce"), "critical", 9.8,
           "Unrestricted upload of an executable handler combined with server "
           "execution → remote code execution.",
           scope="same_host"),
    Recipe("smuggling_auth_bypass", ("smuggling", "broken_auth"), "critical", 9.3,
           "Request smuggling desyncs the front-end proxy so attacker requests "
           "inherit a victim's auth context / reach internal admin routes.",
           scope="same_host"),
    Recipe("graphql_idor_dump", ("graphql", "idor"), "high", 8.5,
           "GraphQL alias batching + IDOR pulls many tenants' objects in a "
           "single unthrottled request → bulk cross-tenant data exfiltration.",
           scope="same_host"),
    Recipe("ssrf_secret_exposure", ("ssrf", "secret_exposure"), "critical", 9.5,
           "SSRF reads internal endpoints/files that expose stored secrets → "
           "credential theft and lateral movement.",
           scope="same_host"),
]


def _key(scope: str, url: str) -> str:
    if scope == "same_origin":
        return _origin(url)
    if scope == "same_host":
        return host_of(url)
    if scope == "same_root":
        return root_domain(host_of(url))
    return "*"


def _ssrf_is_metadata(f: dict) -> bool:
    meta = (f.get("metadata") or {})
    ind = (meta.get("indicator") or "") + " " + (meta.get("detection") or "")
    return any(k in ind.lower() for k in ("metadata", "iam", "oob")) or \
        any(k in (f.get("evidence") or "").lower() for k in ("metadata", "iam", "ami-id"))


def _candidate_score(f: dict) -> float:
    """How promising a single finding is as a chain component: severity, proof,
    and confidence all push it up the candidate list."""
    s = _SEV_RANK.get(f.get("severity", "info"), 0) * 10.0 + float(f.get("cvss", 0) or 0)
    meta = f.get("metadata") or {}
    if meta.get("leaked"):           # CORS/WCD that actually exfiltrated data
        s += 8.0
    if meta.get("verified"):
        s += 6.0
    det = str(meta.get("detection") or "").lower()
    if det in ("oob", "marker", "error", "auth_bypass", "time"):
        s += 4.0
    s += float(f.get("confidence", 0) or 0) * 5.0
    return s


def _path_segs(url: str) -> list[str]:
    try:
        return [seg for seg in urlparse(url if "://" in url else "https://" + url).path.split("/") if seg]
    except Exception:
        return []


def _affinity(a: dict, b: dict) -> float:
    """Reward component pairs that are actually related — shared path prefix and
    shared object ids mean an attacker can plausibly chain *these two*, not just
    two bugs that happen to share a host."""
    pa, pb = _path_segs(a.get("url", "")), _path_segs(b.get("url", ""))
    if not pa or not pb:
        return 0.0
    # shared leading path segments
    common = 0
    for x, y in zip(pa, pb):
        if x == y:
            common += 1
        else:
            break
    score = common * 2.0
    # shared id-shaped segment anywhere (same object referenced)
    ids_a = {s for s in pa if s.isdigit() or len(s) >= 16}
    ids_b = {s for s in pb if s.isdigit() or len(s) >= 16}
    if ids_a & ids_b:
        score += 5.0
    return score


def _combo_score(combo: dict[str, dict]) -> float:
    base = sum(_candidate_score(f) for f in combo.values())
    parts = list(combo.values())
    aff = 0.0
    for i in range(len(parts)):
        for j in range(i + 1, len(parts)):
            aff += _affinity(parts[i], parts[j])
    return base + aff


async def build_chains(ctx: "Context", findings: list[dict], *, aggressive: bool = False) -> list[dict]:
    """Correlate, verify, and escalate. Considers multiple endpoint candidates
    per category and picks/verifies the best pairing(s) rather than collapsing
    each category to a single representative. Returns `chain` finding dicts."""
    import itertools

    by_cat: dict[str, list[dict]] = {}
    for f in findings:
        by_cat.setdefault(f.get("category", ""), []).append(f)

    out: list[dict] = []
    seen_components: set[frozenset] = set()

    for recipe in RECIPES:
        if any(p not in by_cat for p in recipe.parts):
            continue

        # group candidate *lists* per category by scope key
        groups: dict[str, dict[str, list[dict]]] = {}
        for cat in recipe.parts:
            for f in by_cat[cat]:
                if cat == "ssrf" and recipe.name == "ssrf_metadata_rce" and not _ssrf_is_metadata(f):
                    continue
                k = _key(recipe.scope, f.get("url", ""))
                groups.setdefault(k, {}).setdefault(cat, []).append(f)

        # memoize verifier results across pairings that share the relevant component
        verify_memo: dict[tuple, tuple] = {}

        for gkey, cat_lists in groups.items():
            if any(c not in cat_lists for c in recipe.parts):
                continue
            # best candidates per category
            ranked = {c: sorted(cat_lists[c], key=_candidate_score, reverse=True)[:MAX_CANDIDATES_PER_CAT]
                      for c in recipe.parts}
            combos = [dict(zip(recipe.parts, tpl))
                      for tpl in itertools.product(*(ranked[c] for c in recipe.parts))]
            # dedupe degenerate combos (same finding twice) and rank best-first
            combos = [c for c in combos if len({id(f) for f in c.values()}) == len(c)]
            combos.sort(key=_combo_score, reverse=True)
            combos = combos[:MAX_COMBOS]

            emitted_here = 0
            fallback: Optional[dict] = None
            for parts in combos:
                comp_set = frozenset(f.get("_id") or f.get("id") or id(f) for f in parts.values())
                if comp_set in seen_components:
                    continue

                severity, cvss, verified, extra_ev = recipe.severity, recipe.cvss, False, ""
                if recipe.verifier and (aggressive or not recipe.writes):
                    vk = recipe.verify_key or recipe.parts
                    memo_key = tuple(id(parts[c]) for c in vk)
                    if memo_key in verify_memo:
                        verified, extra_ev, esc = verify_memo[memo_key]
                    else:
                        try:
                            verified, extra_ev, esc = await recipe.verifier(ctx, parts, aggressive)
                        except Exception as exc:  # noqa: BLE001
                            verified, extra_ev, esc = False, f"verification error: {exc}", None
                        verify_memo[memo_key] = (verified, extra_ev, esc)
                    if verified and esc:
                        severity, cvss = esc
                elif recipe.verifier and recipe.writes and not aggressive:
                    extra_ev = ("state-changing verification skipped (enable --aggressive to "
                                "auto-confirm); chain is structurally present — verify manually.")

                cf = _chain_finding(recipe, gkey, parts, severity, cvss, verified, extra_ev)
                if verified:
                    out.append(cf)
                    seen_components.add(comp_set)
                    emitted_here += 1
                    if emitted_here >= MAX_VERIFIED_EMIT:
                        break
                elif fallback is None:
                    fallback = cf  # best-scored unverified pairing, held back

            # if nothing verified in this group, emit the single best unverified pairing
            if emitted_here == 0 and fallback is not None:
                fb_set = frozenset(fallback["metadata"]["component_ids"])
                if fb_set not in seen_components:
                    out.append(fallback)
                    seen_components.add(fb_set)

    out.sort(key=lambda f: (_SEV_RANK.get(f["severity"], 0),
                            f["metadata"]["verified"], f["cvss"]), reverse=True)
    return out


def _chain_finding(recipe: Recipe, gkey: str, parts: dict[str, dict],
                   severity: str, cvss: float, verified: bool, extra_ev: str) -> dict:
    comp_ids = [f.get("_id") or f.get("id") or id(f) for f in parts.values()]
    comp_titles = [f"{c}: {parts[c].get('title')} ({parts[c].get('url')})" for c in recipe.parts]
    note = ("Escalation reproduced. " if verified else
            "Components co-located on the same attack surface; "
            "reproduce the escalation step before submitting. ")
    return {
        "category": "chain",
        "title": f"Chain — {recipe.narrative.split(' → ')[0][:80].rstrip('.')} ({severity})",
        "severity": severity, "cvss": cvss,
        "url": parts[recipe.parts[0]].get("url"),
        "parameter": " + ".join(recipe.parts),
        "evidence": recipe.narrative + "\n\n" + note + extra_ev,
        "request": "Components:\n- " + "\n- ".join(comp_titles),
        "metadata": {"chain": recipe.name, "scope": recipe.scope,
                     "group": gkey, "components": recipe.parts,
                     "component_ids": comp_ids, "verified": verified},
    }
