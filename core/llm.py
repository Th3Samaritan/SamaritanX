"""LLM assist layer — planner and judge, never a detector.

Hard rule: an LLM never *decides a bug exists*. That's how you get hallucinated
findings. It is only used where it is sound:

  * ``triage_impact(finding)`` — reason over a finding that already carries a
    captured proof, and write the impact narrative + CVSS justification a triager
    wants. Input is real evidence; the model explains it, it doesn't invent it.
  * ``plan_attack(recon)`` — read the observed tech stack / headers and rank
    which scanners are worth running first.

Backends (chosen via ``llm.provider`` in config, both callable with plain
httpx — no SDK dependency):

  * ``anthropic`` — Messages API (``llm.api_key`` or ANTHROPIC_API_KEY)
  * ``openai``    — Chat Completions API (``llm.api_key`` or OPENAI_API_KEY)

Without a key the deterministic template fallback runs, so the pipeline works
with zero external dependencies and every call stays reproducible in tests.
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

_DEFAULT_MODEL = "claude-sonnet-5"

# provider presets: name -> (chat-completions base URL, env-var fallback)
# deepseek and openai_compatible speak the OpenAI chat-completions dialect, so
# any OpenAI-compatible endpoint (Groq, OpenRouter, Together, vLLM, Ollama,
# LM Studio…) works through the same path.
_CHAT_PROVIDERS = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "deepseek": ("https://api.deepseek.com/v1", "DEEPSEEK_API_KEY"),
}
_DEFAULT_OPENAI_COMPATIBLE_MODEL = "deepseek-chat"


def _api_key(cfg: dict[str, Any] | None = None) -> str | None:
    llm = (cfg or {}).get("llm") or {}
    k = llm.get("api_key") or ""
    if k.startswith("{ENV:") and k.endswith("}"):
        k = os.environ.get(k[5:-1], "")
    if k:
        return k
    provider = (llm.get("provider") or "anthropic").lower()
    if provider == "anthropic":
        return os.environ.get("ANTHROPIC_API_KEY")
    if provider in _CHAT_PROVIDERS:
        return os.environ.get(_CHAT_PROVIDERS[provider][1])
    return os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")


def available(cfg: dict[str, Any] | None = None) -> bool:
    """True when a provider + key are configured (no SDK required)."""
    return bool(_api_key(cfg))


def _model(cfg: dict[str, Any] | None) -> str:
    llm = (cfg or {}).get("llm") or {}
    m = llm.get("model")
    if m:
        return m
    provider = (llm.get("provider") or "anthropic").lower()
    if provider == "deepseek":
        return _DEFAULT_OPENAI_COMPATIBLE_MODEL
    return _DEFAULT_MODEL


def _provider(cfg: dict[str, Any] | None) -> str:
    return ((cfg or {}).get("llm") or {}).get("provider") or "anthropic"


def _base_url(cfg: dict[str, Any] | None, provider: str) -> str | None:
    """Chat-completions base URL for the configured provider."""
    llm = (cfg or {}).get("llm") or {}
    if provider in _CHAT_PROVIDERS:
        return _CHAT_PROVIDERS[provider][0]
    if provider == "openai_compatible":
        return llm.get("base_url") or None
    return None


async def _complete(prompt: str, cfg: dict[str, Any] | None, *, max_tokens: int = 1024) -> str | None:
    """Best-effort single-shot completion; None if the backend is unavailable."""
    key = _api_key(cfg)
    if not key:
        return None
    provider = _provider(cfg).lower()
    model = _model(cfg)
    try:
        async with httpx.AsyncClient(timeout=60.0, verify=False) as client:
            # OpenAI / DeepSeek / any OpenAI-compatible endpoint
            base = _base_url(cfg, provider)
            if base:
                r = await client.post(
                    f"{base.rstrip('/')}/chat/completions",
                    headers={"Authorization": f"Bearer {key}",
                             "Content-Type": "application/json"},
                    json={"model": model, "max_tokens": max_tokens,
                          "messages": [{"role": "user", "content": prompt}]},
                )
                data = r.json()
                return (data.get("choices") or [{}])[0].get("message", {}).get("content")
            # anthropic (default)
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                         "Content-Type": "application/json"},
                json={"model": model, "max_tokens": max_tokens,
                      "messages": [{"role": "user", "content": prompt}]},
            )
            data = r.json()
            parts = [b.get("text", "") for b in data.get("content", [])
                     if isinstance(b, dict) and b.get("type") == "text"]
            text = "\n".join(parts).strip()
            return text or None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Impact triage (judge over captured evidence)
# --------------------------------------------------------------------------- #
_TRIAGE_PROMPT = """You are a bug-bounty triage assistant. Below is a security \
finding that ALREADY has a captured, verified proof. Do NOT question whether the \
bug is real — it is proven. Write a concise, factual impact assessment for a \
program triager.

Return STRICT JSON with keys: "impact" (2-3 sentences on business impact), \
"cvss_rationale" (one sentence justifying the severity), "recommended_severity" \
(one of: critical, high, medium, low).

Finding:
category: {category}
title: {title}
url: {url}
evidence: {evidence}
proof_rationale: {proof}
"""


async def triage_impact(finding: dict[str, Any], cfg: dict[str, Any] | None = None) -> dict[str, str]:
    """Produce {impact, cvss_rationale, recommended_severity} for a proven finding."""
    proof = ""
    poc = (finding.get("metadata") or {}).get("poc")
    if isinstance(poc, dict):
        proof = poc.get("rationale", "")
    prompt = _TRIAGE_PROMPT.format(
        category=finding.get("category", ""), title=finding.get("title", ""),
        url=finding.get("url", ""), evidence=(finding.get("evidence") or "")[:800],
        proof=proof[:600])
    raw = await _complete(prompt, cfg)
    if raw:
        try:
            data = json.loads(raw[raw.find("{"): raw.rfind("}") + 1])
            return {"impact": str(data.get("impact", "")).strip(),
                    "cvss_rationale": str(data.get("cvss_rationale", "")).strip(),
                    "recommended_severity": str(data.get("recommended_severity",
                                                         finding.get("severity", "medium"))).strip()}
        except Exception:
            pass
    return _fallback_triage(finding)


_IMPACT_TEMPLATES = {
    "sqli": "An attacker can read or modify arbitrary database contents, including other users' "
            "records and credentials, and may achieve full database compromise.",
    "rce": "An attacker can execute arbitrary commands on the server, leading to full host "
           "compromise and lateral movement into internal infrastructure.",
    "ssrf": "An attacker can make the server issue requests to internal services and cloud "
            "metadata endpoints, exposing credentials and internal resources.",
    "xss": "An attacker can execute script in victims' authenticated sessions, enabling session "
           "theft, account actions on the victim's behalf, and credential harvesting.",
    "stored_xss": "A persisted payload executes in every viewer's session, enabling mass session "
                  "theft and account takeover without any victim interaction beyond a normal visit.",
    "idor_deep": "An attacker can read or modify other users' objects, breaching data isolation "
                 "and exposing every affected user's private records.",
    "broken_auth": "Privileged functionality or data is reachable without authentication, exposing "
                   "records that should require a valid session.",
    "smuggling": "An attacker can desynchronise the front-end and back-end request queues to poison "
                 "other users' responses, bypass front-end controls, and hijack sessions.",
    "cors": "A malicious origin can read authenticated responses cross-site, exfiltrating the "
            "victim's private data.",
    "open_redirect": "The endpoint can redirect victims to attacker-controlled hosts, enabling "
                     "phishing and OAuth token theft when chained.",
    "secret_exposure": "A live credential is exposed, granting an attacker whatever access that "
                       "credential holds.",
    "lfi": "An attacker can read arbitrary server files, including configuration, credentials and "
           "source code, often escalating to remote code execution.",
    "upload": "An attacker can upload executable content that the server serves or runs, leading "
              "to stored XSS at minimum and full RCE when a server-side handler exists.",
    "nosqli": "An attacker can bypass authentication and read or modify NoSQL document contents "
              "through operator injection.",
    "idor": "An attacker can access or modify other users' records by changing object identifiers.",
    "account_takeover": "An attacker can take over victim accounts through the password-reset "
                        "flow or token leakage.",
    "web_cache_deception": "An attacker can read cached copies of other users' private pages "
                           "without authentication.",
    "cache_poisoning": "An attacker can poison the shared cache to serve malicious or attacker-"
                       "controlled content to every visitor.",
    "prompt_injection": "An attacker can override the system prompt and make the model take "
                        "attacker-directed actions or leak instructions and data.",
    "ssti": "An attacker can execute arbitrary code inside the template engine, leading to full "
            "server compromise.",
    "crlf": "An attacker can inject headers into the response stream, enabling cookie injection, "
            "XSS on old browsers, and cache poisoning.",
    "xxe": "An attacker can read local files and reach internal services through the XML parser.",
    "jwt_priv_esc": "An attacker can forge or weaken tokens to impersonate users or escalate "
                    "privileges.",
    "version_bypass": "An attacker can reach privileged endpoints through unprotected sibling API "
                      "versions.",
}


def _fallback_triage(finding: dict[str, Any]) -> dict[str, str]:
    cat = (finding.get("category") or "").lower()
    sev = (finding.get("severity") or "medium").lower()
    impact = _IMPACT_TEMPLATES.get(cat, "This issue weakens the application's security posture and "
                                        "should be reviewed and remediated.")
    return {"impact": impact,
            "cvss_rationale": f"Rated {sev} based on the confirmed exploitation captured in the PoC.",
            "recommended_severity": sev}


# --------------------------------------------------------------------------- #
# Attack planning (planner over recon)
# --------------------------------------------------------------------------- #
async def plan_attack(recon: dict[str, Any], cfg: dict[str, Any] | None = None) -> list[str]:
    """Rank scanner categories to run first given observed recon signals.

    ``recon`` may contain: tech (list of tech names), headers (dict),
    has_graphql (bool), has_api (bool), has_upload (bool)."""
    raw = await _complete(_PLAN_PROMPT.format(recon=json.dumps(recon)[:1500]), cfg)
    if raw:
        try:
            data = json.loads(raw[raw.find("["): raw.rfind("]") + 1])
            order = [str(x).lower() for x in data if isinstance(x, str)]
            if order:
                return order
        except Exception:
            pass
    return _fallback_plan(recon)


_PLAN_PROMPT = """Given this recon summary of a web target, return a JSON array of \
scanner category names (from: sqli, xss, ssrf, rce, idor_deep, api, graphql, \
open_redirect, cors, upload, smuggling, jwt_priv_esc, nosqli) ordered by which is \
most likely to find a real bug on THIS target first. Only the JSON array.

Recon: {recon}
"""


def _fallback_plan(recon: dict[str, Any]) -> list[str]:
    tech = " ".join(str(t).lower() for t in (recon.get("tech") or []))
    order: list[str] = []

    def add(*cats):
        for c in cats:
            if c not in order:
                order.append(c)

    if recon.get("has_graphql"):
        add("graphql", "idor_deep", "api")
    if recon.get("has_api"):
        add("api", "idor_deep", "jwt_priv_esc")
    if recon.get("has_upload"):
        add("upload")
    if "wordpress" in tech or "php" in tech:
        add("sqli", "rce", "open_redirect")
    if "node" in tech or "express" in tech:
        add("nosqli", "ssrf", "prototype_pollution")
    if "java" in tech or "spring" in tech:
        add("ssrf", "rce", "xxe")
    # sensible default tail — the high-value classes everyone should run
    add("idor_deep", "sqli", "xss", "ssrf", "open_redirect", "cors", "api")
    return order
