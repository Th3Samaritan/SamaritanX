r"""Scope enforcement.

Reads a scope file with one rule per line::

    # comment
    *.example.com           # glob — match host
    api.example.com         # exact host
    !beta.example.com       # deny rule (precedes allow rules)
    re:^https://x\.example\.com/admin/  # regex against full URL
    cidr:10.0.0.0/8         # CIDR block (resolved at request time)

Every outbound URL is checked. If the host falls outside the allow-list
(or matches a deny rule) the request is dropped before it leaves the box.
That's the difference between "rate-limited" and "won't-accidentally-get-
you-banned-from-a-bug-bounty-program".
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# Third-party hosts that regularly appear in a target's traffic but are never
# the target — active/intrusive probes against them are out of scope and a good
# way to get a hunter banned. Matched as a suffix of the registrable domain.
# Denylist for *active* testing only; passive recon is unaffected.
_THIRD_PARTY = (
    "google-analytics.com", "googletagmanager.com", "google.com", "gstatic.com",
    "doubleclick.net", "facebook.com", "facebook.net", "segment.io", "segment.com",
    "singular.net", "branch.io", "amplitude.com", "mixpanel.com", "sentry.io",
    "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net", "unpkg.com",
    "cdnjs.com", "bootstrapcdn.com", "fontawesome.com", "gravatar.com",
    "hotjar.com", "intercom.io", "stripe.com", "paypal.com", "youtube.com",
    "ytimg.com", "twitter.com", "twimg.com", "linkedin.com", "recaptcha.net",
    "cloudfront.net", "akamaihd.net", "fastly.net", "newrelic.com",
)


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain without a tldextract dependency.

    Handles common two-label public suffixes (co.uk, com.au, ...) so
    ``www.example.co.uk`` -> ``example.co.uk``. Good enough for scope grouping.
    """
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_label = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if parts[-2] in two_label:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_third_party(host: str) -> bool:
    reg = registrable_domain(host)
    return any(reg == tp or reg.endswith("." + tp) for tp in _THIRD_PARTY)


@dataclass
class ScopePolicy:
    allow_globs: list[str] = field(default_factory=list)
    deny_globs: list[str] = field(default_factory=list)
    allow_regex: list[re.Pattern] = field(default_factory=list)
    deny_regex: list[re.Pattern] = field(default_factory=list)
    allow_cidr: list[ipaddress._BaseNetwork] = field(default_factory=list)
    deny_cidr: list[ipaddress._BaseNetwork] = field(default_factory=list)
    default_allow: bool = False
    _resolve_cache: dict = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str | Path | None, *, default_allow: bool = False) -> "ScopePolicy":
        p = cls(default_allow=default_allow)
        if not path:
            p.default_allow = True
            return p
        f = Path(path)
        if not f.exists():
            raise FileNotFoundError(f"scope file not found: {f}")
        for raw in f.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            deny = line.startswith("!")
            if deny:
                line = line[1:].strip()
            if line.startswith("re:"):
                pat = re.compile(line[3:])
                (p.deny_regex if deny else p.allow_regex).append(pat)
            elif line.startswith("cidr:"):
                net = ipaddress.ip_network(line[5:], strict=False)
                (p.deny_cidr if deny else p.allow_cidr).append(net)
            else:
                (p.deny_globs if deny else p.allow_globs).append(line.lower())
        return p

    def _resolve(self, host: str) -> str | None:
        if host in self._resolve_cache:
            return self._resolve_cache[host]
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = None
        self._resolve_cache[host] = ip
        return ip

    def allows(self, url: str) -> tuple[bool, str]:
        """Return (allowed, reason). reason is human-readable."""
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
        except Exception:
            return False, "unparsable URL"
        host = (parsed.hostname or "").lower()
        if not host:
            return False, "no host"

        # deny rules first
        for g in self.deny_globs:
            if fnmatch.fnmatch(host, g):
                return False, f"deny glob: {g}"
        for r in self.deny_regex:
            if r.search(url):
                return False, f"deny regex: {r.pattern}"
        if self.deny_cidr:
            ip = self._resolve(host)
            if ip:
                addr = ipaddress.ip_address(ip)
                for net in self.deny_cidr:
                    if addr in net:
                        return False, f"deny cidr: {net}"

        # allow rules
        if self.default_allow and not (self.allow_globs or self.allow_regex or self.allow_cidr):
            return True, "default-allow"
        for g in self.allow_globs:
            if fnmatch.fnmatch(host, g):
                return True, f"allow glob: {g}"
        for r in self.allow_regex:
            if r.search(url):
                return True, f"allow regex: {r.pattern}"
        if self.allow_cidr:
            ip = self._resolve(host)
            if ip:
                addr = ipaddress.ip_address(ip)
                for net in self.allow_cidr:
                    if addr in net:
                        return True, f"allow cidr: {net}"
        if self.default_allow:
            return True, "default-allow"
        return False, "not in scope"

    def active_allows(self, url: str, target: str | None = None) -> tuple[bool, str]:
        """Stricter gate for *active / intrusive* probes (smuggling, uploads,
        injection at scale, anything that could DoS or alter state).

        On top of the normal ``allows()`` check it refuses:
          * recognised third-party hosts (analytics/CDN/payment SDKs), and
          * hosts outside the target's own registrable domain when a target is
            known and no explicit scope allow-list was configured.

        Passive recon should keep calling ``allows()``; only dangerous active
        modules should call this. It closes the hole that let the old scanner
        fire smuggling payloads at segment.io / singular.net."""
        ok, reason = self.allows(url)
        if not ok:
            return False, reason
        host = (urlparse(url if "://" in url else f"http://{url}").hostname or "").lower()
        if not host:
            return False, "no host"
        if is_third_party(host):
            return False, f"third-party host ({registrable_domain(host)}) — out of scope for active tests"
        # When we're relying on default-allow (no explicit allow-list) and we
        # know the target, confine active probes to the target's own domain.
        explicit = bool(self.allow_globs or self.allow_regex or self.allow_cidr)
        if target and not explicit:
            th = (urlparse(target if "://" in target else f"http://{target}").hostname or target)
            if registrable_domain(host) != registrable_domain(th):
                return False, (f"host {registrable_domain(host)} is off the target domain "
                               f"{registrable_domain(th)} — refusing active probe")
        return True, "in scope (active)"
