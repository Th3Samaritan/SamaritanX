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
