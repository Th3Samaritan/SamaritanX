"""Shared helpers: URLs, slugs, file paths, hashing."""
from __future__ import annotations

import hashlib
import ipaddress
import os
import random
import re
import string
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

import tldextract

# Offline public-suffix extractor: use tldextract's bundled snapshot and
# never fetch the suffix list over the network. Keeps the tool fully
# self-contained and silent on offline / proxied hosts.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


SAFE_SLUG_RE = re.compile(r"[^a-zA-Z0-9._\-]")


def slugify(value: str) -> str:
    return SAFE_SLUG_RE.sub("_", value).strip("._-") or "target"


def root_domain(host: str) -> str:
    """Registrable domain of a host (URL / host:port / IP all accepted)."""
    if not host:
        return ""
    if "://" in host:
        host = urlparse(host).netloc
    host = host.strip().lower()
    if host.startswith("["):  # ipv6 literal
        return host
    host = host.split("@")[-1]  # strip userinfo
    if ":" in host:
        host = host.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(host)
        return host  # IPs are their own root
    except ValueError:
        pass
    ext = _EXTRACT(host)
    if not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"


def normalize_url(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    netloc = p.netloc.lower()
    path = p.path or "/"
    return urlunparse((p.scheme.lower(), netloc, path, p.params, p.query, ""))


def host_of(url: str) -> str:
    return urlparse(normalize_url(url)).netloc


def random_token(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def short_hash(value: str, n: int = 10) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:n]


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def merge_query(url: str, params: dict[str, str]) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q.update(params)
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def chunked(items: Iterable, n: int):
    buf = []
    for item in items:
        buf.append(item)
        if len(buf) >= n:
            yield buf
            buf = []
    if buf:
        yield buf


def env_or(default: str, *keys: str) -> str:
    for k in keys:
        v = os.environ.get(k)
        if v:
            return v
    return default
