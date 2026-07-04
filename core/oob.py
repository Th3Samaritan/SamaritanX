"""Out-of-band (OOB) callback client.

Resolves blind detection problems for SSRF / RCE / XXE / DNSlog by giving
each test a unique callback host. Two backends:

    1. interactsh (default) — public oast.fun infrastructure used by the
       projectdiscovery toolchain. Implements the registration / poll
       protocol so any payload pointing at *.oast.fun lands here.

    2. local — fallback that records DNS / HTTP hits to a local subdomain
       under the operator's control. Activated when interactsh isn't
       reachable; payloads are still emitted but verification is manual.

The client gives out short-lived correlation IDs ("tokens"); a scanner
fires a payload referencing `{token}.oob.example` and later asks the
client whether that token saw any interactions.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import string
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# --------- interactsh helpers --------------------------------------------------

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


@dataclass
class _InteractshClient:
    server: str = "oast.fun"
    correlation_id: str = field(default_factory=lambda: _rand(20))
    secret: str = field(default_factory=lambda: _rand(32))
    private_key: Any = None
    public_pem: str = ""
    domain: str = ""
    registered: bool = False
    interactions: list[dict] = field(default_factory=list)
    _http: httpx.AsyncClient = None  # type: ignore

    async def setup(self) -> bool:
        try:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_pem = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
            self._http = httpx.AsyncClient(timeout=10.0, verify=True)
            payload = {
                "public-key": _b64(self.public_pem.encode()),
                "secret-key": self.secret,
                "correlation-id": self.correlation_id,
            }
            r = await self._http.post(
                f"https://{self.server}/register",
                json=payload, headers={"Content-Type": "application/json"},
            )
            if r.status_code != 200:
                return False
            self.domain = f"{self.correlation_id}.{self.server}"
            self.registered = True
            return True
        except Exception:
            return False

    def url_for(self, token: str) -> str:
        return f"http://{token}.{self.domain}/"

    def host_for(self, token: str) -> str:
        return f"{token}.{self.domain}"

    async def poll(self) -> list[dict]:
        if not self.registered:
            return []
        try:
            r = await self._http.get(
                f"https://{self.server}/poll",
                params={"id": self.correlation_id, "secret": self.secret},
            )
            if r.status_code != 200:
                return []
            data = r.json()
        except Exception:
            return []
        new = []
        for enc in data.get("data") or []:
            try:
                blob = self._decrypt(enc, data.get("aes_key"))
                event = json.loads(blob)
                self.interactions.append(event)
                new.append(event)
            except Exception:
                continue
        return new

    def _decrypt(self, enc_b64: str, key_b64: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = self.private_key.decrypt(
            base64.b64decode(key_b64),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        raw = base64.b64decode(enc_b64)
        iv, ct = raw[:aes_iv_len(key)], raw[aes_iv_len(key):]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        return cipher.decryptor().update(ct)

    async def close(self) -> None:
        if self._http:
            await self._http.aclose()


def aes_iv_len(key: bytes) -> int:
    # interactsh uses AES-CFB with the cipher block size (16 bytes for AES)
    return 16


# --------- local fallback ------------------------------------------------------

@dataclass
class _LocalCallbackClient:
    server: str = "oob.local.invalid"
    correlation_id: str = field(default_factory=lambda: _rand(8))

    async def setup(self) -> bool:
        return True

    @property
    def domain(self) -> str:
        return f"{self.correlation_id}.{self.server}"

    @property
    def registered(self) -> bool:
        return True

    def url_for(self, token: str) -> str:
        return f"http://{token}.{self.domain}/"

    def host_for(self, token: str) -> str:
        return f"{token}.{self.domain}"

    async def poll(self) -> list[dict]:
        return []

    async def close(self) -> None:
        return


# --------- public façade -------------------------------------------------------

def _event_id(event: dict) -> str:
    """A stable id string for an interaction, used for token matching + dedupe."""
    return " ".join(str(event.get(k) or "") for k in
                    ("full-id", "unique-id", "query-name", "remote-address",
                     "timestamp", "raw-request")).lower()


def build_oob_finding(template: dict, events: list[dict]) -> dict:
    """Turn a registered token's template + its interactions into a verified
    finding. The callback IS the proof — a blind payload made the target reach
    our controlled host, which cannot happen by accident."""
    from .poc import proof_record
    kinds = sorted({(e.get("protocol") or e.get("proto") or "dns").upper() for e in events})
    remotes = sorted({e.get("remote-address", "") for e in events if e.get("remote-address")})
    excerpt = ""
    for e in events:
        if e.get("raw-request"):
            excerpt = str(e["raw-request"])[:1000]
            break
    poc = proof_record(
        verified=True, method=template.get("_method", "GET"),
        url=template.get("url", ""),
        request=template.get("_request") or template.get("request")
        or f"payload referencing {template.get('_oob_ref','the OOB host')}",
        excerpt=excerpt or f"{len(events)} interaction(s): protocols={kinds} from {remotes}",
        rationale=(f"The blind payload caused the target to contact our out-of-band host via "
                   f"{', '.join(kinds) or 'DNS/HTTP'} ({len(events)} interaction(s)). An "
                   "out-of-band callback to an attacker-controlled host is unforgeable proof "
                   "the injection executed."),
        samples=[{"protocol": e.get("protocol"), "remote_address": e.get("remote-address"),
                  "timestamp": e.get("timestamp")} for e in events[:5]],
    )
    f = {k: v for k, v in template.items() if not k.startswith("_")}
    f.setdefault("severity", "high")
    f.setdefault("cvss", 8.5)
    f["confidence"] = 0.97
    meta = f.setdefault("metadata", {})
    meta["detection"] = template.get("_detection", "oob")
    meta["poc"] = poc
    meta["oob_interactions"] = len(events)
    return f


class OOBClient:
    """Indirection over interactsh / local fallback with a background poller.

    The projectdiscovery poll protocol returns *new* events since the last poll
    and does not repeat them, so a scanner that polls once right after firing
    almost always misses the callback (they arrive seconds-to-minutes later) and
    concurrent scanners consume each other's events. This façade fixes both:

      * a single background loop drains the backend and **accumulates every
        event** into ``self._events`` (deduped),
      * scanners ``register(token, template)`` and later ``check(token, wait=…)``
        which searches the accumulator without consuming, optionally waiting,
      * a finalize ``pending_findings()`` sweep emits findings for any registered
        token whose callback arrived late — after the scanner had moved on.

    Usage:
        oob = await OOBClient.create(cfg); await oob.start_polling()
        token = oob.token(); url = oob.url_for(token)
        oob.register(token, {"category": "ssrf", "url": url, ...})
        # ... fire payload ...
        hits = await oob.check(token)              # instant, non-consuming
        # ... at finalize ...
        for f in oob.pending_findings(): report(f) # catches late callbacks
    """

    def __init__(self, backend) -> None:
        self.backend = backend
        self._events: list[dict] = []
        self._seen: set[str] = set()
        self._registered: dict[str, dict] = {}
        self._emitted: set[str] = set()
        self._poller = None
        self._lock = None  # created lazily on the running loop

    @classmethod
    async def create(cls, cfg: dict) -> "OOBClient":
        oob_cfg = (cfg or {}).get("oob", {}) or {}
        prefer_local = bool(oob_cfg.get("prefer_local", False)) or os.environ.get("SX_OOB_LOCAL")
        server = oob_cfg.get("server") or "oast.fun"

        if not prefer_local:
            backend = _InteractshClient(server=server)
            if await backend.setup():
                return cls(backend)
            await backend.close()

        local = _LocalCallbackClient(server=oob_cfg.get("local_server") or "oob.local.invalid")
        await local.setup()
        return cls(local)

    @property
    def kind(self) -> str:
        return "interactsh" if isinstance(self.backend, _InteractshClient) else "local"

    @property
    def registered(self) -> bool:
        return self.backend.registered

    def token(self, n: int = 8) -> str:
        return _rand(n)

    def url_for(self, token: str) -> str:
        return self.backend.url_for(token)

    def host_for(self, token: str) -> str:
        return self.backend.host_for(token)

    # ---- registration -----------------------------------------------------
    def register(self, token: str, template: dict) -> None:
        """Remember what a token was for, so a late callback can still become a
        finding at finalize even after the scanner has finished."""
        self._registered[token] = dict(template)

    # ---- draining / accumulation -----------------------------------------
    def _lock_obj(self):
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def _drain(self) -> None:
        try:
            new = await self.backend.poll()
        except Exception:
            return
        if not new:
            return
        async with self._lock_obj():
            for e in new:
                eid = _event_id(e)
                if eid in self._seen:
                    continue
                self._seen.add(eid)
                self._events.append(e)

    async def start_polling(self, interval: float = 5.0) -> None:
        if self._poller is not None:
            return
        self._poller = asyncio.create_task(self._poll_loop(interval))

    async def _poll_loop(self, interval: float) -> None:
        try:
            while True:
                await self._drain()
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass

    # ---- querying ---------------------------------------------------------
    def _match(self, token: str) -> list[dict]:
        t = (token or "").lower()
        if not t:
            return []
        return [e for e in self._events if t in _event_id(e)]

    async def check(self, token: str, *, wait: float = 0.0,
                    poll_interval: float = 2.0) -> list[dict]:
        """Return interactions for a token, non-destructively. If ``wait`` > 0,
        poll until a hit appears or the budget expires."""
        loop = asyncio.get_event_loop()
        deadline = loop.time() + max(0.0, wait)
        while True:
            await self._drain()
            hits = self._match(token)
            if hits or loop.time() >= deadline:
                return hits
            await asyncio.sleep(poll_interval)

    # backward-compatible name; now non-consuming (accumulating)
    async def poll(self, token: str | None = None) -> list[dict]:
        await self._drain()
        return self._match(token) if token else list(self._events)

    def pending_findings(self) -> list[dict]:
        """Findings for registered tokens that have interactions and haven't been
        emitted yet. Call at finalize to capture late callbacks."""
        out: list[dict] = []
        for token, template in self._registered.items():
            if token in self._emitted:
                continue
            hits = self._match(token)
            if hits:
                self._emitted.add(token)
                out.append(build_oob_finding(template, hits))
        return out

    async def final_sweep(self, wait: float = 20.0) -> list[dict]:
        """Wait once for stragglers, then return any late-callback findings."""
        loop = asyncio.get_event_loop()
        deadline = loop.time() + max(0.0, wait)
        while loop.time() < deadline:
            await self._drain()
            if any(self._match(t) and t not in self._emitted for t in self._registered):
                break
            await asyncio.sleep(2.0)
        await self._drain()
        return self.pending_findings()

    async def close(self) -> None:
        if self._poller is not None:
            self._poller.cancel()
            try:
                await self._poller
            except Exception:
                pass
            self._poller = None
        await self.backend.close()


def _rand(n: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))
