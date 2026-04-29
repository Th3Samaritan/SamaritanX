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

class OOBClient:
    """Indirection over interactsh / local fallback.

    Usage:
        oob = await OOBClient.create(cfg)
        token = oob.token()
        url   = oob.url_for(token)
        # ... fire payload ...
        events = await oob.poll(token)        # filtered to that token
    """

    def __init__(self, backend) -> None:
        self.backend = backend

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

    async def poll(self, token: str | None = None) -> list[dict]:
        events = await self.backend.poll()
        if token:
            return [e for e in events if token.lower() in
                    (e.get("full-id") or e.get("unique-id") or e.get("query-name") or "").lower()]
        return events

    async def close(self) -> None:
        await self.backend.close()


def _rand(n: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))
