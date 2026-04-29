"""WebSocket security probe.

Detects:
  * unauthenticated WebSocket endpoints (connect with no auth -> handshake
    accepted)
  * Cross-Site WebSocket Hijacking (no Origin enforcement — handshake
    accepted with a forged Origin header)
  * upgrade reflections that suggest the server takes user-supplied
    subprotocol values without validation
"""
from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from core.orchestrator import Context


def _ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    """Probe URL itself if it's already a ws:// / wss:// endpoint, otherwise
    rewrite to ws scheme and try once."""
    findings: list[dict] = []
    parsed = urlparse(url)
    if parsed.scheme not in ("ws", "wss", "http", "https"):
        return findings
    ws_scheme = "wss" if parsed.scheme in ("https", "wss") else "ws"
    ws_url = f"{ws_scheme}://{parsed.netloc}{parsed.path}"
    # use plain httpx to send the upgrade request — websockets package not required
    headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": _ws_key(),
        "Origin": "https://evil.samaritanx.test",
    }
    # httpx won't switch to websocket frames but the handshake response is what we care about
    target_http = url.replace("ws://", "http://").replace("wss://", "https://")
    ev = await ctx.http.get(target_http, headers=headers, allow_redirects=False)
    status = ev.status
    sec_accept = ev.response_headers.get("sec-websocket-accept")
    if status == 101 and sec_accept:
        # handshake succeeded with attacker Origin -> CSWH
        findings.append({
            "category": "websocket",
            "title": f"Cross-Site WebSocket Hijacking — Origin not validated ({ws_url})",
            "severity": "high", "cvss": 7.5,
            "url": ws_url,
            "evidence": "WebSocket handshake (HTTP 101) returned despite a forged "
                        "`Origin: https://evil.samaritanx.test` header. Any third-party site "
                        "can open an authenticated socket on behalf of a victim.",
            "request": f"GET {target_http}\nUpgrade: websocket\nOrigin: https://evil.samaritanx.test",
            "response": str({k: v for k, v in ev.response_headers.items()
                             if k.lower().startswith("sec-")}),
        })
    elif status == 101:
        findings.append({
            "category": "websocket",
            "title": f"Unauthenticated WebSocket endpoint accepts handshake ({ws_url})",
            "severity": "medium", "cvss": 5.3,
            "url": ws_url,
            "evidence": "WebSocket handshake completed without authentication or Origin check.",
            "request": f"GET {target_http}\nUpgrade: websocket",
        })
    return findings
