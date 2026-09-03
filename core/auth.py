"""Authentication layer.

Loads a YAML/JSON auth recipe describing how to obtain and refresh a
session, then exposes a SessionStore that the StealthHttpClient uses to
attach cookies / Authorization / custom headers to every outbound request.

Supported recipe shapes:

    # 1) static cookies / headers (no login flow)
    type: static
    cookies:
      session: abc123
      csrf: xyz
    headers:
      Authorization: "Bearer eyJhbGciOi..."
      X-Tenant: acme

    # 2) form login — POST creds, capture cookies
    type: form
    login_url: https://target/login
    method: POST
    fields:
      username: "{ENV:TARGET_USER}"
      password: "{ENV:TARGET_PASS}"
    success_indicator: "Logout"          # text that proves login worked
    refresh_every: 1800                  # seconds; re-login periodically

    # 3) JSON login -> bearer token from response field
    type: bearer_json
    login_url: https://target/api/auth
    json:
      email: "{ENV:TARGET_USER}"
      password: "{ENV:TARGET_PASS}"
    token_path: data.access_token        # dotted path inside JSON response
    header: Authorization
    header_template: "Bearer {token}"
    refresh_every: 3300

Environment variables are expanded via the {ENV:NAME} placeholder so the
secret never sits inside the repo.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import yaml


_ENV_RE = re.compile(r"\{ENV:([A-Z_][A-Z0-9_]*)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _dotted_get(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)] if int(part) < len(cur) else None
        else:
            return None
    return cur


class SessionStore:
    """Mutable bag of cookies + headers attached to every outbound request."""

    def __init__(self) -> None:
        self.cookies: dict[str, str] = {}
        self.headers: dict[str, str] = {}
        self.label: str = "anon"
        # SameSite attribute observed on the session cookies at login
        # ("strict" / "lax" / "none" / None = not observed)
        self.same_site: str | None = None
        self._refreshed_at: float = 0.0
        self.refresh_every: int = 0
        self._refresh_fn = None
        self._lock = asyncio.Lock()

    def is_authed(self) -> bool:
        return bool(self.cookies or self.headers)

    async def maybe_refresh(self) -> None:
        if not self._refresh_fn or not self.refresh_every:
            return
        if time.time() - self._refreshed_at < self.refresh_every:
            return
        async with self._lock:
            if time.time() - self._refreshed_at < self.refresh_every:
                return
            await self._refresh_fn()
            self._refreshed_at = time.time()

    async def preflight(self, http, validate_url: str | None = None) -> bool:
        """Pre-flight check used by high-value scanners (RCE / SSRF / BOLA).

        Forces a refresh if one is overdue and, when *validate_url* is supplied,
        confirms the session is actually valid by hitting that URL and looking
        for a 2xx-ish response. Returns True if the session is usable."""
        if not self._refresh_fn:
            return self.is_authed()
        async with self._lock:
            try:
                await self._refresh_fn()
                self._refreshed_at = time.time()
            except Exception:
                return False
        if validate_url:
            try:
                ev = await http.request("GET", validate_url, bypass_scope=True)
                if ev.status in (0, 401, 403):
                    return False
            except Exception:
                return False
        return self.is_authed()


def save_session(store: SessionStore, path: str | Path) -> bool:
    """Persist a session's cookies + headers so the next run can resume the
    session without re-running the login flow. Returns True when something was
    written."""
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "label": store.label,
            "cookies": dict(store.cookies),
            "headers": dict(store.headers),
            "same_site": getattr(store, "same_site", None),
            "saved_at": int(time.time()),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def load_persisted_session(path: str | Path) -> SessionStore | None:
    """Restore a previously persisted session (see save_session)."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        store = SessionStore()
        store.label = data.get("label") or "persisted"
        store.cookies.update(data.get("cookies") or {})
        store.headers.update(data.get("headers") or {})
        store.same_site = data.get("same_site")
        return store
    except Exception:
        return None


async def load_session(recipe_path: str | Path | None, http) -> SessionStore:
    """Build a SessionStore from a recipe file. `http` is a StealthHttpClient
    used to perform the initial login (without auth)."""
    store = SessionStore()
    if not recipe_path:
        return store
    recipe_path = Path(recipe_path)
    if not recipe_path.exists():
        return store

    raw = recipe_path.read_text(encoding="utf-8")
    if recipe_path.suffix.lower() in (".yaml", ".yml"):
        recipe = yaml.safe_load(raw) or {}
    else:
        recipe = json.loads(raw)
    recipe = _expand_env(recipe)

    kind = (recipe.get("type") or "static").lower()
    store.label = recipe.get("label") or kind
    store.refresh_every = int(recipe.get("refresh_every") or 0)

    if kind == "static":
        store.cookies.update(recipe.get("cookies") or {})
        store.headers.update(recipe.get("headers") or {})

    elif kind == "form":
        async def _refresh():
            url = recipe["login_url"]
            method = (recipe.get("method") or "POST").upper()
            fields = recipe.get("fields") or {}
            # don't follow the login redirect: the Set-Cookie / SameSite
            # attributes live on the login response itself, and following the
            # 302 would discard them
            ev = await http.request(method, url, data=fields, headers={
                "Content-Type": "application/x-www-form-urlencoded",
            }, allow_redirects=False)
            indicator = recipe.get("success_indicator") or ""
            body = ev.response_body or ""
            if indicator and indicator not in body:
                # recipe expects a marker on the post-login page — fetch the
                # redirect target once with cookies from the login response
                loc = ev.response_headers.get("location") or ""
                if loc:
                    from urllib.parse import urljoin
                    ev2 = await http.request("GET", urljoin(url, loc),
                                             allow_redirects=False)
                    body = ev2.response_body or ""
                    if indicator and indicator not in body:
                        raise RuntimeError(
                            f"form login failed — '{indicator}' not in response")
            # capture cookies from httpx's own cookie jar (robust against
            # commas inside Expires=... / cookie values, which naive
            # Set-Cookie splitting corrupts).
            try:
                jar = getattr(http, "_client", None)
                if jar is not None:
                    for name, val in jar.cookies.items():
                        store.cookies[name] = val
            except Exception:
                pass
            # observe the SameSite attribute of the session cookies as issued
            try:
                raw = [v for v in ((ev.extra or {}).get("set_cookie_headers") or [])]
                blob = " ".join(raw).lower()
                if "samesite=strict" in blob:
                    store.same_site = "strict"
                elif "samesite=lax" in blob:
                    store.same_site = "lax"
                elif "samesite=none" in blob:
                    store.same_site = "none"
            except Exception:
                pass
            for h, v in (recipe.get("extra_headers") or {}).items():
                store.headers[h] = v
        store._refresh_fn = _refresh
        await _refresh()
        store._refreshed_at = time.time()

    elif kind == "bearer_json":
        async def _refresh():
            ev = await http.request("POST", recipe["login_url"],
                                    json_body=recipe.get("json") or {},
                                    headers={"Content-Type": "application/json"})
            data = json.loads(ev.response_body or "{}")
            token = _dotted_get(data, recipe["token_path"])
            if not token:
                raise RuntimeError(f"bearer login failed — token_path '{recipe['token_path']}' empty")
            header = recipe.get("header") or "Authorization"
            template = recipe.get("header_template") or "Bearer {token}"
            store.headers[header] = template.format(token=token)
            for h, v in (recipe.get("extra_headers") or {}).items():
                store.headers[h] = v
        store._refresh_fn = _refresh
        await _refresh()
        store._refreshed_at = time.time()

    else:
        raise ValueError(f"unknown auth recipe type: {kind}")

    return store
