"""Shared scope, cancellation, rate and operation budgets at transport boundaries.

Trusted external tools may opt into an HTTP/TLS proxy adapter. Unsupported
executables remain blocked; native HTTP fallbacks remain available.
"""
from __future__ import annotations

import asyncio
import copy
import time
import os
import shutil
from pathlib import Path
from collections import Counter
from contextvars import ContextVar
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from .scan_execution import request_budget, RequestBudgetExceeded


class TransportBlocked(RequestBudgetExceeded):
    def __init__(self, message):
        budget = request_budget.get()
        if budget is not None:
            budget.exhausted = True
        super().__init__(message)


current_transport = ContextVar("transport_controller", default=None)
operation_purpose = ContextVar("operation_purpose", default="active")
current_phase = ContextVar("transport_phase", default="active")

# Provider hosts reachable with bypass_scope=True (secret validators, OOB
# collaborator, notifications, H1 drafts, LLM triage, OSINT sources). The
# target-scope policy must NEVER apply to these; this allowlist is the
# boundary instead. Operator-configured webhook hosts are appended at runtime.
DEFAULT_PROVIDER_HOSTS = (
    "*.googleapis.com", "*.google.com", "*.gstatic.com",
    "*.slack.com", "hooks.slack.com",
    "*.github.com", "github.com", "gitlab.com",
    "api.mailgun.net", "api.sendgrid.com", "registry.npmjs.org",
    "api.digitalocean.com", "api.stripe.com", "api.twilio.com",
    "api.heroku.com", "api.anthropic.com", "api.openai.com",
    "api.deepseek.com", "api.hackerone.com", "hackerone.com",
    "oast.fun", "*.interactsh.com", "interactsh.com",
    "api.telegram.org", "telegram.org",
    "discord.com", "discordapp.com", "ptb.discord.com",
    "bugcrowd.com", "*.bugcrowd.com", "intigriti.com", "app.intigriti.com",
    "crt.sh", "api.hackertarget.com", "api.certspotter.com",
    "jldc.me", "rapiddns.io", "web.archive.org", "urlscan.io",
    "otx.alienvault.com", "api.shodan.io", "virustotal.com",
    "www.virustotal.com", "api.securitytrails.com",
)


def external_tool_path(name, config):
    directory = config.get("external_tools", {}).get("binary_dir")
    if directory:
        from .tool_installation import active_binary
        selected = active_binary(Path(directory), name)
        if selected:
            return str(selected)
        path = Path(directory) / (name + (".exe" if os.name == "nt" else ""))
        if path.is_file():
            return str(path.resolve())
    return shutil.which(name)


class TransportController:
    def __init__(self, config, scope=None, target=""):
        self.config = config
        self.scope, self.target = scope, target
        self.active_scope = copy.copy(scope)
        if self.active_scope and target and getattr(scope, "default_allow", False):
            self.active_scope.default_allow = False
        cfg = config.get("transport", {})
        self.external_config = config.get("external_tools", {})
        self.aggressive = bool(config.get("safety", {}).get("aggressive"))
        self.strict_mutations = bool(cfg.get("strict_mutations", False))
        self.external_processes = set()
        self.limit = int(cfg.get("operation_budget", 100000))
        self.rate = float(config.get("stealth", {}).get("rate_limit_rps", 6))
        self.per_host_rate = float(config.get("stealth", {}).get("per_host_rps", 2))
        self.used = 0
        self.ledger = None
        self.purpose_counts = Counter()
        self.reserves = {name: max(0, int(cfg.get(name + "_reserve", 0)))
                         for name in ("baseline", "verification")}
        if sum(self.reserves.values()) > self.limit:
            raise ValueError("reserved operations exceed the run budget")
        self.counts = Counter()
        self.blocked = Counter()
        self.cancelled = False
        self._next = 0.0
        self._hosts = {}
        self._lock = asyncio.Lock()
        self.connections = set()

    def bind_ledger(self, path, run_id, *, resume=False):
        from .operation_ledger import OperationLedger
        self.ledger = OperationLedger(path, run_id, self.limit, self.reserves, resume=resume)
        self.limit, self.reserves = self.ledger.limit, self.ledger.reserves
        self.purpose_counts = Counter(self.ledger.counts())
        self.used = sum(self.purpose_counts.values())

    def cancel(self):
        self.cancelled = True
        for writer in self.connections:
            writer.close()
        self.connections.clear()
        for process in list(self.external_processes):
            process.kill()

    async def check_scope(self, url, kind="http"):
        if self.cancelled:
            raise TransportBlocked("run cancelled")
        if self.config.get("recon", {}).get("local_only", False):
            expected, actual = urlparse(self.target), urlparse(url)
            if (actual.scheme, actual.hostname, actual.port) != (expected.scheme, expected.hostname, expected.port):
                self.blocked["scope"] += 1
                raise TransportBlocked("local-only assessment forbids off-origin traffic")
        if kind == "external_provider":
            if not self._provider_allowed(url):
                self.blocked["provider_denied"] += 1
                raise TransportBlocked("provider host not in the external-provider allowlist")
            return
        policy = self.scope if kind in {"http", "external_passive"} and current_phase.get() in {"recon", "discover"} else self.active_scope
        if policy:
            ok, reason = await asyncio.to_thread(policy.allows, url)
            if not ok:
                self.blocked["scope"] += 1
                raise TransportBlocked("scope denied")

    def _provider_allowed(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        allowed = list(DEFAULT_PROVIDER_HOSTS) + list(self._provider_extras())
        for pattern in allowed:
            pattern = pattern.lower().lstrip("*.")
            if host == pattern or host.endswith("." + pattern) or \
                    (pattern.startswith("*.") and host.endswith(pattern[1:])):
                return True
        return False

    def _provider_extras(self) -> list[str]:
        """Operator-configured webhook hosts (monitor/notify) are always
        allowed for provider traffic."""
        extras: list[str] = []
        cfg_sources = [
            self.config.get("monitor", {}).get("webhook"),
            self.config.get("notify", {}).get("slack_webhook"),
            self.config.get("notify", {}).get("discord_webhook"),
        ]
        for v in cfg_sources:
            if isinstance(v, str) and v and not v.startswith("{"):
                h = urlparse(v if "://" in v else "http://" + v).hostname
                if h:
                    extras.append(h)
        return extras

    async def admit(self, url, kind="http", *, mutating: bool = False,
                    sanctioned: bool = False):
        await self.check_scope(url, kind)
        # unified mutation policy (plan 11.4): when strict enforcement is on,
        # unclassified state-changing operations require aggressive mode;
        # explicitly sanctioned flows (auth logins) remain allowed
        if mutating and not sanctioned and not self.aggressive and self.strict_mutations:
            self.blocked["mutation"] += 1
            raise TransportBlocked("state-changing operation blocked (safety.aggressive off)")
        async with self._lock:
            from .operation_ledger import available
            purpose = operation_purpose.get()
            budget = request_budget.get()
            if budget is not None and budget.used >= budget.limit:
                budget.take()
            admitted = (self.ledger.take(purpose) if self.ledger else
                        self.used + 1 if available(self.purpose_counts, self.limit, self.reserves, purpose) else None)
            if admitted is None:
                self.blocked["budget"] += 1
                raise TransportBlocked("run operation budget exhausted or reserved")
            if budget is not None:
                budget.take()
            self.used = admitted
            self.purpose_counts[purpose] += 1
            self.counts[kind] += 1
            host = urlparse(url).netloc
            now = time.monotonic()
            when = max(now, self._next, self._hosts.get(host, 0))
            self._next = when + 1 / max(self.rate, 0.01)
            self._hosts[host] = when + 1 / max(self.per_host_rate, 0.01)
        await asyncio.sleep(max(0, when - time.monotonic()))
        if self.cancelled:
            raise TransportBlocked("run cancelled")

    def snapshot(self):
        if self.ledger:
            self.purpose_counts = Counter(self.ledger.counts())
            self.used = sum(self.purpose_counts.values())
        return {"operations": self.used, "limit": self.limit,
                "by_transport": dict(self.counts), "by_purpose": dict(self.purpose_counts),
                "reserved": dict(self.reserves), "blocked": dict(self.blocked)}


async def guard_browser(context):
    controller = current_transport.get()
    if controller is None:
        return
    if not hasattr(context, "route_web_socket"):
        controller.blocked["unsupported_browser_control"] += 1
        raise TransportBlocked("browser requires WebSocket routing support")

    async def route_handler(route):
        try:
            method = getattr(route.request, "method", "GET").upper()
            await controller.admit(route.request.url, "browser",
                                   mutating=method not in {"GET", "HEAD", "OPTIONS"})
            await route.continue_()
        except TransportBlocked:
            await route.abort()
        except RequestBudgetExceeded:
            await route.abort()

    await context.route("**/*", route_handler)
    # WebSocket frames cannot pass the HTTP route handler's budget checks.
    if hasattr(context, "route_web_socket"):
        async def block_socket(ws):
            controller.blocked["browser_websocket"] += 1
            await ws.close()
        await context.route_web_socket("**/*", block_socket)


class BudgetedWriter:
    def __init__(self, writer, controller, url):
        self.writer, self.controller, self.url = writer, controller, url
        self.pending = []

    def write(self, data):
        self.pending.append(data)

    async def drain(self):
        if self.pending:
            await self.controller.admit(self.url, "raw_write")
            for data in self.pending:
                self.writer.write(data)
            self.pending.clear()
        await self.writer.drain()

    def close(self):
        self.pending.clear()
        self.writer.close()
        self.controller.connections.discard(self.writer)

    async def wait_closed(self):
        try:
            await self.writer.wait_closed()
        finally:
            self.controller.connections.discard(self.writer)

    def __getattr__(self, name):
        return getattr(self.writer, name)


async def open_connection(host, port, **kwargs):
    controller = current_transport.get()
    url = f"{'https' if kwargs.get('ssl') else 'http'}://{host}:{port}/"
    if controller:
        await controller.admit(url, "raw_connection")
    reader, writer = await asyncio.open_connection(host, port, **kwargs)
    if controller:
        controller.connections.add(writer)
    return reader, BudgetedWriter(writer, controller, url) if controller else writer


async def create_subprocess_exec(*args, **kwargs):
    controller = current_transport.get()
    if controller:
        if controller.external_config.get("enabled", False):
            from .external_tools import launch
            resolved = external_tool_path(str(args[0]), {"external_tools": controller.external_config})
            if resolved:
                args = (resolved, *args[1:])
            return await launch(controller, args, kwargs)
        controller.blocked["unmanaged_external_tool"] += 1
        raise TransportBlocked("external adapters disabled by configuration")
    return await asyncio.create_subprocess_exec(*args, **kwargs)


class BudgetedWebSocket:
    def __init__(self, socket, controller, url):
        self.socket, self.controller, self.url = socket, controller, url

    async def send(self, message):
        await self.controller.admit(self.url, "websocket_send")
        return await self.socket.send(message)

    def __getattr__(self, name):
        return getattr(self.socket, name)


@asynccontextmanager
async def websocket_connect(url, **kwargs):
    import websockets
    controller = current_transport.get()
    connector = websockets.connect
    if controller:
        if not hasattr(connector, "process_redirect"):
            raise TransportBlocked("installed WebSocket library cannot disable unmanaged redirects")

        class NoRedirectConnect(connector):
            def process_redirect(self, exc):
                return exc

        connector = NoRedirectConnect
        await controller.admit(url, "websocket_connection")
        kwargs["ping_interval"] = None
    async with connector(url, **kwargs) as socket:
        yield BudgetedWebSocket(socket, controller, url) if controller else socket
