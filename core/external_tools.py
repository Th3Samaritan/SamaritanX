"""Cooperative external-tool adapters through an authenticated HTTP/TLS gateway.

Every proxied request is scope-checked and budgeted before forwarding. This is
not an OS network sandbox: trusted tool versions must honor their proxy options.
Only the command shapes emitted by this application are accepted.
"""
from __future__ import annotations

import asyncio
import base64
import datetime
import ipaddress
import os
import secrets
import ssl
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .scan_execution import RequestBudget, request_budget
from .transport import TransportBlocked, current_phase

_OPTIONS = {
    "ffuf": ({"-u", "-w", "-mc", "-fs", "-of", "-o", "-t"}, {"-s"}),
    "nuclei": ({"-u", "-severity", "-o", "-t"}, {"-silent", "-jsonl"}),
    "subfinder": ({"-d", "-s"}, {"-silent"}),
}


def command(tool_args, proxy):
    if not tool_args:
        raise TransportBlocked("missing executable")
    tool = Path(tool_args[0]).stem.lower()
    if tool not in _OPTIONS:
        raise TransportBlocked("no managed adapter for executable")
    valued, switches = _OPTIONS[tool]
    seen, index = set(), 1
    while index < len(tool_args):
        flag = tool_args[index]
        if flag in seen or flag not in valued | switches:
            raise TransportBlocked(f"unsupported or duplicate {tool} option: {flag}")
        seen.add(flag)
        if flag in valued:
            index += 1
            if index >= len(tool_args) or str(tool_args[index]).startswith("-"):
                raise TransportBlocked(f"missing value for {flag}")
            if flag == "-t" and tool == "nuclei" and not Path(tool_args[index]).exists():
                raise TransportBlocked("nuclei templates must be a local path")
        index += 1
    required = {"-u", "-w", "-o"} if tool == "ffuf" else {"-u", "-o"} if tool == "nuclei" else {"-d"}
    if not required <= seen:
        raise TransportBlocked(f"incomplete {tool} command")
    extra = {
        "ffuf": ["-x", proxy],
        "nuclei": ["-proxy", proxy, "-proxy-internal", "-type", "http", "-ni", "-duc"],
        "subfinder": ["-proxy", proxy, "-duc"],
    }[tool]
    return [str(a) for a in tool_args] + extra


class Gateway:
    def __init__(self, controller, tool, directory):
        self.controller, self.tool, self.directory = controller, tool, Path(directory)
        self.budget = request_budget.get() or RequestBudget(int(controller.external_config.get("request_budget", 250)))
        self.phase = current_phase.get()
        self.failure = None
        self.server = None
        self.clients = set()
        self.tasks = set()
        self.contexts = {}
        self.auth = "Basic " + base64.b64encode(f"sx:{secrets.token_hex(24)}".encode()).decode()
        self.upstream = httpx.AsyncClient(verify=controller.external_config.get("verify_tls", True),
                                          trust_env=False, follow_redirects=False, timeout=20)
        self._create_ca()

    def _create_ca(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SamaritanX ephemeral gateway")])
        self.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
                   .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
                   .sign(self.key, hashes.SHA256()))
        self.ca_path = self.directory / "ca.pem"
        self.ca_path.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))

    def tls_context(self, host):
        if host in self.contexts:
            return self.contexts[host]
        if len(self.contexts) >= 256:
            raise TransportBlocked("gateway certificate-host limit reached")
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
                .issuer_name(self.ca.subject).public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(hours=12))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
                .add_extension(x509.SubjectAlternativeName([san]), critical=False).sign(self.key, hashes.SHA256()))
        cert_path = self.directory / f"leaf-{len(self.contexts)}.pem"
        key_path = self.directory / "leaf.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        context.set_alpn_protocols(["http/1.1"])
        self.contexts[host] = context
        return context

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0, limit=65536)
        port = self.server.sockets[0].getsockname()[1]
        credentials = base64.b64decode(self.auth[6:]).decode()
        return f"http://{credentials}@127.0.0.1:{port}"

    async def close(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for writer in list(self.clients):
            writer.close()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)
        await self.upstream.aclose()

    async def _read(self, reader):
        block = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 20)
        lines = block.decode("latin1").split("\r\n")
        method, target, version = lines[0].split(" ")
        if version != "HTTP/1.1" and version != "HTTP/1.0":
            raise ValueError("unsupported HTTP version")
        headers = []
        for line in lines[1:-2]:
            key, value = line.split(":", 1)
            if not key or key.strip() != key or any(c.isspace() for c in key):
                raise ValueError("invalid header")
            headers.append((key.lower(), value.strip()))
        lengths = [v for k, v in headers if k == "content-length"]
        if len(lengths) > 1 or any(k == "transfer-encoding" for k, _ in headers):
            raise ValueError("ambiguous or unsupported request framing")
        size = int(lengths[0]) if lengths else 0
        if not 0 <= size <= 1024 * 1024:
            raise ValueError("request body exceeds gateway limit")
        body = await asyncio.wait_for(reader.readexactly(size), 20) if size else b""
        return method, target, headers, body

    async def handle(self, reader, writer):
        self.clients.add(writer)
        self.tasks.add(asyncio.current_task())
        budget_token = request_budget.set(self.budget)
        phase_token = current_phase.set(self.phase)
        tunnel = None
        try:
            for _ in range(100):
                method, target, headers, body = await self._read(reader)
                values = dict(headers)
                if tunnel is None and not secrets.compare_digest(values.get("proxy-authorization", ""), self.auth):
                    writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    return
                if method == "CONNECT":
                    if tunnel or body:
                        raise ValueError("nested CONNECT")
                    parsed = urlsplit("https://" + target)
                    if not parsed.hostname or parsed.username or parsed.path or parsed.query or parsed.fragment:
                        raise ValueError("invalid CONNECT authority")
                    await self.controller.check_scope(parsed.geturl(), self._kind())
                    tunnel = parsed.netloc
                    context = self.tls_context(parsed.hostname)
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()
                    if hasattr(writer, "start_tls"):
                        await writer.start_tls(context, ssl_handshake_timeout=10)
                    else:
                        transport = await asyncio.get_running_loop().start_tls(
                            writer.transport, writer._protocol, context, server_side=True, ssl_handshake_timeout=10)
                        writer._transport = transport
                    continue
                if tunnel:
                    if not target.startswith("/") or target.startswith("//"):
                        raise ValueError("invalid tunnel request target")
                    url = "https://" + tunnel + target
                else:
                    url = target
                parsed = urlsplit(url)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.fragment:
                    raise ValueError("invalid forward URL")
                host_values = [v for k, v in headers if k == "host"]
                host_uri = urlsplit(parsed.scheme + "://" + host_values[0]) if len(host_values) == 1 else None
                if host_uri is None or (host_uri.hostname, host_uri.port or (443 if parsed.scheme == "https" else 80)) != (parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)):
                    raise ValueError("Host does not match request authority")
                if method not in {"GET", "HEAD", "OPTIONS"} and not self.controller.aggressive:
                    raise TransportBlocked("external mutation requires safety.aggressive")
                await self.controller.admit(url, self._kind())
                filtered = [(k, v) for k, v in headers if k not in {
                    "proxy-authorization", "proxy-connection", "connection", "content-length", "accept-encoding", "expect"}]
                async with self.upstream.stream(method, url, headers=filtered, content=body) as response:
                    chunks, size = [], 0
                    async for chunk in response.aiter_raw():
                        size += len(chunk)
                        if size > 8 * 1024 * 1024:
                            raise ValueError("response body exceeds gateway limit")
                        chunks.append(chunk)
                    response_body = b"".join(chunks)
                    from .http_client import HttpEvidence
                    HttpEvidence(method, url, dict(filtered), body.decode("utf-8", "replace"), response.status_code,
                                 dict(response.headers), response_body.decode("utf-8", "replace"), 0)
                    response_headers = [(k, v) for k, v in response.headers.multi_items() if k.lower() not in {
                        "connection", "transfer-encoding", "content-length", "proxy-authenticate"}]
                    status = f"HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n"
                    wire_headers = "".join(f"{k}: {v}\r\n" for k, v in response_headers)
                    writer.write((status + wire_headers + f"Content-Length: {len(response_body)}\r\nConnection: close\r\n\r\n").encode("latin1"))
                    if method != "HEAD":
                        writer.write(response_body)
                    await writer.drain()
                    return
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.failure = str(exc)
            self.controller.blocked[f"external:{self.tool}"] += 1
            try:
                writer.write(b"HTTP/1.1 502 Gateway blocked request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
            except (ConnectionError, RuntimeError):
                pass
        finally:
            request_budget.reset(budget_token)
            current_phase.reset(phase_token)
            self.clients.discard(writer)
            self.tasks.discard(asyncio.current_task())
            writer.close()

    def _kind(self):
        return "external_passive" if self.tool == "subfinder" else "external_http"


class ManagedProcess:
    def __init__(self, process, gateway, temporary):
        self.process, self.gateway, self.temporary = process, gateway, temporary
        self.cleanup = None

    @property
    def returncode(self):
        return self.process.returncode

    async def _cleanup(self):
        if self.process.returncode is None:
            self.process.kill()
        await self.process.wait()
        await self.gateway.close()
        self.temporary.cleanup()
        self.gateway.controller.external_processes.discard(self)

    async def _finish(self):
        if self.cleanup is None:
            self.cleanup = asyncio.create_task(self._cleanup())
        await asyncio.shield(self.cleanup)

    async def wait(self):
        try:
            result = await self.process.wait()
            if self.gateway.failure or self.gateway.budget.exhausted:
                raise TransportBlocked(self.gateway.failure or "external request budget exhausted")
            return result
        finally:
            await self._finish()

    async def communicate(self):
        try:
            result = await self.process.communicate()
            if self.gateway.failure or self.gateway.budget.exhausted:
                raise TransportBlocked(self.gateway.failure or "external request budget exhausted")
            return result
        finally:
            await self._finish()

    def kill(self):
        if self.process.returncode is None:
            self.process.kill()
        if self.cleanup is None:
            self.cleanup = asyncio.create_task(self._cleanup())


async def launch(controller, args, kwargs):
    tool = Path(args[0]).stem.lower()
    command(args, "http://127.0.0.1:1")
    temporary = tempfile.TemporaryDirectory(prefix="sx-tool-")
    gateway = Gateway(controller, tool, temporary.name)
    try:
        proxy = await gateway.start()
        argv = command(args, proxy)
        env = dict(os.environ, **(kwargs.pop("env", None) or {}))
        env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, http_proxy=proxy, https_proxy=proxy,
                   NO_PROXY="", no_proxy="", SSL_CERT_FILE=str(gateway.ca_path), REQUESTS_CA_BUNDLE=str(gateway.ca_path))
        # Default per-user configs may enable alternate networking or shell inputs.
        config_dir = Path(temporary.name) / "config"
        config_dir.mkdir()
        env["XDG_CONFIG_HOME"] = str(config_dir)
        env["APPDATA"] = str(config_dir)
        process = await asyncio.create_subprocess_exec(*argv, env=env, **kwargs)
        managed = ManagedProcess(process, gateway, temporary)
        controller.external_processes.add(managed)
        return managed
    except BaseException:
        await gateway.close()
        temporary.cleanup()
        raise
