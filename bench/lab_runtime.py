"""Owned, bounded Juice Shop runtime; never attaches to arbitrary targets."""
import json
import os
import subprocess
import time
import uuid
from pathlib import Path
import httpx

IMAGE = "bkimminich/juice-shop:v19.2.1"
LABEL = "samaritanx.lab.run"


def command(*args, timeout=30):
    # Docker CLI output is UTF-8; Windows' default cp1252 reader crashes on
    # non-ASCII bytes and leaves stderr None, masking the real failure.
    proc = subprocess.run(list(args), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          creationflags=0x08000000 if os.name == "nt" else 0)
    if proc.returncode:
        detail = (proc.stderr or proc.stdout or "").strip()[-2000:]
        raise RuntimeError(detail or f"runtime command failed ({proc.returncode})")
    return proc.stdout.strip()


def get_json(origin, path):
    with httpx.Client(timeout=8, follow_redirects=False, trust_env=False) as client:
        with client.stream("GET", origin + path) as response:
            response.raise_for_status()
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > 4 * 1024 * 1024:
                    raise ValueError("lab response exceeds limit")
            return json.loads(data)


class DockerLab:
    def __init__(self, output):
        self.output = Path(output)
        self.owner = uuid.uuid4().hex
        self.name = "sx-juice-" + self.owner[:12]
        self.origin = None
        self.created = False
        self.metadata = {"runtime": "docker", "image": IMAGE, "owner": self.owner, "name": self.name}

    def start(self):
        command("docker", "info", "--format", "{{.ServerVersion}}", timeout=20)
        command("docker", "pull", IMAGE, timeout=300)
        image = json.loads(command("docker", "image", "inspect", IMAGE))[0]
        self.metadata.update(image_id=image["Id"], digests=image.get("RepoDigests", []))
        command("docker", "create", "--name", self.name, "--label", f"{LABEL}={self.owner}",
                "--memory", "1g", "--cpus", "2", "--publish", "127.0.0.1::3000", IMAGE)
        self.created = True
        command("docker", "start", self.name)
        info = json.loads(command("docker", "inspect", self.name))[0]
        ports = info["NetworkSettings"]["Ports"]["3000/tcp"]
        if len(ports) != 1 or ports[0]["HostIp"] != "127.0.0.1":
            raise RuntimeError("lab binding is not loopback-only")
        self.origin = "http://127.0.0.1:" + ports[0]["HostPort"]
        self.metadata["origin"] = self.origin
        self.metadata["started_at"] = info["State"]["StartedAt"]
        self.ready()
        return self.origin

    def ready(self):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                data = get_json(self.origin, "/rest/admin/application-version")
                version = data.get("version")
                if version != "19.2.1":
                    raise ValueError("unexpected Juice Shop version")
                self.metadata["version"] = version
                return
            except (httpx.HTTPError, ValueError):
                time.sleep(1)
        raise RuntimeError("Juice Shop readiness deadline exceeded")

    def healthy(self):
        info = json.loads(command("docker", "inspect", self.name))[0]
        return info["State"]["Running"] and info["State"]["StartedAt"] == self.metadata["started_at"]

    def close(self, keep=False):
        if not self.created:
            return
        info = json.loads(command("docker", "inspect", self.name))[0]
        if info["Config"].get("Labels", {}).get(LABEL) != self.owner:
            raise RuntimeError("refusing cleanup: lab ownership does not match")
        try:
            logs = command("docker", "logs", "--tail", "1000", self.name)
            (self.output / "lab.log").write_text(logs, encoding="utf-8")
        finally:
            if not keep:
                command("docker", "rm", "--force", self.name)


class NodeLab(DockerLab):
    def __init__(self, output, distribution):
        super().__init__(output)
        self.distribution = Path(distribution).resolve()
        self.process = None
        self.log = None
        self.metadata = {"runtime": "node", "distribution": str(self.distribution), "owner": self.owner}

    def start(self):
        import socket
        package = json.loads((self.distribution / "package.json").read_text(encoding="utf-8"))
        if package.get("name") != "juice-shop" or package.get("version") != "19.2.1":
            raise ValueError("expected official Juice Shop 19.2.1 distribution")
        version = command("node", "--version")
        if not version.startswith("v24."):
            raise ValueError("Node fallback requires Node 24 and its matching distribution")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        # Upstream listens on all interfaces. Force every TCP listen in this owned process to loopback.
        wrapper = self.output / "loopback.cjs"
        wrapper.write_text("const net=require('node:net'); const listen=net.Server.prototype.listen; net.Server.prototype.listen=function(port,...args){if(typeof port!=='number' && !/^[0-9]+$/.test(String(port))) throw new Error('unsupported listen'); const cb=args.find(x=>typeof x==='function'); return listen.call(this,Number(port),'127.0.0.1',cb);};", encoding="utf-8")
        env = os.environ.copy()
        env.update(PORT=str(port), NODE_ENV="test")
        self.log = (self.output / "lab.log").open("w", encoding="utf-8")
        self.process = subprocess.Popen(["node", "--require", str(wrapper), "build/app.js"],
            cwd=self.distribution, env=env, stdout=self.log, stderr=subprocess.STDOUT,
            creationflags=0x08000000 if os.name == "nt" else 0)
        self.created = True
        self.origin = f"http://127.0.0.1:{port}"
        self.metadata.update(origin=self.origin, node=version, pid=self.process.pid)
        self.ready()
        return self.origin

    def healthy(self):
        return self.process is not None and self.process.poll() is None

    def close(self, keep=False):
        if self.process and not keep and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log:
            self.log.close()
