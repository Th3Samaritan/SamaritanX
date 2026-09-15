"""Verified immutable tool versions with atomic activation and reversible selection."""
import hashlib
import io
import json
import os
import re
import tempfile
import uuid
import zipfile
from pathlib import Path


def _name(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
        raise ValueError("invalid tool or version identifier")
    return value


def _read(root):
    path = Path(root) / "active.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _atomic(path, data):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def verified_version(root, tool, version):
    root = Path(root).resolve()
    directory = root / "versions" / _name(tool) / _name(version)
    if not directory.resolve().is_relative_to(root):
        raise ValueError("installation path escaped root")
    record = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    binary = directory / _name(record["binary"])
    if not binary.resolve().is_relative_to(directory.resolve()):
        raise ValueError("binary path escaped version directory")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != record["binary_sha256"]:
        raise ValueError("installed binary checksum mismatch")
    return binary.resolve()


def active_binary(root, tool):
    record = _read(root).get(tool)
    return verified_version(root, tool, record["version"]) if record else None


def activate(root, tool, version):
    verified_version(root, tool, version)
    manifest = _read(root)
    old = manifest.get(tool, {})
    if old.get("version") == version:
        return
    manifest[tool] = {"version": version, "previous": old.get("version")}
    _atomic(Path(root) / "active.json", manifest)


def rollback(root, tool):
    previous = _read(root).get(tool, {}).get("previous")
    if not previous:
        raise ValueError("no previously active verified version")
    activate(root, tool, previous)
    return previous


def install_archive(root, tool, version, data, expected, *, activate_now=True):
    root = Path(root).resolve()
    tool, version = _name(tool), _name(version)
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected.lower():
        raise ValueError("archive checksum mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        binary_name = tool + ".exe"
        info = archive.getinfo(binary_name)
        if info.file_size > 512 * 1024 * 1024:
            raise ValueError("binary exceeds installation size limit")
        binary = archive.read(info)
    parent = root / "versions" / tool
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / version
    record = {"version": version, "archive_sha256": digest, "binary": binary_name,
              "binary_sha256": hashlib.sha256(binary).hexdigest()}
    if destination.exists():
        existing = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        if existing != record:
            raise ValueError("version already installed with different contents")
        verified_version(root, tool, version)
    else:
        with tempfile.TemporaryDirectory(prefix=".install-", dir=parent) as temporary:
            staging = Path(temporary)
            (staging / binary_name).write_bytes(binary)
            (staging / "manifest.json").write_text(json.dumps(record), encoding="utf-8")
            os.replace(staging, destination)
    if activate_now:
        activate(root, tool, version)
    return record
