"""Download official Windows AMD64 releases and verify their published checksums."""
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile
import sys


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "SamaritanX-local-smoke"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read()


def main():
    destination = Path(__file__).resolve().parents[1] / "workspace" / "tools"
    destination.mkdir(parents=True, exist_ok=True)
    if "--templates-only" in sys.argv:
        release = json.loads(fetch("https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest"))
        url = f"https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/tags/{release['tag_name']}"
        data = fetch(url)
        target = (destination / "nuclei-templates").resolve()
        count = 0
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            for entry in bundle.infolist():
                parts = entry.filename.split("/")[1:]
                if not parts or parts[0] not in {"http", "helpers", ".nuclei-ignore"} or entry.is_dir():
                    continue
                path = target.joinpath(*parts).resolve()
                if not path.is_relative_to(target):
                    raise RuntimeError("Template archive path escaped destination")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(bundle.read(entry))
                count += 1
        record = {"version": release["tag_name"], "url": url,
                  "archive_sha256": hashlib.sha256(data).hexdigest(), "files": count}
        (destination / "templates-manifest.json").write_text(json.dumps(record, indent=2))
        print(json.dumps(record), flush=True)
        return
    manifest = {}
    for repository in ("projectdiscovery/nuclei", "projectdiscovery/subfinder", "ffuf/ffuf"):
        name = repository.split("/")[-1]
        release = json.loads(fetch(f"https://api.github.com/repos/{repository}/releases/latest"))
        assets = release["assets"]
        archive = next(a for a in assets if "windows_amd64" in a["name"].lower() and a["name"].endswith(".zip"))
        checksums = next(a for a in assets if "checksums" in a["name"].lower())
        checksum_text = fetch(checksums["browser_download_url"]).decode()
        expected = next(line.split()[0] for line in checksum_text.splitlines()
                        if line.split()[-1].lstrip("*") == archive["name"])
        data = fetch(archive["browser_download_url"])
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise RuntimeError(f"Checksum mismatch: {name}")
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            entry = next(info for info in bundle.infolist() if info.filename == f"{name}.exe")
            executable = bundle.read(entry)
        (destination / f"{name}.exe").write_bytes(executable)
        manifest[name] = {"version": release["tag_name"], "url": archive["browser_download_url"],
                          "archive_sha256": digest, "binary_sha256": hashlib.sha256(executable).hexdigest()}
        print(f"{name} {release['tag_name']}: checksum verified", flush=True)
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
