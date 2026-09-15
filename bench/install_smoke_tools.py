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
    import argparse
    from core.tool_installation import install_archive, activate, rollback
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="append", default=[], metavar="TOOL=TAG")
    parser.add_argument("--activate", nargs=2, metavar=("TOOL", "TAG"))
    parser.add_argument("--rollback", choices=["nuclei", "subfinder", "ffuf"])
    parser.add_argument("--templates-only", action="store_true")
    parser.add_argument("--template-version")
    parser.add_argument("--template-sha256")
    parser.add_argument("--no-activate", action="store_true")
    parser.add_argument("--destination", type=Path, default=Path(__file__).resolve().parents[1] / "workspace" / "tools")
    args = parser.parse_args()
    if sum(bool(x) for x in (args.version, args.activate, args.rollback, args.templates_only)) != 1:
        parser.error("choose explicit --version TOOL=TAG, --activate TOOL TAG, or --rollback TOOL")
    if args.templates_only:
        from core.tool_installation import _name
        from urllib.parse import quote
        if not args.template_version or not args.template_sha256:
            parser.error("template installation requires --template-version TAG and --template-sha256 HASH")
        version = _name(args.template_version)
        url = f"https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/tags/{quote(version, safe='')}"
        data = fetch(url)
        if hashlib.sha256(data).hexdigest() != args.template_sha256.lower():
            raise ValueError("template archive checksum mismatch")
        import tempfile
        import os
        parent = args.destination.resolve() / "nuclei-template-versions"
        parent.mkdir(parents=True, exist_ok=True)
        target = parent / version
        if target.exists():
            raise ValueError("template version already exists; select its existing http directory")
        with tempfile.TemporaryDirectory(prefix=".install-", dir=parent) as temporary:
            staging = Path(temporary).resolve()
            count = 0
            with zipfile.ZipFile(io.BytesIO(data)) as bundle:
                for entry in bundle.infolist():
                    parts = entry.filename.split("/")[1:]
                    if not parts or parts[0] not in {"http", "helpers", ".nuclei-ignore"} or entry.is_dir():
                        continue
                    path = staging.joinpath(*parts).resolve()
                    if not path.is_relative_to(staging):
                        raise ValueError("template archive escaped destination")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(bundle.read(entry))
                    count += 1
            if not count:
                raise ValueError("template archive has no selected files")
            (staging / "manifest.json").write_text(json.dumps({"version": version, "archive_sha256": args.template_sha256, "url": url}), encoding="utf-8")
            os.replace(staging, target)
        print(f"Set external_tools.nuclei_templates to {target / 'http'}")
        return
    if args.rollback:
        print(rollback(args.destination, args.rollback))
        return
    if args.activate:
        activate(args.destination, *args.activate)
        return
    repositories = {"nuclei": "projectdiscovery/nuclei", "subfinder": "projectdiscovery/subfinder", "ffuf": "ffuf/ffuf"}
    from urllib.parse import quote
    for selection in args.version:
        name, separator, version = selection.partition("=")
        if not separator or name not in repositories or not version or version == "latest":
            parser.error("versions must be explicit TOOL=TAG selections")
        release = json.loads(fetch(f"https://api.github.com/repos/{repositories[name]}/releases/tags/{quote(version, safe='')}"))
        if release["tag_name"] != version:
            raise ValueError("release tag differs from requested version")
        assets = release["assets"]
        archive = next(a for a in assets if "windows_amd64" in a["name"].lower() and a["name"].endswith(".zip"))
        checksums = next(a for a in assets if "checksums" in a["name"].lower())
        checksum_text = fetch(checksums["browser_download_url"]).decode()
        expected = next(line.split()[0] for line in checksum_text.splitlines()
                        if len(line.split()) >= 2 and line.split()[-1].lstrip("*") == archive["name"])
        data = fetch(archive["browser_download_url"])
        record = install_archive(args.destination, name, version, data, expected,
                                 activate_now=not args.no_activate)
        print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
