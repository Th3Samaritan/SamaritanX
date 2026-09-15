"""Read-only local privilege-boundary review; never executes an escalation."""
import json
import os
import platform
import re
import stat
import subprocess
from pathlib import Path
from .common import result, candidate


def assess(snapshot):
    if not isinstance(snapshot, dict) or snapshot.get("schema_version", 1) != 1:
        raise ValueError("expected version 1 local inventory")
    system = snapshot.get("platform", "").lower()
    if system not in {"linux", "windows"}:
        raise ValueError("snapshot platform must be linux or windows")
    report = result("local_privilege", system)
    report["checks"] = list(snapshot.get("checks", []))
    report["inventory"] = {"schema_version": 1, "os_version": snapshot.get("os_version"),
                           "collection_privilege": snapshot.get("collection_privilege", "unknown")}
    if len(snapshot.get("files", [])) > 20000 or len(snapshot.get("services", [])) > 2000:
        report["checks"].append({"check": "inventory_limit", "status": "unavailable", "reason": "input exceeds bounded coverage"})
    if system == "linux":
        for row in snapshot.get("files", [])[:20000]:
            mode = int(row.get("mode", 0))
            if row.get("uid") == 0 and mode & stat.S_IWOTH:
                candidate(report, "local_writable_privileged_file", "Root-owned file is writable by everyone",
                          f"{row['path']}: mode {oct(mode)}; contextual execution and ACL review required.",
                          "Remove unnecessary write permissions and verify ownership and service references.")
            if mode & stat.S_ISUID and row.get("uid") == 0:
                report["checks"].append({"check": "setuid_inventory", "status": "observed", "path": row["path"]})
        if snapshot.get("sudo_nopasswd_all"):
            candidate(report, "local_sudo_policy", "Unrestricted passwordless sudo rule needs review",
                      "A readable sudoers policy contains NOPASSWD: ALL; user/group applicability was not established.",
                      "Limit commands and identities to the required administrative scope.")
    else:
        for row in snapshot.get("services", [])[:2000]:
            command = str(row.get("PathName", "")).strip()
            match = re.match(r"([^\"]+?\.exe)(?:\s|$)", command, re.I)
            account = str(row.get("StartName", "")).lower()
            if match and " " in match.group(1) and account in {"localsystem", "nt authority\\system"}:
                candidate(report, "windows_service_path", "Privileged service has an unquoted executable path",
                          f"Service {row.get('Name', 'unknown')}: {match.group(1)}. Writable path prefixes and restart rights need verification.",
                          "Quote the executable path and restrict service binary and directory write permissions.")
        if snapshot.get("always_install_elevated_machine") is True and snapshot.get("always_install_elevated_user") is True:
            candidate(report, "windows_installer_policy", "AlwaysInstallElevated enabled for machine and user",
                      "Both Windows Installer elevation policy values are enabled.",
                      "Disable AlwaysInstallElevated in both policy scopes.")
    if any(row.get("status") == "unavailable" for row in report["checks"]):
        report["status"] = "partial"
    report["limitations"].append("Read-only configuration assessment: no kernel exploits, token theft, credential collection, persistence, or privilege changes are performed.")
    return report


def collect():
    system = platform.system().lower()
    snapshot = {"schema_version": 1, "platform": system, "os_version": platform.version(),
                "collection_privilege": "unknown", "checks": []}
    if system == "linux":
        paths = set()
        for directory in ("/bin", "/usr/bin", "/usr/local/bin", "/etc/systemd/system"):
            try:
                paths.update(p.resolve() for p in list(Path(directory).iterdir())[:5000] if p.is_file())
            except OSError:
                snapshot["checks"].append({"check": directory, "status": "unavailable"})
        snapshot["files"] = []
        for path in sorted(paths):
            try:
                info = path.stat()
                snapshot["files"].append({"path": str(path), "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode)})
            except OSError:
                snapshot["checks"].append({"check": str(path), "status": "unavailable"})
        try:
            from .common import read_limited
            text = read_limited('/etc/sudoers', 1024 * 1024).decode('utf-8', 'replace')
            snapshot["sudo_nopasswd_all"] = any(re.search(r"NOPASSWD:\s*ALL(?:\s|$)", line.split('#', 1)[0]) for line in text.splitlines())
            snapshot["checks"].append({"check": "sudoers", "status": "observed", "included_files": "not assessed"})
        except OSError:
            snapshot["checks"].append({"check": "sudoers", "status": "unavailable", "reason": "not readable as current user"})
    elif system == "windows":
        script = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); @(Get-CimInstance Win32_Service | Select-Object -First 2000 Name,PathName,StartName) | ConvertTo-Json -Compress"
        try:
            proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                  capture_output=True, timeout=30, creationflags=0x08000000)
            if proc.returncode:
                raise ValueError("service inventory unavailable")
            services = json.loads(proc.stdout.decode("utf-8-sig"))
            snapshot["services"] = services if isinstance(services, list) else [services]
            snapshot["checks"].append({"check": "services", "status": "observed"})
        except (OSError, ValueError, subprocess.TimeoutExpired):
            snapshot["checks"].append({"check": "services", "status": "unavailable"})
        import winreg
        for label, hive in (("machine", winreg.HKEY_LOCAL_MACHINE), ("user", winreg.HKEY_CURRENT_USER)):
            try:
                with winreg.OpenKey(hive, r"Software\Policies\Microsoft\Windows\Installer") as key:
                    snapshot["always_install_elevated_" + label] = winreg.QueryValueEx(key, "AlwaysInstallElevated")[0] == 1
            except FileNotFoundError:
                snapshot["always_install_elevated_" + label] = False
            except OSError:
                snapshot["checks"].append({"check": "installer_" + label, "status": "unavailable"})
    else:
        raise ValueError("local collection supports Windows and Linux")
    return snapshot
