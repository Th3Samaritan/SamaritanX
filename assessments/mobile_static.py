"""APK/IPA configuration assessment with bounded, extraction-free archive reads."""
import plistlib
import zipfile
from pathlib import Path, PurePosixPath
from .common import result, candidate, digest_file
from .android_xml import parse

ANDROID = "{http://schemas.android.com/apk/res/android}"


def _member(archive, name):
    info = archive.getinfo(name)
    if info.file_size > 4 * 1024 * 1024 or info.flag_bits & 1:
        raise ValueError("oversized or encrypted metadata")
    return archive.read(info)


def android_manifest(root, report):
    report["package_id"] = root.get("package", "unknown")
    app = root.find("application")
    if app is None:
        raise ValueError("manifest has no application")
    for flag, title in (("debuggable", "Release app allows debugging"),
                        ("testOnly", "App is marked test-only"),
                        ("usesCleartextTraffic", "App permits cleartext network traffic")):
        if app.get(ANDROID + flag) == "true":
            candidate(report, "android_configuration", title, f"application android:{flag}=true",
                      f"Review and disable {flag} in production builds unless explicitly needed.")
    if app.get(ANDROID + "allowBackup") != "false":
        candidate(report, "android_backup", "Review app backup exposure",
                  "allowBackup is true or unspecified; actual backup behavior depends on Android version and backup rules.",
                  "Exclude sensitive data from backups and review dataExtractionRules/fullBackupContent.")
    target = root.find("uses-sdk")
    target_sdk = (target.get(ANDROID + "targetSdkVersion", "") if target is not None else "")
    permissions = [node.get(ANDROID + "name", "") for node in root.findall("uses-permission")]
    report["checks"].append({"check": "manifest", "status": "observed", "target_sdk": target_sdk,
                             "permissions": permissions})
    exported = []
    for node in app:
        if node.tag not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        flag = node.get(ANDROID + "exported")
        implied = flag is None and node.tag != "provider" and node.find("intent-filter") is not None
        if flag == "true" or implied:
            name = node.get(ANDROID + "name", "unnamed")
            permission = node.get(ANDROID + "permission") or app.get(ANDROID + "permission")
            exported.append({"type": node.tag, "name": name, "permission": permission})
            if not permission:
                candidate(report, "android_exported_component", "Exported component needs authorization review",
                          f"{node.tag} {name} is exported without a declared permission; this may be intentional.",
                          "Review component entry points and enforce caller authorization where needed.")
    report["checks"].append({"check": "exported_components", "status": "observed", "components": exported})
    if app.get(ANDROID + "networkSecurityConfig") or any(
            str(app.get(ANDROID + key, "")).startswith("@") for key in ("debuggable", "allowBackup", "usesCleartextTraffic")):
        report["checks"].append({"check": "network_security_resource", "status": "unavailable",
            "reason": "Compiled resource policies require resource-table resolution; manifest alone is insufficient."})
        report["status"] = "partial"
    report["limitations"].append("Manifest review does not verify runtime authorization, signing integrity, pinning, or native code behavior.")


def ios_plist(info, report):
    report["package_id"] = info.get("CFBundleIdentifier", "unknown")
    ats = info.get("NSAppTransportSecurity") or {}
    for key in ("NSAllowsArbitraryLoads", "NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia"):
        if ats.get(key) is True:
            candidate(report, "ios_transport_policy", "Review broad App Transport Security exception",
                      f"{key}=true; effective behavior depends on platform version and other ATS keys.",
                      "Prefer narrowly scoped HTTPS exceptions and verify actual runtime traffic.")
    for domain, policy in (ats.get("NSExceptionDomains") or {}).items():
        if not isinstance(policy, dict):
            continue
        if policy.get("NSExceptionAllowsInsecureHTTPLoads") is True or policy.get("NSTemporaryExceptionAllowsInsecureHTTPLoads") is True:
            candidate(report, "ios_transport_policy", "Domain permits insecure HTTP loads",
                      f"ATS exception for {domain} permits insecure HTTP.", "Require HTTPS for sensitive endpoints.")
    for key in ("UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace"):
        if info.get(key) is True:
            candidate(report, "ios_storage_policy", "Review user-accessible application documents",
                      f"{key}=true; sensitive files may need additional protection.",
                      "Keep credentials and private data out of shared document locations.")
    schemes = [scheme for row in info.get("CFBundleURLTypes", []) for scheme in row.get("CFBundleURLSchemes", [])]
    report["checks"].append({"check": "info_plist", "status": "observed", "url_schemes": schemes,
                            "privacy_declarations": sorted(k for k in info if k.endswith("UsageDescription"))})
    report["limitations"].append("IPA metadata does not establish keychain protection, code-signature validity, runtime pinning or entitlement enforcement.")


def assess(path):
    path = Path(path)
    if path.suffix.lower() not in {".apk", ".ipa"}:
        raise ValueError("expected an APK or IPA archive")
    report = result("mobile_static", path.name)
    report["sha256"] = digest_file(path)
    report["platform"] = "android" if path.suffix.lower() == ".apk" else "ios"
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 50000:
            raise ValueError("too many archive members")
        names = [entry.filename for entry in entries]
        if len(set(names)) != len(names):
            raise ValueError("ambiguous duplicate archive member")
        for name in names:
            p = PurePosixPath(name)
            if p.is_absolute() or ".." in p.parts or "\\" in name:
                raise ValueError("unsafe archive member name")
        if report["platform"] == "android":
            root = parse(_member(archive, "AndroidManifest.xml"))
            android_manifest(root, report)
            from .mobile_metadata import android_policies, string_inventory
            android_policies(archive, root, report, _member)
            string_inventory(archive, names, report)
        else:
            manifests = [name for name in names if len(PurePosixPath(name).parts) == 3
                         and name.startswith("Payload/") and PurePosixPath(name).parts[1].endswith(".app")
                         and name.endswith("/Info.plist")]
            if len(manifests) != 1:
                raise ValueError("IPA must contain exactly one top-level application Info.plist")
            info = plistlib.loads(_member(archive, manifests[0]))
            if not isinstance(info, dict):
                raise ValueError("invalid Info.plist")
            ios_plist(info, report)
            from .mobile_metadata import macho
            executable = info.get("CFBundleExecutable")
            if isinstance(executable, str) and executable and "/" not in executable and "\\" not in executable:
                member = str(PurePosixPath(manifests[0]).parent / executable)
                if member in names:
                    try:
                        check = macho(_member(archive, member))
                        check["member"] = member
                        report["checks"].append(check)
                        if check["status"] != "observed" or check.get("encrypted"):
                            report["status"] = "partial"
                    except ValueError:
                        report["status"] = "partial"
                        report["checks"].append({"check": "macho", "status": "unavailable", "reason": "unsupported or oversized executable"})
    return report
