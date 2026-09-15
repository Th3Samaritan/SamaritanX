"""Bounded policy and executable metadata checks; observations never prove exploitability."""
import hashlib
import re
import struct
from .common import candidate
from .android_xml import parse


def android_policies(archive, root, report, read_member):
    ns = "{http://schemas.android.com/apk/res/android}"
    app = root.find("application")
    sdk = root.find("uses-sdk")
    report["checks"].append({"check": "android_sdk", "status": "observed",
        "minimum": sdk.get(ns + "minSdkVersion") if sdk is not None else None,
        "target": sdk.get(ns + "targetSdkVersion") if sdk is not None else None})
    permissions = [{"name": n.get(ns + "name"), "protection_level": n.get(ns + "protectionLevel", "normal")} for n in root.findall("permission")]
    links = [{"scheme": n.get(ns + "scheme"), "host": n.get(ns + "host"), "path": n.get(ns + "path")} for n in root.findall(".//intent-filter/data")]
    report["checks"].append({"check": "android_entry_policy", "status": "observed", "custom_permissions": permissions, "deep_links": links})
    if app is None:
        return
    for attribute in ("networkSecurityConfig", "fullBackupContent", "dataExtractionRules"):
        ref = app.get(ns + attribute)
        if not ref or ref in {"true", "false"}:
            continue
        match = re.fullmatch(r"@xml/([A-Za-z0-9_]+)", ref)
        member = "res/xml/" + match.group(1) + ".xml" if match else None
        if not member or member not in archive.namelist():
            report["status"] = "partial"
            report["checks"].append({"check": attribute, "status": "unavailable", "reason": "resource table or configuration resolution required"})
            continue
        data = read_member(archive, member)
        policy = parse(data)
        variants = [n for n in archive.namelist() if n.startswith("res/xml-") and n.endswith("/" + match.group(1) + ".xml")]
        report["checks"].append({"check": attribute, "status": "observed", "member": member,
            "sha256": hashlib.sha256(data).hexdigest(), "configuration_variants_unresolved": len(variants),
            "rules": [{"kind": n.tag, "attributes": dict(n.attrib)} for n in policy.iter()]})
        if variants:
            report["status"] = "partial"
        if attribute == "networkSecurityConfig":
            for node in policy.iter():
                if node.get("cleartextTrafficPermitted") == "true":
                    candidate(report, "android_network_policy", "Network policy permits cleartext traffic",
                        f"{member}: {node.tag} permits cleartext; review effective inheritance and domain scope.", "Require HTTPS for sensitive traffic.")
                if node.tag == "certificates" and node.get("src") == "user":
                    candidate(report, "android_trust_policy", "Network policy includes user-installed certificates",
                        f"{member}: user trust anchor present; inspect debug-only context and runtime behavior.", "Restrict production trust anchors to the intended certificate authorities.")


def macho(data):
    if len(data) < 28:
        raise ValueError("truncated executable header")
    magic = data[:4]
    formats = {b"\xce\xfa\xed\xfe": ("<",28), b"\xcf\xfa\xed\xfe": ("<",32),
               b"\xfe\xed\xfa\xce": (">",28), b"\xfe\xed\xfa\xcf": (">",32)}
    if magic not in formats:
        return {"check": "macho", "status": "unavailable", "reason": "universal or unsupported executable; per-slice analysis required"}
    endian, offset = formats[magic]
    _, cpu, _, _, count, size, flags = struct.unpack_from(endian + "7I", data)
    if count > 10000 or offset + size > len(data):
        raise ValueError("invalid Mach-O load command bounds")
    end = offset + size
    encrypted = False
    signature = False
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError("truncated Mach-O command")
        cmd, length = struct.unpack_from(endian + "II", data, offset)
        if length < 8 or offset + length > end:
            raise ValueError("invalid Mach-O command")
        if cmd in {0x21, 0x2c}:
            if length < 20: raise ValueError("truncated encryption command")
            encrypted |= struct.unpack_from(endian + "I", data, offset + 16)[0] != 0
        signature |= cmd == 0x1d
        offset += length
    return {"check": "macho", "status": "observed", "cpu_type": cpu, "pie_flag": bool(flags & 0x200000),
            "encrypted": encrypted, "signature_command_present": signature, "signature_validity": "unavailable"}


def string_inventory(archive, names, report):
    selected = [n for n in names if re.fullmatch(r"classes[0-9]*\.dex", n)]
    remaining = 16 * 1024 * 1024
    endpoints = set()
    inspected = 0
    for name in selected[:10]:
        info = archive.getinfo(name)
        if info.file_size > remaining:
            continue
        data = archive.read(info)
        remaining -= len(data)
        inspected += 1
        for match in re.finditer(rb"https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?", data):
            endpoints.add(match.group().decode("ascii"))
            if len(endpoints) >= 500: break
    if selected:
        report["checks"].append({"check": "dex_endpoint_strings", "status": "observed" if inspected == len(selected) else "partial",
            "members_inspected": inspected, "members_total": len(selected), "origins": sorted(endpoints),
            "reachability": "not established"})
        if inspected != len(selected): report["status"] = "partial"
