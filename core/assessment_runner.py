"""Run declared assessments with durable phase outcomes and isolated artifacts."""
import asyncio
import json
import time
import uuid
from pathlib import Path
from .assessment_profile import load_profile, profile_hash
from .tool_installation import _atomic


def preflight(profile):
    checks = []
    for phase in profile["phases"]:
        row = {"id": phase["id"], "status": "ready"}
        if phase["kind"] == "mobile-dynamic":
            row.update(status="unconfirmed", reason="Appium session identity is checked when execution starts; no device check was performed")
        checks.append(row)
    return checks


def execute_phase(phase, output):
    from assessments.common import read_limited, write_report
    kind = phase["kind"]
    if kind == "web":
        from samaritanx import load_config, _build_orchestrator
        cfg = load_config(phase.get("config"))
        cfg["workspace"]["root"] = str(output)
        cfg["memory"]["db_path"] = str(output / "memory.sqlite")
        orch = _build_orchestrator(cfg, phase["target"], auth=phase.get("auth"),
            second_auth=phase.get("second_auth"), extra_sessions=[], scope_file=phase["scope"],
            resume=False, deadline=phase["deadline"], task_timeout=60, quiet=True, screenshots=False)
        asyncio.run(orch.run())
        from core.utils import slugify
        reports = output / slugify(phase["target"]) / "reports"
        if not (reports / "findings.json").is_file():
            raise RuntimeError("scan did not produce findings.json")
        return {"status": "partial" if getattr(orch, "deadline_reached", False) else "completed", "reports": str(reports)}
    if kind == "mobile-static":
        from assessments.mobile_static import assess
        report = assess(phase["artifact"])
    elif kind == "local-audit":
        from assessments.local_privilege import assess, collect
        report = assess(json.loads(read_limited(phase["snapshot"])) if phase.get("snapshot") else collect())
    elif kind == "mobile-traffic":
        from assessments.mobile_traffic import assess
        report = assess(phase["har"], phase["scope_hosts"])
        _atomic(output / "api-seeds.json", report["api_seeds"])
    else:
        from assessments.mobile_dynamic import assess
        steps = json.loads(read_limited(phase["flow"])).get("steps", []) if phase.get("flow") else []
        if phase.get("device_id"):
            from assessments.mobile_runtime import assess_owned
            report = asyncio.run(assess_owned(phase["server"], phase["platform"], phase["app_id"], phase["device_id"],
                                             steps=steps, aggressive=phase.get("aggressive", False)))
        else:
            report = asyncio.run(assess(phase["server"], phase["session_id"], phase["platform"], phase["app_id"],
                                       steps=steps, aggressive=phase.get("aggressive", False)))
    write_report(report, output)
    return {"status": report["status"], "report": str(output / "assessment.json"),
            "candidates": len(report["candidates"])}


def run_profile(path, *, check_only=False):
    profile = load_profile(path)
    checks = preflight(profile)
    if check_only:
        return {"status": "preflight", "checks": checks}, 2 if any(c["status"] != "ready" for c in checks) else 0
    run_id = uuid.uuid4().hex
    output = Path(profile["output"]) / run_id
    output.mkdir(parents=True)
    manifest = {"version": 1, "run_id": run_id, "profile_hash": profile_hash(profile),
                "started": time.time(), "status": "running", "phases": [], "output": str(output)}
    _atomic(output / "effective-profile.json", profile)
    code = 0
    try:
        for phase in profile["phases"]:
            dest = output / phase["id"]
            dest.mkdir()
            row = {"id": phase["id"], "kind": phase["kind"], "status": "running", "started": time.time()}
            manifest["phases"].append(row)
            _atomic(output / "assessment-run.json", manifest)
            try:
                row.update(execute_phase(phase, dest))
            except (KeyboardInterrupt, asyncio.CancelledError):
                row["status"] = "cancelled"
                raise
            except Exception as exc:
                # Exception strings can contain request bodies and credentials.
                row.update(status="failed", error_type=type(exc).__name__)
            finally:
                row["finished"] = time.time()
                _atomic(output / "assessment-run.json", manifest)
            if phase.get("required", True) and row["status"] != "completed":
                code = 1 if row["status"] == "failed" or code == 1 else 2
        manifest["status"] = "completed" if code == 0 else "partial"
    except (KeyboardInterrupt, asyncio.CancelledError):
        manifest["status"] = "cancelled"
        code = 2
    finally:
        manifest["finished"] = time.time()
        _atomic(output / "assessment-run.json", manifest)
        lines = ["# Assessment run", "", "Status: " + manifest["status"], "",
                 "| Phase | Kind | Status |", "| --- | --- | --- |"]
        lines += [f"| {r['id']} | {r['kind']} | {r['status']} |" for r in manifest["phases"]]
        (output / "assessment-run.md").write_text("\n".join(lines), encoding="utf-8")
    return manifest, code
