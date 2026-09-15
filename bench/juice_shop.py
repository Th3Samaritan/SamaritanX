"""One-command owned local Juice Shop assessment with explicit coverage gaps."""
import argparse
import asyncio
import json
import re
import uuid
from pathlib import Path
import yaml
from core.tool_installation import _atomic
from core.utils import slugify
from .lab_runtime import DockerLab, NodeLab, get_json
from .juice_shop_score import catalog, score


def lab_config(output):
    from samaritanx import load_config
    cfg = load_config(None)
    cfg["workspace"]["root"] = str(output / "scan")
    cfg["memory"]["db_path"] = str(output / "memory.sqlite")
    cfg["recon"]["local_only"] = True
    for section in ("external_tools", "llm", "notify", "monitor", "hackerone", "secret_validation", "oob"):
        cfg.setdefault(section, {})["enabled"] = False
    for key in ("ffuf", "wayback", "cloud_buckets", "github_dorks"):
        cfg["discovery"][key] = False
    cfg["scanners"]["nuclei"] = False
    cfg["safety"]["aggressive"] = True
    cfg["transport"]["strict_mutations"] = True
    cfg["stealth"].update(rate_limit_rps=15, per_host_rps=15, jitter_ms=[0, 20])
    cfg["reporting"]["format"] = ["markdown"]
    cfg["crawler"].update(max_depth=2, max_urls_per_host=150, follow_subdomains=False)
    cfg["scan"].update(task_timeout_seconds=30, scanner_request_budget=60, scanner_retries=0)
    return cfg


def run(output, deadline=180, keep=False, distribution=None, authenticated=False):
    output = Path(output).resolve() / uuid.uuid4().hex
    output.mkdir(parents=True)
    runtime = NodeLab(output, distribution) if distribution else DockerLab(output)
    result = {"status": "starting", "output": str(output), "deadline": deadline, "discovery_mode": "unseeded"}
    code = 2
    from .juice_shop_setup import Identities
    identities = Identities()
    try:
        origin = runtime.start()
        print("[juice-shop] lab ready: " + origin, flush=True)
        cfg = lab_config(output)
        scope = output / "scope.txt"
        scope.write_text("re:^" + re.escape(origin) + r"(?:/|$)" + "\n", encoding="utf-8")
        if authenticated:
            identities.prepare(origin, output)
            cfg["authorization"]["objects"] = identities.objects
        result["identities"] = ["user-a", "user-b"] if authenticated else ["anonymous"]
        _atomic(output / "effective-config.json", cfg)
        before = catalog(get_json(origin, "/api/Challenges"))
        _atomic(output / "challenges-before.json", before)
        from samaritanx import _build_orchestrator
        orch = _build_orchestrator(cfg, origin, auth=identities.recipes[0] if authenticated else None, second_auth=identities.recipes[1] if authenticated else None, extra_sessions=[],
            scope_file=scope, resume=False, deadline=deadline, task_timeout=30, quiet=True, screenshots=False)
        print("[juice-shop] scan started", flush=True)
        asyncio.run(orch.run())
        after = catalog(get_json(origin, "/api/Challenges"))
        _atomic(output / "challenges-after.json", after)
        reports = output / "scan" / slugify(origin) / "reports"
        findings = json.loads((reports / "findings.json").read_text(encoding="utf-8"))
        candidates = json.loads((reports / "candidates.json").read_text(encoding="utf-8"))
        result.update(score(before, after, findings, candidates, healthy=runtime.healthy(),
                            execution=orch.memory.execution_summary(orch.target_slug)))
        _atomic(reports / "coverage.json", orch.memory.execution_coverage(orch.target_slug))
        result["deadline_reached"] = orch.deadline_reached
        try:
            result["circuit"] = orch.http._circuit_registry().snapshot()
        except Exception:
            result["circuit"] = {}
        if result["status"] != "invalid":
            result["status"] = "partial" if orch.deadline_reached else "completed"
        code = 0 if result["status"] == "completed" else 2
    except KeyboardInterrupt:
        result.update(status="cancelled")
    except Exception as exc:
        result.update(status="blocked" if not runtime.origin else "failed", error_type=type(exc).__name__)
        # This workflow uses no credentials; retain bounded runtime diagnostics locally.
        (output / "error.txt").write_text(str(exc)[:4000], encoding="utf-8")
        code = 2 if result["status"] == "blocked" else 1
    finally:
        identities.close()
        try:
            runtime.close(keep)
            result["cleanup"] = "kept" if keep and runtime.created else "completed"
        except Exception as exc:
            result.update(cleanup="failed", cleanup_error=type(exc).__name__)
            code = 1
        result["runtime"] = runtime.metadata
        _atomic(output / "benchmark.json", result)
        (output / "benchmark.md").write_text("# Juice Shop benchmark\n\n```json\n" + json.dumps(result, indent=2) + "\n```\n", encoding="utf-8")
    return result, code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--deadline", type=int, default=180)
    run_parser.add_argument("--output", type=Path, default=Path("workspace/juice-shop"))
    run_parser.add_argument("--keep-lab", action="store_true")
    run_parser.add_argument("--authenticated", action="store_true")
    run_parser.add_argument("--node-distribution", type=Path)
    report = sub.add_parser("report")
    report.add_argument("--run", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "report":
        print((args.run / "benchmark.json").read_text(encoding="utf-8"))
        return 0
    if not 1 <= args.deadline <= 86400:
        parser.error("deadline must be 1-86400 seconds")
    result, code = run(args.output, args.deadline, args.keep_lab, args.node_distribution, args.authenticated)
    print(json.dumps(result, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
