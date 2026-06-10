#!/usr/bin/env python3
"""SamaritanX self-test harness.

Two modes:

    python3 selftest.py            # offline structural checks (fast, no network)
    python3 selftest.py --live     # also run an end-to-end smoke scan

The offline checks catch the failure classes that silently break the tool:
  * any module failing to import (one bad scanner breaks `from scanners import *`)
  * a scanner whose `scan()` signature doesn't match what the VulnAgent calls
  * config.yaml referencing scanners that aren't in the REGISTRY (and vice-versa)
  * the unit-test suite (memory, queue, scope, utils, config validator)

The --live smoke scan points the full pipeline at a deliberately vulnerable,
publicly-authorized target (testphp.vulnweb.com, run by Acunetix as a test
sandbox) and asserts that recon emits a live host, the crawler discovers
parameters, scanners produce at least one finding, and the report files are
written. That is the real "is it working end-to-end" proof.

Exit code 0 = all checks passed; non-zero = something failed.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
_passed = 0
_failed = 0


def ok(msg: str) -> None:
    global _passed
    _passed += 1
    print(f"  {GREEN}PASS{RESET} {msg}")


def fail(msg: str, detail: str = "") -> None:
    global _failed
    _failed += 1
    print(f"  {RED}FAIL{RESET} {msg}")
    if detail:
        for line in detail.strip().splitlines():
            print(f"       {DIM}{line}{RESET}")


def section(title: str) -> None:
    print(f"\n{YELLOW}== {title} =={RESET}")


# --------------------------------------------------------------------------
# 1) every module imports
# --------------------------------------------------------------------------
def check_imports() -> None:
    section("module imports")
    modules: list[str] = []
    for pkg in ("core", "agents", "scanners", "reporting"):
        for f in sorted((ROOT / pkg).glob("*.py")):
            if f.stem == "__init__":
                continue
            modules.append(f"{pkg}.{f.stem}")
    modules += ["scanners", "core.orchestrator", "samaritanx"]
    for mod in modules:
        try:
            importlib.import_module(mod)
            ok(f"import {mod}")
        except Exception:
            fail(f"import {mod}", traceback.format_exc())


# --------------------------------------------------------------------------
# 2) every REGISTRY scanner has the right async signature
# --------------------------------------------------------------------------
EXPECTED_PARAMS = ["ctx", "url", "params", "method", "form"]


def check_scanner_signatures() -> None:
    section("scanner signatures")
    from scanners import REGISTRY
    for name, fn in REGISTRY.items():
        if not inspect.iscoroutinefunction(fn):
            fail(f"{name}: scan() is not async")
            continue
        params = list(inspect.signature(fn).parameters)
        if params[:5] != EXPECTED_PARAMS:
            fail(f"{name}: signature {params[:5]} != {EXPECTED_PARAMS}")
        else:
            ok(f"{name}: async scan(ctx, url, params, method, form)")


# --------------------------------------------------------------------------
# 3) config <-> registry consistency
# --------------------------------------------------------------------------
def check_config_registry() -> None:
    section("config / registry consistency")
    import yaml
    from scanners import REGISTRY
    cfg = yaml.safe_load((ROOT / "config" / "config.yaml").read_text(encoding="utf-8"))
    enabled = cfg.get("scanners", {}).get("enabled", [])
    known = set(REGISTRY)
    unknown = [s for s in enabled if s not in known]
    if unknown:
        fail(f"config enables unknown scanners: {unknown}")
    else:
        ok(f"all {len(enabled)} enabled scanners exist in REGISTRY")
    from core.config_validator import validate_config
    issues = validate_config(cfg)
    if issues:
        fail("config validation produced warnings", "\n".join(issues))
    else:
        ok("config.yaml passes schema validation")


# --------------------------------------------------------------------------
# 4) agent routing — every kind an agent produces is handled by some agent
# --------------------------------------------------------------------------
def check_agent_routing() -> None:
    section("agent routing")
    from agents.recon_agent import ReconAgent
    from agents.crawler_agent import CrawlerAgent
    from agents.discovery_agent import DiscoveryAgent
    from agents.vuln_agent import VulnerabilityAgent
    from agents.logic_agent import LogicAgent
    from agents.exploit_agent import ExploitAgent
    from agents.secret_validator import SecretValidatorAgent
    from agents.screenshot_agent import ScreenshotAgent
    from agents.reporting_agent import ReportingAgent

    agents = [ReconAgent(), CrawlerAgent(), DiscoveryAgent(), VulnerabilityAgent(),
              LogicAgent(), ExploitAgent(), SecretValidatorAgent(),
              ScreenshotAgent(), ReportingAgent()]
    handled: set[str] = set()
    for a in agents:
        handled.update(a.handles)
    produced = {"recon", "crawl", "discover", "scan", "scan.graphql",
                "scan.takeover", "logic", "exploit", "validate_secrets",
                "screenshot", "report"}
    missing = produced - handled
    if missing:
        fail(f"task kinds produced but not handled by any agent: {sorted(missing)}")
    else:
        ok(f"all {len(produced)} task kinds have a registered handler")


# --------------------------------------------------------------------------
# 5) unit tests
# --------------------------------------------------------------------------
def check_unit_tests() -> None:
    section("unit tests (tests/test_core.py)")
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    if result.wasSuccessful():
        ok(f"{result.testsRun} unit tests passed")
    else:
        fail(f"{len(result.failures)} failures, {len(result.errors)} errors",
             "\n".join(str(t[0]) for t in result.failures + result.errors))


# --------------------------------------------------------------------------
# 6) live end-to-end smoke scan (opt-in)
# --------------------------------------------------------------------------
def check_live_scan(target: str) -> None:
    section(f"live smoke scan -> {target}")
    import yaml
    from core.orchestrator import Orchestrator
    from agents.recon_agent import ReconAgent
    from agents.crawler_agent import CrawlerAgent
    from agents.discovery_agent import DiscoveryAgent
    from agents.vuln_agent import VulnerabilityAgent
    from agents.logic_agent import LogicAgent
    from agents.exploit_agent import ExploitAgent
    from agents.reporting_agent import ReportingAgent

    cfg = yaml.safe_load((ROOT / "config" / "config.yaml").read_text(encoding="utf-8"))
    cfg.setdefault("scanners", {})["nuclei"] = False
    cfg.setdefault("reporting", {})["format"] = ["markdown"]

    orch = Orchestrator(cfg, target, deadline=240, task_timeout=60)
    for a in (ReconAgent(), CrawlerAgent(), DiscoveryAgent(), VulnerabilityAgent(),
              LogicAgent(), ExploitAgent(), ReportingAgent()):
        orch.register(a)

    try:
        asyncio.run(orch.run())
    except Exception:
        fail("pipeline raised", traceback.format_exc())
        return

    ws = orch.workspace
    live = ws / "recon" / "live.json"
    if live.exists() and live.read_text().strip() not in ("", "[]"):
        ok("recon found a live host")
    else:
        fail("recon found no live host (network/DNS issue?)")

    params_files = list((ws / "crawl").glob("*_params.txt"))
    n_params = sum(len([l for l in p.read_text().splitlines() if l.strip()])
                   for p in params_files)
    if n_params > 0:
        ok(f"crawler discovered {n_params} parameter(s) to test")
    else:
        fail("crawler discovered 0 parameters — scanners had nothing to inject")

    findings = orch.memory.list_findings(orch.target_slug)
    if findings:
        ok(f"scanners produced {len(findings)} finding(s)")
    else:
        fail("0 findings on a known-vulnerable target — investigate scanners")

    report = ws / "reports" / "report.md"
    if report.exists() and report.stat().st_size > 0:
        ok(f"report written: {report}")
    else:
        fail("report.md was not written")
    print(f"\n  {DIM}workspace: {ws}{RESET}")


def main() -> int:
    ap = argparse.ArgumentParser(description="SamaritanX self-test")
    ap.add_argument("--live", action="store_true",
                    help="run an end-to-end smoke scan against a vulnerable test target")
    ap.add_argument("--target", default="testphp.vulnweb.com",
                    help="target for --live (default: testphp.vulnweb.com, an authorized test site)")
    args = ap.parse_args()

    print(f"{YELLOW}SamaritanX self-test{RESET}  ({ROOT})")

    def run(check, *a):
        try:
            check(*a)
        except Exception:
            fail(f"{check.__name__} aborted", traceback.format_exc())

    run(check_imports)
    run(check_scanner_signatures)
    run(check_config_registry)
    run(check_agent_routing)
    run(check_unit_tests)
    if args.live:
        run(check_live_scan, args.target)

    print(f"\n{'=' * 48}")
    color = GREEN if _failed == 0 else RED
    print(f"{color}{_passed} passed, {_failed} failed{RESET}")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
