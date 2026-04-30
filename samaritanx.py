#!/usr/bin/env python3
"""SamaritanX — agentic bug bounty framework.

Usage:
    python3 samaritanx.py scan <target> [options]
    python3 samaritanx.py report <target>            # rebuild report from memory
    python3 samaritanx.py memory list <target>        # inspect persisted findings
    python3 samaritanx.py self-check                 # verify required tooling

Examples:
    sudo python3 samaritanx.py scan example.com --scope config/scope.example.txt
    python3 samaritanx.py scan https://api.example.com --auth config/auth.example.yaml --tor
    python3 samaritanx.py scan example.com --auth user_a.yaml --second-session user_b.yaml
    python3 samaritanx.py scan example.com --only sqli,rce,prompt_injection --no-pdf
    python3 samaritanx.py scan example.com --resume --walkthrough
"""
from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.logger import configure_logging  # noqa: E402
from core.orchestrator import Orchestrator  # noqa: E402

from agents.recon_agent import ReconAgent  # noqa: E402
from agents.crawler_agent import CrawlerAgent  # noqa: E402
from agents.discovery_agent import DiscoveryAgent  # noqa: E402
from agents.vuln_agent import VulnerabilityAgent  # noqa: E402
from agents.logic_agent import LogicAgent  # noqa: E402
from agents.exploit_agent import ExploitAgent  # noqa: E402
from agents.secret_validator import SecretValidatorAgent  # noqa: E402
from agents.screenshot_agent import ScreenshotAgent  # noqa: E402
from agents.reporting_agent import ReportingAgent  # noqa: E402

app = typer.Typer(add_completion=False, help="Agentic bug-bounty framework — operator: th3Samaritan")
console = Console()
DEFAULT_CONFIG = Path(__file__).resolve().parent / "config" / "config.yaml"


def load_config(path: Path | None) -> dict:
    cfg_path = Path(path) if path else DEFAULT_CONFIG
    if not cfg_path.exists():
        console.print(f"[red]config not found:[/red] {cfg_path}")
        raise typer.Exit(1)
    return yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}


def banner() -> None:
    console.print("[bold magenta]SamaritanX[/bold magenta] — agentic bug bounty framework  "
                  "[dim](operator: th3Samaritan)[/dim]")


@app.command()
def scan(
    target: str = typer.Argument(..., help="domain, host, or URL — e.g. example.com or https://api.example.com"),
    config: Path = typer.Option(None, "--config", "-c", help="override config.yaml path"),
    auth: Path = typer.Option(None, "--auth", help="auth recipe (static / form / bearer_json) — see config/auth.example.yaml"),
    second_auth: Path = typer.Option(None, "--second-session", help="second auth recipe for IDOR/BOLA cross-tenant tests"),
    scope: Path = typer.Option(None, "--scope", help="scope file (allow/deny rules) — see config/scope.example.txt"),
    resume: bool = typer.Option(False, "--resume", help="reuse memory state from a prior run (skip already-completed phases)"),
    wordlist: Path = typer.Option(None, "--wordlist", help="custom wordlist for content discovery"),
    tor: bool = typer.Option(False, "--tor", help="route all traffic via Tor (socks5://127.0.0.1:9050)"),
    proxy: str = typer.Option("", "--proxy", help="HTTP/SOCKS proxy URL (overrides config)"),
    only: str = typer.Option("", "--only", help="comma-separated scanner allow-list (e.g. sqli,xss,rce)"),
    skip: str = typer.Option("", "--skip", help="comma-separated scanner deny-list"),
    depth: int = typer.Option(0, "--depth", help="override crawler max_depth"),
    rate: float = typer.Option(0.0, "--rate", help="override stealth.rate_limit_rps"),
    no_pdf: bool = typer.Option(False, "--no-pdf", help="skip PDF rendering"),
    no_screenshots: bool = typer.Option(False, "--no-screenshots", help="skip Playwright PoC screenshots"),
    no_oob: bool = typer.Option(False, "--no-oob", help="don't register interactsh — disables blind RCE/SSRF callback detection"),
    walkthrough: bool = typer.Option(True, "--walkthrough/--no-walkthrough",
                                     help="include long-form walkthrough text in the report"),
    passive: bool = typer.Option(False, "--passive", help="passive recon only (no active probes)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Run the full agentic pipeline against a target."""
    banner()
    cfg = load_config(config)

    # CLI overrides
    if tor:
        cfg.setdefault("proxy", {})["tor"] = True
        cfg["proxy"]["enabled"] = True
    if proxy:
        cfg.setdefault("proxy", {})["enabled"] = True
        cfg["proxy"]["url"] = proxy
    if only:
        cfg.setdefault("scanners", {})["enabled"] = [s.strip() for s in only.split(",") if s.strip()]
    if skip:
        deny = {s.strip() for s in skip.split(",") if s.strip()}
        cfg.setdefault("scanners", {})["enabled"] = [
            s for s in cfg.get("scanners", {}).get("enabled", []) if s not in deny
        ]
    if depth > 0:
        cfg.setdefault("crawler", {})["max_depth"] = depth
    if rate > 0:
        cfg.setdefault("stealth", {})["rate_limit_rps"] = rate
    if no_pdf:
        cfg.setdefault("reporting", {})["format"] = ["markdown"]
    if no_oob:
        cfg.setdefault("oob", {})["prefer_local"] = True
    if wordlist:
        cfg.setdefault("discovery", {})["wordlist"] = str(wordlist)
    cfg.setdefault("reporting", {})["include_walkthrough"] = walkthrough
    if passive:
        cfg.setdefault("recon", {})["passive_only"] = True

    log_path = Path(cfg.get("workspace", {}).get("root", "./workspace")) / "samaritanx.log"
    configure_logging(verbose=verbose, log_file=log_path)

    orch = Orchestrator(
        cfg, target,
        auth_recipe=str(auth) if auth else None,
        second_auth_recipe=str(second_auth) if second_auth else None,
        scope_file=str(scope) if scope else None,
        resume=resume,
    )
    orch.register(ReconAgent())
    orch.register(CrawlerAgent())
    orch.register(DiscoveryAgent())
    orch.register(VulnerabilityAgent())
    orch.register(LogicAgent())
    orch.register(ExploitAgent())
    orch.register(SecretValidatorAgent())
    if not no_screenshots:
        orch.register(ScreenshotAgent())
    orch.register(ReportingAgent())

    if scope:
        console.print(f"[green]scope[/green]: {scope}")
    elif auth or second_auth:
        console.print("[yellow]warning[/yellow]: no --scope file given. Using auto-derived "
                      f"allow-list (*.{orch.root}, {orch.root}). Be careful.")

    try:
        asyncio.run(orch.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted — partial results in workspace/[/yellow]")
        raise typer.Exit(130)
    console.print(f"\n[green]done[/green] — workspace: {orch.workspace}")
    console.print(f"   report     : {orch.workspace / 'reports' / 'report.md'}")
    console.print(f"   pdf        : {orch.workspace / 'reports' / 'report.pdf'}")
    console.print(f"   findings   : {orch.workspace / 'reports' / 'findings.json'}")
    console.print(f"   hackerone  : {orch.workspace / 'reports' / 'hackerone'}")
    console.print(f"   screenshots: {orch.workspace / 'screenshots'}")


@app.command()
def report(
    target: str,
    config: Path = typer.Option(None, "--config", "-c"),
):
    """Re-render reports for an already-scanned target from memory."""
    banner()
    cfg = load_config(config)
    configure_logging(verbose=False)
    orch = Orchestrator(cfg, target, resume=True)
    from core.task_queue import Task

    async def _do():
        await orch._async_setup()
        t = Task(priority=1, seq=0, kind="report", target=orch.target_slug, payload={})
        await ExploitAgent().handle(t, orch.context)
        await ReportingAgent().handle(t, orch.context)
        await orch.http.close()
        if orch.oob:
            await orch.oob.close()

    asyncio.run(_do())
    console.print(f"[green]regenerated[/green] -> {orch.workspace / 'reports' / 'report.md'}")


memory_app = typer.Typer(help="Inspect SamaritanX memory")
app.add_typer(memory_app, name="memory")


@memory_app.command("list")
def memory_list(target: str, config: Path = typer.Option(None, "--config", "-c")):
    """List persisted findings for a target."""
    cfg = load_config(config)
    orch = Orchestrator(cfg, target, resume=True)
    rows = orch.memory.list_findings(orch.target_slug)
    if not rows:
        console.print("[yellow]no findings recorded[/yellow]")
        return
    t = Table(show_lines=False)
    for col in ("id", "severity", "cvss", "category", "title", "url"):
        t.add_column(col)
    for r in rows:
        t.add_row(str(r["id"]), r["severity"], f"{r['cvss']:.1f}",
                  r["category"], (r["title"] or "")[:80], (r["url"] or "")[:60])
    console.print(t)


@memory_app.command("reset")
def memory_reset(target: str, config: Path = typer.Option(None, "--config", "-c")):
    """Wipe scan_state for a target (forces full re-run on next scan)."""
    cfg = load_config(config)
    orch = Orchestrator(cfg, target, resume=True)
    orch.memory.reset_scan_state(orch.target_slug)
    console.print(f"[green]reset[/green] scan state for {orch.target_slug}")


@app.command("self-check")
def self_check():
    """Verify external tools and Python deps SamaritanX integrates with."""
    banner()
    cli_tools = ["subfinder", "amass", "httpx", "nuclei", "ffuf", "sqlmap", "tor"]
    t = Table(title="external tools")
    t.add_column("tool"); t.add_column("status"); t.add_column("path")
    for tool in cli_tools:
        path = shutil.which(tool)
        t.add_row(tool, "[green]ok[/green]" if path else "[red]missing[/red]", path or "-")
    console.print(t)

    py = Table(title="python modules")
    py.add_column("module"); py.add_column("status")
    for mod in ("httpx", "playwright", "rich", "jinja2", "weasyprint", "bs4",
                "tldextract", "cryptography", "dns.resolver"):
        try:
            __import__(mod)
            py.add_row(mod, "[green]ok[/green]")
        except Exception as exc:
            py.add_row(mod, f"[red]missing[/red] ({exc.__class__.__name__})")
    console.print(py)


if __name__ == "__main__":
    app()
