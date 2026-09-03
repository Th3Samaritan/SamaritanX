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
import os
import shutil
import sys
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.config_validator import validate_config  # noqa: E402
from core.logger import configure_logging  # noqa: E402
from core.orchestrator import Orchestrator  # noqa: E402

from agents.recon_agent import ReconAgent  # noqa: E402
from agents.crawler_agent import CrawlerAgent  # noqa: E402
from agents.discovery_agent import DiscoveryAgent  # noqa: E402
from agents.vuln_agent import VulnerabilityAgent  # noqa: E402
from agents.logic_agent import LogicAgent  # noqa: E402
from agents.authz_agent import AuthzAgent  # noqa: E402
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


def _parse_sessions(specs: list[str] | None) -> list[tuple[str, str, int]]:
    """Parse repeated --session 'label=recipe.yaml[:rank]' into (label, path, rank).

    Rank defaults to 1; a label containing admin/staff/super/root infers rank 2
    so an admin recipe lifts the privilege ceiling without extra syntax.
    """
    out: list[tuple[str, str, int]] = []
    for spec in specs or []:
        if "=" not in spec:
            console.print(f"[yellow]ignoring --session '{spec}'[/yellow] (expected label=path)")
            continue
        label, rest = spec.split("=", 1)
        label = label.strip()
        rank = None
        if ":" in rest and not Path(rest).exists():
            rest, rank_s = rest.rsplit(":", 1)
            try:
                rank = int(rank_s)
            except ValueError:
                rank = None
        path = rest.strip()
        if rank is None:
            rank = 2 if any(k in label.lower() for k in ("admin", "staff", "super", "root")) else 1
        out.append((label, path, rank))
    return out


def banner() -> None:
    console.print("[bold magenta]SamaritanX[/bold magenta] — agentic bug bounty framework  "
                  "[dim](operator: th3Samaritan)[/dim]")


def run_scan(target: str, *, config: Path | None = None, scope: Path | None = None,
             only: str = "", deadline: float = 0.0, no_pdf: bool = True,
             no_screenshots: bool = True, no_oob: bool = True) -> None:
    """Programmatic entry point used by bench.runner and embedders.

    Runs the full agent pipeline synchronously and writes the workspace."""
    cfg = load_config(config)
    if only:
        cfg.setdefault("scanners", {})["enabled"] = [s.strip() for s in only.split(",") if s.strip()]
    if no_pdf:
        cfg.setdefault("reporting", {})["format"] = ["markdown"]
    if no_oob:
        cfg.setdefault("oob", {})["prefer_local"] = True
    log_path = Path(cfg.get("workspace", {}).get("root", "./workspace")) / "samaritanx.log"
    configure_logging(verbose=False, log_file=log_path)
    orch = Orchestrator(
        cfg, target,
        scope_file=str(scope) if scope else None,
        deadline=deadline,
    )
    orch.register(ReconAgent())
    orch.register(CrawlerAgent())
    orch.register(DiscoveryAgent())
    orch.register(VulnerabilityAgent())
    orch.register(LogicAgent())
    orch.register(AuthzAgent())
    orch.register(ExploitAgent())
    orch.register(SecretValidatorAgent())
    if not no_screenshots:
        orch.register(ScreenshotAgent())
    orch.register(ReportingAgent())
    asyncio.run(orch.run())


def _build_orchestrator(cfg: dict, target: str, *, auth, second_auth, extra_sessions,
                        scope_file, resume, deadline, task_timeout,
                        quiet=False, screenshots=True) -> Orchestrator:
    orch = Orchestrator(
        cfg, target,
        auth_recipe=str(auth) if auth else None,
        second_auth_recipe=str(second_auth) if second_auth else None,
        extra_sessions=extra_sessions,
        scope_file=str(scope_file) if scope_file else None,
        resume=resume,
        deadline=deadline,
        task_timeout=task_timeout,
        quiet=quiet,
    )
    orch.register(ReconAgent())
    orch.register(CrawlerAgent())
    orch.register(DiscoveryAgent())
    orch.register(VulnerabilityAgent())
    orch.register(LogicAgent())
    orch.register(AuthzAgent())
    orch.register(ExploitAgent())
    orch.register(SecretValidatorAgent())
    if screenshots:
        orch.register(ScreenshotAgent())
    orch.register(ReportingAgent())
    return orch


def _run_one(cfg: dict, target: str, *, auth, second_auth, extra_sessions, scope_file,
             resume, deadline, task_timeout, no_screenshots, quiet=False) -> None:
    orch = _build_orchestrator(cfg, target, auth=auth, second_auth=second_auth,
                               extra_sessions=extra_sessions, scope_file=scope_file,
                               resume=resume, deadline=deadline,
                               task_timeout=task_timeout, quiet=quiet,
                               screenshots=not no_screenshots)
    asyncio.run(orch.run())
    if quiet:
        n = len(orch.memory.list_findings(orch.target_slug))
        console.print(f"[green]{target}[/green]: {n} finding(s) -> {orch.workspace / 'reports' / 'report.md'}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="domain, host, or URL — e.g. example.com or https://api.example.com"),
    config: Path = typer.Option(None, "--config", "-c", help="override config.yaml path"),
    auth: Path = typer.Option(None, "--auth", help="auth recipe (static / form / bearer_json) — see config/auth.example.yaml"),
    second_auth: Path = typer.Option(None, "--second-session", help="second auth recipe for IDOR/BOLA cross-tenant tests"),
    session: list[str] = typer.Option(None, "--session", help="extra labeled identity for the authz matrix: 'label=recipe.yaml' (optional ':rank', higher=more privileged, e.g. 'admin=admin.yaml:2'). Repeatable — add an admin row for airtight BFLA."),
    scope: Path = typer.Option(None, "--scope", help="scope file (allow/deny rules) — see config/scope.example.txt"),
    program: str = typer.Option(None, "--program", help="platform program handle — fetches live scope and scans every in-scope root (e.g. --program acme)"),
    program_platform: str = typer.Option("hackerone", "--program-platform", help="platform for --program (hackerone)"),
    parallel: int = typer.Option(1, "--parallel", help="how many in-scope roots to scan concurrently with --program (1 = sequential)"),
    resume: bool = typer.Option(False, "--resume", help="reuse memory state from a prior run (skip already-completed phases)"),
    deadline: float = typer.Option(0.0, "--deadline", help="max scan duration in seconds (0 = no limit). Kills the run gracefully when exceeded"),
    task_timeout: float = typer.Option(60.0, "--task-timeout", help="max seconds a single agent task may run before being cancelled"),
    wordlist: Path = typer.Option(None, "--wordlist", help="custom wordlist for content discovery"),
    tor: bool = typer.Option(False, "--tor", help="route all traffic via Tor (socks5://127.0.0.1:9050)"),
    proxy: str = typer.Option("", "--proxy", help="HTTP/SOCKS proxy URL (overrides config)"),
    header: list[str] = typer.Option(None, "--header", "-H", help="extra header sent on every request: 'Name: value' (repeatable; overrides config default_headers)"),
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
    aggressive: bool = typer.Option(False, "--aggressive", help="enable DESTRUCTIVE checks: auth rate-limit probe (account lockout), 25x race-condition POSTs, pricing-tamper form submits. Authorized targets only."),
    monitor: bool = typer.Option(False, "--monitor", help="baseline the attack surface and diff against the previous run — reports new subdomains/endpoints/params (use with cron / --resume for continuous monitoring)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Run the full agentic pipeline against a target."""
    banner()
    cfg = load_config(config)

    # validate config schema before spinning up the pipeline
    cfg_issues = validate_config(cfg)
    if cfg_issues:
        console.print("[yellow]config warnings:[/yellow]")
        for msg in cfg_issues:
            console.print(f"  [dim]- {msg}[/dim]")

    # CLI overrides
    if tor:
        cfg.setdefault("proxy", {})["tor"] = True
        cfg["proxy"]["enabled"] = True
    if proxy:
        # comma-separated = rotation pool; single = fixed proxy
        pool = [p.strip() for p in proxy.split(",") if p.strip()]
        cfg.setdefault("proxy", {})["enabled"] = True
        if len(pool) > 1:
            cfg["proxy"]["rotation"] = pool
            console.print(f"[green]proxy rotation[/green]: {len(pool)} endpoints")
        else:
            cfg["proxy"]["url"] = pool[0]
    if header:
        hdrs: dict[str, str] = {}
        for h in header:
            if ":" not in h:
                console.print(f"[yellow]ignoring --header '{h}'[/yellow] (expected 'Name: value')")
                continue
            name, _, value = h.partition(":")
            hdrs[name.strip()] = value.strip()
        if hdrs:
            cfg.setdefault("http", {}).setdefault("default_headers", {}).update(hdrs)
            console.print("[green]headers[/green]: " + ", ".join(sorted(hdrs)))
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
        # --rate controls the overall request cadence — the per-host bucket
        # must scale with it or every scanner still crawls at the config's
        # default per-host rps and times out mid-sweep
        cfg.setdefault("stealth", {})["rate_limit_rps"] = rate
        cfg["stealth"]["per_host_rps"] = rate
    if no_pdf:
        cfg.setdefault("reporting", {})["format"] = ["markdown"]
    if no_oob:
        cfg.setdefault("oob", {})["prefer_local"] = True
    if wordlist:
        cfg.setdefault("discovery", {})["wordlist"] = str(wordlist)
    cfg.setdefault("reporting", {})["include_walkthrough"] = walkthrough
    if passive:
        cfg.setdefault("recon", {})["passive_only"] = True
    if aggressive:
        cfg.setdefault("safety", {})["aggressive"] = True
    if monitor:
        cfg.setdefault("monitor", {})["enabled"] = True

    log_path = Path(cfg.get("workspace", {}).get("root", "./workspace")) / "samaritanx.log"
    configure_logging(verbose=verbose, log_file=log_path)

    extra_sessions = _parse_sessions(session)
    if extra_sessions:
        console.print("[green]identities[/green]: " +
                      ", ".join(f"{lbl}(rank {rank})" for lbl, _, rank in extra_sessions))

    # --program: fetch the platform scope, derive every in-scope root, and
    # run the full pipeline against each (optionally in parallel)
    if program:
        import os as _os
        from core.scope_import import fetch_program_scope, to_rules, extract_roots
        api_token = _os.environ.get("H1_API_TOKEN", "")
        console.print(f"[dim]fetching {program_platform} program '{program}'…[/dim]")
        try:
            text, label = asyncio.run(fetch_program_scope(program, platform=program_platform,
                                                          api_token=api_token))
        except Exception as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1)
        rules = to_rules(text)
        roots = extract_roots(rules)
        if not roots:
            console.print("[red]no scannable roots derived from program scope[/red]")
            raise typer.Exit(1)
        scope_out = Path(cfg.get("workspace", {}).get("root", "./workspace")) / \
            f"scope.{program}.txt"
        scope_out.parent.mkdir(parents=True, exist_ok=True)
        scope_out.write_text("\n".join(rules) + "\n", encoding="utf-8")
        console.print(f"[green]{label}[/green] -> {len(roots)} in-scope root(s): {', '.join(roots[:12])}")
        console.print(f"scope rules: {scope_out}")

        async def _program_run():
            sem = asyncio.Semaphore(max(1, int(parallel)))
            async def one(root: str) -> None:
                async with sem:
                    await asyncio.to_thread(
                        _run_one, cfg, root, auth=auth, second_auth=second_auth,
                        extra_sessions=extra_sessions, scope_file=str(scope_out),
                        resume=resume, deadline=deadline, task_timeout=task_timeout,
                        no_screenshots=no_screenshots, quiet=True)
            await asyncio.gather(*(one(r) for r in roots))
        try:
            asyncio.run(_program_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]interrupted — partial results in workspace/[/yellow]")
            raise typer.Exit(130)
        console.print(f"\n[green]program scan complete[/green] — {len(roots)} root(s), "
                      f"workspace: {cfg.get('workspace', {}).get('root', './workspace')}")
        return

    orch = _build_orchestrator(cfg, target, auth=auth, second_auth=second_auth,
                               extra_sessions=extra_sessions, scope_file=scope,
                               resume=resume, deadline=deadline,
                               task_timeout=task_timeout,
                               screenshots=not no_screenshots)

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


@app.command("diff")
def diff_cmd(
    target: str,
    config: Path = typer.Option(None, "--config", "-c"),
):
    """Show the change-set between the two most recent monitor snapshots."""
    banner()
    import json as _json
    from core.monitor import diff as _diff
    from core.utils import slugify
    cfg = load_config(config)
    ws = Path(cfg.get("workspace", {}).get("root", "./workspace")) / slugify(target) / "monitor"
    snaps = sorted(ws.glob("snap_*.json"),
                   key=lambda p: int(p.stem.split("_", 1)[1]), reverse=True)
    if len(snaps) < 2:
        console.print("[yellow]need two monitor snapshots[/yellow] — run with --monitor twice")
        raise typer.Exit(1)
    new = _json.loads(snaps[0].read_text(encoding="utf-8"))
    old = _json.loads(snaps[1].read_text(encoding="utf-8"))
    delta = _diff(old, new)

    console.print(f"[bold]monitor diff[/bold]  {snaps[1].name} -> {snaps[0].name}\n")
    for section, icon in (("hosts", "+"), ("endpoints", "+"), ("params", "+"), ("findings", "!")):
        added, removed = delta[section]["added"], delta[section]["removed"]
        if not added and not removed:
            console.print(f"[dim]{section}: no change[/dim]")
            continue
        if added:
            console.print(f"[green]{icon}{len(added)} {section} added[/green]")
            for a in added[:12]:
                console.print(f"    {a[:120]}")
        if removed:
            console.print(f"[red]-{len(removed)} {section} removed[/red]")
            for r in removed[:12]:
                console.print(f"    {r[:120]}")
    counts = delta.get("findings", {}).get("counts", {})
    console.print(f"\nseverity counts: {counts.get('old', {})} -> {counts.get('new', {})}")


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


@app.command("scope-import")
def scope_import(
    source: str = typer.Argument(None, help="path or URL of a platform scope export (HackerOne structured_scopes JSON, Bugcrowd CSV/JSON, Intigriti JSON, Chaos JSON) — omit when using --program"),
    program: str = typer.Option(None, "--program", help="fetch scope live from a platform program handle (e.g. --program acme --platform hackerone)"),
    platform: str = typer.Option("hackerone", "--platform", help="hackerone (default)"),
    output: Path = typer.Option(None, "--output", "-o", help="where to write the generated scope file (default: config/scope.imported.txt)"),
):
    """Convert a bug-bounty platform scope export into a SamaritanX scope file.

    The output is accepted directly by ``scan --scope``. Auto-detects the
    platform shape, maps eligible/ineligible flags to allow/deny rules, and
    converts URLs, wildcards, IPs and CIDRs into the native rule grammar."""
    banner()
    from core.scope_import import to_rules, fetch_program_scope

    if program:
        import asyncio
        api_token = os.environ.get("H1_API_TOKEN", "")
        console.print(f"[dim]fetching {platform} program '{program}'…[/dim]")
        try:
            text, label = asyncio.run(fetch_program_scope(program, platform=platform,
                                                          api_token=api_token))
        except Exception as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1)
        console.print(f"[dim]source: {label}[/dim]")
    else:
        if not source:
            console.print("[red]provide a source file/URL or --program <handle>[/red]")
            raise typer.Exit(1)
        if source.startswith(("http://", "https://")):
            import urllib.request
            console.print(f"[dim]fetching {source}[/dim]")
            try:
                with urllib.request.urlopen(source, timeout=30) as resp:
                    text = resp.read().decode("utf-8", "replace")
            except Exception as exc:
                console.print(f"[red]fetch failed:[/red] {exc}")
                raise typer.Exit(1)
        else:
            p = Path(source)
            if not p.exists():
                console.print(f"[red]not found:[/red] {source}")
                raise typer.Exit(1)
            text = p.read_text(encoding="utf-8", errors="replace")

    rules = to_rules(text)
    if not rules:
        console.print("[yellow]no scope assets could be extracted[/yellow]")
        raise typer.Exit(1)
    out = output or (Path(__file__).resolve().parent / "config" / "scope.imported.txt")
    out.write_text("\n".join(rules) + "\n", encoding="utf-8")
    console.print(f"[green]{len(rules)} rule(s)[/green] written to {out}")
    console.print("usage: python samaritanx.py scan <target> --scope " + str(out))


@app.command("retest")
def retest(
    target: str,
    finding_id: int = typer.Argument(..., help="finding id (see: memory list <target>)"),
    config: Path = typer.Option(None, "--config", "-c"),
):
    """Re-fire one recorded finding fresh and report whether it reproduces.

    Runs the same per-category reproduce check the pipeline uses before
    reporting, updates the finding's confidence/metadata, and prints the
    outcome plus the captured proof."""
    banner()
    cfg = load_config(config)
    configure_logging(verbose=False)
    orch = Orchestrator(cfg, target, resume=True)

    async def _do():
        await orch._async_setup()
        findings = orch.memory.list_findings(orch.target_slug)
        f = next((x for x in findings if x["id"] == finding_id), None)
        if not f:
            console.print(f"[red]finding {finding_id} not found for {orch.target_slug}[/red]")
            return
        from core.revalidate import revalidate
        summary = await revalidate(orch.context, [f])
        updated = orch.memory.list_findings(orch.target_slug)
        f2 = next((x for x in updated if x["id"] == finding_id), f)
        meta = f2.get("metadata") or {}
        res = summary["details"][0]["result"]
        color = {"reproduced": "green", "dropped": "red"}.get(res, "yellow")
        console.print(f"\n[{color}]{res}[/{color}]  {f2['title']}")
        console.print(f"  confidence: {f2['confidence']} "
                      f"({summary['details'][0]['confidence_label']})")
        poc = meta.get("poc")
        if isinstance(poc, dict):
            console.print(f"  request : {str(poc.get('request'))[:220]}")
            if poc.get("response_excerpt"):
                console.print(f"  response: {str(poc['response_excerpt'])[:400]}")
        else:
            console.print("  [dim]no captured proof record[/dim]")
        await orch.http.close()
        if orch.oob:
            try:
                await orch.oob.close()
            except Exception:
                pass

    asyncio.run(_do())


@app.command("triage")
def triage(
    target: str,
    config: Path = typer.Option(None, "--config", "-c"),
    include_verified: bool = typer.Option(False, "--all",
        help="also triage verified findings (default: unproven candidates only)"),
):
    """Interactive triage of unproven candidates (interactive terminal loop).

    Walk every quarantined candidate: [a]ccept, [r]eject, [d]uplicate,
    [s]kip-forever. Decisions persist to memory and to reports/triage.json."""
    banner()
    cfg = load_config(config)
    orch = Orchestrator(cfg, target, resume=True)
    rows = orch.memory.list_findings(orch.target_slug)
    from core.proof_gate import poc_status
    pool = []
    for f in rows:
        status, reason = poc_status(f)
        if include_verified or status != "verified":
            meta = f.get("metadata") or {}
            if meta.get("triage"):
                continue
            pool.append((f, reason))
    if not pool:
        console.print("[green]nothing to triage[/green]")
        return

    i = 0
    while i < len(pool):
        f, reason = pool[i]
        console.print(f"\n[bold]{i + 1}/{len(pool)}[/bold]  "
                      f"[magenta]{str(f.get('severity', 'info')).upper()}[/magenta]  {f['title']}")
        console.print(f"  url     : {f.get('url')}")
        console.print(f"  gate    : {reason}")
        console.print(f"  evidence: {(f.get('evidence') or '')[:280]}")
        cmd = console.input("[a]ccept [r]eject [d]uplicate [s]kip  [q]uit / Enter=next: ").strip().lower()
        if cmd in ("", "n", "next"):
            i += 1
            continue
        if cmd == "q":
            break
        decision = {"a": ("accepted", 0.9), "r": ("rejected", 0.05),
                    "d": ("duplicate", 0.1), "s": ("skipped", None)}
        if cmd not in decision:
            console.print("[dim]unknown key[/dim]")
            continue
        label, conf = decision[cmd]
        meta = dict(f.get("metadata") or {})
        meta["triage"] = label
        updates = {"metadata": meta}
        if conf is not None:
            updates["confidence"] = conf
        orch.memory.update_finding(f["id"], **updates)
        console.print(f"[green]{label}[/green]  {f['title'][:80]}")
        i += 1

    out = orch.workspace / "reports" / "triage.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    import json as _json
    decided = [{"id": f["id"], "category": f.get("category"), "title": f.get("title"),
                "severity": f.get("severity"), "triage": (f.get("metadata") or {}).get("triage")}
               for f in orch.memory.list_findings(orch.target_slug)
               if (f.get("metadata") or {}).get("triage")]
    out.write_text(_json.dumps(decided, indent=2), encoding="utf-8")
    console.print(f"[green]{len(decided)} triage decision(s)[/green] -> {out}")


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
    # Windows console/pipes default to cp1252 — em-dashes, arrows and other
    # Unicode in evidence text would crash printing. Force UTF-8 output.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    app()
