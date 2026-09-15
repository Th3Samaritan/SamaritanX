"""CLI entry points for local and mobile assessments."""
import asyncio
import json
from pathlib import Path
import typer
from .common import read_limited, write_report


def _emit(report, output):
    path = write_report(report, output)
    typer.echo(f"{report['status']}: {len(report['candidates'])} candidate(s); {path.resolve()}")
    if report['status'] == 'blocked':
        raise typer.Exit(2)


def register(app):
    @app.command('local-audit')
    def local_audit(snapshot: Path = typer.Option(None, '--snapshot'),
                    collect_local: bool = typer.Option(False, '--collect'),
                    output: Path = typer.Option(Path('workspace/local-assessment'), '--output')):
        """Review a Windows/Linux snapshot or explicitly collect read-only local configuration."""
        from .local_privilege import assess, collect
        if bool(snapshot) == collect_local:
            raise typer.BadParameter('choose --snapshot FILE or --collect')
        data = json.loads(read_limited(snapshot)) if snapshot else collect()
        _emit(assess(data), output)

    @app.command('mobile-static')
    def mobile_static(artifact: Path = typer.Argument(..., exists=True, dir_okay=False),
                      output: Path = typer.Option(Path('workspace/mobile-static'), '--output')):
        """Assess APK or IPA configuration without executing the app."""
        from .mobile_static import assess
        _emit(assess(artifact), output)

    @app.command('mobile-dynamic')
    def mobile_dynamic(platform: str = typer.Option(..., '--platform'),
                       app_id: str = typer.Option(..., '--app-id'),
                       session_id: str = typer.Option(..., '--session-id'),
                       server: str = typer.Option('http://127.0.0.1:4723', '--appium-url'),
                       flow: Path = typer.Option(None, '--flow'),
                       aggressive: bool = typer.Option(False, '--aggressive'),
                       output: Path = typer.Option(Path('workspace/mobile-dynamic'), '--output')):
        """Inspect an existing Android/iOS Appium session; optional UI flows require --aggressive."""
        from .mobile_dynamic import assess
        steps = json.loads(read_limited(flow)).get('steps', []) if flow else []
        _emit(asyncio.run(assess(server, session_id, platform.lower(), app_id,
                               steps=steps, aggressive=aggressive)), output)

    @app.command('mobile-traffic')
    def mobile_traffic(har: Path = typer.Argument(..., exists=True, dir_okay=False),
                       scope_host: list[str] = typer.Option(..., '--scope-host'),
                       output: Path = typer.Option(Path('workspace/mobile-traffic'), '--output')):
        """Review captured HAR traffic and export value-free read-only API seeds."""
        from .mobile_traffic import assess
        from core.tool_installation import _atomic
        report = assess(har, scope_host)
        _emit(report, output)
        _atomic(output / 'api-seeds.json', report['api_seeds'])
