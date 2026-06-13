\"\"\"CLI entry point.\"\"\"
from __future__ import annotations

import asyncio
import json as jsonlib
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from typing import Optional

from .config import default_db_path, load_config
from .models import Severity
from .normalize import NormalizeError, normalize
from .runner import Runner
from .scanners.registry import build_scanners
from .store import Store

app = typer.Typer(
    help="Credential exposure scanner.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

SEV_COLORS = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}


@app.command()
def scan(
    target_input: str = typer.Argument(..., help="Email or domain to scan."),
    output: str = typer.Option("table", "--output", "-o", help="table | json"),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite DB path."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    \"\"\"Scan an email or domain for credential exposures.\"\"\"
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        target = normalize(target_input)
    except NormalizeError as e:
        console.print(f"[red]Invalid input:[/red] {e}")
        raise typer.Exit(1) from None

    db_path = db or default_db_path()
    cfg = load_config()
    app_cfg = cfg.get("app", {})
    concurrency = app_cfg.get("concurrency", 5)
    scanner_timeout = app_cfg.get("scanner_timeout", 120)
    scanners = build_scanners(cfg)

    with Store(db_path) as store:
        runner = Runner(scanners, store, concurrency=concurrency, scanner_timeout=scanner_timeout)
        applicable = [s.name for s in runner.applicable(target)]

        if output != "json":
            console.print(
                f"[bold cyan]Scanning[/bold cyan] {target.value}  "
                f"[dim](scanners: {', '.join(applicable) or 'none'})[/dim]"
            )
            disabled = [s.name for s in scanners if s.requires_auth and not s.enabled()]
            if disabled:
                console.print(
                    f"[dim]Skipping (no credentials configured): "
                    f"{', '.join(disabled)}[/dim]"
                )

        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(runner.run(target))
        finally:
            loop.close()

    if output == "json":
        # Plain stdout write — Rich's console.print_json would reformat and
        # mangle piping. jsonlib.dumps keeps output machine-readable.
        print(jsonlib.dumps(result.to_public_dict(), indent=2, default=str))
        return

    findings = result.findings
    if not findings:
        console.print("[green]No findings.[/green]")
        return

    findings.sort(key=lambda f: f.severity.rank)
    table = Table(title=f"Findings for {target.value}")
    table.add_column("Severity", style="bold")
    table.add_column("Source")
    table.add_column("Type")
    table.add_column("Title", overflow="fold")
    table.add_column("Evidence", overflow="fold")

    for f in findings:
        color = SEV_COLORS.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.source,
            f.kind,
            f.title,
            f.evidence_url or "",
        )
    console.print(table)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8765, "--port"),
    db: Optional[Path] = typer.Option(None, "--db"),
) -> None:
    \"\"\"Start the local web GUI at http://HOST:PORT.\"\"\"
    import uvicorn

    from .web import create_app

    db_path = db or default_db_path()
    console.print(f"[cyan]credscan[/cyan] web GUI at http://{host}:{port}")
    uvicorn.run(create_app(db_path=db_path), host=host, port=port, log_level="warning")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n"),
    db: Optional[Path] = typer.Option(None, "--db"),
    scan_id: Optional[int] = typer.Option(None, "--scan-id", help="Show detailed telemetry for a specific scan ID."),
) -> None:
    \"\"\"Show recent scan history or details of a specific scan.\"\"\"
    db_path = db or default_db_path()
    with Store(db_path) as store:
        if scan_id is not None:
            telemetry = store.get_scan_telemetry(scan_id)
            if not telemetry:
                console.print(f"[red]No telemetry found for Scan ID {scan_id}[/red]")
                return
            table = Table(title=f"Telemetry for Scan ID {scan_id}")
            table.add_column("Scanner")
            table.add_column("Started")
            table.add_column("Finished")
            table.add_column("Status")
            table.add_column("Findings")
            table.add_column("Error", overflow="fold")
            for t in telemetry:
                table.add_row(
                    t["scanner"],
                    t["started_at"],
                    t["finished_at"] or "running",
                    t["status"],
                    str(t["finding_count"]),
                    t["error"] or "",
                )
            console.print(table)
            return

        scans = store.recent_scans(limit=limit)

    if not scans:
        console.print("[dim]no scans yet[/dim]")
        return

    table = Table(title="Recent scans")
    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Started")
    table.add_column("Status")
    table.add_column("Findings")
    for s in scans:
        table.add_row(
            str(s["id"]),
            s["target"],
            s["started_at"],
            s["status"],
            str(s["finding_count"]),
        )
    console.print(table)


@app.command()
def doctor(
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config file.")
) -> None:
    \"\"\"Validate configuration and check connectivity to external APIs.\"\"\"
    import os
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib
    import httpx
    from .config import default_config_path, ConfigModel

    p = config_path or default_config_path()
    console.print(f"Loading configuration from: [bold]{p}[/bold]")
    if not p.exists():
        console.print("[yellow]Warning:[/yellow] Configuration file does not exist. Using defaults.")
        raw = {}
    else:
        try:
            with open(p, "rb") as f:
                raw = tomllib.load(f)
        except Exception as e:
            console.print(f"[red]Error parsing TOML config file:[/red] {e}")
            raise typer.Exit(1)

    try:
        validated = ConfigModel.model_validate(raw)
        console.print("[green]✓ Configuration is structurally valid.[/green]")
    except Exception as e:
        console.print(f"[red]Configuration validation failed:[/red]\n{e}")
        raise typer.Exit(1)

    # Verify APIs
    scanners = validated.scanners

    # GitHub API verification
    github_token = scanners.github_search.token or os.environ.get("GITHUB_TOKEN")
    if github_token:
        console.print("Checking GitHub Token...")
        try:
            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {github_token}",
                "User-Agent": "credscan-doctor",
            }
            resp = httpx.get("https://api.github.com/user", headers=headers, timeout=10.0)
            if resp.status_code == 200:
                user = resp.json().get("login", "unknown")
                console.print(f"[green]✓ GitHub Token is valid (authenticated as {user}).[/green]")
            else:
                console.print(f"[red]✗ GitHub Token check failed (HTTP {resp.status_code}):[/red] {resp.text}")
        except Exception as e:
            console.print(f"[red]✗ GitHub API request failed:[/red] {e}")
    else:
        console.print("[dim]GitHub Token not configured. Scanners using GitHub search will be skipped.[/dim]")

    # HIBP check
    hibp_key = scanners.hibp.api_key
    if hibp_key:
        console.print("Checking Have I Been Pwned API Key...")
        try:
            headers = {
                "hibp-api-key": hibp_key,
                "User-Agent": "credscan-doctor",
            }
            resp = httpx.get("https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com", headers=headers, timeout=10.0)
            if resp.status_code in (200, 404):
                console.print("[green]✓ Have I Been Pwned API Key is valid.[/green]")
            else:
                console.print(f"[red]✗ Have I Been Pwned API Key check failed (HTTP {resp.status_code}):[/red] {resp.text}")
        except Exception as e:
            console.print(f"[red]✗ Have I Been Pwned API request failed:[/red] {e}")
    else:
        console.print("[dim]Have I Been Pwned API Key not configured. HIBP scanner will be skipped.[/dim]")


if __name__ == "__main__":
    app()
