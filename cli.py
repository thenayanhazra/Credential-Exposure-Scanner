"""CLI entry point."""
from __future__ import annotations

import asyncio
import json as jsonlib
import logging
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import DEFAULT_DB_PATH, load_config, scanner_config
from .models import SEVERITY_ORDER, Severity
from .normalize import NormalizeError, normalize
from .runner import Runner
from .scanners.base import Scanner
from .scanners.crtsh import CrtShScanner
from .scanners.dorks import DorkScanner
from .scanners.github_search import GitHubSearchScanner
from .scanners.hibp import HIBPScanner
from .store import Store

app = typer.Typer(
    help="Credential exposure scanner.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def build_scanners(cfg: dict) -> list[Scanner]:
    return [
        CrtShScanner(scanner_config("crtsh", cfg)),
        GitHubSearchScanner(scanner_config("github_search", cfg)),
        DorkScanner(scanner_config("dorks", cfg)),
        HIBPScanner(scanner_config("hibp", cfg)),
    ]


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
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db", help="SQLite DB path."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Scan an email or domain for credential exposures."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        target = normalize(target_input)
    except NormalizeError as e:
        console.print(f"[red]Invalid input:[/red] {e}")
        raise typer.Exit(1) from None

    cfg = load_config()
    store = Store(db)
    scanners = build_scanners(cfg)
    runner = Runner(scanners, store)
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

    result = asyncio.run(runner.run(target))
    findings = result["findings"]

    if output == "json":
        print(
            jsonlib.dumps(
                {
                    "target": result["target"],
                    "scan_id": result["scan_id"],
                    "scanners_run": result["scanners_run"],
                    "findings": [f.model_dump(mode="json") for f in findings],
                },
                indent=2,
                default=str,
            )
        )
        store.close()
        return

    if not findings:
        console.print("[green]No findings.[/green]")
        store.close()
        return

    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
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
    store.close()


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8765, "--port"),
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db"),
) -> None:
    """Start the local web GUI at http://HOST:PORT."""
    import uvicorn

    from .web import create_app

    os.environ["CREDSCAN_DB"] = str(db)
    console.print(f"[cyan]credscan[/cyan] web GUI at http://{host}:{port}")
    uvicorn.run(create_app(), host=host, port=port, log_level="warning")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n"),
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db"),
) -> None:
    """Show recent scan history."""
    store = Store(db)
    scans = store.recent_scans(limit=limit)
    if not scans:
        console.print("[dim]no scans yet[/dim]")
        store.close()
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
    store.close()


if __name__ == "__main__":
    app()
