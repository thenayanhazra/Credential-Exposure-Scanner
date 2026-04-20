"""CLI entry point."""
from __future__ import annotations

import asyncio
import json as jsonlib
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

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


def _db_option() -> Path:
    return default_db_path()


@app.command()
def scan(
    target_input: str = typer.Argument(..., help="Email or domain to scan."),
    output: str = typer.Option("table", "--output", "-o", help="table | json"),
    db: Path | None = typer.Option(None, "--db", help="SQLite DB path."),
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

    db_path = db or default_db_path()
    cfg = load_config()
    scanners = build_scanners(cfg)

    with Store(db_path) as store:
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
    db: Path | None = typer.Option(None, "--db"),
) -> None:
    """Start the local web GUI at http://HOST:PORT."""
    import uvicorn

    from .web import create_app

    db_path = db or default_db_path()
    console.print(f"[cyan]credscan[/cyan] web GUI at http://{host}:{port}")
    uvicorn.run(create_app(db_path=db_path), host=host, port=port, log_level="warning")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n"),
    db: Path | None = typer.Option(None, "--db"),
) -> None:
    """Show recent scan history."""
    db_path = db or default_db_path()
    with Store(db_path) as store:
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


if __name__ == "__main__":
    app()
