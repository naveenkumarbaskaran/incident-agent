"""
CLI entry-point for incident-agent.

Usage examples
--------------
# One-shot analysis
incident-agent analyze --logs /var/log/app.log --since "1 hour ago"

# Multiple log files + extra context
incident-agent analyze \
    --logs /var/log/nginx/error.log \
    --logs /var/log/app.log \
    --since "30 minutes ago" \
    --context "PagerDuty: high error rate on /api/checkout"

# Watch mode (tail and re-analyse every N seconds)
incident-agent watch --logs /var/log/app.log --interval 60
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta
from typing import Optional

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.text import Text

from .agent import IncidentAgent
from .log_parser import LogParser

console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HUMAN_SINCE_RE = {
    r"(\d+)\s*hour": lambda n: timedelta(hours=int(n)),
    r"(\d+)\s*min": lambda n: timedelta(minutes=int(n)),
    r"(\d+)\s*day": lambda n: timedelta(days=int(n)),
    r"(\d+)\s*sec": lambda n: timedelta(seconds=int(n)),
}


def _parse_since(since: str | None) -> Optional[datetime]:
    """Convert a human-readable 'since' string to a datetime."""
    if since is None:
        return None
    import re
    for pattern, factory in _HUMAN_SINCE_RE.items():
        m = re.search(pattern, since, re.IGNORECASE)
        if m:
            return datetime.now() - factory(m.group(1))
    # Try ISO format
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(since, fmt)
        except ValueError:
            pass
    console.print(f"[yellow]Warning:[/yellow] could not parse --since '{since}'; ignoring.")
    return None


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option()
def cli() -> None:
    """incident-agent -- AI-powered on-call incident response."""


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--logs", "-l",
    multiple=True,
    required=True,
    type=click.Path(exists=True),
    help="Path to a log file.  Repeat for multiple files.",
)
@click.option(
    "--since", "-s",
    default=None,
    help="Time window, e.g. '1 hour ago', '30 minutes ago', '2024-01-15 14:00'.",
)
@click.option(
    "--context", "-c",
    default=None,
    help="Extra context (alert body, Slack message, etc.).",
)
@click.option(
    "--model", "-m",
    default="claude-sonnet-4-6",
    show_default=True,
    help="Claude model to use.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Print tool calls as they happen.",
)
@click.option(
    "--no-stream",
    is_flag=True,
    default=False,
    help="Disable live streaming of the final answer.",
)
def analyze(
    logs: tuple[str, ...],
    since: Optional[str],
    context: Optional[str],
    model: str,
    verbose: bool,
    no_stream: bool,
) -> None:
    """Analyse log files and generate an incident report."""
    console.print(Rule("[bold red]Incident Agent[/bold red]"))
    console.print(f"[bold]Logs:[/bold] {', '.join(logs)}")
    if since:
        console.print(f"[bold]Since:[/bold] {since}")
    if context:
        console.print(f"[bold]Context:[/bold] {context}")
    console.print()

    since_dt = _parse_since(since)

    # Show a quick pre-analysis summary from the parser
    if since_dt is not None:
        parser = LogParser()
        console.print("[dim]Pre-scanning logs...[/dim]")
        all_events = []
        for log_path in logs:
            evts = parser.parse_file(log_path, since=since_dt)
            errors = parser.filter_errors(evts)
            all_events.extend(errors)
            console.print(
                f"  {log_path}: [bold]{len(errors)}[/bold] error/warn events"
                f" (of {len(evts)} total)"
            )
        console.print()

    agent = IncidentAgent(model=model, verbose=verbose)

    # Buffer for streamed output when streaming is enabled
    _streamed_chunks: list[str] = []

    def _on_chunk(text: str) -> None:
        _streamed_chunks.append(text)
        console.print(text, end="", markup=False)

    stream_cb = None if no_stream else _on_chunk

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Analysing incident...", total=None)
        if not no_stream:
            progress.stop()  # let the stream print directly

        report = agent.analyze(
            log_paths=list(logs),
            since=since,
            extra_context=context,
            stream_callback=stream_cb,
        )

        if no_stream:
            progress.stop()

    # If we streamed, the output is already on screen; just print the divider.
    # If not, render the full Markdown report.
    if no_stream or not _streamed_chunks:
        console.print()
        console.print(Rule())
        console.print(Markdown(report.raw_response))
    else:
        console.print()
        console.print(Rule())

    # Print tool call summary
    if report.tool_calls:
        console.print(
            f"\n[dim]Tools used: {len(report.tool_calls)} call(s)[/dim]"
        )
        if verbose:
            for tc in report.tool_calls:
                console.print(
                    f"  [dim]* {tc['tool']}({tc['input']})[/dim]"
                )


# ---------------------------------------------------------------------------
# watch command
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--logs", "-l",
    multiple=True,
    required=True,
    type=click.Path(exists=True),
    help="Path to a log file.  Repeat for multiple files.",
)
@click.option(
    "--interval", "-i",
    default=60,
    show_default=True,
    type=int,
    help="Re-analyse every N seconds.",
)
@click.option(
    "--window", "-w",
    default=5,
    show_default=True,
    type=int,
    help="Look-back window in minutes for each analysis run.",
)
@click.option(
    "--model", "-m",
    default="claude-sonnet-4-6",
    show_default=True,
    help="Claude model to use.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Print tool calls as they happen.",
)
def watch(
    logs: tuple[str, ...],
    interval: int,
    window: int,
    model: str,
    verbose: bool,
) -> None:
    """Tail log files and re-analyse every INTERVAL seconds."""
    console.print(Rule("[bold red]Incident Agent -- Watch Mode[/bold red]"))
    console.print(
        f"Monitoring: [bold]{', '.join(logs)}[/bold]\n"
        f"Re-analysing every [bold]{interval}s[/bold] "
        f"(looking back [bold]{window}m[/bold])"
    )
    console.print("Press [bold]Ctrl+C[/bold] to stop.\n")

    agent = IncidentAgent(model=model, verbose=verbose)

    try:
        while True:
            since_str = f"{window} minutes ago"
            console.print(
                Panel(
                    Text(
                        f"Analysis run @ {datetime.now().strftime('%H:%M:%S')}"
                        f"  (window: last {window}m)",
                        style="bold cyan",
                    ),
                    expand=False,
                )
            )

            try:
                report = agent.analyze(
                    log_paths=list(logs),
                    since=since_str,
                )
                console.print(Markdown(report.raw_response))
            except Exception as exc:  # noqa: BLE001
                console.print(f"[red]Analysis failed:[/red] {exc}")

            console.print(
                f"[dim]Next run in {interval}s -- Ctrl+C to quit[/dim]"
            )
            time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[bold]Exiting watch mode.[/bold]")
        sys.exit(0)


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
