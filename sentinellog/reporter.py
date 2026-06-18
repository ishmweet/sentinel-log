"""
reporter.py — Rich terminal dashboard and file export for SentinelLog.

Three public functions:
  print_report(result)          — full Rich terminal dashboard
  export_csv(result, outdir)    — write alerts to a CSV file
  export_json(result, outdir)   — write alerts to a JSON file

The terminal output is deliberately styled to look like a real SOC tool:
monochrome base with red/yellow/cyan accent on severity, bordered tables,
and a bold ASCII banner.  No gratuitous colour — every colour carries meaning.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from sentinellog.analyzer import AnalysisResult
from sentinellog.utils import (
    SEVERITY_COLORS,
    SEVERITY_ICONS,
    SEVERITY_ORDER,
    Alert,
    truncate,
)

console = Console()

# ── ASCII banner ──────────────────────────────────────────────────────────────

BANNER = r"""
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      ██████╗  ██████╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔═══██╗██╔════╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ██║   ██║██║  ███╗
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██║   ██║██║   ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗╚██████╔╝╚██████╔╝
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝
"""

# ── Severity helpers ──────────────────────────────────────────────────────────

def _severity_badge(level: str) -> Text:
    """Return a Rich Text object with the right colour for *level*."""
    colour = SEVERITY_COLORS.get(level, "white")
    icon   = SEVERITY_ICONS.get(level, "")
    return Text(f"{icon} {level}", style=colour)


def _sort_alerts(alerts: list[Alert]) -> list[Alert]:
    """Return alerts ordered most-severe first."""
    return sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 99))


# ── Main terminal report ──────────────────────────────────────────────────────

def print_report(result: AnalysisResult) -> None:
    """Render the full SOC-style dashboard to the terminal."""
    _print_banner()
    _print_meta(result)
    _print_summary(result)

    if result.log_type == "auth":
        _print_top_ips_auth(result)
    else:
        _print_top_ips_apache(result)
        _print_top_urls(result)
        _print_status_codes(result)

    _print_alerts(result)
    _print_threat_overview(result)


def _print_banner() -> None:
    console.print(Text(BANNER, style="bold red"))
    console.print(
        Panel(
            "[bold white]Security Log Analyzer[/bold white]  ",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()


def _print_meta(result: AnalysisResult) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    console.print(
        f"[dim]Analysis time:[/dim] [white]{now}[/white]   "
        f"[dim]File:[/dim] [white]{result.log_file}[/white]   "
        f"[dim]Type:[/dim] [white]{result.log_type.upper()} LOG[/white]   "
        f"[dim]Records:[/dim] [white]{result.total_lines:,}[/white]"
    )
    console.print(Rule(style="dim"))


def _print_summary(result: AnalysisResult) -> None:
    console.print("\n[bold white]◈  SUMMARY[/bold white]")

    table = Table(box=box.SIMPLE_HEAD, show_edge=False, highlight=True)
    table.add_column("Metric",   style="dim", width=32)
    table.add_column("Value",    style="bold white", justify="right")

    if result.log_type == "auth":
        table.add_row("Total log entries",    f"{result.total_lines:,}")
        table.add_row("Failed login attempts", f"[red]{result.total_failed:,}[/red]")
        table.add_row("Successful logins",    f"[green]{result.total_success:,}[/green]")
        table.add_row("Unique source IPs",    f"{result.unique_ips:,}")
        table.add_row("Alerts triggered",     f"[yellow]{len(result.alerts):,}[/yellow]")
    else:
        total_4xx = sum(
            v for k, v in result.status_code_counts.items() if 400 <= k < 500
        )
        total_5xx = sum(
            v for k, v in result.status_code_counts.items() if 500 <= k < 600
        )
        table.add_row("Total requests",     f"{result.total_lines:,}")
        table.add_row("Unique source IPs",  f"{len(result.top_ips):,}")
        table.add_row("Unique URLs",        f"{len(result.top_urls):,}")
        table.add_row("404 Not Found",      f"[yellow]{result.total_404s:,}[/yellow]")
        table.add_row("4xx client errors",  f"[yellow]{total_4xx:,}[/yellow]")
        table.add_row("5xx server errors",  f"[red]{total_5xx:,}[/red]")
        table.add_row("Alerts triggered",   f"[yellow]{len(result.alerts):,}[/yellow]")

    console.print(table)


def _print_top_ips_auth(result: AnalysisResult) -> None:
    console.print("\n[bold white]◈  TOP SOURCE IPs[/bold white]")
    table = Table(box=box.SIMPLE_HEAD, show_edge=False)
    table.add_column("#",           style="dim",       width=4)
    table.add_column("IP Address",  style="bold white", width=18)
    table.add_column("Total Hits",  justify="right",   width=12)

    for rank, (ip, count) in enumerate(result.top_ips, 1):
        table.add_row(str(rank), ip, str(count))
    console.print(table)


def _print_top_ips_apache(result: AnalysisResult) -> None:
    console.print("\n[bold white]◈  TOP SOURCE IPs[/bold white]")
    table = Table(box=box.SIMPLE_HEAD, show_edge=False)
    table.add_column("#",           style="dim",       width=4)
    table.add_column("IP Address",  style="bold white", width=18)
    table.add_column("Requests",    justify="right",   width=10)

    for rank, (ip, count) in enumerate(result.top_ips, 1):
        table.add_row(str(rank), ip, str(count))
    console.print(table)


def _print_top_urls(result: AnalysisResult) -> None:
    if not result.top_urls:
        return
    console.print("\n[bold white]◈  TOP REQUESTED URLs[/bold white]")
    table = Table(box=box.SIMPLE_HEAD, show_edge=False)
    table.add_column("#",        style="dim",        width=4)
    table.add_column("URL",      style="bold white", width=50)
    table.add_column("Requests", justify="right",    width=10)

    for rank, (url, count) in enumerate(result.top_urls, 1):
        table.add_row(str(rank), truncate(url, 50), str(count))
    console.print(table)


def _print_status_codes(result: AnalysisResult) -> None:
    if not result.status_code_counts:
        return
    console.print("\n[bold white]◈  HTTP STATUS CODE BREAKDOWN[/bold white]")
    table = Table(box=box.SIMPLE_HEAD, show_edge=False)
    table.add_column("Status", style="bold white", width=8)
    table.add_column("Count",  justify="right",    width=10)
    table.add_column("Class",  style="dim",        width=20)

    _class = {
        2: "[green]2xx Success[/green]",
        3: "[cyan]3xx Redirect[/cyan]",
        4: "[yellow]4xx Client Error[/yellow]",
        5: "[red]5xx Server Error[/red]",
    }
    for code, count in sorted(result.status_code_counts.items()):
        label = _class.get(code // 100, "")
        table.add_row(str(code), str(count), label)
    console.print(table)


def _print_alerts(result: AnalysisResult) -> None:
    console.print()
    console.print(Rule("[bold red]  SECURITY ALERTS  [/bold red]", style="red"))
    console.print()

    sorted_alerts = _sort_alerts(result.alerts)

    if not sorted_alerts:
        console.print("  [green]✓  No threats detected.[/green]\n")
        return

    table = Table(
        box=box.ROUNDED,
        show_edge=True,
        border_style="dim red",
        highlight=False,
        expand=True,
    )
    table.add_column("Severity",   width=12)
    table.add_column("Type",       style="bold white", width=26)
    table.add_column("Source IP",  width=16)
    table.add_column("Description")

    for alert in sorted_alerts:
        table.add_row(
            _severity_badge(alert.severity),
            alert.alert_type,
            alert.source_ip,
            truncate(alert.description, 80),
        )
    console.print(table)


def _print_threat_overview(result: AnalysisResult) -> None:
    if not result.alerts:
        return

    console.print("\n[bold white]◈  THREAT OVERVIEW[/bold white]")

    severity_counts: Counter[str] = Counter(a.severity for a in result.alerts)
    type_counts:     Counter[str] = Counter(a.alert_type for a in result.alerts)

    # Build two small tables side-by-side
    sev_table = Table(title="By Severity", box=box.SIMPLE, show_edge=False)
    sev_table.add_column("Level",  width=12)
    sev_table.add_column("Count", justify="right", width=6)
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(level, 0)
        if count:
            sev_table.add_row(_severity_badge(level), str(count))

    type_table = Table(title="By Type", box=box.SIMPLE, show_edge=False)
    type_table.add_column("Alert Type", width=28)
    type_table.add_column("Count", justify="right", width=6)
    for atype, count in type_counts.most_common():
        type_table.add_row(atype, str(count))

    console.print(Columns([sev_table, type_table], padding=(0, 6)))
    console.print()


# ── CSV export ────────────────────────────────────────────────────────────────

def export_csv(result: AnalysisResult, outdir: str | Path = "reports") -> Path:
    """
    Write all alerts to a CSV file under *outdir*.

    Returns the path of the written file.
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    ftype = result.log_type
    out   = outdir / f"sentinellog_{ftype}_{ts}.csv"

    fieldnames = ["timestamp", "alert_type", "severity", "source_ip", "description"]

    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for alert in _sort_alerts(result.alerts):
            writer.writerow(alert.to_dict())

    return out


# ── JSON export ───────────────────────────────────────────────────────────────

def export_json(result: AnalysisResult, outdir: str | Path = "reports") -> Path:
    """
    Write all alerts to a JSON file under *outdir*.

    The file contains a top-level object with metadata and an 'alerts' array.
    Returns the path of the written file.
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    ftype = result.log_type
    out   = outdir / f"sentinellog_{ftype}_{ts}.json"

    payload = {
        "meta": {
            "generated_at": datetime.now().isoformat(),
            "log_file":     result.log_file,
            "log_type":     result.log_type,
            "total_records": result.total_lines,
            "total_alerts":  len(result.alerts),
        },
        "alerts": [a.to_dict() for a in _sort_alerts(result.alerts)],
    }

    with out.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    return out
