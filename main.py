"""
main.py — Command-line entry point for SentinelLog.

Usage
-----
  python main.py --file logs/sample_auth.log
  python main.py --file logs/sample_apache.log
  python main.py --file logs/sample_auth.log  --export csv
  python main.py --file logs/sample_apache.log --export json
  python main.py --file logs/sample_auth.log  --export csv --output my_reports/
  python main.py --file logs/sample_auth.log  --no-banner
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from sentinellog.analyzer import LogAnalyzer
from sentinellog.reporter import export_csv, export_json, print_report

console = Console(stderr=True)


# ── CLI definition ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinellog",
        description=(
            "SentinelLog — Security Log Analyzer\n"
            "Analyze auth/Apache logs, detect threats, and generate reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --file logs/sample_auth.log
  python main.py --file logs/sample_apache.log
  python main.py --file logs/sample_auth.log  --export csv
  python main.py --file logs/sample_apache.log --export json --output reports/
        """,
    )

    p.add_argument(
        "--file", "-f",
        required=True,
        metavar="PATH",
        help="Path to the log file to analyze.",
    )
    p.add_argument(
        "--export", "-e",
        choices=["csv", "json"],
        default=None,
        metavar="FORMAT",
        help="Export alerts to csv or json (optional).",
    )
    p.add_argument(
        "--output", "-o",
        default="reports",
        metavar="DIR",
        help="Directory for exported reports (default: reports/).",
    )
    p.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip the ASCII banner (useful for piping output).",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress terminal report; only write the export file.",
    )

    return p


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    args = build_parser().parse_args()

    log_path = Path(args.file)

    # ── Validate file ─────────────────────────────────────────────────────────
    if not log_path.exists():
        console.print(f"[red]Error:[/red] File not found: {log_path}")
        return 1

    if not log_path.is_file():
        console.print(f"[red]Error:[/red] Not a file: {log_path}")
        return 1

    # ── Run analysis ──────────────────────────────────────────────────────────
    try:
        analyzer = LogAnalyzer()
        result   = analyzer.analyze(log_path)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 1
    except Exception as exc:
        console.print(f"[red]Unexpected error:[/red] {exc}")
        return 1

    # ── Terminal report ───────────────────────────────────────────────────────
    if not args.quiet:
        if args.no_banner:
            # Monkey-patch: hide the banner by replacing it temporarily
            import sentinellog.reporter as _rep
            _orig = _rep.BANNER
            _rep.BANNER = ""
            print_report(result)
            _rep.BANNER = _orig
        else:
            print_report(result)

    # ── Export ────────────────────────────────────────────────────────────────
    if args.export:
        outdir = Path(args.output)
        try:
            if args.export == "csv":
                out = export_csv(result, outdir)
            else:
                out = export_json(result, outdir)

            console.print(
                f"\n[green]✓[/green] Report exported → [bold white]{out}[/bold white]"
            )
        except OSError as exc:
            console.print(f"[red]Export failed:[/red] {exc}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
