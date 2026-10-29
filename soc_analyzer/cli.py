"""Command-line interface: reads args, runs the pipeline, prints a summary.

Pipeline:  parse_file -> detect -> build_summary -> render_report -> write_report

Exit codes:  0 = analysis finished (alerts do NOT make the exit code non-zero)
             1 = problem with input/output (missing file, wrong format, ...)
             2 = invalid command-line arguments (handled by argparse)
"""

import argparse
import os
import sys
from datetime import datetime
from typing import List, Optional

from . import __version__
from .detector import build_summary, detect
from .models import AnalysisConfig
from .parser import LogFileError, parse_file
from .reporter import render_report, write_report

DEFAULT_OUTPUT = os.path.join("output", "triage_report.md")


def _int_in_range(low: int, high: int, name: str):
    """Build an argparse 'type' that accepts integers from low to high."""
    def check(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{name} must be a whole number, got '{text}'")
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"{name} must be between {low} and {high}, got {value}")
        return value
    return check


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc_analyzer",
        description="Analyze SSH authentication logs and create a Markdown triage report. "
                    "Alerts are investigation leads, not proof of an attack.",
    )
    parser.add_argument("logfile", help="path to an OpenSSH syslog-style auth log")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help=f"report file to write (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-t", "--threshold", type=_int_in_range(2, 10000, "threshold"), default=5,
                        help="failed logins needed to raise an alert (default: 5)")
    parser.add_argument("-w", "--window", type=_int_in_range(1, 1440, "window"), default=5,
                        help="time window in minutes for the rules (default: 5)")
    parser.add_argument("-y", "--year", type=_int_in_range(1970, 2100, "year"),
                        default=datetime.now().year,
                        help="year of the log (syslog has none; default: current year)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _use_color() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = AnalysisConfig(threshold=args.threshold, window_minutes=args.window, year=args.year)

    try:
        result = parse_file(args.logfile, config.year)
    except LogFileError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if result.total_lines == 0:
        print(f"error: the log file is empty: {args.logfile}", file=sys.stderr)
        return 1
    if not result.events:
        print("error: no SSH login events found. Expected OpenSSH syslog lines such as\n"
              "  'Oct 12 02:14:03 web01 sshd[4121]: Failed password for root from "
              "203.0.113.45 port 40122 ssh2'", file=sys.stderr)
        return 1

    alerts = detect(result.events, config)
    summary = build_summary(result)
    report = render_report(summary, alerts, config,
                           source_name=os.path.basename(args.logfile),
                           generated_at=datetime.now())

    try:
        write_report(report, args.output)
    except OSError as error:
        print(f"error: could not write report to {args.output}: {error.strerror or error}",
              file=sys.stderr)
        return 1

    _print_summary(args, config, summary, alerts)
    return 0


def _print_summary(args, config, summary, alerts) -> None:
    color = _use_color()
    high = sum(1 for a in alerts if a.severity == "HIGH")
    medium = len(alerts) - high
    print(_paint(f"Mini SOC Log Analyzer v{__version__}", "1;36", color))
    print("-" * 64)
    print(f"Input        : {os.path.basename(args.logfile)}")
    print(f"Lines read   : {summary.total_lines}  (events: {summary.total_events}, "
          f"skipped: {summary.skipped_lines})")
    print(f"Logins       : {summary.failed_count} failed, {summary.accepted_count} successful, "
          f"{summary.unique_source_ips} unique IPs")
    print(f"Rule         : >= {config.threshold} failed logins within {config.window_minutes} min")
    print(f"Alerts       : {len(alerts)}  (HIGH {high}, MEDIUM {medium})")
    if alerts:
        print()
        print(f"  {'ID':<10}{'SEVERITY':<10}{'RULE':<24}{'SOURCE IP':<18}{'COUNT':>5}")
        for number, alert in enumerate(alerts, start=1):
            sev = _paint(f"{alert.severity:<10}", "1;31" if alert.severity == "HIGH" else "1;33", color)
            print(f"  ALERT-{number:03d} {sev}{alert.rule:<24}{alert.source_ip:<18}{alert.attempt_count:>5}")
    print()
    print(f"Report saved : {args.output}")
    print("Reminder     : alerts are leads to investigate, not proof of an attack.")
