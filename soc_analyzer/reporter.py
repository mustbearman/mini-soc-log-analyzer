"""Build the Markdown incident triage report.

Log fields such as usernames are controlled by whoever connects to the
server, so an attacker could try to inject Markdown/HTML into our report.
Every value that comes from a log goes through `md_escape` first.
"""

import os
from datetime import datetime
from typing import List

from .models import (
    RULE_REPEATED_FAILURES,
    RULE_SUCCESS_AFTER_FAILURES,
    Alert,
    AnalysisConfig,
    Summary,
)

MAX_EVIDENCE_LINES = 10    # how many line numbers to show per alert
MAX_NAME_LENGTH = 64       # truncate very long usernames

DISCLAIMER = (
    "**Read this first:** every alert below is an *investigation lead*, not "
    "proof of an attack. Alerts come from simple threshold rules and can be "
    "false positives (for example a user mistyping a password, or a "
    "vulnerability scanner run by your own team) or can miss real activity "
    "(for example very slow guessing). An analyst must verify each lead "
    "before drawing conclusions."
)

TRIAGE_STEPS = {
    RULE_REPEATED_FAILURES: [
        "Check whether the source IP is expected (VPN, office, scanner, jump host).",
        "Search the same period for a *successful* login from this IP.",
        "Check whether the targeted usernames exist and whether any are privileged (e.g. root).",
        "Confirm protections are in place (key-only login, rate limiting, lockout).",
        "Follow your team's runbook for blocking or escalating. Do not decide alone as L1.",
    ],
    RULE_SUCCESS_AFTER_FAILURES: [
        "Contact the account owner and ask if they logged in at that time.",
        "Review what the session did after login (commands, new SSH keys, scheduled jobs).",
        "Compare the source IP with the user's normal locations.",
        "If the login cannot be confirmed as legitimate, escalate to L2 per the runbook.",
    ],
}


def _shorten(value: str, limit: int) -> str:
    value = str(value).replace("\n", " ").replace("\r", " ")
    return value[:limit] + "..." if len(value) > limit else value


def md_escape(value: str, limit: int = 300) -> str:
    """Make untrusted text safe to place in normal Markdown text."""
    value = _shorten(value, limit)
    for char in ("\\", "`", "|", "<", ">", "*", "_", "[", "]", "#"):
        value = value.replace(char, "\\" + char)
    return value


def code_span(value: str, limit: int = MAX_NAME_LENGTH) -> str:
    """Wrap untrusted text in a Markdown code span, e.g. `value`.

    Inside a code span the text is shown literally (HTML is not
    interpreted), so we only need to stop two things: a backtick that would
    close the span early, and a pipe that would break a table row.
    """
    value = _shorten(value, limit).replace("`", "'").replace("|", "\\|")
    return f"`{value}`"


def _fmt(moment) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else "n/a"


def _evidence(lines: List[int]) -> str:
    shown = ", ".join(str(n) for n in lines[:MAX_EVIDENCE_LINES])
    extra = len(lines) - MAX_EVIDENCE_LINES
    return shown + (f" ... and {extra} more" if extra > 0 else "")


def render_report(
    summary: Summary,
    alerts: List[Alert],
    config: AnalysisConfig,
    source_name: str,
    generated_at: datetime,
) -> str:
    """Return the full report as a Markdown string."""
    out: List[str] = []
    add = out.append

    add("# SSH Authentication Log - Incident Triage Report\n")
    add(f"> {DISCLAIMER}\n")

    add("## 1. Scope and settings\n")
    add("| Item | Value |")
    add("|---|---|")
    add(f"| Log file | {code_span(source_name)} |")
    add(f"| Report generated | {_fmt(generated_at)} |")
    add(f"| Log period (assumed year {config.year}) | {_fmt(summary.first_event)} to {_fmt(summary.last_event)} |")
    add(f"| Rule threshold | {config.threshold} failed logins |")
    add(f"| Rule time window | {config.window_minutes} minute(s) |")
    add("")

    add("## 2. Summary\n")
    high = sum(1 for a in alerts if a.severity == "HIGH")
    medium = sum(1 for a in alerts if a.severity == "MEDIUM")
    add("| Metric | Count |")
    add("|---|---|")
    add(f"| Lines read | {summary.total_lines} |")
    add(f"| Login events recognised | {summary.total_events} |")
    add(f"| Lines skipped (not login events) | {summary.skipped_lines} |")
    add(f"| Failed logins | {summary.failed_count} |")
    add(f"| Successful logins | {summary.accepted_count} |")
    add(f"| Unique source IPs | {summary.unique_source_ips} |")
    add(f"| **Alerts raised** | **{len(alerts)}** (HIGH: {high}, MEDIUM: {medium}) |")
    add("")

    add("## 3. Alerts for review\n")
    if not alerts:
        add("No alerts were raised with the current settings. This does **not** "
            "prove the system is safe; see the limitations section.\n")
    else:
        add("| ID | Severity | Rule | Source IP | Attempts | First seen | Last seen |")
        add("|---|---|---|---|---|---|---|")
        for number, alert in enumerate(alerts, start=1):
            add(f"| ALERT-{number:03d} | {alert.severity} | {alert.rule} | "
                f"{code_span(alert.source_ip)} | {alert.attempt_count} | "
                f"{_fmt(alert.first_seen)} | {_fmt(alert.last_seen)} |")
        add("")
        add("### Alert details\n")
        for number, alert in enumerate(alerts, start=1):
            add(f"#### ALERT-{number:03d} - {alert.severity} - {alert.rule}\n")
            add(f"- **Source IP:** {code_span(alert.source_ip)}")
            add(f"- **What was seen:** {md_escape(alert.description)}")
            if alert.successful_user:
                add(f"- **Account that logged in:** {code_span(alert.successful_user)}")
            names = ", ".join(code_span(n) for n in alert.usernames)
            add(f"- **Usernames involved:** {names}")
            add(f"- **Evidence (log line numbers):** {_evidence(alert.evidence_lines)}")
            add("- **Suggested next steps (investigation leads):**")
            for step in TRIAGE_STEPS[alert.rule]:
                add(f"  - {step}")
            add("")

    add("## 4. Top source IPs by failed logins\n")
    if summary.top_failed_ips:
        add("| Source IP | Failed logins |")
        add("|---|---|")
        for ip, count in summary.top_failed_ips:
            add(f"| {code_span(ip)} | {count} |")
    else:
        add("No failed logins were found.")
    add("")

    add("## 5. Limitations of this report\n")
    add("- Only OpenSSH `Failed ...` and `Accepted ...` lines are analysed.")
    add("- Detection uses fixed thresholds per source IP; attackers who use many IPs "
        "or guess slowly can stay below them.")
    add("- IP addresses are not enriched (no geolocation or reputation data).")
    add("- Syslog lines have no year; the year was assumed from the `--year` setting.")
    add("")
    return "\n".join(out)


def write_report(text: str, path: str) -> None:
    """Write the report to disk, creating the folder if needed."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
