"""Detection rules. Each rule looks at parsed events and returns Alerts.

Rule 1 - repeated-failed-logins
    A single source IP has at least `threshold` failed logins inside any
    sliding window of `window_minutes`. Overlapping windows are merged so
    one burst produces one alert.
    Severity: HIGH if the count is 3x the threshold or more, else MEDIUM.

Rule 2 - success-after-failures
    A successful login from an IP that had at least `threshold` failed
    logins in the `window_minutes` just before it. This is the pattern an
    analyst most wants to look at first, because a guess may have worked.
    Severity: always HIGH.

These are simple heuristics. An alert is a lead to investigate, not proof.
"""

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Dict, List

from .models import (
    ACCEPTED,
    FAILED,
    HIGH,
    MEDIUM,
    RULE_REPEATED_FAILURES,
    RULE_SUCCESS_AFTER_FAILURES,
    SEVERITY_ORDER,
    Alert,
    AnalysisConfig,
    AuthEvent,
    ParseResult,
    Summary,
)


def detect(events: List[AuthEvent], config: AnalysisConfig) -> List[Alert]:
    """Run all rules and return alerts sorted by severity, then time."""
    window = timedelta(minutes=config.window_minutes)

    # sorted() is stable, so events with the same timestamp keep file order.
    ordered = sorted(events, key=lambda event: event.timestamp)

    failures_by_ip: Dict[str, List[AuthEvent]] = defaultdict(list)
    accepted: List[AuthEvent] = []
    for event in ordered:
        if event.outcome == FAILED:
            failures_by_ip[event.source_ip].append(event)
        elif event.outcome == ACCEPTED:
            accepted.append(event)

    alerts: List[Alert] = []
    for ip, failures in failures_by_ip.items():
        alerts.extend(_repeated_failures(ip, failures, config.threshold, window))
    alerts.extend(
        _success_after_failures(accepted, failures_by_ip, config.threshold, window)
    )

    alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], a.first_seen, a.source_ip))
    return alerts


def _repeated_failures(ip, failures, threshold, window) -> List[Alert]:
    """Rule 1: sliding window over one IP's failures (already time-sorted)."""
    ranges = []   # [start_index, end_index] pairs, both inclusive
    left = 0
    for right in range(len(failures)):
        # Move the left edge forward until the window is small enough.
        while failures[right].timestamp - failures[left].timestamp > window:
            left += 1
        if right - left + 1 >= threshold:
            if ranges and left <= ranges[-1][1]:
                ranges[-1][1] = right      # overlaps previous burst: extend it
            else:
                ranges.append([left, right])

    alerts = []
    for start, end in ranges:
        burst = failures[start:end + 1]
        usernames = sorted({event.username for event in burst})
        count = len(burst)
        severity = HIGH if count >= threshold * 3 else MEDIUM
        alerts.append(
            Alert(
                rule=RULE_REPEATED_FAILURES,
                severity=severity,
                source_ip=ip,
                attempt_count=count,
                first_seen=burst[0].timestamp,
                last_seen=burst[-1].timestamp,
                usernames=usernames,
                evidence_lines=[event.line_number for event in burst],
                description=(
                    f"{count} failed SSH logins from one source IP, "
                    f"targeting {len(usernames)} distinct username(s)."
                ),
            )
        )
    return alerts


def _success_after_failures(accepted, failures_by_ip, threshold, window) -> List[Alert]:
    """Rule 2: for each successful login, look back `window` for failures."""
    alerts = []
    for login in accepted:
        recent = [
            failure
            for failure in failures_by_ip.get(login.source_ip, [])
            if timedelta(0) <= login.timestamp - failure.timestamp <= window
        ]
        if len(recent) < threshold:
            continue
        usernames = sorted({failure.username for failure in recent})
        alerts.append(
            Alert(
                rule=RULE_SUCCESS_AFTER_FAILURES,
                severity=HIGH,
                source_ip=login.source_ip,
                attempt_count=len(recent),
                first_seen=recent[0].timestamp,
                last_seen=login.timestamp,
                usernames=usernames,
                evidence_lines=[f.line_number for f in recent] + [login.line_number],
                description=(
                    f"A successful '{login.method}' login came from an IP that had "
                    f"{len(recent)} failed logins in the preceding "
                    f"{int(window.total_seconds() // 60)} minute(s)."
                ),
                successful_user=login.username,
            )
        )
    return alerts


def build_summary(result: ParseResult) -> Summary:
    """Compute headline statistics for the report."""
    events = result.events
    failed = [e for e in events if e.outcome == FAILED]
    failed_by_ip = Counter(e.source_ip for e in failed)
    times = [e.timestamp for e in events]
    return Summary(
        total_lines=result.total_lines,
        skipped_lines=result.skipped_lines,
        total_events=len(events),
        failed_count=len(failed),
        accepted_count=len(events) - len(failed),
        unique_source_ips=len({e.source_ip for e in events}),
        first_event=min(times) if times else None,
        last_event=max(times) if times else None,
        top_failed_ips=failed_by_ip.most_common(5),
    )
