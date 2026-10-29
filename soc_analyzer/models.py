"""Plain data containers shared by the parser, detector and reporter.

Keeping these in one small file makes it easy to see what data flows
through the program.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple

# Outcome of a single authentication attempt.
FAILED = "failed"
ACCEPTED = "accepted"

# Names of the detection rules.
RULE_REPEATED_FAILURES = "repeated-failed-logins"
RULE_SUCCESS_AFTER_FAILURES = "success-after-failures"

# Severity labels. Lower number = more urgent (used for sorting).
HIGH = "HIGH"
MEDIUM = "MEDIUM"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1}


@dataclass(frozen=True)
class AuthEvent:
    """One SSH authentication attempt parsed from one log line."""

    line_number: int      # 1-based line number in the log file (evidence)
    timestamp: datetime
    host: str
    username: str
    source_ip: str
    outcome: str          # FAILED or ACCEPTED
    method: str           # e.g. "password" or "publickey"
    port: int


@dataclass
class ParseResult:
    """What the parser found in a whole log file."""

    events: List[AuthEvent] = field(default_factory=list)
    total_lines: int = 0
    skipped_lines: int = 0   # lines that were not password/login events


@dataclass
class AnalysisConfig:
    """Settings that control detection."""

    threshold: int = 5        # failures needed to raise an alert
    window_minutes: int = 5   # ...within this many minutes
    year: int = 2026          # syslog lines do not contain a year


@dataclass
class Alert:
    """A detection result. It is an investigation LEAD, not proof of attack."""

    rule: str
    severity: str
    source_ip: str
    attempt_count: int
    first_seen: datetime
    last_seen: datetime
    usernames: List[str]
    evidence_lines: List[int]
    description: str
    successful_user: str = ""   # only used by the success-after-failures rule


@dataclass
class Summary:
    """Headline numbers shown at the top of the report."""

    total_lines: int
    skipped_lines: int
    total_events: int
    failed_count: int
    accepted_count: int
    unique_source_ips: int
    first_event: Optional[datetime] = None
    last_event: Optional[datetime] = None
    top_failed_ips: List[Tuple[str, int]] = field(default_factory=list)
