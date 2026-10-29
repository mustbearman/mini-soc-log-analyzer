"""Turn raw SSH log lines into AuthEvent objects.

Supported format: classic syslog lines written by OpenSSH (sshd), e.g.

    Oct 12 02:14:03 web01 sshd[4121]: Failed password for root from 203.0.113.45 port 40122 ssh2
    Oct 12 09:15:40 web01 sshd[5230]: Accepted publickey for alice from 192.0.2.10 port 51514 ssh2

Anything else (cron lines, "Connection closed", garbage) is counted as
"skipped" and ignored. Only two kinds of lines become events:
"Failed <method> for ..." and "Accepted <method> for ...".
"""

import ipaddress
import re
from datetime import datetime
from typing import Iterable, Optional

from .models import ACCEPTED, FAILED, AuthEvent, ParseResult


class LogFileError(Exception):
    """Raised when the log file cannot be read (message is user-friendly)."""


# Map month names ourselves so parsing does not depend on the OS locale.
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Outer shape of an sshd syslog line: date, time, host, "sshd[pid]:", message.
_LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)

# The two message shapes we care about. "(?:invalid user )?" is optional
# because sshd adds those words when the username does not exist.
_FAILED_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)


def parse_line(line: str, line_number: int, year: int) -> Optional[AuthEvent]:
    """Parse one log line. Return an AuthEvent, or None if it is not one."""
    outer = _LINE_RE.match(line.strip())
    if outer is None:
        return None

    message = outer.group("message")
    inner = _FAILED_RE.match(message)
    outcome = FAILED
    if inner is None:
        inner = _ACCEPTED_RE.match(message)
        outcome = ACCEPTED
    if inner is None:
        return None

    try:
        # Validate the IP instead of trusting the text in the log.
        source_ip = str(ipaddress.ip_address(inner.group("ip")))
        timestamp = datetime(
            year,
            _MONTHS[outer.group("month")],
            int(outer.group("day")),
            int(outer.group("hour")),
            int(outer.group("minute")),
            int(outer.group("second")),
        )
    except (ValueError, KeyError):
        # Bad IP, or an impossible date such as "Feb 30" or "Xyz 01".
        return None

    return AuthEvent(
        line_number=line_number,
        timestamp=timestamp,
        host=outer.group("host"),
        username=inner.group("user"),
        source_ip=source_ip,
        outcome=outcome,
        method=inner.group("method"),
        port=int(inner.group("port")),
    )


def parse_lines(lines: Iterable[str], year: int) -> ParseResult:
    """Parse many lines (any iterable of strings) into a ParseResult."""
    result = ParseResult()
    for number, line in enumerate(lines, start=1):
        result.total_lines += 1
        event = parse_line(line, number, year)
        if event is None:
            result.skipped_lines += 1
        else:
            result.events.append(event)
    return result


def parse_file(path: str, year: int) -> ParseResult:
    """Read a log file from disk and parse it.

    The file is read one line at a time, so large logs do not need to fit
    in memory. Undecodable bytes are replaced instead of crashing.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return parse_lines(handle, year)
    except FileNotFoundError:
        raise LogFileError(f"log file not found: {path}")
    except IsADirectoryError:
        raise LogFileError(f"expected a file but got a directory: {path}")
    except PermissionError:
        raise LogFileError(f"permission denied when reading: {path}")
    except OSError as exc:
        raise LogFileError(f"could not read {path}: {exc.strerror or exc}")
