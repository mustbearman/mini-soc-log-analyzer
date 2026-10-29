# Learning Guide

Read this alongside the code. Everything here matches what the project actually does.

## 1. What is an SSH authentication log?

SSH lets people log in to a server remotely. The SSH server (`sshd`) writes a line for each login attempt, usually to `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS). Example lines from the sample data:

```text
Oct 12 02:14:03 web01 sshd[20015]: Failed password for root from 203.0.113.45 port 40821 ssh2
Oct 12 02:14:13 web01 sshd[10685]: Failed password for invalid user admin from 203.0.113.45 port 64581 ssh2
Oct 13 03:04:20 web01 sshd[3916]: Accepted password for bob from 192.0.2.88 port 33994 ssh2
```

| Part | Meaning |
|---|---|
| `Oct 12 02:14:03` | Time (no year!) |
| `web01` | Server name |
| `sshd[20015]` | Program and process ID |
| `Failed password` / `Accepted password` | Outcome and method |
| `for root` / `for invalid user admin` | Account tried (`invalid user` = it does not exist on the server) |
| `from 203.0.113.45 port 40821` | Where the attempt came from |

## 2. Why repeated failures matter

People mistype passwords, so one failure means little. Hundreds in minutes from one address usually means automation guessing passwords (**brute force**), or trying one password across many accounts (**password spraying**). The worrying moment is when guessing **succeeds**, which is why rule 2 exists.

## 3. Reading the code (suggested order)

1. `models.py` - the data shapes. `AuthEvent` is one login attempt, `Alert` is one finding.
2. `parser.py` - two regular expressions pick out the fields. Look at how `invalid user` is made optional with `(?:invalid user )?`.
3. `detector.py` - the sliding window in `_repeated_failures`.
4. `reporter.py` - how the Markdown is assembled, and why `code_span` and `md_escape` exist.
5. `cli.py` - how arguments, errors and exit codes are handled.
6. `tests/` - each test is a tiny example of expected behaviour.

## 4. The sliding window, step by step

Failures from one IP, sorted by time. Keep two pointers, `left` and `right`.

```text
for each failure at position `right`:
    while failure[right].time - failure[left].time > window:
        left += 1                       # drop failures that are too old
    if (right - left + 1) >= threshold:
        raise or extend an alert        # enough failures fit inside the window
```

Why two pointers? Each pointer only moves forward, so the loop is fast even for large logs. Overlapping windows are merged so one attack produces one alert instead of dozens.

Worked example with threshold 5, window 5 minutes: five failures 90 seconds apart cover 360 seconds. No 5-minute window ever holds all five, so **no alert**. A 10-minute window would alert. This is the "low and slow" blind spot (the sample log contains this case on purpose).

## 5. Python concepts used

- `dataclass` - a class that mostly stores data
- `re` - regular expressions for pattern matching
- `ipaddress` - validates IP addresses
- `datetime` / `timedelta` - times and durations
- `collections.Counter` / `defaultdict` - counting and grouping
- `argparse` - command-line arguments
- `unittest` - tests

## 6. Glossary (SOC L1 words)

| Term | Meaning |
|---|---|
| Alert | A signal from a tool that something might need attention |
| Triage | Quickly deciding if an alert is real, how serious, and what to do next |
| True positive | Alert about real malicious activity |
| False positive | Alert about harmless activity |
| False negative | Real malicious activity that raised no alert |
| Brute force | Many password guesses against one or more accounts |
| Password spraying | A few common passwords tried across many accounts |
| IOC | Indicator of compromise, such as a malicious IP |
| Escalation | Passing the case to a more senior analyst (L2) |
| Runbook | Written steps your team follows for a given alert |

## 7. Reading the report like an analyst

1. Read the disclaimer, then the summary numbers.
2. Look at HIGH alerts first. `success-after-failures` means a guess may have worked.
3. For each alert ask: is this IP expected? Do the usernames exist? Did anything succeed?
4. Use the evidence line numbers to open the original log and read the raw lines.
5. Record your conclusion and escalate per the runbook if unsure.
