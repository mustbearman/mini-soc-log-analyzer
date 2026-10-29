# Mini SOC Log Analyzer

A small Python command-line tool that reads **SSH authentication logs**, finds **repeated failed logins**, flags events for analyst review, and writes a **Markdown incident triage report**. It was built as a beginner-friendly learning project for entry-level SOC Analyst (L1) work.

> **Important:** alerts are *investigation leads*, not proof of an attack. They come from simple threshold rules and can be false positives or false negatives. A human analyst must verify them.

- Python standard library only - **no dependencies** (Python 3.9+)
- Works on synthetic data included in the repo (documentation-only IP addresses, no real data)
- 53 unit tests (standard `unittest`)

## Quick start

```bash
git clone https://github.com/mustbearman/mini-soc-log-analyzer.git
cd mini-soc-log-analyzer

# Analyze the included synthetic log (the log has no year, so we pass 2026)
python -m soc_analyzer sample_logs/auth_sample.log --year 2026

# Run the tests
python -m unittest discover -v
```

On Windows use `py` instead of `python` if `python` is not found. The report is written to `output/triage_report.md` by default.

## Usage

```text
python -m soc_analyzer LOGFILE [-o OUTPUT] [-t THRESHOLD] [-w WINDOW] [-y YEAR]
```

| Option | Default | Meaning |
|---|---|---|
| `LOGFILE` | required | OpenSSH syslog-style auth log |
| `-o, --output` | `output/triage_report.md` | Report file to write |
| `-t, --threshold` | `5` | Failed logins needed to raise an alert (2-10000) |
| `-w, --window` | `5` | Time window in minutes (1-1440) |
| `-y, --year` | current year | Syslog lines have no year, so you provide it |

Examples:

```bash
python -m soc_analyzer sample_logs/auth_sample.log -y 2026 -t 3          # more sensitive
python -m soc_analyzer sample_logs/auth_sample.log -y 2026 -w 10          # wider window
python -m soc_analyzer /var/log/auth.log -y 2026 -o reports/today.md      # your own log
```

Exit codes: `0` finished (alerts do not change this), `1` input/output problem, `2` bad arguments.

## What it detects

| Rule | Logic | Severity |
|---|---|---|
| `repeated-failed-logins` | At least *threshold* failed logins from one IP inside a sliding *window*. Overlapping windows merge into one alert. | MEDIUM; HIGH when count >= 3 x threshold |
| `success-after-failures` | A successful login from an IP that had at least *threshold* failures in the window just before it. | HIGH |

Severity labels are simple heuristics chosen for this project, not an industry standard.

## Sample output (real run on the included synthetic log)

```text
Input        : auth_sample.log
Lines read   : 183  (events: 85, skipped: 98)
Logins       : 55 failed, 30 successful, 9 unique IPs
Rule         : >= 5 failed logins within 5 min
Alerts       : 5  (HIGH 2, MEDIUM 3)

  ID        SEVERITY  RULE                    SOURCE IP         COUNT
  ALERT-001 HIGH      repeated-failed-logins  203.0.113.45         24
  ALERT-002 HIGH      success-after-failures  192.0.2.88            7
  ALERT-003 MEDIUM    repeated-failed-logins  203.0.113.99          7
  ALERT-004 MEDIUM    repeated-failed-logins  198.51.100.77         6
  ALERT-005 MEDIUM    repeated-failed-logins  192.0.2.88            7
```

Full report: [`sample_output/sample_report.md`](sample_output/sample_report.md)

The sample data also contains two deliberate "traps" so you can see the limits of the rules: a 3-failure near miss (no alert at the default threshold) and a slow attacker guessing every 90 seconds (stays under the 5-minute window). See [limitations](docs/LIMITATIONS_AND_FUTURE_WORK.md).

## Project structure

```text
mini-soc-log-analyzer/
├── soc_analyzer/          # the program
│   ├── models.py          # data containers (AuthEvent, Alert, ...)
│   ├── parser.py          # log line -> AuthEvent
│   ├── detector.py        # detection rules + summary statistics
│   ├── reporter.py        # Markdown report + output escaping
│   └── cli.py             # command-line interface
├── tests/                 # 53 unit tests
├── sample_logs/           # synthetic SSH log (made up)
├── sample_output/         # report generated from the sample log
├── scripts/generate_sample_log.py   # recreates the synthetic log (fixed seed)
└── docs/                  # architecture, learning guide, study plan, interview prep, GitHub steps
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Learning guide](docs/LEARNING_GUIDE.md) - SSH logs, regex, sliding windows, SOC terms
- [Limitations and future work](docs/LIMITATIONS_AND_FUTURE_WORK.md)
- [2-day study plan](docs/STUDY_PLAN.md)
- [Interview prep and LinkedIn text](docs/INTERVIEW_PREP.md)
- [GitHub upload steps](docs/GITHUB_UPLOAD.md)
- [Project report](docs/PROJECT_REPORT.md) and [test results](docs/test_results.txt)

## Safety and data notes

- All sample data is synthetic. IPs come from the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). There are no real users, credentials or personal data.
- Do not commit real logs. Logs can contain usernames, IPs and other sensitive data.
- Values from logs are escaped before they go into the report, because attackers control the usernames they type.

## Author

Arman - [github.com/mustbearman](https://github.com/mustbearman) - MIT licensed (see `LICENSE`).
