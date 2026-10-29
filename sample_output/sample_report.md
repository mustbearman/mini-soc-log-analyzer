# SSH Authentication Log - Incident Triage Report

> **Read this first:** every alert below is an *investigation lead*, not proof of an attack. Alerts come from simple threshold rules and can be false positives (for example a user mistyping a password, or a vulnerability scanner run by your own team) or can miss real activity (for example very slow guessing). An analyst must verify each lead before drawing conclusions.

## 1. Scope and settings

| Item | Value |
|---|---|
| Log file | `auth_sample.log` |
| Report generated | 2026-10-29 10:01:15 |
| Log period (assumed year 2026) | 2026-10-12 02:14:03 to 2026-10-13 18:27:38 |
| Rule threshold | 5 failed logins |
| Rule time window | 5 minute(s) |

## 2. Summary

| Metric | Count |
|---|---|
| Lines read | 183 |
| Login events recognised | 85 |
| Lines skipped (not login events) | 98 |
| Failed logins | 55 |
| Successful logins | 30 |
| Unique source IPs | 9 |
| **Alerts raised** | **5** (HIGH: 2, MEDIUM: 3) |

## 3. Alerts for review

| ID | Severity | Rule | Source IP | Attempts | First seen | Last seen |
|---|---|---|---|---|---|---|
| ALERT-001 | HIGH | repeated-failed-logins | `203.0.113.45` | 24 | 2026-10-12 02:14:03 | 2026-10-12 02:17:53 |
| ALERT-002 | HIGH | success-after-failures | `192.0.2.88` | 7 | 2026-10-13 03:02:00 | 2026-10-13 03:04:20 |
| ALERT-003 | MEDIUM | repeated-failed-logins | `203.0.113.99` | 7 | 2026-10-12 04:40:00 | 2026-10-12 04:42:30 |
| ALERT-004 | MEDIUM | repeated-failed-logins | `198.51.100.77` | 6 | 2026-10-12 11:30:00 | 2026-10-12 11:34:30 |
| ALERT-005 | MEDIUM | repeated-failed-logins | `192.0.2.88` | 7 | 2026-10-13 03:02:00 | 2026-10-13 03:03:42 |

### Alert details

#### ALERT-001 - HIGH - repeated-failed-logins

- **Source IP:** `203.0.113.45`
- **What was seen:** 24 failed SSH logins from one source IP, targeting 6 distinct username(s).
- **Usernames involved:** `admin`, `oracle`, `postgres`, `root`, `test`, `ubuntu`
- **Evidence (log line numbers):** 2, 4, 6, 8, 11, 13, 14, 16, 18, 20 ... and 14 more
- **Suggested next steps (investigation leads):**
  - Check whether the source IP is expected (VPN, office, scanner, jump host).
  - Search the same period for a *successful* login from this IP.
  - Check whether the targeted usernames exist and whether any are privileged (e.g. root).
  - Confirm protections are in place (key-only login, rate limiting, lockout).
  - Follow your team's runbook for blocking or escalating. Do not decide alone as L1.

#### ALERT-002 - HIGH - success-after-failures

- **Source IP:** `192.0.2.88`
- **What was seen:** A successful 'password' login came from an IP that had 7 failed logins in the preceding 5 minute(s).
- **Account that logged in:** `bob`
- **Usernames involved:** `bob`
- **Evidence (log line numbers):** 131, 132, 133, 134, 135, 136, 137, 138
- **Suggested next steps (investigation leads):**
  - Contact the account owner and ask if they logged in at that time.
  - Review what the session did after login (commands, new SSH keys, scheduled jobs).
  - Compare the source IP with the user's normal locations.
  - If the login cannot be confirmed as legitimate, escalate to L2 per the runbook.

#### ALERT-003 - MEDIUM - repeated-failed-logins

- **Source IP:** `203.0.113.99`
- **What was seen:** 7 failed SSH logins from one source IP, targeting 7 distinct username(s).
- **Usernames involved:** `admin`, `ftp`, `guest`, `oracle`, `pi`, `test`, `user`
- **Evidence (log line numbers):** 48, 50, 52, 54, 56, 58, 60
- **Suggested next steps (investigation leads):**
  - Check whether the source IP is expected (VPN, office, scanner, jump host).
  - Search the same period for a *successful* login from this IP.
  - Check whether the targeted usernames exist and whether any are privileged (e.g. root).
  - Confirm protections are in place (key-only login, rate limiting, lockout).
  - Follow your team's runbook for blocking or escalating. Do not decide alone as L1.

#### ALERT-004 - MEDIUM - repeated-failed-logins

- **Source IP:** `198.51.100.77`
- **What was seen:** 6 failed SSH logins from one source IP, targeting 1 distinct username(s).
- **Usernames involved:** `admin`
- **Evidence (log line numbers):** 82, 84, 86, 88, 90, 92
- **Suggested next steps (investigation leads):**
  - Check whether the source IP is expected (VPN, office, scanner, jump host).
  - Search the same period for a *successful* login from this IP.
  - Check whether the targeted usernames exist and whether any are privileged (e.g. root).
  - Confirm protections are in place (key-only login, rate limiting, lockout).
  - Follow your team's runbook for blocking or escalating. Do not decide alone as L1.

#### ALERT-005 - MEDIUM - repeated-failed-logins

- **Source IP:** `192.0.2.88`
- **What was seen:** 7 failed SSH logins from one source IP, targeting 1 distinct username(s).
- **Usernames involved:** `bob`
- **Evidence (log line numbers):** 131, 132, 133, 134, 135, 136, 137
- **Suggested next steps (investigation leads):**
  - Check whether the source IP is expected (VPN, office, scanner, jump host).
  - Search the same period for a *successful* login from this IP.
  - Check whether the targeted usernames exist and whether any are privileged (e.g. root).
  - Confirm protections are in place (key-only login, rate limiting, lockout).
  - Follow your team's runbook for blocking or escalating. Do not decide alone as L1.

## 4. Top source IPs by failed logins

| Source IP | Failed logins |
|---|---|
| `203.0.113.45` | 29 |
| `203.0.113.99` | 7 |
| `192.0.2.88` | 7 |
| `198.51.100.77` | 6 |
| `198.51.100.23` | 3 |

## 5. Limitations of this report

- Only OpenSSH `Failed ...` and `Accepted ...` lines are analysed.
- Detection uses fixed thresholds per source IP; attackers who use many IPs or guess slowly can stay below them.
- IP addresses are not enriched (no geolocation or reputation data).
- Syslog lines have no year; the year was assumed from the `--year` setting.
