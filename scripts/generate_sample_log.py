"""Generate the SYNTHETIC SSH log in sample_logs/auth_sample.log.

Everything here is made up. IP addresses come from the ranges reserved for
documentation (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
so they never belong to a real network. Usernames are generic.

Run from the project root:  python scripts/generate_sample_log.py
The random seed is fixed, so the output is identical every time.
"""

import os
import random
from datetime import datetime, timedelta

HOST = "web01"
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
KNOWN_USERS = {"alice", "bob", "carol", "deploy", "root"}

rng = random.Random(42)
entries = []   # (timestamp, sequence, line) - sequence keeps same-second order


def stamp(moment: datetime) -> str:
    return f"{MONTHS[moment.month - 1]} {moment.day:2d} {moment:%H:%M:%S}"


def add(moment, pid, message, program="sshd"):
    line = f"{stamp(moment)} {HOST} {program}[{pid}]: {message}"
    entries.append((moment, len(entries), line))


def failed_attempt(moment, user, ip):
    pid, port = rng.randint(2000, 30000), rng.randint(30000, 65000)
    if user not in KNOWN_USERS:
        add(moment, pid, f"Invalid user {user} from {ip} port {port}")
        add(moment, pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2")
    else:
        add(moment, pid, f"Failed password for {user} from {ip} port {port} ssh2")


def good_login(moment, user, ip, method):
    pid, port = rng.randint(2000, 30000), rng.randint(30000, 65000)
    add(moment, pid, f"Accepted {method} for {user} from {ip} port {port} ssh2")
    add(moment, pid, f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)")
    end = moment + timedelta(minutes=rng.randint(5, 90))
    add(end, pid, f"Disconnected from user {user} {ip} port {port}")


day1 = datetime(2026, 10, 12)
day2 = datetime(2026, 10, 13)

# --- Background noise -------------------------------------------------------
for day in (day1, day2):
    add(day + timedelta(minutes=1), 801, "Server listening on 0.0.0.0 port 22.")
    add(day + timedelta(hours=12, seconds=5), 77, "(root) CMD (run-parts /etc/cron.hourly)", program="CRON")

# --- Normal users (each from their usual internal address) -----------------
USUAL = {"alice": ("192.0.2.10", "publickey"), "bob": ("192.0.2.11", "password"),
         "carol": ("192.0.2.12", "publickey"), "deploy": ("192.0.2.20", "publickey")}
for day in (day1, day2):
    for _ in range(14):
        user = rng.choice(sorted(USUAL))
        ip, method = USUAL[user]
        when = day + timedelta(hours=rng.randint(8, 18), minutes=rng.randint(0, 59),
                               seconds=rng.randint(0, 59))
        good_login(when, user, ip, method)

# Harmless typos: below the threshold, so they must NOT alert.
failed_attempt(day1 + timedelta(hours=9, minutes=15, seconds=10), "alice", "192.0.2.10")
failed_attempt(day1 + timedelta(hours=9, minutes=15, seconds=25), "alice", "192.0.2.10")
good_login(day1 + timedelta(hours=9, minutes=15, seconds=40), "alice", "192.0.2.10", "password")
failed_attempt(day1 + timedelta(hours=14, minutes=2, seconds=5), "carol", "192.0.2.12")

# --- Scenario A: fast brute force against many accounts (expect HIGH) -------
names = ["root", "admin", "ubuntu", "test", "oracle", "postgres"]
for i in range(24):
    when = day1 + timedelta(hours=2, minutes=14, seconds=3 + i * 10)
    failed_attempt(when, names[i % len(names)], "203.0.113.45")

# --- Scenario B: password spraying, one try per common username (MEDIUM) ----
for i, user in enumerate(["admin", "test", "guest", "oracle", "user", "pi", "ftp"]):
    failed_attempt(day1 + timedelta(hours=4, minutes=40, seconds=i * 25), user, "203.0.113.99")

# --- Scenario C: repeated guesses against one account (MEDIUM) -------------
for i in range(6):
    failed_attempt(day1 + timedelta(hours=11, minutes=30, seconds=i * 54), "admin", "198.51.100.77")

# --- Scenario D: near miss, only 3 failures (no alert at default settings) --
for i in range(3):
    failed_attempt(day1 + timedelta(hours=13, minutes=5, seconds=i * 40), "deploy", "198.51.100.23")

# --- Scenario E: low-and-slow guessing, 90 s apart (evades 5-minute window) -
for i in range(5):
    failed_attempt(day2 + timedelta(hours=1, minutes=30, seconds=i * 90), "root", "203.0.113.45")

# --- Scenario F: failures then a SUCCESS from a new address (HIGH lead) ----
for i in range(7):
    failed_attempt(day2 + timedelta(hours=3, minutes=2, seconds=i * 17), "bob", "192.0.2.88")
good_login(day2 + timedelta(hours=3, minutes=4, seconds=20), "bob", "192.0.2.88", "password")

# --- Write the file ---------------------------------------------------------
entries.sort(key=lambda item: (item[0], item[1]))
lines = [item[2] for item in entries]
lines.insert(9, "this line is not a valid syslog entry (kept on purpose to test error handling)")

target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sample_logs", "auth_sample.log")
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
print(f"Wrote {len(lines)} synthetic log lines to {os.path.normpath(target)}")
