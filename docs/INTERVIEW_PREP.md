# Interview Prep and LinkedIn Text

All statements below match what the project actually does. Do not add claims that are not in the code.

## LinkedIn project description

**Mini SOC Log Analyzer (Python)**

Built a command-line tool in Python (standard library only) that parses SSH authentication logs, detects repeated failed logins using a configurable threshold and sliding time window, flags a "successful login after repeated failures" pattern, and generates a Markdown incident triage report with severity labels, evidence line numbers and suggested next steps.

- Tested on synthetic logs that use documentation-only IP addresses; 53 unit tests written with `unittest`
- Handles missing/empty/wrong-format files, invalid arguments and untrusted log text (output escaping)
- Documented architecture, limitations (e.g. slow-guessing evasion, per-IP counting) and future work

A learning project to practise log analysis and alert triage. Alerts are investigation leads, not proof of an attack.

Code: github.com/mustbearman/mini-soc-log-analyzer

Suggested skills tags: Python, Log Analysis, Security Monitoring, SOC, Incident Triage, Unit Testing

## 60-second interview explanation

"This is a small project I built to practise what a SOC analyst does with authentication logs. It's a Python command-line tool that reads SSH logs, extracts failed and successful logins, and applies two simple rules. The first flags an IP address with at least a configurable number of failed logins inside a time window, five in five minutes by default, using a sliding window. The second flags a successful login that comes right after repeated failures from the same IP, because that could mean a password guess worked. It then writes a Markdown triage report with a severity, the log line numbers as evidence, and suggested next steps. I tested it on synthetic logs I generated with documentation-only IP addresses, and I wrote 53 unit tests. I know its limits: it counts per IP, so a distributed attack or very slow guessing can slip past it, and I treat every alert as a lead to verify rather than proof of an attack. Next I'd add an allow-list and support more log formats."

## Five technical questions and answers

**1. How does your tool decide that something is a brute-force attempt?**
It groups failed logins by source IP and sorts them by time. A sliding window with two pointers checks whether at least *threshold* failures fall inside *window* minutes. If so it raises an alert, and overlapping windows are merged so one attack produces one alert. Defaults are 5 failures in 5 minutes and both are command-line options. I should be clear that "brute force" is my label for the pattern; the tool cannot know the intent behind it.

**2. What false positives and false negatives can it produce?**
False positives: a user who mistypes a password several times, many people behind one shared NAT address, or our own vulnerability scanner. False negatives: slow guessing that stays under the window (my sample log has one every 90 seconds that is not flagged at the defaults), attacks spread over many IPs, and attacks on services other than SSH. Lowering the threshold or widening the window changes the balance, and I show that with the `-t` and `-w` options.

**3. Why did you count only `Failed password` lines and ignore `Invalid user` lines?**
For a non-existent account sshd writes both an `Invalid user ...` line and a `Failed password for invalid user ...` line for the same attempt. Counting both would double the number of failures and inflate severity, so I count only the `Failed` line. The `Invalid user` lines are counted as skipped.

**4. Why is escaping needed in a report generator?**
Usernames in the log are typed by whoever connects, so an attacker controls that text. If I paste it straight into Markdown, they could inject formatting, HTML or break table rows. I put log values in code spans (replacing backticks and pipes) and escape other untrusted text. There is a unit test that tries a username containing a pipe, a backtick and a script tag. This is a small, practical example of treating log data as untrusted input.

**5. How would you improve this for real use?**
Add an allow-list of known-good IPs, support more formats such as journald and timestamps with years, detect many-IP attacks against one account, add enrichment like GeoIP and reputation with human review, export JSON for other tools, and run it in CI. Before trusting it I would test it on large real logs and tune thresholds with the team. A production SOC would also use a SIEM rather than a script like this.

## Questions they may ask about honesty

- *Did you use real data?* No. The logs are synthetic and use documentation-only IP ranges.
- *Is this production ready?* No. It is a learning project with known limits.
- *Did you use AI/ML?* No. The rules are simple thresholds.
- *Can you walk me through one function?* Yes: practise `_repeated_failures` in `detector.py` (see the Learning Guide).
