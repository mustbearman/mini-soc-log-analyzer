# Limitations and Future Work

## Known limitations (honest list)

| Limitation | Effect | Seen in sample data? |
|---|---|---|
| Per-IP counting only | Attackers rotating many IPs (distributed attacks) can stay under the threshold | No |
| Fixed time window | "Low and slow" guessing evades it | **Yes** - 5 failures 90 s apart from `203.0.113.45` raise no alert at defaults |
| Fixed threshold | Too low gives false positives (shared NAT, typos); too high gives false negatives | **Yes** - the 3-failure near miss from `198.51.100.23` raises no alert at 5 |
| Only OpenSSH `Failed`/`Accepted` lines | Other auth events (e.g. `Connection closed by authenticating user`, sudo, web logins) are ignored | Counted as skipped |
| No year in syslog | Year must be supplied; logs spanning New Year (Dec to Jan) are not handled | Yes, by design |
| No IP enrichment | No geolocation, reputation or allow-list; an alert for your own scanner looks the same as an attack | - |
| Heuristic severity | HIGH/MEDIUM are project-defined labels, not a standard | - |
| One log file, whole file at once | No live monitoring or log rotation handling | - |
| Duplicate-looking alerts | `success-after-failures` and `repeated-failed-logins` can both fire for the same IP (ALERT-002 and ALERT-005 in the sample) | **Yes** - intentional, they say different things |
| Synthetic test data | Rules have not been tried on large real-world logs | - |

## What this project is not

It is not a SIEM, an intrusion prevention system or a replacement for real monitoring tools. It does not block anything and it does not use machine learning.

## Future improvements (ideas, none implemented)

1. Support more log formats (e.g. `journalctl` output, ISO-8601 timestamps that include the year).
2. Handle Dec-to-Jan year rollover.
3. Add an allow-list file for known-good IPs (office, scanner).
4. Detect distributed guessing against one username across many IPs.
5. Export JSON or CSV in addition to Markdown.
6. Add `--fail-on-alerts` for use in scripts.
7. Optional IP enrichment (offline GeoIP database).
8. Package with `pyproject.toml` so it installs as a command.
9. Add a GitHub Actions workflow that runs the tests.
10. Test performance on a large generated log.
