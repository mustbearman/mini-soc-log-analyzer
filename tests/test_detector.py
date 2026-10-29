import unittest
from datetime import datetime, timedelta

from soc_analyzer.detector import build_summary, detect
from soc_analyzer.models import (
    ACCEPTED, FAILED, HIGH, MEDIUM,
    RULE_REPEATED_FAILURES, RULE_SUCCESS_AFTER_FAILURES,
    AnalysisConfig, AuthEvent, ParseResult,
)

START = datetime(2026, 10, 12, 2, 0, 0)


def ev(seconds, outcome=FAILED, ip="203.0.113.10", user="root", line=None):
    """Helper: build an event `seconds` after START."""
    return AuthEvent(
        line_number=line if line is not None else int(seconds) + 1,
        timestamp=START + timedelta(seconds=seconds),
        host="web01", username=user, source_ip=ip,
        outcome=outcome, method="password", port=22,
    )


def failures(count, gap, **kwargs):
    return [ev(i * gap, **kwargs) for i in range(count)]


CFG = AnalysisConfig(threshold=5, window_minutes=5)


class RepeatedFailuresTests(unittest.TestCase):
    def test_below_threshold_no_alert(self):
        self.assertEqual(detect(failures(4, 10), CFG), [])

    def test_exactly_threshold_alerts_medium(self):
        alerts = detect(failures(5, 10), CFG)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule, RULE_REPEATED_FAILURES)
        self.assertEqual(alerts[0].severity, MEDIUM)
        self.assertEqual(alerts[0].attempt_count, 5)

    def test_three_times_threshold_is_high(self):
        self.assertEqual(detect(failures(15, 10), CFG)[0].severity, HIGH)
        self.assertEqual(detect(failures(14, 10), CFG)[0].severity, MEDIUM)

    def test_failures_spread_beyond_window_do_not_alert(self):
        # 5 failures, 90 s apart: at most 4 fit inside any 300 s window.
        self.assertEqual(detect(failures(5, 90), CFG), [])

    def test_bigger_window_catches_the_slow_attacker(self):
        wide = AnalysisConfig(threshold=5, window_minutes=10)
        self.assertEqual(len(detect(failures(5, 90), wide)), 1)

    def test_different_ips_are_not_combined(self):
        events = failures(3, 10, ip="203.0.113.1") + failures(3, 10, ip="203.0.113.2")
        self.assertEqual(detect(events, CFG), [])

    def test_one_long_burst_gives_one_alert(self):
        alerts = detect(failures(40, 20), CFG)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attempt_count, 40)

    def test_two_separate_bursts_give_two_alerts(self):
        events = failures(5, 10) + [ev(3600 + i * 10) for i in range(5)]
        self.assertEqual(len(detect(events, CFG)), 2)

    def test_unsorted_input_is_handled(self):
        events = list(reversed(failures(6, 10)))
        self.assertEqual(len(detect(events, CFG)), 1)

    def test_alert_contents(self):
        events = [ev(i * 10, user=("root" if i % 2 else "admin")) for i in range(6)]
        alert = detect(events, CFG)[0]
        self.assertEqual(alert.usernames, ["admin", "root"])
        self.assertEqual(alert.evidence_lines, [1, 11, 21, 31, 41, 51])
        self.assertEqual(alert.first_seen, START)
        self.assertEqual(alert.last_seen, START + timedelta(seconds=50))

    def test_successful_logins_do_not_count_as_failures(self):
        events = [ev(i * 10, outcome=ACCEPTED) for i in range(10)]
        self.assertEqual(detect(events, CFG), [])

    def test_threshold_is_configurable(self):
        strict = AnalysisConfig(threshold=3, window_minutes=5)
        self.assertEqual(len(detect(failures(3, 10), strict)), 1)


class SuccessAfterFailuresTests(unittest.TestCase):
    def test_success_after_enough_failures_is_high(self):
        events = failures(6, 10, user="bob") + [ev(70, outcome=ACCEPTED, user="bob", line=999)]
        alerts = [a for a in detect(events, CFG) if a.rule == RULE_SUCCESS_AFTER_FAILURES]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, HIGH)
        self.assertEqual(alerts[0].successful_user, "bob")
        self.assertEqual(alerts[0].evidence_lines[-1], 999)

    def test_high_alerts_sort_before_medium(self):
        events = failures(6, 10) + [ev(70, outcome=ACCEPTED)]
        severities = [a.severity for a in detect(events, CFG)]
        self.assertEqual(severities, [HIGH, MEDIUM])

    def test_success_without_failures_is_fine(self):
        self.assertEqual(detect([ev(0, outcome=ACCEPTED)], CFG), [])

    def test_few_failures_then_success_is_fine(self):
        events = failures(2, 10) + [ev(40, outcome=ACCEPTED)]
        self.assertEqual(detect(events, CFG), [])

    def test_failures_after_the_success_do_not_count(self):
        events = [ev(0, outcome=ACCEPTED)] + [ev(10 + i * 5) for i in range(5)]
        rules = [a.rule for a in detect(events, CFG)]
        self.assertNotIn(RULE_SUCCESS_AFTER_FAILURES, rules)

    def test_success_from_a_different_ip_does_not_match(self):
        events = failures(6, 10) + [ev(70, outcome=ACCEPTED, ip="203.0.113.99")]
        rules = [a.rule for a in detect(events, CFG)]
        self.assertNotIn(RULE_SUCCESS_AFTER_FAILURES, rules)

    def test_old_failures_outside_window_do_not_match(self):
        events = failures(6, 10) + [ev(3600, outcome=ACCEPTED)]
        rules = [a.rule for a in detect(events, CFG)]
        self.assertNotIn(RULE_SUCCESS_AFTER_FAILURES, rules)


class SummaryTests(unittest.TestCase):
    def test_summary_numbers(self):
        events = failures(3, 10) + [ev(100, outcome=ACCEPTED, ip="192.0.2.1")]
        summary = build_summary(ParseResult(events=events, total_lines=10, skipped_lines=6))
        self.assertEqual(summary.total_events, 4)
        self.assertEqual(summary.failed_count, 3)
        self.assertEqual(summary.accepted_count, 1)
        self.assertEqual(summary.unique_source_ips, 2)
        self.assertEqual(summary.top_failed_ips, [("203.0.113.10", 3)])
        self.assertEqual(summary.first_event, START)

    def test_empty_summary(self):
        summary = build_summary(ParseResult())
        self.assertIsNone(summary.first_event)
        self.assertEqual(summary.top_failed_ips, [])


if __name__ == "__main__":
    unittest.main()
