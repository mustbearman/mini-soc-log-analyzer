import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from soc_analyzer.cli import main

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = str(ROOT / "sample_logs" / "auth_sample.log")


def run(*argv):
    """Run the CLI and return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exit_request:     # argparse exits on bad arguments
            code = exit_request.code
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.report = os.path.join(self.tmp.name, "out", "report.md")

    def test_sample_log_produces_expected_alerts(self):
        code, out, _ = run(SAMPLE, "-o", self.report, "--year", "2026")
        self.assertEqual(code, 0)
        self.assertIn("Alerts       : 5  (HIGH 2, MEDIUM 3)", out)
        with open(self.report, encoding="utf-8") as handle:
            text = handle.read()
        # Expected leads, derived from how the sample log was designed:
        for ip in ("203.0.113.45", "203.0.113.99", "198.51.100.77", "192.0.2.88"):
            self.assertIn(ip, text)
        # Near-miss (3 failures) must not alert at the default threshold.
        alerts_section = text.split("## 3.")[1].split("## 4.")[0]
        self.assertNotIn("198.51.100.23", alerts_section)

    def test_lower_threshold_flags_the_near_miss(self):
        code, out, _ = run(SAMPLE, "-o", self.report, "-y", "2026", "--threshold", "3")
        self.assertEqual(code, 0)
        self.assertIn("198.51.100.23", out)

    def test_larger_window_flags_slow_attacker(self):
        _, default_out, _ = run(SAMPLE, "-o", self.report, "-y", "2026")
        _, wide_out, _ = run(SAMPLE, "-o", self.report, "-y", "2026", "--window", "10")
        self.assertNotEqual(default_out.count("ALERT-"), wide_out.count("ALERT-"))

    def test_missing_file(self):
        code, _, err = run("/no/such/file.log", "-o", self.report)
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_empty_file(self):
        empty = os.path.join(self.tmp.name, "empty.log")
        open(empty, "w").close()
        code, _, err = run(empty, "-o", self.report)
        self.assertEqual(code, 1)
        self.assertIn("empty", err)

    def test_wrong_format_file(self):
        wrong = os.path.join(self.tmp.name, "wrong.log")
        with open(wrong, "w") as handle:
            handle.write("hello\nworld\n")
        code, _, err = run(wrong, "-o", self.report)
        self.assertEqual(code, 1)
        self.assertIn("no SSH login events", err)
        self.assertFalse(os.path.exists(self.report))

    def test_invalid_threshold_is_rejected(self):
        for bad in ("0", "1", "-3", "abc"):
            code, _, err = run(SAMPLE, "-t", bad)
            self.assertEqual(code, 2, bad)
            self.assertIn("threshold", err)

    def test_invalid_window_is_rejected(self):
        code, _, _ = run(SAMPLE, "-w", "0")
        self.assertEqual(code, 2)

    def test_unwritable_output_path(self):
        blocker = os.path.join(self.tmp.name, "file.txt")
        open(blocker, "w").close()
        code, _, err = run(SAMPLE, "-y", "2026", "-o", os.path.join(blocker, "report.md"))
        self.assertEqual(code, 1)
        self.assertIn("could not write report", err)


if __name__ == "__main__":
    unittest.main()
