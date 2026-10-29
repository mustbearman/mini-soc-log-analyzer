import os
import tempfile
import unittest
from datetime import datetime

from soc_analyzer.detector import build_summary, detect
from soc_analyzer.models import AnalysisConfig, ParseResult
import re

from soc_analyzer.reporter import DISCLAIMER, code_span, md_escape, render_report, write_report
from tests.test_detector import ev, failures

NOW = datetime(2026, 10, 29, 12, 0, 0)


def make_report(events, config=None):
    config = config or AnalysisConfig()
    result = ParseResult(events=events, total_lines=len(events), skipped_lines=0)
    return render_report(build_summary(result), detect(events, config), config, "x.log", NOW)


class ReportTests(unittest.TestCase):
    def test_contains_disclaimer_and_sections(self):
        text = make_report(failures(6, 10))
        self.assertIn("investigation lead", DISCLAIMER)
        self.assertIn(DISCLAIMER, text)
        for heading in ("## 1. Scope", "## 2. Summary", "## 3. Alerts", "## 4. Top source", "## 5. Limitations"):
            self.assertIn(heading, text)

    def test_alert_table_and_ids(self):
        text = make_report(failures(6, 10))
        self.assertIn("ALERT-001", text)
        self.assertIn("repeated-failed-logins", text)
        self.assertIn("203.0.113.10", text)

    def test_no_alerts_message_does_not_claim_safety(self):
        text = make_report(failures(2, 10))
        self.assertIn("No alerts were raised", text)
        self.assertIn("does **not** prove", text)

    def test_markdown_injection_in_username_is_neutralised(self):
        evil = "x|`<script>alert(1)</script>"
        text = make_report(failures(6, 10, user=evil))
        outside_code_spans = re.sub(r"`[^`]*`", "", text)
        self.assertNotIn("<script>", outside_code_spans)
        # The user-controlled value must not add a column to the details line.
        self.assertIn("`x\\|'<script>alert(1)</script>`", text)

    def test_filename_is_not_backslash_escaped_inside_code_span(self):
        self.assertIn("`x.log`", make_report(failures(6, 10)))
        self.assertEqual(code_span("auth_sample.log"), "`auth_sample.log`")

    def test_method_text_from_log_is_escaped_in_description(self):
        self.assertEqual(md_escape("<img>"), "\\<img\\>")

    def test_long_values_are_truncated(self):
        self.assertLess(len(code_span("a" * 500)), 80)
        self.assertLess(len(md_escape("a" * 5000)), 400)

    def test_evidence_list_is_shortened(self):
        text = make_report(failures(30, 5))
        self.assertIn("and 20 more", text)

    def test_write_report_creates_missing_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "a", "b", "report.md")
            write_report("hello", path)
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "hello")


if __name__ == "__main__":
    unittest.main()
