import os
import tempfile
import unittest

from soc_analyzer.models import ACCEPTED, FAILED
from soc_analyzer.parser import LogFileError, parse_file, parse_line, parse_lines

FAILED_LINE = "Oct 12 02:14:03 web01 sshd[4121]: Failed password for root from 203.0.113.45 port 40122 ssh2"
INVALID_USER_LINE = "Oct 12 02:14:13 web01 sshd[4122]: Failed password for invalid user admin from 203.0.113.45 port 64581 ssh2"
ACCEPTED_LINE = "Oct 12 09:15:40 web01 sshd[5230]: Accepted publickey for alice from 192.0.2.10 port 51514 ssh2"


class ParseLineTests(unittest.TestCase):
    def test_failed_password(self):
        event = parse_line(FAILED_LINE, 7, 2026)
        self.assertEqual(event.outcome, FAILED)
        self.assertEqual(event.username, "root")
        self.assertEqual(event.source_ip, "203.0.113.45")
        self.assertEqual(event.port, 40122)
        self.assertEqual(event.method, "password")
        self.assertEqual(event.line_number, 7)
        self.assertEqual((event.timestamp.month, event.timestamp.day, event.timestamp.hour), (10, 12, 2))

    def test_failed_for_invalid_user_extracts_real_username(self):
        self.assertEqual(parse_line(INVALID_USER_LINE, 1, 2026).username, "admin")

    def test_accepted_login(self):
        event = parse_line(ACCEPTED_LINE, 1, 2026)
        self.assertEqual(event.outcome, ACCEPTED)
        self.assertEqual(event.method, "publickey")
        self.assertEqual(event.username, "alice")

    def test_year_comes_from_argument(self):
        self.assertEqual(parse_line(FAILED_LINE, 1, 2031).timestamp.year, 2031)

    def test_single_digit_day_is_space_padded(self):
        line = "Oct  3 01:02:03 web01 sshd[1]: Failed password for bob from 192.0.2.5 port 22 ssh2"
        self.assertEqual(parse_line(line, 1, 2026).timestamp.day, 3)

    def test_non_login_sshd_lines_are_ignored(self):
        for text in (
            "Oct 12 02:14:13 web01 sshd[1]: Invalid user admin from 203.0.113.45 port 64581",
            "Oct 12 02:14:13 web01 sshd[1]: Server listening on 0.0.0.0 port 22.",
            "Oct 12 12:00:05 web01 CRON[77]: (root) CMD (run-parts /etc/cron.hourly)",
        ):
            self.assertIsNone(parse_line(text, 1, 2026))

    def test_garbage_and_empty_lines(self):
        self.assertIsNone(parse_line("not a log line", 1, 2026))
        self.assertIsNone(parse_line("", 1, 2026))

    def test_invalid_ip_is_rejected(self):
        line = "Oct 12 02:14:03 web01 sshd[1]: Failed password for root from 999.1.1.1 port 22 ssh2"
        self.assertIsNone(parse_line(line, 1, 2026))

    def test_impossible_date_is_rejected(self):
        line = "Feb 30 02:14:03 web01 sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
        self.assertIsNone(parse_line(line, 1, 2026))

    def test_ipv6_is_accepted(self):
        line = "Oct 12 02:14:03 web01 sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2"
        self.assertEqual(parse_line(line, 1, 2026).source_ip, "2001:db8::1")


class ParseLinesAndFileTests(unittest.TestCase):
    def test_counts(self):
        result = parse_lines([FAILED_LINE, "junk", ACCEPTED_LINE, ""], 2026)
        self.assertEqual(result.total_lines, 4)
        self.assertEqual(len(result.events), 2)
        self.assertEqual(result.skipped_lines, 2)
        self.assertEqual([e.line_number for e in result.events], [1, 3])

    def test_missing_file(self):
        with self.assertRaises(LogFileError) as ctx:
            parse_file("/definitely/not/here.log", 2026)
        self.assertIn("not found", str(ctx.exception))

    def test_directory_instead_of_file(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(LogFileError):
                parse_file(folder, 2026)

    def test_file_with_bad_bytes_does_not_crash(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "bad.log")
            with open(path, "wb") as handle:
                handle.write(FAILED_LINE.encode() + b"\n\xff\xfe\x00 binary junk\n")
            result = parse_file(path, 2026)
            self.assertEqual(len(result.events), 1)
            self.assertEqual(result.skipped_lines, 1)


if __name__ == "__main__":
    unittest.main()
