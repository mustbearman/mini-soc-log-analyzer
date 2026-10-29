# 2-Day Beginner Study Plan

Goal: be able to run the project, read every file, and explain it honestly. About 3-4 hours per day. Take notes in your own words.

## Day 1 - Understand the problem and the code flow

| Time | Task |
|---|---|
| 30 min | Run it: `python -m soc_analyzer sample_logs/auth_sample.log -y 2026`. Open `sample_output/sample_report.md` and read it top to bottom. |
| 30 min | Read `docs/LEARNING_GUIDE.md` sections 1, 2 and 6. Open `sample_logs/auth_sample.log` and find the lines for `203.0.113.45` and `192.0.2.88`. |
| 45 min | Read `models.py` and `parser.py`. Try `parse_line` in a Python shell on the three example lines. |
| 45 min | Read `detector.py`. Draw the sliding window on paper with 6 timestamps. |
| 30 min | Read `reporter.py` and `cli.py` quickly. Find where the exit codes come from. |
| 30 min | Change `-t` and `-w` and see how the alert count changes (`-t 3`, `-w 10`). Write down why. |

End-of-day check (answer from memory, out loud): What goes in? What comes out? What are the two rules? Why is an alert not proof?

## Day 2 - Tests, limits, interview practice

| Time | Task |
|---|---|
| 45 min | Run `python -m unittest discover -v`. Read `tests/test_detector.py` and explain 5 tests in your own words. |
| 30 min | Break something on purpose (e.g. change `>=` to `>` in `detector.py`), run the tests, see which fail, then undo it. |
| 30 min | Read `docs/LIMITATIONS_AND_FUTURE_WORK.md`. Be ready to explain the low-and-slow and near-miss examples. |
| 45 min | Read `docs/INTERVIEW_PREP.md`. Practise the 60-second explanation aloud 3 times, timing yourself. |
| 30 min | Answer the five questions without looking at the answers. |
| 30 min | Generate a report with your own tweaked log (add a few fake lines, use documentation IPs only) and explain the result. |
| 30 min | Follow `docs/GITHUB_UPLOAD.md` and publish the repository. |

## Honest-explanation rules for interviews

- Say "I built a small learning project using synthetic logs", not "I built a SIEM".
- Say "alerts are leads to verify", not "it detects attacks".
- Say what you did not do (real-world testing, enrichment) before they ask.
- If you do not know something, say so and say how you would find out.
- Do not claim certifications, internships or production use.
