"""Engine tests: grading, report rendering, and the CLI end to end."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sessionxray import cli
from sessionxray.finding import Category, Finding, Severity
from sessionxray.grade import grade
from sessionxray.report import render_human, render_json, render_summary
from tests._helpers import assistant_event, write_session

FIXTURES = Path(__file__).parent / "fixtures"


def _f(sev, cat=Category.DESTRUCTIVE):
    return Finding("R", cat, sev, "t", "d")


class Grading(unittest.TestCase):
    def test_clean_is_a(self):
        self.assertEqual(grade([]), ("A", 100))

    def test_any_critical_is_f(self):
        g, _ = grade([_f(Severity.CRITICAL)])
        self.assertEqual(g, "F")

    def test_single_high_caps_below_b(self):
        g, score = grade([_f(Severity.HIGH)])
        self.assertIn(g, ("C", "D", "F"))
        self.assertLessEqual(score, 76)

    def test_three_high_reaches_d(self):
        g, score = grade([_f(Severity.HIGH), _f(Severity.HIGH), _f(Severity.HIGH)])
        self.assertEqual(g, "D")
        self.assertEqual(score, 55)

    def test_medium_alone_stays_in_a_band(self):
        g, score = grade([_f(Severity.MEDIUM)])
        self.assertEqual(g, "A")
        self.assertEqual(score, 94)


class Reporting(unittest.TestCase):
    def _scan_one(self, path):
        from sessionxray.scanner import scan_session
        return scan_session(path)

    def test_json_is_valid_and_complete(self):
        r = self._scan_one(FIXTURES / "malicious" / "destructive.jsonl")
        payload = json.loads(render_json([r]))
        self.assertEqual(payload["tool"], "sessionxray")
        self.assertEqual(len(payload["sessions"]), 1)
        s = payload["sessions"][0]
        self.assertIn("grade", s)
        self.assertTrue(s["findings"])
        self.assertIn("severity", s["findings"][0])
        self.assertIn("event_index", s["findings"][0])

    def test_human_report_shows_grade_and_counts(self):
        r = self._scan_one(FIXTURES / "malicious" / "secrets.jsonl")
        text = render_human([r], color=False)
        self.assertIn("Security grade:", text)
        self.assertIn("SXR-003", text)

    def test_human_report_no_findings_says_so(self):
        r = self._scan_one(FIXTURES / "benign" / "benign-session.jsonl")
        text = render_human([r], color=False)
        self.assertIn("No findings", text)

    def test_summary_is_one_line_per_session(self):
        r1 = self._scan_one(FIXTURES / "benign" / "benign-session.jsonl")
        r2 = self._scan_one(FIXTURES / "malicious" / "destructive.jsonl")
        text = render_summary([r1, r2], color=False)
        self.assertEqual(len(text.splitlines()), 2)

    def test_secret_evidence_never_contains_raw_value(self):
        r = self._scan_one(FIXTURES / "malicious" / "secrets.jsonl")
        blob = json.dumps([f.evidence for f in r.findings])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)


class CLI(unittest.TestCase):
    def _run(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(argv)
        return code, out.getvalue()

    def test_benign_session_exits_zero(self):
        code, _ = self._run([str(FIXTURES / "benign" / "benign-session.jsonl"), "--no-color"])
        self.assertEqual(code, 0)

    def test_malicious_session_fails_on_high(self):
        code, _ = self._run([str(FIXTURES / "malicious" / "destructive.jsonl"), "--no-color", "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_fail_on_none_always_exits_zero(self):
        code, _ = self._run([str(FIXTURES / "malicious" / "destructive.jsonl"), "--no-color", "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_json_output_parses(self):
        code, out = self._run([str(FIXTURES / "malicious" / "secrets.jsonl"), "--json"])
        payload = json.loads(out)
        self.assertEqual(payload["sessions"][0]["grade"], "F")

    def test_missing_path_is_usage_error(self):
        code, _ = self._run(["/no/such/session/anywhere.jsonl", "--no-color"])
        self.assertEqual(code, 2)

    def test_invalid_fail_on_is_usage_error(self):
        with self.assertRaises(SystemExit):
            self._run([str(FIXTURES / "benign" / "benign-session.jsonl"), "--fail-on", "not-a-severity"])

    def test_summary_mode_over_a_directory(self):
        code, out = self._run([str(FIXTURES / "malicious"), "--summary", "--no-color", "--fail-on", "none"])
        self.assertEqual(code, 0)
        lines = [ln for ln in out.splitlines() if ln.strip()]
        self.assertEqual(len(lines), len(list((FIXTURES / "malicious").glob("*.jsonl"))))

    def test_out_file_receives_the_report(self):
        tmp_out = Path(tempfile.mkdtemp()) / "report.txt"
        code, printed = self._run([str(FIXTURES / "benign" / "benign-session.jsonl"),
                                    "--out", str(tmp_out), "--fail-on", "none"])
        self.assertEqual(code, 0)
        self.assertEqual(printed, "")
        self.assertIn("Security grade:", tmp_out.read_text(encoding="utf-8"))

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_project_root_override(self):
        path = write_session([assistant_event(0, "Write", {"file_path": "/outside/file.txt", "content": "x"},
                                                cwd="/outside")])
        code, out = self._run([str(path), "--project-root", "/outside", "--json", "--fail-on", "none"])
        payload = json.loads(out)
        self.assertEqual(payload["sessions"][0]["findings"], [])


if __name__ == "__main__":
    unittest.main()
