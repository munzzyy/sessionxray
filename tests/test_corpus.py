"""Labeled-corpus gate. Every malicious fixture must be caught (recall) and
every benign fixture must stay clean (precision). These are the floors CI
enforces: a rule change that starts missing real attacks or flagging
ordinary agent behavior fails here.

SXR-007 (prompt-injection exposure) is deliberately capped at MEDIUM -- a
finding there means the agent was handed injected text, not that it obeyed
it, so it never earns the same severity as an executed destructive command.
Its fixture is graded against a MEDIUM floor instead of the HIGH floor the
rest of the corpus is held to.
"""

import unittest
from pathlib import Path

from sessionxray.finding import Severity
from sessionxray.scanner import scan_session

CORPUS = Path(__file__).parent / "fixtures"
_MEDIUM_FLOOR = {"injection-exposure"}


class MaliciousRecall(unittest.TestCase):
    def test_every_malicious_session_is_flagged(self):
        paths = sorted((CORPUS / "malicious").glob("*.jsonl"))
        self.assertTrue(paths, "no malicious fixtures found")
        for path in paths:
            with self.subTest(session=path.name):
                r = scan_session(path)
                worst = r.worst()
                self.assertIsNotNone(worst, f"{path.name}: nothing flagged")
                if path.stem in _MEDIUM_FLOOR:
                    self.assertGreaterEqual(worst, Severity.MEDIUM, f"{path.name}: worst {worst} < MEDIUM")
                else:
                    self.assertGreaterEqual(worst, Severity.HIGH, f"{path.name}: worst {worst} < HIGH")
                    self.assertIn(r.grade, ("D", "F"), f"{path.name}: grade {r.grade} too lenient")
                self.assertNotEqual(r.grade, "A", f"{path.name}: grade A, too lenient")


class BenignPrecision(unittest.TestCase):
    def test_every_benign_session_is_clean(self):
        paths = sorted((CORPUS / "benign").glob("*.jsonl"))
        self.assertTrue(paths, "no benign fixtures found")
        for path in paths:
            with self.subTest(session=path.name):
                r = scan_session(path)
                loud = [f for f in r.findings if f.severity >= Severity.HIGH]
                self.assertEqual(loud, [], f"{path.name}: false positives {[f.title for f in loud]}")
                self.assertIn(r.grade, ("A", "B"), f"{path.name}: grade {r.grade}, unexpected penalty")


class MalformedRobustness(unittest.TestCase):
    def test_malformed_lines_do_not_crash_and_are_counted(self):
        path = CORPUS / "malformed" / "malformed-lines.jsonl"
        r = scan_session(path)
        self.assertGreater(r.skipped_lines, 0)
        # The one real tool call buried among the garbage must still surface.
        self.assertEqual(r.tool_call_count, 1)


if __name__ == "__main__":
    unittest.main()
