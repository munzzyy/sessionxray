"""The README's example blocks are real tool output over the shipped fixtures.
Any rule or grading change invalidates them, and a security tool whose own
documented output is wrong is hard to trust. These tests regenerate both blocks
and compare, so the README goes stale loudly instead of quietly.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from sessionxray.report import render_summary
from sessionxray.scanner import scan_session

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
FIXTURES = ROOT / "tests" / "fixtures"


def _block_after(heading: str) -> list:
    """The lines of the first fenced code block following `heading`."""
    text = README.read_text(encoding="utf-8")
    start = text.index(heading)
    fence = text.index("```", start)
    body_start = text.index("\n", fence) + 1
    body_end = text.index("```", body_start)
    return [ln for ln in text[body_start:body_end].splitlines() if ln.strip()]


def _block_containing(marker: str) -> list:
    """The lines of the fenced code block that `marker` sits inside."""
    text = README.read_text(encoding="utf-8")
    at = text.index(marker)
    body_start = text.index("\n", text.rindex("```", 0, at)) + 1
    body_end = text.index("```", body_start)
    return [ln for ln in text[body_start:body_end].splitlines() if ln.strip()]


class FleetTriageBlock(unittest.TestCase):
    def test_summary_columns_match_the_documented_output(self):
        documented = [ln for ln in _block_after("### Fleet triage") if not ln.startswith("$")]
        paths = sorted((FIXTURES / "malicious").glob("*.jsonl"))
        rendered = render_summary([scan_session(p) for p in paths], color=False).splitlines()

        self.assertEqual(len(documented), len(rendered),
                         "the README block has a different number of rows than HEAD produces")
        for doc, live in zip(documented, rendered):
            # The path column is machine-specific; the README abbreviates it.
            self.assertEqual(_columns(doc), _columns(live))
            self.assertTrue(live.endswith(doc.split("SESSIONID")[-1].strip().lstrip(".")),
                            f"row order or file changed:\n  README: {doc}\n  HEAD:   {live}")

    def test_documented_command_is_the_one_that_was_run(self):
        cmd = [ln for ln in _block_after("### Fleet triage") if ln.startswith("$")]
        self.assertEqual(cmd, ["$ sessionxray --summary tests/fixtures/malicious --fail-on none"])


class SingleSessionBlock(unittest.TestCase):
    def test_headline_numbers_match(self):
        block = "\n".join(_block_containing("$ sessionxray tests/fixtures/malicious/secrets.jsonl"))
        r = scan_session(FIXTURES / "malicious" / "secrets.jsonl")
        self.assertIn(f"{r.tool_call_count} tool call(s) across {r.event_count} event(s)", block)
        self.assertIn(f"project root: {r.project_root}", block)
        self.assertIn(f"Security grade: {r.grade}  ({r.grade_score}/100)", block)

    def test_every_finding_title_in_the_block_still_fires(self):
        block = "\n".join(_block_containing("$ sessionxray tests/fixtures/malicious/secrets.jsonl"))
        r = scan_session(FIXTURES / "malicious" / "secrets.jsonl")
        for f in r.findings:
            self.assertIn(f.title, block, f"README is missing {f.title!r}")
            self.assertIn(f.detail, block, f"README's wording for {f.title!r} is stale")

    def test_home_directory_shown_is_the_transcripts_own(self):
        # The block used to print the analyst machine's home, which is the bug
        # the home-inference fix exists for. Guard the README against it too.
        block = "\n".join(_block_containing("$ sessionxray tests/fixtures/malicious/secrets.jsonl"))
        self.assertIn("/home/testuser/.ssh/id_rsa", block)


_GRADE_COL_RE = re.compile(r"^\s*([A-F])\s*\(\s*(\d+)/100\)\s{2}(.+?)\s{2,}(\d+) total")


def _columns(line: str):
    m = _GRADE_COL_RE.match(line)
    assert m, f"unparseable summary row: {line!r}"
    return m.group(1), m.group(2), m.group(3).strip(), m.group(4)


class InstallInstructions(unittest.TestCase):
    def test_readme_does_not_advertise_an_unclaimed_pypi_name(self):
        text = README.read_text(encoding="utf-8")
        self.assertNotIn("pipx install sessionxray", text)
        self.assertNotIn("pip install sessionxray\n", text)
        self.assertIn("pipx install git+https://github.com/munzzyy/sessionxray", text)

    def test_no_reference_to_the_deleted_noslop_package(self):
        for path in [README, ROOT / "CONTRIBUTING.md", ROOT / ".github" / "workflows" / "ci.yml"]:
            self.assertNotIn("noslop", path.read_text(encoding="utf-8").lower(), str(path))


if __name__ == "__main__":
    unittest.main()
