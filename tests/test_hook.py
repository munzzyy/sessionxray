"""Tests for hooks/sessionxray-sessionend.sh, the Claude Code SessionEnd
hook. Runs the real script as a subprocess over a real pipe, exactly how
Claude Code invokes it -- nothing about the shell/jq boundary is mocked.

Skipped on a machine with no bash or no jq, and skipped outright on native
Windows: a bare `bash` on a Windows PATH is ambiguous (it can resolve to the
System32 WSL launcher stub instead of Git Bash, with no distro behind it),
and the hook itself -- a `.sh` invoked from settings.json -- is a POSIX
shell / WSL / macOS / Linux feature to begin with, the same as every other
bash-based Claude Code hook. The hook's own "missing jq" fallback is still
covered here, just not on Windows specifically.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "hooks" / "sessionxray-sessionend.sh"
FIXTURES = Path(__file__).parent / "fixtures"

_HAVE_BASH = shutil.which("bash") is not None
_HAVE_JQ = shutil.which("jq") is not None
_POSIX_ENOUGH = sys.platform != "win32"


@unittest.skipUnless(_HAVE_BASH and _HAVE_JQ and _POSIX_ENOUGH,
                      "bash and jq required to exercise the real hook script (not on native Windows)")
class SessionEndHook(unittest.TestCase):
    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp(prefix="sxr-hook-test-"))
        self.log_path = self._tmpdir / "history.log"

    def _run(self, payload: dict) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["SESSIONXRAY_HISTORY_LOG"] = str(self.log_path)
        return subprocess.run(
            ["bash", str(SCRIPT)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def test_appends_one_line_for_a_real_transcript(self):
        transcript = FIXTURES / "malicious" / "secrets.jsonl"
        proc = self._run({"session_id": "S1", "transcript_path": str(transcript),
                           "cwd": "/home/testuser/widget-app", "hook_event_name": "SessionEnd",
                           "reason": "clear"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(self.log_path.exists())
        lines = [ln for ln in self.log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        self.assertIn("reason=clear", lines[0])
        self.assertIn(str(transcript), lines[0])
        self.assertIn("F (", lines[0])  # secrets.jsonl grades F

    def test_reason_defaults_to_unknown_when_absent(self):
        transcript = FIXTURES / "benign" / "benign-session.jsonl"
        proc = self._run({"transcript_path": str(transcript)})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        line = self.log_path.read_text(encoding="utf-8").strip()
        self.assertIn("reason=unknown", line)

    def test_two_sessions_append_two_lines(self):
        benign = FIXTURES / "benign" / "benign-session.jsonl"
        malicious = FIXTURES / "malicious" / "secrets.jsonl"
        self._run({"transcript_path": str(benign), "reason": "clear"})
        self._run({"transcript_path": str(malicious), "reason": "resume"})
        lines = [ln for ln in self.log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2)
        self.assertIn("reason=clear", lines[0])
        self.assertIn("reason=resume", lines[1])

    def test_missing_transcript_path_is_a_quiet_noop(self):
        proc = self._run({"session_id": "S1", "reason": "clear"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")
        self.assertFalse(self.log_path.exists())

    def test_empty_transcript_path_is_a_quiet_noop(self):
        proc = self._run({"transcript_path": "", "reason": "clear"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self.log_path.exists())

    def test_nonexistent_transcript_path_is_a_quiet_noop(self):
        proc = self._run({"transcript_path": "/no/such/session/anywhere.jsonl", "reason": "clear"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self.log_path.exists())

    def test_malformed_json_stdin_is_a_quiet_noop(self):
        env = dict(os.environ)
        env["SESSIONXRAY_HISTORY_LOG"] = str(self.log_path)
        proc = subprocess.run(["bash", str(SCRIPT)], input="not even json{{{",
                               capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self.log_path.exists())

    def test_empty_stdin_is_a_quiet_noop(self):
        env = dict(os.environ)
        env["SESSIONXRAY_HISTORY_LOG"] = str(self.log_path)
        proc = subprocess.run(["bash", str(SCRIPT)], input="",
                               capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self.log_path.exists())

    def test_empty_zero_byte_transcript_still_grades_clean(self):
        empty = self._tmpdir / "empty-transcript.jsonl"
        empty.write_text("", encoding="utf-8")
        proc = self._run({"transcript_path": str(empty), "reason": "other"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        line = self.log_path.read_text(encoding="utf-8").strip()
        self.assertIn("reason=other", line)
        self.assertIn("A (100/100)", line)

    def test_falls_back_to_the_in_repo_copy_when_sessionxray_is_not_on_path(self):
        # No pip install happened for this test; the fallback to `python3 -m
        # sessionxray`, run against the package next to this script, is the
        # only way this can produce a line at all.
        transcript = FIXTURES / "benign" / "benign-session.jsonl"
        proc = self._run({"transcript_path": str(transcript), "reason": "clear"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(self.log_path.exists())


@unittest.skipUnless(_HAVE_BASH and _POSIX_ENOUGH, "bash required to exercise the real hook script (not on native Windows)")
class NoJq(unittest.TestCase):
    def test_no_jq_is_a_quiet_noop(self):
        tmpdir = Path(tempfile.mkdtemp(prefix="sxr-hook-nojq-"))
        log_path = tmpdir / "history.log"
        # Build a PATH with no jq on it at all, so `command -v jq` fails
        # inside the script regardless of what the host machine has.
        fake_bin = tmpdir / "bin"
        fake_bin.mkdir()
        for tool in ("bash", "cat", "printf", "dirname", "date", "mkdir"):
            real = shutil.which(tool)
            if real:
                (fake_bin / tool).symlink_to(real)
        env = {"PATH": str(fake_bin), "HOME": os.environ.get("HOME", ""),
               "SESSIONXRAY_HISTORY_LOG": str(log_path)}
        transcript = FIXTURES / "benign" / "benign-session.jsonl"
        proc = subprocess.run(
            ["bash", str(SCRIPT)],
            input=json.dumps({"transcript_path": str(transcript), "reason": "clear"}),
            capture_output=True, text=True, env=env, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(log_path.exists())


if __name__ == "__main__":
    unittest.main()
