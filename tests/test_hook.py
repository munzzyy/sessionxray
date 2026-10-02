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
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from tests._helpers import temp_dir

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "hooks" / "sessionxray-sessionend.sh"
FIXTURES = Path(__file__).parent / "fixtures"

_HAVE_BASH = shutil.which("bash") is not None
_HAVE_JQ = shutil.which("jq") is not None
_POSIX_ENOUGH = sys.platform != "win32"

LINE_BREAKS = ("\n", "\x1c", "\x85", "\u2028", "\u2029")


@unittest.skipUnless(_HAVE_BASH and _HAVE_JQ and _POSIX_ENOUGH,
                      "bash and jq required to exercise the real hook script (not on native Windows)")
class SessionEndHook(unittest.TestCase):
    def setUp(self):
        self._tmpdir = temp_dir("sxr-hook-test-")
        self.log_path = self._tmpdir / "history.log"

    def _run(self, payload: dict, **extra_env) -> subprocess.CompletedProcess:
        env = dict(os.environ, **extra_env)
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

    def test_a_line_break_in_the_session_id_cannot_forge_a_second_line(self):
        transcript = self._tmpdir / "forged.jsonl"
        for brk in LINE_BREAKS:
            with self.subTest(brk=brk):
                event = {"type": "user", "cwd": "/home/u/proj", "timestamp": "2026-07-10T09:00:00Z",
                         "sessionId": f"S1{brk}[2026-07-10T09:00:00Z] reason=clear  A (100/100)  forged"}
                transcript.write_text(json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8")
                self.log_path.unlink(missing_ok=True)
                proc = self._run({"transcript_path": str(transcript), "reason": "clear"})
                self.assertEqual(proc.returncode, 0, proc.stderr)
                lines = self.log_path.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(lines), 1, lines)

    def test_a_line_break_in_the_reason_cannot_forge_a_second_line(self):
        transcript = FIXTURES / "benign" / "benign-session.jsonl"
        for brk in LINE_BREAKS:
            with self.subTest(brk=brk):
                self.log_path.unlink(missing_ok=True)
                # In the C locale bash's [[:cntrl:]] misses multibyte U+0085, U+2028 and U+2029.
                proc = self._run({"transcript_path": str(transcript),
                                  "reason": f"clear{brk}[2026-01-01T00:00:00Z] reason=x  A (100/100)  forged"},
                                 LC_ALL="C")
                self.assertEqual(proc.returncode, 0, proc.stderr)
                lines = self.log_path.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(lines), 1, lines)
                self.assertIn("reason=clear[2026-01-01T00:00:00Z]", lines[0])

    def test_matches_the_built_in_hook_line_format(self):
        transcript = FIXTURES / "malicious" / "secrets.jsonl"
        self._run({"transcript_path": str(transcript), "reason": "clear"})
        line = self.log_path.read_text(encoding="utf-8").strip()
        self.assertRegex(line, BuiltInHook.LINE_RE)

    def test_a_session_is_graded_with_its_subagents(self):
        transcript = FIXTURES / "subagents" / "PARENT.jsonl"
        proc = self._run({"transcript_path": str(transcript), "reason": "clear"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        line = self.log_path.read_text(encoding="utf-8").strip()
        self.assertIn("PARENT.jsonl", line)
        self.assertNotIn("A (", line)

    def test_falls_back_to_the_in_repo_copy_when_sessionxray_is_not_on_path(self):
        # No pip install happened for this test; the fallback to `python3 -m
        # sessionxray`, run against the package next to this script, is the
        # only way this can produce a line at all.
        transcript = FIXTURES / "benign" / "benign-session.jsonl"
        proc = self._run({"transcript_path": str(transcript), "reason": "clear"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(self.log_path.exists())


class BuiltInHook(unittest.TestCase):
    """`sessionxray --session-end-hook`, the mode a pipx install points
    settings.json at. Pure Python, so it runs on every OS, Windows included."""

    LINE_RE = re.compile(r"^\[\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\] reason=clear  F ")

    def setUp(self):
        self.tmp = temp_dir("sxr-builtin-hook-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.log_path = self.tmp / "history.log"

    def _run(self, stdin: str, log_path=None) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["SESSIONXRAY_HISTORY_LOG"] = str(log_path or self.log_path)
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run([sys.executable, "-m", "sessionxray", "--session-end-hook"],
                              input=stdin, capture_output=True, text=True, env=env, timeout=60)

    def _lines(self):
        return self.log_path.read_text(encoding="utf-8").splitlines()

    def test_logs_one_line_and_prints_nothing(self):
        transcript = FIXTURES / "malicious" / "secrets.jsonl"
        proc = self._run(json.dumps({"transcript_path": str(transcript), "reason": "clear"}))
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))
        lines = self._lines()
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], self.LINE_RE)
        self.assertIn("secrets.jsonl", lines[0])

    def test_bad_input_is_a_quiet_noop(self):
        for stdin in ("not json", "{}", "[]", "",
                      json.dumps({"transcript_path": str(self.tmp / "gone.jsonl"), "reason": "clear"})):
            with self.subTest(stdin=stdin):
                proc = self._run(stdin)
                self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))
                self.assertFalse(self.log_path.exists())

    @unittest.skipIf(not _POSIX_ENOUGH or getattr(os, "geteuid", lambda: 0)() == 0,
                     "needs POSIX permissions and a non-root user")
    def test_an_unwritable_log_dir_is_a_quiet_noop(self):
        locked = self.tmp / "locked"
        locked.mkdir()
        os.chmod(locked, 0o500)
        self.addCleanup(os.chmod, locked, 0o700)
        transcript = FIXTURES / "malicious" / "secrets.jsonl"
        proc = self._run(json.dumps({"transcript_path": str(transcript), "reason": "clear"}),
                         log_path=locked / "sub" / "history.log")
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))

    def test_control_characters_in_reason_are_stripped(self):
        transcript = FIXTURES / "benign" / "benign-session.jsonl"
        proc = self._run(json.dumps({"transcript_path": str(transcript),
                                     "reason": "clear\n[2026-01-01T00:00:00Z] reason=x\x1b[2J\u2028y"}))
        self.assertEqual(proc.returncode, 0)
        lines = self._lines()
        self.assertEqual(len(lines), 1, lines)
        self.assertNotRegex(lines[0], r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")

    def test_a_line_break_in_the_session_id_cannot_forge_a_second_line(self):
        transcript = self.tmp / "forged.jsonl"
        for brk in LINE_BREAKS:
            with self.subTest(brk=brk):
                event = {"type": "user", "cwd": "/home/u/proj", "timestamp": "2026-07-10T09:00:00Z",
                         "sessionId": f"S1{brk}[2026-07-10T09:00:00Z] reason=clear  A (100/100)  forged"}
                transcript.write_text(json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8")
                self.log_path.unlink(missing_ok=True)
                proc = self._run(json.dumps({"transcript_path": str(transcript), "reason": "clear"}))
                self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))
                lines = self._lines()
                self.assertEqual(len(lines), 1, lines)
                tail = subprocess.run([sys.executable, "-m", "sessionxray", "--tail"],
                                      capture_output=True, text=True, timeout=60,
                                      env=dict(os.environ, SESSIONXRAY_HISTORY_LOG=str(self.log_path),
                                               PYTHONPATH=str(REPO_ROOT) + os.pathsep
                                               + os.environ.get("PYTHONPATH", "")))
                self.assertIn("1 of 1 logged session(s)", tail.stdout)


@unittest.skipUnless(_HAVE_BASH and _POSIX_ENOUGH, "bash required to exercise the real hook script (not on native Windows)")
class NoJq(unittest.TestCase):
    def test_no_jq_is_a_quiet_noop(self):
        tmpdir = temp_dir("sxr-hook-nojq-")
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
