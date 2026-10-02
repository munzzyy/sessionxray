"""--watch: polling a directory for new/changed sessions and reporting only
the delta since the last look."""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sessionxray import cli
from sessionxray.scanner import scan_session
from sessionxray.watch import WatchState, poll, run_watch
from tests._helpers import assistant_event, write_session

FIXTURES = Path(__file__).parent / "fixtures"


class Poll(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _copy(self, name, dest="a.jsonl"):
        shutil.copy(FIXTURES / "malicious" / name, os.path.join(self.dir, dest))

    def test_missing_directory_returns_nothing(self):
        state = WatchState()
        self.assertEqual(poll("/no/such/directory/anywhere", state), [])

    def test_empty_directory_returns_nothing(self):
        state = WatchState()
        self.assertEqual(poll(self.dir, state), [])

    def test_first_poll_reports_every_finding_present(self):
        self._copy("secrets.jsonl")
        state = WatchState()
        items = poll(self.dir, state)
        self.assertTrue(items)
        self.assertTrue(all(path.endswith("a.jsonl") for path, _f in items))

    def test_second_poll_with_no_change_reports_nothing_new(self):
        self._copy("secrets.jsonl")
        state = WatchState()
        poll(self.dir, state)
        self.assertEqual(poll(self.dir, state), [])

    def test_touching_the_file_without_changing_content_reports_nothing_new(self):
        # Re-scanning because mtime moved should not re-report findings that
        # were already reported from the same lines.
        self._copy("secrets.jsonl")
        state = WatchState()
        poll(self.dir, state)
        path = os.path.join(self.dir, "a.jsonl")
        os.utime(path, None)
        self.assertEqual(poll(self.dir, state), [])

    def test_appending_a_new_line_reports_only_the_new_finding(self):
        self._copy("destructive.jsonl")
        state = WatchState()
        first = poll(self.dir, state)
        self.assertTrue(first)
        path = os.path.join(self.dir, "a.jsonl")
        with open(FIXTURES / "malicious" / "secrets.jsonl", encoding="utf-8") as fh:
            extra_line = fh.readline()
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(extra_line)
        second = poll(self.dir, state)
        self.assertTrue(second)
        first_keys = {(p, f.rule_id, f.event_index) for p, f in first}
        second_keys = {(p, f.rule_id, f.event_index) for p, f in second}
        self.assertTrue(second_keys.isdisjoint(first_keys))

    def test_an_append_that_keeps_the_same_mtime_is_still_seen(self):
        # Windows CI hit this: the append landed inside the mtime granularity.
        self._copy("destructive.jsonl")
        path = os.path.join(self.dir, "a.jsonl")
        state = WatchState()
        self.assertTrue(poll(self.dir, state))
        prev = os.stat(path).st_mtime_ns
        with open(FIXTURES / "malicious" / "secrets.jsonl", encoding="utf-8") as fh:
            extra_line = fh.readline()
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(extra_line)
        os.utime(path, ns=(prev, prev))
        self.assertTrue(poll(self.dir, state))

    def test_findings_sharing_a_rule_and_event_are_all_reported(self):
        cmd = "cp /etc/hosts /srv/www/hosts && cat ~/.ssh/config; echo $GITHUB_TOKEN"
        src = write_session([assistant_event(0, "Bash", {"command": cmd})])
        self.addCleanup(shutil.rmtree, src.parent, ignore_errors=True)
        path = os.path.join(self.dir, "a.jsonl")
        shutil.copy(src, path)
        expected = scan_session(path).findings
        self.assertEqual(len(expected), 4)
        self.assertEqual(len(poll(self.dir, WatchState())), len(expected))

    def test_select_and_ignore_are_honored(self):
        self._copy("secrets.jsonl")
        state = WatchState()
        items = poll(self.dir, state, select={"SXR-004"})
        self.assertEqual({f.rule_id for _p, f in items}, {"SXR-004"})

    def test_a_second_file_is_picked_up_independently(self):
        self._copy("secrets.jsonl", "a.jsonl")
        state = WatchState()
        poll(self.dir, state)
        self._copy("destructive.jsonl", "b.jsonl")
        second = poll(self.dir, state)
        self.assertTrue(all(path.endswith("b.jsonl") for path, _f in second))


class RunWatch(unittest.TestCase):
    def test_bounded_run_calls_the_callback_and_returns(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        shutil.copy(FIXTURES / "malicious" / "secrets.jsonl", os.path.join(d, "a.jsonl"))

        seen = []
        sleeps = []
        run_watch(d, interval=0.01, max_cycles=2, on_findings=lambda p, f: seen.append(f),
                  sleep=sleeps.append)

        self.assertTrue(seen)
        # Two cycles means exactly one sleep in between, never a trailing one.
        self.assertEqual(sleeps, [0.01])

    def test_zero_cycles_does_nothing(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        calls = []
        run_watch(d, max_cycles=0, on_findings=lambda p, f: calls.append(f), sleep=calls.append)
        self.assertEqual(calls, [])


class WatchCLI(unittest.TestCase):
    def _run(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(argv)
        return code, out.getvalue()

    def test_watch_prints_findings_and_exits_zero(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        shutil.copy(FIXTURES / "malicious" / "secrets.jsonl", os.path.join(d, "a.jsonl"))
        code, out = self._run(["--watch", d, "--watch-max-cycles", "1",
                               "--watch-interval", "0", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("SXR-003", out)
        self.assertIn("watching", out)

    def test_watch_defaults_to_the_claude_projects_directory(self):
        args = cli.build_parser().parse_args(["--watch"])
        self.assertEqual(args.watch, str(Path.home() / ".claude" / "projects"))

    def test_watch_rejects_targets_given_at_the_same_time(self):
        code, _ = self._run([str(FIXTURES / "benign" / "benign-session.jsonl"), "--watch"])
        self.assertEqual(code, 2)

    def test_watch_conflicts_with_json(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["--watch", "--json"])

    def test_watch_honors_select(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        shutil.copy(FIXTURES / "malicious" / "secrets.jsonl", os.path.join(d, "a.jsonl"))
        code, out = self._run(["--watch", d, "--watch-max-cycles", "1", "--watch-interval", "0",
                               "--no-color", "--select", "SXR-004"])
        self.assertEqual(code, 0)
        self.assertIn("SXR-004", out)
        self.assertNotIn("SXR-003", out)


if __name__ == "__main__":
    unittest.main()
