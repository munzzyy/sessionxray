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
from unittest import mock

from sessionxray import cli
from sessionxray.scanner import scan_session
from sessionxray.watch import WatchState, baseline, poll, run_watch
from tests._helpers import assistant_event, write_session

FIXTURES = Path(__file__).parent / "fixtures"
QUIET_LINE = '{"type": "user", "message": {"role": "user", "content": "keep going"}}\n'


def _append_first_line_of(name, path):
    with open(FIXTURES / "malicious" / name, encoding="utf-8") as fh:
        line = fh.readline()
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)


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

    def test_subagent_findings_are_reported_once_under_their_own_file(self):
        shutil.copytree(FIXTURES / "subagents", os.path.join(self.dir, "s"))
        items = poll(self.dir, WatchState())
        self.assertEqual(sorted(os.path.basename(p) for p, _f in items),
                         ["agent-a1.jsonl", "agent-a1.jsonl", "agent-b2.jsonl"])

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


class Baseline(unittest.TestCase):
    """--watch starts from now: what was already on disk is not reported."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = os.path.join(self.dir, "a.jsonl")
        shutil.copy(FIXTURES / "malicious" / "destructive.jsonl", self.path)

    def test_nothing_on_disk_is_reported_and_nothing_is_scanned(self):
        state = WatchState()
        with mock.patch("sessionxray.watch.scan_session") as scan:
            baseline(self.dir, state)
            self.assertEqual(poll(self.dir, state), [])
        scan.assert_not_called()

    def test_an_append_after_the_baseline_reports_only_the_new_finding(self):
        with open(self.path, "rb") as fh:
            old_lines = fh.read().count(b"\n")
        state = WatchState()
        baseline(self.dir, state)
        _append_first_line_of("secrets.jsonl", self.path)
        items = poll(self.dir, state)
        self.assertTrue(items)
        self.assertEqual({f.event_index for _p, f in items}, {old_lines})
        _append_first_line_of("persistence.jsonl", self.path)
        later = poll(self.dir, state)
        self.assertTrue(later)
        self.assertEqual({f.event_index for _p, f in later}, {old_lines + 1})

    def test_a_file_created_after_the_baseline_is_reported_in_full(self):
        state = WatchState()
        baseline(self.dir, state)
        shutil.copy(FIXTURES / "malicious" / "secrets.jsonl", os.path.join(self.dir, "b.jsonl"))
        items = poll(self.dir, state)
        expected = scan_session(os.path.join(self.dir, "b.jsonl"), include_subagents=False).findings
        self.assertEqual(len(items), len(expected))
        self.assertTrue(all(p.endswith("b.jsonl") for p, _f in items))

    def test_a_finding_tied_to_no_event_is_reported_for_a_new_file(self):
        state = WatchState()
        baseline(self.dir, state)
        with open(os.path.join(self.dir, "b.jsonl"), "w", encoding="utf-8") as fh:
            fh.write("not json\nstill not json\n")
        self.assertEqual([f.rule_id for _p, f in poll(self.dir, state)], ["SXR-000"])

    def test_a_file_rewritten_shorter_is_reported_in_full(self):
        state = WatchState()
        baseline(self.dir, state)
        with open(FIXTURES / "malicious" / "secrets.jsonl", encoding="utf-8") as fh:
            first = fh.readline()
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(first)
        items = poll(self.dir, state)
        self.assertEqual({f.event_index for _p, f in items}, {0})

    def test_a_file_rewritten_shorter_after_a_poll_is_reported_in_full(self):
        state = WatchState()
        baseline(self.dir, state)
        _append_first_line_of("secrets.jsonl", self.path)
        self.assertTrue(poll(self.dir, state))
        with open(FIXTURES / "malicious" / "persistence.jsonl", encoding="utf-8") as fh:
            first = fh.readline()
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(first)
        self.assertEqual({f.event_index for _p, f in poll(self.dir, state)}, {0})

    def test_a_file_empty_at_the_baseline_is_reported_in_full(self):
        empty = os.path.join(self.dir, "b.jsonl")
        open(empty, "w").close()
        state = WatchState()
        baseline(self.dir, state)
        with open(empty, "w", encoding="utf-8") as fh:
            fh.write("not json\nstill not json\n")
        self.assertEqual([f.rule_id for _p, f in poll(self.dir, state)], ["SXR-000"])

    def test_nothing_older_than_the_baseline_turns_up_on_a_later_poll(self):
        state = WatchState()
        baseline(self.dir, state)
        for _ in range(2):
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(QUIET_LINE)
            self.assertEqual(poll(self.dir, state), [])

    def test_a_repeat_of_a_finding_older_than_the_baseline_is_reported(self):
        _append_first_line_of("secrets.jsonl", self.path)
        with open(self.path, "rb") as fh:
            old_lines = fh.read().count(b"\n")
        state = WatchState()
        baseline(self.dir, state)
        _append_first_line_of("secrets.jsonl", self.path)
        items = poll(self.dir, state)
        expected = {(f.rule_id, f.title, f.evidence) for f in scan_session(self.path).findings
                    if old_lines in (f.event_index,) + f.also_at}
        self.assertIn("SXR-003", {rule for rule, _t, _e in expected})
        self.assertEqual({(f.rule_id, f.title, f.evidence) for _p, f in items}, expected)
        self.assertEqual({f.event_index for _p, f in items}, {old_lines})
        _append_first_line_of("secrets.jsonl", self.path)
        self.assertEqual(poll(self.dir, state), [])


class RunWatch(unittest.TestCase):
    def test_bounded_run_calls_the_callback_and_returns(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        shutil.copy(FIXTURES / "malicious" / "secrets.jsonl", os.path.join(d, "a.jsonl"))

        seen = []
        sleeps = []
        run_watch(d, interval=0.01, max_cycles=2, on_findings=lambda p, f: seen.append(f),
                  sleep=sleeps.append, replay=True)

        self.assertTrue(seen)
        # Two cycles means exactly one sleep in between, never a trailing one.
        self.assertEqual(sleeps, [0.01])

    def test_findings_already_on_disk_are_not_reported(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        shutil.copy(FIXTURES / "malicious" / "secrets.jsonl", os.path.join(d, "a.jsonl"))
        seen = []
        run_watch(d, max_cycles=1, on_findings=lambda p, f: seen.append(f), sleep=lambda s: None)
        self.assertEqual(seen, [])
        run_watch(d, max_cycles=1, on_findings=lambda p, f: seen.append(f), sleep=lambda s: None,
                  replay=True)
        self.assertTrue(seen)

    def test_lines_written_while_watching_are_reported(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "a.jsonl")
        shutil.copy(FIXTURES / "malicious" / "destructive.jsonl", path)
        with open(path, "rb") as fh:
            old_lines = fh.read().count(b"\n")
        seen = []
        run_watch(d, max_cycles=2, on_findings=lambda p, f: seen.append(f),
                  sleep=lambda s: _append_first_line_of("secrets.jsonl", path))
        self.assertTrue(seen)
        self.assertEqual({f.event_index for f in seen}, {old_lines})

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
                               "--watch-interval", "0", "--no-color", "--watch-replay"])
        self.assertEqual(code, 0)
        self.assertIn("SXR-003", out)
        self.assertIn("watching", out)

    def test_watch_starts_from_now(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        shutil.copy(FIXTURES / "malicious" / "secrets.jsonl", os.path.join(d, "a.jsonl"))
        code, out = self._run(["--watch", d, "--watch-max-cycles", "1", "--no-color"])
        self.assertEqual(code, 0)
        self.assertEqual(out.splitlines(), [f"sessionxray: watching {d} (every 2s, ctrl-c to stop)"])

    def test_watch_replay_needs_watch(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main([str(FIXTURES / "benign" / "benign-session.jsonl"), "--watch-replay"])
        self.assertEqual(code, 2)
        self.assertIn("--watch-replay", err.getvalue())

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
                               "--no-color", "--select", "SXR-004", "--watch-replay"])
        self.assertEqual(code, 0)
        self.assertIn("SXR-004", out)
        self.assertNotIn("SXR-003", out)


if __name__ == "__main__":
    unittest.main()
