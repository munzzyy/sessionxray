"""Tests for sessionxray.discovery: reading a transcript's events into
ToolCall/ToolResultText, and finding session files on disk."""

import json
import tempfile
import unittest
from pathlib import Path

from sessionxray.discovery import discover_sessions, parse_session
from tests._helpers import DEFAULT_ROOT, assistant_event, result_event, write_session


class ParseToolCalls(unittest.TestCase):
    def test_bash_command_extracted(self):
        events = [assistant_event(0, "Bash", {"command": "echo hi"})]
        parsed = parse_session(write_session(events))
        self.assertEqual(len(parsed.tool_calls), 1)
        self.assertEqual(parsed.tool_calls[0].tool_name, "Bash")
        self.assertEqual(parsed.tool_calls[0].input["command"], "echo hi")

    def test_read_write_edit_extracted(self):
        events = [
            assistant_event(0, "Read", {"file_path": "/a/b.py"}),
            assistant_event(1, "Write", {"file_path": "/a/c.py", "content": "x"}),
            assistant_event(2, "Edit", {"file_path": "/a/d.py", "old_string": "x", "new_string": "y"}),
        ]
        parsed = parse_session(write_session(events))
        names = [tc.tool_name for tc in parsed.tool_calls]
        self.assertEqual(names, ["Read", "Write", "Edit"])

    def test_top_level_tool_use_without_message_wrapper(self):
        # A defensively-supported irregular shape: no "message" envelope at all.
        events = [{"type": "tool_use", "name": "Bash", "input": {"command": "ls"}, "cwd": DEFAULT_ROOT}]
        parsed = parse_session(write_session(events))
        self.assertEqual(len(parsed.tool_calls), 1)
        self.assertEqual(parsed.tool_calls[0].input["command"], "ls")

    def test_alternate_field_names_params_and_tool(self):
        events = [{
            "type": "assistant",
            "cwd": DEFAULT_ROOT,
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "tool": "Bash", "params": {"command": "whoami"}}
            ]},
        }]
        parsed = parse_session(write_session(events))
        self.assertEqual(len(parsed.tool_calls), 1)
        self.assertEqual(parsed.tool_calls[0].input["command"], "whoami")


class ParseToolResults(unittest.TestCase):
    def test_content_list_text_extracted(self):
        events = [
            assistant_event(0, "Read", {"file_path": "/a/b.py"}),
            result_event(0, "tu_0", text="file contents here"),
        ]
        parsed = parse_session(write_session(events))
        self.assertEqual(len(parsed.tool_results), 1)
        self.assertIn("file contents here", parsed.tool_results[0].text)

    def test_tool_use_result_stdout_extracted(self):
        events = [
            assistant_event(0, "Bash", {"command": "echo hi"}),
            result_event(0, "tu_0", stdout="hi\n"),
        ]
        parsed = parse_session(write_session(events))
        self.assertEqual(len(parsed.tool_results), 1)
        self.assertIn("hi", parsed.tool_results[0].text)

    def test_result_correlated_to_tool_name(self):
        events = [
            assistant_event(0, "WebFetch", {"url": "https://example.test"}),
            result_event(0, "tu_0", text="page contents"),
        ]
        parsed = parse_session(write_session(events))
        self.assertEqual(parsed.tool_results[0].tool_name, "WebFetch")


class ProjectRootInference(unittest.TestCase):
    def test_majority_cwd_wins(self):
        events = [
            assistant_event(0, "Bash", {"command": "a"}, cwd="/home/x/proj"),
            assistant_event(1, "Bash", {"command": "b"}, cwd="/home/x/proj"),
            assistant_event(2, "Bash", {"command": "c"}, cwd="/tmp/scratch"),
        ]
        parsed = parse_session(write_session(events))
        self.assertEqual(parsed.project_root, "/home/x/proj")

    def test_no_cwd_gives_empty_root(self):
        events = [{"type": "assistant", "message": {"role": "assistant",
                  "content": [{"type": "tool_use", "id": "t", "name": "Bash", "input": {"command": "x"}}]}}]
        parsed = parse_session(write_session(events))
        self.assertEqual(parsed.project_root, "")


class MalformedLines(unittest.TestCase):
    def test_bad_json_is_skipped_not_raised(self):
        lines = ["not json {{", json.dumps(assistant_event(0, "Bash", {"command": "ok"}))]
        parsed = parse_session(write_session(lines))
        self.assertEqual(parsed.skipped_lines, 1)
        self.assertEqual(len(parsed.tool_calls), 1)

    def test_non_dict_json_is_skipped(self):
        lines = ["42", "null", "[1, 2]", '"a string"']
        parsed = parse_session(write_session(lines))
        self.assertEqual(parsed.skipped_lines, 4)
        self.assertEqual(parsed.event_count, 4)

    def test_blank_lines_are_not_counted_as_events(self):
        lines = ["", "  ", json.dumps(assistant_event(0, "Bash", {"command": "ok"}))]
        parsed = parse_session(write_session(lines))
        self.assertEqual(parsed.event_count, 1)

    def test_oversized_line_is_skipped(self):
        huge = json.dumps({"type": "assistant", "junk": "x" * 6_000_000})
        parsed = parse_session(write_session([huge]))
        self.assertEqual(parsed.skipped_lines, 1)
        self.assertEqual(parsed.tool_calls, [])

    def test_session_id_falls_back_to_filename(self):
        tmp = Path(tempfile.mkdtemp())
        path = tmp / "abc123.jsonl"
        event = {"type": "assistant", "message": {"role": "assistant",
                 "content": [{"type": "tool_use", "id": "t", "name": "Bash", "input": {"command": "x"}}]}}
        path.write_text(json.dumps(event) + "\n", encoding="utf-8")
        parsed = parse_session(path)
        self.assertEqual(parsed.session_id, "abc123")


class Discovery(unittest.TestCase):
    def test_single_file_target(self):
        path = write_session([assistant_event(0, "Bash", {"command": "x"})])
        found = discover_sessions([str(path)])
        self.assertEqual(len(found), 1)
        self.assertEqual(Path(found[0]).name, path.name)

    def test_directory_is_walked_recursively(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "sub").mkdir()
        (tmp / "a.jsonl").write_text("{}\n", encoding="utf-8")
        (tmp / "sub" / "b.jsonl").write_text("{}\n", encoding="utf-8")
        (tmp / "ignore.txt").write_text("nope", encoding="utf-8")
        found = discover_sessions([str(tmp)])
        self.assertEqual(len(found), 2)

    def test_glob_target(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "one.jsonl").write_text("{}\n", encoding="utf-8")
        (tmp / "two.jsonl").write_text("{}\n", encoding="utf-8")
        found = discover_sessions([str(tmp / "*.jsonl")])
        self.assertEqual(len(found), 2)

    def test_nonexistent_target_yields_nothing(self):
        found = discover_sessions(["/no/such/path/anywhere.jsonl"])
        self.assertEqual(found, [])

    def test_dedupes_overlapping_targets(self):
        path = write_session([assistant_event(0, "Bash", {"command": "x"})])
        found = discover_sessions([str(path), str(path.parent)])
        self.assertEqual(len(found), 1)


if __name__ == "__main__":
    unittest.main()
