"""Shared test helpers: build a synthetic session transcript in memory and
scan it, without needing a fixture file on disk for every small unit test.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from sessionxray.finding import Category
from sessionxray.scanner import scan_session

DEFAULT_ROOT = "/home/testuser/widget-app"
DEFAULT_SID = "TESTSESSION"


def assistant_event(idx, tool_name, tool_input, cwd=DEFAULT_ROOT, tool_use_id=None):
    return {
        "type": "assistant",
        "cwd": cwd,
        "sessionId": DEFAULT_SID,
        "timestamp": f"2026-07-10T09:{idx:02d}:00Z",
        "message": {
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": tool_use_id or f"tu_{idx}", "name": tool_name, "input": tool_input}
            ],
        },
    }


def result_event(idx, tool_use_id, text=None, stdout=None, cwd=DEFAULT_ROOT):
    event = {
        "type": "user",
        "cwd": cwd,
        "sessionId": DEFAULT_SID,
        "timestamp": f"2026-07-10T09:{idx:02d}:30Z",
        "message": {
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": [{"type": "text", "text": text}] if text is not None else [],
            }],
        },
    }
    if stdout is not None:
        event["toolUseResult"] = {"stdout": stdout, "stderr": "", "interrupted": False}
    return event


def write_session(events: list) -> Path:
    tmp = tempfile.mkdtemp(prefix="sxr-test-")
    path = Path(tmp) / "session.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for e in events:
            if isinstance(e, str):
                fh.write(e)
            else:
                fh.write(json.dumps(e))
            fh.write("\n")
    return path


def scan_events(events: list, project_root_override=None):
    return scan_session(write_session(events), project_root_override)


def one_call(tool_name, tool_input, *, cwd=DEFAULT_ROOT, stdout=None, text=None, project_root_override=None):
    """Scan a session containing exactly one tool call and its result."""
    events = [
        assistant_event(0, tool_name, tool_input, cwd=cwd),
        result_event(0, "tu_0", text=text, stdout=stdout, cwd=cwd),
    ]
    return scan_events(events, project_root_override=project_root_override)


def one_result(tool_name, tool_input, result_text, *, cwd=DEFAULT_ROOT):
    """Scan a session with one tool call whose *result* is the interesting part
    (for the injection-footprint rule, which only looks at results)."""
    return one_call(tool_name, tool_input, cwd=cwd, text=result_text)


def by_cat(result, cat: Category):
    return [f for f in result.findings if f.category == cat]


def by_rule(result, rule_id: str):
    return [f for f in result.findings if f.rule_id == rule_id]


def titles(result):
    return [f.title for f in result.findings]
