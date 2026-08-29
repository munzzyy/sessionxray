"""Live tailing: poll a directory of session transcripts for new activity and
surface only what changed since the last look.

sessionxray otherwise only reads what is already on disk when it is invoked --
a forensic, after-the-fact tool. This is the same shape as COLE-OS's own
inbox-watch loop, applied to session transcripts: no inotify dependency,
just mtime polling, so it runs anywhere sessionxray already runs.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from .scanner import scan_session


@dataclass
class WatchState:
    """What poll() has already reported, so a later call surfaces only the
    delta. A fresh WatchState (the first poll) reports every finding present
    in every file under the watched directory -- there is no earlier baseline
    to diff against yet."""

    mtimes: dict = field(default_factory=dict)  # str(path) -> mtime last scanned at
    seen: set = field(default_factory=set)  # (path, rule_id, event_index) already reported


def _list_jsonl(directory) -> list:
    found = []
    for dirpath, _dirnames, filenames in os.walk(directory):
        for fn in filenames:
            if fn.lower().endswith(".jsonl"):
                found.append(os.path.join(dirpath, fn))
    return sorted(found)


def poll(directory, state: WatchState, project_root_override=None, select=None, ignore=None) -> list:
    """Rescan every .jsonl file under `directory` whose mtime has advanced
    since the last call, and return the findings new since the last time each
    file was scanned. Deduped by (path, rule_id, event_index), so a file
    rescanned because a later line was appended doesn't re-report findings
    already reported from its earlier lines.

    A missing directory is not an error -- it just means nothing to report
    yet, which matters the first time this points at a fresh ~/.claude/projects
    on a machine that has not run a session yet. Returns a list of
    (path, Finding) pairs, oldest changed file first.
    """
    new_items = []
    if not os.path.isdir(directory):
        return new_items

    for path in _list_jsonl(directory):
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if mtime <= state.mtimes.get(path, -1.0):
            continue
        state.mtimes[path] = mtime

        try:
            result = scan_session(path, project_root_override, select=select, ignore=ignore)
        except OSError:
            continue

        for f in result.findings:
            key = (path, f.rule_id, f.event_index)
            if key in state.seen:
                continue
            state.seen.add(key)
            new_items.append((path, f))

    return new_items


def run_watch(directory, interval=2.0, max_cycles=None, project_root_override=None,
              select=None, ignore=None, on_findings=None, sleep=time.sleep) -> None:
    """Poll `directory` on a loop, calling `on_findings(path, finding)` for
    each finding new since the previous poll. Runs forever when `max_cycles`
    is None (the CLI default); a caller that wants a bounded run instead of a
    daemon -- a test, or a scripted "watch for a minute" check -- passes a
    cycle count instead."""
    state = WatchState()
    cycles = 0
    while max_cycles is None or cycles < max_cycles:
        for path, finding in poll(directory, state, project_root_override, select, ignore):
            if on_findings is not None:
                on_findings(path, finding)
        cycles += 1
        if max_cycles is None or cycles < max_cycles:
            sleep(interval)
