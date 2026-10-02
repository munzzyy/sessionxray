"""Live tailing: poll a directory of session transcripts for new activity and
surface only what changed since the last look.

sessionxray otherwise only reads what is already on disk when it is invoked --
a forensic, after-the-fact tool. This polls instead of using inotify, so it
runs anywhere sessionxray already runs.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from .scanner import _collapse_repeats, scan_session


@dataclass
class WatchState:
    """What poll() has already reported, so a later call surfaces only the
    delta. Without a baseline() first, the first poll reports every finding
    present in every file under the watched directory."""

    stamps: dict = field(default_factory=dict)  # str(path) -> (st_mtime_ns, st_size) last scanned at
    seen: set = field(default_factory=set)  # (path, rule_id, event_index, title, evidence) already reported
    baseline_sizes: dict = field(default_factory=dict)  # str(path) -> st_size at baseline, not reported


def _list_jsonl(directory) -> list:
    found = []
    for dirpath, _dirnames, filenames in os.walk(directory):
        for fn in filenames:
            if fn.lower().endswith(".jsonl"):
                found.append(os.path.join(dirpath, fn))
    return sorted(found)


def baseline(directory, state: WatchState) -> None:
    """Mark every file already under `directory` as seen up to its current
    size, without scanning it, so the next poll() reports only what is
    written from now on."""
    if not os.path.isdir(directory):
        return
    for path in _list_jsonl(directory):
        try:
            st = os.stat(path)
        except OSError:
            continue
        state.stamps[path] = (st.st_mtime_ns, st.st_size)
        state.baseline_sizes[path] = st.st_size


def _lines_before(path, size: int) -> int:
    """Newlines in the first `size` bytes, which is the event index of the first line written after them."""
    count = 0
    with open(path, "rb") as fh:
        while size > 0:
            chunk = fh.read(min(size, 1 << 20))
            if not chunk:
                break
            count += chunk.count(b"\n")
            size -= len(chunk)
    return count


def poll(directory, state: WatchState, project_root_override=None, select=None, ignore=None) -> list:
    """Rescan every .jsonl file under `directory` whose mtime or size has
    changed since the last call, and return the findings new since the last
    time each file was scanned. Deduped by (path, rule_id, event_index, title,
    evidence), so a file rescanned because a later line was appended doesn't
    re-report findings already reported from its earlier lines, and two
    findings one event raised under the same rule both get reported.

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
            st = os.stat(path)
        except OSError:
            continue
        # An append inside the mtime granularity leaves mtime unchanged; size catches it.
        stamp = (st.st_mtime_ns, st.st_size)
        last = state.stamps.get(path)
        if last == stamp:
            continue
        state.stamps[path] = stamp
        if last is not None and st.st_size < last[1]:
            # A file that shrank was rewritten, so none of it is known to predate the baseline.
            state.baseline_sizes.pop(path, None)

        base = state.baseline_sizes.get(path)
        try:
            # Every agent-*.jsonl is polled as a file of its own, so folding
            # subagents into their parent here would report them twice.
            result = scan_session(path, project_root_override, select=select, ignore=ignore,
                                  include_subagents=False, collapse=False)
            findings = result.findings
            if base:
                floor = _lines_before(path, base)
                findings = [f for f in findings if f.event_index >= floor]
        except OSError:
            continue

        # Fold repeats after the cut, so a pattern older than the baseline shows at its first new event.
        for f in _collapse_repeats(findings):
            key = (path, f.rule_id, f.event_index, f.title, f.evidence)
            if key in state.seen:
                continue
            state.seen.add(key)
            new_items.append((path, f))

    return new_items


def run_watch(directory, interval=2.0, max_cycles=None, project_root_override=None,
              select=None, ignore=None, on_findings=None, sleep=time.sleep, replay=False) -> None:
    """Poll `directory` on a loop, calling `on_findings(path, finding)` for
    each finding new since the previous poll. Runs forever when `max_cycles`
    is None (the CLI default); a caller that wants a bounded run instead of a
    daemon -- a test, or a scripted "watch for a minute" check -- passes a
    cycle count instead. Findings already on disk when the watch starts are
    skipped unless `replay` is set."""
    state = WatchState()
    if not replay:
        baseline(directory, state)
    cycles = 0
    while max_cycles is None or cycles < max_cycles:
        for path, finding in poll(directory, state, project_root_override, select, ignore):
            if on_findings is not None:
                on_findings(path, finding)
        cycles += 1
        if max_cycles is None or cycles < max_cycles:
            sleep(interval)
