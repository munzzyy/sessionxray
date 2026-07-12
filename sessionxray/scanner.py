"""Scan orchestration: parse a transcript, run every rule, aggregate, grade."""

from __future__ import annotations

import dataclasses

from .discovery import discover_sessions, parse_session
from .finding import SessionResult
from .grade import grade
from .rules import run_all
from .rules import network

_MAX_ALSO_AT = 4


def _collapse_repeats(findings: list) -> list:
    """The exact same (rule, title, evidence) at multiple events is one
    underlying pattern seen more than once, not N independent findings --
    rereading the same file five times shouldn't count five times toward the
    grade. Collapse to one Finding per unique triple, noting how many times
    and a few of the event indices it recurred at."""
    order: list = []
    groups: dict = {}
    for f in findings:
        key = (f.rule_id, f.title, f.evidence)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    collapsed = []
    for key in order:
        group = groups[key]
        first = group[0]
        if len(group) == 1:
            collapsed.append(first)
            continue
        extra = sorted({f.event_index for f in group[1:]})[:_MAX_ALSO_AT]
        collapsed.append(dataclasses.replace(first, occurrences=len(group), also_at=tuple(extra)))
    return collapsed


def scan_session(path, project_root_override=None) -> SessionResult:
    parsed = parse_session(path)
    if project_root_override:
        parsed.project_root = project_root_override
    findings = _collapse_repeats(run_all(parsed))
    findings.sort(key=lambda f: f.sort_key())
    g, score = grade(findings)
    return SessionResult(
        path=parsed.path,
        session_id=parsed.session_id,
        project_root=parsed.project_root,
        findings=findings,
        network_hosts=network.contacted_hosts(parsed),
        event_count=parsed.event_count,
        tool_call_count=len(parsed.tool_calls),
        skipped_lines=parsed.skipped_lines,
        first_ts=parsed.first_ts,
        last_ts=parsed.last_ts,
        grade=g,
        grade_score=score,
    )


def scan_targets(targets, project_root_override=None) -> list:
    """Resolve CLI targets to session files and scan each one."""
    return [scan_session(p, project_root_override) for p in discover_sessions(targets)]
