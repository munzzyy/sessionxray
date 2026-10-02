"""Scan orchestration: parse a transcript, run every rule, aggregate, grade."""

from __future__ import annotations

import dataclasses

from .discovery import NO_HOME, discover_sessions, parse_session, subagent_transcripts, subagent_type
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


def _filter_by_rule(findings: list, select, ignore) -> list:
    """Keep only what --select/--ignore asked for. `select`, when given, is an
    allow-list: everything not in it is dropped. `ignore` is then applied on
    top as a deny-list, so a rule id in both never reports (select wins the
    inclusion, ignore wins the exclusion). Filtering happens before grading,
    so a rule someone has decided is a false positive for their workflow
    doesn't cost them their grade either."""
    if select:
        findings = [f for f in findings if f.rule_id in select]
    if ignore:
        findings = [f for f in findings if f.rule_id not in ignore]
    return findings


def scan_session(path, project_root_override=None, select=None, ignore=None,
                 include_subagents=True) -> SessionResult:
    """Scan one transcript and, unless told not to, the subagent transcripts
    stored beside it. Each subagent is parsed on its own so its event indices
    and root inference stay its own; its findings join the session's grade."""
    parsed = parse_session(path)
    if project_root_override:
        parsed.project_root = project_root_override
    findings = _collapse_repeats(run_all(parsed))
    hosts = set(network.contacted_hosts(parsed))
    event_count = parsed.event_count
    tool_call_count = len(parsed.tool_calls)
    skipped = parsed.skipped_lines
    truncated = parsed.truncated_results
    subagents = []

    for sub_path in (subagent_transcripts(path) if include_subagents else []):
        try:
            sub = parse_session(sub_path)
        except OSError:
            continue
        sub.project_root = project_root_override or sub.project_root or parsed.project_root
        if sub.home == NO_HOME:
            sub.home = parsed.home
        agent_id = sub.agent_id or sub_path.stem[len("agent-"):]
        findings.extend(dataclasses.replace(f, agent_id=agent_id)
                        for f in _collapse_repeats(run_all(sub)))
        hosts.update(network.contacted_hosts(sub))
        event_count += sub.event_count
        tool_call_count += len(sub.tool_calls)
        skipped += sub.skipped_lines
        truncated += sub.truncated_results
        subagents.append({"agent_id": agent_id, "agent_type": subagent_type(sub_path),
                          "path": str(sub_path)})

    findings = _filter_by_rule(findings, select, ignore)
    findings.sort(key=lambda f: f.sort_key())
    g, score = grade(findings)
    return SessionResult(
        path=parsed.path,
        session_id=parsed.session_id,
        project_root=parsed.project_root,
        findings=findings,
        network_hosts=sorted(hosts),
        event_count=event_count,
        tool_call_count=tool_call_count,
        skipped_lines=skipped,
        truncated_results=truncated,
        first_ts=parsed.first_ts,
        last_ts=parsed.last_ts,
        grade=g,
        grade_score=score,
        subagents=subagents,
    )


def scan_targets(targets, project_root_override=None, select=None, ignore=None) -> list:
    """Resolve CLI targets to session files and scan each one."""
    return [scan_session(p, project_root_override, select=select, ignore=ignore)
            for p in discover_sessions(targets)]
