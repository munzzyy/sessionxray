"""Render one or more SessionResults as human text, JSON, or a one-line-per-
session fleet summary."""

from __future__ import annotations

import json

from . import __version__
from .finding import Severity, SessionResult

_COLOR = {
    Severity.CRITICAL: "\033[1;37;41m",  # white on red
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_GRADE_COLOR = {"A": "\033[32m", "B": "\033[32m", "C": "\033[33m",
                "D": "\033[33m", "F": "\033[1;31m"}
_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)

_RULE_ORDER = ["SXR-001", "SXR-002", "SXR-003", "SXR-004", "SXR-005", "SXR-006", "SXR-007"]
_RULE_LABEL = {
    "SXR-001": "filesystem reach outside the project root",
    "SXR-002": "destructive commands",
    "SXR-003": "credential access",
    "SXR-004": "network egress",
    "SXR-005": "remote code execution",
    "SXR-006": "privilege / persistence",
    "SXR-007": "prompt-injection exposure",
}


def render_human(results: list, color: bool = True) -> str:
    if not results:
        return "\n  sessionxray: no session files matched.\n"
    blocks = [_render_one(r, color) for r in results]
    return ("\n" + "-" * 60 + "\n").join(blocks)


def _render_one(result: SessionResult, color: bool) -> str:
    def c(code, s):
        return f"{code}{s}{_RESET}" if color else s

    counts = result.counts()
    total = sum(counts.values())

    lines = ["", f"  sessionxray  {result.session_id}", f"  {result.path}"]
    meta = f"  {result.tool_call_count} tool call(s) across {result.event_count} event(s)"
    if result.skipped_lines:
        meta += f", {result.skipped_lines} unreadable line(s) skipped"
    lines.append(meta)
    if result.project_root:
        lines.append(f"  project root: {result.project_root}")
    lines.append("")

    if not result.findings:
        lines.append(c("\033[32m", "  No findings. Nothing in this transcript tripped a signal."))
        lines.append("")
    else:
        by_rule: dict = {}
        for f in result.findings:
            by_rule.setdefault(f.rule_id, []).append(f)
        for rid in _RULE_ORDER:
            group = by_rule.get(rid)
            if not group:
                continue
            group = sorted(group, key=lambda f: f.sort_key())
            lines.append(f"  -- {rid} {_RULE_LABEL.get(rid, rid)} ({len(group)}) --")
            for f in group:
                tag = c(_COLOR[f.severity], f" {f.severity.label.upper():^8} ")
                title = f.title if f.occurrences <= 1 else f"{f.title}  (seen {f.occurrences}x)"
                lines.append(f"  {tag} {title}")
                loc = f"event #{f.event_index}" + (f" ({f.tool_name})" if f.tool_name else "")
                if f.also_at:
                    more = ", ".join(f"#{i}" for i in f.also_at)
                    loc += f", also at {more}" + (", ..." if f.occurrences - 1 > len(f.also_at) else "")
                lines.append(f"           {loc}")
                lines.append(f"           {f.detail}")
                if f.evidence:
                    lines.append(c("\033[90m", f"           > {f.evidence}"))
                if f.remediation:
                    lines.append(c("\033[90m", f"           fix: {f.remediation}"))
                lines.append("")

    if result.network_hosts:
        lines.append(f"  outbound hosts contacted: {', '.join(result.network_hosts)}")
        lines.append("")

    parts = [c(_COLOR[sev], f"{counts[sev]} {sev.label}") for sev in _SEVERITY_ORDER if counts[sev]]
    summary = "  " + (", ".join(parts) if parts else "0 findings")
    lines.append(summary + f"   ({total} total)")

    gc = _GRADE_COLOR.get(result.grade, "")
    lines.append(f"  Security grade: {c(gc, result.grade)}  ({result.grade_score}/100)")
    lines.append("")
    return "\n".join(lines)


def render_summary(results: list, color: bool = True) -> str:
    def c(code, s):
        return f"{code}{s}{_RESET}" if color else s

    if not results:
        return "  sessionxray: no session files matched."

    lines = []
    for r in results:
        counts = r.counts()
        total = sum(counts.values())
        bits = ", ".join(
            f"{counts[sev]} {sev.label}" for sev in _SEVERITY_ORDER if counts[sev]
        ) or "clean"
        when = r.last_ts or r.first_ts or "-"
        gc = _GRADE_COLOR.get(r.grade, "")
        grade_field = c(gc, f"{r.grade} ({r.grade_score:>3}/100)")
        lines.append(f"  {grade_field}  {bits:<24}  {total:>2} total  {when}  {r.session_id}  {r.path}")
    return "\n".join(lines)


def render_json(results: list) -> str:
    payload = {
        "tool": "sessionxray",
        "version": __version__,
        "sessions": [_session_payload(r) for r in results],
    }
    return json.dumps(payload, indent=2)


def _session_payload(result: SessionResult) -> dict:
    return {
        "path": result.path,
        "session_id": result.session_id,
        "project_root": result.project_root,
        "event_count": result.event_count,
        "tool_call_count": result.tool_call_count,
        "skipped_lines": result.skipped_lines,
        "first_ts": result.first_ts,
        "last_ts": result.last_ts,
        "grade": result.grade,
        "grade_score": result.grade_score,
        "network_hosts": result.network_hosts,
        "counts": {s.label: result.counts()[s] for s in Severity},
        "findings": [
            {
                "rule_id": f.rule_id,
                "category": f.category.value,
                "severity": f.severity.label,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
                "event_index": f.event_index,
                "tool_name": f.tool_name,
                "remediation": f.remediation,
                "occurrences": f.occurrences,
                "also_at": list(f.also_at),
            }
            for f in result.findings
        ],
    }
