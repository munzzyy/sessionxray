"""SXR-000: transcript integrity. A grade only means something if the parser
could actually read the transcript. When a session produced no readable tool
calls but did have lines the parser had to skip, the "clean A" that falls out
of an empty finding list reflects nothing about what the agent did -- so say so
explicitly, in every output including --summary and --json, rather than letting
an unreadable file log as genuinely clean.
"""

from __future__ import annotations

from ..discovery import ParsedSession
from ..finding import Category, Finding, Severity

RULE_ID = "SXR-000"


def check(session: ParsedSession) -> list:
    if session.tool_calls or not session.skipped_lines:
        return []
    n = session.skipped_lines
    return [Finding(
        rule_id=RULE_ID,
        category=Category.INTEGRITY,
        severity=Severity.INFO,
        title="Transcript unreadable",
        detail=f"No tool calls could be parsed and {n} line(s) were skipped. This grade "
               "reflects nothing about the session's behavior -- treat it as no result, not a pass.",
        remediation="Check that the target is a Claude Code JSONL transcript and not truncated "
                    "or a different format.",
    )]
