"""SXR-002: destructive commands actually run by the agent.

Unlike a static skill scanner looking at example code, everything here came
from a Bash tool call the agent executed. That is a stronger signal than a
pattern match in a document, which is why every hit in this rule is HIGH.
"""

from __future__ import annotations

import re

from ..discovery import ParsedSession
from ..finding import Category, Severity
from ._util import bash_command, classify_tool, mask_quoted, mk

RULE_ID = "SXR-002"
_I = re.IGNORECASE

_PATTERNS = [
    (re.compile(r"\brm\s+-(?=[a-z]*r)(?=[a-z]*f)[a-z]+\b[^\n|;&]*?"
                r"(?:\s/(?:\s|$|['\"])|\s~(?:/|\s|$)|\$HOME|\s/\*|--no-preserve-root)", _I),
     "Destructive recursive delete",
     "A recursive force-delete aimed at a home directory, filesystem root, or a broad glob."),
    (re.compile(r"\bmkfs(?:\.\w+)?\b", _I),
     "Filesystem format command",
     "mkfs rebuilds a filesystem in place, destroying whatever was on it."),
    (re.compile(r"\bdd\b[^\n]*\bof=(?:/dev/|[A-Za-z]:\\\\\.\\\\)", _I),
     "Raw disk write with dd",
     "dd writing to a device node overwrites raw disk contents with no confirmation and no undo."),
    (re.compile(r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b", _I),
     "SQL DROP statement",
     "Drops a table, database, or schema outright."),
    (re.compile(r"\bTRUNCATE\s+TABLE\b", _I),
     "SQL TRUNCATE statement",
     "Empties a table's rows with no way to select which ones."),
    (re.compile(r"(?<!\w)truncate\s+(?:-s\s*0|--size[= ]0)", _I),
     "File truncated to zero bytes",
     "The coreutils truncate command wipes a file's contents in place."),
    (re.compile(r"\bgit\s+reset\s+--hard\b", _I),
     "git reset --hard",
     "Discards uncommitted work and rewrites the working tree with no recovery path."),
    (re.compile(r"\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?\b|(?<!\S)-f\b)", _I),
     "Force push",
     "Force-pushing rewrites remote history; anything only reachable from the old tip is gone for other clones."),
    (re.compile(r"\bchmod\s+(?:-[a-zA-Z]+\s+)*777\b"),
     "World-writable permissions",
     "chmod 777 makes a file or directory writable by anyone on the machine."),
]

_SCRATCH_SUFFIXES = (".log", ".out", ".tmp", ".bak", ".cache")
_CLOBBER_RE = re.compile(r"(?<!>)>(?!>)\s*([^\s|&;<>]+)")
# A clobber target has to look like an actual file: a path, or a bare name
# with a real extension. A lone English word (the kind that turns up right
# after a stray '>' inside HTML or prose) does not count.
_SAFE_TARGET_RE = re.compile(r"^(?:[\w.\-]*/)+[\w.\-]+$|^[\w\-]+\.[A-Za-z0-9]{1,10}$|^[~][\w./\-]*$")


def check(session: ParsedSession) -> list:
    findings: list = []
    seen: set = set()
    for tc in session.tool_calls:
        if classify_tool(tc.tool_name) != "bash":
            continue
        cmd = bash_command(tc)
        if not cmd:
            continue
        for rx, title, detail in _PATTERNS:
            for m in rx.finditer(cmd):
                key = (tc.index, title)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(mk(
                    RULE_ID, Category.DESTRUCTIVE, Severity.HIGH, title, detail,
                    cmd, tc.index, tc.tool_name,
                    "Confirm this was intentional. Scope destructive commands as narrowly as "
                    "possible and prefer a reversible alternative when one exists.",
                ))
        # Quotes are masked only for this specific check: a lone '>' is common
        # incidental noise inside a quoted grep/sed pattern, unlike the more
        # specific multi-word patterns above which don't false-positive that way.
        for m in _CLOBBER_RE.finditer(mask_quoted(cmd)):
            target = m.group(1)
            if _is_scratch_target(target) or not _SAFE_TARGET_RE.match(target):
                continue
            key = (tc.index, "clobber", target)
            if key in seen:
                continue
            seen.add(key)
            findings.append(mk(
                RULE_ID, Category.DESTRUCTIVE, Severity.HIGH,
                "Single-arrow redirect overwrites a file",
                f"'>' truncates {target!r} and replaces it in one step; whatever was there before is gone.",
                cmd, tc.index, tc.tool_name,
                "Use >> to append, write to a new file and diff it, or confirm the target is disposable.",
            ))
    return findings


def _is_scratch_target(target: str) -> bool:
    t = target.lower()
    if t.startswith(("/dev/null", "/dev/stdout", "/dev/stderr")):
        return True
    if "/tmp/" in t or t.startswith("tmp/"):
        return True
    return t.endswith(_SCRATCH_SUFFIXES)
