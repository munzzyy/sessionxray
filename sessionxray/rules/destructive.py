"""SXR-002: destructive commands actually run by the agent.

Unlike a static skill scanner looking at example code, everything here came
from a Bash tool call the agent executed. That is a stronger signal than a
pattern match in a document, which is why the named destructive commands here
are all HIGH.

The one exception is a bare `>` redirect. Overwriting a file is worth noticing
but it is also how an agent writes any file at all, so it is graded by where
the target lands: silent for scratch space, LOW inside the project the session
was working in, MEDIUM for anything else.
"""

from __future__ import annotations

import posixpath
import re

from ..discovery import NO_HOME, ParsedSession
from ..finding import Category, Severity
from ._util import (bash_command, classify_tool, is_scratch_path, is_under, mask_quoted,
                     mcp_command_text, mk, normalize_path, split_bash_segments)

RULE_ID = "SXR-002"
_I = re.IGNORECASE

_PATTERNS = [
    (re.compile(r"\brm\s+-(?=[a-z]*r)(?=[a-z]*f)[a-z]+\b[^\n|;&]*?"
                r"(?:\s/(?:\s|$|['\"])|\s~(?:/|\s|$)|\$HOME|\s/\*|--no-preserve-root)", _I),
     "Destructive recursive delete",
     "A recursive force-delete aimed at a home directory, filesystem root, or a broad glob."),
    # of=/dev/sda on POSIX, or the Windows raw-device path of=\\.\PhysicalDrive0.
    # The old Windows branch required a literal doubled-backslash device path
    # (`X:\\.\\`) that no real command ever produces, so it never fired.
    (re.compile(r"\bdd\b[^\n]*\bof=(?:/dev/|\\\\\.\\|//\./)", _I),
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

# mkfs only formats anything when it is the command being run. Bare-word
# matching flagged `which mkfs.btrfs`, `man mkfs.ext4` and a symlink named
# mkfs.btrfs as filesystem formats.
_MKFS_CMD_RE = re.compile(r"^\s*(?:sudo\s+(?:-\S+\s+)*)?(?:[\w.\-]*/)*mkfs(?:\.\w+)?\b(.*)$", _I)
_MKFS_NO_OP_ARGS_RE = re.compile(r"^(?:\s*(?:--help|-h|--version|-V|--usage))*\s*$", _I)
_CD_RE = re.compile(r"^\s*cd\s+(?:--\s+)?([^\s;&|<>'\"]+)\s*$")


def check(session: ParsedSession) -> list:
    findings: list = []
    seen: set = set()
    root = posixpath.normpath(session.project_root) if session.project_root else None
    home = session.home or NO_HOME

    for tc in session.tool_calls:
        kind = classify_tool(tc.tool_name)
        if kind == "bash":
            cmd = bash_command(tc)
        elif kind == "mcp":
            cmd = mcp_command_text(tc)
        else:
            continue
        if not cmd:
            continue

        def add(key, sev, title, detail, remediation):
            if key in seen:
                return
            seen.add(key)
            findings.append(mk(RULE_ID, Category.DESTRUCTIVE, sev, title, detail,
                                cmd, tc.index, tc.tool_name, remediation))

        for rx, title, detail in _PATTERNS:
            if rx.search(cmd):
                add((tc.index, title), Severity.HIGH, title, detail,
                    "Confirm this was intentional. Scope destructive commands as narrowly as "
                    "possible and prefer a reversible alternative when one exists.")

        # Walk the sub-commands in order so a leading `cd` sets the directory
        # the redirect targets after it actually resolve against. A huge share
        # of real hits are `cd /tmp/scratch && cat > notes.md`, where the target
        # is throwaway and only looks bare because the cd is in another segment.
        base = tc.cwd
        for segment in split_bash_segments(cmd):
            # Quotes are masked only for these checks: a lone '>' is common
            # incidental noise inside a quoted grep/sed pattern, unlike the more
            # specific multi-word patterns above which don't false-positive that way.
            masked = mask_quoted(segment)
            cd = _CD_RE.match(segment)
            if cd:
                moved = normalize_path(cd.group(1), base, home)
                if moved:
                    base = moved
                continue
            if _is_mkfs_command(masked):
                add((tc.index, "Filesystem format command"), Severity.HIGH,
                    "Filesystem format command",
                    "mkfs rebuilds a filesystem in place, destroying whatever was on it.",
                    "Confirm this was intentional. Scope destructive commands as narrowly as "
                    "possible and prefer a reversible alternative when one exists.")
            for m in _CLOBBER_RE.finditer(masked):
                target = m.group(1)
                if not _SAFE_TARGET_RE.match(target) or _is_scratch_target(target):
                    continue
                resolved = normalize_path(target, base, home)
                if resolved and is_scratch_path(resolved):
                    continue
                where = resolved or target
                if resolved and root and is_under(resolved, root):
                    add((tc.index, "clobber", where), Severity.LOW,
                        "Redirect overwrites a file inside the project",
                        f"'>' truncates {where!r} and replaces it in one step. The target is inside "
                        "the project root, so this is ordinary work rather than reach, but whatever "
                        "was there before is gone.",
                        "Use >> to append, or write to a new file and diff it, if the previous "
                        "contents mattered.")
                else:
                    add((tc.index, "clobber", where), Severity.MEDIUM,
                        "Single-arrow redirect overwrites a file",
                        f"'>' truncates {where!r} and replaces it in one step; whatever was there "
                        "before is gone, and the target is outside the project this session was "
                        "working in.",
                        "Use >> to append, write to a new file and diff it, or confirm the target "
                        "is disposable.")
    return findings


def _is_mkfs_command(segment: str) -> bool:
    m = _MKFS_CMD_RE.match(segment)
    if not m:
        return False
    # `mkfs.btrfs --help` prints usage and formats nothing.
    return not _MKFS_NO_OP_ARGS_RE.match(m.group(1))


def _is_scratch_target(target: str) -> bool:
    t = target.lower()
    if t.startswith(("/dev/null", "/dev/stdout", "/dev/stderr")):
        return True
    if "/tmp/" in t or t.startswith("tmp/"):
        return True
    return t.endswith(_SCRATCH_SUFFIXES)
