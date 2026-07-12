"""SXR-005: remote code brought in and run without a human reading it first --
obfuscated payloads, eval of something just downloaded, and package installs
that bypass the registry's version pinning."""

from __future__ import annotations

import re

from ..discovery import ParsedSession
from ..finding import Category, Severity
from ._util import bash_command, classify_tool, mk

RULE_ID = "SXR-005"
_I = re.IGNORECASE

_PATTERNS = [
    (re.compile(r"\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sh|bash|zsh|python3?|node|perl)\b", _I),
     Severity.HIGH, "Base64-decoded payload piped to a shell",
     "Decodes an obfuscated blob and executes it, a common way to hide a command from a reviewer."),
    (re.compile(r"\beval\s+[\"'`]?\$\(\s*(?:curl|wget)\b", _I),
     Severity.HIGH, "Evaluates downloaded content",
     "Runs eval on the output of a network fetch; the remote endpoint controls what executes here."),
    # `eval "$(...)"` (shell, needs whitespace before the opener) and
    # `eval(...)`/`exec(...)` (language-level call, no space at all -- Python's
    # exec(eval(compile(base64.b64decode(...)))) is the common obfuscated-
    # payload shape) are both "run this constructed thing," just spelled
    # differently. `eval\s*\(` stops at "evaluate(": after "eval" comes "uate",
    # not whitespace-then-"(", so it never fires on that word.
    (re.compile(r"\beval\s+[\"'`$(]|\b(?:eval|exec)\s*\("),
     Severity.MEDIUM, "Dynamic shell eval",
     "eval runs a constructed string as a command, which hides what actually executes until runtime."),
    (re.compile(r"\b(?:pip3?|pipx)\s+install\s+[^\n]*(?:git\+|https?://)", _I),
     Severity.HIGH, "Installs a Python package from a URL",
     "Bypasses the package index entirely; there is no published, reviewable release to point to."),
    (re.compile(r"\bnpm\s+(?:i|install|add)\s+[^\n]*(?:git\+|https?://|github:)", _I),
     Severity.HIGH, "Installs an npm package from a URL",
     "Bypasses the npm registry and any version pinning."),
    (re.compile(r"\bnpx\b[^\n]*(?:git\+|https?://|github:)", _I),
     Severity.HIGH, "npx runs a package fetched from a URL",
     "Executes code straight from a git ref or URL rather than a published, versioned package."),
    (re.compile(r"\bnpx\s+(?:-y|--yes)\b", _I),
     Severity.MEDIUM, "npx runs a package without confirmation",
     "-y/--yes skips the install prompt, so whatever the registry currently resolves that name to "
     "runs immediately with no human in the loop."),
]


def check(session: ParsedSession) -> list:
    findings: list = []
    seen: set = set()
    for tc in session.tool_calls:
        if classify_tool(tc.tool_name) != "bash":
            continue
        cmd = bash_command(tc)
        if not cmd:
            continue
        for rx, sev, title, detail in _PATTERNS:
            for m in rx.finditer(cmd):
                key = (tc.index, title)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(mk(
                    RULE_ID, Category.REMOTE_CODE, sev, title, detail,
                    cmd, tc.index, tc.tool_name,
                    "Pin to a published, versioned release and review it before running.",
                ))
    return findings
