"""SXR-001: filesystem reach outside the session's project root.

The project root is inferred from the `cwd` most tool calls in the transcript
ran in. A file tool (Read/Write/Edit) reports its target path directly; a
Bash command is scanned with a regex for absolute-path and home-relative
tokens, since there is no real shell parser here. That means this rule can
miss a path built by string concatenation or passed through a variable, and
can occasionally flag an unrelated absolute-looking argument (a linker flag,
a PATH entry). It cannot miss a plain literal path, which covers most real
tool use.
"""

from __future__ import annotations

import os
import posixpath
import re

from ..discovery import ParsedSession
from ..finding import Category, Severity
from ._util import bash_command, classify_tool, field_str, mask_quoted, mk, split_bash_segments

RULE_ID = "SXR-001"

_SENSITIVE_SUFFIXES = (
    "/.ssh", "/.aws", "/.gnupg", "/.kube", "/.docker", "/.config",
)
_SENSITIVE_ABS = ("/etc", "/root")

_WRITE_RE = re.compile(
    r"(?:>>?(?!&)(?!\s*/dev/(?:null|stdout|stderr|tty)\b)|"
    r"\btee\b|\bcp\b|\bmv\b|\brm\b|\bmkdir\b|\btouch\b|\bdd\b|"
    r"\bsed\s+-i\b|\binstall\b|\brsync\b|\bchmod\b|\bchown\b|\btruncate\b)",
    re.IGNORECASE,
)

# A leading "/" only starts an absolute path if nothing path-like sits right
# before it. Without that boundary check, a *relative* path like
# "tests/corpus/malicious" reads its own internal "/corpus/malicious" as if
# it were an unrelated absolute path -- a real, high-volume false positive.
_PATH_RE = re.compile(r"(?<![\w./\-])(~(?:/[\w.\-]+)*|/(?:[\w.\-]+/)*[\w.\-]+)")
_TRAVERSAL_RE = re.compile(r"(?:^|[\s\"'=])(\.\.(?:/[\w.\-]+)+)")
_URL_RE = re.compile(r"\w+://\S+")
_QUOTED_RE = re.compile(r'"([^"\n]+)"|\'([^\'\n]+)\'')


def check(session: ParsedSession) -> list:
    findings: list = []
    root = posixpath.normpath(session.project_root) if session.project_root else None
    seen: set = set()

    for tc in session.tool_calls:
        kind = classify_tool(tc.tool_name)
        if kind in ("read", "write", "edit"):
            p = field_str(tc.input, "file_path", "path", "notebook_path")
            if p:
                f = _check_path(p, tc.cwd, root, is_write=(kind != "read"),
                                 evidence=p, event_index=tc.index, tool_name=tc.tool_name, seen=seen)
                if f:
                    findings.append(f)
        elif kind == "bash":
            cmd = bash_command(tc)
            if not cmd:
                continue
            # A write verb anywhere in a long "a && b && c" chain used to mark
            # every path in the whole command as a write, including a plain
            # read three commands earlier. Judge each sub-command on its own.
            for segment in split_bash_segments(cmd):
                # Quotes are masked only for deciding write-vs-read: a write
                # verb inside a quoted grep/sed pattern ("mkdir failed") is
                # text being searched for, not a command being run.
                is_write = bool(_WRITE_RE.search(mask_quoted(segment)))
                # Strip URLs before hunting for filesystem paths: a URL's path
                # component (the "/upload" in https://host/upload) looks
                # exactly like an absolute path and is the network rule's job.
                seg_no_urls = _URL_RE.sub(" ", segment)
                # A quoted argument can contain spaces (a path with a space in
                # the name). Check the whole quoted string as one path and
                # remove it, so the unquoted scan below doesn't also pick up
                # a fragment of it.
                seg_unquoted = _consume_quoted_paths(
                    seg_no_urls, tc, root, is_write, cmd, findings, seen)
                for m in _PATH_RE.finditer(seg_unquoted):
                    p = m.group(1)
                    f = _check_path(p, tc.cwd, root, is_write=is_write,
                                     evidence=cmd, event_index=tc.index, tool_name=tc.tool_name, seen=seen)
                    if f:
                        findings.append(f)
                for m in _TRAVERSAL_RE.finditer(segment):
                    key = (tc.index, "traversal", m.group(1))
                    if key in seen:
                        continue
                    seen.add(key)
                    sev = Severity.HIGH if is_write else Severity.MEDIUM
                    findings.append(mk(
                        RULE_ID, Category.FILESYSTEM, sev,
                        "Path traversal in a shell command",
                        f"Walks outside its starting directory with a relative path ({m.group(1)!r}), "
                        "which can land anywhere the process has permission to reach.",
                        cmd, tc.index, tc.tool_name,
                        "Use an absolute, project-scoped path instead of relative traversal.",
                    ))
    return findings


_DEV_NOISE = ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero", "/dev/random", "/dev/urandom")
# The scratch area is where a well-behaved agent is expected to put throwaway
# files; a write there is common enough that treating it the same as a write to
# /etc would drown out findings that actually deserve HIGH. These are the paths
# a transcript uses, so they stay POSIX no matter what OS sessionxray runs on
# (/var/folders is macOS's per-user temp).
_SCRATCH_PREFIXES = ("/tmp", "/var/tmp", "/var/folders")


def _is_scratch(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in _SCRATCH_PREFIXES)


def _consume_quoted_paths(cmd: str, tc, root, is_write: bool, evidence: str,
                           findings: list, seen: set) -> str:
    def repl(m):
        inner = m.group(1) if m.group(1) is not None else m.group(2)
        if inner and (inner.startswith("/") or inner.startswith("~")):
            f = _check_path(inner, tc.cwd, root, is_write=is_write, evidence=evidence,
                             event_index=tc.index, tool_name=tc.tool_name, seen=seen)
            if f:
                findings.append(f)
        return " "
    return _QUOTED_RE.sub(repl, cmd)


def _check_path(raw: str, cwd: str, root, *, is_write: bool, evidence: str,
                 event_index: int, tool_name: str, seen: set):
    norm = _normalize(raw, cwd)
    if norm is None:
        return None
    if norm in _DEV_NOISE:
        return None
    if root and _is_under(norm, root):
        return None
    key = (event_index, norm)
    if key in seen:
        return None
    seen.add(key)

    sensitive = _is_sensitive(norm)
    if is_write and _is_scratch(norm):
        sev = Severity.LOW
        title = "Write reaches the OS scratch directory"
    elif is_write:
        sev = Severity.HIGH
        title = "Write reaches outside the project root"
    elif sensitive:
        sev = Severity.MEDIUM
        title = "Read touches a sensitive directory outside the project root"
    else:
        sev = Severity.LOW
        title = "Read reaches outside the project root"

    root_desc = root or "unknown, no cwd observed in this transcript"
    verb = "Wrote to" if is_write else "Read"
    detail = f"{verb} {norm}, outside the session's project root ({root_desc})."
    return mk(RULE_ID, Category.FILESYSTEM, sev, title, detail, evidence, event_index, tool_name,
              "Scope file access to the project directory; treat anything outside it as a "
              "deliberate, reviewed exception.")


# Transcript paths are the analyzed machine's, which is POSIX in practice; `~`
# refers to that machine's home, which we do not know, so expand it to a stable
# absolute stand-in. Detection only needs it to land outside the project root and
# keep any sensitive suffix (/.ssh and friends) intact, which this does.
_HOME = os.environ.get("HOME") or "/root"
if not _HOME.startswith("/"):
    _HOME = "/root"


def _normalize(raw: str, cwd: str):
    if not raw:
        return None
    try:
        p = raw
        if p == "~":
            p = _HOME
        elif p.startswith("~/"):
            p = _HOME + p[1:]
        if not p.startswith("/"):
            if not cwd:
                return None
            p = posixpath.join(cwd, p)
        return posixpath.normpath(p)
    except (TypeError, ValueError):
        return None


def _is_under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _is_sensitive(path: str) -> bool:
    if any(path.startswith(a) for a in _SENSITIVE_ABS):
        return True
    return any(s in path for s in _SENSITIVE_SUFFIXES)
