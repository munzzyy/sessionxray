"""SXR-003: credential and secret access. The strongest signal is the combo --
a command that both touches credential material and has a way to send it
somewhere in the same line -- which escalates straight to CRITICAL, the same
shape skillxray uses for a static credential-stealer. Every matched secret
value is redacted by `mk()` before it is ever stored in a Finding.
"""

from __future__ import annotations

import re

from ..discovery import ParsedSession
from ..finding import Category, Severity
from ._util import bash_command, classify_tool, field_str, mk

RULE_ID = "SXR-003"
_I = re.IGNORECASE

_SENSITIVE_PATH_RE = re.compile(
    r"(?:"
    r"/\.ssh/|~/\.ssh\b|\bid_rsa\b|\bid_ed25519\b|"
    r"/\.aws/credentials\b|"
    r"/\.config/gcloud\b|/\.netrc\b|\.netrc\b|"
    r"/\.docker/config\.json\b|/\.kube/config\b|"
    r"/\.gnupg\b|/etc/shadow\b|/etc/passwd\b|"
    r"/\.config/gh/hosts\.yml\b|"
    r"/\.claude/[\w.\-]*credential[\w.\-]*|/\.config/claude\b|"
    r"Login\s?Data|/Cookies\b|cookies\.sqlite|"
    r"security\s+find-generic-password|"
    r"\.env(?:\.local|\.production)?\b"
    r")",
    _I,
)
_GH_AUTH_TOKEN_RE = re.compile(r"\bgh\s+auth\s+token\b", _I)
_EGRESS_HINT_RE = re.compile(r"\b(?:curl|wget|nc|ncat)\b|https?://", _I)
_ENV_SECRET_ECHO_RE = re.compile(
    r"\b(?:echo|printf)\b[^\n]*\$\{?[A-Z_]*(?:SECRET|TOKEN|API_?KEY|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY)[A-Z_]*\}?", _I)
_ENV_DUMP_GREP_RE = re.compile(
    r"\b(?:printenv|env)\b[^\n|]*\|\s*grep\s+-i\s+(?:secret|token|key|password|credential)", _I)

_LITERAL_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), "Stripe live secret key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "GitHub fine-grained PAT"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "Anthropic API key"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"), "OpenAI API key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"), "GitLab personal access token"),
]


def check(session: ParsedSession) -> list:
    findings: list = []
    seen: set = set()

    for tc in session.tool_calls:
        kind = classify_tool(tc.tool_name)

        if kind == "bash":
            cmd = bash_command(tc)
            if cmd:
                _scan_bash(cmd, tc, findings, seen)
        elif kind == "read":
            p = field_str(tc.input, "file_path", "path")
            if p:
                _scan_path(p, tc, findings, seen)
        elif kind in ("write", "edit"):
            p = field_str(tc.input, "file_path", "path")
            if p:
                _scan_path(p, tc, findings, seen)
            content = field_str(tc.input, "content", "new_string")
            if content:
                _scan_literal(content, tc, findings, seen, "the content it wrote")
    return findings


def _gh_token_printed_raw(cmd: str, match) -> bool:
    """True if `gh auth token`'s output goes to stdout/a pipe rather than being
    captured into a variable -- `export X=$(gh auth token)` is the standard,
    recommended way to feed a script's own `gh`/`curl` calls and should not
    read the same as printing a live token to a log."""
    before = cmd[: match.start()].rstrip()
    return not (before.endswith("$(") or before.endswith("`"))


def _scan_bash(cmd: str, tc, findings: list, seen: set) -> None:
    sensitive = _SENSITIVE_PATH_RE.search(cmd)
    gh_match = _GH_AUTH_TOKEN_RE.search(cmd)
    gh_token = gh_match if gh_match and _gh_token_printed_raw(cmd, gh_match) else None
    egress = _EGRESS_HINT_RE.search(cmd)

    if (sensitive or gh_token) and egress:
        m = sensitive or gh_token
        _add(findings, seen, tc, Severity.CRITICAL,
             "Reads a credential and can send it out",
             f"This command touches credential material ({m.group(0)!r}) and contains "
             "network-egress code in the same line, the shape of a credential leak.",
             cmd, "Split file/credential access from network calls; never combine reading a "
             "credential store with sending data out.")
    else:
        if sensitive:
            _add(findings, seen, tc, Severity.HIGH, "References a credential path",
                 f"Touches {sensitive.group(0)!r}, a location that holds secrets.",
                 cmd, "Confirm the task has a real, documented need to touch this path.")
        if gh_token:
            _add(findings, seen, tc, Severity.HIGH, "Prints a live gh auth token",
                 "`gh auth token` writes a live, usable GitHub token to stdout; anything "
                 "downstream of this command (a log, a pipe, a file) can now use it.",
                 cmd, "Avoid printing the token directly; scope it to the one process that "
                 "needs it via an environment variable instead of stdout.")

    if _ENV_SECRET_ECHO_RE.search(cmd) or _ENV_DUMP_GREP_RE.search(cmd):
        _add(findings, seen, tc, Severity.HIGH, "Echoes a secret-shaped environment variable",
             "Prints an environment variable whose name suggests it holds a credential.",
             cmd, "Avoid echoing credential-shaped environment variables to stdout or a log.")

    _scan_literal(cmd, tc, findings, seen, "the command")


def _scan_path(path: str, tc, findings: list, seen: set) -> None:
    m = _SENSITIVE_PATH_RE.search(path)
    if not m:
        return
    is_write = classify_tool(tc.tool_name) in ("write", "edit")
    title = "Writes to a credential path" if is_write else "Reads a credential path"
    verb = "Writes to" if is_write else "Reads"
    _add(findings, seen, tc, Severity.HIGH, title,
         f"{verb} {m.group(0)!r}, a location that holds secrets.",
         path, "Confirm the task has a real, documented need to touch this path.")


def _article(word: str) -> str:
    return "an" if word[:1].upper() in "AEIOU" else "a"


def _scan_literal(text: str, tc, findings: list, seen: set, where: str) -> None:
    for rx, label in _LITERAL_PATTERNS:
        m = rx.search(text)
        if not m:
            continue
        sev = Severity.CRITICAL if label == "private key" else Severity.HIGH
        _add(findings, seen, tc, sev, f"Hardcoded {label}",
             f"This looks like {_article(label)} {label}, hardcoded directly in {where}.",
             text, "Remove the credential and rotate it. Anything that touched it should be "
             "treated as compromised; load secrets from the environment instead.")


def _add(findings: list, seen: set, tc, sev: Severity, title: str, detail: str,
         evidence: str, remediation: str) -> None:
    key = (tc.index, title)
    if key in seen:
        return
    seen.add(key)
    findings.append(mk(RULE_ID, Category.SECRET, sev, title, detail, evidence, tc.index, tc.tool_name, remediation))
