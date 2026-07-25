"""SXR-006: privilege escalation and anything that outlives this one session --
sudo, shell startup files, cron and systemd units, and SSH keys."""

from __future__ import annotations

import re

from ..discovery import ParsedSession
from ..finding import Category, Severity
from ._util import bash_command_raw, classify_tool, field_str, mcp_command_text, mcp_paths, mk

RULE_ID = "SXR-006"
_I = re.IGNORECASE

_SUDO_RE = re.compile(r"\bsudo\b", _I)
_RC_FILE_PATH_RE = re.compile(
    r"(?:~|\$HOME)?/?\.(?:bashrc|bash_profile|zshrc|zprofile|profile|zlogin|bash_login)\b", _I)
_RC_WRITE_RE = re.compile(r">>?\s*" + _RC_FILE_PATH_RE.pattern, _I)
_CRON_RE = re.compile(r"\bcrontab\s+(?!-l\b)\S|/etc/cron\.|/var/spool/cron", _I)
_SYSTEMD_UNIT_PATH_RE = re.compile(
    r"\.config/systemd/user/[\w.\-]+\.(?:service|timer)|/etc/systemd/system/[\w.\-]+\.(?:service|timer)", _I)
_SYSTEMCTL_ENABLE_RE = re.compile(r"\bsystemctl\b[^\n]*\benable\b", _I)
_AUTHORIZED_KEYS_RE = re.compile(r"authorized_keys", _I)
_SSH_COPY_ID_RE = re.compile(r"\bssh-copy-id\b", _I)
_WRITE_VERB_RE = re.compile(r">>?|\btee\b|\bcp\b", _I)

# Windows persistence: the per-user Startup folder (paths are POSIX-ified at
# parse time, so match either separator), the CurrentVersion\Run registry keys,
# and a scheduled task created with schtasks.
_WIN_STARTUP_RE = re.compile(
    r"[\\/]Start Menu[\\/]Programs[\\/]Startup[\\/]|"
    r"[\\/]Startup[\\/][\w.\- ]+\.(?:bat|cmd|exe|ps1|vbs|lnk)", _I)
_WIN_RUN_KEY_RE = re.compile(
    r"(?:HKCU|HKLM|HKEY_[A-Z_]+)[\\/][^\n]*[\\/]CurrentVersion[\\/]Run(?:Once)?\b", _I)
_SCHTASKS_RE = re.compile(r"\bschtasks\b[^\n]*/create\b", _I)


def check(session: ParsedSession) -> list:
    findings: list = []
    seen: set = set()

    def add(idx, tool_name, title, detail, evidence):
        key = (idx, title)
        if key in seen:
            return
        seen.add(key)
        findings.append(mk(
            RULE_ID, Category.PERSISTENCE, Severity.HIGH, title, detail, evidence, idx, tool_name,
            "Confirm this is expected. Anything that survives past this session should be an "
            "explicit, reviewed decision, not a side effect.",
        ))

    def scan_cmd(cmd, idx, tool_name):
        if _SUDO_RE.search(cmd):
            add(idx, tool_name, "Uses sudo",
                "Escalates to root. Worth confirming the task actually needed it.", cmd)
        if _RC_WRITE_RE.search(cmd):
            add(idx, tool_name, "Writes to a shell startup file",
                "A shell rc file runs on every new interactive shell, which is a durable place "
                "to install anything.", cmd)
        if _CRON_RE.search(cmd):
            add(idx, tool_name, "Installs or edits a cron job",
                "Cron persistence runs on its own schedule independent of this session.", cmd)
        if _SYSTEMD_UNIT_PATH_RE.search(cmd) or _SYSTEMCTL_ENABLE_RE.search(cmd):
            add(idx, tool_name, "Creates or enables a systemd unit",
                "A systemd service or timer keeps running (or starts on boot) long after this "
                "session ends.", cmd)
        if _AUTHORIZED_KEYS_RE.search(cmd) and (_WRITE_VERB_RE.search(cmd) or _SSH_COPY_ID_RE.search(cmd)):
            add(idx, tool_name, "Adds an SSH authorized key",
                "Grants persistent remote SSH access independent of any password or session.", cmd)
        if _WIN_STARTUP_RE.search(cmd):
            add(idx, tool_name, "Writes to the Windows Startup folder",
                "Anything in the Startup folder runs automatically at every login, long after "
                "this session ends.", cmd)
        if _WIN_RUN_KEY_RE.search(cmd):
            add(idx, tool_name, "Adds a Windows Run registry key",
                "A CurrentVersion\\Run key launches a program at every login, independent of "
                "this session.", cmd)
        if _SCHTASKS_RE.search(cmd):
            add(idx, tool_name, "Creates a scheduled task",
                "A scheduled task runs on its own trigger long after this session ends.", cmd)

    def scan_path(path, idx, tool_name):
        if _RC_FILE_PATH_RE.search(path):
            add(idx, tool_name, "Writes to a shell startup file",
                "A shell rc file runs on every new interactive shell, which is a durable place "
                "to install anything.", path)
        if _SYSTEMD_UNIT_PATH_RE.search(path):
            add(idx, tool_name, "Creates or edits a systemd unit file",
                "A systemd service or timer keeps running (or starts on boot) long after this "
                "session ends.", path)
        if _AUTHORIZED_KEYS_RE.search(path):
            add(idx, tool_name, "Writes to SSH authorized_keys",
                "Grants persistent remote SSH access independent of any password or session.", path)
        if _WIN_STARTUP_RE.search(path):
            add(idx, tool_name, "Writes to the Windows Startup folder",
                "Anything in the Startup folder runs automatically at every login, long after "
                "this session ends.", path)

    for tc in session.tool_calls:
        kind = classify_tool(tc.tool_name)

        if kind == "bash":
            cmd = bash_command_raw(tc)
            if cmd:
                scan_cmd(cmd, tc.index, tc.tool_name)
        elif kind in ("write", "edit"):
            path = field_str(tc.input, "file_path", "path", "notebook_path")
            if path:
                scan_path(path, tc.index, tc.tool_name)
        elif kind == "mcp":
            cmd = mcp_command_text(tc)
            if cmd:
                scan_cmd(cmd, tc.index, tc.tool_name)
            for path in mcp_paths(tc):
                scan_path(path, tc.index, tc.tool_name)
    return findings
