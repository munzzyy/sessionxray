"""SXR-004: network egress. curl/wget/nc leaving the machine, a script piped
straight into a shell, a raw socket standing in for a shell, data going out
in a POST, and web fetches to a domain outside the ordinary run of things.
`contacted_hosts()` is called separately by the scanner to build the
session-wide "outbound hosts" list shown in every report regardless of
severity, so a human can eyeball the full contact list in one place.
"""

from __future__ import annotations

import re

from ..discovery import ParsedSession
from ..finding import Category, Severity
from ._util import bash_command, classify_tool, extract_hosts, field_str, flatten_text, is_external_host, mk

RULE_ID = "SXR-004"
_I = re.IGNORECASE

_SINK_RE = re.compile(
    r"(?:"
    r"webhook\.site|requestbin\.\w+|pipedream\.net|"
    r"hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|"
    r"[0-9a-z-]+\.ngrok(?:-free)?\.(?:io|app|dev)|[0-9a-z-]+\.trycloudflare\.com|[0-9a-z-]+\.lhr\.life|"
    r"pastebin\.com|hastebin\.com|termbin\.com|transfer\.sh|0x0\.st|file\.io|"
    r"\.oast\.(?:fun|live|pro|online|site|me)|burpcollaborator\.net|interact\.sh|"
    r"dnslog\.cn|canarytokens\.\w+|requestrepo\.com"
    r")",
    _I,
)

# A shell interpreter after the pipe is dangerous no matter what follows it --
# `bash -s -- args` still runs the piped bytes as the script. A language
# interpreter is only dangerous the same way when it takes its *program* from
# stdin, which only happens when nothing follows its name: `curl u | python3`.
# `curl u | python3 -c "print(json.load(sys.stdin))"` is the ordinary, safe
# shape of fetching data and parsing it -- the code being run is the -c
# argument the agent wrote itself, not anything that came off the network.
_PIPE_SHELL_RE = re.compile(
    r"\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash)\b", _I)
_PIPE_INTERPRETER_BARE_RE = re.compile(
    r"\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python3?|node|ruby|perl)\s*(?:[;&|)\n]|$)",
    _I | re.MULTILINE)
_NC_EXEC_RE = re.compile(r"\bnc(?:at)?\b[^\n]*\s-e\b", _I)
_DEV_TCP_RE = re.compile(r"/dev/(?:tcp|udp)/[0-9A-Za-z.\-]+/\d+")
_POST_RE = re.compile(
    r"(?:"
    r"curl\b[^\n]*\s(?:-X\s*POST|--request\s+POST|-d\s|--data(?:-raw|-binary)?[= ])|"
    r"wget\b[^\n]*--post-(?:data|file)[= ]|"
    r"requests\.(?:post|put|patch)\s*\(|axios\.(?:post|put|patch)\s*\(|"
    r"fetch\s*\([^)]*method\s*:\s*[\"']POST[\"']|"
    r"Invoke-(?:WebRequest|RestMethod)\b[^\n]*-Method\s+Post"
    r")",
    _I,
)
_EGRESS_TOOL_RE = re.compile(r"\b(?:curl|wget|nc|ncat|httpie|http)\b", _I)


def check(session: ParsedSession) -> list:
    findings: list = []
    seen: set = set()
    for tc in session.tool_calls:
        text, is_web = _egress_text(tc)
        if not text:
            continue
        hosts = _hosts_for(text, is_web)

        if _SINK_RE.search(text):
            _add(findings, seen, tc, "sink", Severity.HIGH,
                 "Known data-collection endpoint contacted",
                 "Reaches a paste, webhook, or tunnel service whose only purpose is "
                 "receiving data out of band.",
                 text, "Confirm this destination is expected; remove it if it is not part of the task.")
        if _PIPE_SHELL_RE.search(text) or _PIPE_INTERPRETER_BARE_RE.search(text):
            _add(findings, seen, tc, "pipe", Severity.HIGH,
                 "Remote script piped straight to a shell",
                 "Downloads content and executes it in the same step; whatever that "
                 "endpoint returns runs unreviewed.",
                 text, "Download to a file, read it, then run it.")
        if _NC_EXEC_RE.search(text):
            _add(findings, seen, tc, "nc-exec", Severity.HIGH,
                 "netcat wired to a shell",
                 "nc/ncat with -e connects a program's input and output to a socket, the shape "
                 "of a bind or reverse shell.",
                 text, "Remove it; there is no benign reason for a coding agent to open a shell socket.")
        if _DEV_TCP_RE.search(text):
            _add(findings, seen, tc, "dev-tcp", Severity.HIGH,
                 "Raw socket redirect",
                 "/dev/tcp (or /dev/udp) opens a raw network socket from inside a shell script, "
                 "the classic bash reverse-shell trick.",
                 text, "Remove it; there is no benign reason for a coding agent to open a raw socket.")
        if _POST_RE.search(text) and hosts:
            _add(findings, seen, tc, "post", Severity.HIGH,
                 "Outbound POST request",
                 f"Sends data to {', '.join(hosts)} rather than just retrieving it.",
                 text, "Confirm what is being sent and that the destination should receive it.")
        elif hosts:
            _add(findings, seen, tc, ("egress", tuple(hosts)), Severity.MEDIUM,
                 "Outbound network request",
                 f"Contacts {', '.join(hosts)}.",
                 text, "Make sure every outbound host is one this task actually needs.")
    return findings


def contacted_hosts(session: ParsedSession) -> list:
    hosts: set = set()
    for tc in session.tool_calls:
        text, is_web = _egress_text(tc)
        if text:
            hosts.update(_hosts_for(text, is_web))
    return sorted(hosts)


def _add(findings, seen, tc, tag, sev, title, detail, evidence, remediation) -> None:
    key = (tc.index, tag)
    if key in seen:
        return
    seen.add(key)
    findings.append(mk(RULE_ID, Category.NETWORK, sev, title, detail, evidence, tc.index, tc.tool_name, remediation))


def _egress_text(tc):
    kind = classify_tool(tc.tool_name)
    if kind == "bash":
        return bash_command(tc), False
    if kind == "web":
        return field_str(tc.input, "url") or field_str(tc.input, "query"), True
    if kind == "mcp":
        return flatten_text(tc.input, max_len=2000), False
    return "", False


def _hosts_for(text: str, is_web: bool) -> list:
    if not is_web and not _EGRESS_TOOL_RE.search(text):
        return []
    return [h for h in extract_hosts(text) if is_external_host(h)]
