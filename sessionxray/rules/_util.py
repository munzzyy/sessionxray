"""Shared helpers for rule modules: tool classification, text extraction,
outbound-host parsing, and secret redaction.

Redaction runs here so every rule gets it automatically through `mk()` --
a rule module cannot forget to scrub a value it just matched.
"""

from __future__ import annotations

import re

from ..discovery import ToolCall, _to_posix_path
from ..finding import Category, Finding, Severity

# A key name ending in one of these tokens, optionally prefixed by another
# identifier segment. DB_PASSWORD and MY_API_KEY are exactly as live as
# PASSWORD and API_KEY on their own, but "_" is a word character, so there is
# no \b between the prefix and the token for a plain \bpassword\b to find.
_SECRET_KEY = (
    r"\b[\w-]*(?:aws_secret_access_key|secret[_-]?key|api[_-]?key|"
    r"access[_-]?token|auth[_-]?token|password|passwd|credentials?|token)\b"
)

# (compiled pattern, capture group to mask (None = whole match), label)
_SECRET_RULES = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?"
                r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", re.DOTALL),
     None, "private-key"),
    (re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), None, "stripe-key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None, "aws-key-id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), None, "github-token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), None, "github-pat"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), None, "anthropic-key"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"), None, "openai-key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), None, "slack-token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), None, "google-api-key"),
    (re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"), None, "gitlab-token"),
    (re.compile(r"(?i)\bAuthorization:\s*Bearer\s+([A-Za-z0-9\-_.=]{16,})"), 1, "bearer-token"),
    (re.compile(r"(?i)" + _SECRET_KEY + r"\s*[:=]\s*[\"']([^\"'\n]{8,})[\"']"), 1, "assigned-secret"),
    # Unquoted form -- `export DB_PASSWORD=Tr0ub4dor3...` is exactly as live a
    # credential as the quoted form, and shell exports/.env files routinely
    # skip the quotes entirely. Cut off at the first shell metacharacter or
    # quote so a long command line never gets swallowed whole as "the secret".
    (re.compile(r"(?i)" + _SECRET_KEY + r"\s*[:=]\s*([^\s;&|`\"'\n]{6,})"), 1, "assigned-secret"),
]


def redact(text: str) -> str:
    """Replace anything that looks like a live credential with a labeled
    placeholder. Applied to every finding's evidence before it is stored."""
    if not text:
        return text
    out = text
    for rx, group, label in _SECRET_RULES:
        def _sub(m, group=group, label=label):
            if group is None:
                return f"<redacted:{label}>"
            whole = m.group(0)
            mstart = m.start(0)
            gstart, gend = m.start(group), m.end(group)
            return whole[: gstart - mstart] + f"<redacted:{label}>" + whole[gend - mstart:]
        out = rx.sub(_sub, out)
    return out


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _escape_controls(text: str) -> str:
    """Replace any C0/C1 control byte -- ESC included -- with a visible \\xNN
    placeholder. Evidence is often the literal text of a tool result, which is
    untrusted: without this, a crafted result can plant terminal escape codes
    that clear the screen or repaint a fake "no findings" line once the report
    reaches a real terminal."""
    return _CONTROL_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)


def truncate(text: str, width: int = 160) -> str:
    text = _escape_controls(" ".join((text or "").split()))
    if len(text) > width:
        return text[: width - 3] + "..."
    return text


def mk(rule_id: str, category: Category, severity: Severity, title: str, detail: str,
       evidence: str, event_index: int, tool_name: str = "", remediation: str = "") -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        detail=detail,
        evidence=truncate(redact(evidence)),
        event_index=event_index,
        tool_name=tool_name,
        remediation=remediation,
    )


_BASH_NAMES = {"bash"}
_READ_NAMES = {"read"}
_WRITE_NAMES = {"write"}
_EDIT_NAMES = {"edit", "multiedit", "notebookedit"}
_WEB_NAMES = {"webfetch", "websearch"}


def classify_tool(name: str) -> str:
    n = (name or "").strip().lower()
    if n in _BASH_NAMES:
        return "bash"
    if n in _READ_NAMES:
        return "read"
    if n in _WRITE_NAMES:
        return "write"
    if n in _EDIT_NAMES:
        return "edit"
    if n in _WEB_NAMES:
        return "web"
    if n.startswith("mcp__"):
        return "mcp"
    return "other"


def field_str(inp: dict, *keys: str) -> str:
    """First non-empty string value among the given keys, or ""."""
    if not isinstance(inp, dict):
        return ""
    for k in keys:
        v = inp.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def flatten_text(value, max_len: int = 8000) -> str:
    """Join every string leaf reachable from `value` (bounded depth and
    fan-out) into one text blob, for regexes that don't care which field
    a string came from."""
    parts: list = []
    total = 0
    stack = [(value, 0)]
    visited = 0
    while stack and total < max_len and visited < 500:
        v, depth = stack.pop()
        visited += 1
        if isinstance(v, str):
            parts.append(v)
            total += len(v)
        elif isinstance(v, dict) and depth < 6:
            for vv in v.values():
                stack.append((vv, depth + 1))
        elif isinstance(v, list) and depth < 6:
            for vv in v[:200]:
                stack.append((vv, depth + 1))
    return "\n".join(parts)[:max_len]


_HEREDOC_RE = re.compile(r"(<<-?~?)\s*([\"']?)(\w+)\2\r?\n(.*?)\r?\n[ \t]*\3[ \t]*(?=\r?\n|$)", re.DOTALL)


def _blank_heredoc(m: re.Match) -> str:
    quote, delim = m.group(2), m.group(3)
    return f"{m.group(1)} {quote}{delim}{quote}\n<heredoc body omitted>\n{delim}"


def strip_heredocs(text: str) -> str:
    """Blank out heredoc bodies (`python3 - <<'EOF' ... EOF`) before pattern
    matching. Without this, arbitrary embedded source -- Python, HTML, JSON,
    whatever the heredoc is feeding an interpreter -- gets scanned as if it
    were shell syntax, which produces matches like a lone '>' inside an HTML
    tag reading as a file-clobbering redirect."""
    return _HEREDOC_RE.sub(_blank_heredoc, text)


def bash_command(tc: ToolCall) -> str:
    """A Bash tool call's command text, with heredoc bodies blanked out.

    Use this only for rules that read shell *syntax* (a redirect, a clobber) --
    a '>' inside an embedded HTML/JSON heredoc body would otherwise read as a
    real shell operator. Rules matching content (a credential path, curl|sh, a
    URL) want the body intact and should use bash_command_raw instead."""
    return strip_heredocs(field_str(tc.input, "command"))


def bash_command_raw(tc: ToolCall) -> str:
    """A Bash tool call's command text with heredoc bodies left intact.

    A full credential-exfil chain hidden inside `python3 - <<'EOF' ... EOF`
    lives entirely in the heredoc body, so any rule that matches on content
    rather than shell syntax has to see it."""
    return field_str(tc.input, "command")


# MCP inputs are arbitrary per-server schemas, so this is best-effort by
# construction: pull anything under a path-shaped key into the path checks and
# anything under a command-shaped key into the command checks. Keys are matched
# on whole underscore-delimited segments so `file_path` and `target` hit but a
# `pathological` field would not.
_MCP_PATH_KEY_RE = re.compile(
    r"(?i)(?:^|_)(?:path|file|filename|filepath|dir|directory|target|dest|destination)(?:_|$)")
_MCP_CMD_KEY_RE = re.compile(
    r"(?i)(?:^|_)(?:command|cmd|script|code|args|argv|shell)(?:_|$)")


def _strings_in(value, limit: int = 50) -> list:
    out: list = []
    stack = [value]
    while stack and len(out) < limit:
        v = stack.pop()
        if isinstance(v, str):
            if v:
                out.append(v)
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v[:200])
    return out


def _collect_by_key(inp: dict, key_re) -> list:
    found: list = []
    if not isinstance(inp, dict):
        return found
    stack = [(inp, 0)]
    visited = 0
    while stack and visited < 500 and len(found) < 200:
        v, depth = stack.pop()
        visited += 1
        if isinstance(v, dict) and depth < 6:
            for k, vv in v.items():
                if isinstance(k, str) and key_re.search(k):
                    found.extend(_strings_in(vv))
                if isinstance(vv, (dict, list)):
                    stack.append((vv, depth + 1))
        elif isinstance(v, list) and depth < 6:
            for vv in v[:200]:
                stack.append((vv, depth + 1))
    return found


def mcp_paths(tc: ToolCall) -> list:
    """Path-like string values from an MCP tool call's arbitrary input.

    MCP inputs are canonicalized here rather than in discovery: the file/path
    fields of a normal tool call get POSIX-ified up front, but MCP keys are
    arbitrary (`target`, `dest`, ...) and never pass through that step. Without
    this a Windows path under such a key (`C:\\Windows\\...`) reads as relative,
    gets joined under cwd, and slips past the outside-root check."""
    return [_to_posix_path(p) for p in _collect_by_key(tc.input, _MCP_PATH_KEY_RE)]


def mcp_command_text(tc: ToolCall) -> str:
    """Command-like string values from an MCP tool call, joined for scanning."""
    return "\n".join(_collect_by_key(tc.input, _MCP_CMD_KEY_RE))


_MCP_WRITE_RE = re.compile(
    r"(?i)(?:^|_)(?:write|create|edit|append|put|save|update|delete|remove|move|rename|mkdir|copy)(?:_|$)")


def mcp_is_write(tool_name: str) -> bool:
    """Guess whether an MCP tool mutates the filesystem, from its verb."""
    return bool(_MCP_WRITE_RE.search(tool_name or ""))


def mask_quoted(text: str) -> str:
    """Replace the *contents* of quoted strings with spaces, keeping the quote
    characters and overall length. A stray shell metacharacter that only
    shows up inside a quoted argument -- the '>' in a grep pattern matching
    an HTML tag, say -- should not be misread as a real shell operator."""
    out = []
    quote = None
    for ch in text:
        if quote:
            out.append(ch if ch == quote else " ")
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        out.append(ch)
    return "".join(out)


def split_bash_segments(cmd: str) -> list:
    """Split a command on ; && || | & and newlines, honoring quotes, so a rule
    that judges "is this a write" doesn't let a write verb in one sub-command
    (`mkdir x && cat y`) bleed onto an unrelated path in another (`y`)."""
    segments: list = []
    buf: list = []
    quote = None
    i, n = 0, len(cmd)
    while i < n:
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in ";\n":
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        if cmd[i:i + 2] in ("&&", "||"):
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch in "&|":
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [s for s in segments if s.strip()]


_URL_RE = re.compile(r"https?://([^\s/'\"<>\\)]+)", re.IGNORECASE)

# A bare host handed to an egress tool: `curl collector.example.net/upload` with
# no scheme. Requires a real-looking TLD so a plain filename argument doesn't get
# mistaken for a host.
_EGRESS_TOOLS = {"curl", "curl.exe", "wget", "wget.exe", "nc", "ncat", "httpie", "http"}
_HOST_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}(?:[:/]|$)", re.IGNORECASE)
# Options whose *next* token is a value, not a host -- skip that value so
# `curl -o out.txt` and `curl --output result.dat` stay silent.
_VALUE_OPTS_LONG = {
    "--data", "--data-raw", "--data-binary", "--data-urlencode", "--header",
    "--output", "--form", "--user", "--referer", "--cookie", "--upload-file", "--config",
}
# Short options whose value is the rest of the same token (`-XPOST`, `-dfoo`) or,
# when nothing is attached, the next token (`-d @secret`). `-O`/`--remote-name`
# is deliberately absent: it takes no value, so `curl -O host` must still see the
# host as the next token.
_VALUE_OPTS_SHORT = set("oHdFTKbeAxuX")


def _clean_host(token: str) -> str:
    return token.split("@")[-1].split("/")[0].split(":")[0].strip().lower()


def _schemeless_hosts(text: str) -> list:
    """Hosts passed to an egress tool without a scheme -- the presence of the
    tool is what tells us the bare token is a destination, not a filename."""
    found: list = []
    tokens = text.split()
    i, n = 0, len(tokens)
    while i < n:
        if tokens[i].lower().rstrip(";|&") not in _EGRESS_TOOLS:
            i += 1
            continue
        j = i + 1
        while j < n:
            t = tokens[j]
            if t in ("|", "||", "&&", "&", ";"):
                break
            if t.startswith("--"):
                opt = t.split("=", 1)[0]
                j += 2 if (opt in _VALUE_OPTS_LONG and "=" not in t) else 1
                continue
            if t.startswith("-"):
                # Clustered short flags (`-fsSL`, `-XPOST`): walk to the first
                # char that takes a value. If it sits at the end of the token
                # its value is the *next* token, so skip that too; otherwise the
                # rest of this token is the value and the next token is untouched
                # -- so `-XPOST host` and `-O host` no longer swallow the host.
                body = t[1:]
                skip_next = False
                for idx, ch in enumerate(body):
                    if ch in _VALUE_OPTS_SHORT:
                        skip_next = idx == len(body) - 1
                        break
                j += 2 if skip_next else 1
                continue
            if _HOST_TOKEN_RE.match(t):
                host = _clean_host(t)
                if host and "." in host:
                    found.append(host)
                break
            j += 1  # a non-host positional (a bare `POST`); keep looking
        i = j if j > i else i + 1
    return found


def extract_hosts(text: str) -> list:
    text = text or ""
    hosts: list = []
    for m in _URL_RE.finditer(text):
        host = _clean_host(m.group(1))
        if host and host not in hosts:
            hosts.append(host)
    for host in _schemeless_hosts(text):
        if host not in hosts:
            hosts.append(host)
    return hosts


def is_external_host(host: str) -> bool:
    h = host.lower()
    if h in ("localhost", "0.0.0.0", "::1") or h.startswith("127."):
        return False
    if h.endswith(".local"):
        return False
    parts = h.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        a, b = int(parts[0]), int(parts[1])
        if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254):
            return False
    return True
