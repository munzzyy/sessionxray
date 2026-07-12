"""Shared helpers for rule modules: tool classification, text extraction,
outbound-host parsing, and secret redaction.

Redaction runs here so every rule gets it automatically through `mk()` --
a rule module cannot forget to scrub a value it just matched.
"""

from __future__ import annotations

import re

from ..discovery import ToolCall
from ..finding import Category, Finding, Severity

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
    (re.compile(r"(?i)\b(?:aws_secret_access_key|secret[_-]?key|api[_-]?key|"
                r"access[_-]?token|auth[_-]?token|password|passwd)\b\s*[:=]\s*"
                r"[\"']([^\"'\n]{8,})[\"']"), 1, "assigned-secret"),
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


def truncate(text: str, width: int = 160) -> str:
    text = " ".join((text or "").split())
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
    """A Bash tool call's command text, with heredoc bodies blanked out."""
    return strip_heredocs(field_str(tc.input, "command"))


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


def extract_hosts(text: str) -> list:
    hosts = []
    for m in _URL_RE.finditer(text or ""):
        host = m.group(1).split("@")[-1].split("/")[0].split(":")[0].strip().lower()
        if host:
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
