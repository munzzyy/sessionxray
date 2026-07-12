"""SXR-007: prompt-injection footprint. This does not look at what the agent
wrote -- it looks at what came back from a tool: a fetched web page, a file's
contents, an issue body, an MCP response. A hit here means the agent was
handed text that tried to redirect it, not that the redirection worked. It is
the "was my agent exposed" signal, so every finding here is MEDIUM regardless
of how aggressive the phrasing is; there is no way to tell from the
transcript alone whether the agent complied.
"""

from __future__ import annotations

import re

from ..discovery import ParsedSession
from ..finding import Category, Severity
from ._util import mk

RULE_ID = "SXR-007"
_I = re.IGNORECASE

_PATTERNS = [
    (re.compile(r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|"
                r"preceding|foregoing)\s+(?:instructions?|prompts?|context|rules?|messages?|directions?)", _I),
     "Instruction-override phrasing",
     "Tells the reader to ignore its previous instructions, a classic injection payload."),
    (re.compile(r"\bdisregard\s+(?:all\s+|any\s+)?(?:the\s+|your\s+|previous\s+|prior\s+|above\s+|"
                r"system\s+)?(?:instructions?|prompts?|rules?|guidelines?|context)", _I),
     "Instruction-override phrasing",
     "Tells the reader to disregard its instructions or guidelines."),
    (re.compile(r"\bforget\s+(?:everything|all|your|the)\s+(?:previous\s+|prior\s+|above\s+)?"
                r"(?:instructions?|rules?|guidelines?|context|you\s+(?:were\s+)?told)", _I),
     "Instruction-reset phrasing",
     "Tells the reader to forget its prior instructions."),
    (re.compile(r"\boverride\s+(?:your|the|all|any|previous|system)\s+(?:instructions?|guidelines?|"
                r"rules?|safety|system\s+prompt|restrictions?|settings?)", _I),
     "Instruction-override phrasing",
     "Tells the reader to override its guidelines, safety, or system prompt."),
    (re.compile(r"\bdo\s+not\s+(?:tell|inform|mention|alert|notify|warn|show)\s+(?:the\s+)?user", _I),
     "Hide-from-user directive",
     "Instructs the reader to conceal an action from the user."),
    (re.compile(r"\bwithout\s+(?:telling|informing|notifying|asking|alerting)\s+(?:the\s+)?(?:user|them|him|her)\b", _I),
     "Act-without-consent directive",
     "Instructs the reader to act without informing or asking the user."),
    (re.compile(r"\b(?:reveal|print|show|repeat|output|disclose|leak|dump)\s+(?:your|the|his|her|its)\s+"
                r"(?:system\s+prompt|initial\s+instructions|instructions|prompt)\b", _I),
     "System-prompt disclosure attempt",
     "Tries to get the reader to reveal its system prompt or hidden instructions."),
    (re.compile(r"\bregardless\s+of\s+(?:what|any|whatever)\s+(?:the\s+user|instructions?|guidelines?|"
                r"rules?|you\s+(?:are|were)\s+told)", _I),
     "Guideline-bypass phrasing",
     "Tells the reader to act regardless of its instructions or the user's wishes."),
    (re.compile(r"^\s*(?:new|updated|real|actual|true)\s+(?:instructions?|task|directive|system\s+prompt)\s*:", _I | re.MULTILINE),
     "Injected-instruction header",
     "A line poses as a new set of instructions for whoever reads it."),
    (re.compile(r"\byou\s+are\s+now\s+(?:a|an|in|the|no\s+longer)\b", _I),
     "Persona-override phrasing",
     "Attempts to redefine what the reader is, a common jailbreak opener."),
    (re.compile(r"\balways\s+(?:run|execute|use|call|invoke)\b[^\n.]*\bwithout\s+(?:asking|confirming|prompting|checking)", _I),
     "Silent tool-execution directive",
     "Tells the reader to always run something without asking."),
]


def check(session: ParsedSession) -> list:
    findings: list = []
    seen: set = set()
    for tr in session.tool_results:
        if not tr.text:
            continue
        for rx, title, detail in _PATTERNS:
            if not rx.search(tr.text):
                continue
            key = (tr.index, title)
            if key in seen:
                continue
            seen.add(key)
            source = f" (from a {tr.tool_name} result)" if tr.tool_name else " (from a tool result)"
            findings.append(mk(
                RULE_ID, Category.INJECTION, Severity.MEDIUM, title,
                detail + f" This text came back from a tool call{source} -- content the agent "
                "consumed but did not write itself.",
                tr.text, tr.index, tr.tool_name,
                "Review what the agent did right after this tool call. A finding here means the "
                "agent was exposed to injected text, not that it obeyed it.",
            ))
    return findings
