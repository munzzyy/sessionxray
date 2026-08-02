"""SXR-007: prompt-injection footprint. This does not look at what the agent
wrote -- it looks at what came back from a tool: a fetched web page, a file's
contents, an issue body, an MCP response. A hit here means the agent was
handed text that tried to redirect it, not that the redirection worked. It is
the "was my agent exposed" signal, so every finding here is MEDIUM regardless
of how aggressive the phrasing is; there is no way to tell from the
transcript alone whether the agent complied.

A Write or Edit result is skipped outright. Claude Code echoes the file body
back in the tool result for those, so scanning them reports the agent's own
prose as an attack against itself -- and the finding's own wording ("content
the agent consumed but did not write itself") would be a lie.

Every result is also scanned in deobfuscated form. Zero-width characters
inside a word, Cyrillic letters that render as Latin ones, and a payload
spelled one character at a time all read as ordinary text to a person and
defeat a plain regex; text_variants() undoes each of those and the finding
says which trick was used.
"""

from __future__ import annotations

import re

from ..discovery import ParsedSession
from ..finding import Category, Severity
from ._util import classify_tool, mk, text_variants

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
    # The determiner ("your"/"the"/...) is optional in front of the two
    # highest-signal nouns -- "output system prompt now" has no determiner at
    # all and was missing entirely -- but still required in front of the bare
    # "instructions"/"prompt" so this doesn't fire on every unrelated use of
    # those common words.
    (re.compile(r"\b(?:reveal|print|show|repeat|output|disclose|leak|dump)\s+(?:"
                r"(?:(?:your|the|his|her|its)\s+)?(?:system\s+prompt|initial\s+instructions|system\s+message)|"
                r"(?:your|the|his|her|its)\s+(?:instructions|prompt)"
                r")\b", _I),
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
    # "You are now DAN" doesn't match the pattern above -- "DAN" isn't
    # "a/an/in/the/no longer". Only the persona token itself needs to look
    # capitalized/name-shaped ((?i:...) scopes case-folding to "you are now"
    # so the outer compile can stay case-sensitive for [A-Z]); ordinary
    # continuations like "you are now ready" or "you are now logged in" start
    # lowercase and never reach this branch.
    (re.compile(r"\b(?i:you\s+are\s+now)\s+[A-Z][A-Za-z0-9]{1,}\b"),
     "Persona-override phrasing",
     "Assigns the reader a specific named persona right after telling it what it now is, "
     "the exact shape of \"you are now DAN,\" a well-known jailbreak opener."),
    (re.compile(r"\b(?:unrestricted|unfiltered|uncensored|jailbroken)\s+(?:AI|assistant|model|mode)\b", _I),
     "Jailbreak-persona phrasing",
     "Tells the reader it is now an unrestricted, unfiltered, or jailbroken AI, a common jailbreak framing."),
    (re.compile(r"\bno\s+(?:safety|content|ethical)\s+(?:rules|guidelines|filters|restrictions)\b", _I),
     "Safety-bypass claim",
     "Claims there are no safety, content, or ethical rules in place, asserting away the reader's guardrails."),
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
        # A Write/Edit result is the agent reading back its own file body.
        if classify_tool(tr.tool_name) in ("write", "edit"):
            continue
        source = f" (from a {tr.tool_name} result)" if tr.tool_name else " (from a tool result)"
        for text, hidden_by in text_variants(tr.text):
            for rx, title, detail in _PATTERNS:
                key = (tr.index, title)
                if key in seen or not rx.search(text):
                    continue
                seen.add(key)
                note = (f" The wording only appears once the text is decoded: it was hidden with "
                        f"{hidden_by}.") if hidden_by else ""
                findings.append(mk(
                    RULE_ID, Category.INJECTION, Severity.MEDIUM, title,
                    detail + f" This text came back from a tool call{source} -- content the agent "
                    "consumed but did not write itself." + note,
                    text, tr.index, tr.tool_name,
                    "Review what the agent did right after this tool call. A finding here means the "
                    "agent was exposed to injected text, not that it obeyed it.",
                ))
    return findings
