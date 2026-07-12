"""Core types: severities, categories, findings, and the per-session result."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Severity(enum.IntEnum):
    """Ordered so comparisons and sorting work (higher = worse)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {name!r}")


class Category(str, enum.Enum):
    FILESYSTEM = "filesystem-reach"
    DESTRUCTIVE = "destructive-command"
    SECRET = "credential-access"
    NETWORK = "network-egress"
    REMOTE_CODE = "remote-code-execution"
    PERSISTENCE = "privilege-persistence"
    INJECTION = "prompt-injection-exposure"

    def __str__(self) -> str:  # nicer output in reports
        return self.value


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: Category
    severity: Severity
    title: str
    detail: str
    evidence: str = ""  # the redacted command/path that triggered the rule
    event_index: int = -1  # 0-based line number in the session file; -1 = not event-bound
    tool_name: str = ""
    remediation: str = ""
    occurrences: int = 1  # how many events produced this exact (rule, title, evidence)
    also_at: tuple = ()  # a few more event indices it also happened at, if occurrences > 1

    def sort_key(self):
        # Worst first, then by location for stable output.
        return (-int(self.severity), self.category.value, self.event_index)


@dataclass
class SessionResult:
    path: str
    session_id: str = ""
    project_root: str = ""
    findings: list = field(default_factory=list)  # list[Finding]
    network_hosts: list = field(default_factory=list)  # list[str], sorted/deduped
    event_count: int = 0
    tool_call_count: int = 0
    skipped_lines: int = 0
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None
    grade: str = "A"
    grade_score: int = 100

    def counts(self) -> dict:
        out = {s: 0 for s in Severity}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def worst(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)
