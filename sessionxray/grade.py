"""Turn a session's findings into a security letter grade.

The score starts at 100 and loses points per finding by severity. Two hard
caps encode the opinion that matters: any unresolved CRITICAL means "read
this session before you trust anything downstream of it" (grade F), and any
HIGH keeps it out of the top band (at most C).

Each severity tier's total contribution is also capped before it's summed.
Without that, a long, ordinary session (a research agent that visited forty
pages, each one its own MEDIUM "outbound network request") would grade the
same as a genuinely alarming one, purely from volume -- MEDIUM and LOW are
"worth a look," and looking at forty unremarkable things is still
unremarkable. HIGH and CRITICAL are not volume-capped the same way: several
destructive commands really is worse than one.
"""

from __future__ import annotations

from .finding import Severity

_WEIGHT = {
    Severity.CRITICAL: 45,
    Severity.HIGH: 15,
    Severity.MEDIUM: 6,
    Severity.LOW: 2,
    Severity.INFO: 0,
}
_TIER_CAP = {
    Severity.CRITICAL: None,  # uncapped; irrelevant anyway, any CRITICAL forces F
    Severity.HIGH: 60,
    Severity.MEDIUM: 20,
    Severity.LOW: 10,
    Severity.INFO: 0,
}


def grade(findings) -> tuple[str, int]:
    per_tier: dict = {s: 0 for s in Severity}
    n_crit = n_high = 0
    for f in findings:
        per_tier[f.severity] += _WEIGHT.get(f.severity, 0)
        if f.severity == Severity.CRITICAL:
            n_crit += 1
        elif f.severity == Severity.HIGH:
            n_high += 1

    score = 100
    for sev, total in per_tier.items():
        cap = _TIER_CAP.get(sev)
        score -= total if cap is None else min(total, cap)
    score = max(0, min(100, score))

    if n_crit:
        return "F", score
    if n_high:
        score = min(score, 76)  # keep out of the A/B band
    return _letter(score), score


def _letter(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"
