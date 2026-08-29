"""Rule registry. Each rule module exposes `check(session) -> list[Finding]`."""

from __future__ import annotations

from . import (
    destructive,
    filesystem,
    injection,
    integrity,
    network,
    persistence,
    remote_code,
    secrets,
)

# Order is cosmetic; findings are sorted by severity at report time.
ALL_RULES = [
    integrity.check,
    filesystem.check,
    destructive.check,
    secrets.check,
    network.check,
    remote_code.check,
    persistence.check,
    injection.check,
]

# Every rule ID this build knows about, for validating --select/--ignore
# before a scan runs instead of silently matching nothing on a typo.
ALL_RULE_IDS = frozenset({
    integrity.RULE_ID,
    filesystem.RULE_ID,
    destructive.RULE_ID,
    secrets.RULE_ID,
    network.RULE_ID,
    remote_code.RULE_ID,
    persistence.RULE_ID,
    injection.RULE_ID,
})


def run_all(session) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(session))
    return findings
