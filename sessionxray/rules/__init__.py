"""Rule registry. Each rule module exposes `check(session) -> list[Finding]`."""

from __future__ import annotations

from . import (
    destructive,
    filesystem,
    injection,
    network,
    persistence,
    remote_code,
    secrets,
)

# Order is cosmetic; findings are sorted by severity at report time.
ALL_RULES = [
    filesystem.check,
    destructive.check,
    secrets.check,
    network.check,
    remote_code.check,
    persistence.check,
    injection.check,
]


def run_all(session) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(session))
    return findings
