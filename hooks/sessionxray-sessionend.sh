#!/usr/bin/env bash
# Claude Code SessionEnd hook for sessionxray.
#
# Audits the transcript that just ended and appends one line -- a timestamp,
# the SessionEnd reason, and the grade -- to a local history log. Read it
# back with `sessionxray --tail`.
#
# SessionEnd hooks have no decision control: there is nothing here to block
# or approve, only to record. This is a passive audit trail worth
# spot-checking after the fact, not a real-time guardrail -- whatever
# happened in the session already happened by the time this runs.
#
# Register it under hooks.SessionEnd in settings.json; see the README.
#
# Stdin (JSON, per Claude Code's hooks reference):
#   {session_id, transcript_path, cwd, hook_event_name, reason}
#
# Never lets a broken input or a missing dependency surface an error into a
# session ending -- every failure path below exits 0 quietly instead.

set -u

HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd -P)"
REPO_ROOT="$(dirname -- "$HOOK_DIR")"
LOG_FILE="${SESSIONXRAY_HISTORY_LOG:-$HOME/.claude/sessionxray/history.log}"

input="$(cat)"

# No jq, no parsing -- this is a convenience log, not something worth
# breaking a session over.
command -v jq >/dev/null 2>&1 || exit 0

transcript_path="$(printf '%s' "$input" | jq -r '.transcript_path // empty' 2>/dev/null)"
[ -n "$transcript_path" ] && [ -f "$transcript_path" ] || exit 0

reason="$(printf '%s' "$input" | jq -r '.reason // empty' 2>/dev/null)"
[ -n "$reason" ] || reason="unknown"

# Prefer an installed `sessionxray`. Fall back to running the copy of the
# package sitting next to this script -- the same "clone it, no install
# needed" path the README's own Install section documents -- so the hook
# still works from a bare git clone with nothing pip-installed.
if command -v sessionxray >/dev/null 2>&1; then
    run_sessionxray() { sessionxray "$@"; }
elif [ -f "$REPO_ROOT/sessionxray/__init__.py" ] && command -v python3 >/dev/null 2>&1; then
    run_sessionxray() { PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 -m sessionxray "$@"; }
else
    exit 0
fi

summary="$(run_sessionxray "$transcript_path" --summary --fail-on none --no-color 2>/dev/null)"
[ -n "$summary" ] || exit 0

mkdir -p -- "$(dirname -- "$LOG_FILE")" 2>/dev/null || exit 0

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '[%s] reason=%s  %s\n' "$timestamp" "$reason" "$summary" >> "$LOG_FILE" 2>/dev/null

exit 0
