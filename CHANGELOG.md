# Changelog

## Unreleased

Licensed GPL-3.0-or-later from this release on. Releases up to 0.1.0 stay
under MIT.

### Added

- `--select` and `--ignore` take a comma-separated list of rule IDs and drop
  those findings before grading, so a rule that is wrong for your workflow
  does not cost you the grade either.
- `--watch [DIR]` polls a directory (default `~/.claude/projects`) for new or
  changed session files and prints findings as they turn up.
  `--watch-interval` and `--watch-max-cycles` tune it.
- A `--json` or `--summary` run that trips `--fail-on` names the session and
  its worst finding on stderr.
- Subagent transcripts under `<session-id>/subagents/`, and under
  `subagents/workflows/<name>/`, are scanned with the session that spawned
  them and count toward its grade. Each finding says which subagent it came
  from. `--json` gains `agent_id` on every finding and a `subagents` list on
  every session.
- `--session-end-hook` is the SessionEnd hook in Python, inside the package,
  so a pipx install has a hook without bash, jq or a clone.
- `--json` has a top-level `unreadable` list of the files that could not be
  read.

### Changed

- A fleet scan keeps going past a file it cannot read. It names the file on
  stderr and exits 2 unless `--fail-on` already tripped.
- A flag given for a mode it does not apply to, like `--sort` without
  `--summary` or `--tail-limit` without `--tail`, is a usage error with exit
  2 instead of being ignored.
- SXR-007 evidence is the matched text with about 60 characters on each
  side, not the first 160 characters of the result.
- CI runs Python 3.14 as well.

### Fixed

- SXR-003 read `process.env`, `import.meta.env`, `Deno.env` and `Bun.env` as
  a `.env` file.
- Grep, Glob and LS calls went unchecked. Their paths now go through SXR-001
  and SXR-003 the same way a Read does.
- SXR-003 graded `~/.ssh` with no trailing slash MEDIUM instead of HIGH.
- SXR-002 missed `rm -r -f`, `rm --recursive --force`, `chmod 0777`, symbolic
  modes that let others write, and `+ref` force pushes.
- SXR-003 now knows the plaintext token files in a home directory:
  `~/.git-credentials`, `~/.npmrc`, `~/.pypirc` and the Azure CLI token
  cache.
- Evidence redaction missed a password inside a URL, `curl -u user:pass` and
  an `Authorization: Basic` header.

### Security

- Every field a report prints from the transcript is escaped: the session
  id, cwd, paths, tool names and timestamps, not only the evidence line.
  Control bytes in a crafted transcript could clear the screen or retitle
  the terminal when you read the report, and a line break in the session id
  (including U+2028 and U+2029) forged an extra row in `--summary`, in the
  history log and in `--tail`. `--json` output does not change.
- Both hooks strip control characters from the SessionEnd reason, which
  could otherwise forge a second line in the history log.

## 0.1.0 (2026-08-02)

First tagged release, under the MIT license.

- Seven checks, SXR-001 to SXR-007: filesystem reach, destructive commands,
  credential access, network egress, remote code, persistence and
  prompt-injection exposure, plus SXR-000 for a transcript it could not
  read. Each session gets a letter grade.
- The human report, `--json`, and `--summary` for a whole tree, with
  `--min-grade` and `--sort`.
- `--fail-on` for CI gates, `--project-root` and `--out`.
- A bash and jq SessionEnd hook that logs one line per session, read back
  with `--tail`.
