# Security

sessionxray reads Claude Code transcripts, and a transcript is untrusted input:
it contains whatever the agent read, fetched, and executed, which means it can
contain content an attacker planted for the agent to see. The tool treats it
that way - it parses the JSONL, matches patterns, and prints a report. It never
executes anything it finds, never re-fetches URLs from the transcript, and
never talks to the network.

The scanner itself is the attack surface. A transcript crafted to crash the
parser, to hide a finding (make a dangerous command grade clean), or to smuggle
terminal escape sequences into the report so they execute in your terminal when
you read it - those are vulnerabilities in sessionxray. A detection gap (agent
behavior the tool should reasonably flag but doesn't) is welcome as a regular
issue with a sample transcript.

## Reporting a vulnerability

Please don't open a public issue for security problems. Use GitHub's private
reporting instead:

https://github.com/munzzyy/sessionxray/security/advisories/new

Include what you found, how to reproduce it, and the impact you'd expect.

## Supported versions

Fixes land on the latest tagged version; there's no backport policy.
