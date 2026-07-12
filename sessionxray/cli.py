"""Command-line interface for sessionxray."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .discovery import discover_sessions
from .finding import Severity
from .report import render_human, render_json, render_summary
from .scanner import scan_session


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sessionxray",
        description="Security audit for a Claude Code session transcript: what did the "
                     "agent touch, and should any of it worry you.",
    )
    p.add_argument("targets", nargs="+",
                    help="session .jsonl file(s), a glob, or a directory to walk")
    p.add_argument("--project-root", metavar="PATH",
                    help="override the inferred project root for every session scanned")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="machine-readable JSON output")
    out.add_argument("--summary", action="store_true",
                      help="one line per session, for triaging a whole directory")
    p.add_argument("--fail-on", default="high", metavar="SEVERITY",
                   help="exit non-zero if any finding is at or above this severity "
                        "(critical|high|medium|low|info|none; default: high)")
    p.add_argument("--out", metavar="PATH", help="write the report to this file instead of stdout")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument("--version", action="version", version=f"sessionxray {__version__}")
    return p


def _fail_threshold(value: str):
    value = value.strip().lower()
    if value in ("none", "off", "never"):
        return None
    try:
        return Severity.parse(value)
    except ValueError:
        raise SystemExit(f"sessionxray: invalid --fail-on value {value!r}")


def _looks_like_glob(target: str) -> bool:
    return any(ch in target for ch in "*?[")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    threshold = _fail_threshold(args.fail_on)

    missing = [t for t in args.targets if not _looks_like_glob(t) and not os.path.exists(t)]
    for t in missing:
        print(f"sessionxray: no such path: {t}", file=sys.stderr)
    if missing:
        return 2

    paths = discover_sessions(args.targets)
    if not paths:
        print("sessionxray: no .jsonl session files found in the given target(s)", file=sys.stderr)
        return 2

    try:
        results = [scan_session(p, args.project_root) for p in paths]
    except OSError as e:
        print(f"sessionxray: {e}", file=sys.stderr)
        return 2

    color = not args.no_color and not args.out and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    if args.json:
        output = render_json(results)
    elif args.summary:
        output = render_summary(results, color=color)
    else:
        output = render_human(results, color=color)

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(output.rstrip("\n") + "\n")
        except OSError as e:
            print(f"sessionxray: could not write --out file: {e}", file=sys.stderr)
            return 2
    else:
        print(output)

    if threshold is not None:
        worst = max((r.worst() for r in results if r.worst() is not None), default=None)
        if worst is not None and worst >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
