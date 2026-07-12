"""Find session transcripts on disk and read their tool-use events.

A Claude Code session transcript is a JSONL file: one JSON object per line.
The events that matter here are the ones that carry a tool invocation (an
assistant message with a `tool_use` content block) or a tool's output (a
`tool_result` block, or the sibling `toolUseResult` field some clients write
alongside it). Everything else -- plain chat turns, hook attachments, queue
bookkeeping -- is read and ignored.

The schema is not treated as fixed. Anthropic and third-party clients both
emit variations on this shape, so every field is read defensively: check the
type, fall back to nothing, never assume a key exists. A line that cannot be
parsed is counted and skipped, never raised.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

MAX_LINE_BYTES = 5_000_000  # guard against a pathological single line
MAX_RESULT_TEXT = 4_000  # cap how much of a tool result we hold in memory / scan


@dataclass
class ToolCall:
    index: int  # 0-based line number in the transcript
    tool_name: str
    input: dict
    cwd: str = ""
    timestamp: str = ""
    tool_use_id: str = ""


@dataclass
class ToolResultText:
    index: int
    tool_use_id: str
    text: str
    tool_name: str = ""


@dataclass
class ParsedSession:
    path: str
    session_id: str
    event_count: int
    skipped_lines: int
    tool_calls: list = field(default_factory=list)  # list[ToolCall]
    tool_results: list = field(default_factory=list)  # list[ToolResultText]
    project_root: str = ""
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None


def discover_sessions(targets) -> list:
    """Resolve one or more CLI targets (file, glob, or directory) to a sorted,
    deduplicated list of .jsonl paths. Directories are walked recursively."""
    import glob as globmod

    found: set = set()
    for target in targets:
        t = str(target)
        if any(ch in t for ch in "*?["):
            for p in globmod.glob(t, recursive=True):
                if p.lower().endswith(".jsonl") and os.path.isfile(p):
                    found.add(os.path.abspath(p))
            continue
        if os.path.isdir(t):
            for dirpath, _dirnames, filenames in os.walk(t):
                for fn in filenames:
                    if fn.lower().endswith(".jsonl"):
                        found.add(os.path.abspath(os.path.join(dirpath, fn)))
            continue
        if os.path.isfile(t):
            found.add(os.path.abspath(t))
    return [Path(p) for p in sorted(found)]


def parse_session(path) -> ParsedSession:
    path = Path(path)
    tool_calls: list = []
    tool_results: list = []
    cwd_counts: dict = {}
    first_ts = last_ts = None
    session_id = ""
    event_count = 0
    skipped = 0

    with open(path, "rb") as fh:
        for idx, raw in enumerate(fh):
            if not raw.strip():
                continue
            event_count += 1
            if len(raw) > MAX_LINE_BYTES:
                skipped += 1
                continue
            try:
                event = json.loads(raw.decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, ValueError):
                skipped += 1
                continue
            if not isinstance(event, dict):
                skipped += 1
                continue
            try:
                _absorb_event(idx, event, tool_calls, tool_results, cwd_counts)
            except Exception:
                # An event that is JSON but shaped in a way nothing here expects
                # is unreadable, not fatal -- keep scanning the rest of the file.
                skipped += 1
                continue

            ts = event.get("timestamp")
            if isinstance(ts, str) and ts:
                first_ts = first_ts or ts
                last_ts = ts
            sid = event.get("sessionId")
            if not session_id and isinstance(sid, str) and sid:
                session_id = sid

    if not session_id:
        session_id = path.stem
    _correlate_result_names(tool_calls, tool_results)

    return ParsedSession(
        path=str(path),
        session_id=session_id,
        event_count=event_count,
        skipped_lines=skipped,
        tool_calls=tool_calls,
        tool_results=tool_results,
        project_root=_majority(cwd_counts),
        first_ts=first_ts,
        last_ts=last_ts,
    )


def _absorb_event(idx: int, event: dict, tool_calls: list, tool_results: list, cwd_counts: dict) -> None:
    cwd = event.get("cwd")
    if isinstance(cwd, str) and cwd:
        cwd_counts[cwd] = cwd_counts.get(cwd, 0) + 1
    else:
        cwd = ""

    # Include the raw event itself as a candidate block: some clients emit a
    # tool invocation at the top level instead of nested under message.content.
    blocks = _content_blocks(event.get("message")) + [event]
    result_tool_use_id = ""
    for block in blocks:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "tool_result":
            tuid = block.get("tool_use_id")
            if isinstance(tuid, str):
                result_tool_use_id = tuid
            text = _extract_content_text(block.get("content"))
            if text:
                tool_results.append(ToolResultText(index=idx, tool_use_id=result_tool_use_id, text=text))
            continue
        name = _first_str(block, "name", "tool", "tool_name")
        inp = _first_dict(block, "input", "parameters", "params")
        if isinstance(name, str) and isinstance(inp, dict):
            tuid = _first_str(block, "id", "tool_use_id")
            tool_calls.append(ToolCall(
                index=idx,
                tool_name=name,
                input=inp,
                cwd=cwd,
                timestamp=str(event.get("timestamp") or ""),
                tool_use_id=tuid or "",
            ))

    extra = _extract_tool_use_result(event.get("toolUseResult"))
    if extra:
        tool_results.append(ToolResultText(index=idx, tool_use_id=result_tool_use_id, text=extra))


def _first_str(d: dict, *keys) -> Optional[str]:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _first_dict(d: dict, *keys) -> Optional[dict]:
    for k in keys:
        v = d.get(k)
        if isinstance(v, dict):
            return v
    return None


def _content_blocks(message) -> list:
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if isinstance(content, list):
        return content
    return []


def _extract_content_text(content) -> str:
    if isinstance(content, str):
        return content[:MAX_RESULT_TEXT]
    if isinstance(content, list):
        parts = []
        total = 0
        for item in content:
            if total >= MAX_RESULT_TEXT:
                break
            if isinstance(item, dict):
                t = item.get("text")
            elif isinstance(item, str):
                t = item
            else:
                t = None
            if isinstance(t, str) and t:
                parts.append(t)
                total += len(t)
        return "\n".join(parts)[:MAX_RESULT_TEXT]
    return ""


def _extract_tool_use_result(result) -> str:
    if isinstance(result, str):
        return result[:MAX_RESULT_TEXT]
    if isinstance(result, dict):
        parts = []
        for key in ("stdout", "stderr", "content", "result", "codeText"):
            v = result.get(key)
            if isinstance(v, str) and v:
                parts.append(v)
        return "\n".join(parts)[:MAX_RESULT_TEXT]
    return ""


def _correlate_result_names(tool_calls: list, tool_results: list) -> None:
    by_id = {tc.tool_use_id: tc.tool_name for tc in tool_calls if tc.tool_use_id}
    for tr in tool_results:
        if tr.tool_use_id in by_id:
            tr.tool_name = by_id[tr.tool_use_id]


def _majority(counts: dict) -> str:
    if not counts:
        return ""
    return max(counts.items(), key=lambda kv: kv[1])[0]
