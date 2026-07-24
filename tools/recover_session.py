#!/usr/bin/env python3
# HAWK — Hostile Assessment WorKit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0

"""
HAWK — session JSON recovery tool.

Usage:
    python3 tools/recover_session.py <path-to-broken-session.json>

Recovers session files corrupted by the pre-fix widget-ref
serialization bug (`_frame_ref`, `_badge_ref`, `_mark_btn_ref`
values that weren't JSON-serializable made json.dump fail
mid-write, leaving a truncated / invalid file).

Strategy:
  1. Strip every `"_frame_ref": …`, `"_badge_ref": …`,
     `"_mark_btn_ref": …` key-value line (whatever the value is —
     string, null, unterminated).
  2. Walk the JSON character-by-character with a brace counter to
     find the deepest well-formed prefix.
  3. Close any still-open brackets/braces to produce a valid JSON.
  4. Recursively strip any deep widget-ref keys that survived inside
     nested structures.
  5. Write <original>_recovered.json next to the source file.

Reports a detailed content summary so the user knows what was
salvaged and what (if anything) was dropped by the truncation.
"""

from __future__ import annotations

import json
import os
import re
import sys


_WIDGET_REF_KEYS = ("_frame_ref", "_badge_ref", "_mark_btn_ref")


def _strip_widget_ref_lines(text: str) -> str:
    """First pass — remove dangling widget-ref lines by regex."""
    # Each pattern matches a different flavour of the broken line:
    patterns = [
        # Value is a properly-quoted string
        r',?\s*"_(?:frame|badge|mark_btn)_ref"\s*:\s*"[^"]*"\s*,?',
        # Value is null
        r',?\s*"_(?:frame|badge|mark_btn)_ref"\s*:\s*null\s*,?',
        # Value is a python-repr angle-bracket <Widget ...>
        r',?\s*"_(?:frame|badge|mark_btn)_ref"\s*:\s*<[^>]*>\s*,?',
        # Value is truncated (colon followed by nothing)
        r',?\s*"_(?:frame|badge|mark_btn)_ref"\s*:\s*(?=[\r\n]|$)',
        # Value is truncated mid-literal (no closing quote before EOL)
        r',?\s*"_(?:frame|badge|mark_btn)_ref"\s*:\s*[^,}\n\r]*(?=[\r\n]|$)',
    ]
    for p in patterns:
        text = re.sub(p, '', text, flags=re.MULTILINE)
    # Collapse dangling commas before a closing brace / bracket
    text = re.sub(r',(\s*[}\]])', r'\1', text)
    # Collapse consecutive commas
    text = re.sub(r',\s*,+', ',', text)
    return text


def _find_last_safe_prefix(text: str) -> int:
    """Walk the text char by char, tracking brace depth + string
    context.  Return the byte offset of the last '}' or ']' that
    was followed by a comma, closing brace, or closing bracket —
    i.e. the last structurally-safe boundary we can truncate at."""
    depth = 0
    in_str = False
    escape = False
    last_safe = -1
    for i, c in enumerate(text):
        if escape:
            escape = False
            continue
        if in_str:
            if c == '\\':
                escape = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
            continue
        if c in '{[':
            depth += 1
        elif c in '}]':
            depth -= 1
            if depth >= 0:
                j = i + 1
                while j < len(text) and text[j] in ' \t\n\r':
                    j += 1
                if j < len(text) and text[j] in ',}]':
                    last_safe = i
                elif j >= len(text) and depth == 0:
                    last_safe = i
    return last_safe


def _close_open_brackets(text: str) -> str:
    """Count unmatched open braces/brackets — STRING-AWARE, because
    the text contains command-line examples inside `description`
    fields that have literal `{` / `}` chars.  A naive .count()
    would over-count openers.  Returns the text with appropriate
    closers appended in the right order."""
    stack = []          # "]" or "}" — what we still need to close
    in_str = False
    escape = False
    for c in text:
        if escape:
            escape = False
            continue
        if in_str:
            if c == '\\':
                escape = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
            continue
        if c == '{':
            stack.append('}')
        elif c == '[':
            stack.append(']')
        elif c in '}]':
            if stack and stack[-1] == c:
                stack.pop()
    text = text.rstrip(' \t\n\r,')
    # Close in reverse order (deepest first → outer last)
    return text + ''.join(reversed(stack))


def _deep_strip_widget_refs(obj):
    """Recursively remove widget-ref keys from a parsed object."""
    if isinstance(obj, dict):
        return {k: _deep_strip_widget_refs(v) for k, v in obj.items()
                if k not in _WIDGET_REF_KEYS}
    if isinstance(obj, list):
        return [_deep_strip_widget_refs(x) for x in obj]
    return obj


def recover(src: str) -> str:
    dst = src.rsplit('.json', 1)[0] + '_recovered.json'

    with open(src, 'r', encoding='utf-8', errors='replace') as f:
        original = f.read()

    print(f'Original file size: {len(original):,} bytes')

    # Pass 1 — strip dangling widget-ref lines
    cleaned = _strip_widget_ref_lines(original)
    stripped = len(original) - len(cleaned)
    print(f'Pass 1 (widget-ref strip):  removed {stripped} bytes')

    # Try parsing after pass 1
    try:
        data = json.loads(cleaned)
        print('[OK] parsed directly after strip — no truncation needed')
    except json.JSONDecodeError as e:
        print(f'Pass 1 still invalid: line {e.lineno} col {e.colno}: '
              f'{e.msg}')
        # Pass 2 — find last safe boundary + close open brackets
        last_safe = _find_last_safe_prefix(cleaned)
        if last_safe < 0:
            print('[FAIL] no structurally safe boundary found')
            return ''
        print(f'Pass 2 (truncate): safe boundary at byte {last_safe} '
              f'(losing {len(cleaned)-last_safe-1} bytes from tail)')
        stub = cleaned[:last_safe + 1]
        stub = _close_open_brackets(stub)
        try:
            data = json.loads(stub)
            print('[OK] recovered after truncation + auto-close')
        except json.JSONDecodeError as e2:
            print(f'[FAIL] truncation recovery failed: {e2}')
            return ''

    # Pass 3 — deep-clean any surviving widget-ref keys
    data = _deep_strip_widget_refs(data)

    # Report what we got
    print()
    print('=== RECOVERED CONTENT ===')
    for k in ('session_id', 'target_ip', 'target_domain',
              'platform', 'detected_os'):
        v = str(data.get(k, ''))[:70]
        print(f'  {k:18s} : {v}')
    for k in ('saved_at', 'terminal_lines', 'credentials',
              'executed_tools', 'discovered_users',
              'discovered_shares', 'discovered_groups'):
        n = len(data.get(k) or [])
        print(f'  {k:18s} : {n} entries')
    ti = data.get('target_intel') or {}
    print(f'  target_intel:')
    print(f'    fingerprint    : '
          f'{"PRESENT" if ti.get("fingerprint") else "empty"}')
    print(f'    auto_findings  : {len(ti.get("auto_findings") or [])} entries')
    print(f'    exploits       : {len(ti.get("exploits") or [])} entries')

    with open(dst, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print()
    print(f'✓ Recovered file: {dst}')
    print(f'  Size: {os.path.getsize(dst):,} bytes')
    return dst


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    src = sys.argv[1]
    if not os.path.isfile(src):
        print(f'File not found: {src}')
        sys.exit(1)
    out = recover(src)
    if not out:
        sys.exit(1)


if __name__ == '__main__':
    main()
