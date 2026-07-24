# HAWK — Hostile Assessment WorKit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0
#
# Attribution "Created by Lorenzo Serafini" must be preserved in all
# redistributed and Derivative Works — see NOTICE for details.

"""
HAWK — MSF Payload Compatibility Probe

Queries msfconsole for the list of payloads actually compatible with a given
exploit module. Used to pick a payload automatically instead of guessing
from OS fingerprint alone (which breaks on legacy x86-only modules, ARM
targets, PHP/Java userland exploits, etc.).

Strategy
========
    msfconsole -q -n -x "use <module>; show payloads; exit -y"

Then parse the "Compatible Payloads" table. Results cached in-memory for
the lifetime of HAWK (MSF modules don't change at runtime).

Public API
==========
    probe_compatible_payloads(module_name, timeout=30) -> list[str]
        Returns list of payload names. Empty list on failure/timeout.
        Uses in-memory cache — subsequent calls are instant.

    pick_best_payload(compatible, platform) -> str | None
        Given a list of compatible payloads and an OS platform string
        ("windows", "linux", ...), returns the best match from a curated
        preference order. Returns None if `compatible` is empty.

    clear_cache()
        Wipe the in-memory cache. Primarily for testing.
"""

from __future__ import annotations

import re
import subprocess
import threading
from typing import Optional

# ─── Cache ────────────────────────────────────────────────────────────────────

_CACHE: dict[str, list[str]] = {}
_CACHE_LOCK = threading.Lock()


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


# ─── Preference order ─────────────────────────────────────────────────────────
# For each platform, try payloads in this order and pick the first one that
# appears in the compatible set reported by msfconsole. Meterpreter first
# (full feature set), then raw shells, then exotic transports. x64 preferred
# over x86 when both available — matters for modern targets.

_PREFERENCE_ORDER: dict[str, list[str]] = {
    "windows": [
        "windows/x64/meterpreter/reverse_tcp",
        "windows/x64/meterpreter/reverse_https",
        "windows/x64/meterpreter/reverse_http",
        "windows/meterpreter/reverse_tcp",
        "windows/meterpreter/reverse_https",
        "windows/meterpreter/reverse_http",
        "windows/x64/shell_reverse_tcp",
        "windows/shell_reverse_tcp",
        "windows/x64/powershell_reverse_tcp",
        "windows/powershell_reverse_tcp",
        "windows/x64/shell/reverse_tcp",
        "windows/shell/reverse_tcp",
    ],
    "linux": [
        "linux/x64/meterpreter/reverse_tcp",
        "linux/x86/meterpreter/reverse_tcp",
        "linux/x64/meterpreter_reverse_tcp",
        "linux/x86/meterpreter_reverse_tcp",
        "linux/x64/shell_reverse_tcp",
        "linux/x86/shell_reverse_tcp",
        "linux/x64/shell/reverse_tcp",
        "linux/x86/shell/reverse_tcp",
        "linux/armle/meterpreter/reverse_tcp",
        "linux/armle/shell_reverse_tcp",
        "linux/mipsle/shell_reverse_tcp",
        "linux/mipsbe/shell_reverse_tcp",
        "cmd/unix/reverse_bash",
        "cmd/unix/reverse",
        "cmd/unix/reverse_python",
        "cmd/unix/reverse_perl",
        "cmd/unix/reverse_netcat",
    ],
    "unix": [
        "cmd/unix/reverse_bash",
        "cmd/unix/reverse",
        "cmd/unix/reverse_python",
        "cmd/unix/reverse_netcat",
        "cmd/unix/reverse_perl",
    ],
    "osx": [
        "osx/x64/meterpreter/reverse_tcp",
        "osx/x64/shell_reverse_tcp",
        "osx/x86/shell_reverse_tcp",
    ],
    "php": [
        "php/meterpreter/reverse_tcp",
        "php/meterpreter_reverse_tcp",
        "php/reverse_php",
    ],
    "java": [
        "java/meterpreter/reverse_tcp",
        "java/meterpreter/reverse_https",
        "java/shell_reverse_tcp",
        "java/shell/reverse_tcp",
    ],
    "python": [
        "python/meterpreter/reverse_tcp",
        "python/meterpreter_reverse_tcp",
        "python/shell_reverse_tcp",
    ],
    "android": [
        "android/meterpreter/reverse_tcp",
        "android/meterpreter/reverse_https",
        "android/shell/reverse_tcp",
    ],
}


# ─── Probe ────────────────────────────────────────────────────────────────────

# msfconsole "show payloads" output format:
#
#    Compatible Payloads
#    ===================
#
#       #   Name                             ... Description
#       -   ----                             ... -----------
#       0   generic/custom                   ... Custom Payload
#       1   generic/shell_bind_tcp           ... Generic Command Shell, Bind
#       2   windows/x64/meterpreter/reverse_tcp ...
#
# We look for lines starting with "   <digits>   <name>"
_ROW_RE = re.compile(r"^\s*\d+\s+(\S+)")


def _parse_show_payloads(output: str) -> list[str]:
    """Extract payload names from the "Compatible Payloads" table."""
    lines = output.splitlines()
    payloads: list[str] = []
    in_table = False
    saw_header_dashes = False

    for ln in lines:
        low = ln.strip().lower()

        if not in_table:
            if "compatible payloads" in low:
                in_table = True
            continue

        if not saw_header_dashes:
            # Look for the dashes row under the column headers
            if set(ln.strip()) <= {"-", " "} and "-" in ln:
                saw_header_dashes = True
            continue

        # Blank line after the table → stop
        if not ln.strip():
            if payloads:
                break
            continue

        m = _ROW_RE.match(ln)
        if m:
            name = m.group(1)
            # Payload names always contain a slash; skip stray rows
            if "/" in name:
                payloads.append(name)

    return payloads


def probe_compatible_payloads(module_name: str,
                              timeout: int = 30) -> list[str]:
    """Return payloads compatible with `module_name` as reported by msfconsole.

    Returns [] on error/timeout. Cached per process.
    """
    if not module_name:
        return []

    # Cache hit?
    with _CACHE_LOCK:
        if module_name in _CACHE:
            return list(_CACHE[module_name])

    # msfconsole: -q quiet banner, -n no database (faster start),
    # -x run commands then exit.
    cmd = [
        "msfconsole", "-q", "-n",
        "-x", f"use {module_name}; show payloads; exit -y",
    ]

    try:
        from utils.runner import _hawk_env
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env=_hawk_env(),
        )
        payloads = _parse_show_payloads(proc.stdout or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        payloads = []
    except Exception:
        payloads = []

    # Cache — even empty results, so we don't retry a failing probe in a loop.
    with _CACHE_LOCK:
        _CACHE[module_name] = list(payloads)

    return list(payloads)


# ─── Picker ───────────────────────────────────────────────────────────────────

def _platform_key(platform: str) -> Optional[str]:
    """Map a free-form platform string to a key in _PREFERENCE_ORDER."""
    if not platform:
        return None
    low = platform.lower()
    for key in _PREFERENCE_ORDER.keys():
        if key in low:
            return key
    return None


def pick_best_payload(compatible: list[str],
                      platform: str = "") -> Optional[str]:
    """Choose the best payload from `compatible` given OS `platform`.

    Algorithm:
      1. If `platform` maps to a preference list → return first match in that
         list that appears in `compatible`.
      2. Fallback: any meterpreter payload in `compatible`.
      3. Fallback: any reverse-connecting payload.
      4. Fallback: first entry in `compatible`.
      5. If `compatible` is empty → None.
    """
    if not compatible:
        return None

    compat_set = set(compatible)

    # 1. Platform preference
    key = _platform_key(platform)
    if key:
        for p in _PREFERENCE_ORDER[key]:
            if p in compat_set:
                return p

    # 2. Any meterpreter
    for p in compatible:
        if "meterpreter" in p.lower():
            return p

    # 3. Any reverse shell
    for p in compatible:
        if "reverse" in p.lower():
            return p

    # 4. First entry
    return compatible[0]
