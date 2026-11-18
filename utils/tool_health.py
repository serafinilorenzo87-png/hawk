# HAWK — Hostile Assessment War-Kit
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
HAWK - Tool health check.

A small, extensible catalogue of tools with KNOWN breakages on recent Kali
(typically Python 3.13 dependency clashes), each with a cheap smoke test and a
one-command fix. `check()` runs the smoke test only for the catalogue tools that
are actually installed, and returns the ones that are present but broken.

Deliberately narrow: this is NOT a general "is every tool working" probe (that
would mean launching dozens of processes at startup). It only covers the few
cases that are known to fail silently and waste the operator's time, so the cost
is a handful of `--version` calls at most.

No GUI imports here — safe to call from a background thread.
"""

import shutil
import subprocess

# Each entry:
#   id              - catalogue key
#   name            - shown in the dialog
#   binary          - what to probe on PATH (defaults to id)
#   smoke           - argv for the smoke test (a cheap, side-effect-free call)
#   bad_signatures  - substrings in stdout/stderr that mark a known breakage
#   fix_cmd         - the one-shot fix, run in an external terminal by the dialog
#   why             - one line: what breaks and what the fix does
_KNOWN = [
    {
        "id": "netexec",
        "name": "NetExec (nxc)",
        "binary": "nxc",
        "smoke": ["nxc", "--version"],
        "bad_signatures": (
            "httpcore", "typing.Union", "AttributeError",
            "ModuleNotFoundError", "Traceback",
        ),
        "fix_cmd": ("sudo apt remove -y netexec; pipx install netexec; "
                    "pipx ensurepath"),
        "why": ("netexec from apt pulls an httpcore too old for Kali 2025's "
                "Python 3.13, so it crashes on import before reaching any "
                "target. Reinstalling it isolated with pipx brings fresh, "
                "compatible dependencies."),
    },
]


def _is_broken(entry) -> bool:
    """True if the tool is installed but its smoke test fails with a known-bad
    signature. Best-effort and conservative: anything uncertain returns False
    so HAWK never cries wolf. Never raises."""
    binary = entry.get("binary") or entry["id"]
    if not shutil.which(binary):
        return False  # not installed — the card's own install flow handles it
    try:
        r = subprocess.run(entry["smoke"], capture_output=True, text=True,
                           timeout=10)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return False  # could not run it cleanly — don't flag it
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode != 0 and any(sig in out
                                     for sig in entry["bad_signatures"])


def check() -> list:
    """Return the catalogue entries whose tool is installed but broken.

    Cheap: runs a smoke test only for the few known-problem tools that are
    actually present. Safe to call from a background thread; swallows all
    errors so a health probe never takes HAWK down."""
    broken = []
    for entry in _KNOWN:
        try:
            if _is_broken(entry):
                broken.append(entry)
        except Exception:
            pass
    return broken
