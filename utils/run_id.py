# HAWK — Hostile Assessment WorKit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""
HAWK — run-id correlation helper.

Every AD-pentesting tool parser that pushes BOTH credentials AND
findings from the same tool run attaches a unique `linked_run_id` to
every output it creates.  Same id = same provenance = linked.

The UI exposes this as two small navigation buttons:
  • "→ intel"  on every cred row in the Credential Store
  • "🔑 creds"  on every finding card in Target Intel
Click → switch tab → scroll + highlight the matching counterpart.

This module provides:
  • new_run_id()        — a fresh UUID for each tool run
  • TOOL_RUN_CATEGORY   — const used by Credential.category to mark
                          creds produced by AD tools (vs. imported
                          or manually-added).  Drives the "AD RESULTS"
                          box grouping in the Credential Store UI.
"""

from __future__ import annotations

import uuid


#: Credential.category value for entries pushed by AD-pentesting tool
#: parsers (bloodhound, addcomputer, secretsdump DCSync, kerberoast,
#: asrep-roast, certipy, adidnsdump, ldapdomaindump, nxc-ldap).
#: The Credential Store renders these in a dedicated "AD RESULTS"
#: section below the main cred list.  Non-AD creds (manual, hydra,
#: clipboard import) have category="" and render in the main list.
TOOL_RUN_CATEGORY = "ad_result"


def new_run_id() -> str:
    """Return a fresh, short, URL-safe UUID for a tool run.

    8 hex chars is enough to avoid collisions within a single HAWK
    session (chance of two IDs colliding across ~1000 tool runs is
    ~10^-6).  Keeping it short makes the scrolling animation log
    readable:  "→ intel: ad3f8c22" vs the full 36-char form.
    """
    return uuid.uuid4().hex[:12]
