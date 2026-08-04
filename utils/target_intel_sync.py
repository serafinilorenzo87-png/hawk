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
Target Intel panel -> session snapshot (Tk-free).

The Target Intel panel holds the LIVE state of a run: the OS fingerprint,
the exploit list and — above all — ``_auto_findings``, the dicts the tool
parsers push as they detect things.  ``session.target_intel`` is only a
SNAPSHOT of that panel: nothing writes into it until somebody takes one.

There used to be exactly two places that took it — manual SAVE and the
autosave tick — with the block copy-pasted in both.  The report engine
reads the SESSION, not the panel, so exporting before ever saving (and
autosave is OFF by default) produced a report with zero findings, no
Target Intelligence section and no error.  The snapshot now lives here,
in one helper that both save paths AND the report path call, so "what the
session knows" can no longer drift from "what the panel shows".

Kept free of tkinter on purpose: the report path has to be able to take
the snapshot from headless code (and from a test without a display).
"""

from __future__ import annotations

import sys

# Keys we store on finding dicts to hold live Tk widget references —
# used by target_intel_widget.TargetIntelWidget._apply_read_style to
# repaint a single finding card in place instead of rerendering the
# whole auto_findings section.  These MUST be stripped before the
# session is serialised to JSON — Tk widgets are not JSON-serialisable.
#
# `_raw_description` carries the un-masked counterpart of a finding's
# description (Bloody Crawl JS-secret values).  It's deliberately kept
# in memory only — writing real tokens / emails / endpoints to a
# session JSON on disk would defeat the masking design (`mask_secret`
# in utils/web_findings.py).  After SAVE/LOAD the SHOW RAW toggle is
# disabled until the parser re-runs.
FINDING_NON_PERSISTED_KEYS = (
    "_frame_ref", "_badge_ref", "_mark_btn_ref",
    "_raw_description",
    # AI-OPS finding side-data captured at probe time.  Re-detected
    # on the next probe run so it doesn't need to survive save/load.
    "_aiops_detected_version",
)


def strip_finding_widget_refs(findings):
    """Return a list of shallow-cloned finding dicts with widget
    references and other in-memory-only keys removed so the session
    serialiser doesn't trip on tkinter widget objects and doesn't leak
    un-masked secrets to disk.

    The clone copies EVERY other key verbatim, curation keys included —
    which is why curation has to be written onto the live panel dicts
    (see modules/report/curation.py): a clone inherits the curation, a
    live dict never inherits it back from a clone."""
    out = []
    for f in findings or []:
        if not isinstance(f, dict):
            out.append(f)
            continue
        clean = {k: v for k, v in f.items()
                 if k not in FINDING_NON_PERSISTED_KEYS}
        out.append(clean)
    return out


def sync_target_intel(app, session) -> bool:
    """Snapshot the live Target Intel panel into ``session.target_intel``.

    Writes exactly the three keys the two save paths have always written
    (fingerprint / exploits / auto_findings), so the on-disk schema is
    unchanged.  The panel holds live Python objects (OSFingerprint,
    ExploitEntry) that the JSON encoder can't serialise directly, hence
    the explicit ``to_dict()`` calls.

    Idempotent and cheap — calling it twice just rewrites the same three
    keys — so every path that is about to READ the session's view of the
    findings (save, autosave, report) can call it first.

    Returns True when a snapshot was taken, False when there was nothing
    to snapshot or the panel could not be read (diagnostic printed; a
    failed snapshot must never abort the save or the report)."""
    if session is None:
        return False
    try:
        intel = getattr(app, "target_intel", None)
        if intel is None:
            return False
        fp = getattr(intel, "_fp", None)
        exploits = getattr(intel, "_exploits", []) or []
        session.set_target_intel({
            "fingerprint":   (fp.to_dict() if fp is not None and
                              hasattr(fp, "to_dict") else None),
            "exploits":      [(e.to_dict() if hasattr(e, "to_dict") else e)
                              for e in exploits],
            "auto_findings": strip_finding_widget_refs(
                getattr(intel, "_auto_findings", []) or []),
        })
        return True
    except Exception as e:
        print(f"[HAWK] target_intel snapshot failed: {e}", file=sys.stderr)
        return False


def live_auto_findings(app):
    """The AUTHORITATIVE auto-finding dicts: the panel's own list when a
    running app is available, else None.

    ``session.target_intel["auto_findings"]`` holds shallow clones of
    these, rebuilt by ``sync_target_intel`` on every save — so anything
    that must survive a later save (operator curation) has to be written
    here, not on the clone."""
    live = getattr(getattr(app, "target_intel", None), "_auto_findings", None)
    return live if isinstance(live, list) else None
