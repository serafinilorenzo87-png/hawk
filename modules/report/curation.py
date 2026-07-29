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
Pre-export curation controller (HEADLESS).

This is the logic half of the curation feature; the Tk dialog
(gui/widgets/curation_dialog.py) is a thin shell over it.  Kept Tk-free so
the whole mutation + persistence path is unit-testable without a display.

WHY IT MUTATES RAW DICTS IN PLACE
─────────────────────────────────
``session.get_all_findings()`` builds FRESH Finding objects from the
underlying persisted dicts on every call, so mutating those objects would
never persist.  And ``Finding.to_auto_dict()`` does NOT re-emit the merge
bookkeeping (occurrences, run_count, first_seen, …) that lives in
``Finding.extra`` — rebuilding the dict from a Finding would silently drop
it.  So the controller writes curation keys directly onto the EXISTING
source dicts in ``session.phases[*]["findings"]`` and
``session.target_intel["auto_findings"]`` — lossless, and exactly what
``session.save()`` serializes.  The report engine then reads the curated
state back through ``get_all_findings()`` — the dialog SETS, the engine
COUNTS; the curation logic is never duplicated.

Curation keys follow the Finding serialization convention: a key is
written only when it deviates from its default and removed when it returns
to default, so session JSON stays minimal and old builds keep loading.
"""

from __future__ import annotations

import re

from utils.config import KILL_CHAIN_PHASES
from utils.session import Finding

# Severity choices for the override control.  "" / None means "keep the
# original objective severity" — the override is cleared.
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_KEEP = ""   # the "(none)" option

_PHASE_LABEL = {p["id"]: (p["name"] or "").title() for p in KILL_CHAIN_PHASES}
_PHASE_ORDER = [p["id"] for p in KILL_CHAIN_PHASES]
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class CurationItem:
    """One finding in the curation list, bound to its persisted source
    dict.  Mutators write through ``raw`` so changes survive save/load."""

    __slots__ = ("raw", "origin", "phase_id", "n")

    def __init__(self, raw: dict, origin: str, phase_id: str, n: int):
        self.raw = raw
        self.origin = origin
        self.phase_id = phase_id
        self.n = n


class CurationController:
    def __init__(self, session):
        self.session = session
        self._items: list[CurationItem] = []
        self._collect()

    # ── build the item list from the persisted source dicts ──
    def _collect(self) -> None:
        n = 0
        phases = self.session.phases if isinstance(self.session.phases, dict) \
            else {}
        # Phase findings, in kill-chain order.
        for pid in _PHASE_ORDER:
            pdata = phases.get(pid)
            if not isinstance(pdata, dict):
                continue
            for raw in (pdata.get("findings") or []):
                if isinstance(raw, dict):
                    n += 1
                    self._items.append(CurationItem(raw, "phase", pid, n))
        # Defensive: any phase whose id is NOT in config.KILL_CHAIN_PHASES
        # (a stray/legacy phase-id) still carries findings that the report
        # counts — get_all_findings() iterates EVERY phase, not just the
        # configured ones.  Collect them too (sorted for determinism) so
        # the curation count never diverges from the report.  groups()
        # already falls back to the raw id for the label.
        known = set(_PHASE_ORDER)
        for pid in sorted(p for p in phases if p not in known):
            pdata = phases.get(pid)
            if not isinstance(pdata, dict):
                continue
            for raw in (pdata.get("findings") or []):
                if isinstance(raw, dict):
                    n += 1
                    self._items.append(CurationItem(raw, "phase", pid, n))
        # Target Intel auto-findings.
        intel = self.session.target_intel if isinstance(
            self.session.target_intel, dict) else {}
        for raw in (intel.get("auto_findings") or []):
            if isinstance(raw, dict):
                n += 1
                self._items.append(CurationItem(raw, "auto", "", n))

    @property
    def items(self) -> list:
        return list(self._items)

    # ── read side (display) ──
    def _finding(self, item: CurationItem) -> Finding:
        if item.origin == "phase":
            return Finding.from_phase_dict(item.raw, phase_id=item.phase_id)
        return Finding.from_auto_dict(item.raw)

    def _detect_kev(self, item: CurationItem):
        """(is_kev, is_ransomware) for the badge.  Delegates to the shared
        ``cisa_kev.first_kev_in`` helper — the SAME detection the report
        engine uses — so the dialog badge and the report's KEV counts
        agree on identical data.  Membership-driven: shown regardless of
        any severity override."""
        raw = item.raw
        try:
            from utils.cisa_kev import first_kev_in
        except Exception:
            return (False, False)
        entry = first_kev_in(raw.get("title", ""), raw.get("source", ""),
                             raw.get("description", ""))
        if entry is None:
            return (False, False)
        return (True, bool(getattr(entry, "known_ransomware", False)))

    def view(self, item: CurationItem) -> dict:
        f = self._finding(item)
        kev, ransom = self._detect_kev(item)
        # Effective ATT&CK ids: operator override wins, else the curated
        # auto-map — same resolution the report provider uses.
        try:
            from utils.attack import resolve_finding as _resolve
            resolved = _resolve(f.source or "", f.title or "",
                                f.technique_ids)
        except Exception:
            resolved = list(f.technique_ids)
        return {
            "n": item.n,
            "origin": item.origin,
            "phase_id": item.phase_id,
            "phase_label": (_PHASE_LABEL.get(item.phase_id, "")
                            if item.origin == "phase"
                            else "Target Intelligence"),
            "title": (f.title or "").strip() or "(untitled)",
            "source": f.source or "",
            "effective_severity": f.effective_severity(),
            "original_severity": f.severity,
            "overridden": bool(f.severity_override),
            "severity_override": f.severity_override or "",
            "included": bool(f.included),
            "false_positive": bool(f.false_positive),
            "operator_note": f.operator_note or "",
            "visible": bool(f.included) and not bool(f.false_positive),
            "kev": kev,
            "kev_ransomware": ransom,
            # ATT&CK: the operator override (may be empty) and the
            # effective resolved ids (override or auto-map).
            "technique_ids": list(f.technique_ids),
            "techniques_resolved": list(resolved),
        }

    def groups(self) -> list:
        """Items grouped for display: one group per phase that has
        findings (kill-chain order), then Target Intelligence.  Within a
        group, sorted by effective severity then title."""
        buckets: dict = {}
        order: list = []
        for it in self._items:
            key = it.phase_id if it.origin == "phase" else "__auto__"
            if key not in buckets:
                buckets[key] = []
                order.append(key)
            buckets[key].append(it)

        # Stable group order: kill-chain phases first, auto last.
        def _gkey(k):
            if k == "__auto__":
                return (len(_PHASE_ORDER) + 1, "")
            return (_PHASE_ORDER.index(k) if k in _PHASE_ORDER
                    else len(_PHASE_ORDER), k)

        out = []
        for key in sorted(order, key=_gkey):
            label = ("Target Intelligence" if key == "__auto__"
                     else _PHASE_LABEL.get(key, key))
            items = sorted(
                buckets[key],
                key=lambda it: (_SEV_ORDER.get(
                    self._finding(it).effective_severity(), 99),
                    (self._finding(it).title or "").lower()))
            out.append((label, items))
        return out

    # ── mutators (write through to the persisted dict) ──
    @staticmethod
    def _set_flag(raw: dict, key: str, value: bool, default: bool) -> None:
        if bool(value) == default:
            raw.pop(key, None)            # back to default -> don't serialize
        else:
            raw[key] = bool(value)

    def set_included(self, item: CurationItem, value: bool) -> None:
        self._set_flag(item.raw, "included", value, default=True)

    def set_false_positive(self, item: CurationItem, value: bool) -> None:
        self._set_flag(item.raw, "false_positive", value, default=False)

    def set_severity_override(self, item: CurationItem, sev) -> None:
        s = (sev or "").strip().lower()
        if s in SEVERITIES:
            item.raw["severity_override"] = s
        else:
            item.raw.pop("severity_override", None)   # "(none)"/invalid clears

    def set_operator_note(self, item: CurationItem, note: str) -> None:
        note = (note or "").strip()
        if note:
            item.raw["operator_note"] = note
        else:
            item.raw.pop("operator_note", None)

    def set_techniques(self, item: CurationItem, ids) -> None:
        """Set the operator ATT&CK override.  ``ids`` may be a list or a
        comma/space-separated string of technique ids; empty clears the
        override (the report then falls back to the curated auto-map).
        Normalised (upper, deduped); written only when non-empty."""
        if isinstance(ids, str):
            ids = re.split(r"[,\s]+", ids)
        seen, out = set(), []
        for tid in (ids or []):
            u = str(tid).strip().upper()
            if u and u not in seen:
                seen.add(u)
                out.append(u)
        if out:
            item.raw["technique_ids"] = out
        else:
            item.raw.pop("technique_ids", None)

    # ── counts ──
    def included_count(self) -> tuple:
        total = len(self._items)
        included = sum(1 for it in self._items
                       if it.raw.get("included", True)
                       and not it.raw.get("false_positive", False))
        return included, total

    # ── persistence + generation ──
    def persist(self) -> str:
        """Write the curation into the session JSON (in-place save)."""
        return self.session.save(new_file=False)

    def generate(self, formats=None, *, branding=None, out_dir=None) -> dict:
        """Persist the curation, then run the report engine on the SAME
        session — the engine reads the curated findings through
        get_all_findings(), so excluded / false-positive findings drop out
        of body and counts and overrides drive effective severity."""
        self.persist()
        from modules.report import generate as _generate, REPORT_FORMATS
        return _generate(self.session, formats or REPORT_FORMATS,
                         branding=branding, out_dir=out_dir)
