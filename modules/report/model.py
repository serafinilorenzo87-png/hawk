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
Report engine — core contracts: Block / Section / SectionProvider, the
ReportContext (curation + counting), and branding loading.

THE PROVIDER CONTRACT
─────────────────────
A provider emits a Section composed of Blocks drawn from a FIXED
vocabulary.  Render targets switch on ``Block.type`` only, so a new
provider that reuses these block types renders everywhere without
touching a single render target:

    BLOCK_KEYVALUE   data = {"rows": [[label, value], ...]}
    BLOCK_TABLE      data = {"columns": [...], "rows": [[...], ...]}
    BLOCK_FINDINGS   data = {"items": [finding_view, ...]}   (see finding_view)
    BLOCK_PHASES     data = {"items": [phase_view, ...]}
    BLOCK_PARAGRAPH  data = {"text": "..."}

Introducing a brand-new block type is the ONLY change that requires
editing the render targets — providers should prefer the existing types.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime

from utils.config import (REPORT_BRANDING, CONFIGS_DIR, BASE_DIR,
                          is_within_base)


# ─── Block vocabulary ──────────────────────────────────────────────────────
BLOCK_KEYVALUE  = "keyvalue"
BLOCK_TABLE     = "table"
BLOCK_FINDINGS  = "findings"
BLOCK_PHASES    = "phases"
BLOCK_PARAGRAPH = "paragraph"

# Effective-severity ordering for counts + sorting (critical first).
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Block:
    type: str
    data: dict = field(default_factory=dict)


@dataclass
class Section:
    id: str
    title: str
    blocks: list = field(default_factory=list)   # list[Block]


class SectionProvider:
    """Base class for a report section.  Subclasses set ``id``/``title``
    and implement ``build``; ``applies`` lets a provider opt out (e.g.
    the reserved ARGUS slot returns False until a plugin fills it)."""

    id: str = ""
    title: str = ""

    def applies(self, ctx: "ReportContext") -> bool:
        return True

    def build(self, ctx: "ReportContext") -> "Section | None":
        raise NotImplementedError


# ─── Branding ──────────────────────────────────────────────────────────────

_BRANDING_OVERRIDE_PATH = os.path.join(CONFIGS_DIR, "report_branding.json")

_LOGO_MIME = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp",
}

# A logo is a logo.  The cap is what stops a mistyped logo_path pointing
# at a capture or a disk image from being base64-inflated (+33%) into RAM
# and into the deliverable — generation runs on the Tk main thread, so a
# large read freezes the GUI as well.
_LOGO_MAX_BYTES = 2 * 1024 * 1024


def load_branding(override: "dict | None" = None) -> dict:
    """Merge branding from three layers (later wins): config defaults ->
    configs/report_branding.json -> per-call override.  Resolves the
    optional logo to a base64 data URI under ``logo_data_uri`` so the
    HTML stays fully self-contained.  Never raises."""
    data = dict(REPORT_BRANDING)
    try:
        if os.path.isfile(_BRANDING_OVERRIDE_PATH):
            with open(_BRANDING_OVERRIDE_PATH, "r", encoding="utf-8") as f:
                disk = json.load(f)
            if isinstance(disk, dict):
                data.update({k: v for k, v in disk.items() if v is not None})
    except Exception:
        pass
    if override:
        data.update({k: v for k, v in override.items() if v is not None})

    data["logo_data_uri"] = _logo_data_uri(data.get("logo_path", ""))
    return data


def _reject_logo(path, reason: str) -> str:
    """One diagnostic line per refusal, then the documented failure mode
    ("" — the template renders no logo).  Silence here is how a wrong
    logo_path went unnoticed until it was already in the client's HTML."""
    print(f"[HAWK] report branding: logo refused ({reason}): {path}",
          file=sys.stderr)
    return ""


def _logo_data_uri(logo_path: str) -> str:
    """Read ``logo_path`` (abs or BASE_DIR-relative) and return a base64
    data URI, or "" when absent/unreadable/refused.

    This is the one place in the report pipeline that opens a path the
    operator chose, and its content is embedded verbatim in the file
    handed to the client — so the path is validated like every other
    HAWK path instead of being trusted:

      * it must resolve INSIDE the HAWK tree (``is_within_base``) — a
        typo or a copy-pasted config must not be able to inline
        ``~/.ssh/id_rsa`` into the deliverable;
      * its extension must be one we actually know a MIME type for (no
        "image/png by default" for arbitrary bytes);
      * its size is checked BEFORE the read, not after.

    Never raises: a non-string logo_path (a stray list/number in
    report_branding.json) returns "" like any other unusable value —
    load_branding() documents that it never raises."""
    if not isinstance(logo_path, str) or not logo_path:
        return ""
    path = logo_path
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, logo_path)
    try:
        if not is_within_base(path):
            return _reject_logo(path, "outside the HAWK folder")
        mime = _LOGO_MIME.get(os.path.splitext(path)[1].lower())
        if mime is None:
            return _reject_logo(path, "unsupported extension")
        if not os.path.isfile(path):
            return ""
        size = os.path.getsize(path)
        if size > _LOGO_MAX_BYTES:
            return _reject_logo(
                path, f"{size} bytes > {_LOGO_MAX_BYTES} byte cap")
        with open(path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        return f"data:{mime};base64,{b64}"
    except Exception as e:
        return _reject_logo(path, f"unreadable: {e}")


# ─── Report context (curation applied once, shared by all targets) ─────────

class ReportContext:
    """Single source of truth for a report run.  Applies curation ONCE
    and exposes the curated finding set + counts so every provider and
    every render target agrees on the numbers.

    Curation rules (honoured even before the curation UI ships):
      * a finding is VISIBLE iff ``included and not false_positive``;
      * all severities are read via ``effective_severity()`` so an
        operator override drives counts/sorting while the objective
        ``severity`` stays intact on the model.
    """

    def __init__(self, session, branding: "dict | None" = None,
                 generated_at: "datetime | None" = None):
        self.session = session
        self.branding = branding if isinstance(branding, dict) \
            else load_branding()
        self.generated_at = generated_at or datetime.now()

        all_findings = list(session.get_all_findings())
        self.all_findings = all_findings
        self.findings = [f for f in all_findings
                         if self._is_visible(f)]
        self.excluded = [f for f in all_findings
                         if not self._is_visible(f)]

        # Counts over the VISIBLE set, by effective severity.  KEV /
        # ransomware membership is counted in the SAME pass, via the
        # shared helper, so the executive-summary counts come from exactly
        # the curated findings the body renders.
        self.severity_counts = {s: 0 for s in SEVERITIES}
        self.kev_count = 0
        self.kev_ransomware_count = 0
        for f in self.findings:
            self.severity_counts[self._eff(f)] += 1
            entry = self.kev_entry(f)
            if entry is not None:
                self.kev_count += 1
                if getattr(entry, "known_ransomware", False):
                    self.kev_ransomware_count += 1
        self.total_findings = len(self.findings)
        self.high_critical = (self.severity_counts["critical"]
                              + self.severity_counts["high"])

    # ── curation predicates ──
    @staticmethod
    def _is_visible(f) -> bool:
        return bool(getattr(f, "included", True)) and \
            not bool(getattr(f, "false_positive", False))

    @staticmethod
    def _eff(f) -> str:
        try:
            s = f.effective_severity()
        except Exception:
            s = getattr(f, "severity", "info")
        return s if s in SEVERITY_ORDER else "info"

    @staticmethod
    def kev_entry(f):
        """Shared KEV membership for a finding: the KevEntry of the first
        KEV CVE in its title/source/description, else None.  Delegates to
        ``cisa_kev.first_kev_in`` — the SAME helper the curation dialog
        uses — so report counts and the curation badge never diverge.
        Membership-driven: independent of any severity override."""
        try:
            from utils.cisa_kev import first_kev_in
            return first_kev_in(getattr(f, "title", ""),
                                getattr(f, "source", ""),
                                getattr(f, "description", ""))
        except Exception:
            return None

    # ── helpers consumed by providers ──
    def auto_findings(self) -> list:
        return [f for f in self.findings if getattr(f, "origin", "") == "auto"]

    def phase_findings(self, phase_id: str) -> list:
        return [f for f in self.findings
                if getattr(f, "origin", "") == "phase"
                and getattr(f, "phase_id", "") == phase_id]

    def sort_by_severity(self, findings: list) -> list:
        return sorted(
            findings,
            key=lambda f: (SEVERITY_ORDER.get(self._eff(f), 99),
                           (f.title or "").lower()))

    def finding_view(self, f, n: int) -> dict:
        """Convert a Finding into the plain dict the BLOCK_FINDINGS render
        contract expects.  Render targets never touch Finding objects —
        only these views — so the model can evolve independently."""
        eff = self._eff(f)
        fields = []
        for key, label in (("confidence", "Confidence"),
                           ("endpoint", "Endpoint"),
                           ("parameter", "Parameter"),
                           ("method", "Method"),
                           ("port", "Port")):
            val = getattr(f, key, "")
            if val:
                fields.append([label, str(val)])
        # KEV badge, surfaced as a finding field exactly like ATT&CK ids
        # are — so it rides the existing BLOCK_FINDINGS render path into
        # HTML/MD with no render-target change.  Membership-driven, so it
        # stays visible even when the operator lowers the severity.
        kev = self.kev_entry(f)
        if kev is not None:
            fields.append(["KEV", kev.badge()])
        return {
            "n": n,
            "severity": eff.upper(),
            "severity_key": eff,
            "original_severity": (getattr(f, "severity", "") or "").upper(),
            "overridden": bool(getattr(f, "severity_override", None)),
            "title": (f.title or "").strip() or "(untitled)",
            "source": getattr(f, "source", "") or "",
            "origin": getattr(f, "origin", ""),
            "phase_id": getattr(f, "phase_id", ""),
            "description": (getattr(f, "description", "") or "").rstrip(),
            "fields": fields,
            "kev": bool(kev),
            "kev_ransomware": bool(kev and getattr(kev,
                                                   "known_ransomware", False)),
            "impact": getattr(f, "impact", "") or "",
            "remediation": getattr(f, "remediation", "") or "",
            "operator_note": getattr(f, "operator_note", "") or "",
        }
