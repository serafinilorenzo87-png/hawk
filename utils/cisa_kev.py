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
HAWK — CISA KEV (Known Exploited Vulnerabilities) membership.

Turns a raw CVE ID into a prioritization signal: "is this CVE on the
CISA Known Exploited Vulnerabilities catalog, i.e. actively exploited
in the wild?"  Read-only enrichment — no offensive capability is added.

Offline-first / portable
────────────────────────
* A KEV snapshot ships inside the HAWK tree at ``profiles/cisa_kev.json``
  and is the baseline.  ``is_kev()`` works with the network fully
  blocked off this file alone — stale-but-present beats absent.
* When online, the operator can opportunistically refresh the catalog
  via ``refresh_from_cisa()``.  The fresh copy is written ONLY to
  ``cache/cisa_kev.json`` (inside the HAWK tree, guarded by
  ``require_within_base``); the bundled baseline is never touched.
  Failure to reach CISA is silent and non-fatal.
* Load priority: cache (if a valid refresh landed) wins over bundled,
  so a refresh takes effect on next load without a code change.

This is the only network touch-point for KEV data — kept isolated here
so the egress is auditable.  Same category as the NVD client
(utils/cve_lookup): optional, cached, degrades gracefully.

Source feed
───────────
CISA KEV JSON — ``known_exploited_vulnerabilities.json``.  Schema:

    {
      "catalogVersion": "2026.06.09",
      "dateReleased":   "...",
      "count":          1617,
      "vulnerabilities": [
        {
          "cveID": "CVE-2017-0144",
          "vendorProject": "Microsoft",
          "product": "SMBv1",
          "vulnerabilityName": "...",
          "dateAdded": "2022-02-10",
          "shortDescription": "...",
          "dueDate": "2022-08-10",
          "knownRansomwareCampaignUse": "Known" | "Unknown"
        },
        ...
      ]
    }

The bundled snapshot keeps only the fields above (the full feed also
carries requiredAction / notes / cwes, dropped to shrink the baseline).
A refresh writes whatever shape CISA serves; the loader reads only the
fields it needs, so a full-feed cache loads fine too.
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass

from utils.config import BASE_DIR, CACHE_DIR, require_within_base


# Canonical CISA feed.  The only URL this module ever reaches, and only
# when the operator explicitly triggers a refresh.
CISA_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")

_BUNDLED_PATH = os.path.join(BASE_DIR, "profiles", "cisa_kev.json")
_CACHE_PATH = os.path.join(CACHE_DIR, "cisa_kev.json")


# ─── Data structure ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class KevEntry:
    cve_id:             str
    vendor_project:     str = ""
    product:            str = ""
    vulnerability_name: str = ""
    date_added:         str = ""
    short_description:  str = ""
    due_date:           str = ""
    known_ransomware:   bool = False

    def badge(self) -> str:
        """One-line badge string for terminal / finding surfaces."""
        if self.known_ransomware:
            return "KEV — actively exploited · ransomware campaign use"
        return "KEV — actively exploited in the wild"

    def summary_line(self) -> str:
        """Compact human-readable summary for descriptions / reports."""
        bits = [f"CISA KEV: {self.cve_id}"]
        if self.date_added:
            bits.append(f"added {self.date_added}")
        if self.due_date:
            bits.append(f"remediation due {self.due_date}")
        if self.known_ransomware:
            bits.append("known ransomware campaign use")
        return "  ·  ".join(bits)


# ─── Catalog loading (lazy, thread-safe, offline-first) ─────────────────────

_lock = threading.Lock()
_catalog: "dict[str, KevEntry] | None" = None   # cve_id (upper) → KevEntry
_meta: dict = {}                                 # version / count / source


def _coerce_entry(raw: dict) -> "KevEntry | None":
    cve = (raw.get("cveID") or raw.get("cve_id") or "").strip().upper()
    if not cve.startswith("CVE-"):
        return None
    rw = str(raw.get("knownRansomwareCampaignUse", "")).strip().lower()
    return KevEntry(
        cve_id=cve,
        vendor_project=str(raw.get("vendorProject", "") or ""),
        product=str(raw.get("product", "") or ""),
        vulnerability_name=str(raw.get("vulnerabilityName", "") or ""),
        date_added=str(raw.get("dateAdded", "") or ""),
        short_description=str(raw.get("shortDescription", "") or ""),
        due_date=str(raw.get("dueDate", "") or ""),
        known_ransomware=(rw == "known"),
    )


def _read_catalog_file(path: str) -> "tuple[dict, dict] | None":
    """Parse a KEV JSON file → ({cve_id: KevEntry}, meta) or None on any
    failure.  Tolerant of every failure mode so a corrupt cache can
    never take down the bundled baseline."""
    try:
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(vulns, list):
            return None
        catalog: dict[str, KevEntry] = {}
        for raw in vulns:
            if not isinstance(raw, dict):
                continue
            ent = _coerce_entry(raw)
            if ent is not None:
                catalog[ent.cve_id] = ent
        if not catalog:
            return None
        meta = {
            "version": str(data.get("catalogVersion", "") or ""),
            "released": str(data.get("dateReleased", "") or ""),
            "count": len(catalog),
            "path": path,
        }
        return catalog, meta
    except Exception as e:
        import sys as _s
        print(f"[HAWK] cisa_kev load failed for {path}: {e}", file=_s.stderr)
        return None


def _load() -> "dict[str, KevEntry]":
    """Build the in-memory catalog once.  Cache (a successful refresh)
    wins over the bundled baseline; bundled is the offline fallback."""
    global _catalog, _meta
    if _catalog is not None:
        return _catalog
    with _lock:
        if _catalog is not None:
            return _catalog
        # Cache first (newer if a refresh landed), bundled as fallback.
        for path, source in ((_CACHE_PATH, "cache"),
                             (_BUNDLED_PATH, "bundled")):
            res = _read_catalog_file(path)
            if res is not None:
                _catalog, meta = res
                meta["source"] = source
                _meta = meta
                return _catalog
        # Nothing usable anywhere — empty catalog, still non-fatal.
        _catalog, _meta = {}, {"version": "", "count": 0, "source": "none"}
        return _catalog


def reload() -> None:
    """Drop the cached in-memory catalog so the next lookup re-reads from
    disk.  Called after a successful refresh so the new cache takes
    effect without restarting HAWK."""
    global _catalog, _meta
    with _lock:
        _catalog = None
        _meta = {}


# ─── Public API ────────────────────────────────────────────────────────────

def is_kev(cve_id: str) -> "KevEntry | None":
    """Return the KevEntry for ``cve_id`` if it is on the CISA KEV
    catalog, else None.  Pure CVE-ID set membership — target-agnostic.
    Case-insensitive; tolerant of surrounding whitespace."""
    if not cve_id:
        return None
    return _load().get(cve_id.strip().upper())


# Canonical CVE-id pattern for free-text KEV detection.  Kept here so the
# detection logic lives in ONE place — both the curation dialog and the
# report engine resolve KEV through ``first_kev_in`` below, never with
# their own regex, so the two can never disagree on a finding's KEV state.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,}", re.IGNORECASE)


def first_kev_in(*texts) -> "KevEntry | None":
    """Shared free-text KEV detection: scan the given text fragments for
    CVE ids and return the KevEntry of the FIRST one that is on the CISA
    KEV catalog, else None.

    This is the single detection helper used by BOTH the pre-export
    curation dialog and the report engine, so the dialog's KEV badge and
    the report's KEV counts are computed identically.  Membership-driven:
    the signal depends only on CVE-id catalog membership, never on the
    finding's severity (so an operator severity-override never hides it).
    """
    blob = " ".join(str(t or "") for t in texts)
    for cve in _CVE_RE.findall(blob):
        entry = is_kev(cve)
        if entry is not None:
            return entry
    return None


def catalog_meta() -> dict:
    """{'version','released','count','source','path'} for the loaded
    catalog.  ``source`` is 'cache' | 'bundled' | 'none'.  Consumed by
    the report engine (KEV catalog provenance in the executive summary)
    and the Target Intel refresh status line."""
    _load()
    return dict(_meta)


def catalog_size() -> int:
    return len(_load())


# ─── Opportunistic refresh (writes to cache/ only, silent on failure) ───────

def refresh_from_cisa(*, timeout: int = 15) -> dict:
    """One-shot HTTPS GET of the CISA KEV feed → atomic write to
    ``cache/cisa_kev.json``.  Designed to be called from a worker
    thread (the GET blocks).

    Returns ``{"ok": True, "count": N, "version": ...}`` on success or
    ``{"ok": False, "reason": <str>}`` on failure.  NEVER raises — a
    failure to reach CISA (offline pentest, isolated VLAN) is silent and
    non-fatal; the bundled baseline keeps serving lookups.

    Only ever writes inside the HAWK tree (CACHE_DIR), guarded by
    ``require_within_base``.  The bundled baseline is never modified.

    POLICY — git-pull-only, NO runtime network trigger (intentional).
    This function has NO automatic caller: not on app start, not on
    first lookup, not on any timer.  ``_load()`` only ever reads the
    local bundled/cache files — it never reaches the network.  The KEV
    catalog is refreshed by pulling a new HAWK release (the bundled
    ``profiles/cisa_kev.json`` ships updated), exactly like the removed
    "REFRESH CVE DB" button decision (see target_intel_widget.py).  This
    keeps HAWK's offline-by-default / no-phone-home posture honest:
    internal-pentest boxes on an isolated VLAN behave identically to an
    online run.  ``refresh_from_cisa`` stays as dormant, explicit-call
    API for a fork that wants an operator-driven refresh — do NOT wire
    it to an automatic runtime trigger without revisiting that posture.
    """
    import urllib.request

    try:
        req = urllib.request.Request(
            CISA_KEV_URL, headers={"User-Agent": "HAWK/cisa-kev"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:
        return {"ok": False, "reason": f"{type(e).__name__}: {e}"}

    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list) or not vulns:
        return {"ok": False, "reason": "unexpected JSON shape"}

    # Validate at least one real CVE entry before overwriting the cache.
    valid = [v for v in vulns
             if isinstance(v, dict) and _coerce_entry(v) is not None]
    if not valid:
        return {"ok": False, "reason": "feed carried no valid CVE entries"}

    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        dst = require_within_base(_CACHE_PATH, "KEV cache write")
        tmp = dst + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"), ensure_ascii=False)
        os.replace(tmp, dst)
    except Exception as e:
        return {"ok": False, "reason": f"cache write failed: {e}"}

    reload()   # next lookup reads the fresh cache
    return {"ok": True,
            "count": len(valid),
            "version": str(data.get("catalogVersion", "") or "")}


__all__ = [
    "CISA_KEV_URL",
    "KevEntry",
    "is_kev",
    "first_kev_in",
    "catalog_meta",
    "catalog_size",
    "refresh_from_cisa",
    "reload",
]
