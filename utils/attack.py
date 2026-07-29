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
HAWK — MITRE ATT&CK technique reference + curated finding mapping.

Two offline assets, both bundled under profiles/ (same offline-first
pattern as utils.cisa_kev):

  profiles/attack_techniques.json  — reference snapshot (id, name,
        tactic(s), url).  A technique can belong to several tactics.
  profiles/attack_map.json         — the HAWK-specific curated map from a
        finding's deterministic, code-emitted signal (source= or title
        prefix) to ATT&CK technique id(s).  NOT heuristic text inference.

Both load ONLY from disk — never the network — so the ATT&CK section
works on an isolated VLAN.  Every loader is tolerant: a missing/corrupt
file yields an empty catalog and the ATT&CK section simply renders
nothing, never an error.

The resolver precedence for a finding (no manual override):
    title-prefix match  (most specific)
      -> exact source match
        -> source-prefix match
A finding with no match stays unmapped and never pollutes the matrix.
``Finding.technique_ids`` (operator override) wins over all of this.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field

from utils.config import BASE_DIR

_TECH_PATH = os.path.join(BASE_DIR, "profiles", "attack_techniques.json")
_MAP_PATH = os.path.join(BASE_DIR, "profiles", "attack_map.json")

# ATT&CK Enterprise tactic order — used to sort the per-tactic coverage.
TACTIC_ORDER = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
)


def tactic_index(name: str) -> int:
    try:
        return TACTIC_ORDER.index(name)
    except ValueError:
        return len(TACTIC_ORDER)


@dataclass(frozen=True)
class AttackTechnique:
    id: str
    name: str = ""
    tactics: tuple = field(default_factory=tuple)
    url: str = ""


_lock = threading.Lock()
_techniques: "dict[str, AttackTechnique] | None" = None
_amap: "dict | None" = None


def _read_json(path: str):
    try:
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        import sys as _s
        print(f"[HAWK] attack reference load failed for {path}: {e}",
              file=_s.stderr)
        return None


def _load_techniques() -> "dict[str, AttackTechnique]":
    global _techniques
    if _techniques is not None:
        return _techniques
    with _lock:
        if _techniques is not None:
            return _techniques
        out: dict = {}
        data = _read_json(_TECH_PATH)
        rows = data.get("techniques") if isinstance(data, dict) else None
        for raw in (rows or []):
            if not isinstance(raw, dict):
                continue
            tid = str(raw.get("id", "")).strip().upper()
            if not tid.startswith("T"):
                continue
            tactics = raw.get("tactics") or []
            if not isinstance(tactics, list):
                tactics = [tactics]
            out[tid] = AttackTechnique(
                id=tid,
                name=str(raw.get("name", "") or ""),
                tactics=tuple(str(t) for t in tactics if t),
                url=str(raw.get("url", "") or ""))
        _techniques = out
        return _techniques


def _load_map() -> dict:
    global _amap
    if _amap is not None:
        return _amap
    with _lock:
        if _amap is not None:
            return _amap
        data = _read_json(_MAP_PATH)
        data = data if isinstance(data, dict) else {}

        def _section(key):
            sec = data.get(key)
            if not isinstance(sec, dict):
                return {}
            # normalise keys to lower-case, values to list[str] upper-case
            out = {}
            for k, v in sec.items():
                if not isinstance(k, str):
                    continue
                ids = v if isinstance(v, list) else [v]
                out[k.strip().lower()] = [str(i).strip().upper()
                                          for i in ids if i]
            return out

        _amap = {
            "by_title_prefix": _section("by_title_prefix"),
            "by_source": _section("by_source"),
            "by_source_prefix": _section("by_source_prefix"),
        }
        return _amap


# ─── Public API ────────────────────────────────────────────────────────────

def technique(tid: str) -> "AttackTechnique | None":
    """Resolve a technique id (e.g. 'T1558.003') to its reference entry,
    or None if unknown.  Offline, case-insensitive."""
    if not tid:
        return None
    return _load_techniques().get(tid.strip().upper())


def auto_techniques(source: str, title: str = "") -> list:
    """Curated auto-mapping for a finding's deterministic signal.  Returns
    a list of technique ids (possibly empty).  Precedence: title-prefix ->
    exact source -> source-prefix; first non-empty wins."""
    amap = _load_map()
    t = (title or "").strip().lower()
    for prefix, ids in amap["by_title_prefix"].items():
        if t.startswith(prefix):
            return list(ids)
    s = (source or "").strip().lower()
    if s in amap["by_source"]:
        return list(amap["by_source"][s])
    for prefix, ids in amap["by_source_prefix"].items():
        if s.startswith(prefix):
            return list(ids)
    return []


def resolve_finding(source: str, title: str, manual_ids=None) -> list:
    """Technique ids for a finding.  A non-empty ``manual_ids`` (operator
    override on the Finding) wins; otherwise the curated auto-map.  Ids
    are normalised + de-duplicated, order preserved."""
    ids = list(manual_ids) if manual_ids else auto_techniques(source, title)
    seen, out = set(), []
    for tid in ids:
        u = str(tid).strip().upper()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def catalog_size() -> int:
    return len(_load_techniques())
