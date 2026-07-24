# HAWK — Hostile Assessment WorKit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0

"""
HAWK — BloodHound ZIP → graph-data builder.

Extracts a bloodhound-python produced .zip (users/computers/groups JSON)
and returns a plain dict with:
    {
        "nodes": [ {id, label, type, category, flags, details}, ... ],
        "edges": [ {src, dst, type}, ... ],
        "stats": {users, computers, groups, kerberoastable,
                  asrepable, unconstrained, da_members},
    }

Pure data — NO tkinter / matplotlib imports.  The graph renderer lives
in gui/dialogs.py and consumes this dict.

Categories used by the renderer:
    "critical" — DA / EA members, unconstrained-delegation computers,
                 Domain Admins / Enterprise Admins groups
    "warn"     — kerberoastable (hasspn) or AS-REP roastable
                 (dontreqpreauth) users
    "medium"   — privileged groups (Account Operators, Server Operators,
                 Backup Operators, DnsAdmins, Print Operators,
                 Schema Admins)
    "normal"   — anything else
"""

from __future__ import annotations

import os
import json
import zipfile
import tempfile
import shutil
from typing import Optional
from utils.config import TMP_DIR


# Groups whose Members should be flagged critical (DA/EA).
_CRITICAL_GROUP_PREFIXES = (
    "DOMAIN ADMINS@",
    "ENTERPRISE ADMINS@",
    "SCHEMA ADMINS@",
    "ADMINISTRATORS@",
)

# Groups that are privileged but not top-tier — yellow.
_PRIVILEGED_GROUP_PREFIXES = (
    "ACCOUNT OPERATORS@",
    "SERVER OPERATORS@",
    "BACKUP OPERATORS@",
    "PRINT OPERATORS@",
    "DNSADMINS@",
    "DNSADMINS ",   # for odd formatting
    "GROUP POLICY CREATOR OWNERS@",
    "CERT PUBLISHERS@",
    "KEY ADMINS@",
    "ENTERPRISE KEY ADMINS@",
)


def _safe_open_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _entries(doc) -> list:
    """bloodhound-python v1.7+ nests records under `data`.  Older
    collectors stored them under a per-kind key (users/computers/...).
    Handle both."""
    if not isinstance(doc, dict):
        return []
    for k in ("data", "users", "computers", "groups", "domains",
              "ous", "gpos", "containers"):
        v = doc.get(k)
        if isinstance(v, list):
            return v
    return []


def _sid(obj) -> str:
    """Extract the canonical ObjectIdentifier from a BH record or ref."""
    if not isinstance(obj, dict):
        return ""
    return (obj.get("ObjectIdentifier")
            or obj.get("objectIdentifier")
            or obj.get("SID")
            or "") or ""


def build_graph_data(zip_path: str) -> Optional[dict]:
    """Open the BloodHound .zip, read the JSONs, return the graph dict.

    Returns None if the ZIP is missing or unreadable.  Partial data is
    fine — missing files (e.g. no groups.json) degrade gracefully.
    """
    if not zip_path or not os.path.isfile(zip_path):
        return None

    os.makedirs(TMP_DIR, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="hawk_bh_graph_", dir=TMP_DIR)
    try:
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(tmp)
        except Exception:
            return None

        users_doc = {}
        computers_doc = {}
        groups_doc = {}
        for fn in os.listdir(tmp):
            p = os.path.join(tmp, fn)
            low = fn.lower()
            if low.endswith("_users.json") or low.endswith("users.json"):
                users_doc = _safe_open_json(p)
            elif low.endswith("_computers.json") or low.endswith("computers.json"):
                computers_doc = _safe_open_json(p)
            elif low.endswith("_groups.json") or low.endswith("groups.json"):
                groups_doc = _safe_open_json(p)

        users = _entries(users_doc)
        computers = _entries(computers_doc)
        groups = _entries(groups_doc)
    finally:
        try:
            shutil.rmtree(tmp)
        except Exception:
            pass

    # ── Pass 1 — enumerate groups, decide criticality, collect member SIDs
    # ────────────────────────────────────────────────────────────────────
    # group_sid → {"name", "category", "member_sids": set}
    groups_by_sid = {}
    critical_member_sids = set()   # everyone in a DA/EA-like group
    for g in groups:
        sid = _sid(g)
        if not sid:
            continue
        props = g.get("Properties", {}) or {}
        name_full = (props.get("name") or "").strip()
        name_up = name_full.upper()
        if any(name_up.startswith(p) for p in _CRITICAL_GROUP_PREFIXES):
            cat = "critical"
        elif any(name_up.startswith(p) for p in _PRIVILEGED_GROUP_PREFIXES):
            cat = "medium"
        else:
            cat = "normal"

        member_sids = set()
        for m in (g.get("Members") or []):
            msid = _sid(m)
            if msid:
                member_sids.add(msid)
                if cat == "critical":
                    critical_member_sids.add(msid)

        groups_by_sid[sid] = {
            "name": name_full or sid,
            "category": cat,
            "member_sids": member_sids,
            "props": props,
        }

    # Propagate criticality through nested groups: if group A is in
    # critical_member_sids (i.e. member of DA), everyone in A is also
    # critical.  One-pass transitive closure (cap iterations for safety).
    for _ in range(5):
        grown = False
        for sid, g in groups_by_sid.items():
            if sid in critical_member_sids:
                for msid in g["member_sids"]:
                    if msid not in critical_member_sids:
                        critical_member_sids.add(msid)
                        grown = True
        if not grown:
            break

    # ── Pass 2 — build user/computer/group nodes with categories ─────────
    nodes = []
    stats = {
        "users": 0, "computers": 0, "groups": 0,
        "kerberoastable": 0, "asrepable": 0,
        "unconstrained": 0, "da_members": 0,
    }

    # Users
    for u in users:
        sid = _sid(u)
        if not sid:
            continue
        props = u.get("Properties", {}) or {}
        name = (props.get("name") or props.get("samaccountname") or
                sid[-12:])
        flags = []
        cat = "normal"

        if props.get("hasspn"):
            flags.append("kerberoastable")
            stats["kerberoastable"] += 1
            cat = "warn"
        if props.get("dontreqpreauth"):
            flags.append("asrep")
            stats["asrepable"] += 1
            if cat == "normal":
                cat = "warn"
        if sid in critical_member_sids:
            flags.append("da_member")
            cat = "critical"  # overrides warn
            stats["da_members"] += 1
        if props.get("unconstraineddelegation"):
            flags.append("unconstrained")
            cat = "critical"

        nodes.append({
            "id": sid,
            "label": name,
            "type": "User",
            "category": cat,
            "flags": flags,
            "details": _user_details(props, flags),
        })
        stats["users"] += 1

    # Computers
    for c in computers:
        sid = _sid(c)
        if not sid:
            continue
        props = c.get("Properties", {}) or {}
        name = (props.get("name") or props.get("samaccountname") or
                sid[-12:])
        flags = []
        cat = "normal"

        if props.get("unconstraineddelegation"):
            flags.append("unconstrained")
            cat = "critical"
            stats["unconstrained"] += 1
        # Critical-group containment for computers too (rare, but
        # computers can be member of a priv group in odd setups).
        if sid in critical_member_sids:
            flags.append("da_member")
            cat = "critical"

        nodes.append({
            "id": sid,
            "label": name,
            "type": "Computer",
            "category": cat,
            "flags": flags,
            "details": _computer_details(props, flags),
        })
        stats["computers"] += 1

    # Groups (only after users/computers so we know stats["da_members"])
    for sid, g in groups_by_sid.items():
        nodes.append({
            "id": sid,
            "label": g["name"].split("@")[0],   # strip @DOMAIN for label
            "type": "Group",
            "category": g["category"],
            "flags": ["group"],
            "details": _group_details(g["props"]),
        })
        stats["groups"] += 1

    # ── Pass 3 — edges ────────────────────────────────────────────────────
    # MemberOf: user/group → group (drawn as "contains" membership line)
    node_ids = {n["id"] for n in nodes}
    edges = []
    seen_edges = set()

    def _add_edge(src, dst, kind):
        if not src or not dst:
            return
        if src not in node_ids or dst not in node_ids:
            return
        key = (src, dst, kind)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append({"src": src, "dst": dst, "type": kind})

    for gsid, g in groups_by_sid.items():
        for msid in g["member_sids"]:
            _add_edge(msid, gsid, "MemberOf")

    # AdminTo: computer.LocalAdmins member → computer
    # Sessions:  computer.Sessions member → computer
    for c in computers:
        csid = _sid(c)
        if not csid:
            continue
        for la in (c.get("LocalAdmins") or c.get("localadmins") or []):
            msid = la.get("ObjectIdentifier") or la.get("MemberId") or ""
            _add_edge(msid, csid, "AdminTo")
        sessions = c.get("Sessions") or {}
        if isinstance(sessions, dict):
            sess_list = sessions.get("Results") or []
        else:
            sess_list = sessions
        for s in (sess_list or []):
            msid = s.get("UserSID") or s.get("UserId") or ""
            _add_edge(csid, msid, "HasSession")

    # AllowedToDelegate (constrained delegation): user → computer
    for u in users:
        usid = _sid(u)
        for tgt in (u.get("AllowedToDelegate") or []):
            tsid = tgt if isinstance(tgt, str) else _sid(tgt)
            _add_edge(usid, tsid, "AllowedToDelegate")

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": stats,
    }


# ───────── per-type detail formatters (for the click popup) ─────────

def _user_details(props: dict, flags: list) -> str:
    out = []
    for k in ("name", "samaccountname", "displayname", "description",
              "enabled", "pwdlastset", "lastlogon", "admincount",
              "serviceprincipalnames", "hasspn", "dontreqpreauth",
              "unconstraineddelegation", "trustedtoauth", "email"):
        v = props.get(k)
        if v in (None, "", [], False) and k not in ("enabled",):
            continue
        if isinstance(v, list):
            v = "\n    ".join(str(x) for x in v[:10])
        out.append(f"{k:<25} {v}")
    if flags:
        out.append("")
        out.append(f"FLAGS: {', '.join(flags)}")
    return "\n".join(out) or "(no properties)"


def _computer_details(props: dict, flags: list) -> str:
    out = []
    for k in ("name", "samaccountname", "operatingsystem", "enabled",
              "lastlogon", "unconstraineddelegation", "trustedtoauth",
              "haslaps", "description"):
        v = props.get(k)
        if v in (None, "", [], False) and k not in ("enabled",):
            continue
        out.append(f"{k:<25} {v}")
    if flags:
        out.append("")
        out.append(f"FLAGS: {', '.join(flags)}")
    return "\n".join(out) or "(no properties)"


def _group_details(props: dict) -> str:
    out = []
    for k in ("name", "samaccountname", "description", "admincount"):
        v = props.get(k)
        if v in (None, "", [], False):
            continue
        out.append(f"{k:<25} {v}")
    return "\n".join(out) or "(no properties)"
