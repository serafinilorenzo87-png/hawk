# HAWK — Hostile Assessment WorKit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0

"""
HAWK — BloodHound Community Edition Cypher query bulk importer.

BH CE v9 no longer ships the classic "Pre-Built Searches" library
that BloodHound Legacy had — users land on an empty Saved Queries
panel and have to paste/save each query by hand.  This module lets
HAWK push a curated set of 30 attack-surface queries into a running
BH CE instance in one shot via its REST API.

Public surface:
    CURATED_QUERIES          list of (name, query) tuples
    BHCEClient(base, token)  REST client wrapping login + save-queries
    bulk_import(base, user, pwd, on_progress=None)
                             convenience: login + POST all queries

No external deps — uses stdlib urllib so it runs on a fresh Kali
with nothing extra pip-installed.
"""

from __future__ import annotations

import json
import ssl
import urllib.request
import urllib.error
import urllib.parse
from typing import Callable, Optional


# ─── The 30 curated queries ──────────────────────────────────────────

CURATED_QUERIES: list = [
    ("01 — Domain name",
     "MATCH (d:Domain) RETURN d"),
    ("02 — All computers",
     "MATCH (c:Computer) RETURN c"),
    ("03 — All users",
     "MATCH (u:User) RETURN u"),
    ("04 — Privileged groups (by member count)",
     "MATCH (g:Group) WHERE g.admincount = true "
     "RETURN g.name, size([(u)-[:MemberOf*1..]->(g) | u]) AS members "
     "ORDER BY members DESC"),
    ("05 — Domain Admins",
     "MATCH p=(u)-[:MemberOf*1..]->(g:Group) "
     "WHERE g.name STARTS WITH 'DOMAIN ADMINS@' RETURN p"),
    ("06 — Enterprise Admins",
     "MATCH p=(u)-[:MemberOf*1..]->(g:Group) "
     "WHERE g.name STARTS WITH 'ENTERPRISE ADMINS@' RETURN p"),
    ("07 — All Tier0 admins (DA/EA/Schema/Administrators)",
     "MATCH p=(u)-[:MemberOf*1..]->(g:Group) "
     "WHERE g.name =~ '(DOMAIN|ENTERPRISE|SCHEMA) ADMINS@.*' "
     "OR g.name STARTS WITH 'ADMINISTRATORS@' RETURN p"),
    ("08 — Kerberoastable users",
     "MATCH (u:User) WHERE u.hasspn = true "
     "RETURN u.name, u.samaccountname, u.serviceprincipalnames"),
    ("09 — AS-REP roastable users",
     "MATCH (u:User) WHERE u.dontreqpreauth = true "
     "RETURN u.name, u.enabled"),
    ("10 — Kerberoastable + privileged (gold)",
     "MATCH (u:User {hasspn: true})-[:MemberOf*1..]->(g:Group) "
     "WHERE g.admincount = true "
     "RETURN DISTINCT u.name, u.samaccountname, g.name"),
    ("11 — Unconstrained delegation computers",
     "MATCH (c:Computer) WHERE c.unconstraineddelegation = true "
     "RETURN c.name, c.operatingsystem"),
    ("12 — Constrained delegation (AllowedToDelegate)",
     "MATCH (u)-[:AllowedToDelegate]->(c:Computer) "
     "RETURN u.name, c.name"),
    ("13 — RBCD-able computers (GenericWrite on computers)",
     "MATCH p=(u)-[:GenericWrite|GenericAll|WriteDacl|WriteOwner]->"
     "(c:Computer) RETURN p"),
    ("14 — DCSync rights",
     "MATCH p=()-[:GetChanges|GetChangesAll|DCSync]->(d:Domain) "
     "RETURN p"),
    ("15 — DCSync non-admin principals (juiciest misconfig)",
     "MATCH p=(u)-[:GetChanges|GetChangesAll|DCSync]->(d:Domain) "
     "WHERE NOT EXISTS { MATCH (u)-[:MemberOf*1..]->(g:Group) "
     "WHERE g.name STARTS WITH 'DOMAIN ADMINS@' } RETURN p"),
    ("16 — ACL paths to Domain Admins",
     "MATCH p=shortestPath((u:User)-[:GenericAll|GenericWrite|"
     "WriteDacl|WriteOwner|AllExtendedRights|ForceChangePassword|"
     "AddMember*1..]->(g:Group)) "
     "WHERE g.name STARTS WITH 'DOMAIN ADMINS@' RETURN p LIMIT 25"),
    ("17 — ForceChangePassword on admin-count users",
     "MATCH p=(u)-[:ForceChangePassword]->(t:User) "
     "WHERE t.admincount = true RETURN p"),
    ("18 — GenericAll / WriteOwner (any target)",
     "MATCH p=(u)-[:GenericAll|WriteOwner]->(t) RETURN p LIMIT 50"),
    ("19 — Domain Users are Local Admin somewhere",
     "MATCH p=(g:Group)-[:AdminTo]->(c:Computer) "
     "WHERE g.name STARTS WITH 'DOMAIN USERS@' RETURN p"),
    ("20 — User AdminTo any computer",
     "MATCH p=(u:User)-[:AdminTo]->(c:Computer) RETURN p LIMIT 50"),
    ("21 — Active sessions (computer → user)",
     "MATCH p=(c:Computer)-[:HasSession]->(u:User) "
     "RETURN p LIMIT 50"),
    ("22 — DA sessions (session-riding targets)",
     "MATCH p=(c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->"
     "(g:Group) WHERE g.name STARTS WITH 'DOMAIN ADMINS@' RETURN p"),
    ("23 — Shortest path from Owned to Domain Admins",
     "MATCH p=shortestPath((s)-[*1..]->(t:Group)) "
     "WHERE s.owned = true AND t.name STARTS WITH 'DOMAIN ADMINS@' "
     "RETURN p"),
    ("24 — Domain Users → high-value targets",
     "MATCH p=shortestPath((g:Group)-[*1..]->(t)) "
     "WHERE g.name STARTS WITH 'DOMAIN USERS@' "
     "AND (t.highvalue = true OR t.admincount = true) "
     "RETURN p LIMIT 25"),
    ("25 — Old-OS computers (Win 7/2008/XP)",
     "MATCH (c:Computer) WHERE c.operatingsystem =~ "
     "'(?i).*(Windows (2000|XP|Vista|7|8|2003|2008)).*' "
     "RETURN c.name, c.operatingsystem"),
    ("26 — Computers without LAPS",
     "MATCH (c:Computer) WHERE c.haslaps = false OR "
     "c.haslaps IS NULL RETURN c.name, c.operatingsystem"),
    ("27 — Computers with SMB signing off",
     "MATCH (c:Computer) WHERE c.smbsigning = false RETURN c.name"),
    ("28 — Domain trusts",
     "MATCH p=(d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN p"),
    ("29 — Owned users summary",
     "MATCH (u:User) WHERE u.owned = true "
     "RETURN u.name, u.admincount, u.hasspn, u.dontreqpreauth"),
    ("30 — High-value targets (admincount OR marked)",
     "MATCH (n) WHERE n.highvalue = true OR n.admincount = true "
     "RETURN n LIMIT 100"),
]


# ─── REST client ─────────────────────────────────────────────────────

class BHCEClient:
    """Thin REST wrapper around BloodHound CE's /api/v2 endpoints.

    We use stdlib urllib so users don't need pip install requests
    on a stock Kali.  No retries on purpose — if the login fails the
    caller can surface the exact HTTP error to the UI.
    """

    def __init__(self, base_url: str,
                 token: Optional[str] = None,
                 verify_ssl: bool = True):
        self.base = base_url.rstrip("/")
        self.token = token
        self.verify_ssl = verify_ssl

    def _ctx(self):
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _request(self, method: str, path: str,
                 headers: dict = None, body=None,
                 timeout: int = 15) -> dict:
        url = f"{self.base}{path}"
        hdrs = {"Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        if self.token:
            hdrs["Authorization"] = f"Bearer {self.token}"
        data = None
        if body is not None:
            hdrs["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        req = urllib.request.Request(
            url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(
                    req, context=self._ctx(),
                    timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body_str = e.read().decode("utf-8", errors="replace")
            except Exception:
                body_str = ""
            raise BHCEError(
                f"HTTP {e.code} {e.reason}: {body_str[:300]}") from e
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            raise BHCEError(f"non-JSON response: {raw[:300]}")

    # ── Auth ─────────────────────────────────────────────────────────
    def login(self, username: str, password: str) -> str:
        """Exchange admin creds for a session_token (JWT).  Sets
        `self.token` on success, returns it."""
        r = self._request(
            "POST", "/api/v2/login",
            body={"login_method": "secret",
                  "username":     username,
                  "secret":       password})
        token = ((r.get("data") or {}).get("session_token")
                 or r.get("session_token"))
        if not token:
            raise BHCEError(
                f"login succeeded but no session_token in response: "
                f"{json.dumps(r)[:200]}")
        self.token = token
        return token

    # ── Saved queries ────────────────────────────────────────────────
    def list_saved_queries(self) -> list:
        r = self._request("GET", "/api/v2/saved-queries")
        return (r.get("data") or r.get("saved_queries") or []) \
            if isinstance(r, dict) else []

    def save_query(self, name: str, query: str,
                   description: str = "") -> dict:
        return self._request(
            "POST", "/api/v2/saved-queries",
            body={"name":        name,
                  "query":       query,
                  "description": description})


class BHCEError(Exception):
    pass


# ─── Bulk import orchestrator ────────────────────────────────────────

def bulk_import(base_url: str, username: str, password: str,
                on_progress: Optional[Callable[[str, str, str], None]]
                = None,
                skip_existing: bool = True,
                verify_ssl: bool = True) -> tuple:
    """Log into BH CE, POST every CURATED_QUERIES entry.

    Args:
        base_url      e.g. "http://localhost:8080"
        username      BH admin user (default "admin")
        password      BH admin password
        on_progress   callback(event, name, detail) invoked for UI
                      updates.  event ∈ {"login_ok","skip","ok",
                      "err","done"}.
        skip_existing True → don't POST a query whose name already
                      exists in the account's saved list (avoids
                      duplicate spam when the user re-runs).
        verify_ssl    False to skip TLS verification (handy for
                      self-signed BH CE reverse-proxy setups).

    Returns (imported_count, skipped_count, failed_count).
    """
    def _emit(event, name="", detail=""):
        if on_progress:
            try:
                on_progress(event, name, detail)
            except Exception:
                pass

    client = BHCEClient(base_url, verify_ssl=verify_ssl)

    # Login.
    try:
        client.login(username, password)
    except BHCEError as e:
        _emit("err", "(login)", str(e))
        return (0, 0, len(CURATED_QUERIES))
    _emit("login_ok", "", "")

    # Optionally fetch existing names to skip duplicates.
    existing_names = set()
    if skip_existing:
        try:
            for q in client.list_saved_queries():
                if isinstance(q, dict) and q.get("name"):
                    existing_names.add(q["name"])
        except BHCEError:
            # Non-fatal — just can't dedup.
            pass

    imported = skipped = failed = 0
    for name, query in CURATED_QUERIES:
        if name in existing_names:
            _emit("skip", name, "already present")
            skipped += 1
            continue
        try:
            client.save_query(
                name, query,
                description="Imported by HAWK bulk loader")
            _emit("ok", name, "")
            imported += 1
        except BHCEError as e:
            _emit("err", name, str(e))
            failed += 1

    _emit("done", "",
          f"{imported} imported, {skipped} skipped, "
          f"{failed} failed")
    return (imported, skipped, failed)
