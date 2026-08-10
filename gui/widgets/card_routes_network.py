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


# ── netexec (SMB) command builder ───────────────────────────────────
# The netexec dialog used to BUILD its command by hand, letting it drift
# from the netexec 1.5.1 CLI: a stale `--sessions` (renamed
# `--smb-sessions`) aborted argparse and zeroed the enum (W-02),
# `--users`/`--groups` moved to the `ldap` protocol and became no-ops
# under `smb` (W-02b), and the Anonymous option dropped the `-u '' -p ''`
# null-session bind legacy Windows needs (W-03).  Building the command
# here — from the module's null-session auth — keeps the flags in one
# place.
#
# nxc 1.5.1 smb enumeration options, each mapped to the EXACT flag nxc
# expects.  Do NOT derive `--<key>`: that produced the stale `--sessions`
# and `--rid`.  `--users`/`--groups` are omitted on purpose (they moved
# to `nxc ldap` in 1.5.1) — the LDAP / enum4linux / rpcclient routes
# still enumerate them.
NXC_SMB_OPTIONS = [
    ("shares",   "--shares",       "--shares        Enumerate shares"),
    ("sessions", "--smb-sessions", "--smb-sessions  Active sessions"),
    ("pass_pol", "--pass-pol",     "--pass-pol      Password policy"),
    ("rid",      "--rid-brute",    "--rid-brute     RID brute force"),
]


def build_netexec_smb_cmd(target, port, selected_flags, cred=None):
    """Build the `netexec smb` enumeration command.

    Anonymous (cred is None) reuses modules.enumeration.NXC_NULL_SESSION_AUTH
    so the null-session bind that legacy Windows (Server 2008 R2) needs
    can't drift from the module cmd_template again (W-03).
    """
    from modules.enumeration import NXC_NULL_SESSION_AUTH
    if cred is not None and cred.cred_type == "cleartext":
        auth = f"-u '{cred.username}' -p '{cred.password}'"
    elif cred is not None and cred.cred_type == "hash" and cred.hash_val:
        auth = f"-u '{cred.username}' -H '{cred.hash_val}'"
    else:
        auth = NXC_NULL_SESSION_AUTH
    flags = " ".join(f for f in selected_flags if f)
    cmd = f"netexec smb {target} --port {port} {auth} {flags}"
    return re.sub(r"\s{2,}", " ", cmd).strip()


class CardNetworkRoutesMixin:
    def _route_smb_tool(self, tool):
        # Check installation FIRST
        if not tool.is_available() and tool.id != "smbclient_list":
            self._show_install_dialog(tool)
            return
        port, _ = self._require_service(tool.name, "smb")
        if port is None:
            return
        target = self._get_target()
        if not target:
            return

        if tool.id == "enum4linux":
            # enum4linux-ng is target-platform-agnostic by design — it
            # speaks SMB / MS-RPC / LDAP / nmblookup, all Windows
            # protocols.  The "linux" in the name refers to the host
            # the tool runs on (Kali), not the target.  In fact Windows
            # AD / Samba domain controllers are its primary use case.
            # Earlier versions of HAWK skipped enum4linux on Windows
            # targets with a "use nxc instead" warning — that was a
            # misread of the tool's name and routinely cost the
            # operator the easiest source of users / groups / password
            # policy / domain SID on null-session-friendly targets.
            #
            # Use the tool's own template (enum4linux-ng -A -r 500-1100)
            # instead of hardcoding the legacy `enum4linux -a` form.  The
            # ng rewrite is parallel + timeout-bounded, 10× faster on
            # Metasploitable-class targets.  The install-first gate in
            # _INSTALL_FIRST_IDS ensures the user is offered the install
            # wizard on a fresh system where enum4linux-ng isn't present.
            self._run_raw(tool, tool.build_command(target))
            return

        if tool.id == "rpcclient":
            self._show_rpcclient_dialog(tool, target, port)
            return

        if tool.id == "netexec":
            self._show_crackmapexec_dialog(tool, target, port)
            return

        if tool.id == "smbclient_list":
            self._show_smbclient_port_dialog(tool, target)
            return

        self._run_raw(tool, tool.build_command(target))

    # ── RPCCLIENT — mode picker + auth ──────────────────────────────────
    # Default rpcclient template (`rpcclient -U '' -N {target}`) drops to
    # an interactive prompt.  Lifting that prompt to xterm only works if
    # _open_terminal succeeds; previously the silent fallback to
    # _run_raw left the tool spinning forever because in-app capture
    # has no way to type "exit".  This dialog forces the user to pick:
    # batch mode (captures + parses real intel, finishes in seconds) or
    # interactive shell (xterm only — if it fails, we tell the user
    # exactly why instead of pretending it worked).
    # `enumtrusts` deliberately omitted: modern rpcclient (Samba ≥4.18,
    # the default on current Kali) removed the local command — invoking
    # it produces a "command not found: enumtrusts" line at the tail of
    # every batch run, polluting the captured output.  On older rpcclient
    # binaries the call was usually answered with STATUS_ACCESS_DENIED
    # by Win Server 2008 R2 null sessions anyway, so the practical loss
    # is nil.  Operators who really need trust-relationship intel should
    # open the Interactive shell mode and use `lsaenumtrust` /
    # `lsaquerytrustdominfo` against an authenticated bind.
    _RPCCLIENT_BATCH_COMMANDS = (
        "srvinfo;"
        "lsaquery;"
        "querydominfo;"
        "getdompwinfo;"
        "enumdomusers;"
        "enumdomgroups;"
        "enumalsgroups builtin;"
        "enumalsgroups domain;"
        "netshareenumall;"
        "enumprivs"
    )

    def _show_rpcclient_dialog(self, tool, target, port):
        """Two-mode dialog for rpcclient.

        Batch (default): runs a curated set of enumeration commands
        via `-c` and captures structured output (users, shares, SID,
        password policy, trusts, groups).  Routed through the same
        in-app parser pipeline that handles enum4linux-ng.

        Interactive shell: launches rpcclient in a real terminal
        emulator.  If _open_terminal fails to find ANY emulator
        (qterminal/xfce4-terminal/gnome-terminal/konsole/xterm), the
        dialog surfaces a hard error — we deliberately do NOT fall
        back to in-app run any more, because in-app rpcclient hangs
        on the prompt forever.

        Authentication: empty fields = anonymous null session.  When
        the user fills Username + Password we switch to `-U user%pass`.
        When Hash is provided (NT or LM:NT) we add `--pw-nt-hash` for
        pass-the-hash.  A stored cred dropdown is offered as a quick
        pick — same source-of-truth pattern used by the smbclient
        dialog (entries override the dropdown at submit time).
        """
        from gui.dialogs import (
            _make_win, _note_box, _btn_row, _btn, _safe_destroy)
        from utils.clipboard import add_context_menu

        win = _make_win(self, "RPCCLIENT — Mode + Auth", 620, 540)
        ctk.CTkLabel(win, text=f"RPCCLIENT  →  {target}:{port}",
                     font=_f("xl", True),
                     text_color=COLORS["text_bright"]).pack(pady=(14, 4))
        _note_box(win,
                  "rpcclient speaks MS-RPC over SMB.\n"
                  "  • Batch (default): runs srvinfo, enumdomusers, "
                  "enumdomgroups, netshareenumall, querydominfo, "
                  "getdompwinfo, lsaquery, enumtrusts, enumprivs in "
                  "one shot.  Finishes in 5-10 s, output parsed into "
                  "Target Intel.\n"
                  "  • Interactive shell: opens a real terminal "
                  "(qterminal / xterm / …) at the rpcclient $> prompt "
                  "for manual drill-down.  Use AFTER the batch enum, "
                  "when you want to queryuser <RID> / lookupsids "
                  "<SID> / sambash …",
                  COLORS["border_dim"])

        # Mode selector
        mode_var = ctk.StringVar(value="batch")
        mf = ctk.CTkFrame(win, fg_color="transparent")
        mf.pack(fill="x", padx=40, pady=(8, 4))
        ctk.CTkLabel(mf, text="Mode:", font=_f("md", True),
                     text_color=COLORS["text_muted"]).pack(anchor="w")
        ctk.CTkRadioButton(
            mf, text="Quick enum (batch — recommended)",
            variable=mode_var, value="batch",
            font=_f("md"), text_color=COLORS["text_green"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(anchor="w", pady=2)
        ctk.CTkRadioButton(
            mf, text="Interactive shell  (opens external terminal)",
            variable=mode_var, value="interactive",
            font=_f("md"), text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(anchor="w", pady=2)

        # Auth block — defaults to anonymous (null session).
        af = ctk.CTkFrame(
            win, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=4)
        af.pack(fill="x", padx=40, pady=(12, 4))
        ctk.CTkLabel(af, text="Authentication  (leave blank = anonymous -N)",
                     font=_f("md", True), text_color=COLORS["text_muted"],
                     anchor="w").pack(anchor="w", padx=10, pady=(8, 2))

        user_var = ctk.StringVar(value="")
        pass_var = ctk.StringVar(value="")
        hash_var = ctk.StringVar(value="")

        def _row(parent, label, var, ph, show=None):
            r = ctk.CTkFrame(parent, fg_color="transparent")
            r.pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(r, text=label, font=_f("sm"),
                         text_color=COLORS["text_muted"], width=80,
                         anchor="w").pack(side="left")
            e = ctk.CTkEntry(
                r, textvariable=var, placeholder_text=ph,
                font=_f("md"), height=28,
                fg_color=COLORS["bg_card"],
                text_color=COLORS["text_bright"],
                border_color=COLORS["border_dim"], border_width=1,
                corner_radius=3,
                show=show)
            e.pack(side="left", fill="x", expand=True, padx=(4, 0))
            add_context_menu(e)

        _row(af, "Username", user_var, "Administrator / DOMAIN\\\\user / leave blank")
        _row(af, "Password", pass_var, "<password>", show="*")
        _row(af, "NTLM hash", hash_var, "<NT hash>   or   <LM>:<NT>")

        # Stored creds quick-pick — fills the entries above
        _ANON = {"anonymous", "anon", "guest", "null", ""}
        creds = []
        try:
            if self.app.session_manager.current:
                creds = self.app.session_manager.current.get_credentials()
        except Exception:
            creds = []
        usable = [c for c in creds
                  if (c.username or "").strip().lower() not in _ANON]
        if usable:
            ctk.CTkLabel(af, text="Or pick a stored cred:",
                         font=_f("xs"), text_color=COLORS["text_dim"],
                         anchor="w").pack(anchor="w", padx=10,
                                           pady=(6, 0))
            labels = {}
            for c in usable[:30]:
                secret = (c.password
                          if c.cred_type == "cleartext"
                          else (c.hash_val or "")[:24] + "…")
                lbl = f"{c.username}  ({secret})"
                labels[lbl] = c
            picker_var = ctk.StringVar(value="(none)")

            def _apply_pick(*_):
                lbl = picker_var.get()
                c = labels.get(lbl)
                if not c:
                    return
                user_var.set(c.username)
                if c.cred_type == "cleartext":
                    pass_var.set(c.password or "")
                    hash_var.set("")
                else:
                    hash_var.set(c.hash_val or "")
                    pass_var.set("")
            picker = ctk.CTkOptionMenu(
                af, values=["(none)"] + list(labels.keys()),
                variable=picker_var, command=_apply_pick,
                font=_f("sm"), fg_color=COLORS["bg_card"],
                button_color=COLORS["border_dim"],
                text_color=COLORS["text_bright"],
                width=560, height=28)
            picker.pack(anchor="w", padx=10, pady=(2, 8))
        else:
            ctk.CTkLabel(af, text="(no stored cleartext/hash creds yet)",
                         font=_f("xs"), text_color=COLORS["text_dim"],
                         anchor="w").pack(anchor="w", padx=10,
                                           pady=(2, 8))

        # Build command — shared by batch + interactive branches.
        def _build_cmd(batch: bool) -> str:
            u = user_var.get().strip()
            p = pass_var.get().strip()
            h = hash_var.get().strip()
            parts = ["rpcclient"]
            if h and u:
                parts += ["--pw-nt-hash",
                          "-U", shlex.quote(f"{u}%{h}")]
            elif u and p:
                parts += ["-U", shlex.quote(f"{u}%{p}")]
            elif u:
                parts += ["-U", shlex.quote(u)]
            else:
                # Empty username + no password → anonymous null session
                parts += ["-U", "''", "-N"]
            if batch:
                parts += ["-c",
                          shlex.quote(self._RPCCLIENT_BATCH_COMMANDS)]
            parts.append(shlex.quote(target))
            return " ".join(parts)

        # Run handler
        def _go():
            mode = mode_var.get()
            cmd = _build_cmd(batch=(mode == "batch"))
            _safe_destroy(win)
            if mode == "batch":
                self.app.terminal.write(
                    f"  [*] RPCCLIENT batch enum on {target}:{port}",
                    "info")
                self._run_raw(tool, cmd)
                return

            # Interactive shell branch — strict, no in-app fallback.
            from utils.runner import _open_terminal
            self.app.terminal.write(
                f"  [*] Launching rpcclient interactive shell "
                f"on {target}:{port} (opens external terminal)",
                "info")
            ok = _open_terminal(
                f"HAWK — rpcclient → {target}",
                cmd)
            if ok:
                self.app.terminal.write(
                    "  [i] Try: srvinfo, enumdomusers, enumdomgroups, "
                    "queryuser <RID>, lookupsids <SID>, "
                    "netshareenumall.",
                    "dim")
                return
            # No emulator at all — hard fail, surface to the user.
            self.app.terminal.write(
                "  [!] No terminal emulator found "
                "(qterminal / xfce4-terminal / gnome-terminal / "
                "konsole / xterm).  Install one or use Quick enum "
                "(batch) instead.",
                "error")
            try:
                from gui.dialogs import _make_win as _mw, _title as _t, _btn_row as _br, _btn as _b
                ew = _mw(self, "No terminal emulator", 520, 240)
                _t(ew, "Interactive shell unavailable")
                _note_box(
                    ew,
                    "rpcclient's interactive prompt needs a real "
                    "terminal window.  HAWK couldn't find any of:\n"
                    "  qterminal, xfce4-terminal, gnome-terminal, "
                    "konsole, xterm.\n\n"
                    "Install qterminal (default on Kali XFCE) or "
                    "xterm, or use the Quick enum (batch) mode — "
                    "it doesn't need a terminal window.",
                    COLORS["text_red"])
                row = _br(ew)
                _b(row, "OK", lambda: _safe_destroy(ew),
                   primary=True, w=110)
            except Exception:
                pass

        row = _btn_row(win)
        _btn(row, "RUN", _go, primary=True, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _show_smbclient_port_dialog(self, tool, target):
        """Let user choose SMB port from detected ports."""
        from gui.dialogs import _make_win, _note_box, _btn_row, _btn, _safe_destroy

        fp = self._get_fp()
        smb_ports = []
        if fp:
            for port, proto, svc, banner in fp.open_ports:
                svc_low = svc.lower()
                if any(k in svc_low for k in ["smb", "microsoft-ds", "netbios"]):
                    smb_ports.append((port, svc))

        if not smb_ports:
            smb_ports = [(445, "microsoft-ds"), (139, "netbios-ssn")]

        win = _make_win(self, "SMBCLIENT — Select Port", 480, 280)
        ctk.CTkLabel(win, text="SMBCLIENT — Select Port",
                     font=_f("xl", True),
                     text_color=COLORS["text_bright"]).pack(pady=(14, 6))

        port_var = ctk.IntVar(value=smb_ports[0][0])

        for port, svc in smb_ports:
            is_recommended = (port == 445)
            rf = ctk.CTkFrame(win, fg_color="transparent")
            rf.pack(anchor="w", padx=40, pady=4)
            ctk.CTkRadioButton(
                rf, text=f"{port}  —  {svc}" + ("  ★ recommended" if is_recommended else ""),
                variable=port_var, value=port,
                font=_f("md"), text_color=COLORS["text_green"] if is_recommended else COLORS["text_dim"],
                fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
            ).pack(side="left")

        # ── Credentials: quick-pick dropdown + always-visible manual
        # input.  The old version exposed ONLY a dropdown with stored
        # creds, so the user had no way to try credentials that weren't
        # already in the Credential Store.  We now always render two
        # text entries — the dropdown is just a convenience that fills
        # those entries.  Source of truth at RUN time is the entries,
        # never the dropdown.
        #
        # Stored creds with username ∈ {anonymous, guest, null, ""}
        # are filtered out — they'd duplicate the "Anonymous (-N)"
        # option and confuse the user.
        _ANON_NAMES = {"anonymous", "anon", "guest", "null", ""}
        creds_available = []
        if self.app.session_manager.current:
            creds_available = (
                self.app.session_manager.current.get_credentials())

        cred_map = {}      # label → (user, pass)
        stored_labels = []
        for c in creds_available:
            if c.cred_type != "cleartext":
                continue
            u = (c.username or "").strip()
            if u.lower() in _ANON_NAMES:
                continue
            p = (c.password or "").strip()
            label = f"{u}:{p}" if p else u
            if label not in cred_map:
                cred_map[label] = (u, p)
                stored_labels.append(label)

        # Dropdown options — always present, regardless of store state.
        _ANON_OPT = "Anonymous (-N)"
        _CUSTOM_OPT = "Custom…  (type below)"
        cred_options = [_ANON_OPT, _CUSTOM_OPT] + stored_labels
        cred_var = ctk.StringVar(value=_ANON_OPT)

        cf = ctk.CTkFrame(win, fg_color="transparent")
        cf.pack(fill="x", padx=24, pady=(10, 2))
        ctk.CTkLabel(cf, text="Quick pick:", font=_f("md"),
                     text_color=COLORS["text_dim"],
                     width=90, anchor="w").pack(side="left")
        ctk.CTkOptionMenu(
            cf, values=cred_options, variable=cred_var,
            width=300, height=28, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_dim"], corner_radius=3,
            command=lambda sel: _on_pick(sel),
        ).pack(side="left", padx=8)

        # Manual entry rows — always visible.
        user_var = ctk.StringVar(value="")
        pass_var = ctk.StringVar(value="")

        def _entry_row(label_text, var, show=""):
            f = ctk.CTkFrame(win, fg_color="transparent")
            f.pack(fill="x", padx=24, pady=(4, 0))
            ctk.CTkLabel(
                f, text=label_text, font=_f("sm", True),
                text_color=COLORS["text_bright"],
                width=90, anchor="w",
            ).pack(side="left")
            e = ctk.CTkEntry(
                f, textvariable=var, font=_f("md"), height=30,
                show=show,
                fg_color=COLORS["bg_card"],
                text_color=COLORS["text_bright"],
                border_color=COLORS["border_green"],
                border_width=1, corner_radius=3)
            e.pack(side="left", fill="x", expand=True)
            add_context_menu(e)
            return e

        user_entry = _entry_row("Username", user_var)
        _entry_row("Password", pass_var)

        ctk.CTkLabel(
            win,
            text=("Leave Username empty for anonymous (-N).  "
                  "Entries override the dropdown — edit freely."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            anchor="w", wraplength=420,
        ).pack(fill="x", padx=24, pady=(4, 0))

        def _on_pick(sel):
            """Dropdown change → update the two entries.
            - Anonymous: clear both.
            - Custom: clear both and focus Username so the user can
              start typing immediately.
            - Stored label: fill with that cred's user/pass.
            """
            if sel == _ANON_OPT:
                user_var.set("")
                pass_var.set("")
            elif sel == _CUSTOM_OPT:
                user_var.set("")
                pass_var.set("")
                try:
                    user_entry.focus_set()
                except Exception:
                    pass
            else:
                u, p = cred_map.get(sel, ("", ""))
                user_var.set(u)
                pass_var.set(p)

        def _run():
            p = port_var.get()
            u = (user_var.get() or "").strip()
            pw = (pass_var.get() or "").strip()
            # Username is the sole switch between authed and anonymous —
            # so "u:" with empty password = authed with blank password
            # (some services accept it), and "" = true anonymous.
            if u:
                # Escape single quotes so a password like o'brien's doesn't
                # break the shell command.
                safe_pw = pw.replace("'", "'\"'\"'")
                cmd = (f"smbclient -L //{target} -p {p} "
                       f"-U '{u}%{safe_pw}'")
            else:
                cmd = f"smbclient -L //{target} -N -p {p}"
            _safe_destroy(win)
            self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _show_crackmapexec_dialog(self, tool, target, port):
        """CrackMapExec interactive dialog with port selection."""
        from gui.dialogs import _make_win, _title, _note_box, _btn_row, _btn, _safe_destroy

        fp = self._get_fp()
        os_hint = fp.platform if fp else "unknown"

        # Get available SMB ports from Target Intel
        smb_ports = []
        if fp:
            for p, proto, svc, banner in fp.open_ports:
                if any(k in svc.lower() for k in ["smb", "microsoft-ds", "netbios"]):
                    smb_ports.append((p, svc))
        if not smb_ports:
            smb_ports = [(445, "microsoft-ds"), (139, "netbios-ssn")]

        win = _make_win(self, "CrackMapExec", 580, 480)
        _title(win, "CRACKMAPEXEC  —  SMB Enumeration")

        # Port selection
        port_var = ctk.IntVar(value=445)
        pf = ctk.CTkFrame(win, fg_color="transparent")
        pf.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(pf, text="Port:", font=_f("md"),
                     text_color=COLORS["text_dim"],
                     width=80, anchor="w").pack(side="left")
        for p, svc in smb_ports:
            is_rec = (p == 445)
            ctk.CTkRadioButton(pf,
                text=f"{p} ({svc})" + ("  ★" if is_rec else ""),
                variable=port_var, value=p,
                font=_f("md"),
                text_color=COLORS["text_green"] if is_rec else COLORS["text_dim"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"]
            ).pack(side="left", padx=8)

        _note_box(win,
                  f"Target: {target}\n"
                  f"OS: {os_hint.upper() if os_hint else 'Unknown'}\n\n"
                  "CrackMapExec works on both Windows and Linux targets.",
                  COLORS["text_green"])

        # Credentials from store
        creds_available = []
        if self.app.session_manager.current:
            creds_available = self.app.session_manager.current.get_credentials()

        cred_frame = ctk.CTkFrame(win, fg_color="transparent")
        cred_frame.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(cred_frame, text="Auth:", font=_f("md"),
                     text_color=COLORS["text_dim"],
                     width=80, anchor="w").pack(side="left")

        cred_options = ["Anonymous (no auth)"]
        cred_map = {}
        for c in creds_available:
            if c.cred_type == "cleartext" and c.username:
                label = f"{c.username}:{c.password}"
                cred_options.append(label)
                cred_map[label] = c
            elif c.cred_type == "hash" and c.username and c.hash_val:
                label = f"{c.username} [hash]"
                cred_options.append(label)
                cred_map[label] = c

        cred_var = ctk.StringVar(value=cred_options[0])
        ctk.CTkOptionMenu(cred_frame, values=cred_options, variable=cred_var,
            width=300, height=28, font=_f("sm"),
            fg_color=COLORS["bg_card"], button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_dim"], corner_radius=3,
        ).pack(side="left", padx=8)

        # Options
        ctk.CTkLabel(win, text="Select enumeration options:",
                     font=_f("md"), text_color=COLORS["text_dim"],
                     anchor="w").pack(fill="x", padx=24, pady=(8,4))

        opts = {}
        for key, flag, label in NXC_SMB_OPTIONS:
            var = ctk.BooleanVar(value=(key == "shares"))
            opts[key] = (var, flag)
            rf = ctk.CTkFrame(win, fg_color="transparent")
            rf.pack(anchor="w", padx=40, pady=2)
            ctk.CTkCheckBox(rf, text=label, variable=var,
                            font=_f("md"), text_color=COLORS["text_dim"],
                            fg_color=COLORS["border_green"],
                            border_color=COLORS["border_dim"],
                            checkmark_color=COLORS["bg_primary"],
                            width=18, height=18).pack(side="left")

        # `--users` / `--groups` intentionally not offered here: netexec
        # 1.5.1 moved them to the `ldap` protocol, so under `smb` they are
        # no-ops.  Point the operator at the routes that still work.
        ctk.CTkLabel(
            win,
            text=("Users / groups moved to the LDAP protocol in netexec "
                  "1.5.1 — use the LDAP / ENUM4LINUX / RPCCLIENT routes "
                  "for AD user + group enumeration."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            anchor="w", wraplength=520).pack(fill="x", padx=40, pady=(6, 0))

        def _run():
            selected = [flag for _k, (var, flag) in opts.items()
                        if var.get()]
            cred = cred_map.get(cred_var.get())
            cmd = build_netexec_smb_cmd(
                target, port_var.get(), selected, cred)
            _safe_destroy(win)
            self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _route_snmp(self, tool):
        """SNMP: check intel for UDP 161, guide scan if not found."""
        target = self._get_target()
        if not target:
            return

        port, _ = self._find_service("snmp")
        if port:
            self._show_snmp_dialog(tool, target, port)
        else:
            self._show_snmp_scan_suggest(tool, target)

    def _show_snmp_scan_suggest(self, tool, target):
        from gui.dialogs import _make_win, _note_box, _btn_row, _btn, _safe_destroy
        win = _make_win(self, "SNMP — Not Found", 540, 300)
        ctk.CTkLabel(win, text="SNMP Not Detected",
                     font=_f("xl",True), text_color=COLORS["text_yellow"]).pack(pady=(14,6))
        _note_box(win,
                  "SNMP runs on UDP port 161.\n\n"
                  "HAWK suggests:\n"
                  "  ★ nmap -Pn -sU -p 161 target  (fast, only SNMP)\n"
                  "    nmap -Pn -sU --top-ports 100  (top 100 UDP)\n\n"
                  "After the scan HAWK auto-opens the SNMPWALK dialog\n"
                  "if the port is reachable.",
                  COLORS["text_yellow"])
        row = _btn_row(win)
        _btn(row, "SCAN UDP 161",
             lambda: [_safe_destroy(win),
                      self._snmp_probe_and_followup(tool, target)],
             primary=True, w=140)
        _btn(row, "OPEN NMAP UDP",
             lambda: [_safe_destroy(win),
                      self.app.kill_chain_panel and
                      self.app.terminal.write(
                          "  [*] Use Port Scanning → NMAP UDP.", "dim")],
             w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _snmp_probe_and_followup(self, tool, target):
        """Run a minimal nmap UDP probe of port 161.  Depending on the
        outcome, either open the SNMPWALK dialog or inform the user
        that SNMP is genuinely unreachable."""
        import re as _re
        from utils.runner import ToolRunner
        # Probe must be FAST: we only need to know whether 161/udp is
        # open / filtered / closed before opening the SNMPWALK dialog.
        # Dropping `-sV` and capping retries + host-timeout brings the
        # probe from ~120 s down to ~5-10 s.  Version detection is
        # snmpwalk's job anyway — the OIDs it returns identify the
        # device far better than nmap's UDP service signatures.
        cmd = (f"sudo nmap -v -Pn -sU -p 161 "
               f"--max-retries 1 --host-timeout 15s "
               f"--stats-every 2s {target}")
        self.app.terminal.section(
            f"ENUMERATION  ·  SNMP UDP 161 probe")
        self.app.terminal.write(f"  $ {cmd}", "cmd")

        def _after_probe(name, rc, log):
            text = "\n".join(l for _, l in (log or []))
            # nmap UDP output states:
            #   "161/udp open         snmp"
            #   "161/udp open|filtered snmp"
            #   "161/udp filtered     snmp"
            #   "161/udp closed       snmp"
            open_match     = _re.search(r"161/udp\s+open\s", text, _re.I)
            open_filt      = _re.search(r"161/udp\s+open\|filtered",
                                         text, _re.I)
            filtered_only  = _re.search(r"161/udp\s+filtered\s",
                                         text, _re.I)
            closed         = _re.search(r"161/udp\s+closed", text, _re.I)

            def _on_ui():
                if open_match:
                    self.app.terminal.write(
                        "  [+] SNMP port OPEN (161/udp answered the "
                        "probe) — opening SNMPWALK to enumerate.",
                        "success")
                    self._show_snmp_dialog(tool, target, 161)
                elif open_filt:
                    # `open|filtered` is nmap saying it got NOTHING
                    # back: a silent open UDP port and a dropping
                    # firewall are indistinguishable from the outside.
                    # It is the NORMAL result for UDP, and calling it
                    # "port reachable" told the operator a fact nmap
                    # never established.
                    self.app.terminal.write(
                        "  [?] 161/udp open|filtered — no reply. nmap "
                        "cannot tell an open silent port from a "
                        "filtered one; this is the usual UDP result. "
                        "Opening SNMPWALK: an actual community-string "
                        "reply is what proves the service is there.",
                        "warn")
                    self._show_snmp_dialog(tool, target, 161,
                                           state_confirmed=False)
                elif filtered_only:
                    self.app.terminal.write(
                        "  [!] SNMP port filtered by firewall. Skip "
                        "SNMP on this target.", "warn")
                elif closed:
                    self.app.terminal.write(
                        "  [!] SNMP port closed — service not running.",
                        "warn")
                else:
                    self.app.terminal.write(
                        "  [!] SNMP scan returned no parseable state. "
                        "Check the raw nmap output above.", "warn")
            self.after(300, _on_ui)

        r = ToolRunner(
            output_callback=self.app.terminal.output_callback,
            done_callback=_after_probe,
            ui_dispatcher=getattr(self.app, "ui_call", None))
        r.run(cmd, "NMAP UDP 161 probe")

    def _show_snmp_dialog(self, tool, target, port, *,
                          preset_community=None,
                          state_confirmed: bool = True):
        """SNMPWALK dialog.

        ``state_confirmed=False`` when the caller only saw
        `open|filtered` — the subtitle then says what was actually
        observed instead of asserting the service is there.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                  _btn_row, _btn, _safe_destroy)
        win = _make_win(self, "SNMPWALK", 560, 440)
        _title(win, "SNMPWALK  —  SNMP Enumeration")
        _sub(win, f"SNMP detected on port {port}."
                  if state_confirmed else
                  f"Port {port}/udp is open|filtered — no reply to the "
                  f"nmap probe. SNMP is NOT confirmed; this walk is "
                  f"the test.")

        # Plain-language primer — the previous dialog showed two bare
        # dropdowns ("Community string" / "SNMP version") that meant
        # nothing to an operator new to SNMP.  This box explains what
        # the fields are and what the defaults imply, so the user can
        # make an informed choice (or just trust the defaults).
        _note_box(
            win,
            "What this asks you:\n"
            "  • Community string = the SNMP 'password'.  'public' is "
            "the factory default and works on ~95% of devices that "
            "expose SNMP.  'private' usually grants write access.\n"
            "  • SNMP version: 2c is the modern standard, 1 is for "
            "legacy gear, 3 requires real user credentials (not "
            "supported by this dialog yet).\n\n"
            "Just click TRY DEFAULTS if you're unsure — if 'public' "
            "doesn't work, HAWK offers a brute-force pass over a "
            "wordlist of common community strings automatically.",
            COLORS["text_dim"])

        community_var = ctk.StringVar(value=preset_community or "public")
        version_var   = ctk.StringVar(value="2c")

        for label, var, opts in [
            ("Community string:", community_var, ["public","private","community","snmp"]),
            ("SNMP version:",     version_var,   ["1","2c","3"]),
        ]:
            rf = ctk.CTkFrame(win, fg_color="transparent")
            rf.pack(fill="x", padx=24, pady=4)
            ctk.CTkLabel(rf, text=label, font=_f("md"),
                         text_color=COLORS["text_dim"],
                         width=160, anchor="w").pack(side="left")
            ctk.CTkOptionMenu(rf, values=opts, variable=var,
                              width=200, height=28, font=_f("md"),
                              fg_color=COLORS["bg_card"],
                              button_color=COLORS["border_dim"],
                              dropdown_fg_color=COLORS["bg_secondary"],
                              dropdown_text_color=COLORS["text_bright"],
                              text_color=COLORS["text_dim"],
                              corner_radius=3).pack(side="left", padx=8)

        def _run():
            import re as _re
            from utils.runner import ToolRunner
            community = community_var.get()
            version   = version_var.get()
            cmd = (f"snmpwalk -v{version} -c {community} "
                   f"-t 3 -r 1 {target}")
            _safe_destroy(win)
            self.app.terminal.section(f"ENUMERATION  ·  {tool.name}")
            self.app.terminal.write(f"  $ {cmd}", "cmd")

            # Record the run on the session so the SNMPWALK card flips
            # to its "done" state once the tool finishes.  Previously
            # this dialog drove ToolRunner directly and skipped the
            # session bookkeeping that _run_raw performs — leaving the
            # card stuck on its pre-run colour even after a successful
            # walk.  Mirror the start/finish pattern used in _run_raw.
            exec_id = None
            try:
                sess = self.app.session_manager.current
                if sess is not None:
                    exec_id = sess.start_tool_execution(
                        tool_id=tool.id, tool_name=tool.name,
                        phase_id=getattr(self, "phase_id",
                                          "enumeration"),
                        command=cmd)
            except Exception as e:
                print(f"[HAWK] snmpwalk start_tool_execution failed: {e}")

            def _after_walk(name, rc, log):
                text = "\n".join(l for _, l in (log or []))
                # Real SNMP response lines look like:
                #   iso.3.6.1.2.1.1.1.0 = STRING: "Linux server ..."
                #   SNMPv2-MIB::sysDescr.0 = STRING: ...
                has_oids = bool(_re.search(
                    r"^(?:iso\.|SNMPv2-MIB::|\.1\.3\.6)", text, _re.M))
                # Typical no-response indicators.
                no_response = any(k in text.lower() for k in (
                    "timeout: no response",
                    "unable to connect",
                    "authorizationerror",
                    "authentication failure",
                    "no such name",
                ))

                # Finalise the execution record so the card turns
                # green/yellow/red based on the actual outcome.  We
                # mark the run as "done" whenever snmpwalk produced
                # parseable output OR exited cleanly with rc=0 — the
                # tool DID run end-to-end, the user just may not have
                # had the right community string.  Bruteforce is the
                # next step, not a failure of this run.
                final_status = ("done" if (has_oids or rc == 0)
                                else "error")
                try:
                    if exec_id is not None and \
                            self.app.session_manager.current is not None:
                        lines = [l for _, l in (log or [])]
                        self.app.session_manager.current. \
                            finish_tool_execution(
                                exec_id, rc, lines, final_status)
                except Exception as e:
                    print(f"[HAWK] snmpwalk finish_tool_execution "
                          f"failed: {e}")

                def _on_ui():
                    # Reflect the run on the card's status dot.
                    try:
                        self._set_tool_status(tool.id, final_status)
                    except Exception:
                        pass
                    if has_oids:
                        # Community string is GOOD — save it.
                        self._save_snmp_community(target, community)
                        self.app.terminal.write(
                            f"  [+] SNMPWALK succeeded with community "
                            f"'{community}'. Saved to Credential Store.",
                            "success")
                    elif no_response:
                        # Offer bruteforce.
                        self.app.terminal.write(
                            f"  [!] snmpwalk got no useful response with "
                            f"'{community}'. Offering brute-force next.",
                            "warn")
                        self._offer_snmp_bruteforce(tool, target, version)
                    else:
                        # Ambiguous — RC was 0 but no data.  Probably
                        # same as no-response but nmap didn't say so.
                        self.app.terminal.write(
                            "  [!] SNMP scan returned no data. Service "
                            "may use a different community string.",
                            "warn")
                        self._offer_snmp_bruteforce(tool, target, version)
                self.after(300, _on_ui)

            # Flip the card dot to "running" so the user immediately
            # sees the launch — without this the row stays "ready"
            # until done_callback fires.
            try:
                self._set_tool_status(tool.id, "running")
            except Exception:
                pass

            r = ToolRunner(
                output_callback=self.app.terminal.output_callback,
                done_callback=_after_walk,
                ui_dispatcher=getattr(self.app, "ui_call", None))
            r.run(cmd, tool.name)

        def _skip_to_brute():
            # User already knows the defaults aren't going to work
            # (or just wants the wordlist sweep).  Skip the single
            # snmpwalk attempt and go straight to onesixtyone.  We
            # still record an execution entry so the card reflects
            # the action — status 'aborted' so a green dot doesn't
            # claim a successful walk that never ran.
            _safe_destroy(win)
            try:
                sess = self.app.session_manager.current
                if sess is not None:
                    eid = sess.start_tool_execution(
                        tool_id=tool.id, tool_name=tool.name,
                        phase_id=getattr(self, "phase_id",
                                          "enumeration"),
                        command="(skipped — straight to bruteforce)")
                    sess.finish_tool_execution(
                        eid, 0, [], "aborted")
            except Exception:
                pass
            try:
                self._set_tool_status(tool.id, "aborted")
            except Exception:
                pass
            self._offer_snmp_bruteforce(tool, target, version_var.get())

        row = _btn_row(win)
        _btn(row, "TRY DEFAULTS", _run, primary=True, w=160)
        _btn(row, "SKIP TO BRUTEFORCE", _skip_to_brute, w=180)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=110)

    def _offer_snmp_bruteforce(self, tool, target, version):
        from gui.dialogs import _make_win, _title, _note_box, _btn_row, _btn, _safe_destroy
        import shutil as _sh
        win = _make_win(self, "SNMP — Try Bruteforce", 560, 340)
        _title(win, "SNMP — No Response")

        msg = (f"snmpwalk got no reply from {target} with the community "
               "string you chose.\n\n"
               "Two possibilities:\n"
               "  1. The service uses a non-default community string.\n"
               "     → Bruteforce with onesixtyone + SecLists wordlist\n"
               "       (~600 common strings, ~15-30 seconds).\n"
               "  2. SNMP is genuinely not exposed.\n"
               "     → Skip.  No point continuing.")
        if not _sh.which("onesixtyone"):
            msg += ("\n\nNOTE: 'onesixtyone' is NOT installed.  Install "
                    "first:\n  sudo apt install -y onesixtyone")
        _note_box(win, msg,
                  COLORS["text_yellow"] if _sh.which("onesixtyone")
                  else COLORS["text_red"])

        row = _btn_row(win)
        if _sh.which("onesixtyone"):
            _btn(row, "BRUTEFORCE",
                 lambda: [_safe_destroy(win),
                          self._run_snmp_bruteforce(tool, target, version)],
                 primary=True, w=140)
        _btn(row, "SKIP", lambda: _safe_destroy(win), w=100)

    def _run_snmp_bruteforce(self, tool, target, version):
        import os as _os
        import re as _re
        from utils.runner import ToolRunner

        # Pick a wordlist in preference order.  All are standard Kali
        # / SecLists paths — if none exists we fall back to a hand-coded
        # inline list written to /tmp.
        candidates = [
            "/usr/share/seclists/Discovery/SNMP/"
            "common-snmp-community-strings.txt",
            "/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt",
            "/usr/share/wordlists/snmp.txt",
        ]
        wl = next((p for p in candidates if _os.path.isfile(p)), "")
        if not wl:
            import tempfile
            _os.makedirs(TMP_DIR, exist_ok=True)
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False,
                prefix="hawk-snmp-", dir=TMP_DIR)
            tmp.write("\n".join([
                "public", "private", "community", "admin", "manager",
                "snmp", "snmpd", "read", "write", "test", "guest",
                "root", "router", "cisco", "tivoli", "secret",
                "password", "pass", "access"]))
            tmp.close()
            wl = tmp.name

        cmd = f"onesixtyone -c {wl} {target}"
        self.app.terminal.section(f"ENUMERATION  ·  SNMP Bruteforce")
        self.app.terminal.write(f"  $ {cmd}", "cmd")

        def _after_brute(name, rc, log):
            text = "\n".join(l for _, l in (log or []))
            # onesixtyone hit lines look like:
            #   192.168.1.10 [public] Cisco IOS Software ...
            hits = _re.findall(
                r"^\s*\d+\.\d+\.\d+\.\d+\s+\[([^\]]+)\]",
                text, _re.M)
            # De-dupe preserving order.
            seen = set(); uniq = []
            for h in hits:
                if h not in seen:
                    uniq.append(h); seen.add(h)

            def _on_ui():
                if uniq:
                    first = uniq[0]
                    self.app.terminal.write(
                        f"  [+] Community strings found: "
                        f"{', '.join(uniq)}", "success")
                    # Save each to Credential Store.
                    for c in uniq:
                        self._save_snmp_community(target, c)
                    # Auto-open SNMPWALK dialog with the first hit
                    # pre-filled.
                    self.app.terminal.write(
                        f"  [*] Re-opening SNMPWALK dialog with "
                        f"community '{first}'.", "info")
                    self._show_snmp_dialog(
                        tool, target, 161, preset_community=first)
                else:
                    self.app.terminal.write(
                        "  [!] Bruteforce found 0 community strings. "
                        "SNMP is either filtered or uses an uncommon "
                        "string. Skip SNMP on this target.", "warn")
            self.after(300, _on_ui)

        r = ToolRunner(
            output_callback=self.app.terminal.output_callback,
            done_callback=_after_brute,
            ui_dispatcher=getattr(self.app, "ui_call", None))
        r.run(cmd, "SNMP brute (onesixtyone)")

    def _save_snmp_community(self, target, community):
        """Push a working SNMP community string into the Credential Store.
        Stored as a cleartext credential with empty username (community
        strings don't have a user component)."""
        if not hasattr(self.app, "cred_store") or not community:
            return
        try:
            from utils.session import Credential
            self.app.cred_store.add_credential(Credential(
                username="",
                password=community,
                cred_type="cleartext",
                services=["SNMP"],
                source_phase="enumeration",
                host=target,
                notes=(f"SNMP community string on {target}: '{community}'.\n"
                       f"Use:  snmpwalk -v2c -c {community} {target}"),
                # Both callers only get here after the agent answered
                # to this community string.
                verified=True))
        except Exception as e:
            print(f"[HAWK] save SNMP community failed: {e}")

    def _route_kerbrute(self, tool):
        """Custom Kerbrute dialog.

        kerbrute needs a realm/domain (required) and a DC IP (usually the
        target). The four sub-commands are user-enum, password-spray,
        brute-user and brute-force. HAWK builds the correct command line,
        suggests wordlists that actually exist on disk, and explains what
        each mode does + the expected signal so the user doesn't need to
        read the kerbrute docs.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        target = self._get_target()
        if not target:
            return

        # Pre-fill realm from session target_domain if present
        default_realm = ""
        try:
            sess = self.app.session_manager.current
            if sess and getattr(sess, "target_domain", ""):
                default_realm = sess.target_domain
        except Exception:
            pass

        # Wordlist candidates — we auto-pick the first that exists, but
        # show the user the full list so they can override.
        USER_WL_OPTIONS = [
            "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
            "/usr/share/seclists/Usernames/"
            "xato-net-10-million-usernames-dup.txt",
            "/usr/share/seclists/Usernames/Names/names.txt",
            "/usr/share/wordlists/metasploit/unix_users.txt",
        ]
        PASS_WL_OPTIONS = [
            "/usr/share/seclists/Passwords/Common-Credentials/"
            "10-million-password-list-top-1000.txt",
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/"
            "best1050.txt",
        ]
        first_existing = lambda opts, fallback: next(
            (p for p in opts if os.path.isfile(p)), fallback)
        default_users = first_existing(USER_WL_OPTIONS, USER_WL_OPTIONS[0])
        default_passes = first_existing(PASS_WL_OPTIONS, PASS_WL_OPTIONS[0])

        win = _make_win(self, "Kerbrute", 680, 640)
        _title(win, "KERBRUTE  —  Active Directory Kerberos Attacks")
        _sub(win, "Enumerate users or spray passwords against a Domain "
                  "Controller (TCP/UDP 88).")
        _note_box(win,
                  "ℹ  kerbrute talks Kerberos directly via AS-REQ, so\n"
                  "   valid users can be enumerated WITHOUT locking\n"
                  "   accounts. Password-spray DOES increment bad-pwd\n"
                  "   counters — respect the lockout policy: one\n"
                  "   password per round, then wait for the observation\n"
                  "   window. Feed users from userenum first.",
                  COLORS["border_dim"])

        # Mode selector — descriptions explain what to look for
        mode_var = ctk.StringVar(value="userenum")
        modes_info = {
            "userenum":
                "Enumerate valid AD users from a usernames wordlist.\n"
                "Success signal: '[+] VALID USERNAME: user@REALM'",
            "passwordspray":
                "Try ONE password against MANY users. Low lockout risk\n"
                "if run once. Signal: '[+] VALID LOGIN: user:pass'",
            "bruteuser":
                "Try many passwords against ONE user. HIGH lockout risk.\n"
                "Use only on known-safe / service accounts.",
            "bruteforce":
                "user:pass combo file, one pair per line. Very noisy —\n"
                "avoid on production domains.",
        }
        mode_frame = ctk.CTkFrame(win, fg_color="transparent")
        mode_frame.pack(fill="x", padx=24, pady=(4, 2))
        for m in modes_info:
            ctk.CTkRadioButton(
                mode_frame, text=m, variable=mode_var, value=m,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["text_green"]).pack(side="left", padx=6)

        mode_desc = ctk.CTkLabel(win, text=modes_info["userenum"],
                                 font=_f("sm"), justify="left",
                                 text_color=COLORS["text_dim"], anchor="w")
        mode_desc.pack(fill="x", padx=24, pady=(0, 4))

        # Realm + DC
        realm_var = ctk.StringVar(value=default_realm)
        dc_var    = ctk.StringVar(value=target)
        target_user_var = ctk.StringVar(value="")  # only for bruteuser

        def _row(label, var, hint=""):
            f = ctk.CTkFrame(win, fg_color="transparent")
            f.pack(fill="x", padx=24, pady=(4, 0))
            ctk.CTkLabel(f, text=label, width=110, anchor="w",
                         font=_f("sm", True),
                         text_color=COLORS["text_bright"]).pack(side="left")
            e = ctk.CTkEntry(f, textvariable=var, font=_f("sm"), height=30,
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

        _row("Realm",   realm_var, "e.g. TARGET.LOCAL / COMPANY.HTB (required)")
        _row("DC IP",   dc_var,    "Domain controller address")
        # Target user stays editable in every mode — if you type one
        # AND a Password, HAWK treats it as a "test this single cred"
        # intent and guides you to passwordspray emulation at RUN time.
        entry_tgt_user = _row("Target user", target_user_var,
             "bruteuser uses this alone.  Target user + Password = "
             "single-credential test (HAWK guides you on RUN).")

        # Wordlist / user / pass inputs
        user_var = ctk.StringVar(value=default_users)
        # Password field starts EMPTY — don't auto-fill a seasonal guess
        # ("Spring2024!", "Summer2025!", …) because (a) on userenum the
        # field is disabled and showing a pre-filled value confuses the
        # user ("perché c'è una password che non posso cambiare?"), and
        # (b) password sprays should be a deliberate choice, not a
        # side-effect of pressing RUN too fast.  The hint below still
        # suggests common seasonal guesses so the user has a starting
        # point when they actually want to spray.
        pass_var = ctk.StringVar(value="")
        passwl_var = ctk.StringVar(value=default_passes)
        entry_users = _row("Users file", user_var,
             "userenum / passwordspray / bruteforce — one username per line")
        entry_pass  = _row("Password",   pass_var,
             "Single password for passwordspray — "
             "e.g. 'Spring2024!', 'Welcome123', or the domain name + '1'. "
             "Editable in any mode — HAWK warns on mismatch.")
        entry_pwl   = _row("Pass file",  passwl_var,
             "bruteuser — passwords to try against the target user")

        # Extra-flags: rate limit, verbose
        extra_var = ctk.StringVar(value="--delay 200")
        _row("Extra args", extra_var,
             "e.g. '--delay 200' (ms between requests), "
             "'-v' (verbose), '-o out.txt'")

        # All 4 entries stay editable at all times — the user can fill
        # WHATEVER they want and HAWK figures out the right kerbrute
        # mode at RUN time.  The previous version disabled entries not
        # relevant to the selected mode, which blocked the very natural
        # case "I want to test these credentials I already have" when
        # the default mode was userenum.
        #
        # Coherence is enforced later by _kerbrute_detect_conflict():
        # if the filled fields don't match the mode, a guidance dialog
        # lets the user switch to the mode that does match, or run the
        # current mode anyway and discard the conflicting inputs.
        def _on_mode(*_):
            mode_desc.configure(text=modes_info[mode_var.get()])
        mode_var.trace_add("write", _on_mode)

        def _build_and_fire(mode, realm, dc, users, pwd, pwl,
                            tgt_u, extra):
            """Build the kerbrute command for `mode` and run it.

            Extracted from _run() so the coherence-resolution dialog can
            call it directly after the user picks "USE SUGGESTED" or
            "RUN ANYWAY" without re-reading the entry widgets (which
            might have been destroyed if we destroyed `win`).
            """
            from modules.base import _find_binary
            kb = _find_binary("kerbrute") or "kerbrute"
            extra_s = f" {extra}" if extra else ""

            if mode == "userenum":
                cmd = (f"{kb} userenum -d {realm} --dc {dc}"
                       f"{extra_s} {users}")
            elif mode == "passwordspray":
                if not pwd:
                    self.app.terminal.write(
                        "[!] passwordspray cancelled — the 'Password' "
                        "field is empty.  Type a candidate (e.g. "
                        "'Spring2024!') before pressing RUN.", "warn")
                    return
                # When the users-file is a throwaway path (single-user
                # test case), we generate it here on the fly so the
                # caller doesn't have to.
                if users.startswith("__HAWK_TMP_USER__:"):
                    try:
                        single_user = users.split(":", 1)[1]
                        import tempfile
                        os.makedirs(TMP_DIR, exist_ok=True)
                        fd, users = tempfile.mkstemp(
                            prefix="hawk_kerbrute_",
                            suffix=".users",
                            dir=TMP_DIR)
                        os.write(fd, single_user.encode() + b"\n")
                        os.close(fd)
                    except Exception as e:
                        self.app.terminal.write(
                            f"[!] Could not create temp userfile: {e}",
                            "error")
                        return
                cmd = (f"{kb} passwordspray -d {realm} --dc {dc}"
                       f"{extra_s} {users} '{pwd}'")
            elif mode == "bruteuser":
                if not tgt_u:
                    self.app.terminal.write(
                        "[!] bruteuser cancelled — 'Target user' is "
                        "required.", "warn")
                    return
                cmd = (f"{kb} bruteuser -d {realm} --dc {dc}"
                       f"{extra_s} {pwl} {tgt_u}")
            else:  # bruteforce
                cmd = (f"{kb} bruteforce -d {realm} --dc {dc}"
                       f"{extra_s} {users}")
                self.app.terminal.write(
                    "[i] bruteforce expects user:pass pairs one per line.",
                    "info")

            # Stash the realm/DC so the parser can build usage hints.
            self._kerbrute_ctx = {"realm": realm, "dc": dc, "mode": mode}
            _safe_destroy(win)
            # Kerbrute runs are long: userenum on xato-net 10M takes
            # tens of minutes, bruteuser with rockyou (14M) hours.  We
            # route through the BG-jobs bar so the UI stays responsive
            # and the operator can keep working on other cards while
            # the spray / enum churns.  Estimates are conservative —
            # the bar shows a moving ETA based on actual output.
            ETA = {
                "userenum":      1800,   # 30 min on big wordlists
                "passwordspray":  600,   # 10 min — small users list
                "bruteuser":     3600,   # 1 h with rockyou
                "bruteforce":    1800,   # depends on input
            }
            self._run_in_background(
                tool, cmd, estimated_secs=ETA.get(mode, 1800))

        def _run(_force=False):
            realm = realm_var.get().strip()
            dc    = dc_var.get().strip()
            users = user_var.get().strip()
            pwd   = pass_var.get().strip()
            pwl   = passwl_var.get().strip()
            tgt_u = target_user_var.get().strip()
            extra = extra_var.get().strip()
            mode  = mode_var.get()
            if not realm:
                self.app.terminal.write(
                    "[!] Kerbrute cancelled — realm/domain is required.",
                    "warn")
                return
            if not dc:
                dc = target

            # ── Coherence check ──────────────────────────────────────
            # `_force=True` means the user already saw the guidance
            # dialog and picked "RUN CURRENT ANYWAY" — skip the check.
            if not _force:
                conflict = self._kerbrute_detect_conflict(
                    mode=mode, has_tgt_u=bool(tgt_u),
                    has_pwd=bool(pwd),
                    has_users=bool(users), has_pwl=bool(pwl))
                if conflict:
                    # Show guidance dialog.  When the user picks an
                    # option it calls _build_and_fire() directly with
                    # the resolved mode + fields — we don't come back
                    # through _run().
                    self._show_kerbrute_conflict_dialog(
                        parent_win=win,
                        conflict=conflict,
                        current_mode=mode,
                        fields={
                            "realm": realm, "dc": dc, "users": users,
                            "pwd": pwd, "pwl": pwl, "tgt_u": tgt_u,
                            "extra": extra,
                        },
                        on_build_and_fire=_build_and_fire,
                        on_run_current_anyway=lambda: _run(_force=True),
                    )
                    return

            _build_and_fire(mode, realm, dc, users, pwd, pwl,
                            tgt_u, extra)

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _kerbrute_detect_conflict(self, mode, has_tgt_u, has_pwd,
                                   has_users, has_pwl):
        """Return a dict describing the best alternate mode when the
        filled fields don't line up with the selected mode, or None
        when everything is coherent.

        Only `Target user` and `Password` are "strong intent" fields —
        they start empty and any value means the user deliberately
        typed it.  `Users file` and `Pass file` are auto-pre-filled
        with a default dictionary path on Kali, so their presence is
        ambient, not a signal of intent.  We therefore only check for
        conflict when strong-intent fields don't match the mode.

        Conflict dict shape:
            {
              "suggested_mode":   "bruteuser" | "passwordspray" | None,
              "reason":           human string — why we suggest this,
              "action_desc":      what running the suggested mode does,
              "extra_note":       optional caveat (e.g. temp file),
              "override_fields":  dict of field overrides to apply
                                  before firing the suggested mode
                                  (e.g. {"users": "__HAWK_TMP_USER__:JDOE"})
            }
        """
        # Map typed-field combinations to the natural kerbrute mode.
        #
        # "1 user + 1 pass" — the most natural interpretation of
        # someone typing their test credentials.  kerbrute has no
        # native "single user × single pass" mode, so we emulate via
        # passwordspray with a temp userfile holding only that one
        # name.  Marker "__HAWK_TMP_USER__:<name>" is expanded by
        # _build_and_fire().
        if has_tgt_u and has_pwd:
            if mode in ("userenum", "bruteforce"):
                return {
                    "suggested_mode": "passwordspray",
                    "reason":
                        "You typed both a Target user and a Password. "
                        "kerbrute has no single-pair test mode, so "
                        "HAWK will emulate it via passwordspray with a "
                        "temp userfile containing only that user.",
                    "action_desc":
                        "Test if <target_user> : <password> is a valid "
                        "Kerberos credential (one AS-REQ against the "
                        "DC, no lockout risk).",
                    "extra_note":
                        "Uses passwordspray under the hood — safe for "
                        "a one-shot test.  Do NOT repeat with many "
                        "passwords on the same account (=> lockout).",
                    "override_fields": {
                        "mode":  "passwordspray",
                        "users": None,  # sentinel — filled in dialog
                    },
                }
            if mode == "bruteuser":
                # Bruteuser wants a pass FILE — but user gave a single
                # password.  Suggest passwordspray single-pair emulation.
                return {
                    "suggested_mode": "passwordspray",
                    "reason":
                        "bruteuser expects a FILE of passwords, but "
                        "you typed a single password.  For a single "
                        "credential test, passwordspray + a one-line "
                        "temp userfile is the right tool.",
                    "action_desc":
                        "Test <target_user> : <password> as a single "
                        "Kerberos credential.",
                    "extra_note":
                        "If you meant to brute-force many passwords "
                        "against <target_user>, fill 'Pass file' "
                        "instead and leave Password empty.",
                    "override_fields": {
                        "mode":  "passwordspray",
                        "users": None,
                    },
                }

        # Target user alone (no password) → probably wanted bruteuser
        # but forgot to pick a pass file, OR is about to type a password.
        if has_tgt_u and not has_pwd:
            if mode in ("userenum", "bruteforce"):
                return {
                    "suggested_mode": "bruteuser",
                    "reason":
                        "You typed a Target user but the current mode "
                        "ignores it.  bruteuser is the mode that uses "
                        "Target user (with a pass file).",
                    "action_desc":
                        "Try every password from the 'Pass file' list "
                        "against <target_user>.  ⚠ High lockout risk — "
                        "do not run on a real production account.",
                    "extra_note":
                        "If you meant to check a single credential, "
                        "type a password in the 'Password' field and "
                        "re-run.",
                    "override_fields": {"mode": "bruteuser"},
                }

        # Password alone (no target user) → passwordspray across the
        # users file.
        if has_pwd and not has_tgt_u:
            if mode in ("userenum", "bruteuser", "bruteforce"):
                return {
                    "suggested_mode": "passwordspray",
                    "reason":
                        "You typed a Password but the current mode "
                        "ignores it.  passwordspray tries ONE password "
                        "against MANY users — that's what you've set up.",
                    "action_desc":
                        "Try the password you typed against every user "
                        "in the 'Users file' (auto-filled with a "
                        "dictionary).  Single-round = no lockout risk.",
                    "extra_note":
                        "If you meant to enumerate users only, leave "
                        "the Password empty and run with mode=userenum.",
                    "override_fields": {"mode": "passwordspray"},
                }

        return None  # coherent — run normally

    def _show_kerbrute_conflict_dialog(self, parent_win, conflict,
                                        current_mode, fields,
                                        on_build_and_fire,
                                        on_run_current_anyway):
        """Modal guidance dialog: shows the conflict the user created
        between mode and filled fields, explains each option's effect,
        and fires the chosen option via the passed-in callbacks.

        Three actions:
          1. USE SUGGESTED — applies `conflict["override_fields"]` and
             calls on_build_and_fire with the resolved fields.
          2. RUN CURRENT ANYWAY — calls on_run_current_anyway() which
             re-enters _run with _force=True (skips the check).
          3. BACK — just closes this dialog, leaves the main form open
             so the user can tweak fields.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        suggested = conflict.get("suggested_mode") or "?"
        win = _make_win(self, "KERBRUTE — resolve input",
                        720, 560)
        _title(win, "⚠  Kerbrute — inputs vs mode mismatch")

        _sub(win, f"Current mode: {current_mode}    →    "
                  f"Suggested: {suggested}",
             COLORS["text_yellow"])

        _note_box(
            win,
            conflict.get("reason", "") or
            "Some fields you filled don't match the selected mode.",
            COLORS["border_amber"])

        # ── Option A: USE SUGGESTED ──────────────────────────────────
        ctk.CTkLabel(
            win, text=f"  ➊  USE {suggested.upper()} (suggested)",
            font=_f("md", True), text_color=COLORS["text_green"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(10, 2))
        _note_box(
            win,
            (conflict.get("action_desc", "") or "") + "\n\n" +
            (conflict.get("extra_note", "") or ""),
            COLORS["border_green"])

        # ── Option B: RUN CURRENT ANYWAY ─────────────────────────────
        ctk.CTkLabel(
            win, text=f"  ➋  RUN {current_mode.upper()} ANYWAY",
            font=_f("md", True), text_color=COLORS["text_dim"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(8, 2))
        _note_box(
            win,
            f"Runs kerbrute {current_mode} as originally selected, "
            f"ignoring the fields that don't apply to this mode.  "
            f"Pick this if the extra fields were entered by mistake.",
            COLORS["border_dim"])

        # ── Buttons row ──────────────────────────────────────────────
        def _do_suggested():
            # Apply the override_fields and dispatch.
            ovr = conflict.get("override_fields") or {}
            new_mode = ovr.get("mode", suggested)
            users = fields["users"]
            # Sentinel: suggested mode needs a temp userfile for the
            # Target user typed by the user.
            if ovr.get("users", "") is None and fields.get("tgt_u"):
                users = f"__HAWK_TMP_USER__:{fields['tgt_u']}"
            _safe_destroy(win)
            on_build_and_fire(
                new_mode, fields["realm"], fields["dc"], users,
                fields["pwd"], fields["pwl"], fields["tgt_u"],
                fields["extra"])

        def _do_current():
            _safe_destroy(win)
            try:
                on_run_current_anyway()
            except Exception as e:
                print(f"[HAWK] kerbrute 'run anyway' failed: {e}")

        row = _btn_row(win)
        _btn(row, f"USE {suggested.upper()}",
             _do_suggested, primary=True, w=200)
        _btn(row, f"RUN {current_mode.upper()} ANYWAY",
             _do_current, w=220)
        _btn(row, "BACK", lambda: _safe_destroy(win), w=100)

    def _route_ldapsearch(self, tool):
        """Show a configuration dialog — anonymous OR authenticated LDAP.

        Presets cover the most common queries (naming contexts, users,
        groups, computers, kerberoastable, AS-REP roastable).  A "Custom"
        preset exposes raw filter + attribute inputs.  A live command
        preview updates on every keystroke so the operator knows exactly
        what will run before hitting RUN.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        target = self._get_target()
        if not target:
            return

        port, _ = self._find_service("ldap")
        if port is None:
            self.app.terminal.write(
                "[!] LDAPSEARCH skipped — no LDAP (389/tcp) detected.\n"
                "    Run Port Scanning first, or re-run the nmap service\n"
                "    scan against the DC to confirm 389 is open.", "warn")
            return

        # ── Pull session defaults ─────────────────────────────────────────
        try:
            sess       = self.app.session_manager.current
            saved_dn   = getattr(sess, "ldap_base_dn",   "") or ""
            saved_dom  = getattr(sess, "target_domain",  "") or ""
        except Exception:
            sess = None
            saved_dn = saved_dom = ""

        def _domain_to_dn(domain: str) -> str:
            if not domain:
                return ""
            return ",".join(f"DC={p}" for p in domain.strip().split(".") if p)

        default_dn = saved_dn or _domain_to_dn(saved_dom)

        # ── Credential pre-fill from Credential Store ─────────────────────
        _ANON_USERS = {"anonymous", "anon", "guest", "nobody", ""}

        def _pick_creds():
            try:
                if sess is None:
                    return ("", "", saved_dom)
                creds = sess.get_credentials()
                def _ok(c):
                    u = (c.username or "").strip().lower()
                    return u not in _ANON_USERS and (
                        c.password or getattr(c, "hash_val", ""))
                cands = [c for c in creds
                         if (getattr(c, "host", "") or "").lower() == target.lower()
                         and _ok(c)
                         and any(s.upper() in ("LDAP", "AD", "SMB", "KERBEROS", "WINRM")
                                 for s in (c.services or []))]
                if not cands:
                    cands = [c for c in creds if _ok(c)]
                if cands:
                    c = cands[0]
                    return (
                        (c.username or "").strip(),
                        (c.password or "").strip(),
                        saved_dom or getattr(sess, "target_domain", "") or "",
                    )
            except Exception:
                pass
            return ("", "", saved_dom)

        du, dp, dd = _pick_creds()

        # ── Query presets ─────────────────────────────────────────────────
        # Each entry: (display_name, ldap_filter, attributes, scope, note)
        # scope "base" → -s base; "sub" → default (subtree)
        # filter "namingcontexts" is a special sentinel for the base query
        _PRESETS = [
            ("Naming Contexts  (anonymous-friendly)",
             "namingcontexts", "",
             "base",
             "Returns the root baseDN — safe with anonymous bind"),
            ("All Users",
             "(objectClass=user)", "sAMAccountName mail displayName memberOf",
             "sub",
             "List all domain user accounts and their group memberships"),
            ("All Groups",
             "(objectClass=group)", "cn member managedBy",
             "sub",
             "List all security and distribution groups"),
            ("All Computers",
             "(objectClass=computer)", "dNSHostName operatingSystem lastLogon",
             "sub",
             "List domain-joined machines with OS info"),
            ("Kerberoastable accounts",
             "(&(objectClass=user)(servicePrincipalName=*)(!samAccountType=805306370))",
             "sAMAccountName servicePrincipalName",
             "sub",
             "Accounts with SPNs — hash can be cracked offline (GetUserSPNs)"),
            ("AS-REP Roastable  (no pre-auth)",
             "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
             "sAMAccountName userAccountControl",
             "sub",
             "Accounts with 'Don't require Kerberos pre-auth' — offline hash crack"),
            ("Domain Admins members",
             "(memberOf=CN=Domain Admins,CN=Users,{dn})",
             "sAMAccountName distinguishedName",
             "sub",
             "High-value targets — {dn} is replaced with Base DN automatically"),
            ("Password Policy",
             "(objectClass=domain)", "minPwdLength pwdHistoryLength lockoutThreshold",
             "sub",
             "Domain password & lockout policy — informs spraying strategy"),
            ("Custom filter…",
             "", "", "sub",
             ""),
        ]
        preset_names = [p[0] for p in _PRESETS]

        # ── Build dialog ──────────────────────────────────────────────────
        win = _make_win(self, "LDAPSEARCH — configuration", 740, 720)
        _title(win, "LDAPSEARCH — query builder")
        _sub(win, f"Target: {target}:{port}", COLORS["text_dim"])

        body = ctk.CTkScrollableFrame(
            win, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["text_dim"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 4))

        # ── §1 Auth mode ──────────────────────────────────────────────────
        ctk.CTkLabel(body, text="  ◇  AUTH MODE",
                     font=_f("md", True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=16, pady=(10, 2))

        auth_var = ctk.StringVar(value="anonymous")
        mode_row = ctk.CTkFrame(body, fg_color="transparent")
        mode_row.pack(fill="x", padx=20, pady=(0, 6))
        _rb_kw = dict(font=_f("sm"), text_color=COLORS["text_bright"],
                      fg_color=COLORS["border_green"],
                      hover_color=COLORS["bg_card_hover"])
        ctk.CTkRadioButton(
            mode_row, text="Anonymous  (no credentials)",
            variable=auth_var, value="anonymous", **_rb_kw,
        ).pack(side="left", padx=(0, 32))
        ctk.CTkRadioButton(
            mode_row, text="Authenticated",
            variable=auth_var, value="auth", **_rb_kw,
        ).pack(side="left")

        # ── §2 Credentials section ────────────────────────────────────────
        cred_box = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                border_color=COLORS["border_dim"],
                                border_width=1, corner_radius=4)
        ctk.CTkLabel(cred_box, text="  CREDENTIALS",
                     font=_f("sm", True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=12, pady=(8, 4))

        user_var   = ctk.StringVar(value=du)
        pass_var   = ctk.StringVar(value=dp)
        domain_var = ctk.StringVar(value=dd)

        def _cred_row(parent, lbl, var, ph, show=""):
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.pack(fill="x", padx=12, pady=(2, 0))
            ctk.CTkLabel(f, text=lbl, font=_f("sm"),
                         text_color=COLORS["text_dim"],
                         width=88, anchor="w").pack(side="left")
            e = ctk.CTkEntry(
                f, textvariable=var, placeholder_text=ph, show=show,
                font=_f("sm"), fg_color=COLORS["bg_secondary"],
                border_color=COLORS["border_dim"],
                text_color=COLORS["text_bright"], width=500)
            e.pack(side="left", fill="x", expand=True)
            add_context_menu(e)

        _cred_row(cred_box, "Username", user_var, "user  or  user@DOMAIN.LOCAL")
        _cred_row(cred_box, "Password", pass_var, "password", show="*")
        _cred_row(cred_box, "Domain",   domain_var, "CORP.LOCAL  (optional if user@domain used)")
        ctk.CTkLabel(cred_box,
                     text="  Bind DN built as:  user@DOMAIN  "
                          "or  user@domain.local  depending on format",
                     font=_f("xs"), text_color=COLORS["text_dim"],
                     anchor="w").pack(fill="x", padx=12, pady=(4, 8))

        # ── §3 Query ──────────────────────────────────────────────────────
        ctk.CTkLabel(body, text="  ◇  QUERY",
                     font=_f("md", True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=16, pady=(10, 2))

        # Base DN
        base_dn_var = ctk.StringVar(value=default_dn)
        base_row = ctk.CTkFrame(body, fg_color="transparent")
        base_row.pack(fill="x", padx=16, pady=(4, 0))
        ctk.CTkLabel(base_row, text="Base DN", font=_f("sm", True),
                     text_color=COLORS["text_dim"],
                     width=88, anchor="w").pack(side="left")
        base_entry = ctk.CTkEntry(
            base_row, textvariable=base_dn_var,
            placeholder_text="DC=domain,DC=local  (blank = use naming context result)",
            font=_f("sm"), fg_color=COLORS["bg_secondary"],
            border_color=COLORS["border_dim"],
            text_color=COLORS["text_bright"])
        base_entry.pack(side="left", fill="x", expand=True)
        add_context_menu(base_entry)
        ctk.CTkLabel(body,
                     text="  Required for all queries except Naming Contexts",
                     font=_f("xs"), text_color=COLORS["text_dim"],
                     anchor="w").pack(fill="x", padx=108, pady=(0, 4))

        # Preset dropdown
        preset_var = ctk.StringVar(value=preset_names[0])
        preset_row = ctk.CTkFrame(body, fg_color="transparent")
        preset_row.pack(fill="x", padx=16, pady=(4, 0))
        ctk.CTkLabel(preset_row, text="Preset", font=_f("sm", True),
                     text_color=COLORS["text_dim"],
                     width=88, anchor="w").pack(side="left")
        ctk.CTkOptionMenu(
            preset_row, values=preset_names, variable=preset_var,
            font=_f("sm"),
            fg_color=COLORS["bg_secondary"],
            button_color=COLORS["bg_card"],
            button_hover_color=COLORS["bg_card_hover"],
            text_color=COLORS["text_bright"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            dropdown_hover_color=COLORS["bg_card_hover"],
        ).pack(side="left", fill="x", expand=True)

        # Preset hint label (updates with preset selection)
        preset_hint_var = ctk.StringVar(value=_PRESETS[0][4])
        ctk.CTkLabel(body, textvariable=preset_hint_var,
                     font=_f("xs"), text_color=COLORS["text_cyan"],
                     anchor="w", wraplength=640,
                     ).pack(fill="x", padx=108, pady=(2, 4))

        # Custom filter + attributes — single container (hidden when not custom)
        # Wrapping them in one frame avoids before= ordering problems when
        # showing/hiding the section dynamically inside a CTkScrollableFrame.
        filter_var = ctk.StringVar(value="")
        attrs_var  = ctk.StringVar(value="")
        custom_box = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                  border_color=COLORS["border_dim"],
                                  border_width=1, corner_radius=4)
        ctk.CTkLabel(custom_box, text="  ◇  CUSTOM FILTER",
                     font=_f("sm", True), text_color=COLORS["text_yellow"],
                     anchor="w").pack(fill="x", padx=12, pady=(8, 4))

        for _lbl, _var, _ph in (
            ("Filter",     filter_var, "(objectClass=user)"),
            ("Attributes", attrs_var,  "sAMAccountName mail  (blank = all attributes)"),
        ):
            _fr = ctk.CTkFrame(custom_box, fg_color="transparent")
            _fr.pack(fill="x", padx=12, pady=(2, 0))
            ctk.CTkLabel(_fr, text=_lbl, font=_f("sm", True),
                         text_color=COLORS["text_dim"],
                         width=88, anchor="w").pack(side="left")
            ctk.CTkEntry(_fr, textvariable=_var, placeholder_text=_ph,
                         font=_f("sm"), fg_color=COLORS["bg_secondary"],
                         border_color=COLORS["border_dim"],
                         text_color=COLORS["text_bright"],
                         ).pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(custom_box, height=6, text="",
                     fg_color="transparent").pack()  # bottom padding

        # ── §4 Command preview ────────────────────────────────────────────
        preview_lbl = ctk.CTkLabel(body, text="  ◇  COMMAND PREVIEW",
                     font=_f("md", True), text_color=COLORS["text_green"],
                     anchor="w")
        preview_lbl.pack(fill="x", padx=16, pady=(12, 2))
        preview_box = ctk.CTkTextbox(
            body, height=72, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"],
            border_width=1, corner_radius=3, wrap="word")
        preview_box.pack(fill="x", padx=16, pady=(0, 8))
        preview_box.configure(state="disabled")

        # ── Reactive update ───────────────────────────────────────────────
        def _build_cmd() -> str:
            mode   = auth_var.get()
            dn     = base_dn_var.get().strip()
            pname  = preset_var.get()

            # find matching preset entry
            entry  = next((p for p in _PRESETS if p[0] == pname), _PRESETS[0])
            filt   = entry[1]
            attrs  = entry[2]
            scope  = entry[3]

            if pname.startswith("Custom"):
                filt  = filter_var.get().strip()
                attrs = attrs_var.get().strip()
                scope = "sub"

            # substitute {dn} in filter
            if dn:
                filt = filt.replace("{dn}", dn)

            parts = [f"ldapsearch -x -H ldap://{target}:{port}"]

            if mode == "auth":
                u   = user_var.get().strip()
                p   = pass_var.get().strip()
                dom = domain_var.get().strip()
                bind_dn = u
                if u and dom and "@" not in u and "," not in u:
                    bind_dn = f"{u}@{dom}"
                if bind_dn:
                    parts.append(f"-D '{bind_dn}'")
                if p:
                    parts.append(f"-w '{p}'")

            if filt == "namingcontexts":
                parts.append("-s base namingcontexts")
            else:
                if dn:
                    parts.append(f"-b '{dn}'")
                if filt:
                    parts.append(f"'{filt}'")
                if attrs:
                    parts.append(attrs)

            return " ".join(parts)

        def _update(*_):
            # refresh command preview
            cmd = _build_cmd()
            preview_box.configure(state="normal")
            preview_box.delete("1.0", "end")
            preview_box.insert("1.0", cmd)
            preview_box.configure(state="disabled")

            # show/hide cred box — always inserts just above base_row
            pname = preset_var.get()
            if auth_var.get() == "auth":
                cred_box.pack(fill="x", padx=16, pady=(0, 6),
                              before=base_row)
            else:
                cred_box.pack_forget()

            # show/hide custom filter container — always inserts just above
            # the COMMAND PREVIEW heading (preview_lbl is always packed)
            is_custom = pname.startswith("Custom")
            if is_custom:
                custom_box.pack(fill="x", padx=16, pady=(6, 4),
                                before=preview_lbl)
            else:
                custom_box.pack_forget()

            # update preset hint
            entry = next((p for p in _PRESETS if p[0] == pname), _PRESETS[0])
            preset_hint_var.set(f"  {entry[4]}" if entry[4] else "")

        for v in (auth_var, base_dn_var, preset_var, filter_var,
                  attrs_var, user_var, pass_var, domain_var):
            v.trace_add("write", _update)

        _update()   # initial render

        # ── Footer buttons ────────────────────────────────────────────────
        def _do_run():
            cmd  = _build_cmd()
            mode = auth_var.get()
            pnam = preset_var.get()
            self.app.terminal.write(
                f"  [*] ldapsearch → {target}:{port}  "
                f"[{'anonymous' if mode == 'anonymous' else 'authenticated'}]  "
                f"— {pnam}",
                "info")
            _safe_destroy(win)
            self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "RUN", _do_run, primary=True, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _run_searchsploit(self, tool):
        target = self._get_target()
        if not target:
            return

        fp = self._get_fp()
        # Gate: refuse to run with a naked 'Windows' / 'Linux' fingerprint —
        # searchsploit will match thousands of unrelated entries.  Reuse the
        # Target Intel warning dialog so the user sees the same explanation
        # and can refine the OS in one place.
        intel = getattr(self.app, "target_intel", None)
        if intel and hasattr(intel, "_is_fp_too_generic"):
            try:
                is_generic, _ = intel._is_fp_too_generic()
            except Exception:
                is_generic = False
            if is_generic:
                def _after_confirm():
                    # Re-enter the actual search with the generic gate bypassed.
                    self._run_searchsploit_inner(tool, intel._fp)
                intel._show_fp_warning_dialog("SEARCHSPLOIT", _after_confirm)
                return

        self._run_searchsploit_inner(tool, fp)

