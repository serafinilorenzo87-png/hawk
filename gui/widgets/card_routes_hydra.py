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

class CardHydraRoutesMixin:
    def _route_hydra(self, tool):
        # Check installation FIRST
        if not tool.is_available():
            self._show_install_dialog(tool)
            return
        target = self._get_target()
        if not target:
            return

        # HTML-form brute force has its own dialog — the command shape
        # is completely different (PATH:BODY:CONDITION triplet instead
        # of a URL) so sharing the Basic-Auth dialog would bolt on too
        # many conditionals.  Dispatch early and keep each path clean.
        #
        # Before the form dialog itself we run a 3-question wizard
        # (_show_hydra_web_wizard) that filters modern-webapp edge
        # cases hydra can't handle (dynamic HTML CSRF, JSON APIs, rate
        # limiting) and routes them to the alternatives dialog instead
        # of wasting the user's time.
        if tool.id in ("hydra_http_form", "hydra_http_post_form",
                       "hydra_http_get_form"):
            port, _ = self._require_service(tool.name, "http", "https")
            if port is None:
                return
            detected_os = ""
            if self.app.session_manager.current:
                detected_os = (self.app.session_manager.current
                               .detected_os or "")
            self._show_hydra_web_wizard(
                tool, target, port, detected_os, mode="form")
            return

        # Basic Auth also goes through a preflight wizard — much
        # simpler (single question "did you confirm this is Basic
        # Auth?") because the module itself has no modern-webapp
        # ambiguity, but running http-get against a form login
        # produces false positives on every password so the sanity
        # check is worth the extra click.
        if tool.id in ("hydra_http", "hydra_http_get"):
            port, _ = self._require_service(tool.name, "http", "https")
            if port is None:
                return
            detected_os = ""
            if self.app.session_manager.current:
                detected_os = (self.app.session_manager.current
                               .detected_os or "")
            self._show_hydra_web_wizard(
                tool, target, port, detected_os, mode="basic")
            return

        # Proto column is the Hydra module name — NOT the URL scheme.
        # Hydra has no plain "http" module (it errors out with
        #   "There is no service 'http', most likely you mean one of
        #    the many web modules, e.g. http-get or http-form-post")
        # so hydra_http → http-get (Basic Auth brute force — what
        # the tool label "HYDRA HTTP-GET" in exploitation.py implies).
        # Form-based auth uses a separate tool id (hydra_http_form)
        # since the command shape is completely different.
        svc_map = {
            "hydra_ssh":      ("ssh",      22,   ("ssh",)),
            "hydra_ftp":      ("ftp",      21,   ("ftp",)),
            "hydra_http":     ("http-get", 80,   ("http","https")),
            "hydra_http_get": ("http-get", 80,   ("http","https")),
            "hydra_smb":      ("smb",      445,  ("smb",)),
            "hydra_rdp":      ("rdp",      3389, ("rdp",)),
        }
        proto, default_port, svc_keys = svc_map.get(
            tool.id, ("http", 80, ("http",)))

        port, _ = self._require_service(tool.name, *svc_keys)
        if port is None:
            return

        # ── Hydra SMB module ALWAYS speaks raw SMB on 445.  When the
        # target only exposes 139 (NetBIOS Session Service) hydra
        # receives NetBIOS framing it can't parse and bails with
        # "invalid reply from target smb://target:139/".  If both 139
        # and 445 are open, we silently prefer 445.  If only 139 is
        # open we ask the user how to proceed (try 445 anyway OR
        # switch to a tool that handles NetBIOS like nxc / enum4linux).
        if tool.id == "hydra_smb" and port != 445:
            fp = self._get_fp()
            has_445 = False
            if fp:
                for p, _proto, _svc, _ban in fp.open_ports:
                    if p == 445:
                        has_445 = True
                        break
            if has_445:
                self.app.terminal.write(
                    "  [hawk] hydra SMB: using 445 (raw SMB) instead "
                    "of detected 139 (NetBIOS Session).", "dim")
                port = 445
            else:
                self._show_hydra_smb_139_warning(tool, target)
                return

        detected_os = ""
        if self.app.session_manager.current:
            detected_os = self.app.session_manager.current.detected_os or ""

        self._show_hydra_wordlist_dialog(tool, target, port, proto, detected_os)

    def _show_hydra_wordlist_dialog(self, tool, target, port, proto, detected_os):
        """Hydra dialog with OS selection and wordlist dropdowns."""
        from gui.dialogs import _make_win, _title, _sub, _note_box, _btn_row, _btn, _safe_destroy
        import tkinter.filedialog as fd

        # ── Collect hostnames for IP/domain selector ───────────────
        domain = ""
        vhost_hosts = []
        try:
            sess = self.app.session_manager.current
            if sess:
                domain = getattr(sess, "target_domain", "") or ""
                from utils.hosts_helper import list_hawk_entries
                for e in list_hawk_entries():
                    for h in e.get("hostnames", []):
                        if h not in vhost_hosts:
                            vhost_hosts.append(h)
        except Exception:
            pass

        win = _make_win(self, f"Hydra — {tool.name}", 640, 620)
        _title(win, f"HYDRA — {tool.name}")

        _outer = win
        body = ctk.CTkScrollableFrame(
            _outer, fg_color=COLORS["bg_primary"],
            corner_radius=0,
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=4, pady=(0, 2))
        win = body

        # ── Target host (IP / domain / vhost) ──────────────────────
        host_options = [f"{target}  (IP)"]
        host_map = {host_options[0]: target}
        if domain.strip() and domain.strip() != target:
            lbl = f"{domain.strip()}  (domain)"
            host_options.append(lbl)
            host_map[lbl] = domain.strip()
        for vh in vhost_hosts:
            if vh != domain.strip() and vh != target:
                lbl = f"{vh}  (vhost)"
                host_options.append(lbl)
                host_map[lbl] = vh
        host_var = ctk.StringVar(value=host_options[0])
        if len(host_options) > 1:
            _sub(win, "Target host:")
            ctk.CTkOptionMenu(
                win, values=host_options, variable=host_var,
                width=500, height=28, font=_f("sm"),
                fg_color=COLORS["bg_card"],
                button_color=COLORS["border_dim"],
                dropdown_fg_color=COLORS["bg_secondary"],
                dropdown_text_color=COLORS["text_bright"],
                text_color=COLORS["text_bright"], corner_radius=3,
            ).pack(fill="x", padx=24, pady=(0, 4))

        # ── Port ───────────────────────────────────────────────────
        _sub(win, "Port:")
        port_var = ctk.StringVar(value=str(port))
        port_row = ctk.CTkFrame(win, fg_color="transparent")
        port_row.pack(fill="x", padx=24, pady=(0, 6))
        port_entry = ctk.CTkEntry(
            port_row, textvariable=port_var,
            font=_f("md"), height=28, width=100,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        port_entry.pack(side="left")
        add_context_menu(port_entry)

        # OS selection
        _sub(win, "Target OS:")
        os_var = ctk.StringVar(value=detected_os or "unknown")
        os_row = ctk.CTkFrame(win, fg_color="transparent")
        os_row.pack(pady=4)
        for val, label in [("windows","Windows"),("linux","Linux"),("unknown","Unknown")]:
            rb = ctk.CTkRadioButton(
                os_row, text=label, variable=os_var, value=val,
                font=_f("md"), text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"], border_color=COLORS["border_dim"])
            rb.pack(side="left", padx=12)
        if detected_os:
            ctk.CTkLabel(win, text=f"  ★ Detected: {detected_os.upper()}",
                         font=_f("sm"), text_color=COLORS["text_green"],
                         anchor="w").pack(fill="x", padx=24, pady=(0,4))

        # Username mode
        _sub(win, "Username:")
        user_mode_var = ctk.StringVar(value="single")
        single_var = ctk.StringVar(value="admin")

        um_row = ctk.CTkFrame(win, fg_color="transparent")
        um_row.pack(fill="x", padx=24, pady=2)
        ctk.CTkRadioButton(um_row, text="Single user:",
                           variable=user_mode_var, value="single",
                           font=_f("md"), text_color=COLORS["text_dim"],
                           fg_color=COLORS["border_green"],
                           border_color=COLORS["border_dim"]).pack(side="left")
        single_entry = ctk.CTkEntry(um_row, textvariable=single_var,
                                    font=_f("md"), height=28, width=180,
                                    fg_color=COLORS["bg_card"],
                                    text_color=COLORS["text_bright"],
                                    border_color=COLORS["border_dim"],
                                    border_width=1, corner_radius=3)
        single_entry.pack(side="left", padx=8)
        add_context_menu(single_entry)

        # Username wordlist — OS-aware ordering
        user_wl = _get_user_wordlists(detected_os)
        user_wl_labels = [l for l, _ in user_wl] + ["Browse custom..."]
        user_wl_var = ctk.StringVar(value=user_wl_labels[0] if user_wl_labels else "")

        uwl_row = ctk.CTkFrame(win, fg_color="transparent")
        uwl_row.pack(fill="x", padx=24, pady=2)
        ctk.CTkRadioButton(uwl_row, text="Wordlist:",
                           variable=user_mode_var, value="wordlist",
                           font=_f("md"), text_color=COLORS["text_dim"],
                           fg_color=COLORS["border_green"],
                           border_color=COLORS["border_dim"]).pack(side="left")

        user_wl_custom = ctk.StringVar(value="")
        user_wl_entry = ctk.CTkEntry(uwl_row, textvariable=user_wl_var,
                                      font=_f("sm"), height=28, width=300,
                                      fg_color=COLORS["bg_card"],
                                      text_color=COLORS["text_bright"],
                                      border_color=COLORS["border_dim"],
                                      border_width=1, corner_radius=3)
        user_wl_entry.pack(side="left", padx=4)
        add_context_menu(user_wl_entry)

        def _browse_user():
            p = fd.askopenfilename(title="Select username wordlist",
                                   filetypes=[("Text","*.txt"),("All","*")])
            if p:
                user_wl_var.set(p)
        ctk.CTkButton(uwl_row, text="📂", width=32, height=28,
                      font=_f("sm"), fg_color=COLORS["bg_card"],
                      hover_color=COLORS["bg_card_hover"],
                      border_color=COLORS["border_dim"], border_width=1,
                      text_color=COLORS["text_dim"], corner_radius=3,
                      command=_browse_user).pack(side="left", padx=2)

        # Quick select user wordlist
        if user_wl:
            uf = ctk.CTkScrollableFrame(win, height=80,
                                         fg_color=COLORS["bg_card"],
                                         border_color=COLORS["border_dim"],
                                         border_width=1, corner_radius=3)
            uf.pack(fill="x", padx=24, pady=(0,4))
            for label, path in user_wl[:8]:
                def _set_user(p=path, l=label):
                    user_wl_var.set(p)
                    user_mode_var.set("wordlist")
                ctk.CTkButton(uf, text=label, anchor="w",
                              height=22, font=_f("xs"),
                              fg_color="transparent",
                              hover_color=COLORS["bg_card_hover"],
                              text_color=COLORS["text_dim"],
                              corner_radius=2,
                              command=_set_user).pack(fill="x", padx=4, pady=1)

        # Password wordlist
        _sub(win, "Password wordlist:")
        pass_wl = _get_pass_wordlists()
        pass_wl_labels = [l for l, _ in pass_wl] + ["Browse custom..."]
        pass_wl_var = ctk.StringVar(
            value=next((l for l in pass_wl_labels if "rockyou" in l.lower()),
                       pass_wl_labels[0] if pass_wl_labels else ""))

        pass_wl_map = dict(pass_wl)
        pass_custom  = ctk.StringVar(value="")

        def _browse_pass():
            p = fd.askopenfilename(title="Select password wordlist",
                                   filetypes=[("Text","*.txt"),("All","*")])
            if p:
                pass_custom.set(p)
                pass_wl_var.set(f"Custom: {p}")

        pf_row = ctk.CTkFrame(win, fg_color="transparent")
        pf_row.pack(fill="x", padx=24, pady=2)
        pass_entry = ctk.CTkEntry(pf_row, textvariable=pass_wl_var,
                                   font=_f("sm"), height=28,
                                   fg_color=COLORS["bg_card"],
                                   text_color=COLORS["text_bright"],
                                   border_color=COLORS["border_dim"],
                                   border_width=1, corner_radius=3)
        pass_entry.pack(side="left", fill="x", expand=True, padx=(0,4))
        add_context_menu(pass_entry)
        ctk.CTkButton(pf_row, text="📂", width=32, height=28,
                      font=_f("sm"), fg_color=COLORS["bg_card"],
                      hover_color=COLORS["bg_card_hover"],
                      border_color=COLORS["border_dim"], border_width=1,
                      text_color=COLORS["text_dim"], corner_radius=3,
                      command=_browse_pass).pack(side="left")

        # Quick select pass wordlist
        pscroll = ctk.CTkScrollableFrame(win, height=80,
                                          fg_color=COLORS["bg_card"],
                                          border_color=COLORS["border_dim"],
                                          border_width=1, corner_radius=3)
        pscroll.pack(fill="x", padx=24, pady=(0,4))
        for label, path in pass_wl[:8]:
            def _set_pass(p=path, l=label):
                pass_wl_var.set(p)
            ctk.CTkButton(pscroll, text=label, anchor="w",
                          height=22, font=_f("xs"),
                          fg_color="transparent",
                          hover_color=COLORS["bg_card_hover"],
                          text_color=COLORS["text_dim"],
                          corner_radius=2,
                          command=_set_pass).pack(fill="x", padx=4, pady=1)

        # ── Target path (only for HTTP-family protocols) ─────────────
        # Hydra HTTP-GET / POST-FORM will happily run against the bare
        # root URL, but if the server returns 200 there (no auth
        # challenge) every attempt looks like a success → false
        # positives.  We pre-load paths previously discovered by
        # gobuster/ffuf so the user can pick a real login/admin page
        # with one click.
        path_var = ctk.StringVar(value="/")
        is_http = proto.startswith("http")
        if is_http:
            ps = ctk.CTkFrame(win, fg_color="transparent")
            ps.pack(fill="x", padx=24, pady=(6, 2))
            ctk.CTkLabel(ps, text="Target path:", font=_f("md", True),
                         text_color=COLORS["text_bright"],
                         anchor="w").pack(anchor="w")

            pr = ctk.CTkFrame(win, fg_color="transparent")
            pr.pack(fill="x", padx=24, pady=2)
            path_entry = ctk.CTkEntry(pr, textvariable=path_var,
                                      font=_f("md"), height=28,
                                      fg_color=COLORS["bg_card"],
                                      text_color=COLORS["text_bright"],
                                      border_color=COLORS["border_dim"],
                                      border_width=1, corner_radius=3)
            path_entry.pack(side="left", fill="x", expand=True)
            add_context_menu(path_entry)

            # Discovered paths picker — one-click fill.
            disc = []
            try:
                sess = self.app.session_manager.current
                if sess is not None:
                    disc = list(sess.discovered_web_paths or [])
            except Exception:
                disc = []

            if disc:
                ctk.CTkLabel(
                    win,
                    text="  Discovered by gobuster/ffuf "
                         f"({len(disc)} path{'s' if len(disc)!=1 else ''}):",
                    font=_f("sm"), text_color=COLORS["text_muted"],
                    anchor="w").pack(fill="x", padx=24)
                picker = ctk.CTkScrollableFrame(
                    win, height=80,
                    fg_color=COLORS["bg_card"],
                    border_color=COLORS["border_dim"],
                    border_width=1, corner_radius=3)
                picker.pack(fill="x", padx=24, pady=(0, 4))
                # Sort by "most interesting first": 401/403 (auth-gated,
                # exactly what Hydra wants), then 200, then redirects.
                sev = {401: 0, 403: 1, 200: 2, 301: 3, 302: 4, 307: 5}
                disc_sorted = sorted(
                    disc, key=lambda e: sev.get(e.get("status", 999), 99))
                for entry in disc_sorted[:30]:
                    pp = entry.get("path", "")
                    st = entry.get("status", 0)
                    sz = entry.get("size", 0)
                    if not pp:
                        continue
                    color = (COLORS["text_yellow"] if st in (401, 403)
                             else COLORS["text_green"] if st == 200
                             else COLORS["text_dim"])
                    label = f"[{st}]  {pp}" + (f"  ({sz}B)" if sz else "")
                    btn = ctk.CTkButton(
                        picker, text=label,
                        font=_f("sm"),
                        anchor="w", height=22,
                        fg_color="transparent",
                        hover_color=COLORS["bg_card_hover"],
                        text_color=color, corner_radius=2,
                        command=lambda p=pp: path_var.set(p))
                    btn.pack(fill="x", padx=4, pady=1)
            else:
                ctk.CTkLabel(
                    win,
                    text="  (no paths discovered yet — run Gobuster/FFUF "
                         "first to populate this picker)",
                    font=_f("sm"), text_color=COLORS["text_muted"],
                    anchor="w").pack(fill="x", padx=24, pady=(0, 4))

        # End of scrollable body — restore `win` to the toplevel so
        # threads + button row stay fixed at the bottom of the window
        # (outside the scroll area, always visible).
        win = _outer

        # Threads + background — fixed row above the buttons.
        opt_row = ctk.CTkFrame(win, fg_color="transparent")
        opt_row.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(opt_row, text="Threads:", font=_f("md"),
                     text_color=COLORS["text_dim"]).pack(side="left")
        threads_var = ctk.StringVar(value="4")
        threads_entry = ctk.CTkEntry(opt_row, textvariable=threads_var,
                                     width=50, height=28, font=_f("md"),
                                     fg_color=COLORS["bg_card"],
                                     text_color=COLORS["text_bright"],
                                     border_color=COLORS["border_dim"],
                                     border_width=1, corner_radius=3)
        threads_entry.pack(side="left", padx=8)
        add_context_menu(threads_entry)
        bg_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(opt_row, text="Run in background",
                        variable=bg_var, font=_f("md"),
                        text_color=COLORS["text_dim"],
                        fg_color=COLORS["border_green"],
                        border_color=COLORS["border_dim"],
                        checkmark_color=COLORS["bg_primary"]).pack(side="left", padx=20)

        def _start():
            # Resolve username
            if user_mode_var.get() == "single":
                user_arg = f"-l {_shq(single_var.get().strip())}"
            else:
                selected = user_wl_var.get()
                if selected == "Browse custom...":
                    return
                path = dict(user_wl).get(selected, selected)
                user_arg = f"-L {_shq(path)}"

            # Resolve password
            selected_p = pass_wl_var.get()
            if pass_custom.get():
                pass_path = pass_custom.get()
            else:
                pass_path = pass_wl_map.get(selected_p, selected_p)

            threads = threads_var.get().strip() or "4"
            # For HTTP-family protocols Hydra wants the path AFTER the
            # host:port, e.g.  http-get://target:80/admin/
            url_path = ""
            if is_http:
                p = path_var.get().strip()
                if p and p != "/":
                    if not p.startswith("/"):
                        p = "/" + p
                    url_path = p
                else:
                    url_path = "/"
            chosen_host = host_map.get(host_var.get(), target)
            chosen_port = port_var.get().strip() or str(port)
            target_url = f"{proto}://{chosen_host}:{chosen_port}{url_path}"
            cmd = (f"hydra {user_arg} -P {_shq(pass_path)} "
                   f"{target_url} -t {threads} -V")
            _safe_destroy(win)
            self.app.terminal.section(f"BRUTE FORCE  ·  {tool.name}")
            self.app.terminal.write(f"  $ {cmd}", "cmd")
            if bg_var.get():
                self._run_in_background(tool, cmd, 3600)
            else:
                self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "START", _start, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _show_hydra_form_dialog(self, tool, target, port, detected_os,
                                prefill=None):
        """Dialog for `hydra http-post-form` (and http-get-form).

        Supports both URL-encoded forms AND JSON APIs.  When the user
        selects JSON format, the body template switches to JSON syntax
        and Content-Type: application/json is injected automatically.
        An ffuf alternative command is also generated for JSON targets
        since hydra sometimes struggles with JSON encoding.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        import tkinter.filedialog as fd

        # ── Collect hostnames for IP/domain selector ───────────────
        domain = ""
        vhost_hosts = []
        try:
            sess = self.app.session_manager.current
            if sess:
                domain = getattr(sess, "target_domain", "") or ""
                from utils.hosts_helper import list_hawk_entries
                for e in list_hawk_entries():
                    for h in e.get("hostnames", []):
                        if h not in vhost_hosts:
                            vhost_hosts.append(h)
        except Exception:
            pass

        win = _make_win(self, f"Hydra — {tool.name}", 760, 760)
        _title(win, f"HYDRA — {tool.name}")

        _outer = win
        body = ctk.CTkScrollableFrame(
            _outer, fg_color=COLORS["bg_primary"],
            corner_radius=0,
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=4, pady=(0, 2))
        win = body

        pf = prefill or {}
        if pf.get("cookie_warning"):
            _note_box(win, pf["cookie_warning"], COLORS["border_amber"])

        # ── Target host (IP / domain / vhost) ──────────────────────
        _sub(win, "Target host:")
        host_options = [f"{target}  (IP)"]
        host_map = {host_options[0]: target}
        if domain.strip() and domain.strip() != target:
            lbl = f"{domain.strip()}  (domain)"
            host_options.append(lbl)
            host_map[lbl] = domain.strip()
        for vh in vhost_hosts:
            if vh != domain.strip() and vh != target:
                lbl = f"{vh}  (vhost)"
                host_options.append(lbl)
                host_map[lbl] = vh
        host_var = ctk.StringVar(value=host_options[0])
        if len(host_options) > 1:
            ctk.CTkOptionMenu(
                win, values=host_options, variable=host_var,
                width=500, height=28, font=_f("sm"),
                fg_color=COLORS["bg_card"],
                button_color=COLORS["border_dim"],
                dropdown_fg_color=COLORS["bg_secondary"],
                dropdown_text_color=COLORS["text_bright"],
                text_color=COLORS["text_bright"], corner_radius=3,
            ).pack(fill="x", padx=24, pady=(0, 4))

        # ── Port ───────────────────────────────────────────────────
        _sub(win, "Port:")
        port_var = ctk.StringVar(value=str(port))
        port_row = ctk.CTkFrame(win, fg_color="transparent")
        port_row.pack(fill="x", padx=24, pady=(0, 6))
        port_entry = ctk.CTkEntry(
            port_row, textvariable=port_var,
            font=_f("md"), height=28, width=100,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        port_entry.pack(side="left")
        add_context_menu(port_entry)

        # ── Body format toggle: FORM vs JSON ───────────────────────
        _sub(win, "Body format:")
        fmt_var = ctk.StringVar(value=pf.get("format", "form"))
        fmt_row = ctk.CTkFrame(win, fg_color="transparent")
        fmt_row.pack(fill="x", padx=24, pady=(0, 4))

        FORM_PRESETS = [
            ("WordPress",
             "log=^USER^&pwd=^PASS^&wp-submit=Log+In"),
            ("DVWA",
             "username=^USER^&password=^PASS^&Login=Login"),
            ("Django admin",
             "username=^USER^&password=^PASS^&next=%2Fadmin%2F"),
            ("Generic user/pass",
             "username=^USER^&password=^PASS^"),
            ("email/password",
             "email=^USER^&password=^PASS^"),
        ]
        JSON_PRESETS = [
            ("Generic JSON",
             '{"username":"^USER^","password":"^PASS^"}'),
            ("email + password",
             '{"email":"^USER^","password":"^PASS^"}'),
            ("user + pass",
             '{"user":"^USER^","pass":"^PASS^"}'),
            ("login + password",
             '{"login":"^USER^","password":"^PASS^"}'),
        ]

        body_var = ctk.StringVar(
            value="username=^USER^&password=^PASS^")
        chip_frame = ctk.CTkFrame(win, fg_color="transparent")

        def _on_fmt_change(*_a):
            fmt = fmt_var.get()
            presets = JSON_PRESETS if fmt == "json" else FORM_PRESETS
            body_var.set(presets[0][1])
            for w in chip_frame.winfo_children():
                w.destroy()
            for label, tpl in presets:
                ctk.CTkButton(
                    chip_frame, text=label, width=120, height=24,
                    font=_f("xs"),
                    fg_color=COLORS["bg_card"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_dim"], border_width=1,
                    text_color=COLORS["text_dim"], corner_radius=3,
                    command=lambda t=tpl: body_var.set(t),
                ).pack(side="left", padx=2)

        ctk.CTkRadioButton(
            fmt_row, text="FORM (url-encoded)",
            variable=fmt_var, value="form",
            font=_f("md"), text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            command=_on_fmt_change,
        ).pack(side="left", padx=(0, 16))
        ctk.CTkRadioButton(
            fmt_row, text="JSON (application/json)",
            variable=fmt_var, value="json",
            font=_f("md"), text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            command=_on_fmt_change,
        ).pack(side="left")

        json_note = ctk.CTkLabel(
            win, text="",
            font=_f("xs"), text_color=COLORS["text_yellow"],
            anchor="w", wraplength=660, justify="left")
        json_note.pack(fill="x", padx=24, pady=(0, 2))

        def _update_json_note(*_a):
            if fmt_var.get() == "json":
                json_note.configure(
                    text="⚠  JSON mode: Content-Type header is auto-added. "
                         "Hydra may struggle with JSON — use FFUF ALTERNATIVE "
                         "button if hydra fails.")
            else:
                json_note.configure(text="")
        fmt_var.trace_add("write", _update_json_note)

        # ── Username source ────────────────────────────────────────
        _sub(win, "Username:")
        user_mode_var = ctk.StringVar(value="single")
        single_var = ctk.StringVar(value="admin")

        um_row = ctk.CTkFrame(win, fg_color="transparent")
        um_row.pack(fill="x", padx=24, pady=2)
        ctk.CTkRadioButton(
            um_row, text="Single user:",
            variable=user_mode_var, value="single",
            font=_f("md"), text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(side="left")
        single_entry = ctk.CTkEntry(
            um_row, textvariable=single_var,
            font=_f("md"), height=28, width=180,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        single_entry.pack(side="left", padx=8)
        add_context_menu(single_entry)

        user_wl = _get_user_wordlists(detected_os)
        user_wl_var = ctk.StringVar(
            value=user_wl[0][1] if user_wl else "")
        uwl_row = ctk.CTkFrame(win, fg_color="transparent")
        uwl_row.pack(fill="x", padx=24, pady=2)
        ctk.CTkRadioButton(
            uwl_row, text="Wordlist:",
            variable=user_mode_var, value="wordlist",
            font=_f("md"), text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(side="left")
        user_wl_entry = ctk.CTkEntry(
            uwl_row, textvariable=user_wl_var,
            font=_f("sm"), height=28, width=300,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        user_wl_entry.pack(side="left", padx=4)
        add_context_menu(user_wl_entry)

        def _browse_user():
            p = fd.askopenfilename(title="Select username wordlist",
                                   filetypes=[("Text", "*.txt"),
                                              ("All", "*")])
            if p:
                user_wl_var.set(p)
                user_mode_var.set("wordlist")
        ctk.CTkButton(
            uwl_row, text="📂", width=32, height=28,
            font=_f("sm"), fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=3,
            command=_browse_user).pack(side="left", padx=2)

        if user_wl:
            uf = ctk.CTkScrollableFrame(win, height=60,
                                         fg_color=COLORS["bg_card"],
                                         border_color=COLORS["border_dim"],
                                         border_width=1, corner_radius=3)
            uf.pack(fill="x", padx=24, pady=(0, 4))
            for label, path in user_wl[:6]:
                def _set_user(p=path):
                    user_wl_var.set(p)
                    user_mode_var.set("wordlist")
                ctk.CTkButton(uf, text=label, anchor="w",
                              height=22, font=_f("xs"),
                              fg_color="transparent",
                              hover_color=COLORS["bg_card_hover"],
                              text_color=COLORS["text_dim"],
                              corner_radius=2,
                              command=_set_user).pack(fill="x", padx=4, pady=1)

        # ── Password wordlist ──────────────────────────────────────
        _sub(win, "Password wordlist:")
        pass_wl = _get_pass_wordlists()
        pass_wl_var = ctk.StringVar(
            value=next((p for _, p in pass_wl if "rockyou" in p.lower()),
                       pass_wl[0][1] if pass_wl else ""))
        pf_row = ctk.CTkFrame(win, fg_color="transparent")
        pf_row.pack(fill="x", padx=24, pady=2)
        pass_entry = ctk.CTkEntry(
            pf_row, textvariable=pass_wl_var,
            font=_f("sm"), height=28,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_context_menu(pass_entry)

        def _browse_pass():
            p = fd.askopenfilename(title="Select password wordlist",
                                   filetypes=[("Text", "*.txt"),
                                              ("All", "*")])
            if p:
                pass_wl_var.set(p)
        ctk.CTkButton(
            pf_row, text="📂", width=32, height=28,
            font=_f("sm"), fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=3,
            command=_browse_pass).pack(side="left")

        if pass_wl:
            pscroll = ctk.CTkScrollableFrame(
                win, height=60,
                fg_color=COLORS["bg_card"],
                border_color=COLORS["border_dim"],
                border_width=1, corner_radius=3)
            pscroll.pack(fill="x", padx=24, pady=(0, 4))
            for label, path in pass_wl[:6]:
                def _set_pass(p=path):
                    pass_wl_var.set(p)
                ctk.CTkButton(
                    pscroll, text=label, anchor="w",
                    height=22, font=_f("xs"),
                    fg_color="transparent",
                    hover_color=COLORS["bg_card_hover"],
                    text_color=COLORS["text_dim"],
                    corner_radius=2,
                    command=_set_pass).pack(fill="x", padx=4, pady=1)

        # ── HTTP method ────────────────────────────────────────────
        _sub(win, "HTTP method:")
        method_var = ctk.StringVar(value="http-post-form")
        mr = ctk.CTkFrame(win, fg_color="transparent")
        mr.pack(fill="x", padx=24, pady=(2, 4))
        for mod, lbl in [("http-post-form", "POST (most logins)"),
                         ("http-get-form",  "GET  (search-style)"),
                         ("https-post-form", "POST over HTTPS"),
                         ("https-get-form",  "GET over HTTPS")]:
            ctk.CTkRadioButton(
                mr, text=lbl, variable=method_var, value=mod,
                font=_f("sm"), text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
            ).pack(side="left", padx=6)

        # ── Login path ─────────────────────────────────────────────
        _sub(win, "Login path:")
        path_var = ctk.StringVar(value="/login")
        path_entry = ctk.CTkEntry(
            win, textvariable=path_var,
            font=_f("md"), height=30,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3,
            placeholder_text="/login.php  or  /api/auth/login")
        path_entry.pack(fill="x", padx=24, pady=(0, 4))
        add_context_menu(path_entry)

        try:
            sess = self.app.session_manager.current
            disc = list(sess.discovered_web_paths or []) if sess else []
        except Exception:
            disc = []
        if disc:
            ctk.CTkLabel(
                win, text=f"  Discovered paths ({len(disc)}):",
                font=_f("sm"), text_color=COLORS["text_muted"],
                anchor="w").pack(fill="x", padx=24)
            dp = ctk.CTkScrollableFrame(
                win, height=70,
                fg_color=COLORS["bg_card"],
                border_color=COLORS["border_dim"],
                border_width=1, corner_radius=3)
            dp.pack(fill="x", padx=24, pady=(0, 4))
            sev = {200: 0, 302: 1, 301: 2, 401: 3, 403: 4}
            disc_sorted = sorted(
                disc, key=lambda e: sev.get(e.get("status", 999), 99))
            for entry in disc_sorted[:25]:
                pp = entry.get("path", "")
                st = entry.get("status", 0)
                if not pp:
                    continue
                color = (COLORS["text_green"] if st == 200 else
                         COLORS["text_yellow"] if st in (301, 302)
                         else COLORS["text_muted"])
                lbl = f"[{st}]  {pp}"
                ctk.CTkButton(
                    dp, text=lbl, anchor="w",
                    height=22, font=_f("sm"),
                    fg_color="transparent",
                    hover_color=COLORS["bg_card_hover"],
                    text_color=color, corner_radius=2,
                    command=lambda p=pp: path_var.set(p),
                ).pack(fill="x", padx=4, pady=1)

        # ── Body template + preset chips ───────────────────────────
        _sub(win, "Body template (use ^USER^ and ^PASS^ placeholders):")
        body_entry = ctk.CTkEntry(
            win, textvariable=body_var,
            font=_f("md"), height=30,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        body_entry.pack(fill="x", padx=24, pady=(0, 2))
        add_context_menu(body_entry)

        chip_frame.pack(fill="x", padx=24, pady=(2, 4))
        _on_fmt_change()

        # ── Cookie header (optional) ───────────────────────────────
        _sub(win, "Cookie header (optional):")
        cookie_var = ctk.StringVar(value=pf.get("cookie", ""))
        cookie_entry = ctk.CTkEntry(
            win, textvariable=cookie_var,
            font=_f("md"), height=30,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3,
            placeholder_text="PHPSESSID=abc123; csrf_token=xyz "
                             "(leave empty if none)")
        cookie_entry.pack(fill="x", padx=24, pady=(0, 6))
        add_context_menu(cookie_entry)

        # ── Match condition (F= or S=) ─────────────────────────────
        _sub(win, "Match condition:")
        match_mode_var = ctk.StringVar(value=pf.get("match_mode", "F"))
        mmr = ctk.CTkFrame(win, fg_color="transparent")
        mmr.pack(fill="x", padx=24, pady=(0, 2))
        ctk.CTkRadioButton(
            mmr, text="F=  string on FAILURE page",
            variable=match_mode_var, value="F",
            font=_f("sm"), text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(side="left", padx=(0, 12))
        ctk.CTkRadioButton(
            mmr, text="S=  string on SUCCESS page (or status code like S=200)",
            variable=match_mode_var, value="S",
            font=_f("sm"), text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(side="left")

        match_str_var = ctk.StringVar(
            value=pf.get("match_string", "Invalid"))
        match_entry = ctk.CTkEntry(
            win, textvariable=match_str_var,
            font=_f("md"), height=30,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3,
            placeholder_text="e.g. 'Invalid credentials' or "
                             "'Authentication Failed'")
        match_entry.pack(fill="x", padx=24, pady=(0, 4))
        add_context_menu(match_entry)

        ctk.CTkLabel(
            win,
            text=("Tip: submit one WRONG credential in F12 → Network, "
                  "copy a phrase from the error response body, paste "
                  "here with F= mode."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            wraplength=660, justify="left", anchor="w",
        ).pack(fill="x", padx=24, pady=(0, 6))

        # ── Threads + BG ───────────────────────────────────────────
        win = _outer
        opt_row = ctk.CTkFrame(win, fg_color="transparent")
        opt_row.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(opt_row, text="Threads:", font=_f("md"),
                     text_color=COLORS["text_dim"]).pack(side="left")
        threads_var = ctk.StringVar(value="4")
        threads_entry = ctk.CTkEntry(
            opt_row, textvariable=threads_var,
            width=50, height=28, font=_f("md"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        threads_entry.pack(side="left", padx=8)
        add_context_menu(threads_entry)
        bg_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opt_row, text="Run in background",
            variable=bg_var, font=_f("md"),
            text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            checkmark_color=COLORS["bg_primary"],
        ).pack(side="left", padx=20)

        def _resolve_user_pass():
            """Returns (user_arg, pass_path) or None on validation error."""
            if user_mode_var.get() == "single":
                u = single_var.get().strip()
                if not u:
                    self.app.terminal.write(
                        "[!] Hydra form cancelled — Single user empty.",
                        "warn")
                    return None
                user_arg = f"-l {_shq(u)}"
            else:
                p = user_wl_var.get().strip()
                if not p:
                    self.app.terminal.write(
                        "[!] Hydra form cancelled — user wordlist "
                        "missing.", "warn")
                    return None
                user_arg = f"-L {_shq(p)}"
            pp = pass_wl_var.get().strip()
            if not pp:
                self.app.terminal.write(
                    "[!] Hydra form cancelled — password wordlist "
                    "missing.", "warn")
                return None
            return user_arg, pp

        def _start():
            resolved = _resolve_user_pass()
            if not resolved:
                return
            user_arg, pass_path = resolved

            chosen_host = host_map.get(host_var.get(), target)
            chosen_port = port_var.get().strip() or str(port)

            path = path_var.get().strip() or "/"
            if not path.startswith("/"):
                path = "/" + path
            body_tpl = body_var.get().strip()
            if "^USER^" not in body_tpl or "^PASS^" not in body_tpl:
                self.app.terminal.write(
                    "[!] Body template must contain both ^USER^ and "
                    "^PASS^ placeholders.", "error")
                return
            match_str = match_str_var.get().strip().replace(":", "\\:")
            if not match_str:
                self.app.terminal.write(
                    "[!] Match condition is required — without it "
                    "hydra reports ALL passwords as valid.", "error")
                return
            condition = f"{match_mode_var.get()}={match_str}"

            cookie_val = cookie_var.get().strip()
            extra_headers = ""
            if cookie_val:
                extra_headers += f":H=Cookie\\: {cookie_val}"
            if fmt_var.get() == "json":
                extra_headers += ":H=Content-Type\\: application/json"

            # Hydra uses ':' as triplet delimiter (path:body:condition).
            # Literal colons inside the body (JSON keys/values) must be
            # escaped as '\:' so hydra doesn't split on them.
            body_escaped = body_tpl.replace(":", "\\:")
            triplet = f"{path}:{body_escaped}:{condition}{extra_headers}"
            threads = threads_var.get().strip() or "4"
            method = method_var.get()

            cmd = (f"hydra {user_arg} -P {_shq(pass_path)} "
                   f"{chosen_host} -s {chosen_port} "
                   f"{method} {_shq(triplet)} -t {threads} -V")
            _safe_destroy(win)
            self.app.terminal.section(f"BRUTE FORCE  ·  {tool.name}")
            self.app.terminal.write(f"  $ {cmd}", "cmd")
            if bg_var.get():
                self._run_in_background(tool, cmd, 3600)
            else:
                self._run_raw(tool, cmd)

        def _start_ffuf():
            """Generate and run an ffuf command as JSON brute-force alternative."""
            resolved = _resolve_user_pass()
            if not resolved:
                return
            user_arg_raw, pass_path = resolved

            chosen_host = host_map.get(host_var.get(), target)
            chosen_port = port_var.get().strip() or str(port)
            path = path_var.get().strip() or "/"
            if not path.startswith("/"):
                path = "/" + path
            body_tpl = body_var.get().strip()
            match_str = match_str_var.get().strip()
            method = method_var.get()
            scheme = "https" if "https" in method else "http"

            # For ffuf, replace ^PASS^ with FUZZ
            ffuf_body = body_tpl.replace("^PASS^", "FUZZ")
            # Single user: inject directly; wordlist: can't do both in ffuf
            if user_mode_var.get() == "single":
                u = single_var.get().strip() or "admin"
                ffuf_body = ffuf_body.replace("^USER^", u)
            else:
                ffuf_body = ffuf_body.replace("^USER^", "FUZZ2")

            url = f"{scheme}://{chosen_host}:{chosen_port}{path}"
            ct_header = ""
            if fmt_var.get() == "json":
                ct_header = '-H "Content-Type: application/json" '

            fc = ""
            if match_mode_var.get() == "F" and match_str:
                fc = "-fc 401,403 "
            elif match_mode_var.get() == "S":
                fc = f"-mc 200 "

            cmd = (f"ffuf -u {_shq(url)} -X POST "
                   f"{ct_header}"
                   f"-d {_shq(ffuf_body)} "
                   f"-w {_shq(pass_path)} "
                   f"{fc}-t 40")

            _safe_destroy(win)
            self.app.terminal.section(f"BRUTE FORCE  ·  FFUF (JSON alternative)")
            self.app.terminal.write(f"  $ {cmd}", "cmd")
            if bg_var.get():
                self._run_in_background(tool, cmd, 3600)
            else:
                self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "START HYDRA", _start, primary=True, w=140)
        _btn(row, "FFUF ALTERNATIVE", _start_ffuf, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _show_hydra_smb_139_warning(self, tool, target):
        """Warn the user that hydra SMB can't talk to port 139 alone.

        Target has 139 open but no 445 — hydra's smb module needs raw
        SMB (445), not NetBIOS Session Service.  We explain, offer an
        "OVERRIDE 445 anyway" escape hatch (for hosts where the scan
        might have missed 445), and suggest a better tool path.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        win = _make_win(self, "HYDRA SMB — port mismatch", 620, 440)
        _title(win, "⚠  HYDRA SMB needs port 445")
        _note_box(
            win,
            "Your port scan only found 139 (NetBIOS Session) open on "
            "this target — no 445 (raw SMB).\n\n"
            "Hydra's SMB module ALWAYS speaks raw SMB on 445.  When "
            "you point it at 139 it gets NetBIOS framing it can't "
            "parse and exits with 'invalid reply from target'.",
            COLORS["text_yellow"])
        _note_box(
            win,
            "Recommended:\n"
            "  1. Re-run Port Scanning with -p 445 explicitly.\n"
            "     A missed 445 is common when scan is limited to top-100\n"
            "     or the first scan was filtered.\n"
            "  2. If 445 really is closed, use a NetBIOS-aware tool\n"
            "     instead — nxc (netexec), enum4linux, rpcclient — they\n"
            "     speak both 139 and 445 transparently.\n"
            "  3. OVERRIDE 445 only if you KNOW 445 exists but HAWK\n"
            "     didn't pick it up (rare).",
            COLORS["border_dim"])
        # Show the fallback nxc command the user can try right now.
        _note_box(
            win,
            "Try instead (NetBIOS-aware, reads both 139 and 445):\n"
            "  nxc smb " + target +
            " -u users.txt -p /usr/share/wordlists/rockyou.txt --continue-on-success",
            COLORS["text_cyan"])

        def _override():
            _safe_destroy(win)
            detected_os = ""
            if self.app.session_manager.current:
                detected_os = (self.app.session_manager.current
                               .detected_os or "")
            self._show_hydra_wordlist_dialog(
                tool, target, 445, "smb", detected_os)

        row = _btn_row(win)
        _btn(row, "OVERRIDE — TRY 445 ANYWAY", _override, warn=True, w=260)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _show_hydra_web_wizard(self, tool, target, port, detected_os,
                                mode="form"):
        """Pre-launch diagnostic for hydra web modules.

        Modern webapps break hydra's assumptions in predictable ways
        (dynamic CSRF tokens, JSON APIs, rate limiters, SPA flows).
        Rather than let the user discover this via 10 minutes of
        failed runs, we ask 3 questions that separate the cases hydra
        CAN handle from the ones that need a different tool.

        `mode="basic"` — HYDRA HTTP-GET preflight: just a one-shot
          confirmation that the target actually uses Basic Auth (401 +
          WWW-Authenticate).  If the user says no, we offer to switch
          to HTTP-POST-FORM.

        `mode="form"` — HYDRA HTTP-POST-FORM preflight: 3 questions
          about server behavior, CSRF, and pre-session cookies.  Based
          on answers, routes to either the form dialog (with prefill)
          or the alternatives dialog (hydra not the right tool).
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy,
                                 _selectable_text)

        # ── Branch: Basic Auth (simple preflight) ───────────────────
        if mode == "basic":
            win = _make_win(self, "HYDRA HTTP-GET — preflight", 620, 460)
            _title(win, "Is this really Basic Auth?")
            _note_box(
                win,
                "HTTP-GET brute-force in hydra targets ONLY RFC-7617 "
                "Basic Auth (the browser-native login popup).  Most "
                "modern webapps use HTML login forms instead — running "
                "HTTP-GET against a form login returns 200 for EVERY "
                "password and hydra reports them all as valid.\n\n"
                "Confirm via curl — you should see 401 + "
                "'WWW-Authenticate: Basic realm=...' :",
                COLORS["border_dim"])
            _selectable_text(
                win, f"curl -I http://{target}:{port}/",
                color=COLORS["text_cyan"], height=32)
            _note_box(
                win,
                "If you see a 200 OK or a <html> form, cancel and use "
                "HYDRA HTTP-POST-FORM instead — it handles HTML "
                "logins correctly.",
                COLORS["text_yellow"])

            def _proceed():
                _safe_destroy(win)
                self._show_hydra_wordlist_dialog(
                    tool, target, port, "http-get", detected_os)

            def _switch_to_form():
                _safe_destroy(win)
                # Find the form tool by id and re-enter _route_hydra.
                for card in self.app.kill_chain_panel.cards.values():
                    for t in card.module.get_tools() or []:
                        if t.id == "hydra_http_form":
                            self._route_hydra(t)
                            return
                self.app.terminal.write(
                    "  [!] HYDRA HTTP-POST-FORM not found in any card.",
                    "warn")

            row = _btn_row(win)
            _btn(row, "CONFIRMED — PROCEED", _proceed,
                 primary=True, w=200)
            _btn(row, "SWITCH TO HTTP-POST-FORM", _switch_to_form, w=220)
            _btn(row, "CANCEL", lambda: _safe_destroy(win), w=100)
            return

        # ── Branch: Form auth (3-question wizard) ───────────────────
        win = _make_win(self, "HYDRA HTTP-POST-FORM — preflight",
                        780, 760)
        _title(win, "Modern webapp checklist")
        _sub(win,
             "Answer 3 questions so HAWK can pick the right approach.",
             COLORS["text_dim"])

        _outer = win
        body = ctk.CTkScrollableFrame(
            _outer, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 2))
        win = body

        # Q1 — server response on failed login
        ctk.CTkLabel(
            win, text="1.  On FAILED login, the server returns:",
            font=_f("md", True), text_color=COLORS["text_bright"],
            anchor="w").pack(fill="x", padx=24, pady=(10, 4))
        q1_var = ctk.StringVar(value="html")
        for val, lbl in [
            ("html",    "HTML page with visible error text "
                        "(e.g. 'Invalid credentials')"),
            ("redirect","HTTP 302 redirect to /login?error=..."),
            ("json",    "JSON response like {\"error\": \"...\"}"),
            ("429",     "HTTP 429 Too Many Requests (rate-limited)"),
            ("unknown", "Don't know yet"),
        ]:
            ctk.CTkRadioButton(
                win, text=lbl, variable=q1_var, value=val,
                font=_f("sm"), text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
            ).pack(anchor="w", padx=40, pady=2)

        # Q2 — CSRF token
        ctk.CTkLabel(
            win, text="2.  The login form has a CSRF token:",
            font=_f("md", True), text_color=COLORS["text_bright"],
            anchor="w").pack(fill="x", padx=24, pady=(12, 4))
        q2_var = ctk.StringVar(value="no")
        for val, lbl in [
            ("no",       "No — the form submits user+pass only"),
            ("cookie",   "Yes, but it's in a Set-Cookie header "
                         "(double-submit cookie pattern)"),
            ("hidden",   "Yes, in an <input type=hidden> that "
                         "changes every page load"),
            ("unknown",  "Don't know"),
        ]:
            ctk.CTkRadioButton(
                win, text=lbl, variable=q2_var, value=val,
                font=_f("sm"), text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
            ).pack(anchor="w", padx=40, pady=2)

        # Q3 — pre-session cookie
        ctk.CTkLabel(
            win, text="3.  Opening the login page sets a required "
                     "session cookie:",
            font=_f("md", True), text_color=COLORS["text_bright"],
            anchor="w").pack(fill="x", padx=24, pady=(12, 4))
        q3_var = ctk.StringVar(value="no")
        ctk.CTkRadioButton(
            win, text="No / don't know",
            variable=q3_var, value="no",
            font=_f("sm"), text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(anchor="w", padx=40, pady=2)
        ctk.CTkRadioButton(
            win, text="Yes — I captured one (paste below):",
            variable=q3_var, value="yes",
            font=_f("sm"), text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(anchor="w", padx=40, pady=2)
        cookie_var = ctk.StringVar(value="")
        cookie_entry = ctk.CTkEntry(
            win, textvariable=cookie_var,
            font=_f("sm"), height=28,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3,
            placeholder_text="PHPSESSID=abc123; sessionId=def456")
        cookie_entry.pack(fill="x", padx=60, pady=(0, 6))
        add_context_menu(cookie_entry)

        ctk.CTkLabel(
            win,
            text="Tip: in browser devtools → Application → Cookies, "
                 "or `curl -I` on the login page and copy from "
                 "Set-Cookie.",
            font=_f("xs"), text_color=COLORS["text_dim"],
            anchor="w", wraplength=680, justify="left",
        ).pack(fill="x", padx=60, pady=(0, 8))

        # Back to outer toplevel for the button row.
        win = _outer

        def _proceed():
            q1 = q1_var.get()
            q2 = q2_var.get()
            q3 = q3_var.get()
            cookie = cookie_var.get().strip()

            # ── Decision tree ──────────────────────────────────────
            # Cases where hydra cannot reliably succeed: dynamic HTML
            # CSRF and JSON APIs.  Route to alternatives.
            if q2 == "hidden":
                _safe_destroy(win)
                self._show_hydra_alternatives_dialog(
                    tool, target, port,
                    reason="csrf-html",
                    context={"csrf_field": "csrf_token",
                             "cookie": cookie})
                return
            if q1 == "json":
                prefill = {"format": "json", "cookie": cookie}
                _safe_destroy(win)
                self._show_hydra_form_dialog(
                    tool, target, port, detected_os, prefill=prefill)
                return
            if q1 == "429":
                _safe_destroy(win)
                self._show_hydra_alternatives_dialog(
                    tool, target, port,
                    reason="rate-limit",
                    context={"cookie": cookie})
                return

            # Cases hydra can handle: compose prefill with cookie/CSRF
            # helper and proceed to the form dialog.
            prefill = {}
            if q3 == "yes" and cookie:
                prefill["cookie"] = cookie
            if q2 == "cookie" and not cookie:
                # User said CSRF is cookie-based but didn't paste it —
                # warn so they know they probably need to.
                prefill["cookie_warning"] = (
                    "You selected 'CSRF in cookie' but didn't paste a "
                    "cookie.  Hydra needs it — capture via devtools "
                    "and re-open this dialog.")
            # Suggested condition hint based on answer 1.
            if q1 == "redirect":
                prefill["match_mode"] = "F"
                prefill["match_string"] = "/login"  # typical redirect
            _safe_destroy(win)
            self._show_hydra_form_dialog(
                tool, target, port, detected_os, prefill=prefill)

        row = _btn_row(win)
        _btn(row, "PROCEED", _proceed, primary=True, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _show_hydra_alternatives_dialog(self, tool, target, port,
                                         reason, context=None):
        """Guidance dialog shown when the web wizard detected a case
        hydra can't handle (dynamic CSRF, JSON API, aggressive rate
        limit).  Shows the REASON, a short explanation, and 3-4
        selectable command templates for alternative tools that WILL
        work (ffuf, patator, Python + requests, sqlmap for login
        pages).

        Every command block is a `_selectable_text` so the user can
        double-click → copy → paste into a shell.  An OPEN SHELL
        button at the bottom opens an xterm in <HAWK>/outputs/ where
        those commands can be run.

        `reason`:
          - "csrf-html"   — CSRF token in <input type=hidden>
          - "json-api"    — server speaks JSON
          - "rate-limit"  — 429 on first try
        `context`:   optional dict with {cookie, csrf_field, ...}
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy,
                                 _selectable_text)
        ctx = context or {}

        REASONS = {
            "csrf-html": {
                "title": "Dynamic CSRF token — hydra cannot handle",
                "why":
                    "Hydra has no built-in way to pre-fetch a login "
                    "page, parse the HTML to extract a fresh CSRF "
                    "token, then inject it into the POST body — all "
                    "before every attempt.  Each brute-force hit needs "
                    "that pipeline.  The alternatives below do it for "
                    "you.",
            },
            "json-api": {
                "title": "JSON API login — hydra's body parser can't",
                "why":
                    "hydra http-*-form submits application/"
                    "x-www-form-urlencoded.  Modern SPAs POST JSON "
                    "({\"user\":\"x\",\"pass\":\"y\"}) and expect an "
                    "Accept: application/json response.  Hydra won't "
                    "encode your body as JSON or set the Content-Type.",
            },
            "rate-limit": {
                "title": "Rate-limited target — hydra will lock you out",
                "why":
                    "The app returned 429 Too Many Requests on a "
                    "single probe.  Running hydra with default "
                    "threads (16) against a rate-limited endpoint "
                    "either gets your IP blocked, fills the honeypot "
                    "queue, or burns through the window without "
                    "testing real passwords.",
            },
        }
        info = REASONS.get(reason, {
            "title": "Hydra can't reliably handle this login",
            "why": "Alternatives below.",
        })

        win = _make_win(self,
                        f"Hydra — switch to alternative tool",
                        820, 800)
        _title(win, f"⚠  {info['title']}")
        _sub(win, f"Target: {target}:{port}", COLORS["text_dim"])

        _outer = win
        body = ctk.CTkScrollableFrame(
            _outer, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 2))
        win = body

        _note_box(win, info["why"], COLORS["text_yellow"])

        cookie_hdr = ""
        if ctx.get("cookie"):
            cookie_hdr = f"-b '{ctx['cookie']}'"

        # ── Alternative 1: ffuf with prefetch for CSRF or JSON ──────
        if reason in ("csrf-html", "json-api"):
            ctk.CTkLabel(
                win, text="  ➊  ffuf — flexible fuzzer",
                font=_f("md", True), text_color=COLORS["text_green"],
                anchor="w").pack(fill="x", padx=24, pady=(10, 2))
            if reason == "csrf-html":
                ffuf_explain = (
                    "ffuf doesn't pre-fetch CSRF on its own, but a "
                    "small shell wrapper fetches the login page, "
                    "extracts the token with grep/sed, then feeds it "
                    "into ffuf's body via -d.  Below is a one-liner "
                    "template: replace <CSRF_FIELD> and <FAIL_REGEX>.")
                _note_box(win, ffuf_explain, COLORS["border_dim"])
                _selectable_text(
                    win,
                    f"for user in $(cat users.txt); do\n"
                    f"  for pass in $(cat passes.txt); do\n"
                    f"    TOKEN=$(curl -s http://{target}:{port}/login "
                    f"-c /tmp/cjar | grep -oP "
                    f"'name=\"csrf_token\" value=\"\\K[^\"]+')\n"
                    f"    curl -s -b /tmp/cjar http://{target}:{port}"
                    f"/login \\\n"
                    f"      -d \"user=$user&pass=$pass"
                    f"&csrf_token=$TOKEN\" \\\n"
                    f"      -o /tmp/resp\n"
                    f"    grep -q 'Invalid' /tmp/resp || "
                    f"echo \"HIT  $user:$pass\"\n"
                    f"  done\n"
                    f"done",
                    color=COLORS["text_bright"], height=180)
            else:  # json-api
                _note_box(
                    win,
                    "ffuf with -H 'Content-Type: application/json' "
                    "and a JSON body template.  Adjust the key names "
                    "(username/password → email/pwd) to match your "
                    "API.",
                    COLORS["border_dim"])
                _selectable_text(
                    win,
                    f"ffuf -w users.txt:USER -w passes.txt:PASS "
                    f"\\\n  -u http://{target}:{port}/api/login "
                    f"\\\n  -X POST "
                    f"-H 'Content-Type: application/json' "
                    f"{cookie_hdr} \\\n"
                    f"  -d '{{\"username\":\"USER\","
                    f"\"password\":\"PASS\"}}' "
                    f"\\\n  -mc 200 -fr 'invalid'",
                    color=COLORS["text_bright"], height=110)

        # ── Alternative 2: patator — purpose-built credential brute ─
        ctk.CTkLabel(
            win, text="  ➋  patator — brute-force framework",
            font=_f("md", True), text_color=COLORS["text_green"],
            anchor="w").pack(fill="x", padx=24, pady=(10, 2))
        _note_box(
            win,
            "patator's http_fuzz module has first-class support for "
            "cookies, regex-extracted CSRF, and arbitrary headers.  "
            "Slower than ffuf but more accurate on finicky logins.",
            COLORS["border_dim"])
        if reason == "csrf-html":
            _selectable_text(
                win,
                f"patator http_fuzz url=http://{target}:{port}/login "
                f"\\\n  method=POST "
                f"body='user=FILE0&pass=FILE1&csrf_token=TOKEN' "
                f"\\\n  0=users.txt 1=passes.txt "
                f"\\\n  before_urls=http://{target}:{port}/login "
                f"\\\n  before_egrep='TOKEN:"
                f"name=\"csrf_token\" value=\"([^\"]+)\"' "
                f"\\\n  -x ignore:fgrep='Invalid'",
                color=COLORS["text_bright"], height=110)
        elif reason == "json-api":
            _selectable_text(
                win,
                f"patator http_fuzz url=http://{target}:{port}"
                f"/api/login "
                f"\\\n  method=POST "
                f"header='Content-Type: application/json' "
                f"\\\n  body='{{\"username\":\"FILE0\","
                f"\"password\":\"FILE1\"}}' "
                f"\\\n  0=users.txt 1=passes.txt "
                f"\\\n  -x ignore:code=401",
                color=COLORS["text_bright"], height=100)
        else:  # rate-limit
            _selectable_text(
                win,
                f"# patator with rate limit — 1 req/sec, "
                f"back off on 429.\n"
                f"patator http_fuzz url=http://{target}:{port}/login "
                f"\\\n  method=POST body='user=FILE0&pass=FILE1' "
                f"\\\n  0=users.txt 1=passes.txt "
                f"\\\n  -x retry:code=429 --rate-limit 1",
                color=COLORS["text_bright"], height=90)

        # ── Alternative 3: Python requests skeleton ─────────────────
        ctk.CTkLabel(
            win, text="  ➌  Python + requests — full control",
            font=_f("md", True), text_color=COLORS["text_green"],
            anchor="w").pack(fill="x", padx=24, pady=(10, 2))
        _note_box(
            win,
            "When nothing above fits: a 20-line Python script with "
            "requests.Session() handles any flow — cookies, CSRF, "
            "JSON, multi-step redirects, whatever.  Save as "
            "brute.py, run with python3 brute.py.",
            COLORS["border_dim"])
        if reason == "csrf-html":
            _selectable_text(
                win,
                "import re, requests\n"
                f"URL = 'http://{target}:{port}/login'\n"
                "users = open('users.txt').read().split()\n"
                "passes = open('passes.txt').read().split()\n"
                "for u in users:\n"
                "  for p in passes:\n"
                "    s = requests.Session()\n"
                "    r = s.get(URL)\n"
                "    tok = re.search(\n"
                "      r'name=\"csrf_token\" value=\"([^\"]+)\"',\n"
                "      r.text).group(1)\n"
                "    r = s.post(URL, data={\n"
                "      'user': u, 'pass': p, 'csrf_token': tok})\n"
                "    if 'Invalid' not in r.text:\n"
                "      print(f'HIT {u}:{p}'); exit()\n",
                color=COLORS["text_bright"], height=200)
        else:
            _selectable_text(
                win,
                "import requests\n"
                f"URL = 'http://{target}:{port}/api/login'\n"
                "users = open('users.txt').read().split()\n"
                "passes = open('passes.txt').read().split()\n"
                "for u in users:\n"
                "  for p in passes:\n"
                "    r = requests.post(URL,\n"
                "      json={'username': u, 'password': p})\n"
                "    if r.status_code == 200:\n"
                "      print(f'HIT {u}:{p}'); exit()\n",
                color=COLORS["text_bright"], height=140)

        # ── Rate-limit-specific hint ────────────────────────────────
        if reason == "rate-limit":
            ctk.CTkLabel(
                win, text="  ➍  Slow-and-low hydra (if you insist)",
                font=_f("md", True), text_color=COLORS["text_yellow"],
                anchor="w").pack(fill="x", padx=24, pady=(10, 2))
            _note_box(
                win,
                "If the rate limit is permissive enough, hydra still "
                "works with -t 1 -w 30 (one attempt every 30s).  "
                "Realistic for small custom wordlists (< 100).",
                COLORS["border_dim"])
            _selectable_text(
                win,
                f"hydra -L users.txt -P passes.txt -t 1 -w 30 "
                f"\\\n  {target} -s {port} http-post-form "
                f"\\\n  '/login:user=^USER^&pass=^PASS^:F=Invalid' -V",
                color=COLORS["text_bright"], height=90)

        # Back to outer for button row.
        win = _outer

        def _open_shell():
            """Open xterm in <HAWK>/outputs/ so the user can paste
            commands and any artefacts they generate land alongside
            the rest of the HAWK-produced data (ntds dumps, ldap
            dumps, certipy pfx, etc).

            `open_native_shell` has no cwd arg, so we chain a `cd`
            and a short banner into `initial_cmd` before dropping
            the user to bash (auto_close=False).  `mkdir -p` makes
            the dir exist on first run."""
            try:
                from utils.runner import open_native_shell
                from utils.config import OUTPUTS_DIR as _OUTDIR
                init = (
                    f"mkdir -p {_OUTDIR!r} && cd {_OUTDIR!r} && "
                    f"printf '\\e[36m[HAWK] alt-tools shell "
                    f"({_OUTDIR}) — paste a command from the "
                    f"dialog above.\\e[0m\\n'"
                )
                open_native_shell(
                    title="HAWK — alt-tools shell",
                    initial_cmd=init,
                    auto_close=False)
            except Exception as e:
                self.app.terminal.write(
                    f"  [!] Could not open shell: {e}", "error")

        row = _btn_row(win)
        _btn(row, "OPEN SHELL (<HAWK>/outputs)", _open_shell,
             primary=True, w=240)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=120)

    def _show_wordlist_picker(self, tool, wordlist_options: list,
                              title: str, subtitle: str,
                              callback, *,
                              show_extensions: bool = False,
                              show_threads: bool = True,
                              default_threads: str = "20",
                              extra_widgets_fn=None,
                              show_base_path: bool = False,
                              default_base_path: str = "/"):
        """Reusable wordlist picker dialog.

        *wordlist_options*: list of (label, path) tuples — first one is default.
        *callback*: called with (wordlist_path, extensions_str, threads_str,
                    extra_data) when user hits RUN.
        *extra_widgets_fn*: optional callable(win) → dict to add custom widgets
                            and return their data for callback. The returned dict
                            is passed to callback as extra_data.
        """
        from gui.dialogs import (_make_win, _title as _dtitle, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        import tkinter.filedialog as fd

        detected_os = ""
        try:
            sess = self.app.session_manager.current
            if sess:
                detected_os = sess.detected_os or ""
        except Exception:
            pass

        win = _make_win(self, tool.name, 640, 560)
        _dtitle(win, title)
        _sub(win, subtitle)

        if detected_os:
            _note_box(win, f"★ OS fingerprint: {detected_os.upper()} — "
                      "wordlist suggestion adapted",
                      COLORS["text_green"])

        # Base path (optional — for web directory brute-force tools)
        base_path_var = ctk.StringVar(value=default_base_path or "/")
        if show_base_path:
            bpf = ctk.CTkFrame(win, fg_color="transparent")
            bpf.pack(fill="x", padx=24, pady=(4, 2))
            ctk.CTkLabel(bpf, text="Base path:", font=_f("sm"),
                         text_color=COLORS["text_muted"],
                         anchor="w").pack(side="left")
            bp_entry = ctk.CTkEntry(
                bpf, textvariable=base_path_var,
                placeholder_text="/",
                font=_f("md"), height=30, width=200,
                fg_color=COLORS["bg_card"],
                text_color=COLORS["text_bright"],
                border_color=COLORS["border_dim"], border_width=1,
                corner_radius=3)
            bp_entry.pack(side="left", padx=(4, 0))
            add_context_menu(bp_entry)
            ctk.CTkLabel(bpf, text="+ FUZZ", font=_f("sm", True),
                         text_color=COLORS["text_green"],
                         anchor="w").pack(side="left", padx=(2, 0))

        # Wordlist radio buttons
        wl_var = ctk.StringVar(
            value=wordlist_options[0][1] if wordlist_options else "")
        lf = ctk.CTkFrame(win, fg_color="transparent")
        lf.pack(fill="x", padx=24, pady=(6, 2))
        ctk.CTkLabel(lf, text="Wordlist:", font=_f("md", True),
                     text_color=COLORS["text_bright"], anchor="w").pack(anchor="w")

        scroll = ctk.CTkScrollableFrame(win, height=120,
                                         fg_color=COLORS["bg_card"],
                                         border_color=COLORS["border_dim"],
                                         border_width=1, corner_radius=3)
        scroll.pack(fill="x", padx=24, pady=(0, 4))
        for lbl, path in wordlist_options[:12]:
            rb = ctk.CTkRadioButton(
                scroll, text=f"{lbl}",
                variable=wl_var, value=path,
                font=_f("sm"), text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"])
            rb.pack(anchor="w", padx=10, pady=1)

        # Custom wordlist override
        custom_var = ctk.StringVar(value="")
        cf = ctk.CTkFrame(win, fg_color="transparent")
        cf.pack(fill="x", padx=24, pady=(4, 2))
        ctk.CTkLabel(cf, text="Custom path:", font=_f("sm"),
                     text_color=COLORS["text_muted"],
                     anchor="w").pack(side="left")
        custom_entry = ctk.CTkEntry(
            cf, textvariable=custom_var,
            placeholder_text="/path/to/custom.txt",
            font=_f("md"), height=30,
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3)
        custom_entry.pack(side="left", fill="x", expand=True, padx=(4, 4))
        add_context_menu(custom_entry)

        def _browse():
            p = fd.askopenfilename(title="Select wordlist",
                                   filetypes=[("Text", "*.txt"), ("All", "*")])
            if p:
                custom_var.set(p)
        ctk.CTkButton(cf, text="📂", width=32, height=30,
                      font=_f("sm"), fg_color=COLORS["bg_card"],
                      hover_color=COLORS["bg_card_hover"],
                      border_color=COLORS["border_dim"], border_width=1,
                      text_color=COLORS["text_dim"], corner_radius=3,
                      command=_browse).pack(side="left")

        # Extensions (optional, for dir brute-force)
        ext_var = ctk.StringVar(value="")
        if show_extensions:
            # Smart extension default based on detected OS.
            # NOTE: gobuster prepends `.` to each extension automatically,
            # so `-x .aspx` produces `word..aspx` (double-dot) which the
            # server rejects as 400.  We pass extensions WITHOUT the
            # leading dot (ffuf's `-e` expects them WITH the dot and we
            # handle that separately when building the ffuf command).
            os_lower = (detected_os or "").lower()
            if "windows" in os_lower:
                # IIS / ASP.NET stack
                default_ext = "asp,aspx,config,bak"
            elif any(k in os_lower for k in ("linux", "unix", "bsd",
                                             "ubuntu", "debian",
                                             "centos", "redhat",
                                             "apache")):
                # Apache / nginx / PHP stack — most common Linux web.
                default_ext = "php,html,txt,bak"
            else:
                # OS unknown — try a generic mix so something useful
                # turns up on either platform.
                default_ext = "php,html,asp,aspx,txt,bak"
            ef = ctk.CTkFrame(win, fg_color="transparent")
            ef.pack(fill="x", padx=24, pady=(4, 2))
            ctk.CTkLabel(ef, text="Extensions:", font=_f("sm"),
                         text_color=COLORS["text_muted"],
                         anchor="w").pack(side="left")
            ext_entry = ctk.CTkEntry(
                ef, textvariable=ext_var,
                placeholder_text="php,asp,aspx,html,bak,txt",
                font=_f("md"), height=30,
                fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                border_color=COLORS["border_dim"], border_width=1,
                corner_radius=3)
            ext_entry.pack(side="left", fill="x", expand=True, padx=(4, 0))
            add_context_menu(ext_entry)
            if default_ext:
                ext_var.set(default_ext)

        # Threads
        threads_var = ctk.StringVar(value=default_threads)
        if show_threads:
            tf = ctk.CTkFrame(win, fg_color="transparent")
            tf.pack(fill="x", padx=24, pady=(4, 2))
            ctk.CTkLabel(tf, text="Threads:", font=_f("sm"),
                         text_color=COLORS["text_muted"],
                         anchor="w").pack(side="left")
            t_entry = ctk.CTkEntry(
                tf, textvariable=threads_var, width=60, height=30,
                font=_f("md"),
                fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                border_color=COLORS["border_dim"], border_width=1,
                corner_radius=3)
            t_entry.pack(side="left", padx=(4, 0))
            add_context_menu(t_entry)

        # Extra custom widgets (if provided)
        extra_data = {}
        if extra_widgets_fn:
            extra_data = extra_widgets_fn(win) or {}
        if show_base_path:
            extra_data["base_path_var"] = base_path_var

        def _run():
            wl = custom_var.get().strip() or wl_var.get()
            if not wl:
                self.app.terminal.write(
                    f"[!] {tool.name} cancelled — no wordlist selected.",
                    "warn")
                _safe_destroy(win)
                return
            ext = ext_var.get().strip()
            # Strip any stray leading `.` the user may have typed —
            # gobuster/ffuf add the dot themselves, so `.aspx` becomes
            # `..aspx` and produces malformed URLs that return 400.
            if ext:
                ext = ",".join(
                    e.strip().lstrip(".") for e in ext.split(",")
                    if e.strip().lstrip("."))
            threads = threads_var.get().strip() or default_threads
            _safe_destroy(win)
            callback(wl, ext, threads, extra_data)

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

