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

class CardWebRoutesMixin:
    def _route_certipy(self, tool):
        """Interactive Certipy launcher.

        Certipy v5+ refuses empty usernames (unlike older AD enumeration
        tools), so the previous hardcoded `-u '' -p ''` template always
        crashed with 'Username is not specified'. This dialog:
          • pulls creds from the Credential Store (pre-filled)
          • supports cleartext, NTLM hash, or Kerberos ticket
          • asks for the AD realm/domain (required)
          • builds the command with proper quoting
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                  _btn_row, _btn, _safe_destroy)

        target = self._get_target()
        if not target:
            return

        # Default realm: try session target_domain, else ""
        default_realm = ""
        try:
            sess = self.app.session_manager.current
            if sess and getattr(sess, "target_domain", ""):
                default_realm = sess.target_domain
        except Exception:
            pass

        # Gather creds from store
        creds_available = []
        try:
            if self.app.session_manager.current:
                creds_available = (self.app.session_manager.current
                                       .get_credentials())
        except Exception:
            creds_available = []

        cred_options = ["<manual entry>"]
        cred_map = {}
        for c in creds_available:
            if not c.username:
                continue
            if c.cred_type == "cleartext" and c.password:
                label = f"{c.username} : {c.password}  (cleartext)"
            elif c.cred_type == "hash" and c.hash_val:
                short = c.hash_val if len(c.hash_val) < 40 else \
                    c.hash_val[-32:]
                label = f"{c.username} : {short}  (NTLM hash)"
            else:
                label = f"{c.username}  ({c.cred_type})"
            cred_options.append(label)
            cred_map[label] = c

        win = _make_win(self, "Certipy — AD CS Attack", 700, 680)
        _title(win, "CERTIPY  —  AD Certificate Services")
        _sub(win, "Certipy v5+ needs valid domain credentials "
                  "(or a Kerberos ticket).")

        # Subcommand
        sub_frame = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                  border_color=COLORS["border_dim"],
                                  border_width=1, corner_radius=4)
        sub_frame.pack(fill="x", padx=24, pady=(6, 4))
        ctk.CTkLabel(sub_frame, text="SUBCOMMAND",
                     font=_f("sm", True),
                     text_color=COLORS["text_green"]
                     ).pack(anchor="w", padx=10, pady=(6, 2))
        cmd_var = ctk.StringVar(value="find_vuln")
        for val, lbl, desc in [
            ("find_vuln", "find (vulnerable only)",
             "Look for ESC1-ESC11 vulnerable cert templates — the typical "
             "first move. --vulnerable filters the output."),
            ("find_all",  "find (all templates)",
             "Enumerate every cert template, vuln or not. Noisy."),
            ("find_text", "find + -text",
             "Same as find but output raw text blobs (good for grep)."),
        ]:
            row_s = ctk.CTkFrame(sub_frame, fg_color="transparent")
            row_s.pack(fill="x", padx=10, pady=1)
            ctk.CTkRadioButton(
                row_s, text=lbl, variable=cmd_var, value=val,
                font=_f("sm", True), width=230,
                text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                hover_color=COLORS["bg_card_hover"],
            ).pack(side="left")
            ctk.CTkLabel(row_s, text=desc, font=_f("xs"),
                         text_color=COLORS["text_dim"],
                         anchor="w", justify="left", wraplength=400
                         ).pack(side="left", padx=6)
        ctk.CTkFrame(sub_frame, fg_color="transparent", height=4).pack()

        # Credential picker
        cred_frame = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                   border_color=COLORS["border_dim"],
                                   border_width=1, corner_radius=4)
        cred_frame.pack(fill="x", padx=24, pady=(4, 4))
        ctk.CTkLabel(cred_frame, text="AUTHENTICATION",
                     font=_f("sm", True),
                     text_color=COLORS["text_green"]
                     ).pack(anchor="w", padx=10, pady=(6, 2))

        cred_var = ctk.StringVar(value=cred_options[0])
        ctk.CTkOptionMenu(
            cred_frame, values=cred_options, variable=cred_var,
            width=500, height=28, font=_f("sm"),
            fg_color=COLORS["bg_secondary"],
            button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_bright"],
            corner_radius=3,
        ).pack(anchor="w", padx=10, pady=2)

        # Manual entry (used only if <manual entry> is selected OR to tweak)
        user_var  = ctk.StringVar(value="")
        pass_var  = ctk.StringVar(value="")
        hash_var  = ctk.StringVar(value="")
        use_kerb  = ctk.BooleanVar(value=False)
        scheme_ldap_var = ctk.BooleanVar(value=False)

        def _on_cred_change(*_):
            sel = cred_var.get()
            if sel == "<manual entry>":
                return
            c = cred_map.get(sel)
            if not c:
                return
            user_var.set(c.username or "")
            if c.cred_type == "cleartext":
                pass_var.set(c.password or "")
                hash_var.set("")
            elif c.cred_type == "hash":
                pass_var.set("")
                hash_var.set(c.hash_val or "")
        cred_var.trace_add("write", _on_cred_change)

        # User
        uf = ctk.CTkFrame(cred_frame, fg_color="transparent")
        uf.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(uf, text="Username:", font=_f("sm"),
                     text_color=COLORS["text_dim"], width=90, anchor="w"
                     ).pack(side="left")
        u_entry = ctk.CTkEntry(uf, textvariable=user_var,
                                font=_f("sm"), height=26,
                                fg_color=COLORS["bg_secondary"],
                                text_color=COLORS["text_bright"],
                                border_color=COLORS["border_dim"],
                                border_width=1, corner_radius=3,
                                placeholder_text="e.g. bob.smith")
        u_entry.pack(side="left", fill="x", expand=True)
        add_context_menu(u_entry)

        # Password
        pf = ctk.CTkFrame(cred_frame, fg_color="transparent")
        pf.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(pf, text="Password:", font=_f("sm"),
                     text_color=COLORS["text_dim"], width=90, anchor="w"
                     ).pack(side="left")
        p_entry = ctk.CTkEntry(pf, textvariable=pass_var,
                                font=_f("sm"), height=26,
                                fg_color=COLORS["bg_secondary"],
                                text_color=COLORS["text_bright"],
                                border_color=COLORS["border_dim"],
                                border_width=1, corner_radius=3,
                                placeholder_text="cleartext password")
        p_entry.pack(side="left", fill="x", expand=True)
        add_context_menu(p_entry)

        # NTLM hash alternative
        hf = ctk.CTkFrame(cred_frame, fg_color="transparent")
        hf.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(hf, text="NTLM hash:", font=_f("sm"),
                     text_color=COLORS["text_dim"], width=90, anchor="w"
                     ).pack(side="left")
        h_entry = ctk.CTkEntry(hf, textvariable=hash_var,
                                font=_f("xs"), height=26,
                                fg_color=COLORS["bg_secondary"],
                                text_color=COLORS["text_bright"],
                                border_color=COLORS["border_dim"],
                                border_width=1, corner_radius=3,
                                placeholder_text="aad3b435b51404ee..."
                                                 ":e19ccf75ee54e06b...")
        h_entry.pack(side="left", fill="x", expand=True)
        add_context_menu(h_entry)

        # Kerberos ticket
        kf = ctk.CTkFrame(cred_frame, fg_color="transparent")
        kf.pack(fill="x", padx=10, pady=(2, 6))
        ctk.CTkCheckBox(
            kf, text="use Kerberos (-k, needs $KRB5CCNAME set)",
            variable=use_kerb, font=_f("xs"),
            text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            hover_color=COLORS["bg_card_hover"],
        ).pack(side="left", padx=(0, 4))

        # Realm / Domain
        dom_frame = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                  border_color=COLORS["border_dim"],
                                  border_width=1, corner_radius=4)
        dom_frame.pack(fill="x", padx=24, pady=(4, 4))
        ctk.CTkLabel(dom_frame, text="DOMAIN",
                     font=_f("sm", True),
                     text_color=COLORS["text_green"]
                     ).pack(anchor="w", padx=10, pady=(6, 2))

        realm_var = ctk.StringVar(value=default_realm)
        rf = ctk.CTkFrame(dom_frame, fg_color="transparent")
        rf.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(rf, text="Realm:", font=_f("sm"),
                     text_color=COLORS["text_dim"], width=90, anchor="w"
                     ).pack(side="left")
        r_entry = ctk.CTkEntry(rf, textvariable=realm_var,
                                font=_f("sm"), height=26,
                                fg_color=COLORS["bg_secondary"],
                                text_color=COLORS["text_bright"],
                                border_color=COLORS["border_dim"],
                                border_width=1, corner_radius=3,
                                placeholder_text="e.g. corp.htb")
        r_entry.pack(side="left", fill="x", expand=True)
        add_context_menu(r_entry)

        dc_var = ctk.StringVar(value=target)
        df = ctk.CTkFrame(dom_frame, fg_color="transparent")
        df.pack(fill="x", padx=10, pady=(2, 4))
        ctk.CTkLabel(df, text="DC IP:", font=_f("sm"),
                     text_color=COLORS["text_dim"], width=90, anchor="w"
                     ).pack(side="left")
        d_entry = ctk.CTkEntry(df, textvariable=dc_var,
                                font=_f("sm"), height=26,
                                fg_color=COLORS["bg_secondary"],
                                text_color=COLORS["text_bright"],
                                border_color=COLORS["border_dim"],
                                border_width=1, corner_radius=3)
        d_entry.pack(side="left", fill="x", expand=True)
        add_context_menu(d_entry)

        # Force plain LDAP — bypass LDAPS when TLS handshake breaks
        lf = ctk.CTkFrame(dom_frame, fg_color="transparent")
        lf.pack(fill="x", padx=10, pady=(2, 6))
        ctk.CTkCheckBox(
            lf, text="Force plain LDAP (-scheme ldap)",
            variable=scheme_ldap_var, font=_f("sm", True),
            text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            hover_color=COLORS["bg_card_hover"],
        ).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(
            lf,
            text="bypass LDAPS — use when TLS fails with "
                 "'Connection reset by peer'",
            font=_f("xs"),
            text_color=COLORS["text_dim"],
            anchor="w", justify="left", wraplength=360
        ).pack(side="left")

        # Extra args
        extra_var = ctk.StringVar(value="")
        ctk.CTkLabel(win, text="Extra args (optional):",
                     font=_f("xs"),
                     text_color=COLORS["text_dim"]
                     ).pack(anchor="w", padx=26, pady=(6, 0))
        e_entry = ctk.CTkEntry(win, textvariable=extra_var,
                                font=_f("sm"), height=28,
                                fg_color=COLORS["bg_card"],
                                text_color=COLORS["text_bright"],
                                border_color=COLORS["border_dim"],
                                border_width=1, corner_radius=3,
                                placeholder_text="e.g. -dns-tcp  -timeout 30")
        e_entry.pack(fill="x", padx=24, pady=(2, 6))
        add_context_menu(e_entry)

        # No-creds warning
        if not creds_available:
            _note_box(win,
                      "⚠  No credentials in Credential Store.\n"
                      "Certipy needs a valid AD user. Run kerbrute or\n"
                      "impacket-GetNPUsers first to get a user, then come back.",
                      COLORS["text_yellow"])

        # Preview
        warn_lbl = ctk.CTkLabel(win, text="", font=_f("xs"),
                                 text_color=COLORS["text_yellow"],
                                 wraplength=620, justify="left")
        warn_lbl.pack(anchor="w", padx=26, pady=(0, 2))

        ctk.CTkLabel(win, text="Command preview:",
                     font=_f("xs"),
                     text_color=COLORS["text_dim"]
                     ).pack(anchor="w", padx=26, pady=(4, 0))
        preview_lbl = ctk.CTkLabel(
            win, text="", font=_f("sm"),
            text_color=COLORS["text_green"],
            wraplength=620, justify="left", anchor="w")
        preview_lbl.pack(anchor="w", fill="x", padx=26, pady=(0, 6))

        def _build():
            sub = cmd_var.get()
            user = user_var.get().strip()
            pwd  = pass_var.get()
            hsh  = hash_var.get().strip()
            kerb = use_kerb.get()
            realm = realm_var.get().strip()
            dc_ip = dc_var.get().strip() or target

            if not kerb and not user:
                return None, ("Certipy needs -u <user>. Pick a cred from the "
                               "dropdown, type one, or enable Kerberos.")
            if not kerb and not pwd and not hsh:
                return None, ("Supply either a password or an NTLM hash "
                               "(or tick Kerberos).")
            if not realm and not kerb:
                return None, ("Realm is required. Typical HTB/THM realms "
                               "are like 'corp.htb' or 'company.local'.")

            parts = ["certipy"]
            # Subcommand
            if sub == "find_vuln":
                parts += ["find", "-vulnerable", "-stdout"]
            elif sub == "find_text":
                parts += ["find", "-text", "-stdout"]
            else:
                parts += ["find", "-stdout"]

            # Auth
            if kerb:
                parts += ["-k", "-no-pass"]
                if user:
                    parts += ["-u", _shq(f"{user}@{realm}" if realm else user)]
            else:
                parts += ["-u", _shq(f"{user}@{realm}")]
                if hsh:
                    parts += ["-hashes", _shq(hsh)]
                else:
                    parts += ["-p", _shq(pwd)]

            parts += ["-dc-ip", _shq(dc_ip)]

            if scheme_ldap_var.get():
                parts += ["-scheme", "ldap"]

            extra = extra_var.get().strip()
            if extra:
                parts.append(extra)
            return " ".join(parts), ""

        def _preview(*_):
            cmd, warn = _build()
            warn_lbl.configure(text=warn or "")
            if cmd:
                preview_lbl.configure(text=f"$ {cmd}",
                                       text_color=COLORS["text_green"])
            else:
                preview_lbl.configure(text="(incomplete)",
                                       text_color=COLORS["text_dim"])

        for v in (cmd_var, user_var, pass_var, hash_var, use_kerb,
                  realm_var, dc_var, extra_var, scheme_ldap_var):
            v.trace_add("write", _preview)
        _preview()

        def _run():
            cmd, warn = _build()
            if warn or not cmd:
                warn_lbl.configure(text=warn or "incomplete")
                return
            _safe_destroy(win)
            self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "RUN CERTIPY", _run, primary=True, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _route_web_tool(self, tool):
        target = self._get_target()
        if not target:
            return

        if tool.id == "gobuster_dns":
            self._route_gobuster_dns(tool)
            return

        if tool.id == "sqlmap":
            self._route_sqlmap(tool)
            return

        fp = self._get_fp()
        if fp is None:
            self.app.terminal.write(
                f"[!] {tool.name} skipped — no port scan data available.\n"
                f"    Run Port Scanning first.", "warn")
            return

        NON_WEB_HTTP_PORTS = {135, 593, 5985, 5986}

        def _is_http_service(svc_str, banner_str, p):
            if p in NON_WEB_HTTP_PORTS:
                return False
            token = (svc_str + " " + (banner_str or "")).lower()
            if any(b in token for b in WINRM_BANNERS):
                return False
            return any(t == svc_str.lower().split("/")[0] or t in token
                       for t in TRUE_HTTP_SERVICES)

        all_ports = []
        default_port = None
        for p, _pr, svc, bann in fp.open_ports:
            is_http = _is_http_service(svc, bann, p)
            svc_label = svc or "unknown"
            if bann:
                svc_label += f" ({bann[:40]})"
            tag = " ✓ HTTP" if is_http else ""
            label = f"{p}  —  {svc_label}{tag}"
            all_ports.append((p, label, svc, bann, is_http))
            if is_http and default_port is None:
                default_port = p

        if not all_ports:
            self.app.terminal.write(
                f"[!] {tool.name} skipped — no open ports found.", "warn")
            return

        self._show_web_port_picker(tool, target, all_ports, default_port, fp)

    def _show_web_port_picker(self, tool, target, all_ports, default_port, fp):
        from gui.dialogs import (_make_win, _title, _sub,
                                  _btn_row, _btn, _safe_destroy)

        # ── Collect available hostnames (domain + vhost entries) ────
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
        has_hostnames = bool(domain.strip()) or bool(vhost_hosts)

        dlg_h = 320 if has_hostnames else 260
        win = _make_win(self, f"{tool.name} — Port Selection", 560, dlg_h)
        _title(win, f"{tool.name.upper()}  —  Target Port")
        _sub(win, f"Target: {target}", COLORS["text_dim"])

        # ── Port selector ──────────────────────────────────────────
        port_labels = [item[1] for item in all_ports]
        port_map = {item[1]: item for item in all_ports}

        default_label = port_labels[0]
        if default_port is not None:
            for item in all_ports:
                if item[0] == default_port:
                    default_label = item[1]
                    break

        ctk.CTkLabel(win, text="Port:",
                     font=_f("md", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=14, pady=(10, 2))
        port_var = ctk.StringVar(value=default_label)

        warn_lbl = ctk.CTkLabel(
            win, text="", font=_f("sm"),
            text_color=COLORS["text_yellow"], anchor="w")
        warn_lbl.pack(fill="x", padx=14, pady=(0, 2))

        def _on_port_change(*_a):
            sel = port_var.get()
            entry = port_map.get(sel)
            if entry and not entry[4]:
                warn_lbl.configure(
                    text="⚠  This port does not appear to run an "
                         "HTTP/HTTPS service — results may be unreliable.")
            else:
                warn_lbl.configure(text="")

        port_var.trace_add("write", _on_port_change)
        ctk.CTkOptionMenu(
            win, values=port_labels, variable=port_var,
            width=520, height=30, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_bright"], corner_radius=3,
            command=lambda _v: _on_port_change(),
        ).pack(fill="x", padx=14, pady=(0, 6))

        _on_port_change()

        # ── Target host selector (domain preferred, IP fallback) ──
        # When a domain is known we surface it FIRST so it's the
        # default. Web tools that hit the IP often miss the real app
        # when the server routes on Host header (vhosts) or returns a
        # different cert via SNI.
        ip_label = f"🔢  {target}  (IP)"
        host_options: list[str] = []
        host_map: dict[str, str] = {}
        if domain.strip() and domain.strip() != target:
            lbl = f"🌐  {domain.strip()}  (domain)"
            host_options.append(lbl)
            host_map[lbl] = domain.strip()
        for vh in vhost_hosts:
            if vh != domain.strip() and vh != target:
                lbl = f"🌐  {vh}  (vhost)"
                host_options.append(lbl)
                host_map[lbl] = vh
        host_options.append(ip_label)
        host_map[ip_label] = target

        if len(host_options) > 1:
            ctk.CTkLabel(win, text="Target host:",
                         font=_f("md", True),
                         text_color=COLORS["text_bright"],
                         anchor="w").pack(fill="x", padx=14, pady=(6, 2))
            host_var = ctk.StringVar(value=host_options[0])
            ctk.CTkOptionMenu(
                win, values=host_options, variable=host_var,
                width=520, height=30, font=_f("sm"),
                fg_color=COLORS["bg_card"],
                button_color=COLORS["border_dim"],
                dropdown_fg_color=COLORS["bg_secondary"],
                dropdown_text_color=COLORS["text_bright"],
                text_color=COLORS["text_bright"], corner_radius=3,
            ).pack(fill="x", padx=14, pady=(0, 6))
        else:
            host_var = ctk.StringVar(value=host_options[0])

        def _proceed():
            sel = port_var.get()
            entry = port_map.get(sel)
            if not entry:
                return
            port = entry[0]
            svc = entry[2]
            bann = entry[3]
            svc_low = ((svc or "") + " " + (bann or "")).lower()
            scheme = "https" if ("https" in svc_low or
                                 "ssl/http" in svc_low or
                                 port in (443, 8443)) else "http"
            chosen_host = host_map.get(host_var.get(), target)

            def _go(final_host):
                base_url = f"{scheme}://{final_host}:{port}"
                _safe_destroy(win)
                self._dispatch_web_tool(tool, final_host, port, scheme,
                                        base_url, fp)

            # If the user kept an IP, no DNS work is needed. If a
            # hostname was picked, gate it through the resolver / hosts
            # helper so we don't ship bogus FQDNs to the tools.
            if chosen_host == target:
                _go(chosen_host)
            else:
                from gui.widgets.card_common import verify_host_or_prompt
                verify_host_or_prompt(self, self.app, chosen_host,
                                      target, _go)

        row = _btn_row(win)
        _btn(row, "CONTINUE", _proceed, primary=True, w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _dispatch_web_tool(self, tool, target, port, scheme, base_url, fp):
        if tool.id == "gobuster_dir":
            self._route_gobuster_dir(tool, base_url)
            return
        elif tool.id == "ffuf":
            self._route_ffuf(tool, base_url)
            return
        elif tool.id == "dirb":
            self._route_dirb(tool, base_url)
            return
        elif tool.id == "nikto":
            self._route_nikto(tool, base_url, ssl_mode=False)
            return
        elif tool.id == "nikto_ssl":
            if scheme != "https":
                self.app.terminal.write(
                    f"[!] {tool.name} — selected port {port} does not "
                    f"appear to be HTTPS. Running nikto -ssl anyway, "
                    f"but it may fail.", "warn")
            base_url = f"https://{target}:{port}"
            self._route_nikto(tool, base_url, ssl_mode=True)
            return
        elif tool.id == "nuclei":
            self._route_nuclei(tool, base_url)
            return
        elif tool.id == "wpscan":
            self._route_wpscan(tool, base_url)
            return
        elif tool.id == "wafw00f":
            cmd = f"wafw00f {base_url} -a"
        elif tool.id == "whatweb":
            cmd = f"whatweb {base_url}"
        else:
            cmd = tool.build_command(target)

        self.app.terminal.write(f"  [*] {tool.name} → {base_url}", "info")
        self._run_raw(tool, cmd)

    def _route_gobuster_dir(self, tool, base_url, *,
                             wordlist_kind: str = "generic",
                             default_base_path: str = "/"):
        """Gobuster Dir with wordlist picker, extensions, and thread count.

        ``wordlist_kind`` flips the picker's default selection — "api"
        prepends SecLists API wordlists so the operator gets the right
        list when the FUZZ button on Target Intel routes here from a
        REST-style endpoint. ``default_base_path`` pre-fills the base-
        path field so the URL is ready to RUN as-is.
        """
        detected_os = ""
        try:
            sess = self.app.session_manager.current
            if sess:
                detected_os = sess.detected_os or ""
        except Exception:
            pass

        wl_options = _get_dir_wordlists(detected_os, kind=wordlist_kind)
        if not wl_options:
            # Absolute fallback
            wl_options = [("directory-list-2.3-medium",
                           "/usr/share/wordlists/dirbuster/"
                           "directory-list-2.3-medium.txt")]

        prescan_size_var = ctk.StringVar(value="")

        def _add_antifp_widgets(win):
            from gui.dialogs import _note_box
            fp_frame = ctk.CTkFrame(
                win, fg_color=COLORS["bg_card"],
                border_color=COLORS["text_yellow"],
                border_width=1, corner_radius=4)
            fp_frame.pack(fill="x", padx=24, pady=(4, 6))
            ctk.CTkLabel(
                fp_frame, text="  Anti false-positive filters",
                font=_f("md", True), text_color=COLORS["text_yellow"],
                anchor="w").pack(fill="x", padx=8, pady=(6, 2))

            # Default ON: the most common reason gobuster bails out
            # in 1 second with "Please exclude the response length"
            # is exactly the catch-all 200 that this prescan
            # auto-detects.  The 3-curl probe costs ~3-30s on a
            # 10-30min job — negligible.  User can untick if they
            # know the target doesn't wildcard.
            prescan_var = ctk.BooleanVar(value=True)
            prescan_cb = ctk.CTkCheckBox(
                fp_frame,
                text="HAWK pre-scan calibration  (recommended)",
                variable=prescan_var,
                font=_f("sm", True), text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                checkmark_color=COLORS["bg_primary"],
                checkbox_width=18, checkbox_height=18)
            prescan_cb.pack(anchor="w", padx=16, pady=(2, 0))
            ctk.CTkLabel(
                fp_frame,
                text=("HAWK probes 3 random non-existent paths before launch, "
                      "reads the response size, and auto-adds --exclude-length "
                      "to gobuster. Filters out default error/redirect pages "
                      "that would otherwise flood results — and avoids the "
                      "'server returns a status code that matches…' bail-out "
                      "on wildcard targets (catch-all 200, common on SPAs). "
                      "Untick only if you know the target has no wildcard."),
                font=_f("xs"), text_color=COLORS["text_dim"],
                wraplength=540, justify="left", anchor="w",
            ).pack(fill="x", padx=32, pady=(0, 8))
            return {"prescan_var": prescan_var}

        def _on_run(wl_path, ext_str, threads, extra):
            bp_var = extra.get("base_path_var")
            bp = bp_var.get().strip() if bp_var else "/"
            if not bp.startswith("/"):
                bp = "/" + bp
            if bp != "/" and not bp.endswith("/"):
                bp += "/"
            scan_url = f"{base_url}{bp}" if bp != "/" else base_url

            def _launch(exclude_len: str):
                parts = [f"gobuster dir -u {scan_url} -w {_shq(wl_path)}"
                         f" -t {threads}"]
                if ext_str:
                    parts.append(f"-x {ext_str}")
                if exclude_len:
                    parts.append(f"--exclude-length {exclude_len}")
                cmd = " ".join(parts)
                self.app.terminal.write(
                    f"  [*] {tool.name} → {scan_url}", "info")
                # Background job — dirbusting can take 10-30+ minutes on
                # mid/large wordlists; the bar gives the user a STOP +
                # OPEN-LOG handle and frees the card to launch other tools.
                self._run_in_background(tool, cmd, estimated_secs=900)

            prescan_var = extra.get("prescan_var")
            if not (prescan_var and prescan_var.get()):
                _launch("")
                return

            # Run the calibration probes off the Tk thread so the GUI
            # doesn't freeze for up to 30s while curl is timing out.
            self.app.terminal.write(
                f"  [hawk] {tool.name} — pre-scan calibrating "
                f"(probing 3 random paths)…", "dim")

            def _worker():
                import subprocess, random, string
                random_paths = [
                    "".join(random.choices(string.ascii_lowercase, k=12))
                    for _ in range(3)
                ]
                # base_url is often passed in WITHOUT a trailing slash
                # (e.g. 'http://silentium.htb:80'), so concatenating
                # 'rp' directly yields a malformed URL like
                # 'http://silentium.htb:80aaaa…'.  curl returns
                # immediately with size 0, sizes[] stays empty,
                # detected stays '', gobuster runs without
                # --exclude-length and bail-outs on the wildcard.
                # Force a single slash before the random path.
                probe_root = scan_url if scan_url.endswith("/") \
                    else scan_url + "/"
                sizes = []
                for rp in random_paths:
                    try:
                        url = f"{probe_root}{rp}"
                        result = subprocess.run(
                            ["curl", "-skL", "-o", "/dev/null", "-w",
                             "%{size_download}", url],
                            capture_output=True, text=True, timeout=10)
                        sz = result.stdout.strip()
                        if sz.isdigit():
                            sizes.append(int(sz))
                    except Exception:
                        pass
                detected = ""
                if len(sizes) >= 2:
                    from collections import Counter
                    n = Counter(sizes).most_common(1)[0][0]
                    if n > 0:
                        detected = str(n)

                def _post():
                    if detected:
                        self.app.terminal.write(
                            f"  [hawk] Pre-scan detected default response "
                            f"size: {detected}B → auto-added "
                            f"--exclude-length {detected}", "dim")
                    _launch(detected)
                try:
                    self.app.after(0, _post)
                except Exception:
                    _post()

            import threading
            threading.Thread(target=_worker, daemon=True).start()

        self._show_wordlist_picker(
            tool, wl_options,
            title="GOBUSTER Dir  —  Directory Brute Force",
            subtitle=f"Target: {base_url}",
            callback=_on_run,
            show_extensions=True,
            show_threads=True,
            default_threads="20",
            extra_widgets_fn=_add_antifp_widgets,
            show_base_path=True,
            default_base_path=default_base_path)

    def _route_dirb(self, tool, base_url):
        """Dirb with wordlist picker."""
        detected_os = ""
        try:
            sess = self.app.session_manager.current
            if sess:
                detected_os = sess.detected_os or ""
        except Exception:
            pass

        wl_options = _get_dir_wordlists(detected_os)
        if not wl_options:
            wl_options = [("common.txt (dirb)",
                           "/usr/share/wordlists/dirb/common.txt")]

        def _on_run(wl_path, _ext, _threads, extra):
            bp_var = extra.get("base_path_var")
            bp = bp_var.get().strip() if bp_var else "/"
            if not bp.startswith("/"):
                bp = "/" + bp
            if bp != "/" and not bp.endswith("/"):
                bp += "/"
            scan_url = f"{base_url}{bp}" if bp != "/" else base_url
            cmd = f"dirb {scan_url} {_shq(wl_path)}"
            self.app.terminal.write(
                f"  [*] {tool.name} → {scan_url}", "info")
            self._run_raw(tool, cmd)

        # Wildcard-target advisory: dirb has no native length filter
        # (unlike gobuster's --exclude-length / ffuf's -fs), so on
        # SPAs / catch-all servers it floods every word as a hit and
        # the run is unusable.  Surface a note so the operator
        # switches tool instead of staring at a 0-second exit.
        def _add_wildcard_advisory(win):
            from gui.dialogs import _note_box
            _note_box(
                win,
                "Heads-up: dirb has NO built-in response-length\n"
                "filter.  If the target is a SPA / catch-all (every\n"
                "path returns 200 with the same body), dirb will\n"
                "either flood you with false positives or exit\n"
                "instantly.  Use GOBUSTER Dir or FFUF on those\n"
                "targets — both auto-calibrate via HAWK pre-scan.",
                COLORS.get("text_yellow", "#FFCC00"))
            return {}

        self._show_wordlist_picker(
            tool, wl_options,
            title="DIRB  —  Web Directory Scanner",
            subtitle=f"Target: {base_url}",
            callback=_on_run,
            show_extensions=False,
            show_threads=False,
            show_base_path=True,
            extra_widgets_fn=_add_wildcard_advisory)

    def _route_gobuster_dns(self, tool):
        """Gobuster DNS with domain entry + wordlist picker."""
        # Pre-fill: explicit override (e.g. from the FUZZ VHOSTS button
        # on a wildcard-cert advisory finding) wins, otherwise fall
        # back to the session-known target_domain.
        default_domain = ""
        try:
            override = getattr(self, "_gobuster_dns_default_domain", "")
            if override:
                default_domain = override
                # Consume the override so subsequent clicks don't
                # silently keep prefilling from a stale source.
                self._gobuster_dns_default_domain = ""
        except Exception:
            pass
        if not default_domain:
            try:
                sess = self.app.session_manager.current
                if sess and getattr(sess, "target_domain", ""):
                    default_domain = sess.target_domain
            except Exception:
                pass

        wl_options = _get_dns_wordlists()
        if not wl_options:
            wl_options = [("subdomains-top1million-5000",
                           "/usr/share/seclists/Discovery/DNS/"
                           "subdomains-top1million-5000.txt")]

        def _add_domain_widget(win):
            """Extra widget: domain entry field."""
            from gui.dialogs import _note_box
            if not default_domain:
                _note_box(win,
                          "⚠  No target domain set. Gobuster DNS needs a real\n"
                          "    domain name — e.g. target.local, company.htb.\n"
                          "    IPs will not work.",
                          COLORS["text_yellow"])
            else:
                _note_box(win, f"Using session domain: {default_domain}",
                          COLORS["border_dim"])
            domain_var = ctk.StringVar(value=default_domain)
            df = ctk.CTkFrame(win, fg_color="transparent")
            df.pack(fill="x", padx=24, pady=(4, 6))
            ctk.CTkLabel(df, text="Domain:", font=_f("sm", True),
                         text_color=COLORS["text_bright"],
                         anchor="w").pack(side="left")
            e = ctk.CTkEntry(
                df, textvariable=domain_var,
                placeholder_text="e.g. target.local",
                font=_f("md"), height=30,
                fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                border_color=COLORS["border_green"], border_width=1,
                corner_radius=3)
            e.pack(side="left", fill="x", expand=True, padx=(4, 0))
            add_context_menu(e)
            return {"domain_var": domain_var}

        def _on_run(wl_path, _ext, threads, extra):
            domain_var = extra.get("domain_var")
            domain = domain_var.get().strip() if domain_var else ""
            if not domain:
                self.app.terminal.write(
                    "[!] gobuster DNS cancelled — no domain provided.",
                    "warn")
                return
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
                self.app.terminal.write(
                    "[!] gobuster DNS needs a domain name, not an IP.",
                    "warn")
                return
            # gobuster 3.8+ rebound `-d` to `--delay` (millisecond
            # wait between requests), so the historical `-d <domain>`
            # invocation fails with 'invalid value for flag -d: parse
            # error' on every modern Kali (gobuster 3.8.2 and later).
            # The portable spelling is the long form `--domain`.
            cmd = (f"gobuster dns --domain {_shq(domain)} "
                   f"-w {_shq(wl_path)} -t {threads}")
            # Background — DNS brute against a top-1M list runs for
            # several minutes; bg bar lets the user keep working.
            self._run_in_background(tool, cmd, estimated_secs=600)

        self._show_wordlist_picker(
            tool, wl_options,
            title="GOBUSTER DNS  —  Subdomain Enumeration",
            subtitle="Enumerate subdomains for a base domain.",
            callback=_on_run,
            show_extensions=False,
            show_threads=True,
            default_threads="20",
            extra_widgets_fn=_add_domain_widget)

    def _route_ffuf(self, tool, base_url):
        """Interactive ffuf launcher: pick wordlist, extensions, and filters.

        Two modes selectable from the dialog:

          • Directory mode (default) — fuzz the path component:
                ffuf -u {base_url}/{base_path}FUZZ -w wordlist ...

          • VHOST mode — fuzz the Host header to discover virtual hosts
            served from the same IP / front-end:
                ffuf -u {base_url}/ -H "Host: FUZZ.{base_domain}" \
                     -w subdomains.txt ...

        VHOST mode pairs well with HTB-style boxes (single IP, multiple
        sites behind nginx/Apache vhosts) and with internal pentests
        where staging/dev sub-vhosts are NOT in DNS. For external
        targets with real public DNS, run a DNS subdomain scan
        (gobuster dns / amass) FIRST — vhost-fuzzing only finds vhosts
        the IP itself routes via Host header.
        """
        from gui.dialogs import (
            _make_win, _title, _sub, _note_box, _btn_row, _btn, _safe_destroy,
        )

        # Path-mode (directory) wordlists.  First existing one is the
        # default for directory mode.
        WL_OPTIONS = [
            ("directory-list-2.3-medium",
             "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
            ("directory-list-2.3-small",
             "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"),
            ("common.txt (dirb)",
             "/usr/share/wordlists/dirb/common.txt"),
            ("big.txt (dirb)",
             "/usr/share/wordlists/dirb/big.txt"),
            ("raft-medium-directories (SecLists)",
             "/usr/share/seclists/Discovery/Web-Content/"
             "raft-medium-directories.txt"),
            ("raft-small-words (SecLists)",
             "/usr/share/seclists/Discovery/Web-Content/"
             "raft-small-words.txt"),
            ("quickhits.txt (SecLists)",
             "/usr/share/seclists/Discovery/Web-Content/quickhits.txt"),
        ]
        # Vhost-mode wordlists.  DNS subdomain dictionaries — sized
        # 5k → 110k → 1M.  Smallest first as the practical default.
        VHOST_WL_OPTIONS = [
            ("subdomains-top1million-5000 (SecLists, fast)",
             "/usr/share/seclists/Discovery/DNS/"
             "subdomains-top1million-5000.txt"),
            ("subdomains-top1million-20000 (SecLists)",
             "/usr/share/seclists/Discovery/DNS/"
             "subdomains-top1million-20000.txt"),
            ("subdomains-top1million-110000 (SecLists, thorough)",
             "/usr/share/seclists/Discovery/DNS/"
             "subdomains-top1million-110000.txt"),
            ("dns-Jhaddix.txt (SecLists, extensive)",
             "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"),
        ]
        existing = [(lbl, p) for lbl, p in WL_OPTIONS if os.path.isfile(p)]
        if not existing:
            existing = [WL_OPTIONS[0]]  # let ffuf fail loud if really missing
        existing_vhost = [(lbl, p) for lbl, p in VHOST_WL_OPTIONS
                          if os.path.isfile(p)]
        if not existing_vhost:
            existing_vhost = [VHOST_WL_OPTIONS[0]]

        # Auto-extract a base_domain from the URL.  Returns "" when the
        # URL host is an IPv4/IPv6 literal (vhost mode then needs the
        # user to type the base domain manually — common when the
        # target is an internal IP routed via Host header to several
        # named vhosts).
        def _extract_base_domain(u: str) -> str:
            try:
                from urllib.parse import urlparse
                host = (urlparse(u).hostname or "").strip().strip("[]")
                if not host:
                    return ""
                # IPv4 literal
                import re as _re_d
                if _re_d.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                    return ""
                # IPv6 literal — has at least one colon
                if ":" in host:
                    return ""
                # Bare hostname (e.g. "localhost") — not useful as a
                # parent domain for FUZZ.localhost, treat as empty.
                if "." not in host:
                    return ""
                return host
            except Exception:
                return ""
        _auto_domain = _extract_base_domain(base_url)
        _is_https = base_url.lower().startswith("https://")

        win = _make_win(self, "ffuf", 640, 760)
        _title(win, "FFUF  —  Web Fuzzer")
        _sub(win, f"Target: {base_url}")
        _note_box(win,
                  "Directory mode (default): fuzz paths under the URL.\n"
                  "VHOST mode: fuzz the Host header to find virtual hosts\n"
                  "served by the same IP. Use AFTER a DNS subdomain scan\n"
                  "if the target has real public DNS — vhost-fuzzing only\n"
                  "finds vhosts the IP routes via Host header.",
                  COLORS["border_dim"])

        # ── Scrollable body ────────────────────────────────────────────
        # The dialog has grown past comfortable laptop height (vhost
        # toggle + 2 wordlist groups + path/ext/mc/fs/threads/anti-FP).
        # All field widgets pack into `body`; the RUN/CANCEL row stays
        # bolted to `win` so the operator always sees the action
        # buttons regardless of scroll position.
        body = ctk.CTkScrollableFrame(
            win, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["text_dim"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 4))

        # ── VHOST MODE toggle ──────────────────────────────────────────
        # Sits at the top so the operator picks intent first.  When on,
        # _run_after_prescan ignores Base path / Extensions and switches
        # to the DNS wordlist + -H Host: FUZZ.{domain}.  All other
        # fields stay visible (and applicable when the box is unchecked)
        # so the dialog stays predictable — no jumpy show/hide.
        vhost_frame = ctk.CTkFrame(
            body, fg_color=COLORS["bg_card"],
            border_color=COLORS["text_cyan"],
            border_width=1, corner_radius=4)
        vhost_frame.pack(fill="x", padx=24, pady=(2, 6))
        vhost_var = ctk.BooleanVar(value=False)
        vhost_cb = ctk.CTkCheckBox(
            vhost_frame,
            text="VHOST mode  (-H 'Host: FUZZ.{domain}')",
            variable=vhost_var,
            font=_f("md", True), text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            checkmark_color=COLORS["bg_primary"],
            checkbox_width=18, checkbox_height=18)
        vhost_cb.pack(anchor="w", padx=10, pady=(8, 2))

        domain_var = ctk.StringVar(value=_auto_domain)
        df = ctk.CTkFrame(vhost_frame, fg_color="transparent")
        df.pack(fill="x", padx=10, pady=(0, 4))
        ctk.CTkLabel(df, text="Base domain:", font=_f("sm"),
                     text_color=COLORS["text_muted"],
                     anchor="w").pack(side="left")
        domain_entry = ctk.CTkEntry(
            df, textvariable=domain_var,
            placeholder_text="silentium.htb  /  acme.com  /  corp.local",
            font=_f("md"), height=30,
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3)
        domain_entry.pack(side="left", fill="x", expand=True, padx=(4, 0))
        add_context_menu(domain_entry)
        ctk.CTkLabel(
            vhost_frame,
            text=("In VHOST mode, Base path and Extensions are ignored.\n"
                  "Use the DNS-subdomain wordlist (auto-suggested below).\n"
                  "On HTTPS targets HAWK adds -k automatically. On WAF/CDN\n"
                  "targets drop threads to 5-10 to avoid getting banned."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            wraplength=560, justify="left", anchor="w",
        ).pack(fill="x", padx=12, pady=(0, 8))

        # Base path — default "/" but user can change to /data/, /api/, etc.
        path_var = ctk.StringVar(value="/")
        pf = ctk.CTkFrame(body, fg_color="transparent")
        pf.pack(fill="x", padx=24, pady=(4, 2))
        ctk.CTkLabel(pf, text="Base path:", font=_f("sm"),
                     text_color=COLORS["text_muted"],
                     anchor="w").pack(side="left")
        ctk.CTkEntry(
            pf, textvariable=path_var,
            placeholder_text="/",
            font=_f("md"), height=30, width=200,
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3,
        ).pack(side="left", padx=(4, 0))
        ctk.CTkLabel(pf, text="FUZZ", font=_f("sm", True),
                     text_color=COLORS["text_green"],
                     anchor="w").pack(side="left", padx=(2, 0))

        # Wordlist selector — directory mode lists first, then vhost
        # (DNS subdomain) lists.  Both share one variable; VHOST mode
        # at launch time picks the first DNS list if the user hasn't
        # picked one explicitly.
        wl_var = ctk.StringVar(value=existing[0][1])
        vhost_wl_default = existing_vhost[0][1]
        lf = ctk.CTkFrame(body, fg_color="transparent"); lf.pack(fill="x", padx=24, pady=(6,2))
        ctk.CTkLabel(lf, text="Wordlist (path mode):", font=_f("md", True),
                     text_color=COLORS["text_bright"], anchor="w").pack(anchor="w")
        for lbl, path in existing:
            rb = ctk.CTkRadioButton(
                lf, text=f"{lbl}  —  {path}",
                variable=wl_var, value=path,
                font=_f("sm"), text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"])
            rb.pack(anchor="w", padx=10, pady=1)
        ctk.CTkLabel(lf, text="Wordlist (vhost mode):", font=_f("md", True),
                     text_color=COLORS["text_cyan"],
                     anchor="w").pack(anchor="w", pady=(6, 0))
        for lbl, path in existing_vhost:
            rb = ctk.CTkRadioButton(
                lf, text=f"{lbl}  —  {path}",
                variable=wl_var, value=path,
                font=_f("sm"), text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"])
            rb.pack(anchor="w", padx=10, pady=1)

        # Custom wordlist override
        import tkinter.filedialog as _fd_ffuf
        custom_var = ctk.StringVar(value="")
        ctk.CTkLabel(body, text="  Custom wordlist path (overrides above):",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=24, pady=(4,0))
        cust_frame = ctk.CTkFrame(body, fg_color="transparent")
        cust_frame.pack(fill="x", padx=24, pady=(0,6))
        custom_entry = ctk.CTkEntry(
            cust_frame, textvariable=custom_var,
            placeholder_text="/path/to/custom.txt",
            font=_f("md"), height=30,
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3)
        custom_entry.pack(side="left", fill="x", expand=True)
        add_context_menu(custom_entry)

        def _browse_ffuf_wl():
            p = _fd_ffuf.askopenfilename(
                title="Select wordlist",
                filetypes=[("Text", "*.txt"), ("All", "*")])
            if p:
                custom_var.set(p)
        ctk.CTkButton(cust_frame, text="📂", width=32, height=30,
                      font=_f("sm"), fg_color=COLORS["bg_card"],
                      hover_color=COLORS["bg_card_hover"],
                      border_color=COLORS["border_dim"], border_width=1,
                      text_color=COLORS["text_dim"], corner_radius=3,
                      command=_browse_ffuf_wl).pack(side="left", padx=(4, 0))

        # Extensions
        ext_var = ctk.StringVar(value="")
        ctk.CTkLabel(body, text="  Extensions (comma-separated, optional):",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=24, pady=(4,0))
        ext_entry = ctk.CTkEntry(
            body, textvariable=ext_var,
            placeholder_text="php,asp,aspx,html,bak",
            font=_f("md"), height=30,
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3)
        ext_entry.pack(fill="x", padx=24, pady=(0,6))
        add_context_menu(ext_entry)

        # Match / filter status codes
        mc_var = ctk.StringVar(value="200,204,301,302,307,401,403")
        ctk.CTkLabel(body, text="  Match HTTP status codes (-mc):",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=24, pady=(4,0))
        mc_entry = ctk.CTkEntry(
            body, textvariable=mc_var,
            font=_f("md"), height=30,
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3)
        mc_entry.pack(fill="x", padx=24, pady=(0,6))
        add_context_menu(mc_entry)

        fs_var = ctk.StringVar(value="")
        ctk.CTkLabel(body,
                     text="  Filter by response size (-fs, optional):",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=24, pady=(4,0))
        fs_entry = ctk.CTkEntry(
            body, textvariable=fs_var,
            placeholder_text="e.g. 1234  (hide responses of this size)",
            font=_f("md"), height=30,
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3)
        fs_entry.pack(fill="x", padx=24, pady=(0,6))
        add_context_menu(fs_entry)

        # Threads
        threads_var = ctk.StringVar(value="40")
        tf = ctk.CTkFrame(body, fg_color="transparent")
        tf.pack(fill="x", padx=24, pady=(4, 2))
        ctk.CTkLabel(tf, text="Threads (-t):", font=_f("sm"),
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

        # ── Anti false-positive options ────────────────────────────
        fp_frame = ctk.CTkFrame(
            body, fg_color=COLORS["bg_card"],
            border_color=COLORS["text_yellow"],
            border_width=1, corner_radius=4)
        fp_frame.pack(fill="x", padx=24, pady=(4, 6))
        ctk.CTkLabel(
            fp_frame, text="  Anti false-positive filters",
            font=_f("md", True), text_color=COLORS["text_yellow"],
            anchor="w").pack(fill="x", padx=8, pady=(6, 2))

        ac_var = ctk.BooleanVar(value=True)
        ac_cb = ctk.CTkCheckBox(
            fp_frame,
            text="Auto-calibrate (-ac)",
            variable=ac_var,
            font=_f("sm", True), text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            checkmark_color=COLORS["bg_primary"],
            checkbox_width=18, checkbox_height=18)
        ac_cb.pack(anchor="w", padx=16, pady=(2, 0))
        ctk.CTkLabel(
            fp_frame,
            text=("ffuf sends random requests before scanning to learn "
                  "what a 'default' response looks like, then auto-filters "
                  "it. Eliminates 95% of false positives."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            wraplength=540, justify="left", anchor="w",
        ).pack(fill="x", padx=32, pady=(0, 6))

        # Default ON: ffuf's -ac auto-calibration handles SOME wildcard
        # cases but misses the most common one in pentest labs — fresh
        # IIS replying 200/689B (iisstart.htm) to every random path.
        # The 3-curl HAWK probe measures the size directly and auto-
        # adds -fs <N>, eliminating the false-positive 200s the user
        # sees as e.g. "/.htaccess<rand>" and "/#" on Metasploitable3.
        # User can still untick when scanning a target known to vary
        # response sizes (a real app, not a blank server).
        prescan_var = ctk.BooleanVar(value=True)
        prescan_cb = ctk.CTkCheckBox(
            fp_frame,
            text="HAWK pre-scan calibration  (recommended)",
            variable=prescan_var,
            font=_f("sm", True), text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            checkmark_color=COLORS["bg_primary"],
            checkbox_width=18, checkbox_height=18)
        prescan_cb.pack(anchor="w", padx=16, pady=(2, 0))
        ctk.CTkLabel(
            fp_frame,
            text=("HAWK probes 3 random non-existent paths before launch, "
                  "reads the response size, and auto-fills the -fs filter. "
                  "Stacks with -ac to catch the cases -ac alone misses "
                  "(IIS iisstart.htm 689B, custom 404 pages with stable "
                  "size, etc.)."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            wraplength=540, justify="left", anchor="w",
        ).pack(fill="x", padx=32, pady=(0, 8))

        # Inline status label so the user sees what HAWK is doing during
        # the (potentially 30s) calibration phase. Hidden until needed.
        prescan_status = ctk.CTkLabel(
            fp_frame, text="",
            font=_f("xs"), text_color=COLORS["text_yellow"],
            anchor="w")
        prescan_status.pack(fill="x", padx=32, pady=(0, 4))

        def _do_prescan(on_done):
            """Probe 3 random paths to detect default response size.

            Runs the curl probes on a worker thread so the dialog stays
            responsive — previously the 3×10s subprocess.run calls
            blocked the Tk loop and froze ffuf for up to 30 seconds
            before the BG job appeared.
            """
            import threading, subprocess, random, string
            random_paths = [
                "".join(random.choices(string.ascii_lowercase, k=12))
                for _ in range(3)
            ]
            scan_bp = path_var.get().strip()
            if not scan_bp.startswith("/"):
                scan_bp = "/" + scan_bp
            if not scan_bp.endswith("/"):
                scan_bp += "/"

            def _worker():
                sizes = []
                for rp in random_paths:
                    try:
                        url = f"{base_url}{scan_bp}{rp}"
                        result = subprocess.run(
                            ["curl", "-skL", "-o", "/dev/null", "-w",
                             "%{size_download}", url],
                            capture_output=True, text=True, timeout=10)
                        sz = result.stdout.strip()
                        if sz.isdigit():
                            sizes.append(int(sz))
                    except Exception:
                        pass
                detected = 0
                if len(sizes) >= 2:
                    from collections import Counter
                    detected = Counter(sizes).most_common(1)[0][0]

                def _post():
                    if detected > 0:
                        fs_var.set(str(detected))
                        self.app.terminal.write(
                            f"  [hawk] Pre-scan detected default response "
                            f"size: {detected}B → auto-added -fs "
                            f"{detected}", "dim")
                    on_done()
                try:
                    self.after(0, _post)
                except Exception:
                    _post()

            threading.Thread(target=_worker, daemon=True).start()

        def _run():
            if prescan_var.get():
                # Disable RUN button + status feedback while the prescan
                # threads run. Once done, _do_prescan calls _run_after_prescan
                # which carries the rest of the launch path.
                for child in win.winfo_children():
                    try:
                        if isinstance(child, ctk.CTkButton):
                            child.configure(state="disabled")
                    except Exception:
                        pass
                prescan_status.configure(
                    text="…  calibrating (probing 3 random paths)")
                _do_prescan(_run_after_prescan)
                return
            _run_after_prescan()

        def _run_after_prescan():

            wl = custom_var.get().strip() or wl_var.get()
            ext = ext_var.get().strip()
            mc  = mc_var.get().strip()
            fs  = fs_var.get().strip()
            if ext:
                ext = ",".join(
                    (e if e.startswith(".") else f".{e}")
                    for e in (x.strip() for x in ext.split(","))
                    if e
                )
            threads = threads_var.get().strip() or "40"

            if vhost_var.get():
                # ── VHOST branch ────────────────────────────────────────
                # Validate domain.  Empty / single-label / IPv4 / IPv6
                # are rejected — FUZZ.<empty> or FUZZ.10.0.0.5 produce
                # nonsense Host headers (vhost-fuzzing only makes sense
                # against a real DNS name space).
                import re as _re_d
                dom = domain_var.get().strip().strip(".")
                _is_ipv4 = bool(_re_d.fullmatch(
                    r"\d{1,3}(?:\.\d{1,3}){3}", dom))
                if (not dom or "." not in dom or _is_ipv4
                        or ":" in dom):
                    self.app.terminal.write(
                        "  [!] VHOST mode needs a base domain "
                        "(e.g. silentium.htb / acme.com / corp.local). "
                        "An IP address can't be a base domain. "
                        "Fill 'Base domain' and try again.", "error")
                    return
                # If the user kept a path-mode wordlist selected, swap
                # to the first DNS list — saves a click in the common
                # case while still honouring an explicit choice.
                if wl == existing[0][1] and not custom_var.get().strip():
                    wl = vhost_wl_default
                root_url = base_url.rstrip("/") + "/"
                parts = [
                    f"ffuf -u {root_url}",
                    f"-H {_shq('Host: FUZZ.' + dom)}",
                    f"-w {_shq(wl)}",
                    f"-t {threads}",
                ]
                if mc:
                    parts.append(f"-mc {mc}")
                if fs:
                    parts.append(f"-fs {fs}")
                if ac_var.get():
                    parts.append("-ac")
                # On HTTPS the cert almost never matches FUZZ.{domain}
                # (lab self-signed, mismatched SNI, internal CA).  -k
                # tells ffuf to skip TLS verification so the scan
                # actually runs end-to-end.
                if _is_https:
                    parts.append("-k")
                parts.append("-noninteractive")
                cmd = " ".join(parts)
                _safe_destroy(win)
                self._run_in_background(tool, cmd, estimated_secs=900)
                return

            # ── DIR branch (default, unchanged) ─────────────────────
            bp = path_var.get().strip()
            if not bp.startswith("/"):
                bp = "/" + bp
            if not bp.endswith("/"):
                bp += "/"
            fuzz_url = f"{base_url}{bp}FUZZ"
            parts = [f"ffuf -u {fuzz_url} -w {_shq(wl)} -t {threads}"]
            if ext:
                parts.append(f"-e {ext}")
            if mc:
                parts.append(f"-mc {mc}")
            if fs:
                parts.append(f"-fs {fs}")
            if ac_var.get():
                parts.append("-ac")
            parts.append("-noninteractive")
            cmd = " ".join(parts)
            _safe_destroy(win)
            # Background — fuzzing campaigns commonly run 10-30 min
            # depending on wordlist + extensions; bg bar adds STOP +
            # log-tail handles.
            self._run_in_background(tool, cmd, estimated_secs=900)

        # ── Wheel-scroll through children ──────────────────────────────
        # CTkScrollableFrame's internal canvas only receives mousewheel
        # events when the cursor is over its own area, NOT when over
        # child widgets (CTkLabel, CTkFrame, CTkRadioButton).  Bind
        # <MouseWheel>/<Button-4>/<Button-5> on every descendant so the
        # rotellina works anywhere inside the dialog body.  CTkTextbox
        # widgets are skipped so their own internal scroll keeps
        # working; ditto for any widget already flagged with
        # _hawk_bubble_wheel.
        try:
            _canvas = body._parent_canvas
            def _on_mw(ev, _c=_canvas):
                try:
                    if hasattr(ev, "delta") and ev.delta:
                        _c.yview_scroll(int(-1 * (ev.delta / 120)),
                                        "units")
                    elif getattr(ev, "num", None) == 4:
                        _c.yview_scroll(-1, "units")
                    elif getattr(ev, "num", None) == 5:
                        _c.yview_scroll(1, "units")
                except Exception:
                    pass
            def _bind_mw(widget):
                if isinstance(widget, ctk.CTkTextbox):
                    return
                if getattr(widget, "_hawk_bubble_wheel", False):
                    return
                try:
                    widget.bind("<MouseWheel>", _on_mw, add="+")
                    widget.bind("<Button-4>", _on_mw, add="+")
                    widget.bind("<Button-5>", _on_mw, add="+")
                except Exception:
                    pass
                for child in widget.winfo_children():
                    _bind_mw(child)
            _bind_mw(body)
        except Exception:
            pass

        row = _btn_row(win)
        _btn(row, "RUN FFUF", _run, primary=True, w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _route_nuclei(self, tool, base_url):
        """Interactive Nuclei launcher.

        Exposes the flags that actually matter in practice:
          - severity filter (default: medium,high,critical — skip info noise)
          - tag filter (cve, rce, takeover, exposure, default-login, …)
          - template-update policy (auto / force / skip)
          - concurrency + rate-limit (defensive defaults)
          - custom args passthrough

        Template updates are NOT forced on every run. Nuclei templates are
        refreshed daily upstream; re-downloading every click wastes ~30s
        and a lot of bandwidth. Default is 'auto' = update only if the
        templates directory is older than 7 days.
        """
        from gui.dialogs import (
            _make_win, _title, _sub, _note_box, _btn_row, _btn, _safe_destroy,
        )

        win = _make_win(self, "Nuclei", 680, 720)
        _title(win, "NUCLEI  —  Template Vulnerability Scanner")
        _sub(win, f"Target: {base_url}")
        _note_box(win,
                  "Nuclei runs YAML templates against the target. Pick\n"
                  "which severities / tags to include. High/Critical hits\n"
                  "will land in Target Intel with searchsploit / MSF\n"
                  "follow-up suggestions. Keep info-level off unless you\n"
                  "specifically want fingerprint noise.",
                  COLORS["border_dim"])

        # Severity checkboxes.
        sev_frame = ctk.CTkFrame(win, fg_color="transparent")
        sev_frame.pack(fill="x", padx=24, pady=(6, 2))
        ctk.CTkLabel(sev_frame, text="Severities:",
                     font=_f("md", True), text_color=COLORS["text_bright"],
                     width=110, anchor="w").pack(side="left")
        sev_vars = {}
        for label, default in [("info", False), ("low", True),
                               ("medium", True), ("high", True),
                               ("critical", True)]:
            v = ctk.BooleanVar(value=default)
            sev_vars[label] = v
            ctk.CTkCheckBox(
                sev_frame, text=label, variable=v,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["text_green"],
                border_color=COLORS["border_dim"],
                checkbox_width=16, checkbox_height=16,
            ).pack(side="left", padx=6)

        # Tag presets — checkboxes for quick toggle.
        tag_frame = ctk.CTkFrame(win, fg_color="transparent")
        tag_frame.pack(fill="x", padx=24, pady=(8, 2))
        ctk.CTkLabel(tag_frame, text="Tags (optional):",
                     font=_f("md", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(anchor="w")
        tag_grid = ctk.CTkFrame(win, fg_color="transparent")
        tag_grid.pack(fill="x", padx=34)
        tag_vars = {}
        TAG_OPTIONS = [
            ("cve",            "Known CVEs with PoC"),
            ("rce",            "Remote code execution"),
            ("takeover",       "Subdomain takeovers"),
            ("exposure",       "Exposed files / endpoints"),
            ("default-login",  "Default credentials"),
            ("misconfig",      "Misconfigurations"),
            ("tech",           "Technology fingerprinting"),
            ("network",        "Non-HTTP (Redis, Mongo, Docker)"),
        ]
        for i, (t, desc) in enumerate(TAG_OPTIONS):
            v = ctk.BooleanVar(value=False)
            tag_vars[t] = v
            ctk.CTkCheckBox(
                tag_grid, text=f"{t}  —  {desc}", variable=v,
                font=_f("sm"), text_color=COLORS["text_dim"],
                fg_color=COLORS["text_green"],
                border_color=COLORS["border_dim"],
                checkbox_width=14, checkbox_height=14,
            ).grid(row=i // 2, column=i % 2, sticky="w", padx=4, pady=2)

        # Template-update policy (radio).
        upd_frame = ctk.CTkFrame(win, fg_color="transparent")
        upd_frame.pack(fill="x", padx=24, pady=(10, 2))
        ctk.CTkLabel(upd_frame, text="Templates:",
                     font=_f("md", True), text_color=COLORS["text_bright"],
                     width=110, anchor="w").pack(side="left")
        upd_var = ctk.StringVar(value="auto")
        for val, lbl in [
            ("skip",  "skip (fastest)"),
            ("auto",  "auto (update if > 7 days old)"),
            ("force", "force update now"),
        ]:
            ctk.CTkRadioButton(
                upd_frame, text=lbl, variable=upd_var, value=val,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["text_green"],
                border_color=COLORS["border_dim"],
            ).pack(side="left", padx=4)

        # Concurrency + rate limit.
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

        conc_var   = ctk.StringVar(value="25")
        rate_var   = ctk.StringVar(value="150")
        extra_var  = ctk.StringVar(value="")
        _row("Concurrency", conc_var,
             "-c — parallel templates (25 default, 50+ is aggressive)")
        _row("Rate limit",  rate_var,
             "-rl — requests/second cap (150 default)")
        _row("Extra args",  extra_var,
             "e.g. '-etags dos,fuzz' (exclude), '-nt' (new templates only)")

        def _run():
            sevs = [s for s, v in sev_vars.items() if v.get()]
            tags = [t for t, v in tag_vars.items() if v.get()]
            upd  = upd_var.get()
            conc = conc_var.get().strip() or "25"
            rate = rate_var.get().strip() or "150"
            extra = extra_var.get().strip()

            if not sevs:
                self.app.terminal.write(
                    "[!] Nuclei cancelled — pick at least one severity.",
                    "warn")
                return

            # Nuclei template management — DO NOT use `-ud` any more.
            # Historic context: HAWK previously tried to keep nuclei
            # templates inside the portable tree via
            # `-ud <hawkC/cache/nuclei>`.  Two reasons it was broken:
            #   (1) nuclei v3.7+ moved its default template directory
            #       from ~/nuclei-templates to ~/.local/nuclei-templates.
            #       HAWK's "system fallback" pointed at the old path,
            #       so it was wrong on every modern Kali.
            #   (2) `nuclei -update-templates -ud <custom>` in v3.7
            #       only wrote `index.gob` to the custom dir without
            #       downloading the actual template tree (`http/`,
            #       `cves/`, etc.).  Subsequent `nuclei -u ... -ud
            #       <custom>` then exited rc=1 with "no templates
            #       provided for scan" because the dir was a marker-
            #       only stub.
            # Cure: let nuclei manage its own template directory.
            # The `nuclei -update-templates` (no `-ud`) call writes
            # to ~/.local/nuclei-templates correctly, and a plain
            # `nuclei -u TARGET ...` then finds them.
            # Tradeoff: HAWK is no longer a single-folder portable
            # for nuclei content.  Templates live in $HOME.  Noted
            # in memory as a known limitation pending an upstream fix.
            common_parts = ["nuclei", "-u", base_url,
                            "-severity", ",".join(sevs),
                            "-c", conc, "-rl", rate,
                            "-stats", "-silent"]
            if tags:
                common_parts += ["-tags", ",".join(tags)]
            if extra:
                common_parts.append(extra)
            scan_cmd = " ".join(common_parts)

            # Stale check: ask nuclei itself.  We can't reliably
            # introspect its template dir from Python (it has moved
            # between versions and may move again).  Cheapest signal:
            # always run `-update-templates` in auto/force mode and
            # let nuclei decide if anything actually changes.  When
            # everything is current, nuclei finishes in ~2 seconds
            # with `No new updates found`.  Negligible cost, no
            # heuristic to get wrong.
            #
            # `-silent` deliberately omitted on the update step so
            # network / rate-limit / template-server errors reach
            # the operator instead of being swallowed.
            if upd in ("auto", "force"):
                update_step = (
                    "echo '[hawk] updating nuclei templates "
                    "(nuclei manages its own template dir)'; "
                    "nuclei -update-templates "
                    "|| echo '[hawk] template update returned "
                    "non-zero (continuing — scan may still work "
                    "with existing templates)'; "
                )
            else:
                update_step = ""

            cmd = update_step + scan_cmd
            _safe_destroy(win)
            self._run_raw(tool, cmd)

        row = _btn_row(win)
        _btn(row, "RUN NUCLEI", _run, primary=True, w=150)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _route_nikto(self, tool, base_url, ssl_mode: bool = False):
        """Nikto customization dialog.

        Flags covered (each with a preset so the user doesn't need the
        man page):
          • -Tuning <x>       — limit scan to one test class
          • -evasion <x>      — IDS evasion technique
          • -useragent        — custom User-Agent string
          • -Format / -output — save report to file in chosen format
          • -nolookup         — skip reverse DNS on target IP
          • -maxtime          — hard time cap per target
          • -Plugins          — semicolon-separated plugin list
          • Extra args        — free-form tail (mirrors nmap custom)

        The preview updates live as fields change so the user sees the
        exact shell command before running.  The dialog is SSL-aware:
        ssl_mode=True adds the `-ssl` flag automatically.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                  _btn_row, _btn, _safe_destroy)
        from utils.clipboard import add_context_menu
        import time as _t

        title = f"Nikto  —  {'SSL' if ssl_mode else 'plain HTTP'}"
        win = _make_win(self, title, 720, 720)
        _title(win, f"NIKTO  —  Web Vulnerability Scanner "
               f"({'HTTPS' if ssl_mode else 'HTTP'})")
        _sub(win, f"Target: {base_url}", COLORS["text_dim"])

        # Scrollable body — lots of options.
        body = ctk.CTkScrollableFrame(
            win, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["text_dim"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 4))

        # ── Info card ─────────────────────────────────────────────
        info = ctk.CTkFrame(
            body, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_green"],
            border_width=2, corner_radius=4)
        info.pack(fill="x", padx=14, pady=(8, 10))
        ctk.CTkLabel(
            info, text="  ⓘ  NIKTO — what it does",
            font=_f("md", True), text_color=COLORS["text_green"],
            anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        ctk.CTkLabel(
            info,
            text=("Nikto probes a web server for ~7000 dangerous files "
                  "and misconfigurations: default pages, admin panels, "
                  "outdated software, exposed .git / .svn, "
                  "vulnerable CGI, insecure headers, etc.  Noisy — "
                  "hits thousands of URLs per scan.  Not stealthy.  "
                  "Best combined with the 'Tuning' presets below to "
                  "narrow the test class."),
            font=_f("sm"), text_color=COLORS["text_dim"],
            wraplength=660, justify="left", anchor="w",
        ).pack(fill="x", padx=12, pady=(0, 8))

        # ── Base path ─────────────────────────────────────────────
        bp_row = ctk.CTkFrame(body, fg_color="transparent")
        bp_row.pack(fill="x", padx=14, pady=(6, 8))
        ctk.CTkLabel(bp_row, text="Base path:",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     width=90, anchor="w").pack(side="left")
        ctk.CTkLabel(bp_row, text=base_url.rstrip("/"),
                     font=_f("sm"),
                     text_color=COLORS["text_dim"],
                     anchor="w").pack(side="left")
        bp_var = ctk.StringVar(value="/")
        bp_entry = ctk.CTkEntry(
            bp_row, textvariable=bp_var,
            font=_f("sm"), height=28, width=160,
            placeholder_text="/",
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3)
        bp_entry.pack(side="left", padx=(2, 0))
        add_context_menu(bp_entry)
        ctk.CTkLabel(bp_row, text="(e.g. /app/ or /data/)",
                     font=_f("sm"),
                     text_color=COLORS["text_dim"],
                     anchor="w").pack(side="left", padx=(6, 0))

        # ── Tuning preset ────────────────────────────────────────
        # Each Nikto tuning digit maps to a test class.  `x<digit>` =
        # EVERYTHING EXCEPT that class.  We pre-bake the most useful
        # combos so the user doesn't need to memorise the map.
        TUNING_PRESETS = [
            ("[default] all tests                    — -Tuning left off",     ""),
            ("0  File upload                         — -Tuning 0",            "0"),
            ("1  Interesting files / default pages   — -Tuning 1",            "1"),
            ("2  Misconfig / default files           — -Tuning 2",            "2"),
            ("3  Info disclosure                     — -Tuning 3",            "3"),
            ("4  Injection (XSS / script / HTML)     — -Tuning 4",            "4"),
            ("5  Remote file retrieval (inside docroot)— -Tuning 5",          "5"),
            ("6  Denial of Service                   — -Tuning 6  (⚠ DoS!)",  "6"),
            ("7  Remote file retrieval (root path)   — -Tuning 7",            "7"),
            ("8  Command execution / Remote shell    — -Tuning 8",            "8"),
            ("9  SQL injection                       — -Tuning 9",            "9"),
            ("b  Software identification             — -Tuning b",            "b"),
            ("[common] 1,2,3,4,5,7,8,9 (no DoS, no upload) — -Tuning x06",    "x06"),
        ]
        ctk.CTkLabel(body, text="Tuning preset (test class to run):",
                     font=_f("md", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=14, pady=(4, 2))
        # Plain-language hint — the single-digit presets run ONLY that
        # class, which on most targets means almost nothing to do and
        # nikto can exit in seconds with no findings.  `[default]` runs
        # everything; `[common]` is the recommended balanced default.
        ctk.CTkLabel(
            body,
            text=("  Single-digit presets run ONE class of tests only "
                  "(targeted, fast — useful when you know what you're "
                  "looking for).  [default] runs every class.  [common] "
                  "is the recommended balanced scan."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            wraplength=680, justify="left", anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 4))
        tuning_var = ctk.StringVar(value=TUNING_PRESETS[0][0])
        ctk.CTkOptionMenu(
            body, values=[p[0] for p in TUNING_PRESETS],
            variable=tuning_var,
            width=680, height=30, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_bright"], corner_radius=3,
        ).pack(fill="x", padx=14, pady=(0, 8))

        # ── Evasion technique ────────────────────────────────────
        EVASION_PRESETS = [
            ("[none] no evasion         — default",                 ""),
            ("1  Random URI encoding",                              "1"),
            ("2  Directory self-reference (/./)",                   "2"),
            ("3  Premature URL ending",                             "3"),
            ("4  Prepend long random string",                       "4"),
            ("5  Fake parameter",                                   "5"),
            ("6  TAB as request spacer",                            "6"),
            ("7  Change case of URL",                               "7"),
            ("8  Use Windows path separator (\\)",                  "8"),
            ("A  Session splicing (slow)",                          "A"),
            ("B  Max randomness (combine 1-8)",                     "B"),
        ]
        ctk.CTkLabel(body, text="Evasion technique (IDS bypass):",
                     font=_f("md", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=14, pady=(4, 2))
        evasion_var = ctk.StringVar(value=EVASION_PRESETS[0][0])
        ctk.CTkOptionMenu(
            body, values=[p[0] for p in EVASION_PRESETS],
            variable=evasion_var,
            width=680, height=30, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_bright"], corner_radius=3,
        ).pack(fill="x", padx=14, pady=(0, 8))

        # ── Output format ────────────────────────────────────────
        FORMAT_PRESETS = [
            ("[stdout] terminal only — no file",            ""),
            ("text  — save as .txt",                        "txt"),
            ("htm   — save as .html (browseable)",          "htm"),
            ("csv   — save as .csv",                        "csv"),
            ("xml   — save as .xml",                        "xml"),
            ("json  — save as .json",                       "json"),
        ]
        ctk.CTkLabel(body, text="Output format (save report to file):",
                     font=_f("md", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=14, pady=(4, 2))
        format_var = ctk.StringVar(value=FORMAT_PRESETS[0][0])
        ctk.CTkOptionMenu(
            body, values=[p[0] for p in FORMAT_PRESETS],
            variable=format_var,
            width=680, height=30, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_bright"], corner_radius=3,
        ).pack(fill="x", padx=14, pady=(0, 8))

        # ── Toggle / flag options ────────────────────────────────
        opts_frame = ctk.CTkFrame(body, fg_color="transparent")
        opts_frame.pack(fill="x", padx=14, pady=(4, 8))

        nolookup_var = ctk.BooleanVar(value=False)
        display404_var = ctk.BooleanVar(value=False)
        nossl_var = ctk.BooleanVar(value=False)

        ctk.CTkCheckBox(
            opts_frame, text="-nolookup (skip reverse DNS on target)",
            variable=nolookup_var,
            font=_f("sm"), text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            width=16, height=16,
        ).pack(anchor="w", pady=2)
        ctk.CTkCheckBox(
            opts_frame, text=("-Display V (verbose — show 404/200 lines "
                              "from every URL tested)"),
            variable=display404_var,
            font=_f("sm"), text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            width=16, height=16,
        ).pack(anchor="w", pady=2)
        if ssl_mode:
            ctk.CTkCheckBox(
                opts_frame, text=("-nossl (disable SSL — use only if "
                                  "the target speaks plain HTTP on "
                                  "this port)"),
                variable=nossl_var,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                width=16, height=16,
            ).pack(anchor="w", pady=2)

        # ── Max time (seconds) ───────────────────────────────────
        # In SSL mode a blank field would let nikto run for ~20+ min
        # on a default-installed IIS (TLS handshake adds ~10x per-
        # request overhead).  We surface that explicitly in the help
        # label and apply an auto -maxtime 900 at launch time when
        # the field stays blank; the user can override by typing a
        # different value.
        maxtime_row = ctk.CTkFrame(body, fg_color="transparent")
        maxtime_row.pack(fill="x", padx=14, pady=(4, 2))
        maxtime_label = (
            "Max runtime (-maxtime, seconds, "
            "blank = auto 900 in SSL mode / no limit in HTTP):"
            if ssl_mode else
            "Max runtime (-maxtime, seconds, blank = no limit):"
        )
        ctk.CTkLabel(maxtime_row,
                     text=maxtime_label,
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(side="left")
        maxtime_var = ctk.StringVar(value="")
        maxtime_entry = ctk.CTkEntry(
            maxtime_row, textvariable=maxtime_var,
            font=_f("sm"), height=28, width=80,
            placeholder_text="e.g. 600",
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3)
        maxtime_entry.pack(side="left", padx=(6, 0))
        add_context_menu(maxtime_entry)

        if ssl_mode:
            # Inline advisory — only meaningful in SSL mode.  A vanilla
            # IIS run over HTTPS routinely took ~20 min on the test
            # session JSON we audited (1244 s vs 13 s for the same
            # target on plain HTTP).  TLS handshake per request is
            # the multiplier — we cannot fix it, but we surface why
            # and what HAWK does about it.
            ctk.CTkLabel(
                body,
                text=(
                    "  SSL scans are ~10x slower than plain HTTP "
                    "(TLS handshake per request).  HAWK auto-applies "
                    "-maxtime 900 (15 min) when this field is left "
                    "blank.  Type a higher number if you need a full "
                    "sweep on this target."),
                font=_f("xs"), text_color=COLORS["text_yellow"],
                wraplength=680, justify="left", anchor="w",
            ).pack(fill="x", padx=14, pady=(0, 6))

        # ── User-Agent ───────────────────────────────────────────
        ua_row = ctk.CTkFrame(body, fg_color="transparent")
        ua_row.pack(fill="x", padx=14, pady=(6, 2))
        ctk.CTkLabel(ua_row, text="User-Agent:",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     width=110, anchor="w").pack(side="left")
        ua_var = ctk.StringVar(value="")
        ua_entry = ctk.CTkEntry(
            ua_row, textvariable=ua_var,
            font=_f("sm"), height=28,
            placeholder_text="blank = Nikto default",
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3)
        ua_entry.pack(side="left", fill="x", expand=True)
        add_context_menu(ua_entry)

        # ── Extra args ───────────────────────────────────────────
        extras_row = ctk.CTkFrame(body, fg_color="transparent")
        extras_row.pack(fill="x", padx=14, pady=(8, 0))
        ctk.CTkLabel(extras_row, text="Extra args:",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     width=110, anchor="w").pack(side="left")
        extras_var = ctk.StringVar(value="")
        extras_entry = ctk.CTkEntry(
            extras_row, textvariable=extras_var,
            font=_f("sm"), height=28,
            placeholder_text=("appended to command — e.g. -Plugins "
                              "'apache_expect_xss;http_basic' -ask no"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3)
        extras_entry.pack(side="left", fill="x", expand=True)
        add_context_menu(extras_entry)

        # ── Preview ──────────────────────────────────────────────
        preview_var = ctk.StringVar(value="")
        ctk.CTkLabel(body, text="Preview:",
                     font=_f("md", True),
                     text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=14, pady=(12, 2))
        ctk.CTkLabel(body, textvariable=preview_var,
                     font=_f("sm"), text_color=COLORS["text_cyan"],
                     wraplength=680, justify="left", anchor="w",
                     ).pack(fill="x", padx=14, pady=(0, 8))

        def _selected_preset_value(var, presets):
            """Lookup the code for the currently-selected preset label."""
            label = var.get()
            for lbl, val in presets:
                if lbl == label:
                    return val
            return ""

        def _build_cmd():
            bp = (bp_var.get() or "/").strip()
            if bp and bp != "/":
                if not bp.startswith("/"):
                    bp = "/" + bp
                scan_url = base_url.rstrip("/") + bp
            else:
                scan_url = base_url
            parts = ["nikto", "-h", scan_url]
            if ssl_mode and not nossl_var.get():
                parts.append("-ssl")
            t = _selected_preset_value(tuning_var, TUNING_PRESETS)
            if t:
                parts += ["-Tuning", t]
            ev = _selected_preset_value(evasion_var, EVASION_PRESETS)
            if ev:
                parts += ["-evasion", ev]
            fmt = _selected_preset_value(format_var, FORMAT_PRESETS)
            if fmt:
                # Report path goes in <HAWK>/outputs/ with a timestamp
                # so the user never silently overwrites a previous
                # scan, and every HAWK-generated artefact stays
                # inside the HAWK tree.
                from utils.config import OUTPUTS_DIR as _OUTDIR
                ts = _t.strftime("%Y%m%d-%H%M%S")
                safe_host = base_url.replace("://", "-").replace(":", "-")
                safe_host = "".join(c if c.isalnum() or c in "-." else "_"
                                    for c in safe_host)
                outpath = os.path.join(
                    _OUTDIR, f"nikto-{safe_host}-{ts}.{fmt}")
                parts += ["-Format", fmt, "-output", outpath]
            if nolookup_var.get():
                parts.append("-nolookup")
            if display404_var.get():
                parts += ["-Display", "V"]
            mt = (maxtime_var.get() or "").strip()
            if mt:
                parts += ["-maxtime", mt]
            ua = (ua_var.get() or "").strip()
            if ua:
                parts += ["-useragent", _shq(ua)]
            cmd = " ".join(parts)
            extras = (extras_var.get() or "").strip()
            if extras:
                cmd += " " + extras
            return cmd

        def _refresh_preview(*_):
            preview_var.set(_build_cmd())
        for v in (tuning_var, evasion_var, format_var,
                  nolookup_var, display404_var, nossl_var,
                  maxtime_var, ua_var, extras_var, bp_var):
            v.trace_add("write", _refresh_preview)
        _refresh_preview()

        def _run():
            # SSL nikto runs against vanilla IIS measured 1244 s in
            # the audited session JSON — TLS handshake overhead per
            # request, ~10x the plain-HTTP cost.  Auto-apply
            # -maxtime 900 (15 min) when the field is blank and we're
            # in SSL mode, so the user's first SSL run doesn't burn
            # an hour silently.  The inline advisory above the RUN
            # button already announces this behaviour; we also log
            # the auto-cap to the terminal so the operator can spot
            # it after the fact.
            if ssl_mode and not (maxtime_var.get() or "").strip():
                maxtime_var.set("900")
                self.app.terminal.write(
                    "  [hawk] Nikto SSL — auto-applied -maxtime 900 "
                    "(15 min cap).  Override by typing a value in the "
                    "Max runtime field before launching.",
                    "dim")
            cmd = _build_cmd()
            _safe_destroy(win)
            self.app.terminal.write(
                f"  [*] {tool.name} → {base_url}  (running in background)",
                "info")
            # Nikto scans run for several minutes (thousands of probes).
            # Route through the background-jobs bar so the user keeps an
            # OPEN/STOP handle and the live HAWK terminal stays usable.
            # 15-minute estimate matches the default -maxtime=900 nikto
            # uses for typical runs.
            self._run_in_background(tool, cmd, estimated_secs=900)

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _route_wpscan(self, tool, base_url):
        """WPScan is WordPress-specific.  Before launching the actual
        scan we probe the target with a couple of HTTP GETs — if no
        WordPress markers turn up, we tell the user it's almost
        certainly a waste of time and make SKIP the primary action
        (user can still force-launch if they want).  Detection keys
        used, in order of reliability:
          • HTTP header `x-powered-by: wordpress` / `x-pingback`
          • HTML <meta name="generator" content="WordPress …">
          • Any reference to `wp-content`, `wp-includes`, `wp-login.php`,
            `wp-admin/` in the homepage HTML
          • `/readme.html` first-200-bytes containing "WordPress"
          • `/wp-login.php` returning 200/302 (login page present)
        We give the probe a hard 4-second timeout so HAWK doesn't
        hang the UI if the target is slow/unreachable.
        """
        from gui.dialogs import (_make_win, _title, _note_box, _btn_row,
                                  _btn, _safe_destroy)
        # Kick off the detection first — short-lived, runs inline (we
        # want the dialog's content to reflect the result).  Uses
        # urllib from the stdlib so no new deps.
        wp_status, wp_evidence = self._detect_wordpress(base_url)

        win = _make_win(self, "WPScan", 560, 360)
        _title(win, "WPSCAN  —  WordPress Scanner")

        if wp_status == "detected":
            _note_box(win,
                      f"Target: {base_url}\n\n"
                      f"✓  WordPress detected.\n"
                      f"Evidence: {wp_evidence}",
                      COLORS["text_green"])
            primary_label = "RUN WPSCAN"
            cancel_label  = "CANCEL"
            primary_is_run = True
        elif wp_status == "unreachable":
            _note_box(win,
                      f"Target: {base_url}\n\n"
                      f"⚠  The target did not respond to a quick HTTP probe.\n"
                      f"Reason: {wp_evidence}\n\n"
                      f"Running wpscan now will likely fail the same way.",
                      COLORS["text_yellow"])
            primary_label = "CANCEL"
            cancel_label  = "RUN ANYWAY"
            primary_is_run = False
        else:  # "not_found"
            _note_box(win,
                      f"Target: {base_url}\n\n"
                      f"✗  WordPress NOT detected on this host.\n"
                      f"Probed: / , /readme.html , /wp-login.php — "
                      f"no WordPress markers found.\n\n"
                      f"WPScan against a non-WordPress site returns empty "
                      f"results and wastes ~30-60 s of scan time.  "
                      f"Suggested next step: gobuster / nikto / whatweb "
                      f"to identify the actual stack.",
                      COLORS["text_red"])
            primary_label = "CANCEL (recommended)"
            cancel_label  = "RUN ANYWAY"
            primary_is_run = False

        def _run():
            _safe_destroy(win)
            # --no-update: skip the interactive "Do you want to update
            # the database now? [Y]es [N]o" prompt that wpscan shows
            # when its local DB is older than ~35 days.  HAWK does not
            # feed stdin to subprocesses, so without this flag wpscan
            # blocks on the prompt until SIGTERM (observed: ~9 min
            # before user-kill on a stale-DB session).
            # --no-banner: shave the ASCII banner from the captured
            # output so the parser sees real scan lines first.
            # --random-user-agent: low-cost evasion against trivial
            # User-Agent filtering — does not affect real WordPress
            # detection.
            # --disable-tls-checks: tolerate self-signed certs on
            # lab / HTB targets; no-op on plain HTTP.
            self._run_raw(tool,
                f"wpscan --url {base_url} --enumerate u,p,t "
                f"--no-update --no-banner --random-user-agent "
                f"--disable-tls-checks")

        def _cancel():
            _safe_destroy(win)
            self.app.terminal.write(
                "  [*] WPScan cancelled.", "dim")

        row = _btn_row(win)
        if primary_is_run:
            _btn(row, primary_label, _run, primary=True, w=160)
            _btn(row, cancel_label, _cancel, w=140)
        else:
            # Flip the button roles when WordPress isn't detected —
            # CANCEL becomes the highlighted default so the user has
            # to deliberately pick RUN ANYWAY.
            _btn(row, primary_label, _cancel, primary=True, w=200)
            _btn(row, cancel_label, _run, warn=True, w=140)

    def _detect_wordpress(self, base_url: str) -> tuple:
        """Quick-probe the target for WordPress signals.  Returns
        (status, evidence) where status is one of:
          "detected"   — WordPress found
          "not_found"  — target responds but no WP markers
          "unreachable"— target didn't respond within the timeout
        `evidence` is a short human string describing what was seen
        (for the UI note box)."""
        import urllib.request, urllib.error, re as _re, socket
        socket.setdefaulttimeout(4)

        # Paths to probe.  Order matters — the first positive short-
        # circuits the rest for speed.
        probes = [
            "",               # / — homepage
            "/wp-login.php",  # dead giveaway if present
            "/readme.html",   # WP-style readme with "WordPress"
        ]
        # Markers grouped by confidence — any hit means "detected".
        STRONG_MARKERS = (
            "wp-login.php",
            "wp-content/",
            "wp-includes/",
            "wp-admin/",
            '<meta name="generator" content="WordPress',
            "/xmlrpc.php",
        )
        HEADER_MARKERS = ("x-pingback", "wordpress")

        last_err = ""
        for path in probes:
            url = base_url.rstrip("/") + path
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent":
                             "Mozilla/5.0 (HAWK/wpscan-probe)"})
                with urllib.request.urlopen(req, timeout=4) as r:
                    # Headers first — cheapest win
                    for hname, hval in r.headers.items():
                        low = (hname + ": " + (hval or "")).lower()
                        if any(m in low for m in HEADER_MARKERS):
                            return ("detected",
                                    f"HTTP header `{hname}: {hval[:60]}`")
                    body = r.read(65536).decode(
                        "utf-8", errors="replace")
                    low = body.lower()
                    for m in STRONG_MARKERS:
                        if m.lower() in low:
                            return ("detected",
                                    f"found `{m}` in {path or '/'}")
                    # /wp-login.php returning 200 is conclusive even
                    # without markers (the file simply existing IS
                    # WordPress).
                    if path == "/wp-login.php" and r.status == 200:
                        return ("detected",
                                f"/wp-login.php returned 200")
            except urllib.error.HTTPError as e:
                # 404 on /wp-login.php is normal when it's not WP;
                # we just keep probing.  Other non-404 codes may
                # still be useful evidence (e.g. 403 on wp-admin).
                if path == "/wp-login.php" and e.code in (401, 403):
                    return ("detected",
                            f"/wp-login.php returned {e.code}")
                last_err = f"HTTP {e.code} on {path or '/'}"
                continue
            except urllib.error.URLError as e:
                last_err = f"URLError on {path or '/'}: {e.reason}"
                # Homepage unreachable → don't waste time on the
                # follow-up paths.
                if path == "":
                    return ("unreachable", last_err)
                continue
            except (socket.timeout, TimeoutError):
                last_err = f"timeout on {path or '/'}"
                if path == "":
                    return ("unreachable", last_err)
                continue
            except Exception as e:
                last_err = f"{type(e).__name__} on {path or '/'}: {e}"
                continue
        # Finished all probes without a positive.
        return ("not_found", last_err or "none of the probes matched")

    def _route_sqlmap(self, tool):
        port, banner = self._require_service(tool.name, "http", "https")
        if port is None:
            return
        target = self._get_target()
        svc_low = (banner or "").lower()
        if any(p in svc_low for p in WINRM_BANNERS):
            self.app.terminal.write(
                "[!] SQLMAP skipped — port is WinRM, not HTTP.", "warn")
            return
        scheme = "https" if port in (443, 8443) else "http"
        # Prefer the session-known domain over the raw IP for the
        # default URL — vhost-routed apps return wrong content (or
        # nothing) when hit via IP. The user can still edit the URL
        # field manually and the DNS gate at launch time enforces
        # resolvability.
        domain = ""
        try:
            sess = self.app.session_manager.current
            if sess:
                domain = (getattr(sess, "target_domain", "") or "").strip()
        except Exception:
            pass
        host_for_url = domain if (domain and domain != target) else target
        base_url = f"{scheme}://{host_for_url}:{port}"

        # Try to surface URLs with ?param=value that earlier tools
        # (ffuf/gobuster/nikto/nuclei) may have already discovered —
        # those are the best sqlmap targets.
        suggested_urls = self._collect_sqlmap_candidates(base_url)

        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                  _btn_row, _btn, _safe_destroy)
        win = _make_win(self, "SQLmap — Scan Configuration", 680, 620)
        _title(win, "SQLMAP  —  Scan Configuration")
        _sub(win, "SQLmap needs something to inject into. "
                  "Pick a mode below.")

        # ── MODE selection ───────────────────────────────────────────────
        mode_var = ctk.StringVar(value="crawl" if not suggested_urls else "direct")

        mode_frame = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                   border_color=COLORS["border_dim"],
                                   border_width=1, corner_radius=4)
        mode_frame.pack(fill="x", padx=24, pady=(6, 4))
        ctk.CTkLabel(mode_frame, text="MODE",
                     font=_f("sm", True),
                     text_color=COLORS["text_green"]).pack(
            anchor="w", padx=10, pady=(6, 2))

        for val, lbl, desc in [
            ("direct", "Direct URL",
             "Test a specific URL that has a ?param=value (most precise)."),
            ("crawl",  "Crawl & forms",
             "Auto-discover endpoints + form params (start here if unsure)."),
            ("forms",  "Forms only",
             "Scan every <form> on the given page."),
            ("post",   "POST body",
             "Test a raw request body (JSON/XML/multipart)."),
        ]:
            row_m = ctk.CTkFrame(mode_frame, fg_color="transparent")
            row_m.pack(fill="x", padx=10, pady=2)
            ctk.CTkRadioButton(
                row_m, text=lbl, variable=mode_var, value=val,
                font=_f("md", True), width=130,
                text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                hover_color=COLORS["bg_card_hover"],
            ).pack(side="left")
            ctk.CTkLabel(row_m, text=desc, font=_f("sm"),
                         text_color=COLORS["text_dim"]
                         ).pack(side="left", padx=(8, 0))
        ctk.CTkFrame(mode_frame, fg_color="transparent", height=4
                     ).pack()

        # ── URL / BODY entry ──────────────────────────────────────────────
        default_url = suggested_urls[0] if suggested_urls else f"{base_url}/"
        url_var = ctk.StringVar(value=default_url)

        # Host dropdown — auto-rewrites the hostname in url_var on change.
        attach_host_dropdown(win, self.app, target, url_var,
                              pack_kwargs={"fill": "x",
                                           "padx": 26, "pady": (6, 0)})

        ctk.CTkLabel(win, text="URL", font=_f("sm", True),
                     text_color=COLORS["text_green"]
                     ).pack(anchor="w", padx=26, pady=(6, 0))

        entry = ctk.CTkEntry(win, textvariable=url_var,
                             font=_f("md"), height=34,
                             fg_color=COLORS["bg_card"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=3)
        entry.pack(fill="x", padx=24, pady=(2, 4))
        add_context_menu(entry)

        # ── Suggestions from prior findings ───────────────────────────────
        if suggested_urls:
            sug_frame = ctk.CTkFrame(win, fg_color="transparent")
            sug_frame.pack(fill="x", padx=24, pady=(0, 4))
            ctk.CTkLabel(sug_frame,
                         text="↓ discovered URLs (click to use):",
                         font=_f("xs"),
                         text_color=COLORS["text_dim"]
                         ).pack(anchor="w")
            for s in suggested_urls[:6]:
                ctk.CTkButton(
                    sug_frame, text=s, anchor="w",
                    height=22, font=_f("xs"),
                    fg_color=COLORS["bg_card"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_dim"], border_width=1,
                    text_color=COLORS["text_bright"],
                    corner_radius=2,
                    command=lambda u=s: url_var.set(u),
                ).pack(fill="x", pady=1)

        # ── Quick-add param buttons ───────────────────────────────────────
        qp_frame = ctk.CTkFrame(win, fg_color="transparent")
        qp_frame.pack(fill="x", padx=24, pady=(2, 4))
        ctk.CTkLabel(qp_frame, text="Quick-add param:",
                     font=_f("xs"),
                     text_color=COLORS["text_dim"]
                     ).pack(side="left", padx=(0, 6))

        def _append_param(p: str):
            cur = url_var.get().strip() or f"{base_url}/"
            if "?" in cur:
                if cur.endswith("?") or cur.endswith("&"):
                    cur += p.lstrip("?&")
                else:
                    cur += "&" + p.lstrip("?&")
            else:
                cur += "?" + p.lstrip("?&")
            url_var.set(cur)

        for p in ["id=1", "page=1", "user=1", "cat=1", "file=1", "q=test"]:
            ctk.CTkButton(
                qp_frame, text=f"?{p}", width=70, height=22,
                font=_f("xs"),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_green"], border_width=1,
                text_color=COLORS["text_green"],
                corner_radius=2,
                command=lambda pp=p: _append_param(pp),
            ).pack(side="left", padx=2)

        # ── Options ──────────────────────────────────────────────────────
        opt_frame = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                  border_color=COLORS["border_dim"],
                                  border_width=1, corner_radius=4)
        opt_frame.pack(fill="x", padx=24, pady=(6, 4))
        ctk.CTkLabel(opt_frame, text="ENUMERATION",
                     font=_f("sm", True),
                     text_color=COLORS["text_green"]
                     ).pack(anchor="w", padx=10, pady=(6, 2))

        dbs_var     = ctk.BooleanVar(value=True)
        tables_var  = ctk.BooleanVar(value=False)
        dump_var    = ctk.BooleanVar(value=False)
        cookies_var = ctk.BooleanVar(value=False)

        for var, lbl, hint in [
            (dbs_var,     "--dbs",
             "list databases"),
            (tables_var,  "--tables",
             "list tables (needs a DB)"),
            (dump_var,    "--dump",
             "dump rows — slow and noisy"),
            (cookies_var, "--cookie='PHPSESSID=...'",
             "carry session cookie"),
        ]:
            row_o = ctk.CTkFrame(opt_frame, fg_color="transparent")
            row_o.pack(fill="x", padx=10, pady=1)
            ctk.CTkCheckBox(
                row_o, text=lbl, variable=var,
                font=_f("sm"),
                text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                hover_color=COLORS["bg_card_hover"], width=220,
            ).pack(side="left")
            ctk.CTkLabel(row_o, text=hint, font=_f("xs"),
                         text_color=COLORS["text_dim"]
                         ).pack(side="left", padx=6)
        ctk.CTkFrame(opt_frame, fg_color="transparent", height=4
                     ).pack()

        # Level + Risk
        lr_frame = ctk.CTkFrame(win, fg_color="transparent")
        lr_frame.pack(fill="x", padx=24, pady=2)
        level_var = ctk.StringVar(value="1")
        risk_var  = ctk.StringVar(value="1")
        ctk.CTkLabel(lr_frame, text="Level:", font=_f("sm"),
                     text_color=COLORS["text_dim"]
                     ).pack(side="left", padx=(0, 4))
        ctk.CTkOptionMenu(lr_frame, values=["1","2","3","4","5"],
                          variable=level_var, width=60, height=24,
                          font=_f("sm"),
                          fg_color=COLORS["bg_card"],
                          button_color=COLORS["border_dim"],
                          text_color=COLORS["text_bright"],
                          ).pack(side="left", padx=(0, 12))
        ctk.CTkLabel(lr_frame, text="Risk:", font=_f("sm"),
                     text_color=COLORS["text_dim"]
                     ).pack(side="left", padx=(0, 4))
        ctk.CTkOptionMenu(lr_frame, values=["1","2","3"],
                          variable=risk_var, width=60, height=24,
                          font=_f("sm"),
                          fg_color=COLORS["bg_card"],
                          button_color=COLORS["border_dim"],
                          text_color=COLORS["text_bright"],
                          ).pack(side="left")

        # Extra args
        ctk.CTkLabel(win, text="Extra args (optional):",
                     font=_f("xs"),
                     text_color=COLORS["text_dim"]
                     ).pack(anchor="w", padx=26, pady=(6, 0))
        extra_var = ctk.StringVar(value="")
        extra_entry = ctk.CTkEntry(win, textvariable=extra_var,
                                    font=_f("sm"), height=28,
                                    fg_color=COLORS["bg_card"],
                                    text_color=COLORS["text_bright"],
                                    border_color=COLORS["border_dim"],
                                    border_width=1, corner_radius=3,
                                    placeholder_text="e.g. --tamper=space2comment --random-agent")
        extra_entry.pack(fill="x", padx=24, pady=(2, 6))
        add_context_menu(extra_entry)

        # Warning label (dynamic)
        warn_lbl = ctk.CTkLabel(win, text="", font=_f("xs"),
                                 text_color=COLORS["text_yellow"],
                                 wraplength=600, justify="left")
        warn_lbl.pack(anchor="w", padx=26, pady=(0, 2))

        def _build_cmd() -> tuple:
            """Return (cmd, warning) tuple. warning is "" if no issue."""
            url  = url_var.get().strip()
            mode = mode_var.get()
            if not url:
                return None, "URL is empty."

            parts = ["sqlmap", "--batch"]

            if mode == "direct":
                if "?" not in url:
                    return None, ("Direct mode needs a ?param=value in the URL. "
                                   "Use one of the quick-add buttons, or switch "
                                   "to 'Crawl & forms'.")
                parts += ["-u", f"'{url}'"]
            elif mode == "crawl":
                parts += ["-u", f"'{url}'", "--crawl=2", "--forms"]
            elif mode == "forms":
                parts += ["-u", f"'{url}'", "--forms"]
            elif mode == "post":
                # Drop a request skeleton file for the user to edit, then
                # re-run sqlmap -r on it. That's the standard workflow.
                os.makedirs(TMP_DIR, exist_ok=True)
                req_path = os.path.join(TMP_DIR, "sqlmap_req.txt")
                parts = [f"echo 'Edit {req_path} first, then rerun sqlmap -r {req_path}' && ",
                         f"printf 'POST / HTTP/1.1\\nHost: {target}\\nContent-Type: application/json\\n\\n{{\"id\":1}}\\n' > {req_path} && ",
                         f"sqlmap -r {req_path} --batch"]

            if dbs_var.get():    parts.append("--dbs")
            if tables_var.get(): parts.append("--tables")
            if dump_var.get():   parts.append("--dump")
            if cookies_var.get():
                parts.append("--cookie='PHPSESSID=REPLACE_ME'")
            lvl = level_var.get()
            rsk = risk_var.get()
            if lvl != "1": parts.append(f"--level={lvl}")
            if rsk != "1": parts.append(f"--risk={rsk}")

            extra = extra_var.get().strip()
            if extra:
                parts.append(extra)

            return " ".join(parts), ""

        def _preview():
            """Live preview of the command and any warning."""
            cmd, warn = _build_cmd()
            warn_lbl.configure(text=warn or "")
            if cmd:
                preview_lbl.configure(text=cmd,
                                       text_color=COLORS["text_green"])
            else:
                preview_lbl.configure(text="(incomplete)",
                                       text_color=COLORS["text_dim"])

        # Preview area
        ctk.CTkLabel(win, text="Command preview:",
                     font=_f("xs"),
                     text_color=COLORS["text_dim"]
                     ).pack(anchor="w", padx=26, pady=(4, 0))
        preview_lbl = ctk.CTkLabel(
            win, text="", font=_f("sm"),
            text_color=COLORS["text_green"],
            wraplength=620, justify="left", anchor="w")
        preview_lbl.pack(anchor="w", fill="x", padx=26, pady=(0, 6))

        # Wire updates on every widget change
        for v in (mode_var, url_var, extra_var, dbs_var, tables_var,
                  dump_var, cookies_var, level_var, risk_var):
            v.trace_add("write", lambda *_: _preview())
        _preview()

        def _run():
            cmd, warn = _build_cmd()
            if warn:
                warn_lbl.configure(text=warn)
                return
            if not cmd:
                return

            # DNS gate: if the URL's hostname is not the target IP and
            # doesn't resolve, offer /etc/hosts add or fall back to IP.
            from urllib.parse import urlparse, urlunparse
            try:
                parsed = urlparse(url_var.get().strip())
                host_in_url = (parsed.hostname or "").strip()
            except Exception:
                host_in_url = ""

            def _go():
                _safe_destroy(win)
                self._run_raw(tool, cmd)

            if host_in_url and host_in_url != target:
                from gui.widgets.card_common import verify_host_or_prompt

                def _proceed_with(final_host):
                    # Rewrite the URL/cmd if the user fell back to IP.
                    if final_host != host_in_url:
                        netloc = (f"{final_host}:{parsed.port}"
                                  if parsed.port else final_host)
                        new_url = urlunparse(parsed._replace(
                            netloc=netloc))
                        rebuilt = cmd.replace(url_var.get().strip(),
                                              new_url, 1)
                        _safe_destroy(win)
                        self._run_raw(tool, rebuilt)
                    else:
                        _go()

                verify_host_or_prompt(self, self.app, host_in_url,
                                      target, _proceed_with)
            else:
                _go()

        row = _btn_row(win)
        _btn(row, "RUN SQLMAP", _run, primary=True, w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _collect_sqlmap_candidates(self, base_url: str) -> list:
        """Scan Target Intel auto-findings for URLs that carry a ?param=.

        Populated from ffuf/gobuster/nikto/nuclei findings when those tools
        have already run. Returns a de-duplicated list of URL strings
        sharing base_url's host.
        """
        out = []
        try:
            intel = self.app.target_intel
            findings = list(getattr(intel, "_auto_findings", []) or [])
        except Exception:
            return out

        host = base_url.split("//", 1)[-1].split("/", 1)[0]
        seen = set()
        import re as _re
        url_re = _re.compile(r"https?://[^\s'\"<>()]+\?[^\s'\"<>()]+")
        param_re = _re.compile(r"[?&][A-Za-z_]\w*=")
        for f in findings:
            blob = (f.get("description") or "") + " " + (f.get("title") or "")
            for m in url_re.findall(blob):
                if host not in m or m in seen:
                    continue
                if not param_re.search(m):
                    continue
                seen.add(m)
                out.append(m)
        return out[:12]

