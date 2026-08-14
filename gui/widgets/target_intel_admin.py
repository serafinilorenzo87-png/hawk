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
HAWK - Target Intel Widget v1.0
- Nmap vuln scripts findings → auto-populate intel
- Per-finding MSF launch button with pre-configured editable dialog
- OS Detection merge (don't overwrite existing ports)
- Single nonstandard port popup (flag)
- Spinner on all operations
"""

import customtkinter as ctk
import tkinter as tk
import os
import re
import time
import threading
import subprocess
import shlex
import json
import socket
import tempfile
import shutil
from datetime import datetime

from gui.widgets.target_intel_common import *

class TargetIntelAdminMixin:
    def _change_service_dialog(self, port: int, proto: str,
                                current_svc: str, banner: str, port_idx: int):
        """
        Dialog to change the service type for a port.
        Shown after netcat or manual discovery reveals wrong service.
        """
        from gui.dialogs import _make_win, _note_box, _btn_row, _btn, _safe_destroy

        win = _make_win(self, f"Change Service — Port {port}", 540, 380)
        ctk.CTkLabel(win, text=f"Change Service on Port {port}",
                     font=_f("xl", True),
                     text_color=COLORS["text_bright"]).pack(pady=(14,6))

        _note_box(win,
                  f"Current: {proto.upper()} {port} → {current_svc}\n"
                  f"Banner:  {banner or 'none'}\n\n"
                  "Select the actual service you discovered:",
                  COLORS["text_yellow"])

        SERVICES = [
            "http", "https", "ftp", "ssh", "smb", "winrm",
            "rdp", "smtp", "mysql", "mssql", "ldap", "vnc",
            "telnet", "snmp", "redis", "mongodb", "postgresql",
            "unknown",
        ]

        svc_var = ctk.StringVar(value=current_svc.lower())

        # Service buttons grid — with live highlight as user clicks
        grid = ctk.CTkFrame(win, fg_color="transparent")
        grid.pack(fill="x", padx=24, pady=8)
        svc_buttons = {}

        def _refresh_highlight(*_):
            sel = svc_var.get()
            for s, b in svc_buttons.items():
                on = (s == sel)
                b.configure(
                    fg_color=COLORS["border_green"] if on else COLORS["bg_card"],
                    border_color=COLORS["border_green"] if on else COLORS["border_dim"],
                    text_color=COLORS["bg_primary"] if on else COLORS["text_dim"],
                )

        for i, svc in enumerate(SERVICES):
            btn = ctk.CTkButton(
                grid, text=svc.upper(),
                width=100, height=28,
                font=_f("sm", True),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_dim"], border_width=1,
                text_color=COLORS["text_dim"],
                corner_radius=3,
                command=lambda s=svc: svc_var.set(s),
            )
            btn.grid(row=i//4, column=i%4, padx=4, pady=3, sticky="ew")
            svc_buttons[svc] = btn
        for col in range(4):
            grid.grid_columnconfigure(col, weight=1)

        svc_var.trace_add("write", _refresh_highlight)
        _refresh_highlight()

        # Custom entry
        ctk.CTkLabel(win, text="Or type custom:",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=24, pady=(8,2))
        custom_var = ctk.StringVar(value="")
        custom_e = ctk.CTkEntry(win, textvariable=custom_var,
                                placeholder_text="e.g. redis, mongodb...",
                                font=_f("md"), height=30,
                                fg_color=COLORS["bg_card"],
                                text_color=COLORS["text_bright"],
                                border_color=COLORS["border_dim"], border_width=1,
                                corner_radius=3)
        custom_e.pack(fill="x", padx=24, pady=(0,8))

        def _apply():
            new_svc = custom_var.get().strip() or svc_var.get()
            if self._fp and port_idx < len(self._fp.open_ports):
                p, pr, _, b = self._fp.open_ports[port_idx]
                self._fp.open_ports[port_idx] = (p, pr, new_svc,
                                                  f"[CHANGED: {new_svc}]")
            _safe_destroy(win)
            self.app.terminal.write(
                f"  [+] Port {port} service updated: {current_svc} → {new_svc}",
                "success")
            # add_auto_finding already schedules an auto_findings re-render
            # via _render_auto_findings().  The port table lives inside
            # the fingerprint section, so we also need to refresh that —
            # but only the fingerprint subtree, not the whole scroll.
            self.add_auto_finding(
                title=f"Port {port} — {new_svc.upper()} confirmed",
                description=f"Service manually identified as {new_svc} on port {port}.",
                severity="info", source="manual")
            self._rerender_section("fingerprint")

        row = _btn_row(win)
        _btn(row, "APPLY", _apply, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _edit_os_dialog(self):
        """Dialog to manually set/correct OS fingerprint."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn

        OS_CATEGORIES = {
            "Windows Endpoint": ["Windows XP","Windows Vista","Windows 7","Windows 8","Windows 8.1","Windows 10 1507","Windows 10 1511","Windows 10 1607","Windows 10 1703","Windows 10 1709","Windows 10 1803","Windows 10 1809","Windows 10 1903","Windows 10 1909","Windows 10 2004","Windows 10 20H2","Windows 10 21H1","Windows 10 21H2","Windows 10 22H2","Windows 11 21H2","Windows 11 22H2","Windows 11 23H2","Windows 11 24H2"],
            "Windows Server":   ["Windows Server 2003","Windows Server 2003 R2","Windows Server 2008","Windows Server 2008 R2","Windows Server 2012","Windows Server 2012 R2","Windows Server 2016","Windows Server 2019","Windows Server 2022","Windows Server 2025"],
            "Linux Desktop":    ["Ubuntu 18.04","Ubuntu 20.04","Ubuntu 22.04","Ubuntu 24.04","Debian 10","Debian 11","Debian 12","Kali Linux","Parrot OS","Fedora 38","Fedora 39","Fedora 40","Arch Linux","Manjaro","Linux Mint 21","Linux Mint 22","Pop!_OS 22.04"],
            "Linux Server":     ["Ubuntu Server 18.04","Ubuntu Server 20.04","Ubuntu Server 22.04","Ubuntu Server 24.04","Debian Server 10","Debian Server 11","Debian Server 12","CentOS 7","CentOS 8","RHEL 8","RHEL 9","Rocky Linux 8","Rocky Linux 9","AlmaLinux 8","AlmaLinux 9","openSUSE Leap 15","SUSE Linux Enterprise 15","Alpine Linux"],
            "macOS":            ["macOS Mojave (10.14)","macOS Catalina (10.15)","macOS Big Sur (11)","macOS Monterey (12)","macOS Ventura (13)","macOS Sonoma (14)","macOS Sequoia (15)"],
            "Other":            ["Android","iOS","FreeBSD","OpenBSD","Unknown"],
        }

        win = _make_win(self, "Edit OS Fingerprint", 560, 420)
        ctk.CTkLabel(win, text="Edit OS Fingerprint",
                     font=_f("xl", True),
                     text_color=COLORS["text_bright"]).pack(pady=(14,8))

        # Current values
        current_platform = (self._fp.platform or "").capitalize() if self._fp else ""
        current_version  = (self._fp.version  or "") if self._fp else ""

        # Category selection
        cat_var = ctk.StringVar(value="Windows Server")
        for cat in OS_CATEGORIES:
            if current_platform.lower() in cat.lower():
                cat_var.set(cat)
                break

        cf = ctk.CTkFrame(win, fg_color="transparent")
        cf.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(cf, text="Category:", font=_f("md"),
                     text_color=COLORS["text_dim"],
                     width=100, anchor="w").pack(side="left")
        cat_menu = ctk.CTkOptionMenu(cf,
            values=list(OS_CATEGORIES.keys()),
            variable=cat_var,
            width=320, height=30, font=_f("md"),
            fg_color=COLORS["bg_card"], button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_dim"], corner_radius=3,
            command=lambda _: _update_versions())
        cat_menu.pack(side="left", padx=8)

        # Version selection
        ver_var = ctk.StringVar(value=current_version or OS_CATEGORIES[cat_var.get()][0])
        vf = ctk.CTkFrame(win, fg_color="transparent")
        vf.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(vf, text="Version:", font=_f("md"),
                     text_color=COLORS["text_dim"],
                     width=100, anchor="w").pack(side="left")
        ver_menu = ctk.CTkOptionMenu(vf,
            values=OS_CATEGORIES[cat_var.get()],
            variable=ver_var,
            width=320, height=30, font=_f("md"),
            fg_color=COLORS["bg_card"], button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_dim"], corner_radius=3)
        ver_menu.pack(side="left", padx=8)

        def _update_versions():
            versions = OS_CATEGORIES.get(cat_var.get(), [])
            ver_menu.configure(values=versions)
            ver_var.set(versions[0] if versions else "")

        # Confidence
        conf_var = ctk.StringVar(value=str(self._fp.confidence or 80) if self._fp else "80")
        conf_f = ctk.CTkFrame(win, fg_color="transparent")
        conf_f.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(conf_f, text="Confidence:", font=_f("md"),
                     text_color=COLORS["text_dim"],
                     width=100, anchor="w").pack(side="left")
        ctk.CTkEntry(conf_f, textvariable=conf_var,
                     width=80, height=30, font=_f("md"),
                     fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                     border_color=COLORS["border_dim"], border_width=1,
                     corner_radius=3).pack(side="left", padx=8)
        ctk.CTkLabel(conf_f, text="%", font=_f("md"),
                     text_color=COLORS["text_dim"]).pack(side="left")

        def _save():
            cat     = cat_var.get()
            version = ver_var.get()
            try:
                confidence = int(conf_var.get())
            except Exception:
                confidence = 80

            # Determine platform from category
            if "Windows" in cat:
                platform = "windows"
            elif "Linux" in cat or "macOS" in cat:
                platform = "linux" if "Linux" in cat else "macos"
            else:
                platform = "unknown"

            if self._fp is None:
                from modules.exploit_suggester import OSFingerprint
                self._fp = OSFingerprint()

            self._fp.platform   = platform
            self._fp.version    = version
            self._fp.confidence = confidence
            self._fp.ambiguous  = False

            # Update session
            if self.app.session_manager.current:
                self.app.session_manager.current.detected_os = version
                self.app.session_manager.current.save()

            _safe_destroy(win)
            # Manual OS edit affects only the fingerprint section.
            self._rerender_section("fingerprint")
            self._blink_start()
            self.app.terminal.write(
                f"  [+] OS updated: {version} (confidence: {confidence}%)", "success")

        row = _btn_row(win)
        _btn(row, "SAVE", _save, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _check_nonstandard_ports(self, fp):
        """Check once per session for nonstandard ports."""
        from utils.config import SERVICE_PORT_MAP
        for port, proto, service, banner in fp.open_ports:
            svc_clean = service.lower().split("/")[0]
            default   = SERVICE_PORT_MAP.get(svc_clean)
            if default and port != default:
                self.after(800, lambda p=port, s=svc_clean:
                           self._netcat_verify(p, s))
                break  # only first one

    def _toggle_show_all(self):
        # "Show all" toggle only affects the exploits section (re-filters
        # which exploits are rendered) — no need to touch fingerprint or
        # findings.
        if "exploits" in getattr(self, "_section_rows", {}):
            self._rerender_section("exploits")
        else:
            self._render_all()

    def _is_fp_too_generic(self):
        """Return (True, reason) when the current fingerprint would produce
        a torrent of irrelevant CVE/exploit hits. We refuse to treat a bare
        platform ('windows') as a usable search key — nmap frequently says
        'Windows 98%' with no build number and that alone matches every
        Windows CVE from the past 25 years."""
        fp = self._fp
        if not fp:
            return True, "No OS fingerprint yet."
        plat = (fp.platform or "").strip().lower()
        ver  = (fp.version  or "").strip()
        if not plat or plat in ("unknown", ""):
            return True, "Platform is unknown."
        if getattr(fp, "ambiguous", False):
            return True, "nmap returned ambiguous matches (multiple OSes)."
        if not ver:
            return True, f"Only the family is known ('{plat}') — no version."
        # Version equals the family (e.g. platform='windows', version='windows')
        if ver.lower() == plat:
            return True, f"Version is generic ('{ver}')."
        # Version is a very short family keyword with no build/release.
        toklower = ver.lower()
        if toklower in ("windows", "linux", "unix", "macos", "bsd"):
            return True, f"Version is generic ('{ver}')."
        return False, ""

    def _show_fp_warning_dialog(self, action_label, on_continue):
        """Warn the user that the current fingerprint is too generic to
        produce meaningful CVE/exploit hits, and offer three choices:
          • EDIT FINGERPRINT  → open the same dialog used from Target Intel.
          • SEARCH ANYWAY     → invoke `on_continue()` with current fp.
          • CANCEL            → abort.
        Returns nothing; the caller must not run the search after calling
        this method — `on_continue` fires it from within the dialog."""
        from gui.dialogs import (_make_win, _title, _note_box,
                                  _btn_row, _btn, _safe_destroy)

        fp = self._fp
        is_generic, reason = self._is_fp_too_generic()
        current = "(none)"
        if fp:
            if fp.platform or fp.version:
                current = (f"{fp.platform or '?'} "
                           f"{fp.version or ''}".strip()
                           + f"  ({fp.confidence or 0}% confidence)")

        win = _make_win(self, "Fingerprint too generic", 620, 520)
        _title(win, f"⚠  {action_label} — OS fingerprint is too generic")

        _note_box(win,
                  f"Current fingerprint:\n  {current}\n\n"
                  f"Problem: {reason}\n\n"
                  "Running CVE / exploit search with this level of detail\n"
                  "will return thousands of loosely-related results\n"
                  "(every Windows CVE since 2000, every Linux kernel bug,\n"
                  "etc.).  Most of those won't apply to this host.\n\n"
                  "Recommended: refine the fingerprint first.  Use NMAP\n"
                  "Service+Scripts / Vuln Scripts for deeper OS detection,\n"
                  "or set the version manually (e.g. 'Windows Server 2019',\n"
                  "'Ubuntu 22.04') via the editor below.",
                  COLORS["text_yellow"])

        _note_box(win,
                  "Tips to nail the version:\n"
                  "  • nmap -sV -sC -O   → banner grab + OS detection.\n"
                  "  • nmap --script smb-os-discovery -p445   → SMB banner.\n"
                  "  • nxc smb <ip>            → domain + build number.\n"
                  "  • curl -I http(s)://<ip>   → Server header for web.\n"
                  "  • The Credential Store / banners tab often leaks it.",
                  COLORS["border_dim"])

        def _edit_then_back():
            _safe_destroy(win)
            # Open the canonical edit dialog — after save, let the user
            # re-click SEARCH.  We don't auto-continue because they may
            # want to tweak more than just the OS.
            self._edit_os_dialog()
            self.app.terminal.write(
                f"  [*] {action_label} paused — refine the fingerprint "
                "and click the button again.", "dim")

        def _proceed():
            _safe_destroy(win)
            self.app.terminal.write(
                f"  [!] {action_label} running with generic fingerprint "
                "— expect noisy results.", "warn")
            try:
                on_continue()
            except Exception as e:
                self.app.terminal.write(
                    f"  [!] Search failed to start: {e}", "error")

        row = _btn_row(win)
        _btn(row, "EDIT FINGERPRINT", _edit_then_back, primary=True, w=180)
        _btn(row, "SEARCH ANYWAY",    _proceed,       warn=True,    w=150)
        _btn(row, "CANCEL",           lambda: _safe_destroy(win))

    def _show_search_picker(self, action_label: str, placeholder: str,
                              tip: str, run_fp, run_custom,
                              run_web=None,
                              default_keyword: str = "",
                              default_mode: str = ""):
        """Three-mode picker for SEARCH EXPLOITS / SEARCH CVEs.

        Mode 1 — "OS Fingerprint  (queries: NVD)":
            Runs the existing fingerprint-driven NVD search.
        Mode 2 — "Custom keywords  (queries: NVD)":
            User types keywords; queries the NVD API.
        Mode 3 — "Custom keywords on web  (Google / GitHub /
                  ExploitDB / Packet Storm)":
            Opens 4 browser tabs with the keywords pre-filled.
            Best for finding public PoCs / writeups, not structured
            CVE data.

        Parameters
        ----------
        action_label, placeholder, tip
            Same as before — header text + entry hint.
        run_fp : callable
            Called when the user picks the fingerprint mode.
        run_custom : callable[[str], None]
            Called with the typed keyword string in NVD-custom mode.
        run_web : callable[[str], None] or None
            Called with the typed keyword string in web-custom mode.
            When None, mode 3 is hidden (callers that don't make
            sense on the web — e.g. EXPLOIT search routes through
            local MSF — pass None).
        default_keyword : str
            Pre-fills the entry.  Used by AI-OPS findings that
            invoke the picker with ``<tool> <version>`` already
            ready.
        default_mode : str
            One of "fp" / "custom" / "web" / "" (auto).  When
            non-empty, that radio is selected on open.  Defaults to
            "fp" when a fingerprint is present, else "custom".
        """
        from gui.dialogs import (_make_win, _title, _note_box,
                                  _btn_row, _btn, _safe_destroy)
        from utils.clipboard import add_context_menu

        fp_summary = ""
        fp_available = bool(self._fp)
        if fp_available:
            fp_summary = self._fp.summary() or "(empty fingerprint)"

        # Pick initial mode.  When the caller passed a default and
        # the corresponding mode is wired, honour it.
        if default_mode in ("fp", "custom", "web"):
            initial_mode = default_mode
            if initial_mode == "fp" and not fp_available:
                initial_mode = "custom"
            if initial_mode == "web" and run_web is None:
                initial_mode = "custom"
        else:
            initial_mode = "fp" if fp_available else "custom"

        win = _make_win(self, action_label, 660, 460)
        _title(win, f"🔍  {action_label}")

        mode_var = ctk.StringVar(value=initial_mode)
        kw_var   = ctk.StringVar(value=default_keyword or "")

        # ── Radio 1: fingerprint mode ───────────────────────────────
        fp_frame = ctk.CTkFrame(win, fg_color="transparent")
        fp_frame.pack(fill="x", padx=24, pady=(8, 4))
        fp_radio = ctk.CTkRadioButton(
            fp_frame, text="", variable=mode_var, value="fp",
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            state=("normal" if fp_available else "disabled"))
        fp_radio.pack(side="left", padx=(0, 8))
        fp_text = (
            f"OS Fingerprint  (queries: NVD)  —  {fp_summary}"
            if fp_available else
            "OS Fingerprint  (queries: NVD)  —  "
            "(no scan data; run NMAP first)")
        ctk.CTkLabel(
            fp_frame, text=fp_text, font=_f("md", True),
            text_color=(COLORS["text_bright"] if fp_available
                        else COLORS["text_muted"]),
            anchor="w", justify="left", wraplength=560
        ).pack(side="left", fill="x", expand=True)

        # ── Radio 2: custom keywords (NVD) ──────────────────────────
        custom_frame = ctk.CTkFrame(win, fg_color="transparent")
        custom_frame.pack(fill="x", padx=24, pady=(8, 2))
        custom_radio = ctk.CTkRadioButton(
            custom_frame, text="", variable=mode_var, value="custom",
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"])
        custom_radio.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(
            custom_frame, text="Custom keywords  (queries: NVD)",
            font=_f("md", True),
            text_color=COLORS["text_bright"], anchor="w"
        ).pack(side="left", fill="x", expand=True)

        # ── Radio 3 (optional): custom keywords on web ──────────────
        if run_web is not None:
            web_frame = ctk.CTkFrame(win, fg_color="transparent")
            web_frame.pack(fill="x", padx=24, pady=(8, 2))
            web_radio = ctk.CTkRadioButton(
                web_frame, text="", variable=mode_var, value="web",
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"])
            web_radio.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                web_frame,
                text=("Custom keywords on web  (opens Google / GitHub "
                      "Advisories / ExploitDB / Packet Storm)"),
                font=_f("md", True),
                text_color=COLORS["text_bright"],
                anchor="w", justify="left", wraplength=560
            ).pack(side="left", fill="x", expand=True)

        # Single keyword entry, shared between Modes 2 and 3.
        kw_entry = ctk.CTkEntry(
            win, textvariable=kw_var,
            placeholder_text=placeholder,
            font=_f("md"), height=32,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["text_cyan"], border_width=2,
            corner_radius=4)
        kw_entry.pack(fill="x", padx=48, pady=(2, 4))
        add_context_menu(kw_entry)

        ctk.CTkLabel(
            win, text=f"  {tip}", font=_f("xs"),
            text_color=COLORS["text_dim"],
            anchor="w", wraplength=580, justify="left"
        ).pack(fill="x", padx=48, pady=(0, 8))

        # When the user clicks into the entry, snap to whichever
        # custom mode is currently selected — never override their
        # explicit "web" selection by demoting it to "custom".
        def _on_entry_focus(_e=None):
            if mode_var.get() not in ("custom", "web"):
                mode_var.set("custom")
        kw_entry.bind("<FocusIn>", _on_entry_focus)
        kw_entry.bind("<KeyPress>", _on_entry_focus)

        def _go():
            mode = mode_var.get()
            if mode == "fp":
                if not fp_available:
                    self.app.terminal.write(
                        "  [!] No fingerprint available yet — type "
                        "keywords or run a scan first.", "warn")
                    return
                _safe_destroy(win)
                run_fp()
                return
            kw = (kw_var.get() or "").strip()
            if not kw:
                self.app.terminal.write(
                    "  [!] Type at least one keyword.", "warn")
                return
            _safe_destroy(win)
            if mode == "web" and run_web is not None:
                run_web(kw)
                return
            run_custom(kw)

        row = _btn_row(win)
        _btn(row, "RUN",    _go, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

        # Focus the entry on open so the user can just start typing —
        # but if a default keyword was passed, place the cursor at end
        # so they can edit / extend without overwriting.
        try:
            kw_entry.focus_set()
            if default_keyword:
                kw_entry.icursor("end")
        except Exception:
            pass

    # NOTE: _refresh_cve_kb (UI handler for the old "🔄 REFRESH CVE DB"
    # button) was removed.  The button itself is gone from
    # target_intel_widget.py.  Library-level helpers — KB_REMOTE_URL,
    # fetch_remote, cache_path — stay in utils/cve_knowledge.py as
    # dormant API for forks that point HAWK at their own remote CVE
    # KB endpoint.  The single-operator workflow uses SEARCH CVE
    # (web mode + NVD modes) instead.

    def _start_exploit_search(self):
        if self._search_running:
            return
        # Show the two-mode picker.  The fp-mode callback applies the
        # existing "too generic" gate; the custom-mode callback bypasses
        # it because the user is explicitly typing the search terms.
        def _run_fp_then_check():
            if not self._fp:
                hint = ("[!] No intel extracted yet. Try NMAP Service+"
                        "Scripts or Vuln Scripts."
                        if _nmap_already_run(self.app)
                        else "[!] No scan data. Run NMAP Quick first.")
                self.app.terminal.write(hint, "error")
                return
            is_generic, _ = self._is_fp_too_generic()
            if is_generic:
                self._show_fp_warning_dialog(
                    "SEARCH EXPLOITS", self._run_exploit_search)
                return
            self._run_exploit_search()

        self._show_search_picker(
            action_label="SEARCH EXPLOITS",
            placeholder="e.g.  vsftpd 2.3.4    eternalblue smb    "
                        "apache struts    log4shell",
            tip=("Tip: software name + version, MSF alias (eternalblue, "
                 "log4shell), or product name. Searches local Metasploit "
                 "modules — keep it specific to avoid noise."),
            run_fp=_run_fp_then_check,
            run_custom=self._run_exploit_search_custom)

    def _run_exploit_search(self):
        """Actual exploit-search execution — extracted so the fingerprint
        warning dialog can invoke it via 'SEARCH ANYWAY'."""
        self._search_running = True
        self._search_btn.configure(text="SEARCHING...", state="disabled")
        self.app.terminal.section("EXPLOIT SEARCH  ·  msfconsole")
        self.app.terminal.write(f"  Target: {self._fp.summary()}", "info")
        open_ports = [p for p,_,_,_ in self._fp.open_ports]
        self.app.terminal.write(
            f"  Open ports: {', '.join(str(p) for p in open_ports)}", "dim")
        from modules.exploit_suggester import ExploitQueryBuilder, MsfSearchRunner
        queries = ExploitQueryBuilder().build_queries(self._fp)
        self.app.terminal.write(
            f"  Building {len(queries)} port-aware queries...", "dim")
        self._spinner_start(f"Searching {len(queries)} exploit categories...")

        def _progress(idx, total, label):
            self.after(0, lambda: [
                self._progress_update(idx+1, total, label),
                self.app.terminal.write(f"  [{idx+1}/{total}] {label}...", "dim"),
            ])

        def _done(exploits):
            self.after(0, lambda: self._finish_exploit_search(
                exploits, runner.errors))

        runner = MsfSearchRunner(progress_callback=_progress,
                                 done_callback=_done)
        runner.search(queries, self._fp)

    def _run_exploit_search_custom(self, keywords: str):
        """Custom-keyword variant of _run_exploit_search.

        Bypasses the OS fingerprint entirely.  Builds a single MSF
        ``search type:exploit <keywords>`` query and runs it through
        ``MsfSearchRunner`` with ``fp=None`` so the port-relevance
        filter is skipped (would otherwise drop hits that don't match
        any open port — defeats the purpose of a free-text search).
        """
        self._search_running = True
        self._search_btn.configure(text="SEARCHING...", state="disabled")
        self.app.terminal.section("EXPLOIT SEARCH  ·  msfconsole (custom)")
        self.app.terminal.write(f"  Keywords: {keywords}", "info")
        from modules.exploit_suggester import MsfSearchRunner
        # Tuple shape matches ExploitQueryBuilder.build_queries:
        # (label, msf-cmd, service, ports).
        queries = [(
            f"Custom: {keywords}",
            f"search type:exploit {keywords}",
            "custom",
            [],
        )]
        self._spinner_start("Searching MSF modules…")

        def _progress(idx, total, label):
            self.after(0, lambda: [
                self._progress_update(idx + 1, total, label),
                self.app.terminal.write(
                    f"  [{idx+1}/{total}] {label}...", "dim"),
            ])

        def _done(exploits):
            self.after(0, lambda: self._finish_exploit_search(
                exploits, runner.errors))

        # fp=None → MsfSearchRunner skips _filter_by_ports so user-typed
        # keywords aren't dropped just because they don't map to an
        # open port on the current target.
        runner = MsfSearchRunner(
            progress_callback=_progress, done_callback=_done)
        runner.search(queries, fp=None)

    def _finish_exploit_search(self, exploits, errors):
        """Render the results and — crucially — report a FAILED search.

        A missing msfconsole or a 60s timeout used to be swallowed
        inside MsfSearchRunner and reached the operator as a
        successful search with zero results: "0 exploits match open
        ports" for a target that was never actually searched.
        """
        for msg in (errors or []):
            self.app.terminal.write(f"  [!] EXPLOIT SEARCH: {msg}",
                                    "error")
        if errors and not exploits:
            self.app.terminal.write(
                "  [!] The search did NOT complete — the empty result "
                "below says nothing about the target.", "error")
        self.add_exploit_results(exploits)

    def _start_cve_search(self):
        # Show the two-mode picker.  Fp-mode uses the existing flow;
        # custom-mode bypasses fingerprint-based keyword extraction.
        def _run_fp_then_check():
            if not self._fp or not self._fp.open_ports:
                hint = ("[!] Scan ran but no open ports found. Try NMAP "
                        "Full (-p-) or masscan for wider coverage."
                        if _nmap_already_run(self.app)
                        else "[!] No port data. Run NMAP Quick first.")
                self.app.terminal.write(hint, "error")
                return
            is_generic, _ = self._is_fp_too_generic()
            if is_generic:
                self._show_fp_warning_dialog(
                    "SEARCH CVEs", self._run_cve_search)
                return
            self._run_cve_search()

        self._show_search_picker(
            action_label="SEARCH CVEs",
            placeholder="e.g.  apache 2.4.49    openssl 1.1.1k    "
                        "windows server 2008    sudo 1.8.27",
            tip=("Tip: software + version (most precise) or product "
                 "name. NVD modes query the structured CVE database "
                 "(score ≥ 7.0).  Web mode opens Google / GitHub "
                 "Advisories / ExploitDB / Packet Storm in your "
                 "default browser — best for finding public PoCs and "
                 "writeups."),
            run_fp=_run_fp_then_check,
            run_custom=self._run_cve_search_custom,
            run_web=self._run_cve_search_on_web)

    def _run_cve_search_custom(self, keywords: str):
        """Custom-keyword variant of _run_cve_search.

        Splits the user input on commas / whitespace into individual
        terms (max 5, mirroring the NVD-rate-limit budget the
        fingerprint flow uses) and queries each via
        ``cve_lookup.search_async``.  Bypasses the platform/banner
        keyword extraction entirely.
        """
        self._cve_btn.configure(text="SEARCHING...", state="disabled")
        self.app.terminal.section("CVE LOOKUP  ·  NVD API (custom)")
        from utils.cve_lookup import get_client, search_async
        client    = get_client()
        rate_note = "50 req/30s" if client.has_key() else "5 req/30s"
        self.app.terminal.write(f"  Rate limit: {rate_note}", "dim")
        # Keep multi-word phrases together when separated by commas.
        # "apache 2.4.49, sudo 1.8.27" → ["apache 2.4.49", "sudo 1.8.27"].
        # Plain whitespace → single phrase; user can use commas to split
        # into multiple queries when they want explicit separation.
        if "," in keywords:
            kw_list = [k.strip() for k in keywords.split(",") if k.strip()]
        else:
            kw_list = [keywords.strip()] if keywords.strip() else []
        kw_list = kw_list[:5]
        if not kw_list:
            self._cve_btn.configure(text="SEARCH CVEs", state="normal")
            self.app.terminal.write(
                "  [!] No usable keywords parsed.", "warn")
            return
        self._spinner_start(
            f"Querying NVD API for {len(kw_list)} keyword(s)…")
        all_cves  = []
        remaining = [len(kw_list)]

        def _got(results):
            all_cves.extend(results)
            remaining[0] -= 1
            if remaining[0] <= 0:
                self.after(0, lambda: self._show_cves(all_cves))

        for kw in kw_list:
            self.app.terminal.write(f"  Searching: {kw}", "dim")
            search_async(kw, _got, min_score=7.0)

    def _run_cve_search_on_web(self, keywords: str):
        """Web-search variant of CVE lookup: opens 4 browser tabs
        (Google, GitHub Security Advisories, ExploitDB, Packet Storm)
        with the operator-typed keywords pre-filled.

        Use this when the structured NVD entry isn't enough — Google
        and GitHub surface community PoCs / blog write-ups that NVD
        doesn't index.  Implementation is `webbrowser.open_new_tab`
        (Python stdlib, zero new deps); the BROWSER env var or the
        OS default determines which browser opens.
        """
        import webbrowser
        from utils.cve_knowledge import cve_web_search_urls
        urls = cve_web_search_urls(keywords)
        if not urls:
            self.app.terminal.write(
                "  [!] No usable keywords for web search.", "warn")
            return
        self.app.terminal.section("CVE WEB SEARCH  ·  browser")
        self.app.terminal.write(
            f"  Keywords: {keywords}", "info")
        opened = 0
        for label, url in urls:
            try:
                webbrowser.open_new_tab(url)
                opened += 1
                self.app.terminal.write(
                    f"  → {label:<18}  {url}", "dim")
            except Exception as e:
                self.app.terminal.write(
                    f"  [!] {label} open failed: {e}", "warn")
        if opened == 0:
            self.app.terminal.write(
                "  [!] Could not open any browser tab — check that a "
                "browser is installed and BROWSER env / xdg-open works.",
                "error")
        else:
            self.app.terminal.write(
                f"  [+] Opened {opened}/{len(urls)} browser tab(s).",
                "success")

    def _run_cve_search(self):
        """Actual CVE search — extracted so the fingerprint warning dialog
        can invoke it via 'SEARCH ANYWAY'."""
        self._cve_btn.configure(text="SEARCHING...", state="disabled")
        self.app.terminal.section("CVE LOOKUP  ·  NVD API")
        self._spinner_start("Querying NVD API...")
        from utils.cve_lookup import get_client, search_async
        client    = get_client()
        rate_note = "50 req/30s" if client.has_key() else "5 req/30s"
        self.app.terminal.write(f"  Rate limit: {rate_note}", "dim")
        keywords  = []
        if self._fp.platform and self._fp.version:
            keywords.append(
                f"Windows Server {self._fp.version.upper()}"
                if "windows" in self._fp.platform.lower()
                else f"Linux {self._fp.version}")
        # Generic service names that produce too many irrelevant CVEs
        GENERIC_SERVICES = {
            "http", "https", "ssh", "ftp", "smtp", "dns", "snmp",
            "telnet", "pop3", "imap", "rdp", "smb", "netbios",
            "microsoft-ds", "netbios-ssn", "msrpc", "epmap",
            "tcpwrapped", "unknown", "", "ssl", "tcp",
        }
        for port, proto, service, banner in self._fp.open_ports:
            if banner:
                sw = re.search(r'([A-Za-z][\w-]+)[/ ](\d+[\d.]+)', banner)
                if sw:
                    name = sw.group(1)
                    # Skip generic protocol names in banners
                    if name.lower() not in GENERIC_SERVICES:
                        keywords.append(f"{name} {sw.group(2)}")
            svc = service.lower().split("/")[0]
            if svc not in GENERIC_SERVICES:
                keywords.append(svc)
        all_cves  = []
        remaining = [min(len(keywords), 5)]

        def _got(results):
            all_cves.extend(results)
            remaining[0] -= 1
            if remaining[0] <= 0:
                self.after(0, lambda: self._show_cves(all_cves))

        for kw in keywords[:5]:
            self.app.terminal.write(f"  Searching: {kw}", "dim")
            search_async(kw, _got, min_score=7.0)

        if not keywords:
            self._spinner_stop("No keywords found")
            self._cve_btn.configure(text="SEARCH CVEs", state="normal")

    def _show_cves(self, cves):
        self._cve_btn.configure(text="SEARCH CVEs", state="normal")
        seen, unique = set(), []
        for c in cves:
            if c.cve_id not in seen:
                seen.add(c.cve_id); unique.append(c)
        unique.sort(key=lambda c: -c.cvss_score)
        self._spinner_stop(f"Found {len(unique)} CVEs (score ≥ 7.0)")
        self.app.terminal.write(f"  [+] {len(unique)} CVEs found", "success")
        for cve in unique[:10]:
            self.app.terminal.write(
                f"  [{cve.severity} {cve.cvss_score}]  {cve.cve_id}", "finding")
            self.app.terminal.write(f"     {cve.short_desc(100)}", "dim")
            if cve.cvss_score >= 7.0:
                sev = ("critical" if cve.cvss_score >= 9.0 else
                       "high" if cve.cvss_score >= 7.0 else "medium")
                self.add_auto_finding(
                    title=cve.cve_id,
                    description=cve.short_desc(150),
                    severity=sev, source="NVD API")
        self._blink_start()

    def _blink_start(self, count_as_new: bool = True):
        """Pulse the Target Intel tab to draw the user's attention.

        The "(N new)" badge always mirrors the number of unread (fresh)
        findings — see _refresh_new_badge — so it can never drift from the
        highlighted rows.  The old incrementing counter did drift: a
        mark-read or a removal cleared a row's highlight but left the
        badge stuck showing e.g. "(2 new)" over a single live row.
        ``count_as_new`` is kept for call-site compatibility.
        """
        if not self._tab_label:
            return
        self._refresh_new_badge()
        # If already blinking, restart the cycle; the badge text is
        # already up to date, so just let the animation continue.
        if self._blink_active:
            self._blink_count = 0
            return
        self._blink_active = True
        self._blink_count  = 0
        self._blink_tick()

    def _refresh_new_badge(self):
        """Set the "(N new)" badge to the current number of unread (fresh)
        findings, so it always equals the number of highlighted rows.
        No-op until the tab label exists.  Callers: every add / merge
        (via _blink_start), every removal, and mark-read."""
        if not self._tab_label:
            return
        n = sum(1 for f in getattr(self, "_auto_findings", [])
                if f.get("_fresh"))
        self._new_findings = n
        try:
            if n > 0:
                self._tab_label.configure(
                    text=f"{self._tab_base_text}  ({n} new)")
            else:
                self._tab_label.configure(text=self._tab_base_text)
        except Exception:
            pass

    def _blink_tick(self):
        if not self._blink_active or self._blink_count >= 24:
            # After animation ends, keep the badge but settle on a
            # steady bright color so it stays visible until clicked.
            self._blink_active = False
            if self._tab_label and self._tab_label.winfo_exists():
                try:
                    self._tab_label.configure(
                        text_color=COLORS["tab_blink"])   # steady cyan
                except Exception:
                    pass
            return
        if not self._tab_label or not self._tab_label.winfo_exists():
            return
        # RED ↔ CYAN is impossible to miss on a dark background.
        color = ("#FF4444" if self._blink_count % 2 == 0
                 else COLORS["tab_blink"])
        try:
            self._tab_label.configure(text_color=color)
        except Exception:
            pass
        self._blink_count += 1
        self.after(320, self._blink_tick)

    def _blink_stop(self):
        """Called when the user opens the Target Intel tab — stops the
        attention pulse.  The '(N new)' badge is NOT cleared here: opening
        the tab is not the same as reading the findings, so the count
        stays and shrinks only as findings are marked read (keeping it in
        lock-step with the highlighted rows)."""
        self._blink_active = False
        self._refresh_new_badge()          # badge text = live unread count
        if self._tab_label and self._tab_label.winfo_exists():
            try:
                self._tab_label.configure(text_color=COLORS["text_green"])
            except Exception:
                pass

