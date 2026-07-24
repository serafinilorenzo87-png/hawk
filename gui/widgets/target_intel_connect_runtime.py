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


def _patator_available() -> bool:
    """True if a runnable `patator` binary is on PATH.

    Catches both "missing" (which is None) and "not executable" cases —
    the latter is what produced the "/bin/sh: 1: patator: Permission
    denied" failure that mystified the operator: shutil.which can
    happily return a path to a binary that lacks +x bits if the file
    exists in a PATH-listed directory.  os.access(p, X_OK) is the
    proper test.  Cheap (one stat call), safe to call from a dialog
    render path."""
    p = shutil.which("patator")
    if not p:
        return False
    try:
        return os.access(p, os.X_OK)
    except OSError:
        return False

class TargetIntelConnectRuntimeMixin:
    def _open_connect_terminal(self, cmd, target, port, svc,
                                action=None, used_creds=None):
        """Launch the connect command in a native terminal AND mirror
        every line live into HAWK's internal terminal as the session
        runs (history view).  When xterm closes:
          1. Inspect the captured log for legacy-rescuable failures
             (TLS handshake mismatch, SSH host-key refusal, SMB
             protocol negotiation error, ...).  If a rescuable
             signature is found AND the current generation for this
             port wasn't already "legacy", offer a one-click retry
             with the override flipped.
          2. If ``action`` is provided, run the per-service captured
             parser (``_parse_connect_result``) so findings get pushed
             to Target Intel and matching credentials get verified
             (``_mark_creds_verified``).

        Parameters
        ----------
        action : dict or None
            Connect-dialog action dict.  Required to enable the
            findings/credential parser on close — pass it for any
            connect that should produce intel.  None for ad-hoc
            commands (legacy-retry relaunches, manual cmds).
        used_creds : tuple or None
            ``(user, password, hash)`` typed in the dialog, forwarded
            to the parser so a verified-cred entry can be added when
            the captured output proves the login worked.
        """
        from utils.runner import open_native_shell_captured
        title = f"HAWK — {svc or 'connect'} → {target}:{port}"

        svc_key = (svc or "").lower().split("?")[0].strip()

        # GUI-launcher services — the command spawns a separate GUI
        # window (xfreerdp for RDP, vncviewer for VNC).  User interacts
        # with THAT window, the xterm is only useful for seeing the
        # launch banner + any error output.  Auto-close the xterm on
        # rc=0 to stop leaving dead terminals littered around the
        # screen after every connect.  Also catch the command string
        # itself (not just the service key) so a custom command that
        # invokes xfreerdp / vncviewer is treated the same way.
        _GUI_LAUNCHER_SERVICES = {
            "rdp", "ms-wbt-server", "vnc",
        }
        cmd_low = (cmd or "").lower()
        is_gui_launcher = (svc_key in _GUI_LAUNCHER_SERVICES or
                           "xfreerdp" in cmd_low or
                           "vncviewer" in cmd_low)

        def _on_line(line):
            """Mirror each new line from the spawned terminal into the
            HAWK terminal as it appears.  Filters the [HAWK]__CONNECT_RC
            marker (already stripped by runner) and the trailing
            'Drop to shell' banner so the history stays clean."""
            try:
                if not line:
                    return
                low = line.lstrip()
                if low.startswith("[HAWK]"):
                    return
                self.app.terminal.write(line, "dim")
            except Exception:
                pass

        def _on_session_end(lines, rc):
            """Runs on a background thread after the terminal window
            closes."""
            # Legacy-rescue inspection (TLS / SSH / SMB compat).
            try:
                self._inspect_connect_session(
                    lines, rc, cmd, target, port, svc_key)
            except Exception as e:
                try:
                    self.app.terminal.write(
                        f"  [!] Connect inspect error: {e}", "dim")
                except Exception:
                    pass

            # Findings + credential verification — only when an action
            # was supplied (i.e. the connect originated from the dialog
            # with a known action profile).
            if action is not None:
                try:
                    self._parse_connect_result(
                        svc_key, action.get("id", ""), target, port,
                        lines, rc, used_creds=used_creds, cmd=cmd)
                except Exception as e:
                    try:
                        self.app.terminal.write(
                            f"  [!] Connect parse error: {e}", "dim")
                    except Exception:
                        pass

            # Tail marker so the user sees the session boundary in the
            # HAWK terminal even when the xterm was closed manually.
            try:
                color = "success" if rc == 0 else "warn"
                self.app.terminal.write(
                    f"  [+] CONNECT terminal closed (rc={rc})", color)
            except Exception:
                pass

        ok = open_native_shell_captured(
            title, cmd,
            on_exit_callback=_on_session_end,
            on_line_callback=_on_line,
            auto_close=is_gui_launcher)

        if ok:
            self.app.terminal.write(
                f"  [+] Opened terminal: {cmd}", "success")
        else:
            self.app.terminal.write(
                "  [!] Could not launch terminal emulator.", "error")

    def _inspect_connect_session(self, lines, rc, cmd, target, port, svc_key):
        """Scan captured CONNECT log for signatures that compat flags
        would fix.  If found AND the port wasn't already using compat
        flags, ask the user whether to retry with Force legacy."""
        if not lines:
            return
        joined = "\n".join(lines)
        compat_key = self._COMPAT_ALIASES.get(svc_key, svc_key)
        sigs = self._LEGACY_RESCUE_SIGNATURES.get(compat_key, [])
        if not sigs:
            return
        import re as _re
        matched = None
        for pat in sigs:
            m = _re.search(pat, joined, _re.IGNORECASE)
            if m:
                matched = m.group(0)
                break
        if not matched:
            return

        # Figure out which generation was in force when the command ran.
        # If the port is already "legacy" (override or target-wide), the
        # command already HAD compat flags and still failed → retry with
        # the same flags won't help; offer a different remedy.
        current_gen = self._current_generation(port)
        fp = self._get_fingerprint()
        port_override = fp.get_port_override(port) if fp else "auto"

        def _show_dialog():
            self._show_legacy_retry_dialog(
                cmd=cmd, target=target, port=port, svc_key=svc_key,
                matched_signature=matched,
                current_generation=current_gen,
                port_override=port_override)

        # Must hop to the UI thread.
        try:
            ui = getattr(self.app, "ui_call", None)
            if ui:
                ui(_show_dialog)
            else:
                _show_dialog()
        except Exception:
            pass

    def _show_legacy_retry_dialog(self, cmd, target, port, svc_key,
                                    matched_signature,
                                    current_generation, port_override):
        """Offer to flip the port override to 'legacy' and re-launch
        the connect terminal with compat flags applied.  If already
        legacy, just explain the situation (compat didn't help)."""
        from gui.dialogs import (_make_win, _title, _note_box, _btn_row,
                                  _btn, _safe_destroy)
        fp = self._get_fingerprint()

        win = _make_win(self, "Connect failed — legacy rescue?", 620, 460)
        _title(win, "⚠  Connect session ended with a legacy-looking error")
        _note_box(win,
                  f"Target: {target}:{port}   Service: {svc_key}\n"
                  f"Error signature found in the session log:\n"
                  f"    “{matched_signature}”\n\n"
                  f"This pattern is usually fixed by emitting protocol-"
                  f"compat flags (ssh-rsa host keys, SMB1 fallback, TLS "
                  f"SECLEVEL=0, etc.) on the client.",
                  COLORS["text_yellow"])

        already_legacy = current_generation == "legacy"
        if already_legacy:
            _note_box(win,
                      "This port is ALREADY classified as 'legacy', so the "
                      "retry would produce the exact same command that just "
                      "failed.  Possible causes:\n"
                      "  • Wrong credentials (check the auth layer first).\n"
                      "  • Server is even older than what our compat flags "
                      "cover.\n"
                      "  • Service doesn't actually match the port — try "
                      "CHANGE SERVICE.\n"
                      "  • Network issue / firewall mid-session.\n"
                      "Dismiss and investigate manually.",
                      COLORS["text_muted"])
            row = _btn_row(win)
            _btn(row, "DISMISS", lambda: _safe_destroy(win), primary=True)
            return

        _note_box(win,
                  f"Currently classified: {current_generation}\n"
                  f"Per-port override:    {port_override}\n\n"
                  f"Retry will:\n"
                  f"  1. Set port {port}'s override to 'legacy'\n"
                  f"  2. Re-launch the connect terminal with compat flags\n"
                  f"  3. Leave all other ports on this target unchanged",
                  COLORS["text_cyan"])

        def _retry():
            _safe_destroy(win)
            if fp:
                fp.set_port_override(port, "legacy")
                # Persist override right away so a mid-session crash
                # doesn't lose the fix.
                try:
                    sess = self.app.session_manager.current
                    if sess and hasattr(sess, "save"):
                        sess.save()
                except Exception:
                    pass
            # Rebuild the command: re-apply compat with the new override.
            new_tpl = self._terminal_cmd_for(svc_key, port) or ""
            if "{compat}" in new_tpl:
                new_tpl = self._apply_compat(
                    new_tpl, svc_key, host=target, port=port)
            # We still need user/pass tokens — we don't have them here
            # (they were rendered into the original `cmd`).  Best-effort
            # approach: prepend the legacy compat flag string onto the
            # original command if the simple template rebuild didn't
            # include them.  For the common case (ssh/smb/mysql/psql)
            # the original cmd already has the full auth payload; we
            # just need to splice compat flags into the right spot.
            #
            # Strategy: compute the compat string, find a well-known
            # binary name in the original cmd, and insert compat right
            # after it.  Covers ssh / smbclient / mysql / psql / curl.
            flags = self._compat_flags_for(svc_key, port=port)
            flags = flags.replace("{host}", target) if flags else ""
            retry_cmd = cmd
            if flags:
                import re as _re
                binary_map = {
                    "ssh":        r"\bssh\b",
                    "smb":        r"\bsmbclient\b",
                    "microsoft-ds": r"\bsmbclient\b",
                    "netbios-ssn":  r"\bsmbclient\b",
                    "mysql":      r"\bmysql\b",
                    "postgresql": r"\bpsql\b",
                    "https":      r"\bcurl\b",
                    "ssl/http":   r"\bcurl\b",
                    "ms-sql-s":   r"\bimpacket-mssqlclient\b",
                    "mssql":      r"\bimpacket-mssqlclient\b",
                }
                pat = binary_map.get(svc_key) or binary_map.get(
                    self._COMPAT_ALIASES.get(svc_key, ""))
                # PostgreSQL compat is an env-var prefix — prepend instead
                # of inserting after the binary.
                is_env_prefix = (
                    self._COMPAT_ALIASES.get(svc_key, svc_key) == "postgresql")
                if is_env_prefix:
                    retry_cmd = f"{flags} {cmd}"
                elif pat:
                    retry_cmd = _re.sub(
                        pat, lambda m: f"{m.group(0)} {flags}",
                        cmd, count=1)
            # Relaunch
            self.app.terminal.write(
                f"  [*] Retrying with compat flags (port {port} → legacy)",
                "success")
            self._open_connect_terminal(retry_cmd, target, port, svc_key)

        row = _btn_row(win)
        _btn(row, "RETRY WITH LEGACY FLAGS", _retry, primary=True, w=220)
        _btn(row, "DISMISS", lambda: _safe_destroy(win))

    def _service_is_lockout_aware(self, svc_key: str) -> bool:
        """True when brute-forcing this service on a real AD environment
        carries account-lockout risk (SMB / WinRM / RDP / LDAP / MSSQL
        with Windows-auth).  When True the launch dialog routes through
        ``_show_lockout_warning`` instead of running directly."""
        canon = self._canonical_profile_key(svc_key)
        preset = self._BRUTE_PRESETS.get(canon, {})
        return bool(preset.get("lockout_aware", False))

    def _build_strategy_commands(self, svc_key: str, target: str,
                                   port: int, hydra_cmd: str) -> dict:
        """Build the per-strategy command lines used by the lockout popup.

        Returns a dict ``{strategy_id: {label, tpl, tool, captured, ...}}``.
        ``hydra_cmd`` is the ORIGINAL hydra/netexec command the user was
        about to launch — used as the ``brute_anyway`` fallback.

        Strategies (each maps to an alternative attack pattern):
          * ``spray``        — N-users × 1-password via netexec
          * ``kerb_spray``   — Kerberos pre-auth spray via kerbrute
          * ``check_policy`` — recon-only, prints lockout policy
          * ``slow_brute``   — hydra single thread + 60 s wait
          * ``patator_skip`` — patator with skip-on-lockout filter
          * ``brute_anyway`` — original wordlist × wordlist (locks accounts)
        """
        canon = self._canonical_profile_key(svc_key)
        # Map service → nxc backend name (some services use a different
        # token in nxc than in hydra).  Falls back to the canonical key.
        NXC_PROTO = {
            "smb": "smb", "winrm": "winrm", "rdp": "rdp",
            "ldap": "ldap", "mssql": "mssql",
        }
        nxc_proto = NXC_PROTO.get(canon, canon)

        # Default users wordlist + a single sensible "spray" password
        users_wl = self._BRUTE_PRESETS.get(canon, {}).get(
            "users_wl",
            "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt")
        spray_pw = "Spring2024!"  # standard pentest seasonal default

        # Try to read the configured target domain from the app — needed
        # for kerbrute.  When absent, the kerb_spray strategy gets a
        # placeholder + a flag so the popup can disable the radio.
        try:
            t_domain = self.app.target_bar.get_target_domain() or ""
        except Exception:
            t_domain = ""

        return {
            "spray": {
                "label": "Password Spray (recommended)",
                "tool":  "netexec",
                "info":  "1 password × many users — no lockout, more stealth.",
                "tpl": (f"netexec {nxc_proto} {target} "
                        f"-u {users_wl} -p '{spray_pw}' "
                        f"--continue-on-success"),
                "captured": True,
                "bg":       True,
                "available": True,
            },
            "kerb_spray": {
                "label": "Kerberos Pre-Auth Spray (AD only, stealthier)",
                "tool":  "kerbrute",
                "info":  ("Uses Kerberos pre-auth — may bypass lockout "
                          "counter on default Windows policies."),
                "tpl": (f"kerbrute passwordspray "
                        f"-d {t_domain or '<DOMAIN>'} "
                        f"--dc {target} "
                        f"{users_wl} '{spray_pw}'"),
                "captured": True,
                "bg":       True,
                "available": bool(t_domain),
                "disabled_reason":
                    "Set target domain first (Target Bar → Domain field)",
            },
            "check_policy": {
                "label": "Check Lockout Policy First (recon, no attack)",
                "tool":  "netexec",
                "info":  ("Discovers lockoutThreshold and lockoutDuration "
                          "so you can size the brute safely."),
                "tpl": (f"netexec {nxc_proto} {target} "
                        f"-u 'guest' -p '' --pass-pol"),
                "captured":  True,
                "bg":        False,    # short, runs in HAWK terminal
                "available": True,
            },
            "slow_brute": {
                "label": "Slow Brute (1 attempt every 60 s)",
                "tool":  "Hydra",
                "info":  ("Single-thread brute with -W 60 wait between "
                          "attempts.  Lockout counter usually resets in "
                          "30 min so a slow enough brute avoids it."),
                "tpl": hydra_cmd.replace(
                    "-t 4", "-t 1 -W 60", 1
                ) if "-t 4" in hydra_cmd else hydra_cmd + " -t 1 -W 60",
                "captured": True,
                "bg":       True,
                "available": True,
            },
            "patator_skip": {
                "label": "Skip Locked Accounts (patator)",
                "tool":  "patator",
                "info":  ("Uses patator's per-response filtering to skip "
                          "users whose account got locked mid-run; "
                          "continues attacking still-unlocked users."),
                "tpl": (f"patator {nxc_proto}_login host={target} "
                        f"port={port} user=FILE0 password=FILE1 "
                        f"0={users_wl} 1=/usr/share/wordlists/rockyou.txt "
                        f"-x ignore:fgrep='Account locked'"),
                "captured":  True,
                "bg":        True,
                # Real availability probe: shutil.which finds it AND it's
                # executable.  Pre-fix the strategy was always shown as
                # available, so when patator was missing / not-executable
                # the run failed with rc=127 ("patator: Permission denied"
                # or "command not found") and the operator had no clue
                # why.  When unavailable we disable the radio + surface
                # the install hint.
                "available": _patator_available(),
                "disabled_reason":
                    "patator not installed or not executable — "
                    "`sudo apt install patator` (Kali) then re-open this "
                    "dialog.  Or use 'Password Spray (netexec)' above.",
            },
            "brute_anyway": {
                "label": "Brute Anyway (will lock accounts)",
                "tool":  "Hydra",
                "info":  ("Original wordlist × wordlist attack — fastest "
                          "but WILL trigger lockout on production AD."),
                "tpl":  hydra_cmd,
                "captured": True,
                "bg":       True,
                "available": True,
                "warn": True,
            },
        }

    def _show_lockout_warning(self, target: str, port: int, svc_key: str,
                               hydra_cmd: str, action: dict,
                               used_creds=None) -> None:
        """Modal popup that warns the user about account-lockout risk on
        AD-attached services and lets them pick one of 6 strategies
        (spray / kerb_spray / check_policy / slow_brute / patator_skip /
        brute_anyway).  The selected strategy's command is shown in an
        editable preview before the final LAUNCH.
        """
        from gui.dialogs import _make_win, _safe_destroy
        from utils.clipboard import add_context_menu

        win = _make_win(self, "⚠ Account Lockout Risk", 760, 720)

        # Header
        ctk.CTkLabel(
            win, text="⚠   ACCOUNT LOCKOUT RISK",
            font=_f("xl", True),
            text_color="#FF6666",
        ).pack(pady=(14, 4))
        ctk.CTkLabel(
            win,
            text=(f"You're about to brute {svc_key.upper()} on {target}:{port} "
                  f"with a wordlist of password attempts.\n"
                  f"On Windows AD this will LOCK OUT user accounts after "
                  f"3-5 fails — disrupts users, triggers SOC alerts, and "
                  f"after the lockout the brute is useless anyway."),
            font=_f("sm"), text_color=COLORS["text_yellow"],
            justify="left", wraplength=720,
        ).pack(fill="x", padx=20, pady=(0, 8))

        # Build the strategy table
        strategies = self._build_strategy_commands(
            svc_key, target, port, hydra_cmd)

        # Strategy radio + descriptions
        ctk.CTkLabel(
            win, text="CHOOSE STRATEGY",
            font=_f("md", True), text_color=COLORS["text_green"],
            anchor="w",
        ).pack(fill="x", padx=20, pady=(4, 4))

        strategy_var = ctk.StringVar(value="spray")  # safest default
        radios_frame = ctk.CTkFrame(win, fg_color="transparent")
        radios_frame.pack(fill="x", padx=22, pady=(0, 6))

        # Build one radio + description block per strategy
        for sid, data in strategies.items():
            row = ctk.CTkFrame(radios_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            r = ctk.CTkRadioButton(
                row, text=data["label"],
                variable=strategy_var, value=sid,
                font=_f("sm", True),
                fg_color=COLORS["text_green"],
                border_color=COLORS["border_dim"],
                text_color=(COLORS["text_bright"] if data["available"]
                            else COLORS["text_dim"]),
                state=("normal" if data["available"] else "disabled"),
            )
            r.pack(side="left", anchor="w")
            info = data["info"]
            if not data["available"] and data.get("disabled_reason"):
                info = info + "  —  " + data["disabled_reason"]
            ctk.CTkLabel(
                row, text="  " + info,
                font=_f("xs"), text_color=COLORS["text_muted"],
                anchor="w", wraplength=600,
            ).pack(side="left", anchor="w", padx=(4, 0))

        # Editable preview
        ctk.CTkLabel(
            win, text="COMMAND PREVIEW (editable)",
            font=_f("md", True), text_color=COLORS["text_green"],
            anchor="w",
        ).pack(fill="x", padx=20, pady=(8, 2))
        preview_box = ctk.CTkTextbox(
            win, height=80, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_cyan"],
            border_color=COLORS["text_cyan"], border_width=2,
            corner_radius=3, wrap="word",
        )
        preview_box.pack(fill="x", padx=20, pady=(0, 6))
        add_context_menu(preview_box)

        def _set_preview(cmd_text: str):
            preview_box.delete("1.0", "end")
            preview_box.insert("1.0", cmd_text)

        def _on_strategy_change(*_):
            sid = strategy_var.get()
            _set_preview(strategies[sid]["tpl"])

        strategy_var.trace_add("write", _on_strategy_change)
        _on_strategy_change()  # initial fill

        # Buttons
        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(pady=(8, 12))

        def _launch_selected():
            sid = strategy_var.get()
            data = strategies[sid]
            edited_cmd = preview_box.get("1.0", "end").strip()
            if not edited_cmd:
                return
            _safe_destroy(win)
            # Build a synthetic action mirroring the original brute so
            # _run_captured_connect can reuse all the BG/parser plumbing.
            new_action = {
                "id":    "brute" if data.get("bg") else "policy_check",
                "label": data["label"],
                "what":  data["info"],
                "tpl":   edited_cmd,
                "mode":  "anon",
            }
            # Note in the terminal which strategy was chosen
            try:
                self.app.terminal.write(
                    f"  [*] Lockout strategy chosen: {data['label']}",
                    "dim")
            except Exception:
                pass
            self._run_captured_connect(
                edited_cmd, target, port, svc_key, svc_key,
                new_action, used_creds=used_creds)

        ctk.CTkButton(
            btn_row, text="CANCEL", width=120, height=34,
            font=_f("md"),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=4,
            command=lambda: _safe_destroy(win),
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            btn_row, text="▶ LAUNCH STRATEGY", width=200, height=34,
            font=_f("md", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=4,
            command=_launch_selected,
        ).pack(side="left", padx=8)

    def _run_captured_connect(self, cmd, target, port, svc, svc_key, action,
                                used_creds=None):
        """Run a CONNECT command through ToolRunner, streaming output to the
        HAWK terminal and then parsing the full log for findings.

        ``used_creds`` is the (user, password, hash) tuple the dialog had
        when LAUNCH was clicked.  Per-service parsers use it to upgrade
        the matching save-on-launch entry from [unverified] → [verified]
        when they detect login success.

        Brute-force routing (added 2026-04-29): when the action_id starts
        with ``brute`` (telnet brute, FTP brute, SSH brute, SMB brute, …)
        we ALSO register the run as a Background Job in the BgJobsBar so
        the user gets:
          • [▶ OPEN]  → tail -f the live log in a separate xterm
          • [⏹ STOP]  → SIGTERM the running brute via runner.kill()
        Output is teed to a temp log file so the OPEN button always has
        something fresh to tail.  Non-brute captured actions keep the
        original behaviour (output streams to HAWK terminal, no BG row).
        """
        from utils.runner import ToolRunner
        import tempfile as _tempfile

        action_id    = action.get("id", "")
        action_label = action.get("label", action_id or "connect")
        tool_name    = f"connect:{svc_key}:{action_id}"

        # Brute-force jobs are long-running, killable, and benefit from
        # a tail-able log file so the user can monitor them via OPEN.
        _aid_low = (action_id or "").lower()
        is_brute = (_aid_low.startswith("brute")
                    and _aid_low not in ("brute_creds", "brute_creds_ncrack"))

        # Wall-clock start so the post-mortem auto-tail can decide
        # whether the brute "failed quickly" (rc != 0 within a few
        # seconds usually means the tool aborted on a config/algo/wordlist
        # error rather than running through the wordlist).
        start_ts = time.time()

        # Banner in the terminal so the user sees where output comes from.
        try:
            self.app.terminal.section(
                f"CONNECT · {svc_key.upper()} {action_label} "
                f"→ {target}:{port}")
        except Exception:
            pass
        self.app.terminal.write(f"  $ {cmd}", "dim")

        # ── Non-brute captured actions: route through xterm ──────────────
        # The user wants every connect to open an external terminal AND
        # mirror its output live to the HAWK internal terminal as a
        # history view.  Non-brute actions (curl/smbclient/nxc one-shots,
        # interactive shells) all go through _open_connect_terminal which
        # spawns xterm, tails the captured logfile to HAWK terminal in
        # real time, and runs _parse_connect_result on close so findings
        # and verified credentials still flow into Target Intel.
        # Brute-force actions keep the old inline ToolRunner + BG-job
        # path because (a) they run for hours and an xterm window pinned
        # to the screen the whole time is bad UX, (b) the BgJobsBar
        # already provides OPEN/STOP for live-tail and abort.
        if not is_brute:
            self._open_connect_terminal(
                cmd, target, port, svc,
                action=action, used_creds=used_creds)
            return

        # Track the run in the session timeline (so reload restores it).
        sess = None; exec_id = None
        try:
            sess = self.app.session_manager.current
            if sess:
                exec_id = sess.start_tool_execution(
                    tool_name, action_label, "enumeration", cmd)
        except Exception:
            pass

        # ── Optional log file for OPEN/tail-f ────────────────────────────
        # Created only for brute-force jobs to keep tmpdir clean.  Wrapped
        # in a try/except so a tempfile failure doesn't kill the whole
        # connect path — we just lose the OPEN feature.
        log_fh = None
        log_path = ""
        if is_brute:
            try:
                import os as _os
                _os.makedirs(TMP_DIR, exist_ok=True)
                _ntf = _tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", errors="replace",
                    prefix=f"hawk_{svc_key}_brute_", suffix=".log",
                    delete=False, dir=TMP_DIR)
                log_fh   = _ntf
                log_path = _ntf.name
                # Header so an early OPEN shows context immediately
                log_fh.write(f"# HAWK background brute-force log\n")
                log_fh.write(f"# tool:    {action_label}\n")
                log_fh.write(f"# target:  {svc_key.upper()} {target}:{port}\n")
                log_fh.write(f"# cmd:     {cmd}\n")
                log_fh.write(f"# started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_fh.write("# " + "-" * 70 + "\n\n")
                log_fh.flush()
            except Exception as _le:
                print(f"[HAWK] BG brute log file failed: {_le}")
                log_fh = None
                log_path = ""

        # Job-id used by BgJobsBar.  Stable per-run, derived from
        # tool_name + monotonic timestamp so concurrent brutes don't
        # collide.
        job_id = f"{tool_name}@{int(time.time() * 1000)}"

        def _out(line, name, level):
            # Tee to the log file FIRST (cheap, never raises out).
            if log_fh:
                try:
                    log_fh.write(line.rstrip() + "\n")
                    log_fh.flush()
                except Exception:
                    pass
            # For non-brute captured actions we still stream to HAWK
            # terminal so the user sees what's happening live.  For
            # brute jobs the volume of output (one line per attempt) is
            # too noisy — keep the terminal clean and route the user
            # to the OPEN button for live progress.
            if not is_brute:
                try:
                    self.app.terminal.write(line)
                except Exception:
                    pass

        # Forward-ref needed inside _done — assigned after ToolRunner
        # construction.  Closure captures the binding.
        runner_ref = {"obj": None}
        bg_job_ref = {"obj": None}

        def _done(name, rc, log):
            lines = [ln for _, ln in log]
            # Finalize the session timeline entry.
            try:
                if sess and exec_id:
                    status = "success" if rc == 0 else "fail"
                    sess.finish_tool_execution(exec_id, rc, lines, status)
            except Exception:
                pass
            # Close the tail log so any still-running OPEN viewer sees
            # the EOF marker; the file stays on disk until next reboot
            # (it's in /tmp).
            if log_fh:
                try:
                    log_fh.write("\n# " + "-" * 70 + "\n")
                    log_fh.write(f"# finished rc={rc} at "
                                  f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    log_fh.flush()
                    log_fh.close()
                except Exception:
                    pass
            # Remove the job from the BG bar.
            bg_job = bg_job_ref["obj"]
            if bg_job is not None:
                try:
                    bar = getattr(self.app, "bg_jobs_bar", None)
                    if bar is not None:
                        bar.finish_job(
                            bg_job.job_id,
                            f"{action_label} finished (rc={rc})")
                except Exception as _be:
                    print(f"[HAWK] BG finish_job failed: {_be}")
            # Dispatch to the per-service parser — any exception here is
            # non-fatal, we just log it.  Track whether the parser
            # produced new findings so the closing tail message can
            # de-escalate the tone when rc != 0 just signals a normal
            # transaction-level rejection (swaks rc=23/24, curl rc=22,
            # mysql access-denied 1, …).
            findings_before = len(self._auto_findings)
            try:
                self._parse_connect_result(
                    svc_key, action_id, target, port, lines, rc,
                    used_creds=used_creds, cmd=cmd)
            except Exception as e:
                self.app.terminal.write(
                    f"  [!] Result parse error: {e}", "warn")
            findings_after = len(self._auto_findings)
            produced_findings = (findings_after > findings_before)

            # ── Post-mortem auto-tail (brute-force quick-failure) ──────
            # Brute-force tools that exit with rc != 0 in less than 5
            # seconds almost always mean a configuration error: missing
            # wordlist, unsupported protocol/algos (hydra+legacy SSH
            # MAC mismatch), tool not compiled with the right module,
            # target unreachable.  In all those cases the user sees
            # only `rc=255` on screen — the actual error is buried in
            # the BG log file the user has to dig out manually.
            #
            # Auto-surface the last 30 lines of the log to the HAWK
            # terminal so the user immediately sees WHY the brute
            # died, plus actionable hints for the most common
            # signatures (legacy SSH algos → ncrack, missing wordlist
            # → install seclists, etc.).
            elapsed = time.time() - start_ts
            if (is_brute and rc != 0 and elapsed < 5.0
                    and log_path):
                try:
                    with open(log_path, "r", encoding="utf-8",
                                errors="replace") as _fh:
                        _all = _fh.readlines()
                    _tail_lines = [ln.rstrip() for ln in _all[-30:]
                                   if ln.strip()]
                    if _tail_lines:
                        self.app.terminal.write(
                            f"  [!] Brute force failed quickly "
                            f"(rc={rc}, {elapsed:.1f}s) — last "
                            f"{len(_tail_lines)} lines from log:",
                            "warn")
                        for _ln in _tail_lines:
                            self.app.terminal.write(f"      {_ln}",
                                                     "dim")
                        # ── Actionable hint detection ──────────────
                        _joined = "\n".join(_tail_lines).lower()
                        hints = []
                        if ("no match for method" in _joined
                                or "kex error" in _joined
                                or "no matching mac" in _joined
                                or "no matching cipher" in _joined
                                or "no matching key exchange" in _joined):
                            hints.append(
                                "→ Hydra/libssh rejected the target's "
                                "legacy SSH algorithms.  Switch the "
                                "Connect dialog action to "
                                "\"Brute force (Ncrack — works on "
                                "legacy SSH)\" — ncrack accepts "
                                "hmac-md5/sha1, group1-sha1, "
                                "aes128-cbc, etc.")
                        if "was compiled without ssh support" in _joined:
                            hints.append(
                                "→ This Hydra build has no SSH support. "
                                "Install via `apt install hydra-libssh` "
                                "or use ncrack: `ncrack -p 22 -U <users> "
                                "-P <pass> ssh://<target>`")
                        if ("was not found" in _joined or
                                "no such file" in _joined):
                            hints.append(
                                "→ Wordlist file missing.  Install via "
                                "`apt install seclists` or change the "
                                "wordlist paths in the dialog.")
                        if ("all children were disabled" in _joined or
                                "all childs were disabled" in _joined):
                            hints.append(
                                "→ Hydra disabled all workers — every "
                                "attempt failed at connection-level.  "
                                "Check target reachability and port: "
                                f"`nc -vz {target} {port}`")
                        if "connection refused" in _joined:
                            hints.append(
                                f"→ Target refused TCP/{port}.  Service "
                                "may be down, firewalled, or behind a "
                                "different port — re-scan with nmap -sV.")
                        for _hint in hints:
                            self.app.terminal.write(f"  {_hint}",
                                                     "warn")
                except Exception as _te:
                    print(f"[HAWK] post-mortem tail failed: {_te}")

            # ── Tail marker — tone scales with what actually happened ──
            # rc=0 always means success (green).
            # rc!=0 + parser produced ≥1 finding  →  informational dim
            #   (the tool ran fine, the target just said no — common for
            #   swaks rc=23/24 SMTP rejection, curl rc=22 HTTP 4xx/5xx,
            #   psql denied auth, etc.; the user already sees the useful
            #   facts as findings, no need to alarm).
            # rc!=0 + no findings  →  yellow warn (something genuinely
            #   went wrong — network unreachable, command malformed,
            #   tool not installed).
            if rc == 0:
                tail  = "  [+] CONNECT finished (rc=0)"
                color = "success"
            elif produced_findings:
                tail  = (f"  [*] CONNECT finished (rc={rc} — "
                         f"informational; see findings)")
                color = "dim"
            else:
                tail  = f"  [!] CONNECT finished (rc={rc})"
                color = "warn"
            self.app.terminal.write(tail, color)

        runner = ToolRunner(
            output_callback=_out,
            done_callback=_done,
            ui_dispatcher=getattr(self.app, "ui_call", None))
        runner_ref["obj"] = runner

        # Register a BG job entry FIRST so the bar shows the job from
        # the moment the runner starts.  Non-brute actions still don't
        # get a BG row (label-only, no actions, no tail file).
        if is_brute:
            try:
                from gui.widgets.bg_jobs_bar import BackgroundJob
                bar = getattr(self.app, "bg_jobs_bar", None)
                if bar is not None:
                    bg_label = f"{svc_key.upper()} {action_label} → {target}:{port}"
                    bg_job = BackgroundJob(
                        job_id=job_id,
                        label=bg_label,
                        estimated_secs=0,        # unknown — not shown
                        runner=runner,
                        log_path=log_path,
                        killable=True,
                        host=target, port=port, service=svc_key,
                    )
                    bar.add_job(bg_job)
                    bg_job_ref["obj"] = bg_job
                    self.app.terminal.write(
                        f"  [bg] Brute force running in background — "
                        f"use OPEN to watch live, STOP to abort.",
                        "dim")
            except Exception as _be:
                print(f"[HAWK] BG add_job failed: {_be}")

        runner.run(cmd, tool_name)

    def _parse_connect_result(self, svc_key, action_id, target, port,
                              lines, rc, used_creds=None, cmd=""):
        """Route captured CONNECT output to the right parser. Each parser
        is responsible for pushing findings via self.add_auto_finding and
        (where relevant) session.add_discovered_*().

        ``used_creds`` is the (user, password, hash) tuple from the dialog,
        forwarded so parsers can upgrade matching save-on-launch entries
        from [unverified] → [verified] when login success is detected.

        ``cmd`` is the launched shell command — forwarded to
        ``_parse_hydra_output`` so HTTP/S hydra runs can run the
        false-positive cascade guard (the http-get module flags every
        cred as valid against a target without real auth, producing
        garbage like ``root:123456`` in the store).
        """
        import re as _re
        key = (svc_key or "").lower()
        aid = (action_id or "").lower()

        # Canonicalize nmap service names → parser keys.  nmap reports
        # "netbios-ssn" (139) and "microsoft-ds" (445) which are both SMB,
        # "ms-wbt-server" which is RDP, "ms-sql-s" which is MSSQL, and
        # various HTTP aliases.  Without this mapping the dispatcher
        # silently drops findings because `key == "smb"` never matches.
        # Use the unified resolver so substring matches (vsftpd → ftp,
        # openssh → ssh, etc.) AND exact aliases all collapse the same
        # way the Connect dialog did when it picked the profile.
        key = self._canonical_profile_key(key)
        if key == "microsoft-httpapi":
            key = "http"
        # Strip verbose-trace prefixes that many CONNECT commands produce
        # (curl -v, ssh -v, ftp -v, telnet, smbclient, etc.). Every per-service
        # parser anchors its regexes on ^, so lines like "< HTTP/1.1 200 OK"
        # or "debug1: kex_input_kexinit" would otherwise never match and no
        # findings would reach Target Intel. The strip is safe: it only
        # removes leading "< ", "> ", "* " (curl) or "debug1: " (ssh) and
        # is a no-op on already-clean output.
        cleaned = []
        for ln in lines:
            ln = _re.sub(r"^\s*[<>*]\s?", "", ln)
            ln = _re.sub(r"^debug\d+:\s?", "", ln)
            cleaned.append(ln)
        lines = cleaned
        text = "\n".join(lines)

        # SMB silent-success hint ─────────────────────────────────────────
        # smbclient -L can return rc=0 with empty output when the target
        # (e.g. Win Server 2008 R2 with RestrictAnonymous) allows the null
        # session to connect but refuses to enumerate shares. Surface a
        # helpful next-step note so the user isn't left staring at an
        # empty terminal.
        if key == "smb" and aid in ("enum_anon", "enum_guest") and rc == 0 \
                and not text.strip():
            self.app.terminal.write(
                "  [!] smbclient returned no share list. The host likely\n"
                "      restricts anonymous enumeration (RestrictAnonymous\n"
                "      on Windows, or Samba 'restrict anonymous = 2').\n"
                "      Next steps:\n"
                f"        • enum4linux -a {target}\n"
                f"        • netexec smb {target} -u guest -p ''\n"
                f"        • Try authenticated enumeration via CONNECT → "
                f"Enumerate (with creds)",
                "warn")
            self.add_auto_finding(
                "SMB anonymous listing refused",
                f"{target}:{port} accepted the null session but returned "
                "no shares. RestrictAnonymous is likely enabled. Try "
                "guest credentials or authenticated enumeration.",
                severity="info", source="CONNECT / SMB")
            return

        # Nothing useful to parse if the log is empty.
        if not text.strip():
            return

        # ── Brute / spray / policy output parsers ───────────────────────
        # Multiple tools can produce credential hits and they all use
        # different output formats.  We sniff the captured text for
        # tool-specific signatures and run the matching parser(s).
        # Each parser is idempotent and dedup-aware so running multiple
        # in sequence is harmless.
        if aid.startswith("brute") or aid == "policy_check":
            # Hydra — most brute force runs use it.  Detected by the
            # signature line `[<port>][<proto>] host: ... login: ...`.
            # _parse_hydra_output internally guards on the regex so it's
            # a no-op when no hydra hit lines are present.
            self._parse_hydra_output(target, port, key, text, cmd=cmd)
            # netexec brute / spray — same parser handles both.  Detected
            # via the [+] DOM\u:p line shape.
            self._parse_netexec_brute_output(target, port, key, text)
            # kerbrute pre-auth spray — VALID LOGIN: u@dom:pw lines.
            self._parse_kerbrute_output(target, port, key, text)
            # patator — used by the lockout-warning popup's "skip locked"
            # strategy.  Detected via the per-row table format.
            self._parse_patator_output(target, port, key, text)
            # netexec --pass-pol — only fires for the "check_policy"
            # strategy chosen from the lockout warning, but the parser
            # is regex-gated so it's safe to run on any brute run.
            self._parse_pass_policy_output(target, port, key, text)

        if key == "smb":
            self._parse_smb_connect(aid, target, port, lines, text,
                                     used_creds=used_creds)
        elif key == "winrm":
            self._parse_winrm_connect(aid, target, port, lines, text,
                                       used_creds=used_creds)
        elif key == "rdp":
            self._parse_rdp_connect(aid, target, port, lines, text)
        elif key == "ssh":
            self._parse_ssh_connect(aid, target, port, lines, text,
                                     used_creds=used_creds)
        elif key == "ftp":
            self._parse_ftp_connect(aid, target, port, lines, text,
                                     used_creds=used_creds)
        elif key == "http":
            self._parse_http_connect(aid, target, port, lines, text,
                                     scheme="http", used_creds=used_creds)
        elif key == "https":
            self._parse_http_connect(aid, target, port, lines, text,
                                     scheme="https", used_creds=used_creds)
        elif key == "mysql":
            self._parse_mysql_connect(aid, target, port, lines, text,
                                       used_creds=used_creds)
        elif key == "postgresql":
            self._parse_postgres_connect(aid, target, port, lines, text,
                                          used_creds=used_creds)
        elif key == "mssql":
            self._parse_mssql_connect(aid, target, port, lines, text,
                                       used_creds=used_creds)
        elif key == "ldap":
            self._parse_ldap_connect(aid, target, port, lines, text,
                                      used_creds=used_creds)
        elif key == "redis":
            self._parse_redis_connect(aid, target, port, lines, text)
        elif key == "vnc":
            self._parse_vnc_connect(aid, target, port, lines, text)
        elif key == "smtp":
            self._parse_smtp_connect(aid, target, port, lines, text)
        elif key == "telnet":
            self._parse_telnet_connect(aid, target, port, lines, text,
                                        used_creds=used_creds)

