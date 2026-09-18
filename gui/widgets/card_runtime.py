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


def kerbrute_run_summary(lines: list, rc: int) -> str:
    """One-line BG-job summary for a kerbrute run.

    kerbrute emits neither hydra-style credentials nor gobuster-style
    path rows, so the content-discovery regexes used for every other
    non-hydra tool matched NONE of its output: every run — including a
    successful spray that had just handed the operator a domain
    account — was summarised as "No paths found."

    The two markers counted here are the same ones the structured
    parser (_parse_kerbrute_to_intel) keys on.
    """
    import re as _re
    blob = "\n".join((ln or "") for ln in (lines or []))
    n_users = len(_re.findall(r"VALID USERNAME", blob, _re.I))
    n_logins = len(_re.findall(r"VALID LOGIN", blob, _re.I))
    if n_logins or n_users:
        bits = []
        if n_logins:
            bits.append(f"{n_logins} valid login"
                        f"{'' if n_logins == 1 else 's'}")
        if n_users:
            bits.append(f"{n_users} valid username"
                        f"{'' if n_users == 1 else 's'}")
        return " and ".join(bits) + " — see Target Intel for details."
    if rc == 0:
        return "No valid usernames or logins found."
    return f"Exited rc={rc}; nothing captured."


def _proxychains_scan_dispatch(log, target_intel, parse_output_to_intel_cb,
                                tool, terminal=None):
    """Ramo dedicato per proxychains_scan (extracted so it can be unit-
    tested end-to-end without importing customtkinter-heavy modules).

    Strips [proxychains]-prefixed noise from the raw runner log, then
    fires TWO sinks with the cleaned data:

      1. target_intel.update_from_nmap([strings]) — structured port
         parser (populates Ports / System Info panel).  Extract the
         string half of each (ts, line) tuple FIRST: from_nmap_output
         calls .strip() on every element, which raises AttributeError
         on tuples and used to silently blank the Ports panel until
         the caller learnt to unpack the tuples.

      2. parse_output_to_intel_cb(tool, clean_log) — the visible
         auto_finding in Target Intel ("PROXYCHAINS NMAP on <target>")
         with no [proxychains] lines in the description.

    Errors get logged to stderr AND to the terminal at "warn" level
    when a terminal handle is provided — surfacing them prevents the
    silent-swallow that masked the tuple/strings bug in production.
    """
    if not log:
        return
    clean_log = [
        (ts, line) for ts, line in log
        if not line.startswith("[proxychains]")
    ]
    if not clean_log:
        return
    if target_intel is not None:
        try:
            target_intel.update_from_nmap(
                [line for _, line in clean_log])
        except Exception as e:
            msg = f"[HAWK] proxychains nmap-parse error: {e}"
            print(msg)
            if terminal is not None:
                try:
                    terminal.write(
                        f"  [!] proxychains nmap parser failed: {e} "
                        f"— ports not extracted", "warn")
                except Exception:
                    pass
    try:
        parse_output_to_intel_cb(tool, clean_log)
    except Exception as e:
        msg = f"[HAWK] proxychains finding-push error: {e}"
        print(msg)
        if terminal is not None:
            try:
                terminal.write(
                    f"  [!] proxychains finding push failed: {e}", "warn")
            except Exception:
                pass


class CardRuntimeMixin:
    def _osint_preflight(self, tool) -> bool:
        """
        Validate target and API-key availability for OSINT tools
        (whois, theHarvester, subfinder, amass).

        Returns:
            True  → preflight consumed the run (dialog shown, or blocked).
                    Caller must NOT continue routing.
            False → no OSINT concern, continue normal routing.
        """
        binary = (tool.binary or "").lower()
        tid    = (tool.id or "").lower()
        osint_tools = {"whois", "theharvester", "subfinder", "amass",
                       "nslookup", "dig", "host",
                       "dnsrecon", "fierce", "assetfinder"}
        if binary not in osint_tools and not any(
                tid.startswith(x) for x in osint_tools):
            return False

        target = self._get_target()
        if not target:
            return False   # let the normal path handle "no target" UX

        # 1. Target validation
        try:
            from utils.target_validator import (
                validate_for_tool, private_block, classify_target)
        except Exception:
            return False

        # Tools that MUST receive a domain as their argument. If the session
        # target is an IP and there's a saved target_domain, substitute it
        # silently; otherwise prompt the user. dnsrecon/fierce/dnsenum/
        # assetfinder all expect a domain and fail or emit nothing useful
        # when handed an IP.
        _DOMAIN_REQUIRED = ("subfinder", "amass", "dnsrecon", "fierce",
                            "dnsenum", "assetfinder")
        if binary in _DOMAIN_REQUIRED:
            kind = classify_target(target)
            if kind != "domain":
                saved_domain = ""
                try:
                    sess = self.app.session_manager.current
                    if sess:
                        saved_domain = (getattr(sess, "target_domain", "") or "").strip()
                except Exception:
                    saved_domain = ""
                if saved_domain:
                    # Re-validate in case the saved value is stale/corrupted
                    from utils.target_validator import is_domain
                    if is_domain(saved_domain):
                        self._run_osint_on_domain(tool, saved_domain)
                        return True
                # No saved domain → ask the user
                self._prompt_domain_for_osint(tool, current_target=target)
                return True
            # target IS a domain → fall through to key-check + run

        ok, reason, suggestion = validate_for_tool(target, binary or tid)
        if not ok:
            self._show_osint_block_dialog(tool, target, reason, suggestion)
            return True

        # 2. API-key pre-flight (subfinder, amass, theHarvester)
        key_tools = {"theharvester", "subfinder", "amass"}
        if binary in key_tools:
            try:
                from utils.apikeys import (
                    config_arg_for, has_keys_for, write_all_configs)
            except Exception:
                return False

            tool_key = "theHarvester" if binary == "theharvester" else binary
            if not has_keys_for(tool_key):
                self._show_apikey_dialog(tool, tool_key)
                return True

            # Regenerate config files so the tool picks up the latest keys
            try:
                write_all_configs()
            except Exception as e:
                print(f"[HAWK] write_all_configs failed: {e}")
        else:
            config_arg_for = lambda _tool: ""

        if binary == "subfinder":
            cfg = config_arg_for("subfinder")
            cfg = f" {cfg}" if cfg else ""
            cmd = f"timeout 180 subfinder{cfg} -d {_shq(target)} -silent"
            self._run_raw(tool, cmd)
            return True

        # 3. Amass needs a mode choice (passive/active/intel) + timeout
        if binary == "amass":
            self._show_amass_mode_dialog(tool)
            return True

        # 4. theHarvester: offer a timeout wrapper so private/slow targets
        #    don't hang forever
        if binary == "theharvester":
            self._run_theharvester_safe(tool)
            return True

        return False

    def _show_osint_block_dialog(self, tool, target, reason, suggestion):
        from gui.dialogs import _make_win, _note_box, _btn_row, _btn, _safe_destroy
        win = _make_win(self, f"{tool.name} — Target Not Supported", 560, 320)
        ctk.CTkLabel(
            win, text=f"⚠  {tool.name}: unsuitable target",
            font=_f("xl", True),
            text_color=COLORS["text_yellow"]).pack(pady=(14, 6))
        _note_box(win,
                  f"Target:  {target}\n\n{reason}",
                  COLORS["text_yellow"])
        if suggestion:
            _note_box(win,
                      f"Alternative:\n  {suggestion}",
                      COLORS["text_green"])
        row = _btn_row(win)
        _btn(row, "UNDERSTOOD", lambda: _safe_destroy(win), primary=True, w=140)

    def _show_apikey_dialog(self, tool, tool_key: str):
        from gui.dialogs import ApiKeyManagerDialog

        def _after_save():
            # Keys saved — run it now
            self._continue_osint_run(tool)

        def _skip():
            # Proceed without keys (user accepts degraded results)
            self._continue_osint_run(tool)

        ApiKeyManagerDialog(
            self, tool=tool_key,
            on_save=_after_save,
            on_skip=_skip)

    def _continue_osint_run(self, tool):
        """Resume OSINT run after keys dialog — re-enter preflight, which
        will now pass the key check and fall through to amass-mode/timeout."""
        binary = (tool.binary or "").lower()
        config_arg_for = lambda _tool: ""
        if binary == "amass":
            self._show_amass_mode_dialog(tool)
        elif binary == "theharvester":
            self._run_theharvester_safe(tool)
        elif binary == "subfinder":
            try:
                from utils.apikeys import config_arg_for, write_all_configs
                write_all_configs()
                cfg = config_arg_for("subfinder")
            except Exception:
                cfg = ""
            cfg = f" {cfg}" if cfg else ""
            target = self._get_target()
            cmd = f"timeout 180 subfinder{cfg} -d {_shq(target)} -silent"
            self._run_raw(tool, cmd)
        else:
            self._run_tool(tool)

    def _prompt_domain_for_osint(self, tool, current_target: str = ""):
        """
        subfinder / amass enum need a DOMAIN. When the session target is an
        IP (public or private), pop a small dialog to capture the domain and
        run the tool against THAT domain instead of the IP.
        """
        from gui.dialogs import _make_win, _note_box, _btn_row, _btn, _safe_destroy
        from utils.target_validator import is_domain

        binary = (tool.binary or "").lower()
        win = _make_win(self, f"{tool.name} — Domain Required", 560, 340)

        # Use a body frame (see fix for pack/grid mixing with _make_win).
        body = ctk.CTkFrame(win, fg_color=COLORS["bg_primary"], corner_radius=0)
        body.pack(fill="both", expand=True)

        ctk.CTkLabel(body, text=f"{tool.name} — enter a domain",
                     font=_f("xl", True),
                     text_color=COLORS["text_green"]).pack(pady=(14, 6))
        _note_box(body,
                  f"Current target: {current_target or '(none)'}\n\n"
                  f"{tool.name} enumerates SUBDOMAINS — it needs a domain, "
                  "not an IP. Enter the domain you want to enumerate.\n\n"
                  "TIP: tick 'Save to session' to make it the default domain — "
                  "subfinder/amass will use it automatically on the next run.",
                  COLORS["text_yellow"])

        domain_var = ctk.StringVar(value="")
        entry = ctk.CTkEntry(
            body, textvariable=domain_var, height=32,
            placeholder_text="e.g. example.com",
            font=_f("md"), fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            placeholder_text_color=COLORS["text_muted"],
            corner_radius=3)
        entry.pack(fill="x", padx=28, pady=(4, 4))
        try:
            entry.focus_set()
        except Exception:
            pass

        # Save-to-session checkbox (default ON: the whole point of target_domain)
        save_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            body,
            text="Save to session as Target Domain (skip this prompt next time)",
            variable=save_var,
            font=_f("sm"), text_color=COLORS["text_dim"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            checkmark_color=COLORS["bg_primary"],
            width=18, height=18,
        ).pack(anchor="w", padx=28, pady=(4, 2))

        err_lbl = ctk.CTkLabel(body, text="", font=_f("sm"),
                               text_color=COLORS["text_red"])
        err_lbl.pack(pady=(2, 4))

        def _go():
            d = domain_var.get().strip().rstrip(".")
            if not d or not is_domain(d):
                err_lbl.configure(text="⚠  Not a valid domain name.")
                return
            # Persist to session + reflect in the target bar
            if save_var.get():
                try:
                    sess = self.app.session_manager.current
                    if sess:
                        sess.target_domain = d
                        sess.save()
                        if hasattr(self.app, "target_bar"):
                            self.app.target_bar.set_target_domain(d)
                        self.app.terminal.write(
                            f"[+] Target domain saved to session: {d}", "success")
                except Exception as e:
                    print(f"[HAWK] failed to persist target_domain: {e}")
            _safe_destroy(win)
            self._run_osint_on_domain(tool, d)

        entry.bind("<Return>", lambda e: _go())
        row = _btn_row(body)
        _btn(row, "RUN ON THIS DOMAIN", _go, primary=True, w=200)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _run_osint_on_domain(self, tool, domain: str,
                              skip_key_check: bool = False):
        """Run a domain-aware OSINT tool against a user-provided domain,
        bypassing the session target. Enforces the API-key pre-flight once
        (for tools that actually use keys).

        `skip_key_check=True` is used by the ApiKeyManagerDialog callbacks so
        that "Run without keys" / "Save and run" do NOT re-enter the key
        check (which would just re-open the dialog forever when the user
        hasn't saved any keys)."""
        binary = (tool.binary or "").lower()
        config_arg_for = lambda _tool: ""

        # API-key check — only for tools that actually use keys. dnsrecon /
        # fierce / dnsenum / assetfinder never need keys, so don't gate them
        # on a dialog that would be irrelevant and confusing.
        needs_keys = binary in self._KEY_AWARE_OSINT
        if needs_keys and not skip_key_check:
            try:
                from utils.apikeys import (
                    config_arg_for, has_keys_for, write_all_configs)
                tool_key = binary
                if not has_keys_for(tool_key):
                    self._show_apikey_dialog_for_domain(tool, tool_key, domain)
                    return
                try:
                    write_all_configs()
                except Exception as e:
                    print(f"[HAWK] write_all_configs failed: {e}")
            except Exception as e:
                print(f"[HAWK] OSINT domain key preflight failed: {e}")
        elif needs_keys and skip_key_check:
            # Dialog already consumed — just refresh config files in case
            # keys were saved in this pass.
            try:
                from utils.apikeys import config_arg_for, write_all_configs
                write_all_configs()
            except Exception as e:
                print(f"[HAWK] write_all_configs (skip branch) failed: {e}")

        if not tool.is_available():
            self._show_install_dialog(tool)
            return

        if binary == "subfinder":
            cfg = config_arg_for("subfinder")
            cfg = f" {cfg}" if cfg else ""
            cmd = f"timeout 180 subfinder{cfg} -d {_shq(domain)} -silent"
        elif binary == "amass":
            self._show_amass_mode_dialog(tool, domain_override=domain)
            return
        else:
            cmd = tool.build_command(domain)

        self._run_raw(tool, cmd)

    def _show_apikey_dialog_for_domain(self, tool, tool_key: str, domain: str):
        from gui.dialogs import ApiKeyManagerDialog

        def _after():
            # skip_key_check=True so the dialog is NOT reopened — otherwise
            # clicking "Run without keys" loops straight back here.
            self._run_osint_on_domain(tool, domain, skip_key_check=True)

        ApiKeyManagerDialog(
            self, tool=tool_key,
            on_save=_after,
            on_skip=_after)

    def _show_amass_mode_dialog(self, tool, domain_override: str = None):
        """Offer amass passive / active / intel with sensible timeout."""
        from gui.dialogs import _make_win, _note_box, _btn_row, _btn, _safe_destroy
        target = domain_override or self._get_target()
        if not target:
            return
        try:
            from utils.apikeys import config_arg_for
            amass_cfg = config_arg_for("amass")
        except Exception:
            amass_cfg = ""
        amass_cfg = f" {amass_cfg}" if amass_cfg else ""

        win = _make_win(self, "AMASS — Enumeration Mode", 560, 380)
        ctk.CTkLabel(win, text="AMASS — choose enumeration mode",
                     font=_f("xl", True),
                     text_color=COLORS["text_green"]).pack(pady=(14, 6))
        _note_box(win,
                  "passive  →  only public OSINT sources (safe, no traffic to target)\n"
                  "active   →  DNS brute-force + zone walking (noisy, hits the target)\n"
                  "intel    →  ASN / org / whois correlation — maps the attack surface",
                  COLORS["text_dim"])

        mode = {"v": "passive"}

        def _go():
            m = mode["v"]
            _safe_destroy(win)
            if m == "passive":
                cmd = f"timeout 180 amass enum{amass_cfg} -passive -d {_shq(target)}"
            elif m == "active":
                cmd = f"timeout 300 amass enum{amass_cfg} -active -d {_shq(target)}"
            else:
                cmd = f"timeout 180 amass intel{amass_cfg} -d {_shq(target)}"
            self._run_raw(tool, cmd)

        row1 = _btn_row(win)
        for label, val in [("PASSIVE", "passive"),
                           ("ACTIVE",  "active"),
                           ("INTEL",   "intel")]:
            def _mk(v=val):
                mode["v"] = v
                _go()
            _btn(row1, label, _mk,
                 primary=(val == "passive"), w=140)

        row2 = _btn_row(win)
        _btn(row2, "CANCEL", lambda: _safe_destroy(win))

    def _run_theharvester_safe(self, tool):
        """Run theHarvester wrapped in `timeout 120` so it can't hang."""
        target = self._get_target()
        if not target:
            return
        if not tool.is_available():
            self._show_install_dialog(tool)
            return
        cmd = f"timeout 120 theHarvester -d {_shq(target)} -b all -l 100"
        self._run_raw(tool, cmd)

    def _run_tool(self, tool, extra_args=""):
        target = self._get_target()
        if not target:
            return
        if not tool.is_available():
            self._show_install_dialog(tool)
            return
        cmd = tool.build_command(target, extra_args)
        self._run_raw(tool, cmd)

    def _poll_install_complete(self, tool, attempts: int = 40):
        """Poll tool.is_available() every 3s up to `attempts` times.
        When the binary shows up, refresh the row in place so the user
        sees the green ● + "RUN" button without having to click.

        Runs entirely on the Tk main thread via after() — no threads,
        no races with the ToolRunner.  Default 40 × 3s = 2 minutes
        window which is plenty for even slow pipx installs on Kali."""
        # Clear the extra-bin-dirs subprocess-probe cache so is_available
        # re-checks instead of trusting the stale 'not found' from the
        # pre-install check.
        try:
            from modules.base import _SUBPROC_POSITIVE_CACHE
            _SUBPROC_POSITIVE_CACHE.pop(tool.binary, None)
        except Exception:
            pass

        def _tick(remaining=attempts):
            try:
                if tool.is_available():
                    self._refresh_tool_row(tool)
                    self.app.terminal.write(
                        f"  [+] {tool.name} is now installed — row "
                        f"refreshed.", "success")
                    return
            except Exception:
                pass
            if remaining <= 1:
                self.app.terminal.write(
                    f"  [*] {tool.name} install polling gave up after "
                    f"{attempts * 3}s — click the tool button manually "
                    f"once the xterm reports '=== OK ==='.", "dim")
                return
            # Still missing — poll again in 3s
            self.after(3000, lambda: _tick(remaining - 1))

        # First tick with a 3s grace period so pipx has a chance to
        # start — no point polling 100ms after launch.
        self.after(3000, _tick)

    def _refresh_tool_row(self, tool):
        """Repaint a tool's row after its availability state changed
        (post-install).  Updates icon color, name color, description
        text/color, row background, button label/colors/command IN
        PLACE — no destroy/rebuild, no grid relayout, no flicker, no
        risk of the replacement row showing a stale color scheme."""
        w = self._tool_widgets.get(tool.id)
        if not w:
            return
        row_fr   = w.get("row")
        icon_lbl = w.get("icon")
        name_lbl = w.get("name_lbl")
        desc_lbl = w.get("desc_lbl")
        run_btn  = w.get("run_btn")
        if not (row_fr and row_fr.winfo_exists()):
            return

        install_first = tool.id in self._INSTALL_FIRST_IDS
        installed = tool.is_available()
        avail = installed or install_first

        # Row background — bg_secondary when active, bg_card when muted
        try:
            row_fr.configure(
                fg_color=(COLORS["bg_secondary"] if avail
                          else COLORS["bg_card"]))
        except Exception:
            pass

        # Icon — ready/done glyph + muted/dim color
        try:
            if icon_lbl is not None and icon_lbl.winfo_exists():
                icon_lbl.configure(
                    text_color=(COLORS["text_muted"] if avail
                                else COLORS["border_dim"]))
        except Exception:
            pass

        # Tool name — BRIGHT when available, MUTED when not.
        # User-reported bug: name stayed MUTED after install even though
        # the run button flipped to green.  Fixed by driving this label
        # directly from the tool cache ref instead of destroying the
        # whole row (which could race with grid relayout and leave the
        # old dim label visible).
        try:
            if name_lbl is not None and name_lbl.winfo_exists():
                name_lbl.configure(
                    text_color=(COLORS["text_bright"] if avail
                                else COLORS["text_muted"]))
        except Exception:
            pass

        # Description text + color — recompute from the same rules
        # _build_tool_row uses.
        desc_first = (tool.desc.split("\n")[0] if "\n" in tool.desc
                      else tool.desc)
        if install_first and not installed:
            desc_first = ("Not installed — click INSTALL to launch the "
                          "install wizard")
            desc_color = COLORS["text_yellow"]
        elif avail:
            desc_color = COLORS["text_dim"]
        else:
            try:
                strats = tool.get_install_strategies()
                short = (strats[0][1] if strats
                         else f"apt install -y {tool.binary}")
            except Exception:
                short = f"apt install -y {tool.binary}"
            desc_first = f"Not installed — {short}"
            desc_color = COLORS["text_muted"]
        try:
            if desc_lbl is not None and desc_lbl.winfo_exists():
                desc_lbl.configure(text=desc_first, text_color=desc_color)
        except Exception:
            pass

        # Run button — flip INSTALL/RUN + colors + command.
        try:
            if run_btn is not None and run_btn.winfo_exists():
                btn_label = ("INSTALL"
                             if (install_first and not installed)
                             else "RUN")
                btn_border = (COLORS["border_green"] if installed
                              else COLORS["border_amber"])
                btn_text = (COLORS["text_green"] if installed
                            else COLORS["text_yellow"])
                run_btn.configure(
                    text=btn_label,
                    border_color=btn_border,
                    text_color=btn_text,
                    # Command re-bound so the re-armed "RUN" routes
                    # through _gate_check (the actual launch), not
                    # through the install dialog like it used to.
                    command=(lambda t=tool:
                             self._show_install_dialog(t)
                             if (t.id in self._INSTALL_FIRST_IDS
                                 and not t.is_available())
                             else self._gate_check(t)),
                )
        except Exception:
            pass

    # NOTE: _show_target_command_dialog lives in CardAccessRoutesMixin
    # (gui/widgets/card_routes_access.py) and wins the MRO for KillChainCard
    # (CardRoutesMixin precedes CardRuntimeMixin).  A second copy used to sit
    # here and was shadowed dead code — removed so the target-shell dialog has
    # a single source of truth: the one that renders the lane banner and
    # serves BOTH the Linux finders and the Windows built-ins.

    def _show_install_dialog(self, tool):
        """Guide user to install a missing tool."""
        from gui.dialogs import _make_win, _note_box, _btn_row, _btn, _safe_destroy
        from utils.runner import _open_terminal

        # Get install strategies as a list of (label, command). We accept
        # both the new list format and the legacy plain-string fallback
        # so this works even if get_install_hint() is overridden elsewhere.
        strategies = []
        if hasattr(tool, "get_install_strategies"):
            try:
                strategies = tool.get_install_strategies() or []
            except Exception:
                strategies = []
        if not strategies:
            raw = tool.get_install_hint() if hasattr(tool, "get_install_hint") else ""
            if isinstance(raw, list):
                strategies = raw
            elif isinstance(raw, str) and raw:
                strategies = [("install", raw)]
            else:
                strategies = [("install", f"sudo apt install -y {tool.binary}")]
        # Compatibility for rest of the method — keep the legacy variable.
        hint = " || ".join(f"({c})" for _, c in strategies)

        # Manual-only flow for tools whose install hints break on modern Kali
        # (rustscan apt package gone, kerbrute not packaged at all, go/cargo
        # not preinstalled). We just print clean per-tool instructions and
        # open an empty shell so the user runs the commands themselves.
        manual = tool.id in self._MANUAL_INSTALL_IDS
        if manual:
            manual_hints = {
                "rustscan": (
                    "Rustscan is not in the current Kali repo. Install via "
                    "one of:\n\n"
                    "  # Option 1 — cargo (Rust toolchain):\n"
                    "  sudo apt install -y cargo && cargo install rustscan\n"
                    "  # then add ~/.cargo/bin to PATH if not already there.\n\n"
                    "  # Option 2 — prebuilt .deb:\n"
                    "  # https://github.com/bee-san/RustScan/releases\n"
                    "  sudo dpkg -i rustscan_*.deb\n\n"
                    "After install, click the RUSTSCAN button again — HAWK "
                    "re-checks $PATH and ~/.cargo/bin on every click."
                ),
                "kerbrute": (
                    "Kerbrute is not packaged on Kali. Install via one of:\n\n"
                    "  # Option 1 — prebuilt binary (recommended):\n"
                    "  wget https://github.com/ropnop/kerbrute/releases/latest"
                    "/download/kerbrute_linux_amd64 -O /tmp/kerbrute\n"
                    "  sudo install -m 0755 /tmp/kerbrute /usr/local/bin/kerbrute\n\n"
                    "  # Option 2 — build from source (needs Go):\n"
                    "  sudo apt install -y golang && \\\n"
                    "  git clone https://github.com/ropnop/kerbrute && \\\n"
                    "  cd kerbrute && make linux && \\\n"
                    "  sudo install -m 0755 dist/kerbrute_linux_amd64 "
                    "/usr/local/bin/kerbrute\n\n"
                    "If you get 'externally-managed-environment' with pip, "
                    "use pipx or a venv — but kerbrute does NOT need pip, "
                    "it's a Go binary. Just drop it in /usr/local/bin.\n\n"
                    "After install, click KERBRUTE again — HAWK re-checks "
                    "$PATH, ~/kerbrute, ~/go/bin on every click."
                ),
            }
            manual_hints["kerbrute_userenum"] = manual_hints["kerbrute"]

            win = _make_win(self, f"Install {tool.name}", 640, 460)
            ctk.CTkLabel(win, text=f"⚠  {tool.name} Not Installed",
                         font=_f("xl", True),
                         text_color=COLORS["text_yellow"]).pack(pady=(14,6))
            _note_box(win, manual_hints[tool.id], COLORS["text_yellow"])

            def _open_shell():
                _safe_destroy(win)
                # Build a tool-specific ready-to-paste command based on the
                # current target, so the user doesn't have to figure out
                # flags on the fly. The shell starts in $HOME with the line
                # pre-typed (via `read -e -p` fallback to just printed hint
                # if readline isn't cooperative).
                target = self._get_target() or "TARGET"
                domain = ""
                try:
                    domain = (self.app.session_manager.current.domain
                              if self.app.session_manager.current else "") or ""
                except Exception:
                    pass
                realm = domain or "DOMAIN.LOCAL"

                if tool.id in ("kerbrute", "kerbrute_userenum"):
                    sample_cmd = (
                        f"./kerbrute userenum -d {realm} --dc {target} "
                        f"/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
                    )
                    hint = (
                        f"# Test run (edit wordlist if needed):\n"
                        f"#   {sample_cmd}\n"
                        f"# Other modes:\n"
                        f"#   ./kerbrute passwordspray -d {realm} --dc {target} users.txt 'Password123'\n"
                        f"#   ./kerbrute bruteuser    -d {realm} --dc {target} rockyou.txt <user>\n"
                    )
                elif tool.id == "rustscan":
                    sample_cmd = f"rustscan -a {target} --ulimit 5000"
                    hint = (
                        f"# Fast full-port scan:\n"
                        f"#   {sample_cmd}\n"
                    )
                else:
                    sample_cmd = ""
                    hint = ""

                # Compose the inline shell script. We:
                #   1. Print the install hint (user pastes the wget/build lines)
                #   2. Print the ready-to-run sample command
                #   3. Drop into an interactive bash so user can tweak and run
                preamble = (
                    f"echo '=== Install {tool.name} manually — see HAWK "
                    f"dialog for instructions ==='; "
                )
                if hint:
                    # Use printf so newlines render; escape single quotes for xterm.
                    esc = hint.replace("'", "'\\''")
                    preamble += f"printf '%s\\n' '{esc}'; "
                preamble += "cd ~ && "

                # If we have a sample command, inject it into bash history so
                # the user can recall it with Up-arrow after install.
                if sample_cmd:
                    hist = sample_cmd.replace('"', '\\"')
                    preamble += (
                        f'HISTFILE=~/.bash_history history -s "{hist}"; '
                        f'echo "  (↑ arrow recalls the sample command above)"; '
                    )

                _open_terminal(
                    f"HAWK — Install {tool.name} (manual)",
                    preamble + "bash")
                self.app.terminal.write(
                    f"  [*] Opened shell for manual {tool.name} install.\n"
                    f"  [*] Sample command pre-loaded into history — press "
                    f"↑ arrow after install.\n"
                    f"  [*] After install, click the {tool.name} button "
                    f"again — HAWK rechecks the binary on every click.",
                    "info")

            row = _btn_row(win)
            _btn(row, "OPEN SHELL", _open_shell, primary=True, w=160)
            _btn(row, "CLOSE", lambda: _safe_destroy(win))
            return

        # Default flow — tool has one or more install strategies. Show the
        # full cascade to the user; they can pick "Auto" (try all in order,
        # stop at first success) or an individual strategy.
        h = 300 if len(strategies) <= 1 else min(520, 260 + 60 * len(strategies))
        win = _make_win(self, f"Install {tool.name}", 620, h)
        ctk.CTkLabel(win, text=f"⚠  {tool.name} Not Installed",
                     font=_f("xl", True),
                     text_color=COLORS["text_yellow"]).pack(pady=(14,6))

        intro = (f"Tool binary: {tool.binary}\n"
                 f"HAWK searches $PATH plus ~/.cargo/bin, ~/go/bin, "
                 f"~/.local/bin,\n/usr/local/bin and runs '{tool.binary} --help' "
                 f"as a last check.\nPick an install strategy below — HAWK "
                 f"runs it in a new xterm.")
        _note_box(win, intro, COLORS["text_yellow"])

        # Strategy picker (radio). "auto" = cascade all with ||.
        choice_var = ctk.StringVar(value="auto")
        opts = [("auto", "Auto — try each strategy in order, stop at first success")]
        for label, cmd in strategies:
            pretty = cmd if len(cmd) < 72 else cmd[:68] + "…"
            opts.append((label, f"{label:>8}  —  {pretty}"))

        picker = ctk.CTkFrame(win, fg_color="transparent")
        picker.pack(fill="x", padx=24, pady=(6, 4))
        for val, lbl in opts:
            ctk.CTkRadioButton(
                picker, text=lbl, variable=choice_var, value=val,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["text_green"],
                border_color=COLORS["border_dim"]).pack(anchor="w", pady=2)

        def _install():
            sel = choice_var.get()
            if sel == "auto":
                chain = " || ".join(f"({c})" for _, c in strategies)
                display_cmd = chain
            else:
                chain = next((c for l, c in strategies if l == sel), hint)
                display_cmd = chain
            _safe_destroy(win)
            # Wrap in a function so failure is visible. The echoed banner
            # makes xterm logs easier to skim if multiple installs fail.
            script = (
                f"echo '=== Installing {tool.name} ({sel}) ==='; "
                f"echo '$ {display_cmd}'; echo ''; "
                f"{chain}; RC=$?; "
                f"echo ''; "
                f"if [ $RC -eq 0 ]; then "
                f"echo '=== OK — {tool.name} installed ==='; "
                f"else echo \"=== FAILED (exit $RC) — try another strategy or "
                f"install manually ===\"; fi; "
                f"read -p 'Press ENTER to close...'"
            )
            _open_terminal(f"HAWK — Install {tool.name}", script)
            self.app.terminal.write(
                f"  [*] Installing {tool.name} in xterm (strategy: {sel}).\n"
                f"  [*] Polling binary availability every 3 s — "
                f"the tool row will flip to green automatically when "
                f"{tool.binary} appears on PATH / ~/.local/bin.", "info")
            # Kick off a background poll that re-renders the row the
            # instant the binary becomes available.  Previously the row
            # stayed dark-grey until the user manually re-clicked —
            # source of the user-reported "tool seems not installed
            # but RUN works" confusion.
            self._poll_install_complete(tool, attempts=40)

        row = _btn_row(win)
        _btn(row, "INSTALL IN XTERM", _install, primary=True, w=180)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _run_raw(self, tool, cmd: str):
        # Safety guard — refuse to launch a command that still has
        # <user>/<password>/<domain>/<TARGET_COMPUTER>/<CA_NAME> etc.
        # literal placeholders.  These are the fallback values that
        # Tool.build_command() inserts when no dialog filled the
        # slots — passing them to the shell causes "cannot open
        # user: No such file" (shell treats `<user>` as stdin
        # redirection from a file named "user").
        import re as _re
        placeholder_hits = _re.findall(r"<([A-Za-z_][A-Za-z0-9_]*)>", cmd)
        # Case-insensitive match — the base.Tool.build_command fallback
        # mixes cases ("<user>" lowercase, "<DOMAIN>" upper, "<TARGET_
        # COMPUTER>" upper) so normalise both sides before comparing.
        _KNOWN_PLACEHOLDERS = {
            "user", "password", "domain", "target_computer",
            "ca_name", "template", "domain_sid",
        }
        unresolved = [p for p in placeholder_hits
                      if p.lower() in _KNOWN_PLACEHOLDERS]
        if unresolved:
            self.app.terminal.section(
                f"{self.phase_config['name']}  ·  {tool.name}")
            self.app.terminal.write(
                f"[!] {tool.name} blocked — command still has unfilled "
                f"placeholder(s): {', '.join('<'+p+'>' for p in unresolved)}",
                "error")
            self.app.terminal.write(
                f"    The tool needs credentials / template values that "
                f"weren't provided.  If this is an AD-pentesting tool, "
                f"re-launch it so the auth dialog can collect them.  "
                f"If it's a template with a literal <CA_NAME> or similar, "
                f"use Target Intel → INFO to see what the tool expects "
                f"and supply it manually.", "warn")
            self.app.terminal.write(f"    Skipped command:  {cmd}", "dim")
            # Don't flip the row status to running — leave it "ready".
            return
        self._set_tool_status(tool.id, "running")
        self.set_status(STATUS_RUNNING)
        self._toggle_run_btn(tool, True)
        # Per-tool buffer: a concurrent run on the same card must not
        # wipe the output another tool is still waiting to have parsed.
        raw_log = []
        self._raw_logs[tool.id] = raw_log
        self._raw_log = raw_log
        # Stash the command on the tool's widget dict so per-tool
        # parsers (e.g. _parse_smb_output) can inspect the actual
        # invocation — knowing whether the run was anonymous (-N)
        # or authenticated (-U user%pass) is essential to produce a
        # correct Target Intel finding and to decide whether to
        # push used credentials into the Credential Store.
        if tool.id in self._tool_widgets:
            self._tool_widgets[tool.id]["_last_cmd"] = cmd
        self.app.terminal.section(
            f"{self.phase_config['name']}  ·  {tool.name}")
        self.app.terminal.write(f"  $ {cmd}", "cmd")

        # Record this execution in the session — finalized in _on_done
        exec_id = None
        try:
            sess = self.app.session_manager.current
            if sess is not None:
                exec_id = sess.start_tool_execution(
                    tool_id=tool.id, tool_name=tool.name,
                    phase_id=self.phase_id, command=cmd)
        except Exception as e:
            print(f"[HAWK] start_tool_execution failed: {e}")
        # Stash exec_id on the tool widget dict so _on_done can retrieve it,
        # together with the identity of the session this run belongs to —
        # a tool that outlives a session switch must not write the old
        # target's output into the session that is current when it ends.
        if tool.id in self._tool_widgets:
            self._tool_widgets[tool.id]["_exec_id"] = exec_id
            self._tool_widgets[tool.id]["_session_token"] = (
                self.app.session_token())

        # Show initial progress bar at 0% for scan tools so the user
        # sees immediate feedback even on fast scans.
        # Use after(0) so the bar appears AFTER the "$ cmd" line
        # (which is also deferred via terminal.write → self.after).
        if tool.binary in ("nmap", "masscan", "rustscan"):
            self.app.terminal.after(0, lambda tn=tool.name:
                self.app.terminal._update_progress(
                    0.0, "Starting scan", "", tn))

        def _out(line, name, level):
            raw_log.append(line)
            self.app.terminal.output_callback(line, name, level)

        runner = ToolRunner(
            output_callback=_out,
            done_callback=lambda n, rc, log: self._on_done(tool, n, rc, log),
            ui_dispatcher=getattr(self.app, "ui_call", None))
        self._tool_runners[tool.id] = runner

        # Per-tool cwd override.  Some tools (currently only
        # bloodhound-python) drop their output as a file in the *current
        # working directory* and offer no `--output-dir` flag.  Letting
        # them write to whatever cwd the HAWK process happens to have
        # makes the produced .zip hard to find later — we pre-create a
        # session-scoped directory and run the tool inside it, so the
        # parser knows exactly where to look and the user gets a stable
        # path on disk.  Falls back to None (= inherit HAWK cwd) for
        # every other tool, preserving the previous behavior.
        cwd = None
        if tool.id == "bloodhound_python":
            try:
                from utils.config import SESSIONS_DIR
                from utils.run_id import new_run_id
                sess = self.app.session_manager.current
                sid = (sess.session_id if sess else "default")[:16]
                target = self._get_target() or "target"
                safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:40]
                rid = new_run_id()
                cwd = os.path.join(
                    SESSIONS_DIR, sid, "bloodhound",
                    f"{safe_target}_{rid}")
                os.makedirs(cwd, exist_ok=True)
                # Stash on the tool widget so _parse_bloodhound_to_intel
                # can glob the exact dir instead of guessing.
                if tool.id in self._tool_widgets:
                    self._tool_widgets[tool.id]["_cwd"] = cwd
                self.app.terminal.write(
                    f"  [hawk] bloodhound output dir: {cwd}", "dim")
            except Exception as e:
                # Non-fatal: if anything goes wrong setting up the dir,
                # fall back to legacy behavior (zip in process cwd).
                print(f"[HAWK] bloodhound cwd setup failed: {e}")
                cwd = None

        # Tool.timeout has existed in modules/base.py since day one and
        # was never read — a hung tool held the reader thread forever.
        runner.run(cmd, tool.name, cwd=cwd,
                   timeout=getattr(tool, "timeout", None))

    def _record_tool_start(self, tool, cmd: str):
        """Open a session execution record for a run launched OUTSIDE the
        standard _run_raw path (background jobs, ORACLE, Bloody Crawl).

        These paths used to skip start_tool_execution, so they never
        landed in session.executed_tools — the log that drives the
        tool-status dot restore on session reload (target_bar.apply_
        session) and the session tool-history / reports.  We stash the
        exec_id where _on_done already looks for it, so the finish is
        handled by the same _on_done every one of these paths calls.
        """
        exec_id = None
        try:
            sess = self.app.session_manager.current
            if sess is not None:
                exec_id = sess.start_tool_execution(
                    tool_id=tool.id, tool_name=tool.name,
                    phase_id=self.phase_id, command=cmd)
        except Exception as e:
            print(f"[HAWK] start_tool_execution failed: {e}")
        if tool.id in self._tool_widgets:
            self._tool_widgets[tool.id]["_exec_id"] = exec_id
        return exec_id

    def _run_in_background(self, tool, cmd: str, estimated_secs: int):
        import uuid
        job_id = str(uuid.uuid4())[:8]

        # Stash the command on the tool's widget dict so per-tool
        # parsers (e.g. _extract_web_target_label, _parse_smb_output)
        # can inspect the actual invocation — the foreground `_run`
        # path already does this, the background path used to skip
        # it, which left every gobuster/dirb/ffuf finding with a
        # bare-IP title (no scope, no port, no path → wrong merge).
        if tool.id in self._tool_widgets:
            self._tool_widgets[tool.id]["_last_cmd"] = cmd

        # Identity of the session this job belongs to.  Background jobs
        # are the longest-lived thing HAWK starts (hydra runs for hours),
        # so they are the most likely to finish after the operator has
        # switched target — at which point their credentials and output
        # would be filed under the wrong session, or dropped silently
        # while the popup still said "completed".
        session_token = self.app.session_token()
        if tool.id in self._tool_widgets:
            self._tool_widgets[tool.id]["_session_token"] = session_token

        # Record this run in the session (executed_tools) so its dot is
        # restored on reload and it shows in the tool history / report.
        # The finish is applied by _on_done, called at the end of _done.
        self._record_tool_start(tool, cmd)

        def _done(name, rc, log):
            if not self.app.session_token_valid(
                    session_token, f"{tool.name} background job"):
                # Drop the job from the bar so it doesn't linger as a
                # phantom row, but write nothing into the new session.
                try:
                    self.app.bg_jobs_bar.finish_job(
                        job_id,
                        f"Aborted by session switch — results belong to "
                        f"the previous target and were NOT saved.")
                except Exception as e:
                    print(f"[HAWK] bg job discard failed: {e}")
                self._toggle_run_btn(tool, False)
                self._set_tool_status(tool.id, "ready")
                return
            cred_lines = [l for _, l in log
                          if "login:" in l.lower()
                          and "password:" in l.lower()]
            # Extract (user, password) pairs from hydra's success
            # lines BEFORE saving anything to the Credential Store.
            # If hydra was attacking a misconfigured target (the
            # classic "GET /  → 200 OK regardless of auth" trap)
            # every attempt looks successful and we'd flood the
            # store with garbage — utils.hydra_verify catches this
            # via a fake-password counter-check probe.
            import re as _re
            extracted: list[tuple[str, str]] = []
            for line in cred_lines:
                m = _re.search(
                    r"login:\s*(\S+)\s+password:\s*(\S+)",
                    line, _re.I)
                if m:
                    extracted.append((m.group(1), m.group(2)))

            # Run the false-positive cascade check.  Only kicks in
            # for hydra (the binary that famously cascades); other
            # tools that flow through this background path are
            # already trustworthy.
            # (user, password, probe) triples: probe is True when HAWK
            # authenticated the cred itself, None when no verifier
            # applies.  Anything hydra reported that our own probe
            # rejected never gets here.
            kept = [(u, p, None) for u, p in extracted]
            cred_note = ""
            cascade_reason = None
            if (extracted and
                    (tool.binary == "hydra"
                     or tool.id.startswith("hydra"))):
                try:
                    from utils.hydra_verify import (
                        parse_hydra_cmd, verify_creds, unverified_note)
                    cmd_info = parse_hydra_cmd(cmd)
                    cred_note = unverified_note(cmd_info)
                    self.app.terminal.write(
                        f"  [*] hydra: verifying "
                        f"{len(extracted)} candidate cred(s) "
                        f"against {cmd_info.proto}://"
                        f"{cmd_info.host}:{cmd_info.port}"
                        f"{cmd_info.path} via fake-password "
                        f"counter-check…", "dim")
                    kept, rejected, cascade_reason, is_cascade = (
                        verify_creds(extracted, cmd_info))
                    for _u, _p in rejected:
                        self.app.terminal.write(
                            f"  [!] hydra reported {_u} but HAWK's own "
                            f"{cmd_info.proto or 'auth'} probe was "
                            f"REJECTED — credential dropped, not "
                            f"saved.", "error")
                    if is_cascade:
                        self.app.terminal.write(
                            f"  [!] HYDRA FALSE-POSITIVE CASCADE "
                            f"DETECTED — dropping "
                            f"{len(extracted)} candidate cred(s) "
                            f"reported by hydra.", "error")
                        for ln in (cascade_reason or "").splitlines():
                            self.app.terminal.write(
                                f"      {ln}", "warn")
                        # Add a HIGH finding to Target Intel so the
                        # operator can navigate to the warning even
                        # after the terminal scrolls away.
                        try:
                            from utils.run_id import new_run_id
                            rid = new_run_id()
                            self.app.target_intel.add_auto_finding(
                                title=(f"HYDRA false-positive "
                                       f"cascade on "
                                       f"{cmd_info.proto}://"
                                       f"{cmd_info.host}:"
                                       f"{cmd_info.port}"),
                                description=cascade_reason,
                                severity="high",
                                source="hydra-verify",
                                linked_run_id=rid)
                        except Exception as e:
                            print(f"[HAWK] hydra cascade "
                                  f"finding push failed: {e}")
                    else:
                        n_proven = sum(1 for _, _, v in kept if v is True)
                        self.app.terminal.write(
                            f"  [+] hydra verify: counter-check "
                            f"clean → {len(kept)} credential(s) "
                            f"kept, {n_proven} authenticated by "
                            f"HAWK's own probe.", "success")
                        if n_proven < len(kept):
                            self.app.terminal.write(
                                f"      {len(kept) - n_proven} saved as "
                                f"UNVERIFIED — {cred_note}", "warn")
                except Exception as e:
                    # Verifier failure → fall back to old
                    # behaviour (trust hydra) so we don't silently
                    # eat real creds.  They stay UNVERIFIED: nothing
                    # proved them.
                    print(f"[HAWK] hydra verify failed: {e}")
                    self.app.terminal.write(
                        f"  [!] hydra verify failed: {e} — "
                        f"falling back to legacy behaviour (saving "
                        f"without counter-check, as UNVERIFIED).",
                        "warn")
                    kept = [(u, p, None) for u, p in extracted]

            # Summary line shown in the bg-jobs bar when the job
            # finishes.  Hydra-style ("Found N credential(s)") only
            # makes sense for hydra; non-cred tools (gobuster, ffuf)
            # report discovered paths instead, counted from the live
            # log lines.
            is_hydra = (tool.binary == "hydra"
                        or tool.id.startswith("hydra"))
            is_kerbrute = (tool.binary == "kerbrute")
            if is_hydra:
                summary = (f"Found {len(kept)} credential(s)."
                           if kept else
                           (f"No credentials saved "
                            f"({len(extracted)} dropped as "
                            f"false-positive cascade)."
                            if cascade_reason else
                            "No credentials found."))
            elif is_kerbrute:
                summary = kerbrute_run_summary(
                    [ln for _, ln in log], rc)
            else:
                # Content-discovery tools (gobuster / ffuf / dirb): count
                # hits using the SAME regex set + noise filter + dedup
                # key that the structured parser
                # `card_parsers_web._parse_gobuster_to_intel` uses, so
                # the number in the BG-job dialog matches exactly the
                # number of entries that end up in the Target Intel
                # finding.  Mismatch is what the user complained about
                # ("4 paths found" but the terminal had 800+ raw hits
                # scrolling past, with no way to tell which 4 ended up
                # in the finding).
                #
                # Parser parity rules:
                #   • Status codes 400 / 404 / 500 are noise (server
                #     side rejections, never real discovery).
                #   • Dedup key is (path, status) — gobuster sometimes
                #     prints the same path twice.
                #   • Path leading slash is normalised the same way
                #     the parser does (gobuster classic prints "/admin",
                #     gobuster modern prints "admin").
                import re as _re
                _GB_RE = _re.compile(
                    r"^/?([A-Za-z0-9._~\-%][^\s]*)\s+"
                    r"\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]")
                _DIRB_LINE_RE = _re.compile(
                    r"^\+\s+(\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)")
                _DIRB_DIR_RE = _re.compile(
                    r"^==>\s+DIRECTORY:\s+(\S+)")
                _FFUF_RE = _re.compile(
                    r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)")
                _NOISE = {400, 404, 500}

                seen = set()
                hits = 0
                noise = 0

                def _bump(path, status):
                    nonlocal hits, noise
                    if status in _NOISE:
                        noise += 1
                        return
                    key = (path, status)
                    if key in seen:
                        return
                    seen.add(key)
                    hits += 1

                for _, ln in log:
                    s = (ln or "").strip()
                    if not s:
                        continue
                    m = _GB_RE.match(s)
                    if m:
                        word = m.group(1)
                        path = word if word.startswith("/") else "/" + word
                        _bump(path, int(m.group(2)))
                        continue
                    m = _DIRB_LINE_RE.match(s)
                    if m:
                        from urllib.parse import urlparse as _up
                        path = _up(m.group(1)).path or m.group(1)
                        _bump(path, int(m.group(2)))
                        continue
                    m = _DIRB_DIR_RE.match(s)
                    if m:
                        from urllib.parse import urlparse as _up
                        path = _up(m.group(1)).path or m.group(1)
                        _bump(path, 301)
                        continue
                    m = _FFUF_RE.match(s)
                    if m:
                        word = m.group(1)
                        path = word if word.startswith("/") else "/" + word
                        _bump(path, int(m.group(2)))
                        continue

                # User-requested copy: short and pointing at Target
                # Intel as source of truth.  Plural-aware (1 path vs
                # N paths).  Noise count intentionally omitted from
                # the success line so the dialog stays minimal — it
                # already lives in the Target Intel finding when it
                # matters.
                # Only the dir-busters (gobuster/dirb/ffuf) produce the
                # path table this branch counts.  Other bg tools that flow
                # here — nikto, nuclei, sqlmap, wpscan — push their findings
                # to Target Intel via their own parser, so `hits` is always
                # 0 for them and "No paths found" is wrong + confusing (the
                # operator sees a full NIKTO card yet a "No paths" popup).
                _PATH_BINS = {"gobuster", "dirb", "ffuf"}
                # gobuster in DNS mode enumerates subdomains, not paths —
                # it shares the "gobuster" binary but its hits land in
                # Target Intel like the other non-path scanners, so keep
                # it out of the "No paths found" branch.
                _is_path_tool = (
                    (tool.binary or "").lower() in _PATH_BINS
                    and (getattr(tool, "id", "") or "").lower() != "gobuster_dns")
                _word = "path" if hits == 1 else "paths"
                if rc == 0:
                    if not _is_path_tool:
                        summary = ("Scan complete — findings (if any) are "
                                   "in Target Intel.")
                    elif hits == 0:
                        summary = "No paths found."
                    else:
                        summary = (f"{hits} {_word} found — "
                                   f"see Target Intel for details.")
                else:
                    # Non-zero exit: be explicit so the user knows the
                    # tool itself failed (not a clean empty result).
                    if not _is_path_tool:
                        summary = (f"Exited rc={rc} — scan incomplete; "
                                   f"see Target Intel / terminal.")
                    elif hits == 0:
                        summary = (f"Exited rc={rc}; no paths captured.")
                    else:
                        summary = (f"Exited rc={rc}; "
                                   f"{hits} {_word} captured — "
                                   f"see Target Intel for details.")

            # Nikto-specific failure surface: when nikto exits non-zero
            # with very little output (typically only the banner — happens
            # on cmd-line parse errors, certain `-Tuning` + `-nolookup`
            # combos, or when the target rejects HEAD/OPTIONS hard), the
            # operator otherwise sees just "Exited rc=1" with no clue
            # why.  Append the executed command, the last captured
            # lines, and a quick troubleshooting checklist directly into
            # the BG-job summary so it shows up in the auto-popup.
            if (tool.binary == "nikto" and rc != 0
                    and len(log) <= 12):
                tail = [(ln or "").rstrip()
                        for _, ln in log[-10:]
                        if (ln or "").strip()]
                tail_block = "\n".join(f"    {l}" for l in tail) \
                    if tail else "    (no output captured)"
                summary = (
                    f"NIKTO exited early (rc={rc}) with only "
                    f"{len(log)} line(s) of output.\n\n"
                    f"Command:\n"
                    f"    {cmd}\n\n"
                    f"Last output lines:\n"
                    f"{tail_block}\n\n"
                    f"Common causes:\n"
                    f"  - `-Tuning` set to a single class with no "
                    f"applicable tests on this target.\n"
                    f"  - `-nolookup` + hostname target on a Perl "
                    f"build with a stale Net::DNS module.\n"
                    f"  - Target rejects HEAD/OPTIONS — nikto bails "
                    f"out treating the host as offline.\n"
                    f"  - Wrong port / SSL mismatch (try toggling "
                    f"-ssl / changing port).\n\n"
                    f"Quick fixes to try:\n"
                    f"  1. Re-run with the `[default] all tests` "
                    f"preset and uncheck `-nolookup`.\n"
                    f"  2. If still failing, run the command above "
                    f"in a terminal to see nikto's full stderr."
                )

            is_http = ("http" in tool.id.lower()
                       or "http" in cmd.lower())
            if is_http:
                svc_tag = "HTTP"
                method = ""
                if "http-post" in cmd.lower():
                    method = "POST"
                elif "http-get" in cmd.lower():
                    method = "GET"
                if method:
                    svc_tag = f"HTTP-{method}"
            else:
                svc_tag = tool.id.split("_")[-1].upper()
            # Weak-credentials finding.  A successful hydra brute used to
            # raise NOTHING in Target Intel (only the false-positive
            # cascade path did), so a real compromise — e.g.
            # msfadmin:msfadmin on MS2 SSH — never showed in the panel or
            # the report even though the cred was saved.  Push a stable-
            # titled HIGH finding so re-runs UPDATE (merge key = title+port)
            # instead of stacking a new card.
            if is_hydra and kept and not cascade_reason:
                try:
                    from utils.hydra_verify import parse_hydra_cmd as _phc
                    _ci = _phc(cmd)
                    _fhost = _ci.host or self._get_target() or "target"
                    _fport = _ci.port or None
                except Exception:
                    _fhost = self._get_target() or "target"
                    _fport = None
                _n_ver = sum(1 for _, _, v in kept if v is True)
                _cred_lines = "\n".join(
                    f"  - {u}:{p}"
                    + ("  [verified]" if v is True else "  [unverified]")
                    for u, p, v in kept)
                try:
                    self.app.target_intel.add_auto_finding(
                        title=f"Weak credentials — {svc_tag} on {_fhost}",
                        description=(
                            f"hydra recovered {len(kept)} credential(s) "
                            f"({_n_ver} verified by HAWK's own probe) on "
                            f"{svc_tag} {_fhost}"
                            + (f":{_fport}" if _fport else "")
                            + ".\n" + _cred_lines
                            + "\n\nSaved to the Credential Store."),
                        severity="high",
                        source="hydra",
                        port=_fport,
                        replace=True)
                except Exception as e:
                    print(f"[HAWK] hydra success finding push failed: {e}")
            for u, p, probe in kept:
                # VERIFIED only when HAWK's own probe authenticated
                # the credential — hydra saying so is not proof (see
                # utils/hydra_verify).  Everything else is stored
                # unverified and says why in the notes.
                cred = Credential(
                    username=u, password=p,
                    cred_type="cleartext",
                    services=[svc_tag],
                    source_phase=self.phase_id,
                    notes=("" if probe is True
                           else (cred_note
                                 or "[unverified - no HAWK probe]")),
                    verified=(probe is True))
                self.app.cred_store.add_credential(cred)
            self.app.bg_jobs_bar.finish_job(job_id, summary)
            self.after(0, lambda: self._on_done(tool, name, rc, log))

        import time as _t_bg
        from utils.config import OUTPUTS_DIR as _BG_OUTDIR
        log_fname = (f"bg-{tool.id}-{_t_bg.strftime('%Y%m%d-%H%M%S')}"
                     f"-{job_id}.log")
        log_path = os.path.join(_BG_OUTDIR, log_fname)
        _bg_log_fh = open(log_path, "w", buffering=1)

        def _bg_output(line, name, level):
            try:
                _bg_log_fh.write(line + "\n")
            except Exception:
                pass
            self.app.terminal.output_callback(line, name, level)

        def _bg_done_wrapper(name, rc, log):
            try:
                _bg_log_fh.close()
            except Exception:
                pass
            _done(name, rc, log)

        runner = ToolRunner(
            output_callback=_bg_output,
            done_callback=_bg_done_wrapper,
            ui_dispatcher=getattr(self.app, "ui_call", None))
        from gui.widgets.bg_jobs_bar import BackgroundJob
        bg_label = f"{tool.name}"
        if tool.binary == "hydra" or tool.id.startswith("hydra"):
            method = ""
            if "http-post" in cmd.lower():
                method = "HTTP-POST"
            elif "http-get" in cmd.lower():
                method = "HTTP-GET"
            elif "http-form" in cmd.lower():
                method = "HTTP-FORM"
            if method:
                bg_label = f"Hydra {method}"
        self.app.bg_jobs_bar.add_job(
            BackgroundJob(job_id=job_id, label=bg_label,
                          estimated_secs=estimated_secs, runner=runner,
                          killable=True, log_path=log_path))
        # Force a synchronous repaint of the BG bar BEFORE the tool starts
        # producing output. Without this, fast-banner tools (ffuf, nuclei)
        # flood the terminal before Tk gets to repaint the bar, so the
        # entry "appears late" from the user's POV — even though the job
        # was registered immediately.
        try:
            self.app.bg_jobs_bar.update_idletasks()
        except Exception:
            pass
        # Register the runner and flip the row to STOP.  Without this the
        # row still said RUN while the job was on the wire, so the same
        # background job could be launched twice — and the row's STOP
        # had no runner to reach even once it appeared.
        self._tool_runners[tool.id] = runner
        runner.run(cmd, tool.name, timeout=getattr(tool, "timeout", None))
        self._set_tool_status(tool.id, "running")
        self.set_status(STATUS_RUNNING)
        self._toggle_run_btn(tool, True)

    def _extract_hydra_cred(self, line: str, tool):
        # NOTE: kept for backward compat / external callers that
        # might still wire to it.  The PRIMARY ingestion path is
        # now `_run_in_background._done` which buffers all
        # candidate creds, runs `utils.hydra_verify` to drop
        # false-positive cascades, and only then saves to the
        # Credential Store.  This single-line helper bypasses the
        # cascade check, so prefer the buffered path.
        import re
        m = re.search(r'login:\s*(\S+)\s+password:\s*(\S+)', line, re.I)
        if not m:
            return
        cred = Credential(
            username=m.group(1), password=m.group(2),
            cred_type="cleartext",
            services=[tool.id.split("_")[-1].upper()],
            source_phase=self.phase_id,
            # No cascade check and no probe on this path — nothing
            # here proves the credential authenticates.
            notes="[unverified - no HAWK probe]",
            verified=False)
        self.app.cred_store.add_credential(cred)

    def _run_greenbone(self, tool, scan_config: str):
        target = self._get_target()
        if not target:
            return
        self._set_tool_status(tool.id, "running")
        self.set_status(STATUS_RUNNING)
        self.app.terminal.section("GREENBONE / OpenVAS")
        runner = GreenBoneRunner(
            output_callback=self.app.terminal.output_callback,
            done_callback=lambda n, rc, log: self._on_done(tool, n, rc, log),
            ui_dispatcher=getattr(self.app, "ui_call", None))
        self._tool_runners[tool.id] = runner
        self._toggle_run_btn(tool, True)
        runner.run(target, scan_config)

    def _run_msf(self, tool, commands: list, lhost: str, lport: str):
        from utils.runner import is_port_free, find_free_port
        target = self._get_target()
        if not target:
            return
        # Safety net: LhostDialog already blocks busy ports with an explicit
        # conflict dialog, but a race is possible if another process grabs
        # the port between confirmation and launch. In that case ABORT and
        # tell the user — do NOT silently switch ports, they might expect
        # a specific LPORT (port-forwarding, firewall rule, etc.).
        try:
            port_int = int(lport)
            if not is_port_free(port_int):
                suggested = find_free_port(port_int + 1)
                self.app.terminal.write(
                    f"  [!] LPORT {lport} became busy right before launch.\n"
                    f"      Exploit aborted to avoid 'Handler failed to bind'.\n"
                    f"      Re-run with LPORT {suggested} (or another free port).",
                    "error")
                self._set_tool_status(tool.id, "error")
                return
        except ValueError:
            self.app.terminal.write(
                f"  [!] Invalid LPORT '{lport}' — exploit aborted.", "error")
            self._set_tool_status(tool.id, "error")
            return
        # Extract the MSF module name (for pre-flight routing) from the
        # already-substituted command list.
        exploit_name = ""
        for c in commands:
            cl = c.strip().lower()
            if cl.startswith("use exploit/") or cl.startswith("use auxiliary/"):
                exploit_name = c.split(None, 1)[-1].strip()
                break

        def _actually_launch():
            self._set_tool_status(tool.id, "running")
            self.set_status(STATUS_RUNNING)
            self.app.terminal.section("METASPLOIT  ·  Automated")
            self.app.terminal.write(
                "  [*] Writing resource script and opening xterm...", "info")
            for c in commands:
                display = (c.replace("{target}", target)
                            .replace("{lhost}", lhost)
                            .replace("{lport}", lport))
                self.app.terminal.write(f"  msf> {display}", "cmd")

            def _shell(t):
                self.app.terminal.write(
                    "  │  SHELL OBTAINED — Check the xterm window!  🦅", "finding")

            runner = MetasploitRunner(
                output_callback=self.app.terminal.output_callback,
                done_callback=lambda n, rc, log: self._on_done(tool, n, rc, log),
                shell_callback=_shell)
            self._tool_runners[tool.id] = runner
            # Flip to STOP so the row can't launch the same exploit
            # twice.  MetasploitRunner.kill() reports False (the work
            # lives in an xterm HAWK does not own), so pressing STOP
            # says so instead of pretending.
            self._toggle_run_btn(tool, True)
            runner.run(commands, target, lhost, lport)

        def _cancelled():
            # User dismissed the pre-flight dialog — leave the card in its
            # pre-click state so they can pick a different exploit.
            self._set_tool_status(tool.id, "idle")

        # Delegate to the Target Intel pre-flight machinery (it owns the
        # fingerprint state and SMB dialect cache). Fall through cleanly
        # if Target Intel isn't around for any reason.
        intel = getattr(self.app, "target_intel", None)
        if intel and hasattr(intel, "preflight_exploit_launch") and exploit_name:
            intel.preflight_exploit_launch(exploit_name, target,
                                            on_continue=_actually_launch,
                                            on_cancel=_cancelled)
        else:
            _actually_launch()

    def _on_done(self, tool, tool_name, returncode, log):
        def _update():
            # Abort guard (F-03): a run the operator STOPped — or that a
            # session switch aborted — must not post-process.  Parsers
            # and the "no open ports" popup would otherwise fire on the
            # partial / stale buffer and surface phantom findings (a
            # bogus "No open ports", an FTP 2121 carried over from an
            # earlier run).  Same principle the network sweep already
            # applies: no parsing on abort.  Only ToolRunner-based runs
            # carry the flag; other runners fall through unchanged.
            runner = self._tool_runners.get(tool.id)
            if getattr(runner, "_kill_requested", False):
                # Scanners that STREAM already-confirmed match lines
                # (nuclei/nikto) keep their partial results on STOP: their
                # parsers only lift explicit "[template] … URL" / "+ [code]
                # …" matches, so a partial buffer cannot produce the
                # phantom findings an inference-based parser (nmap "No open
                # ports") would.  A long scan the operator aborts at 99%
                # still surfaces what it already found — everything else
                # keeps the original discard (F-03).
                _binlow = (tool.binary or "").lower()
                _kept = False
                if _binlow in ("nuclei", "nikto") and log:
                    try:
                        if _binlow == "nuclei":
                            _kept = bool(
                                self._parse_nuclei_to_intel(tool, log))
                        else:
                            _kept = bool(
                                self._parse_nikto_to_intel(tool, log))
                    except Exception as e:
                        self.app.terminal.write(
                            f"  [!] {tool.name} partial parse error: {e}",
                            "error")
                self._set_tool_status(tool.id, "done" if _kept else "error")
                self._toggle_run_btn(tool, False)
                if _kept:
                    self.app.terminal.write(
                        f"  [*] {tool.name} stopped — partial results kept "
                        f"(matches found before STOP are in Target Intel).",
                        "success")
                else:
                    self.app.terminal.write(
                        f"  [*] {tool.name} stopped — output not parsed.",
                        "dim")
                # Finalize the execution record — the STOP path used to
                # leave it "running" forever, so the dot never restored and
                # it was missing from history.
                try:
                    sess = self.app.session_manager.current
                    if sess is not None:
                        w = self._tool_widgets.get(tool.id) or {}
                        exec_id = w.get("_exec_id")
                        if exec_id:
                            sess.finish_tool_execution(
                                exec_id, returncode,
                                [ln for _, ln in (log or [])],
                                "done" if _kept else "aborted")
                except Exception as e:
                    print(f"[HAWK] stop finish_tool_execution failed: {e}")
                self._raw_logs.pop(tool.id, None)
                return

            # Session guard: the run may have outlived a NEW SESSION /
            # LOAD (session switch aborts runners, but a kill takes up
            # to ~3 s to close the loop, and the xterm/background paths
            # can outrun it).  Everything below writes into the ACTIVE
            # session — parsers, Target Intel, credential store, the
            # execution record — so a stale run stops here and says so.
            w0 = self._tool_widgets.get(tool.id) or {}
            token = w0.get("_session_token")
            current = getattr(
                self.app.session_manager.current, "session_id", None)
            stale = False
            if token is not None:
                stale = not self.app.session_token_valid(
                    token, f"{tool.name} output")
            elif "_session_token" in w0 and current is not None:
                # Null-token hole (F-02): the run was launched with NO
                # active session (session_token() returned None), then a
                # session became active while it ran.  session_token_valid
                # deliberately lets a None token through for legacy
                # callers that never recorded one, so the leak is closed
                # here — at the one caller that DID record the launch
                # identity — rather than in the shared guard.
                stale = True
                self.app.terminal.write(
                    f"  [!] {tool.name} output discarded — it was "
                    f"launched with no active session; it is NOT written "
                    f"into the session that became active while it ran.",
                    "warn")
            if stale:
                self._set_tool_status(tool.id, "ready")
                self._toggle_run_btn(tool, False)
                self._raw_logs.pop(tool.id, None)
                return
            # nmap exit code 1 is normal; nc banner grabs exit non-zero
            # after timeout (124 from `timeout`, or 1 from nc EOF).
            is_nmap = tool.binary in ("nmap", "masscan", "rustscan")
            is_banner_grab = tool.id == "ssh_banner"
            if returncode == 0 or (is_nmap and returncode == 1) or is_banner_grab:
                self._set_tool_status(tool.id, "done")
                self.app.terminal.write(
                    f"  [+] {tool.name} completed.", "success")
                final_status = "done"
            else:
                self._set_tool_status(tool.id, "error")
                self.app.terminal.write(
                    f"  [!] {tool.name} exited rc={returncode}.", "warn")
                final_status = "error"
                # Friendly explanation for common non-zero exits
                try:
                    self._explain_common_errors(tool, returncode, log)
                except Exception as e:
                    print(f"[HAWK] error-explainer failed: {e}")

            # Blink-alert: if the card is collapsed, pulse the border
            # (yellow for clean completion, red for error) until the
            # user expands it.  No-op when the card is already open.
            try:
                self._notify_activity(
                    is_error=(final_status == "error"))
            except Exception as e:
                print(f"[HAWK] notify activity failed: {e}")

            # Finalize the session execution record (started in _run_raw)
            try:
                sess = self.app.session_manager.current
                if sess is not None:
                    w = self._tool_widgets.get(tool.id) or {}
                    exec_id = w.get("_exec_id")
                    if exec_id:
                        # log is a list of (level, line) tuples — store
                        # just the text lines to keep the JSON compact.
                        lines = [ln for _, ln in (log or [])]
                        sess.finish_tool_execution(
                            exec_id, returncode, lines, final_status)
            except Exception as e:
                print(f"[HAWK] finish_tool_execution failed: {e}")

            self._toggle_run_btn(tool, False)
            self.app.terminal.flush_tool_output(tool_name, tool.binary)

            # Feed nmap to Target Intel.  Read THIS tool's buffer —
            # falling back to the shared one for the callers that reach
            # _on_done without going through _run_raw.
            raw_log = self._raw_logs.get(tool.id, self._raw_log)
            if tool.binary in ("nmap", "masscan", "rustscan") and raw_log:
                if hasattr(self.app, "target_intel"):
                    self.app.target_intel.update_from_nmap(raw_log)
                    # No open ports → terminal message only, no popup.
                    # Accept both "/tcp" and "/udp", and tolerate whitespace
                    # between the port number and the 'open' column.
                    import re as _re
                    open_found = any(
                        _re.search(r"^\s*\d+/(tcp|udp)\s+open\b", l)
                        for l in raw_log)
                    if not open_found and tool.binary == "nmap":
                        self._explain_no_open_ports(raw_log)

                    if open_found:
                        self._check_cleartext_protocols(raw_log)

                    # Vuln scripts → parse to intel
                    if tool.id == "nmap_vuln" and hasattr(self.app, "target_intel"):
                        self.app.target_intel.update_from_vuln_scripts(
                            raw_log)
                    sess = None
                    try:
                        sess = self.app.session_manager.current
                    except Exception:
                        pass
                    if (sess and sess.platform in ("HTB", "THM")
                            and hasattr(self.app, "target_bar")):
                        try:
                            self.app.target_bar.auto_detect_vhost(
                                sess.target_ip)
                        except Exception:
                            pass

            # SMB tools → parse shares + push used credentials to
            # the store.  Now receives the `tool` object so the
            # parser can pull the cmd line and distinguish anonymous
            # (-N) from authenticated (-U user%pass) runs.
            if tool.id in ("smbclient_list", "netexec"):
                self._parse_smb_output(tool, log)

            # netexec → detect known crash patterns and emit a friendlier
            # explanation so the user isn't staring at a raw IndexError.
            if tool.binary in ("netexec", "nxc", "crackmapexec", "cme"):
                self._explain_netexec_errors(log)

            # netexec / impacket — anon-access-denied → offer cred retry.
            # Detects the classic "null session accepted but operation
            # refused" pattern and pops up a credentials dialog so the
            # user can immediately re-run with Administrator/vagrant
            # (or whatever) without retyping the whole command.
            #
            # Skipped for the consolidated IMPACKET EXEC card: it
            # ALWAYS runs authenticated (the dialog forces user +
            # password OR NTLM hash before RUN), so any
            # SMB SessionError / ACCESS_DENIED in its output means
            # something other than a null-session refusal — most
            # commonly the atexec 2008 R2 STATUS_OBJECT_NAME_NOT_FOUND
            # race, which _parse_impacket_exec_to_intel classifies as
            # "launched (unclear)" rather than as an auth failure.
            # Popping the cred-retry dialog on top of that is a false
            # positive and confuses the operator.
            if tool.id != "impacket_exec" and (
                    tool.binary in ("netexec", "nxc",
                                     "crackmapexec", "cme")
                    or (tool.binary or "").startswith("impacket-")):
                try:
                    self._maybe_offer_cred_retry(tool, log, returncode)
                except Exception as e:
                    print(f"[HAWK] cred-retry offer failed: {e}")

            # Initialise the "specialised parser ran" flag early so every
            # tool-specific branch below can set it and the generic
            # fallback at the end knows to stay out of the way.
            used_specialized = False

            # gobuster / dirb / ffuf → structured directory listing to Target Intel
            if tool.binary in ("gobuster", "dirb", "ffuf") and log:
                try:
                    used_specialized = self._parse_gobuster_to_intel(
                        tool, log, returncode) or used_specialized
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] gobuster parser error: {e}", "error")

            # ncrack SSH → creds to Credential Store + "Weak credentials"
            # finding.  ncrack's output format differs from hydra's, so the
            # hydra background-path extractor never matches it — this
            # dedicated parser (also runs on the foreground path) is what
            # lands the cred and the finding.
            if tool.binary == "ncrack" and log:
                try:
                    used_specialized = self._parse_ncrack_to_intel(
                        tool, log) or used_specialized
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] ncrack parser error: {e}", "error")

            # Web Oracle auto-trigger hint — after any web-recon tool
            # in the ENUMERATION phase completes successfully, nudge
            # the user toward WEB ASSAULT once per session so they know
            # the profiler exists.  One-shot flag on the app keeps it
            # from spamming after every gobuster/nikto/whatweb run.
            _WEB_RECON_TOOLS = {
                "gobuster", "dirb", "ffuf", "feroxbuster",
                "nikto", "whatweb", "wafw00f",
            }
            if (self.phase_id == "enumeration"
                    and final_status == "done"
                    and tool.binary in _WEB_RECON_TOOLS
                    and not getattr(self.app, "_web_oracle_hint_shown",
                                     False)):
                self.app.terminal.write(
                    "  [hawk]  tip:  WEB ASSAULT (phase 04) is ready "
                    "to profile this target — tech stack, auth, "
                    "APIs, CVEs, endpoint mapping.  Open the "
                    "WEB ASSAULT card → ORACLE or BLOODY CRAWL.",
                    "info")
                self.app._web_oracle_hint_shown = True

            # IMPACKET EXEC (captureable methods) → parse the
            # captured stdout for success/failure signals and push
            # an honest finding (confirmed = HIGH, launched-unclear
            # = MEDIUM, failed = INFO).  Xterm-only methods never
            # reach _on_done — the dialog pushes their LOW
            # "launched" finding directly.
            if tool.id == "impacket_exec" and log:
                try:
                    used_specialized = (
                        self._parse_impacket_exec_to_intel(tool, log)
                        or used_specialized)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] IMPACKET EXEC parser error: {e}",
                        "error")

            # SSH banner grab → extract version string to Target Intel
            if tool.id == "ssh_banner" and log:
                try:
                    used_specialized = self._parse_ssh_banner_to_intel(tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] SSH banner parser error: {e}", "error")

            # DB Fingerprint → identify DBs on open ports, upgrade
            # fp.open_ports + emit per-port Target Intel findings.
            if tool.id == "db_fingerprint" and log:
                try:
                    used_specialized = (
                        self._parse_db_fingerprint_to_intel(tool, log)
                        or used_specialized)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] DB Fingerprint parser error: {e}",
                        "error")

            # enum4linux / rpcclient batch → specialized structured parser
            # (users / shares / groups).  rpcclient -c "..." emits the same
            # interesting lines (user:[]/rid:[], netshareenumall table,
            # SIDs, srvinfo) so we reuse the parser instead of duplicating.
            if tool.binary in ("enum4linux", "enum4linux-ng",
                                "rpcclient") and log:
                try:
                    used_specialized = self._parse_enum4linux_to_intel(tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] {tool.binary} parser error: {e}", "error")

            # traceroute → structured summary (not raw hop list)
            if (not used_specialized and log
                    and tool.binary in ("traceroute", "tracepath", "mtr")):
                try:
                    used_specialized = self._parse_traceroute_to_intel(tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] traceroute parser error: {e}", "error")

            # ldapsearch → explain namingContexts & suggest next queries
            if (not used_specialized and log
                    and tool.binary == "ldapsearch"):
                try:
                    used_specialized = self._parse_ldapsearch_to_intel(tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] ldapsearch parser error: {e}", "error")

            # whatweb → web technology fingerprint (server, CMS, frameworks).
            # Single-line banner output that the generic parser silently drops
            # as "too short for info severity". Specialized parser extracts
            # the Plugin[value] tokens and creates one Target Intel entry.
            if (not used_specialized and log
                    and tool.binary == "whatweb"):
                try:
                    used_specialized = self._parse_whatweb_to_intel(tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] whatweb parser error: {e}", "error")

            # kerbrute → extract valid usernames + valid logins, push to
            # Credential Store with usage hints, and summarize in Target Intel.
            if (not used_specialized and log
                    and tool.binary == "kerbrute"):
                try:
                    used_specialized = self._parse_kerbrute_to_intel(tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] kerbrute parser error: {e}", "error")

            # nuclei → extract [template-id] [proto] [severity] URL matches
            # into structured findings grouped by severity, skip banner/info.
            if (not used_specialized and log
                    and tool.binary == "nuclei"):
                try:
                    used_specialized = self._parse_nuclei_to_intel(tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] nuclei parser error: {e}", "error")

            # nikto → extract the `+ [...]` findings from the noisy
            # banner/config output so Target Intel gets a clean view.
            if (not used_specialized and log
                    and tool.binary == "nikto"):
                try:
                    used_specialized = self._parse_nikto_to_intel(tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] nikto parser error: {e}", "error")

            # wpscan → WordPress version, vulnerable plugins/themes with
            # CVEs, enumerated users.  Runs regardless of exit code —
            # wpscan exits 5 exactly when it FINDS vulnerabilities, which
            # the rc==0-gated generic fallback below would otherwise
            # discard (findings lost precisely when they exist).
            if (not used_specialized and log
                    and tool.binary == "wpscan"):
                try:
                    used_specialized = self._parse_wpscan_to_intel(tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] wpscan parser error: {e}", "error")

            # getcap → parse Linux capabilities, flag dangerous combos
            if (not used_specialized and log
                    and tool.id == "capabilities_check"):
                try:
                    used_specialized = self._parse_capabilities_to_intel(
                        tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] capabilities parser error: {e}", "error")

            # impacket-secretsdump → parse every NTLM / DCC2 / Kerberos
            # hash line and push each one into the Credential Store as
            # a proper hash credential (viewable + editable in the
            # standard way, not just a blob in Target Intel).
            if (not used_specialized and log
                    and tool.binary == "impacket-secretsdump"):
                try:
                    used_specialized = self._parse_secretsdump_to_intel(
                        tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] secretsdump parser error: {e}", "error")

            # sqlmap → only create a finding when it actually found
            # something injectable.  Suppress the generic parser's
            # false-positive "SQLMAP — target" card when sqlmap exits
            # with "[CRITICAL] no parameter(s) found".
            if tool.binary == "sqlmap" and log:
                try:
                    used_specialized = self._parse_sqlmap_to_intel(tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] sqlmap parser error: {e}", "error")

            # ── AD-pentest output parsers ─────────────────────────────
            # Each parser generates a single run_id (utils.run_id.new_run_id)
            # and attaches it to EVERY credential + finding it pushes in
            # the same run.  The UI uses that id to show the "→ INTEL"
            # and "🔑 CREDS" navigation buttons linking the two sides.
            AD_PARSER_BY_TOOL_ID = {
                "addcomputer":       self._parse_addcomputer_to_intel,
                # gpp-decrypt recovers a reusable local-admin password —
                # capture it as a credential + HIGH finding, not a dump.
                "gpp_decrypt":       self._parse_gpp_decrypt_to_intel,
                "getuserspns":       self._parse_kerberoast_to_intel,
                "getnpusers":        self._parse_asrep_to_intel,
                # The Exploitation-phase card uses id "impacket_getnpusers"
                # (the AD-phase one is "getnpusers"); both run GetNPUsers, so
                # both must map to the AS-REP parser — otherwise AS-REP
                # hashes from the Exploitation card are silently dropped on
                # save (secretsdump is binary-keyed above and doesn't have
                # this asymmetry; getnpusers was the only id-keyed gap).
                "impacket_getnpusers": self._parse_asrep_to_intel,
                # Quick and full certipy find share output format —
                # reuse the same parser.  The quick variant just has
                # fewer template blocks because -vulnerable filters
                # server-side.
                "certipy_quick":     self._parse_certipy_find_to_intel,
                "certipy_find":      self._parse_certipy_find_to_intel,
                # req mints a cert impersonating a privileged user — HIGH
                # finding naming the identity + the actual .pfx path.
                "certipy_req":       self._parse_certipy_req_to_intel,
                # auth UnPAC's the target's NT hash — CRITICAL, and pushes
                # the recovered hash to the Credential Store.
                "certipy_auth":      self._parse_certipy_auth_to_intel,
                "bloodhound_python": self._parse_bloodhound_to_intel,
                "adidnsdump":        self._parse_adidnsdump_to_intel,
                "ldapdomaindump":    self._parse_ldapdomaindump_to_intel,
                "nxc_ldap":          self._parse_nxc_ldap_to_intel,
                "findDelegation":    self._parse_findelegation_to_intel,
                # ticketer forges a Golden Ticket — full domain-wide
                # persistence, so it gets a dedicated CRITICAL parser
                # instead of the low-severity generic dump.
                "ticketer_golden":   self._parse_ticketer_to_intel,
                # rbcd_attack produces mostly text output — handled by
                # the generic fallback since it rarely produces
                # structured creds/findings.
            }
            if (not used_specialized and log
                    and tool.id in AD_PARSER_BY_TOOL_ID):
                try:
                    used_specialized = AD_PARSER_BY_TOOL_ID[tool.id](
                        tool, log)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] {tool.id} parser error: {e}", "error")
                    import traceback
                    traceback.print_exc()

            # Target-domain discovery — run on EVERY tool's log.  Any
            # tool that happens to leak a DNS/AD domain in its output
            # (enum4linux, ldapsearch, nmap ssl-cert, reverse-DNS, NTLM
            # challenges, redirects, ...) will surface a suggestion
            # dialog.  The app-level handler deduplicates and respects
            # previous user dismissals so we don't spam.
            try:
                cands = self._detect_domain_candidates(log or [])
                if cands:
                    best = cands[0]
                    self.app.suggest_target_domain(
                        best["domain"], best["source"],
                        best["confidence"], best["evidence"])
            except Exception as e:
                print(f"[HAWK] domain detection failed: {e}")

            # Cert SAN advisories — wildcard / multi-host SAN are signals
            # the operator otherwise has to spot by hand. _detect_cert_
            # advisories pushes findings via target_intel directly so
            # there's nothing to receive here.
            try:
                self._detect_cert_advisories(log or [])
            except Exception as e:
                print(f"[HAWK] cert advisory detection failed: {e}")

            # Generic output → intel (any tool with significant output).
            # EXCLUDE every tool that already has a dedicated parser above
            # (or its own dedicated handler further down) — otherwise the
            # fallback dumps the first 6 "significant" lines, which for
            # many tools is the ASCII banner / version header rather than
            # actual findings.  Example:  wafw00f's cartoon banner landing
            # in Target Intel as a fake "finding".
            _NO_GENERIC_FALLBACK = {
                # Scanners with dedicated parsers elsewhere in this file.
                "nmap", "masscan", "rustscan", "ping",
                "traceroute", "tracepath", "mtr",
                # Web recon — handled by _parse_gobuster_to_intel.
                "gobuster", "dirb", "ffuf",
                # WAF — handled by _parse_wafw00f_output below.
                "wafw00f",
                # Dedicated parsers in this module:
                "sqlmap",
                "enum4linux", "enum4linux-ng",
                "kerbrute",
                # hydra — its cred extraction, false-positive verification
                # and the "Weak credentials" finding all run on the
                # background completion path; the generic fallback would
                # double-post a bland raw-output card ("HYDRA FTP on
                # <host>", just the banner + attempt log) on top.
                "hydra",
                # ncrack — dedicated _parse_ncrack_to_intel above already
                # lands the cred + finding; the generic fallback would
                # double-post a raw "NCRACK SSH on <host>" card.
                "ncrack",
                "whatweb",
                "nuclei",
                "nikto",
                "ldapsearch",
                "impacket-secretsdump",
                "getcap",
                # SMB — handled by _parse_smb_output above.
                # Previously the generic fallback would add a bland
                # "SMBCLIENT List — <target>" finding on top of the
                # specialised parser's output, double-posting.
                "smbclient", "netexec", "nxc", "crackmapexec", "cme",
            }
            # Tools that are pure *actions* (download a script, copy a file,
            # open a shell) — their stdout is progress/status, not a finding.
            # Previously winpeas / linpeas produced a fake "vulnerability"
            # card containing the curl progress-bar table.  Extended in
            # 2026-04 to cover EVERY downloader family so no
            # "downloaded X" junk ends up in Target Intel.  The real
            # findings come from the dedicated PEAS parsers that run
            # AFTER the user has hosted+executed+exfil'd the script.
            _NO_GENERIC_FALLBACK_IDS = {
                "linpeas", "winpeas", "winpeas_exe",
                "privesc_check", "powerup_download",
                "lse", "pspy",
                "bloody_crawl", "web_oracle",
                # proxychains_scan runs nmap under proxychains4 — its
                # dedicated branch below routes the clean nmap log to
                # target_intel.update_from_nmap (structured port list).
                # Without this exclusion the generic fallback ALSO
                # push a bland "PROXYCHAINS NMAP" finding capped at 6
                # significant lines (card_widget.py:2480), losing 21
                # of 23 ports and double-posting the run.
                "proxychains_scan",
            }
            if (not used_specialized and returncode == 0 and log
                    and tool.binary not in _NO_GENERIC_FALLBACK
                    and tool.id not in _NO_GENERIC_FALLBACK_IDS):
                self._parse_output_to_intel(tool, log)

            # WAF — wafw00f reports three useful outcomes:
            #   1. "is behind <VENDOR>"     → WAF detected, name known
            #   2. "No WAF detected ..."    → no WAF in front of target
            #   3. Generic fingerprint hit  → something filtering, vendor unknown
            # Each one is intel worth capturing so the user sees it alongside
            # ports / services. Previously we only surfaced case (1) through a
            # dialog — cases (2) and (3) silently produced nothing in Intel.
            if tool.binary == "wafw00f":
                self._parse_wafw00f_output(log, tool)

            # PEAS family (linpeas / winpeas.bat / winpeas.exe /
            # PrivescCheck.ps1 / lse / pspy) → after a successful
            # download open the interactive workflow dialog so the
            # user doesn't have to remember the host / transfer /
            # execute / exfil steps manually.  The dialog handles
            # per-ext command variants internally (cmd vs PowerShell
            # for .exe, AMSI bypass for .ps1, bash for .sh).
            _PEAS_WORKFLOW_IDS = {
                "linpeas", "winpeas", "winpeas_exe",
                "privesc_check", "powerup_download", "lse", "pspy",
            }
            if returncode == 0 and tool.id in _PEAS_WORKFLOW_IDS:
                try:
                    self._open_peas_workflow(tool)
                except Exception as e:
                    print(f"[HAWK] peas-workflow dialog failed: {e}")

            # proxychains nmap — strip [proxychains] prefix lines that
            # pollute the output, then feed the CLEAN log to both:
            #   1. target_intel.update_from_nmap → structured port
            #      state (populates the Ports / System Info panel with
            #      every open port), same call the NMAP recon card
            #      uses at line 1703.
            #   2. _parse_output_to_intel(tool, clean_log) → the
            #      visible auto_finding in Target Intel ("PROXYCHAINS
            #      NMAP on <target>"), same call the generic fallback
            #      would have made but with clean_log so no
            #      "[proxychains]" lines pollute the description.
            # The tool.id was excluded from _NO_GENERIC_FALLBACK_IDS's
            # generic fallback specifically so it doesn't ALSO fire on
            # the raw log at line 2069 (which would push a second
            # noisy finding + explain the ~30 s UI freeze).
            if tool.id == "proxychains_scan" and log:
                _proxychains_scan_dispatch(
                    log,
                    getattr(self.app, "target_intel", None),
                    self._parse_output_to_intel,
                    tool,
                    getattr(self.app, "terminal", None))

            self._run_defense_detection(log, tool_name)

            all_done = all(
                self._tool_widgets[tid].get("_status") in ("done","error")
                for tid in self._tool_widgets)
            if all_done:
                self.set_status(STATUS_DONE)
                self.app.terminal.opsec_notes(self.phase_id)

            if self.app.session_manager.current:
                self.app.session_manager.current.add_output(
                    self.phase_id, tool_name, [l for _, l in log])
                self.app.session_manager.current.save()

        self.after(0, _update)

    def _detect_python_dep_issue(self, tool, joined_lower: str) -> str:
        """Return a short label identifying the kind of Python-env failure,
        or "" if none is detected.

        Labels we emit (stable strings for the dialog to key off):
          "distutils"   — `No module named 'distutils'`  (Python 3.12+)
          "missing_mod" — `No module named 'XYZ'`        (broken install)
          "pkg_res"     — `No module named 'pkg_resources'`  (setuptools gone)
          "importerror" — `ImportError:` at startup       (dep mismatch)
        """
        if not joined_lower:
            return ""
        # Python 3.12+ distutils removal — highest priority because its
        # fix is different (install setuptools, not reinstall the tool).
        if "no module named 'distutils'" in joined_lower:
            return "distutils"
        if "no module named 'pkg_resources'" in joined_lower:
            return "pkg_res"
        # Generic missing module raised at import time.
        if "modulenotfounderror" in joined_lower and \
           "no module named" in joined_lower:
            return "missing_mod"
        # ImportError during startup of the very first traceback line.
        # Heuristic: first 30 lines contain 'Traceback' AND 'ImportError'.
        head = "\n".join(joined_lower.splitlines()[:30])
        if "traceback" in head and "importerror" in head:
            return "importerror"
        return ""

    def _show_python_dep_dialog(self, tool, kind: str, joined_lower: str):
        """One-click remediation popup for broken Python tooling.

        Shows three install strategies, lets the user run any of them
        inside an xterm so apt/pipx prompts are visible. This is reached
        on every tool that fails with a Python import-time traceback.
        """
        from gui.dialogs import (_make_win, _title, _note_box, _btn_row,
                                  _btn, _safe_destroy)
        from utils.runner import _open_terminal

        bin_low = (tool.binary or "").lower()
        pipx_pkg = self._PYTHON_TOOL_PIPX.get(bin_low, "")

        # Pull the first "No module named 'X'" target for the dialog so
        # the user sees what's actually missing.
        import re as _re
        m = _re.search(r"no module named ['\"]([^'\"]+)['\"]", joined_lower)
        missing = m.group(1) if m else ""

        title_map = {
            "distutils":   "Python 3.12+ broke this tool — distutils is gone",
            "pkg_res":     "Missing pkg_resources (setuptools not installed)",
            "missing_mod": f"Missing Python module: {missing or '?'}",
            "importerror": "ImportError at tool startup",
        }
        why_map = {
            "distutils": (
                "Since Python 3.12 the 'distutils' module was removed from\n"
                "the standard library (PEP 632). Older versions of this tool\n"
                "still import it. This hits anyone on a modern Kali install."
            ),
            "pkg_res": (
                "The tool needs 'pkg_resources' which ships with setuptools.\n"
                "Setuptools is no longer a default on fresh Python installs."
            ),
            "missing_mod": (
                f"The tool tried to import '{missing or 'a module'}' but it's\n"
                "not installed in the current Python environment. This is an\n"
                "environment problem — not a HAWK bug."
            ),
            "importerror": (
                "The tool crashed during startup with an ImportError. Usually\n"
                "a dependency-version mismatch between what the tool expects\n"
                "and what apt / pip installed."
            ),
        }

        win = _make_win(self, f"{tool.name} — Python environment broken",
                         720, 600)
        _title(win, title_map.get(kind, "Python environment broken"))

        # Scrollable body for the diagnostic + strategy list, so the
        # CLOSE button at the bottom stays visible even on short
        # screens.  `win` is locally rebound to the scrollable frame;
        # we restore it before the final button row.
        _outer = win
        body = ctk.CTkScrollableFrame(
            _outer, fg_color=COLORS["bg_primary"], corner_radius=0,
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=4, pady=(0, 2))
        win = body

        _note_box(win, why_map.get(kind, ""), COLORS["text_yellow"])

        # ── Live diagnostic: tell the user exactly WHICH binary HAWK is
        # about to use, whether it's the apt-shipped wrapper or the pipx
        # copy. This is the #1 thing users stare at wondering "but I
        # installed it!" — having both `/usr/bin/<tool>` (broken) and
        # `~/.local/bin/<tool>` (working) is the common failure.
        import shutil as _sh, os as _os, subprocess as _sp
        bin_name = tool.binary
        which_path = _sh.which(bin_name) or ""
        pipx_local = _os.path.expanduser(f"~/.local/bin/{bin_name}")
        has_pipx   = (_os.path.isfile(pipx_local)
                      and _os.access(pipx_local, _os.X_OK))
        has_apt    = (_os.path.isfile(f"/usr/bin/{bin_name}"))

        diag_lines = [f"Binary:            {bin_name}"]
        if has_apt and has_pipx:
            diag_lines.append(
                f"⚠ BOTH versions exist — /usr/bin (apt, broken) and\n"
                f"   ~/.local/bin (pipx, working). PATH order decides which\n"
                f"   one runs. HAWK now prefers the pipx copy.")
        elif has_apt and not has_pipx:
            diag_lines.append(
                "✗ Only /usr/bin (apt) — this is the broken copy on\n"
                "   Python 3.12+. Install via pipx to get a working one.")
        elif has_pipx and not has_apt:
            diag_lines.append(
                "✓ pipx copy found at ~/.local/bin — this should work.\n"
                "   If you still see this dialog, click VERIFY below.")
        else:
            diag_lines.append("? Tool not found at any known location.")
        diag_lines.append(f"shutil.which():    {which_path or '(not on $PATH)'}")
        if has_pipx:
            diag_lines.append(f"pipx copy:         {pipx_local}")
        _note_box(win, "\n".join(diag_lines), COLORS["border_dim"])

        # ── VERIFY button: smoke-test the current binary. If it runs
        # cleanly now (maybe the user already fixed it in another terminal
        # and this dialog is stale), close the dialog and show a friendly
        # confirmation — no need to run any strategy.
        def _run_smoke_test():
            """Return (ok, message). ok=True if <tool> --help exits without
            a Python import crash."""
            # Pick the binary HAWK would actually use. Mirror _find_binary
            # (prefer pipx when applicable).
            target = pipx_local if has_pipx else (which_path or bin_name)
            try:
                r = _sp.run([target, "--help"],
                            capture_output=True, text=True, timeout=5)
                out = (r.stdout + r.stderr).lower()
                if "no module named 'distutils'" in out:
                    return False, "still fails with 'No module named distutils'"
                if "modulenotfounderror" in out:
                    m2 = _re.search(
                        r"no module named ['\"]([^'\"]+)['\"]", out)
                    miss = m2.group(1) if m2 else "?"
                    return False, f"still fails: ModuleNotFoundError '{miss}'"
                if "traceback" in out and "importerror" in out:
                    return False, "still fails with ImportError"
                return True, f"{bin_name} runs cleanly ({target})"
            except FileNotFoundError:
                return False, f"binary '{target}' not found"
            except _sp.TimeoutExpired:
                # Some impacket scripts print help slowly but do run.
                return True, f"{bin_name} responds (timeout OK)"
            except Exception as e:
                return False, f"smoke test error: {e}"

        def _verify():
            ok, msg = _run_smoke_test()
            if ok:
                _safe_destroy(win)
                self.app.terminal.write(
                    f"  [+] {tool.name}  verified:  {msg}", "success")
                self.app.terminal.write(
                    f"      The fix worked — re-click the card to run.",
                    "info")
            else:
                self.app.terminal.write(
                    f"  [!] {tool.name}  still broken:  {msg}",
                    "warn")
                # Refresh the diagnostic line at the top so user sees
                # why the fix didn't take.
                self.app.terminal.write(
                    "      Try the NUCLEAR strategy below — it purges\n"
                    "      every conflicting copy before reinstalling.",
                    "dim")

        verify_row = ctk.CTkFrame(win, fg_color="transparent")
        verify_row.pack(fill="x", padx=24, pady=(0, 4))
        _btn(verify_row, "✓ VERIFY CURRENT INSTALL", _verify,
             primary=True, w=240)
        ctk.CTkLabel(
            verify_row,
            text="   ↑ click if you already fixed it in a shell",
            font=_f("xs"),
            text_color=COLORS["text_dim"],
        ).pack(side="left")

        # Build fix strategies based on the kind.
        strategies = []   # list of (label, human_desc, shell_cmd)

        # ── Nuclear option: always first when we have a pipx mapping.
        # Does the full purge-and-reinstall in a single shell pipeline.
        # This is what the user should have been able to click ONCE.
        if pipx_pkg:
            apt_conflicts_map = {
                "impacket":       "python3-impacket impacket-scripts",
                "certipy-ad":     "certipy-ad",
                "smbmap":         "smbmap",
                "netexec":        "netexec crackmapexec",
                "theHarvester":   "theharvester",
                # penelope-shell is pypi-only — no apt package to remove.
            }
            apt_pkg_for_pipx = apt_conflicts_map.get(pipx_pkg, "")
            if apt_pkg_for_pipx:
                nuclear = (
                    f"set -e; echo '[1/5] Ensuring pipx is installed…'; "
                    f"(command -v pipx >/dev/null || sudo apt install -y pipx); "
                    f"echo '[2/5] Removing apt package: {apt_pkg_for_pipx}…'; "
                    f"sudo apt remove -y {apt_pkg_for_pipx} 2>/dev/null || true; "
                    f"echo '[3/5] Purging old pipx venv…'; "
                    f"pipx uninstall {pipx_pkg} 2>/dev/null || true; "
                    f"echo '[4/5] Installing {pipx_pkg} via pipx…'; "
                    f"pipx install {pipx_pkg}; "
                    f"pipx ensurepath; "
                    f"echo '[5/5] Smoke test:'; "
                    f"~/.local/bin/{bin_name} --help 2>&1 | head -3 "
                    f"&& echo '' && echo '✓ {tool.name} now works — close '"
                    f"'this window and re-click VERIFY in HAWK.'"
                )
                strategies.append((
                    f"☢  NUCLEAR — full purge & reinstall (recommended)",
                    "Removes the apt package, wipes any existing pipx venv, "
                    "reinstalls via pipx, and smoke-tests the result. This "
                    "is the 'just make it work' button.",
                    nuclear,
                ))

        # ── Impacket legacy-deps conflict (pyasn1 0.5+ / cryptography 43+) ──
        # After the distutils shim fixes the import, the next wall is
        # usually a `TypeError: init() takes from 0 to 1 positional
        # arguments but 2 were given` raised deep inside impacket's
        # Kerberos / ASN.1 code.  Root cause: apt `python3-impacket` is
        # version 0.11 but apt bumped `python3-pyasn1` to 0.5.x which
        # changed Sequence.__init__ signatures.  Downgrade pyasn1 back
        # to 0.4.x (last compatible with impacket 0.11) and similarly
        # cryptography < 43 / pyopenssl < 24 for consistent behaviour.
        if (kind in ("missing_mod", "importerror", "distutils")
                and bin_low.startswith("impacket-")):
            strategies.append((
                "★★★  LEGACY DEPS — pin pyasn1/cryptography for impacket 0.11",
                "Kali ships apt `python3-impacket` 0.11 together with "
                "pyasn1 0.6+ which broke ABI compatibility (TypeError "
                "on init).  This installs the LAST versions that "
                "impacket 0.11 actually supports SIDE-BY-SIDE with the "
                "apt ones (via --ignore-installed → lands in "
                "/usr/local/lib which has PATH priority).  Harmless — "
                "no apt package is uninstalled or broken.",
                "set -e; "
                "echo '[1/4] Installing pyasn1 <0.5 alongside apt "
                "version …'; "
                "sudo pip3 install --break-system-packages "
                "--ignore-installed "
                "'pyasn1<0.5.0' 'pyasn1-modules<0.3.0'; "
                "echo '[2/4] Pinning cryptography / pyopenssl (best "
                "effort)…'; "
                "sudo pip3 install --break-system-packages "
                "--ignore-installed "
                "'cryptography<43' 'pyopenssl<24' 2>/dev/null || true; "
                "echo '[3/4] Verifying /usr/local version takes "
                "priority…'; "
                "python3 -c 'import pyasn1; "
                "print(\"    pyasn1 version:\", pyasn1.__version__); "
                "print(\"    loaded from:   \", pyasn1.__file__)'; "
                "echo '[4/4] Smoke-testing impacket-psexec --help…'; "
                "hash -r 2>/dev/null || true; "
                "impacket-psexec --help 2>&1 | head -5 "
                "&& echo '' && echo "
                "'✓ impacket legacy deps pinned. Close this window and "
                "re-run from HAWK.'"
            ))

        if kind == "distutils":
            # ROCK-SOLID FIX — doesn't depend on network reachability.
            # Creates a manual distutils package in the system site-
            # packages that re-exports everything from setuptools'
            # bundled _distutils.  setuptools is shipped with every
            # Python 3 install (even without apt/pip), so this works
            # offline after the very first OS install.
            strategies.append((
                "★★  DEEP FIX — distutils shim (sys.modules swap, "
                "covers ALL submodules)",
                "The bullet-proof option: creates "
                "/usr/lib/python3/dist-packages/distutils/__init__.py "
                "with 3 lines that REPLACE sys.modules['distutils'] "
                "with setuptools._distutils.  This way ANY "
                "distutils.<submodule> import transparently resolves "
                "to the setuptools-bundled copy — no need to shim "
                "each submodule individually.  Works offline, only "
                "needs setuptools (which ships with Python).",
                "set -e; "
                "echo '[1/4] Locating Python site-packages…'; "
                "SP=$(python3 -c 'import site; "
                "print(site.getsitepackages()[0])'); "
                "echo '  → '$SP; "
                "if ! python3 -c 'import setuptools._distutils' "
                "2>/dev/null; then "
                "  echo '[1b/4] setuptools missing — installing…'; "
                "  sudo apt install -y python3-setuptools 2>/dev/null || "
                "  sudo pip3 install --break-system-packages "
                "--ignore-installed -U setuptools 2>/dev/null || "
                "  { echo '   ✗ setuptools unreachable (apt + PyPI "
                "blocked).  Fix network / AV first.'; exit 1; }; "
                "fi; "
                "echo '[2/4] Writing distutils sys.modules swap shim…'; "
                "sudo mkdir -p \"$SP/distutils\"; "
                "sudo tee \"$SP/distutils/__init__.py\" >/dev/null "
                "<< 'PYSHIM'\n"
                "# HAWK distutils shim — PEP 632 workaround.\n"
                "# Replaces sys.modules['distutils'] with the copy of\n"
                "# distutils that setuptools still ships.  Every\n"
                "# subsequent 'import distutils.X' resolves against\n"
                "# setuptools._distutils.X transparently, whatever X.\n"
                "import sys\n"
                "import setuptools._distutils as _d\n"
                "sys.modules[__name__] = _d\n"
                "PYSHIM\n"
                # Clean up any old per-submodule shim files from an
                # earlier DEEP FIX run — they'd shadow the sys.modules
                # swap.
                "sudo rm -f \"$SP/distutils/spawn.py\" "
                "\"$SP/distutils/util.py\" "
                "\"$SP/distutils/version.py\" "
                "\"$SP/distutils/log.py\" "
                "\"$SP/distutils/errors.py\" "
                "\"$SP/distutils/sysconfig.py\" "
                "\"$SP/distutils/ccompiler.py\" "
                "\"$SP/distutils/dep_util.py\" "
                "\"$SP/distutils/dir_util.py\" "
                "\"$SP/distutils/file_util.py\" 2>/dev/null || true; "
                "sudo rm -rf \"$SP/distutils/__pycache__\" 2>/dev/null "
                "|| true; "
                "echo '[3/4] Verifying shim covers every common "
                "submodule…'; "
                "python3 -c '"
                "import distutils.spawn, distutils.util, "
                "distutils.version, distutils.cmd, distutils.core, "
                "distutils.command, distutils.log, distutils.errors; "
                "print(\"   ✓ all submodules resolve via setuptools._distutils\")'; "
                "echo '[4/4] Smoke-testing '\"$(basename "
                f"{_shq(bin_name)})\"'…'; "
                "hash -r 2>/dev/null || true; "
                f"{_shq(bin_name)} --help 2>&1 | head -3 "
                "&& echo '' && echo "
                "'✓ distutils shim installed system-wide.  '"
                f"'{tool.name} should now work.  '"
                "'Close this window and re-run from HAWK.'"
            ))
            strategies.append((
                "Install setuptools shim (quick, fixes most cases)",
                "Adds a distutils shim back to the interpreter.",
                "sudo apt install -y python3-setuptools || "
                "pip install --break-system-packages setuptools",
            ))
            # The DEFINITIVE fix for impacket on Kali 2025 / Python
            # 3.13+.  The PyPI `impacket` release lags and still
            # imports distutils; the fortra/impacket HEAD removed every
            # distutils reference and is what modern Kali tracks.  We
            # pipx-install directly from git so the user's local env
            # always gets a working build regardless of PyPI / apt.
            if bin_low.startswith("impacket-"):
                strategies.append((
                    "★  Install impacket HEAD from fortra git (FIX)",
                    "The PyPI release of impacket is stale and still "
                    "uses distutils.  The fortra/impacket GitHub HEAD "
                    "removed distutils entirely.  This strategy nukes "
                    "the apt + pipx copies and installs the fixed "
                    "HEAD in an isolated pipx venv.",
                    "set -e; "
                    "echo '[1/6] Ensuring pipx / git are installed…'; "
                    "(command -v pipx >/dev/null || sudo apt install -y pipx); "
                    "(command -v git  >/dev/null || sudo apt install -y git); "
                    "echo '[2/6] Purging apt impacket (broken on Py3.13)…'; "
                    "sudo apt purge -y python3-impacket impacket-scripts "
                    "2>/dev/null || true; "
                    "echo '[3/6] Wiping any leftover /usr/bin/impacket-* wrappers…'; "
                    "sudo rm -f /usr/bin/impacket-* /usr/local/bin/impacket-* "
                    "2>/dev/null || true; "
                    "echo '[4/6] Removing existing pipx install (if any)…'; "
                    "pipx uninstall impacket 2>/dev/null || true; "
                    "echo '[5/6] Installing fortra/impacket HEAD (distutils-free)…'; "
                    "pipx install 'impacket @ "
                    "git+https://github.com/fortra/impacket.git'; "
                    "pipx ensurepath; "
                    "echo '[6/6] Smoke-testing impacket-psexec…'; "
                    "hash -r 2>/dev/null || true; "
                    "~/.local/bin/impacket-psexec --help 2>&1 | head -3 "
                    "&& echo '' && echo "
                    "'✓ impacket fixed.  Close this window and re-run the "
                    "tool from HAWK.'"
                ))

        # ── NetExec specifically: missing impacket.examples.regsecrets ──
        # apt impacket is 0.11; apt netexec is 1.5.x which expects the
        # `impacket.examples.regsecrets` module that only landed in
        # impacket 0.12 (fortra fork).  pip-install impacket 0.12+
        # alongside the apt one via --ignore-installed; /usr/local has
        # path priority so netexec finds the new file.
        if (kind == "missing_mod"
                and "impacket.examples" in (missing or "")):
            strategies.append((
                "★★★★  PIN IMPACKET 0.12 (fixes NetExec regsecrets)",
                "apt impacket 0.11 is missing examples/regsecrets.py — "
                "added in impacket 0.12 (fortra).  This installs "
                "impacket >=0.12 from PyPI into /usr/local side-by-side "
                "with apt's 0.11.  Python's path order (/usr/local "
                "before /usr/lib) means every tool — apt netexec "
                "included — now loads the new impacket.",
                "set -e; "
                "echo '[1/4] Checking PyPI reachability…'; "
                "timeout 5 curl -sfI https://pypi.org/simple/ "
                ">/dev/null || "
                "{ echo '   ✗ PyPI unreachable. AV/firewall issue — "
                "activate VPN and retry.'; exit 1; }; "
                "echo '   ✓ PyPI reachable.'; "
                "echo '[2/4] Installing impacket 0.12+ via pip …'; "
                "sudo pip3 install --break-system-packages "
                "--ignore-installed 'impacket>=0.12'; "
                "echo '[3/4] Verifying regsecrets module loads…'; "
                "python3 -c '"
                "import impacket.examples.regsecrets as r; "
                "print(\"   ✓ regsecrets loaded from:\", r.__file__)'; "
                "echo '[4/4] Smoke-testing netexec…'; "
                "hash -r 2>/dev/null || true; "
                "netexec --help 2>&1 | head -5 "
                "&& echo '' && echo "
                "'✓ netexec 1.5 + impacket 0.12 pinned.  Close this "
                "window and re-run from HAWK.'"
            ))

        # ── NetExec / impacket.examples.* missing-module FIX ──────────
        # netexec 1.5.x shipped via apt pulls python3-impacket as a dep,
        # but that apt impacket is older than what netexec expects.
        # netexec tries to `from impacket.examples import regsecrets` /
        # `serviceinstall` / etc. — modules that only exist in newer
        # impacket HEAD.  The fix is to install both netexec AND the
        # fortra/impacket HEAD in their own pipx venvs so they use a
        # matched, distutils-free, up-to-date stack.
        if kind == "missing_mod" and (bin_low in ("netexec", "nxc")
                                       or (missing or "").startswith(
                                           "impacket")):
            strategies.append((
                "★  Install NetExec HEAD + impacket HEAD from git (FIX)",
                "The apt netexec package drags in an older apt impacket "
                "that's missing the examples/ modules NetExec 1.5+ "
                "needs (regsecrets, serviceinstall, ...).  Install "
                "both tools from their GitHub HEAD in isolated pipx "
                "venvs so the dep chain is consistent.",
                "set -e; "
                "echo '[1/7] Ensuring pipx / git are installed…'; "
                "(command -v pipx >/dev/null || sudo apt install -y pipx); "
                "(command -v git  >/dev/null || sudo apt install -y git); "
                "echo '[2/7] Purging apt netexec & crackmapexec…'; "
                "sudo apt purge -y netexec crackmapexec 2>/dev/null || true; "
                "echo '[3/7] Removing /usr/bin leftovers…'; "
                "sudo rm -f /usr/bin/netexec /usr/bin/nxc "
                "/usr/bin/crackmapexec /usr/bin/cme "
                "/usr/local/bin/netexec /usr/local/bin/nxc "
                "2>/dev/null || true; "
                "echo '[4/7] Wiping old pipx installs…'; "
                "pipx uninstall netexec 2>/dev/null || true; "
                "pipx uninstall impacket 2>/dev/null || true; "
                "echo '[5/7] Installing fortra/impacket HEAD…'; "
                "pipx install 'impacket @ "
                "git+https://github.com/fortra/impacket.git'; "
                "echo '[6/7] Installing NetExec HEAD with impacket injected…'; "
                "pipx install 'netexec @ "
                "git+https://github.com/Pennyw0rth/NetExec.git'; "
                "pipx inject netexec "
                "'impacket @ git+https://github.com/fortra/impacket.git'; "
                "pipx ensurepath; "
                "hash -r 2>/dev/null || true; "
                "echo '[7/7] Smoke-testing nxc…'; "
                "~/.local/bin/nxc --help 2>&1 | head -3 "
                "&& echo '' && echo "
                "'✓ NetExec fixed.  Close this window and re-run from HAWK.'"
            ))

        if pipx_pkg:
            # Map the pipx package back to the apt package(s) it conflicts
            # with. If BOTH are installed, /usr/bin/<tool> (apt, broken on
            # Py3.12+) shadows ~/.local/bin/<tool> (pipx, working) because
            # /usr/bin comes first in $PATH. We uninstall apt first.
            apt_conflicts = {
                "impacket":     "python3-impacket impacket-scripts",
                "certipy-ad":   "certipy-ad",
                "smbmap":       "smbmap",
                "netexec":      "netexec crackmapexec",
                "theHarvester": "theharvester",
                # penelope-shell is pypi-only — no apt conflict.
            }.get(pipx_pkg, "")
            apt_remove = (
                f"sudo apt remove -y {apt_conflicts} 2>/dev/null; "
                if apt_conflicts else ""
            )
            strategies.append((
                f"Reinstall '{pipx_pkg}' via pipx (isolated, recommended)",
                "Removes the broken apt version first so /usr/bin doesn't "
                "shadow pipx, then installs fresh in an isolated venv — "
                "immune to system Python changes.",
                f"(command -v pipx >/dev/null || sudo apt install -y pipx) && "
                f"{apt_remove}"
                f"pipx uninstall {pipx_pkg} 2>/dev/null; "
                f"pipx install {pipx_pkg} && pipx ensurepath",
            ))

        # Last resort: force a reinstall of the apt package itself.
        # Many Kali mirrors have a newer version than the one currently
        # installed; upgrading might resolve the distutils import.
        apt_pkg = {
            "impacket-psexec":       "python3-impacket impacket-scripts",
            "impacket-secretsdump":  "python3-impacket impacket-scripts",
            "impacket-getnpusers":   "python3-impacket impacket-scripts",
            "impacket-getuserspns":  "python3-impacket impacket-scripts",
            "smbmap":                "smbmap",
            "netexec":               "netexec",
        }.get(bin_low, "")
        if apt_pkg:
            strategies.append((
                f"Upgrade apt package ({apt_pkg})",
                "apt update + reinstall. Works if the repo now ships a "
                "distutils-free release.",
                f"sudo apt update && sudo apt install -y --reinstall {apt_pkg}",
            ))

        if not strategies:
            strategies.append((
                "Generic: bring Python tooling up to date",
                "Last-resort catch-all.",
                "sudo apt install -y python3-setuptools python3-pip pipx && "
                "pipx ensurepath",
            ))

        # Render each strategy as a row with RUN + COPY buttons.
        for label, desc, cmd in strategies:
            row = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                                border_color=COLORS["border_dim"],
                                border_width=1, corner_radius=4)
            row.pack(fill="x", padx=24, pady=4)
            ctk.CTkLabel(row, text=label, font=_f("sm", True),
                         text_color=COLORS["text_green"],
                         anchor="w", justify="left"
                         ).pack(fill="x", padx=10, pady=(6, 0))
            ctk.CTkLabel(row, text=desc, font=_f("xs"),
                         text_color=COLORS["text_dim"],
                         anchor="w", justify="left", wraplength=600
                         ).pack(fill="x", padx=10, pady=(0, 2))
            cmd_lbl = ctk.CTkLabel(row, text=f"$ {cmd}", font=_f("xs"),
                                    text_color=COLORS["text_bright"],
                                    anchor="w", justify="left",
                                    wraplength=600)
            cmd_lbl.pack(fill="x", padx=10, pady=(0, 4))

            btns = ctk.CTkFrame(row, fg_color="transparent")
            btns.pack(fill="x", padx=10, pady=(0, 6))

            def _run_in_xterm(c=cmd, lbl=label):
                # Proper bash single-quote escape: inside '...' a
                # single quote becomes '\'' — CLOSE the string, emit a
                # literal \', REOPEN the string.  The old code used
                # \' which bash does NOT interpret as escape inside
                # single-quoted strings, producing a syntax error that
                # silently killed the whole xterm invocation.
                safe_disp = c.replace("'", "'\\''")
                _open_terminal(
                    f"HAWK — Fix: {lbl}",
                    f"echo '=== HAWK fix ===' && "
                    f"echo '$ {safe_disp}' && "
                    f"{c}; "
                    f"echo; "
                    f"read -p 'Done — press ENTER to close...'")
                self.app.terminal.write(
                    f"  [*] Launched fix in xterm: {lbl}", "info")

            def _copy(c=cmd):
                try:
                    from utils.clipboard import clipboard_copy
                    clipboard_copy(c)
                    self.app.terminal.write(
                        "  [+] Fix command copied to clipboard.", "success")
                except Exception as e:
                    print(f"[HAWK] clipboard copy failed: {e}")

            ctk.CTkButton(btns, text="RUN IN XTERM", width=130, height=24,
                          font=_f("xs", True),
                          fg_color="#001500",
                          hover_color="#003000",
                          border_color=COLORS["border_green"],
                          border_width=1,
                          text_color=COLORS["text_green"],
                          corner_radius=3,
                          command=_run_in_xterm
                          ).pack(side="left", padx=(0, 4))
            ctk.CTkButton(btns, text="COPY", width=70, height=24,
                          font=_f("xs"),
                          fg_color=COLORS["bg_card"],
                          hover_color=COLORS["bg_card_hover"],
                          border_color=COLORS["border_dim"],
                          border_width=1,
                          text_color=COLORS["text_dim"],
                          corner_radius=3,
                          command=_copy
                          ).pack(side="left")

        _note_box(win,
                  "After a fix completes, close this dialog and re-run the\n"
                  "tool from HAWK. If it still fails, try the next strategy.",
                  COLORS["border_dim"])

        # End of scrollable body — restore win for the fixed bottom row
        # so CLOSE stays pinned and always visible.
        win = _outer

        row = _btn_row(win)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=110)

        # Also log a short line in the terminal so the user sees it scrolled
        # back later.
        self.app.terminal.write(
            f"  → Python-env issue ({kind}) — opened fix dialog.", "warn")

    def _show_waf_dialog(self):
        target = self._get_target()
        if not target:
            return
        from gui.dialogs import WAFEvasionDialog

        def _apply(opts, custom=None):
            custom = custom or {}
            if opts:
                self.app.terminal.write(
                    f"  [*] WAF evasion techniques: {', '.join(opts)}",
                    "info")
            # Echo any custom values so the user can copy/paste them into
            # follow-up runs. We also stash them on the widget so future
            # tools in this phase can pick them up.
            non_empty = {k: v for k, v in custom.items() if v}
            if non_empty:
                for k, v in non_empty.items():
                    self.app.terminal.write(
                        f"      {k} = {v}", "dim")
                self._waf_custom = non_empty
            # Persist to session so other cards (sqlmap, nikto, ffuf)
            # can read the preferences if they want.
            try:
                sess = self.app.session_manager.current
                if sess:
                    bits = []
                    if opts:
                        bits.append(f"WAF evasion: {', '.join(opts)}")
                    for k, v in non_empty.items():
                        bits.append(f"WAF {k}={v}")
                    if bits:
                        extra = "\n".join(bits)
                        sess.notes = (sess.notes + "\n" + extra
                                      if sess.notes else extra)
                        sess.save()
            except Exception:
                pass

        WAFEvasionDialog(self, target, self.app, callback=_apply)

    def _run_defense_detection(self, log: list, tool_name: str):
        from modules.defense_detection import DefenseDetector
        target = self._get_target()
        if not target:
            return
        # wafw00f IS the dedicated WAF detector — its captured output
        # already carries the authoritative verdict for Target Intel.
        # Running HAWK's coarser keyword heuristic on top of it just
        # picks up the tool's own banner ("The Web Application
        # Firewall Fingerprinting Toolkit") and emits a 'WAF detected
        # — 80%' alert that contradicts wafw00f's real result.  Skip.
        if (tool_name or "").strip().lower() in ("wafw00f", "wafwoof"):
            return
        alerts = DefenseDetector().analyze(log, target)
        if not alerts:
            return
        if self.app.session_manager.current:
            for a in alerts:
                self.app.session_manager.current.add_defense_alert(a)
            self.app.session_manager.current.save()
        from gui.dialogs import DefenseAlertDialog
        self.after(100, lambda: DefenseAlertDialog(
            self, alerts,
            callback_continue=lambda: self.app.terminal.write(
                "  [*] Continuing with caution.", "warn"),
            callback_abort=lambda: self.app.terminal.write(
                "  [!] Phase aborted.", "warn")))

