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

class CardScanRoutesMixin:
    def _request_run(self, tool):
        if tool is None:
            return

        # A tool declared runs_on_target is meant to execute inside the
        # TARGET shell.  Never dispatch it down the local-run path, no
        # matter how it got here: several of the Windows built-ins have
        # same-named binaries on Kali (`whoami`, `net`, `netstat`), so
        # an availability-gated check let them run locally and report
        # Kali's state as the target's.
        if getattr(tool, "runs_on_target", False):
            # netsh_portfwd has its own guided builder (it needs the
            # three ports before a command exists at all); it also only
            # ever produces a paste-in-the-target-shell command.
            if tool.id == "netsh_portfwd":
                self._route_netsh_portfwd(tool)
            else:
                self._show_target_command_dialog(tool)
            return

        # Generic pre-check: if the tool's binary isn't on PATH, show
        # the install wizard BEFORE routing to any dialog.  Without
        # this, AD tools (bloodhound-python, adidnsdump, certipy, …)
        # opened their auth dialog even when the binary was missing,
        # so clicking RUN ran a command that hit "command not found"
        # silently.  Tools in the exempt set below have their own
        # special handling (interactive dialogs that work without a
        # binary on PATH, e.g. metasploit launcher, greenbone which
        # HAWK can auto-install).
        _NO_BINARY_PRECHECK = {
            # These route straight to an install wizard themselves or
            # are installable via their own dialog.
            "greenbone", "metasploit", "metasploit_console",
            "msfconsole", "rustscan", "nuclei", "kerbrute",
            "kerbrute_userenum", "enum4linux",
            # gpp-decrypt has a fallback path; also Kali usually
            # ships it.
            "gpp_decrypt",
        }
        if (tool.id not in _NO_BINARY_PRECHECK
                and not tool.is_available()):
            self._show_install_dialog(tool)
            return

        # OSINT guard-rails: target validation + API key pre-flight
        if self._osint_preflight(tool):
            return

        # Greenbone
        if tool.id == "greenbone":
            self._route_greenbone(tool)
            return

        # Metasploit card — the main METASPLOIT button from the Exploitation
        # phase should ALWAYS just pop open an xterm on msfconsole (after
        # printing DB-setup hints). No pre-flight dialog, no automated
        # exploit-module runner — the user drives msfconsole directly.
        #
        # We match by tool.id because different entry points reach here:
        #   - Exploitation phase card → id="msfconsole"
        #   - (legacy / alt routes)   → id="metasploit" / "metasploit_console"
        if tool.id in ("metasploit", "metasploit_console", "msfconsole"):
            self._route_metasploit_launcher(tool)
            return

        # Automated MSF dialog — reserved for OTHER entry points that
        # synthesise a tool with binary=msfconsole but a different id (e.g.
        # Target Intel "▶ EXPLOIT WITH MSF" buttons that pre-pick a
        # specific module). Keep this path for them; the main card is
        # handled above.
        if tool.binary == "msfconsole" and tool.id not in (
                "metasploit", "metasploit_console", "msfconsole"):
            from gui.dialogs import MetasploitDialog
            MetasploitDialog(self, tool, callback=self._run_msf)
            return

        # Nmap routing
        if tool.binary == "nmap":
            self._route_nmap(tool)
            return

        # Masscan direct
        if tool.id == "masscan":
            self._run_tool(tool)
            return

        # Rustscan — custom option builder
        if tool.id == "rustscan":
            from gui.dialogs import RustscanCustomDialog
            RustscanCustomDialog(self, tool, callback=self._run_rustscan_custom)
            return

        # Ping
        if tool.id == "ping":
            self._run_ping(tool)
            return

        # Ncrack SSH — legacy-capable SSH brute (hydra can't negotiate
        # old crypto).  Own dialog with a Concurrency (CL) field.
        if tool.id == "ncrack_ssh":
            self._route_ncrack_ssh(tool)
            return

        # Hydra — port-aware with wordlist dialog
        if tool.binary == "hydra":
            self._route_hydra(tool)
            return

        # Responder — interface picker + port-conflict pre-check
        if tool.binary == "responder":
            self._route_responder(tool)
            return

        # Certipy — needs domain creds; build a proper dialog
        if tool.binary == "certipy-ad":
            self._route_certipy(tool)
            return

        # Web tools
        if tool.id in WEB_TOOLS:
            self._route_web_tool(tool)
            return

        # SMB tools
        if tool.id in SMB_TOOLS:
            self._route_smb_tool(tool)
            return

        # SSH banner — port-aware
        if tool.id == "ssh_banner":
            port, _ = self._require_service(tool.name, "ssh")
            if port is None:
                return
            target = self._get_target()
            if target:
                # SSH banner grab — Python helper backend.
                #
                # The previous two backends both had silent-failure
                # modes that left HAWK unable to read the banner even
                # when the server WAS sending it:
                #   • `cat /dev/null | nc -nv host port` — different
                #     nc flavours close the socket before the server
                #     flushes the SSH-2.0-… line (gnu-nc / openbsd-nc
                #     / nmap-ncat are inconsistent).
                #   • `bash -c 'exec 3<>/dev/tcp/...; head -c 256
                #     <&3'` — `head` uses C-stdio block buffering and
                #     loses the captured bytes when the outer
                #     `timeout` killed bash.
                #   • `bash -c '... read -r -t 3 banner <&3 ...'`
                #     — the bash builtin `read` on a /dev/tcp FD
                #     was observed live (Kali 2025, bash 5.3) to
                #     time out without consuming any bytes even
                #     when the server WAS in fact sending the
                #     banner.  No fix at the shell level.
                #
                # Python's socket module is the only reliable
                # primitive here: deterministic across distros,
                # no buffering issues, and gives us actionable
                # diagnostics when the SERVER is at fault
                # (MaxStartups exhausted, TCP wrappers,
                # tcpwrapped state — output `[HAWK: connection
                # closed by remote, no banner sent]`).  The
                # helper lives at utils/banner_grab.py and is
                # reusable for FTP / SMTP / IMAP banner grab
                # tools we may add in a future pacchetto.
                #
                # The explicit [HAWK port=N target=...] marker
                # tells the parser which port produced this run.
                import os as _os
                from utils.config import BASE_DIR as _BASE
                helper = _os.path.join(_BASE, "utils", "banner_grab.py")
                self._run_raw(
                    tool,
                    f"echo '[HAWK port={port} target={target}]'; "
                    f"python3 {helper} {target} {port} 3")
            return

        # NOTE: the standalone "FTP Anonymous" tool was removed at
        # user request — the integrated Connect → FTP → "Anonymous
        # login" action covers the same use case and ALSO saves the
        # verified cred to the Credential Store via the Pkg-B fix
        # in target_intel_parsers._parse_ftp_connect.  Keep this
        # comment so the absence of the `ftp_anon` dispatcher is
        # explicit.

        # DB Fingerprint — active probe across all open ports.
        # Identifies the 9 supported DB protocols (Elasticsearch,
        # CouchDB, InfluxDB, ClickHouse, ArangoDB, Redis, Memcached,
        # MongoDB, Cassandra) via HTTP probes + protocol-specific
        # binary magic.  Updates fp.open_ports with the detected
        # svc + version through the parser in card_parsers_service.
        if tool.id == "db_fingerprint":
            target = self._get_target()
            if not target:
                self.app.terminal.write(
                    "  [!] DB Fingerprint: no target set.", "warn")
                return
            # Gather currently-known open ports from the target intel
            # fingerprint.  Bail out cleanly if there's nothing to probe.
            ports = []
            try:
                ti = getattr(self.app, "target_intel", None)
                fp = getattr(ti, "_fp", None) if ti else None
                if fp is not None:
                    for entry in (getattr(fp, "open_ports", None) or []):
                        try:
                            p = int(entry[0])
                        except (TypeError, ValueError, IndexError):
                            continue
                        if 1 <= p <= 65535:
                            ports.append(p)
            except Exception:
                ports = []
            if not ports:
                self.app.terminal.write(
                    "  [!] DB Fingerprint: no open ports known yet — "
                    "run a port scan first (Rustscan / Nmap).", "warn")
                return
            import os as _os
            from utils.config import BASE_DIR as _BASE
            helper = _os.path.join(
                _BASE, "utils", "db_fingerprint.py")
            # Pass ports comma-separated (the helper accepts both
            # space- and comma-separated forms but comma keeps the
            # shell cmd readable).
            ports_arg = ",".join(str(p) for p in ports)
            self._run_raw(
                tool,
                f"python3 {helper} {target} {ports_arg}")
            return

        # SNMP
        if tool.id == "snmpwalk":
            self._route_snmp(tool)
            return

        # Searchsploit
        if tool.binary == "searchsploit":
            self._run_searchsploit(tool)
            return

        # Kerbrute — AD user enumeration / password spraying
        if tool.binary == "kerbrute" or tool.id in ("kerbrute",
                                                     "kerbrute_userenum"):
            self._route_kerbrute(tool)
            return

        # Impacket GetNPUsers — needs a users wordlist + domain.
        # Two ID spellings in use: "impacket_getnpusers" (classic
        # Enumeration phase) and "getnpusers" (AD PENTESTING phase
        # module).  Both route through the same dedicated dialog.
        if tool.id in ("impacket_getnpusers", "getnpusers"):
            self._route_getnpusers(tool)
            return

        # GPP-DECRYPT — NOT a credentialed AD tool.  The {password}
        # placeholder in its template is the *cpassword* blob (base64
        # string) extracted from SYSVOL Groups.xml / Services.xml.
        # Needs its own dialog with a single large textbox for pasting
        # the blob — the generic AD auth dialog would be meaningless.
        if tool.id == "gpp_decrypt":
            self._route_gpp_decrypt(tool)
            return

        # Impacket tools that take user:pass@host — all share the same
        # auth dialog (user / password / optional NTLM hash) with creds
        # prefilled from the Credential Store.  Without this the raw
        # template `impacket-psexec administrator@{target}` hangs
        # forever waiting for a password that nobody's typing.
        _IMPACKET_AUTH_IDS = {
            "impacket_psexec",
            "impacket_secretsdump",
            "impacket_wmiexec",
            "impacket_atexec",
            "impacket_dcomexec",
            "impacket_smbclient",
            "impacket_mssqlclient",
            "impacket_lookupsid",
            "impacket_samrdump",
            "impacket_rpcdump",
            "impacket_goldenpac",
        }
        if tool.id in _IMPACKET_AUTH_IDS:
            self._route_impacket_auth(tool)
            return

        # RDP Connect — needs its own auth dialog (xfreerdp3 uses
        # /u: /p: /pth: flags, not the impacket user:pass@host format).
        if tool.id == "rdp_connect":
            self._route_rdp_connect(tool)
            return

        # AD-pentesting tools that use {user}/{password}/{domain}
        # placeholders in their cmd_template — route through a single
        # credential-collection dialog before rendering the command.
        # Without this, the template renders `<user>` / `<password>` as
        # literals and the shell interprets `<user>` as stdin redirect
        # ("cannot open user: No such file").
        _AD_TEMPLATE_AUTH_IDS = {
            "bloodhound_python", "ldapdomaindump", "nxc_ldap",
            "getuserspns",
            "certipy_quick", "certipy_find", "certipy_req",
            "rbcd_attack", "findDelegation",
            "secretsdump_dcsync",
            "addcomputer", "adidnsdump",
        }
        if tool.id in _AD_TEMPLATE_AUTH_IDS:
            # Tools with LITERAL <PLACEHOLDER> tokens that must be
            # filled from PRIOR tool runs get a prerequisite check
            # first — otherwise the user hits RUN, the placeholder
            # field dialog opens, they don't know what to type, the
            # command fires with '<CA_NAME>' still in it, and the
            # safety guard blocks it.  Much better to intercept here
            # and either auto-fill from Target Intel or show a
            # dedicated "you need to run X first" dialog.
            if tool.id == "certipy_req":
                self._route_certipy_req(tool)
                return
            if tool.id == "rbcd_attack":
                self._route_rbcd_attack(tool)
                return
            self._route_ad_template(tool)
            return

        # CERTIPY AUTH — doesn't use {user}/{password}/{domain}
        # placeholders (the PFX is the credential), so it's NOT in
        # _AD_TEMPLATE_AUTH_IDS above.  Its own dedicated dialog asks
        # for the PFX path + DC IP (+ optional username/domain when
        # the cert has no UPN) and validates the PFX exists before
        # firing.
        if tool.id == "certipy_auth":
            self._route_certipy_auth(tool)
            return

        # TICKETER (Golden Ticket) — same rationale: the credential
        # that matters is krbtgt's NTLM hash (from secretsdump), NOT
        # a user password.  Reusing _route_ad_template here silently
        # mapped {password} → -nthash which let cleartext passwords
        # sneak into the command as fake hashes.  Dedicated dialog
        # with validated krbtgt-hash + domain-SID fields.
        if tool.id == "ticketer_golden":
            self._route_ticketer_golden(tool)
            return

        # LDAP search
        if tool.id in ("ldapsearch_base", "ldapsearch") \
           or tool.binary == "ldapsearch":
            self._route_ldapsearch(tool)
            return

        # WEB ASSAULT — webapp profiler + smart crawler + offensive
        # tools (Injection, JWT Analyzer).  All four are "thin route"
        # mixin methods that hand off to workers in utils/.
        if tool.id == "web_oracle":
            self._route_web_oracle(tool)
            return
        if tool.id == "bloody_crawl":
            self._route_bloody_crawl(tool)
            return
        if tool.id == "injection_tester":
            self._route_injection_tester(tool)
            return
        if tool.id == "jwt_analyzer":
            self._route_jwt_analyzer(tool)
            return

        # Generic
        network_note = self.phase_config.get("network_note", "")
        if network_note or tool.requires_sudo:
            from gui.dialogs import PermissionDialog
            PermissionDialog(self, tool, self.phase_config,
                             callback_yes=lambda t=tool: self._run_tool(t))
        else:
            self._run_tool(tool)

    def _route_metasploit_launcher(self, tool):
        """Open msfconsole in an xterm, printing DB-check suggestions first.

        Deliberately NOT interactive — no dialog, no pre-flight probing.
        msfconsole is a tool the user drives directly; HAWK's job is just
        to spawn the terminal and remind them of the DB commands they
        might want to run (inside or outside msfconsole) if the DB isn't
        already set up.
        """
        from utils.runner import _open_terminal

        # Printed inside the xterm before msfconsole launches. Uses
        # single-quoted heredoc-style so shell metacharacters don't need
        # escaping. Everything here is advisory — user decides what to run.
        banner = (
            "echo ''; "
            "echo '═══════════════════════════════════════════════════════════'; "
            "echo '  HAWK  —  Metasploit Framework'; "
            "echo '═══════════════════════════════════════════════════════════'; "
            "echo ''; "
            "echo 'HAWK auto-starts the DB below. If it fails, run OUTSIDE msfconsole:'; "
            "echo '  sudo msfdb init                    # first-time setup'; "
            "echo '  sudo msfdb status                  # verify'; "
            "echo '  sudo systemctl start postgresql    # start PG manually'; "
            "echo ''; "
            "echo 'Inside msfconsole:'; "
            "echo '  db_status                          # confirm DB connected'; "
            "echo '  workspace -a hawk                  # isolate this engagement'; "
            "echo '  db_nmap -sV <target>               # import nmap into DB'; "
            "echo '  hosts / services / vulns / creds   # query stored data'; "
            "echo ''; "
            "echo '───────────────────────────────────────────────────────────'; "
            "echo ''; "
        )
        # Ensure the Metasploit database is up before launching msfconsole,
        # so db_status is connected without a manual step.  Elevate only
        # when postgres isn't already running (pgrep needs no sudo), so a
        # host that already has the DB up gets no needless password prompt.
        db_up = (
            "if pgrep -x postgres >/dev/null 2>&1; then "
            "echo '[HAWK] Metasploit database already running.'; "
            "else "
            "echo '[HAWK] Starting Metasploit database (sudo may be asked)...'; "
            "sudo msfdb start; "
            "fi; echo ''; "
        )
        script = (banner + db_up
                  + "msfconsole; read -p 'Press ENTER to close...'")
        _open_terminal("HAWK — Metasploit Console", script)
        self.app.terminal.write(
            "  [+] Metasploit launched in xterm (DB auto-started).",
            "success")

    def _route_greenbone(self, tool):
        from gui.dialogs import GreenboneDialog

        def _setup_complete(t):
            # Web-UI mode (START / AUTOFIX) doesn't drive a GMP scan,
            # so the regular done_callback path that flips the card
            # dot to "done" never fires.  Do it manually here so the
            # operator sees the tool counted as run + the session
            # log carries an execution entry that survives restart.
            try:
                self._set_tool_status(t.id, "done")
            except Exception as e:
                print(f"[HAWK] greenbone set_tool_status failed: {e}")
            try:
                sess = self.app.session_manager.current
                if sess is not None:
                    exec_id = sess.start_tool_execution(
                        tool_id=t.id, tool_name=t.name,
                        phase_id=getattr(self, "phase_id",
                                          "vuln_scan"),
                        command="(Greenbone web UI mode — "
                                "scan driven manually via gvmd)")
                    sess.finish_tool_execution(
                        exec_id, 0, [], "done")
            except Exception as e:
                print(f"[HAWK] greenbone session bookkeeping "
                      f"failed: {e}")

        GreenboneDialog(self, tool, self.app,
                        callback_run=self._run_greenbone,
                        callback_skip=lambda: self.app.terminal.write(
                            "  [*] Greenbone skipped.", "dim"),
                        callback_setup_complete=_setup_complete)

    def _route_nmap(self, tool):
        if tool.id == "nmap_custom":
            from gui.dialogs import NmapCustomDialog
            NmapCustomDialog(self, tool, callback=self._run_nmap_custom)
            return
        if tool.id == "nmap_udp":
            self._show_udp_scope_dialog(tool)
            return
        if tool.id == "nmap_vuln":
            self._show_vuln_scope_dialog(tool)
            return
        if tool.id == "nmap_os":
            self._show_os_mode_dialog(tool)
            return
        self._show_nmap_confirm(tool)

    def _run_rustscan_custom(self, tool, flags: str):
        """Called from RustscanCustomDialog — builds 'rustscan <flags>' with target injected."""
        target = self._get_target()
        if not target:
            return
        stripped = flags.strip()
        # If user included {target} placeholder, respect it; otherwise inject -a <target>
        if "{target}" in stripped:
            cmd = f"rustscan {stripped.replace('{target}', target)}"
        elif "-a " in stripped or stripped.startswith("-a"):
            cmd = f"rustscan {stripped}"
        else:
            cmd = f"rustscan -a {target} {stripped}".strip()
        self._run_raw(tool, cmd)

    def _run_nmap_custom(self, tool, flags_or_command: str):
        """
        Called from NmapCustomDialog.
        If flags_or_command starts with 'nmap' → use as-is (free field override).
        Otherwise → append to 'nmap {flags} {target}'.

        We auto-inject `-v --stats-every 2s` when the user didn't already
        set them — without these flags nmap emits no Initiating/Completed
        or Timing lines and HAWK's progress bar stays at 0 % the whole scan.
        """
        target = self._get_target()
        if not target:
            return
        stripped = flags_or_command.strip()
        if stripped.startswith("nmap ") or stripped == "nmap":
            # Free field — use exactly as typed
            cmd = stripped.replace("{target}", target)
            if "{target}" not in stripped:
                cmd = f"{stripped} {target}"
        else:
            cmd = f"nmap {stripped} {target}"

        # Inject progress flags if the user hasn't already asked for them.
        # Detect `-v` / `-vv` / `-vvv` via a word-boundary check so we don't
        # mistake flags like `-vvvv` or `--verbose-xxx` from future nmap.
        import re as _re
        if not _re.search(r'(?:^|\s)-v+(?:\s|$)', cmd) \
                and "--verbose" not in cmd:
            # Place -v right after 'nmap' so it reads naturally
            cmd = cmd.replace("nmap ", "nmap -v ", 1)
        if "--stats-every" not in cmd:
            # Append before the target (which is last); keeps output clean
            parts = cmd.rsplit(" ", 1)
            if len(parts) == 2:
                cmd = f"{parts[0]} --stats-every 2s {parts[1]}"
            else:
                cmd = f"{cmd} --stats-every 2s"

        self._run_raw(tool, cmd)

    def _show_nmap_confirm(self, tool):
        from gui.dialogs import _make_win, _note_box, _btn_row, _btn, _safe_destroy
        target = self._get_target()
        if not target:
            return
        cmd = tool.build_command(target)

        DESCRIPTIONS = {
            "nmap_service": "Version detection + default NSE scripts.\nIdentifies software versions, banners, SSL certs.\nNon-invasive — does NOT test vulnerabilities.",
            "nmap_vuln":    "NSE 'vuln' category scripts.\nActively tests MS17-010, Heartbleed, SMB issues and more.\nMore invasive and noisy than Service+Scripts.",
            "nmap_quick":   "Fast SYN stealth scan — top 1000 ports.\nDetects ports, versions and OS. Good starting point.",
            "nmap_full":    "Full SYN stealth scan — ALL 65535 ports.\nFinds services on non-standard ports. Use after Quick.",
        }
        desc = DESCRIPTIONS.get(tool.id, tool.desc.split("\n")[0])

        win = _make_win(self, tool.name, 580, 320)
        ctk.CTkLabel(win, text=tool.name, font=_f("xl", True),
                     text_color=COLORS["text_bright"]).pack(pady=(14, 4))
        _note_box(win, desc, COLORS["text_dim"])
        ctk.CTkLabel(win, text="Command:",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=24, pady=(8, 2))
        box = ctk.CTkTextbox(win, height=32, font=_f("md"),
                             fg_color=COLORS["bg_card"],
                             text_color=COLORS["text_cyan"],
                             border_color=COLORS["border_dim"], border_width=1,
                             corner_radius=3)
        box.pack(fill="x", padx=24, pady=(0, 8))
        box.insert("1.0", cmd)
        box.configure(state="disabled")
        add_context_menu(box)
        if tool.requires_sudo:
            _note_box(win, "⚠  Requires sudo.", COLORS["text_yellow"])
        row = _btn_row(win)
        _btn(row, "PROCEED",
             lambda: [_safe_destroy(win), self._run_tool(tool)],
             primary=True)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _show_udp_scope_dialog(self, tool):
        from gui.dialogs import _make_win, _title, _sub, _btn_row, _btn, _safe_destroy
        target = self._get_target()
        if not target:
            return
        win = _make_win(self, "NMAP UDP", 480, 320)
        _title(win, "NMAP UDP  —  Port Scope")
        _sub(win, "UDP scans are slow.", COLORS["text_yellow"])
        scope_var = ctk.StringVar(value="top100")
        for val, label in [("top100","Top 100  (~5 min)  ★"),
                            ("top1000","Top 1000  (~30 min)"),
                            ("all","All ports  (very slow)"),
                            ("custom","Specific port(s)")]:
            rf = ctk.CTkFrame(win, fg_color="transparent")
            rf.pack(anchor="w", padx=40, pady=4)
            ctk.CTkRadioButton(rf, text=label, variable=scope_var, value=val,
                               font=_f("md"), text_color=COLORS["text_dim"],
                               fg_color=COLORS["border_green"],
                               border_color=COLORS["border_dim"]).pack(side="left")
        custom_var = ctk.StringVar(value="")
        entry = ctk.CTkEntry(win, textvariable=custom_var,
                     placeholder_text="e.g. 53,161,500",
                     font=_f("md"), height=30,
                     fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                     border_color=COLORS["border_dim"], border_width=1,
                     corner_radius=3)
        entry.pack(fill="x", padx=40, pady=4)
        add_context_menu(entry)

        def _run():
            sv = scope_var.get()
            m = {"top100":"--top-ports 100","top1000":"--top-ports 1000","all":"-p-"}
            extra = (f"-p {custom_var.get().strip()}"
                     if sv == "custom" and custom_var.get().strip()
                     else m.get(sv, "--top-ports 100"))
            _safe_destroy(win)
            self._run_raw(tool,
                f"sudo nmap -v -Pn -sU -sV {extra} -T3 --stats-every 2s {target}")

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _show_vuln_scope_dialog(self, tool):
        from gui.dialogs import _make_win, _title, _sub, _btn_row, _btn, _safe_destroy
        target = self._get_target()
        if not target:
            return
        win = _make_win(self, "NMAP Vuln Scripts", 480, 320)
        _title(win, "NMAP Vuln Scripts  —  Port Scope")
        scope_var = ctk.StringVar(value="wellknown")
        for val, label in [("wellknown","Well-known 1-1023  ★"),
                            ("top1000","Top 1000"),
                            ("all","All ports"),
                            ("custom","Specific")]:
            rf = ctk.CTkFrame(win, fg_color="transparent")
            rf.pack(anchor="w", padx=40, pady=3)
            ctk.CTkRadioButton(rf, text=label, variable=scope_var, value=val,
                               font=_f("md"), text_color=COLORS["text_dim"],
                               fg_color=COLORS["border_green"],
                               border_color=COLORS["border_dim"]).pack(side="left")
        custom_var = ctk.StringVar(value="")
        entry = ctk.CTkEntry(win, textvariable=custom_var,
                     placeholder_text="e.g. 80,443,445",
                     font=_f("md"), height=30,
                     fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                     border_color=COLORS["border_dim"], border_width=1,
                     corner_radius=3)
        entry.pack(fill="x", padx=40, pady=4)
        add_context_menu(entry)

        def _run():
            sv = scope_var.get()
            m = {"wellknown":"-p 1-1023","top1000":"--top-ports 1000","all":"-p-"}
            extra = (f"-p {custom_var.get().strip()}"
                     if sv == "custom" and custom_var.get().strip()
                     else m.get(sv, "-p 1-1023"))
            _safe_destroy(win)
            self._run_raw(tool,
                f"nmap -v -Pn --script vuln {extra} -T3 --stats-every 2s {target}")

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _show_os_mode_dialog(self, tool):
        from gui.dialogs import _make_win, _title, _note_box, _btn_row, _btn, _safe_destroy
        target = self._get_target()
        if not target:
            return
        win = _make_win(self, "NMAP OS Detection", 560, 340)
        _title(win, "NMAP OS Detection  —  Mode")
        mode_var = ctk.StringVar(value="normal")
        cmds = {
            "normal":     f"sudo nmap -v -Pn -O -sV --top-ports 100 -T3 --stats-every 2s {target}",
            "aggressive": f"sudo nmap -v -Pn -O --osscan-guess --max-os-tries 5 -sV -p- -T3 --stats-every 2s {target}",
        }
        for val, label, desc in [
            ("normal",     "Normal  ★",  "Top 100 ports. ~1 minute."),
            ("aggressive", "Aggressive", "All ports, max retries. ~15 min."),
        ]:
            fr = ctk.CTkFrame(win, fg_color=COLORS["bg_card"], corner_radius=3)
            fr.pack(fill="x", padx=24, pady=4)
            ctk.CTkRadioButton(fr, text=label, variable=mode_var, value=val,
                               font=_f("md",True), text_color=COLORS["text_bright"],
                               fg_color=COLORS["border_green"],
                               border_color=COLORS["border_dim"],
                               ).pack(anchor="w", padx=10, pady=(8,2))
            ctk.CTkLabel(fr, text=f"  {desc}", font=_f("sm"),
                         text_color=COLORS["text_dim"],
                         anchor="w").pack(anchor="w", padx=30, pady=(0,8))
        preview_var = ctk.StringVar(value=cmds["normal"])
        mode_var.trace_add("write",
                           lambda *_: preview_var.set(cmds.get(mode_var.get(),"")))
        ctk.CTkLabel(win, textvariable=preview_var, font=_f("sm"),
                     text_color=COLORS["text_cyan"], anchor="w"
                     ).pack(fill="x", padx=24, pady=(4,0))
        _note_box(win, "⚠  Requires sudo.", COLORS["text_yellow"])
        row = _btn_row(win)
        _btn(row, "RUN",
             lambda: [_safe_destroy(win),
                      self._run_raw(tool, cmds[mode_var.get()])],
             primary=True)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _run_ping(self, tool):
        target = self._get_target()
        if not target:
            return
        self._set_tool_status(tool.id, "running")
        self.set_status(STATUS_RUNNING)
        self._toggle_run_btn(tool, True)
        self.app.terminal.section("RECONNAISSANCE  ·  PING")
        cmd = f"ping -c 4 {target}"
        self.app.terminal.write(f"  $ {cmd}", "cmd")

        def _on_icmp(name, rc, log):
            if rc == 0:
                self.app.terminal.write("[+] Host responding to ICMP.", "success")
                self.after(0, lambda: [
                    self._set_tool_status(tool.id, "done"),
                    self._toggle_run_btn(tool, False),
                    self.set_status(STATUS_DONE),
                ])
            else:
                self.app.terminal.write(
                    "  [!] No ICMP response. Trying TCP SYN on ports 1-1023...", "warn")
                self.after(0, lambda: self._ping_tcp_syn(tool, target))

        ToolRunner(output_callback=self.app.terminal.output_callback,
                   done_callback=_on_icmp,
                   ui_dispatcher=getattr(self.app, "ui_call", None)).run(cmd, "ping")

    def _ping_tcp_syn(self, tool, target):
        cmd = f"sudo nmap -sn -PS1-1023 {target}"
        self.app.terminal.write(f"  $ {cmd}", "cmd")

        def _done(name, rc, log):
            up = any("Host is up" in l for _, l in log)
            if up:
                self.app.terminal.write("[+] Host UP via TCP SYN.", "success")
                self.after(0, lambda: [
                    self._set_tool_status(tool.id, "done"),
                    self._toggle_run_btn(tool, False),
                    self.set_status(STATUS_DONE),
                ])
            else:
                self.app.terminal.write(
                    "  [!] No TCP SYN response. Trying TCP ACK...", "warn")
                self.after(0, lambda: self._ping_tcp_ack(tool, target))

        ToolRunner(output_callback=self.app.terminal.output_callback,
                   done_callback=_done,
                   ui_dispatcher=getattr(self.app, "ui_call", None)).run(cmd, "nmap-syn")

    def _ping_tcp_ack(self, tool, target):
        cmd = f"sudo nmap -sn -PA1-1023 {target}"
        self.app.terminal.write(f"  $ {cmd}", "cmd")

        def _done(name, rc, log):
            up = any("Host is up" in l for _, l in log)
            if up:
                self.app.terminal.write("[+] Host UP via TCP ACK.", "success")
                self.after(0, lambda: [
                    self._set_tool_status(tool.id, "done"),
                    self._toggle_run_btn(tool, False),
                    self.set_status(STATUS_DONE),
                ])
            else:
                self.app.terminal.write(
                    "  [!] No response to any probe.", "warn")
                self.after(0, lambda: [
                    self._set_tool_status(tool.id, "error"),
                    self._toggle_run_btn(tool, False),
                    self._show_host_down_popup(target),
                ])

        ToolRunner(output_callback=self.app.terminal.output_callback,
                   done_callback=_done,
                   ui_dispatcher=getattr(self.app, "ui_call", None)).run(cmd, "nmap-ack")

    def _show_host_down_popup(self, target):
        from gui.dialogs import _make_win, _note_box, _btn_row, _btn, _safe_destroy
        win = _make_win(self, "Host Not Responding", 560, 300)
        ctk.CTkLabel(win, text="⚠  Host Not Responding",
                     font=_f("xl",True), text_color=COLORS["text_red"]).pack(pady=(14,6))
        _note_box(win,
                  f"No response to ICMP, TCP SYN, or TCP ACK on ports 1-1023.\n\n"
                  "Use NMAP Quick or Full with -Pn from Port Scanning card.",
                  COLORS["text_red"])
        row = _btn_row(win)
        _btn(row, "OK", lambda: _safe_destroy(win), primary=True)

