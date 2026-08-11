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

class CardServiceParserMixin:
    def _parse_sqlmap_to_intel(self, tool, log: list) -> bool:
        """Parse sqlmap output — only emit a finding when injection was
        actually confirmed.  Returns True (consumed) even on failure so
        the generic parser doesn't create a false-positive card."""
        import re
        text = "\n".join(ln for _, ln in log)

        if re.search(r"\[CRITICAL\]\s*no parameter", text, re.I):
            self.app.terminal.write(
                "  [!] sqlmap found no injectable parameters in this URL.\n"
                "      Try: add a ?param=value, use Crawl mode, or pick a\n"
                "      different URL from gobuster/nikto findings.",
                "warn")
            return True

        injectable = re.findall(
            r"Parameter:\s*['\"]?(\S+?)['\"]?\s.*?is vulnerable", text, re.I)
        dbs = re.findall(
            r"available databases\s*\[.*?\]:\s*(.*?)(?:\n\n|\Z)",
            text, re.S)
        tables = re.findall(
            r"Database:\s*(\S+)\s+Table:\s*(\S+)", text)

        if not injectable and "sqlmap identified" not in text.lower():
            return True

        target = self._get_target() or "target"
        parts = []
        if injectable:
            parts.append(f"Injectable parameter(s): {', '.join(set(injectable))}")
        if dbs:
            db_list = re.findall(r"\[\*\]\s+(\S+)", dbs[0]) if dbs else []
            if db_list:
                parts.append(f"\nDatabases ({len(db_list)}):")
                parts += [f"  • {d}" for d in db_list[:20]]
        if tables:
            parts.append(f"\nTables found: {len(tables)}")
            for db, tbl in tables[:15]:
                parts.append(f"  {db}.{tbl}")

        sev = "critical" if injectable else "high"
        desc = "\n".join(parts) if parts else "SQL injection confirmed."
        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=f"SQL Injection — {target}",
            description=desc, severity=sev,
            source=tool.name))
        return True

    def _parse_ssh_banner_to_intel(self, tool, log: list) -> bool:
        """Extract SSH version string from the banner-grab output and
        propagate it to the Ports panel.

        Tolerates three backend output formats:
          • legacy nc -nv "(UNKNOWN) [host] 22 (ssh) open" line
            (nc closed before the SSH server flushed its banner)
          • bash /dev/tcp lines (one SSH-2.0-… line)
          • current python3 helper output (utils/banner_grab.py):
            one SSH-2.0-… line on success OR a `[HAWK: ...]`
            diagnostic line when the server is in tcpwrapped /
            MaxStartups / refused state.

        When a real SSH banner is captured, the corresponding entry in
        ``target_intel._fp.open_ports`` is upgraded so the Ports panel
        shows the version string — previously the banner only lived in
        the Target Intel finding and the Ports panel kept an empty
        banner column for SSH.

        When the python3 helper emits a `[HAWK: ...]` diagnostic
        (server didn't send banner), we emit an info-level finding
        with an actionable explanation instead of silently returning
        False — the user needs to know WHY the banner grab failed.
        """
        import re
        target = self._get_target() or "target"
        banner_lines = []
        diagnostic_msg = None       # set when helper reports a problem
        port = 22
        for _, line in log:
            s = line.strip()
            if not s:
                continue
            # Helper diagnostic line — emitted by utils/banner_grab.py
            # when the server didn't send anything (closed, timed out,
            # refused).  Starts with `[HAWK: ` (with COLON after HAWK)
            # to distinguish from the launcher's `[HAWK port=N ...]`
            # marker (no colon, has `port=`).
            if s.startswith("[HAWK: "):
                diagnostic_msg = s
                continue
            # Launcher marker [HAWK port=NNN target=...] emitted by
            # card_routes_scan.py before invoking the helper.
            mh = re.search(r"\[HAWK\s+port=(\d+)", s)
            if mh:
                port = int(mh.group(1))
                continue
            # Legacy nc -nv "..(UNKNOWN) [ip] NNN (ssh) open" status line.
            # Square bracket `]` delimits the IP, not a round paren.
            m = re.search(r'\]\s+(\d+)\s+\(', s)
            if m:
                port = int(m.group(1))
            if re.match(r'^SSH-', s, re.I):
                banner_lines.append(s)
            elif "open" in s.lower() and not s.startswith("["):
                banner_lines.append(s)

        # ── Helper diagnostic: emit actionable finding + bail ────────
        # Banner-grab helper reached the server but the server refused
        # to send anything.  We don't have a banner to show, but we
        # DO have a concrete reason that the user needs.
        if diagnostic_msg and not banner_lines:
            self._emit_ssh_banner_diagnostic(
                tool, target, port, diagnostic_msg)
            return True   # parser DID handle the output (just with a diag)

        if not banner_lines:
            return False

        ssh_version = ""
        for bl in banner_lines:
            if bl.upper().startswith("SSH-"):
                ssh_version = bl
                break

        parts = []
        if ssh_version:
            parts.append(f"Banner: {ssh_version}")
            m = re.search(r'OpenSSH[_\s](\S+)', ssh_version, re.I)
            if m:
                parts.append(f"OpenSSH version: {m.group(1)}")
            m = re.search(r'Dropbear[_\s](\S+)', ssh_version, re.I)
            if m:
                parts.append(f"Dropbear version: {m.group(1)}")
        else:
            parts.append("\n".join(banner_lines))

        parts.append(f"\nTarget: {target}:{port}")
        parts.append("Next steps:")
        parts.append(f"  $ nmap -p {port} -sV --script ssh2-enum-algos,ssh-auth-methods {target}")
        parts.append(f"  $ searchsploit openssh")

        sev = "info"
        all_text = " ".join(banner_lines).lower()
        if any(k in all_text for k in ("4.7", "4.3", "3.9", "dropbear")):
            sev = "medium"

        desc = "\n".join(parts)

        # ── Propagate the banner to the Ports panel ──────────────────
        # The Ports panel reads from `target_intel._fp.open_ports`,
        # a list of `(port, proto, svc, banner)` tuples.  When nmap
        # missed the banner during scan (common on Metasploitable2 +
        # legacy SSH 4.x) but this tool DID capture it, upgrade the
        # entry so the user sees it in the Ports table at the next
        # re-render.  We only overwrite EMPTY or generic banners —
        # never a banner nmap already populated with version data
        # (cf. the same upgrade policy in target_intel_render.py:1547).
        #
        # Render hygiene: previously this helper called
        # `target_intel._render_all()` immediately, which fully repaints
        # the fingerprint + findings + exploits sections.  When
        # `add_auto_finding` ran right after, it also re-rendered the
        # findings section, producing visible back-to-back redraws —
        # the "intel glitched / got rewritten" the user reported.
        # Fix: update fp.open_ports in place and DEBOUNCE the full
        # re-render through `app.after(...)` so multiple banner
        # updates (or rapid emissions of any kind) coalesce into a
        # single repaint ~250 ms later.  `add_auto_finding`'s own
        # `_render_auto_findings()` still runs synchronously so the
        # finding appears immediately; the port-banner repaint
        # follows quietly.
        def _propagate_banner_to_ports():
            try:
                ti = getattr(self.app, "target_intel", None)
                if ti is None or not ssh_version:
                    return
                fp = getattr(ti, "_fp", None)
                if fp is None or not getattr(fp, "open_ports", None):
                    return
                _GENERIC_SVC = {"unknown", "tcpwrapped", "filtered", ""}
                changed = False
                for idx, entry in enumerate(fp.open_ports):
                    try:
                        p, proto, svc, old_ban = entry
                    except (ValueError, TypeError):
                        continue
                    if int(p) != int(port):
                        continue
                    has_useful = (old_ban and old_ban.strip()
                                  and not old_ban.startswith("["))
                    if has_useful:
                        return
                    new_svc = svc if (svc and svc.lower()
                                       not in _GENERIC_SVC) else "ssh"
                    fp.open_ports[idx] = (p, proto, new_svc, ssh_version)
                    changed = True
                    break
                if not changed:
                    return
                # Debounced re-render: cancel any pending tick and
                # schedule a new one.  Multiple banner updates within
                # 250 ms collapse to a single repaint, avoiding the
                # render storm.  Stored on the widget so concurrent
                # parsers share the same tick.
                prev = getattr(ti, "_ssh_banner_render_tick", None)
                if prev is not None:
                    try:
                        self.app.after_cancel(prev)
                    except Exception:
                        pass
                def _do_repaint():
                    try:
                        if hasattr(ti, "_render_all"):
                            ti._render_all()
                    except Exception:
                        pass
                    finally:
                        try:
                            ti._ssh_banner_render_tick = None
                        except Exception:
                            pass
                try:
                    ti._ssh_banner_render_tick = self.app.after(
                        250, _do_repaint)
                except Exception:
                    # if after() fails, do a direct repaint as fallback
                    _do_repaint()
            except Exception:
                pass

        self.app.after(0, _propagate_banner_to_ports)
        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=f"SSH Banner — {ssh_version or 'detected'} on {target}:{port}",
            description=desc, severity=sev,
            source=tool.name, port=port))
        return True

    def _emit_ssh_banner_diagnostic(self, tool, target: str, port: int,
                                      diagnostic_msg: str) -> None:
        """Surface a `[HAWK: ...]` diagnostic from utils/banner_grab.py
        as an actionable info-level Target Intel finding.

        The helper writes one of these well-known strings when it
        couldn't get a banner from the server:
          • [HAWK: connection closed by remote, no banner sent]
              SSH server in tcpwrapped / MaxStartups state, or
              TCP wrappers (/etc/hosts.deny) blocking our IP.
          • [HAWK: timeout waiting for banner]
              Server accepted the TCP handshake but never wrote
              anything within the helper's read timeout.
          • [HAWK: connection refused]
              Port not actually open (race / firewall reaction /
              service restarted).
          • [HAWK: error: <details>]
              Other low-level OSError (network unreachable, etc.).
        """
        body = diagnostic_msg.lstrip("[").rstrip("]")
        # Friendly explanation per diagnostic class.
        if "closed by remote" in body:
            cause = (
                "The SSH server accepted the TCP handshake but "
                "closed the connection BEFORE sending its protocol "
                "banner.  On OpenSSH this almost always means one "
                "of:\n"
                "  • MaxStartups exhausted — too many concurrent "
                "connections from the previous brute/scan attempts "
                "queued up.  Wait 30–60s, or restart sshd / the "
                "target VM, then re-run.\n"
                "  • TCP wrappers blocking our source IP (check "
                "/etc/hosts.deny + /etc/hosts.allow on the target).\n"
                "  • Older OpenSSH (4.x / 5.x) under load — known "
                "race that drops new connections silently.")
        elif "timeout" in body:
            cause = (
                "The TCP handshake completed but no data arrived "
                "within the timeout window.  Possible causes:\n"
                "  • Server is throttling / under heavy load.\n"
                "  • Stateful firewall midway between us and the "
                "target dropped the response packets.\n"
                "  • Target is in a half-open state (post-handshake "
                "ACK only).  Try re-running after a short wait.")
        elif "refused" in body:
            cause = (
                "Connection actively refused.  Either the port is "
                "no longer open (service restarted, host firewall "
                "shut it down) or a stateful firewall sent a RST.")
        else:
            cause = (
                "Low-level network error.  Check basic reachability "
                "(`ping {host}`, `nmap -p {port} {host}`) and re-run."
            ).format(host=target, port=port)

        desc = (
            f"Target: {target}:{port}\n"
            f"Result: {diagnostic_msg}\n\n"
            f"{cause}\n\n"
            f"Manual verification (run from a Kali terminal):\n"
            f"  $ python3 -c \"import socket; "
            f"s=socket.socket(); s.settimeout(5); "
            f"s.connect(('{target}',{port})); "
            f"print(repr(s.recv(256)))\"\n"
            f"  $ ssh -v -o ConnectTimeout=5 user@{target} -p {port}\n"
            f"  $ nmap -p {port} -sV {target}\n\n"
            f"If the manual python3 test ALSO returns b'' or times "
            f"out, the server is at fault — not HAWK.  Restart the "
            f"target / wait, then retry the SSH Banner Grab tool.")
        try:
            self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
                title=f"SSH Banner Grab — server did not respond on "
                      f"{target}:{port}",
                description=desc, severity="info",
                source=tool.name, port=port))
        except Exception:
            # Never let a render glitch swallow the diagnostic — log
            # to the HAWK terminal as a fallback.
            try:
                self.app.terminal.write(
                    f"  [!] SSH Banner Grab: {diagnostic_msg}",
                    "warn")
            except Exception:
                pass

    def _parse_db_fingerprint_to_intel(self, tool, log: list) -> bool:
        """Parse output of the DB Fingerprint tool (STEP 4 / Fase 2).

        Walks the captured lines, extracts [HAWK_DB ...] identifications
        and:

          • For each high/medium-confidence hit, UPGRADES the matching
            entry in ``target_intel._fp.open_ports`` so the per-port
            "📋 CMDS" button and Connect dialog routing pick up the
            correct service automatically.
          • Emits a Target Intel finding per port.  Title is either
            "DB confirmed:" (same svc as nmap had) or
            "Service re-classified:" (nmap got it wrong — e.g. an
            Elasticsearch instance behind a generic 'http' label).
          • Low-confidence hits are surfaced as an info finding only,
            with NO update to fp.open_ports — keeps the fingerprint
            clean of guesses.

        Returns True when the parser produced any output (success,
        diagnostic, or empty result).  Returns False only when the
        log was empty (so the generic raw-log dumper still runs).
        """
        import re
        if not log:
            return False

        target = self._get_target() or "target"

        # Extract hits + diagnostics from the captured log.
        HIT_RE = re.compile(
            r"\[HAWK_DB\s+port=(\d+)\s+svc=(\S+)\s+version=(\S+)"
            r"\s+confidence=(\S+)\]")
        DIAG_RE = re.compile(r"\[HAWK_DB_DIAG:\s*([^\]]+)\]")
        hits = []      # list of (port, svc, version, confidence)
        diag_msgs = []
        for _, line in log:
            s = line.strip()
            if not s:
                continue
            m = HIT_RE.search(s)
            if m:
                port = int(m.group(1))
                svc  = m.group(2).strip()
                ver  = m.group(3).strip()
                conf = m.group(4).strip()
                if ver == "?":
                    ver = ""
                hits.append((port, svc, ver, conf))
                continue
            d = DIAG_RE.search(s)
            if d:
                diag_msgs.append(d.group(1).strip())

        if not hits and not diag_msgs:
            # Nothing recognisable — let the generic raw dumper deal
            # with whatever bizarre output we got.
            return False

        # Build the per-hit Target Intel findings and (when conf is
        # high/medium) update the fingerprint open_ports entry.
        SCHEME = "DB Fingerprint"

        # Closure-local snapshot of what we'll mutate, applied
        # synchronously from the after() callback below — keeps Tk
        # widget access on the main thread.
        def _apply():
            ti = getattr(self.app, "target_intel", None)
            if ti is None:
                return
            fp = getattr(ti, "_fp", None)
            mutated = False
            for port, svc, ver, conf in hits:
                # Lookup current entry (if any) for this port.
                old_entry = None
                if fp is not None and getattr(fp, "open_ports", None):
                    for entry in fp.open_ports:
                        try:
                            p, proto, old_svc, old_ban = entry
                        except (ValueError, TypeError):
                            continue
                        if int(p) == port:
                            old_entry = (proto, old_svc, old_ban)
                            break
                # ── Low-confidence: emit finding only, no fp change.
                if conf == "low":
                    desc = (
                        f"{target}:{port} — low-confidence "
                        f"identification as '{svc}'"
                        + (f" {ver}" if ver else "")
                        + ".\n\nThe protocol probe matched a "
                        f"keyword in the response but no protocol-"
                        f"level magic was confirmed.  The Ports "
                        f"panel service classification was NOT "
                        f"changed.  Re-run the tool, or use the "
                        f"📋 CMDS button manually if you want to "
                        f"investigate."
                    )
                    try:
                        ti.add_auto_finding(
                            title=(f"DB Fingerprint (low-confidence): "
                                   f"{svc} candidate on "
                                   f"{target}:{port}"),
                            description=desc,
                            severity="info",
                            source=SCHEME,
                            port=port)
                    except Exception:
                        pass
                    continue

                # ── High/medium confidence: update fp + emit finding.
                if old_entry is None:
                    # Port not in fp.open_ports (shouldn't happen —
                    # the dispatcher built the cmd from fp's port
                    # list — but be defensive: still emit a finding
                    # so the operator sees the result).
                    try:
                        ti.add_auto_finding(
                            title=(f"DB confirmed: {svc}"
                                   f"{(' '+ver) if ver else ''} on "
                                   f"{target}:{port}"),
                            description=(
                                f"Active probe identified {svc}"
                                f"{(' '+ver) if ver else ''} on "
                                f"{target}:{port} (confidence "
                                f"{conf}).\n\nThe port was not in "
                                f"the current Ports table — no "
                                f"fingerprint update applied."),
                            severity="info",
                            source=SCHEME,
                            port=port)
                    except Exception:
                        pass
                    continue

                proto, old_svc, old_ban = old_entry
                new_ban = (f"DB Fingerprint: {svc}"
                           + (f" {ver}" if ver else ""))
                # Update the fp.open_ports tuple in place.
                if fp is not None:
                    for idx, entry in enumerate(fp.open_ports):
                        try:
                            ep = int(entry[0])
                        except Exception:
                            continue
                        if ep != port:
                            continue
                        fp.open_ports[idx] = (
                            port, proto, svc, new_ban)
                        mutated = True
                        break

                # Emit a finding per port.  If nmap had a different
                # service label, surface it as a re-classification.
                same_svc = (old_svc or "").lower() == svc.lower()
                if same_svc:
                    title = (f"DB confirmed: {svc}"
                             f"{(' '+ver) if ver else ''} on "
                             f"{target}:{port}")
                    desc = (
                        f"Active probe confirmed the nmap "
                        f"identification.\n\n"
                        f"Service:   {svc}"
                        + (f"\nVersion:   {ver}" if ver else "")
                        + f"\nConfidence: {conf}\n\n"
                        f"The 📋 CMDS button in the Ports panel "
                        f"now opens the cheatsheet for this DB."
                    )
                    sev = "info"
                else:
                    title = (f"Service re-classified on "
                             f"{target}:{port}: '{old_svc or '?'}' → "
                             f"'{svc}'")
                    desc = (
                        f"Active protocol probe identified this "
                        f"port as {svc}"
                        f"{(' '+ver) if ver else ''} (confidence "
                        f"{conf}).  Nmap originally labelled the "
                        f"port as '{old_svc or '(unknown)'}'.  "
                        f"The Ports panel has been updated with "
                        f"the correct service so the Connect "
                        f"dialog and the 📋 CMDS button route to "
                        f"the right cheatsheet / template.\n\n"
                        f"Old banner: {old_ban or '(none)'}\n"
                        f"New banner: {new_ban}"
                    )
                    sev = "medium"
                try:
                    ti.add_auto_finding(
                        title=title, description=desc,
                        severity=sev, source=SCHEME, port=port)
                except Exception:
                    pass

            # Trigger a single full re-render after all mutations so
            # the Ports panel shows the new svc labels.  Debounced
            # 250ms — same pattern used by the SSH banner propagator
            # (#8 fix) to avoid render storms.
            if mutated and ti is not None:
                prev = getattr(ti, "_db_fingerprint_render_tick", None)
                if prev is not None:
                    try:
                        self.app.after_cancel(prev)
                    except Exception:
                        pass
                def _do_repaint():
                    try:
                        if hasattr(ti, "_render_all"):
                            ti._render_all()
                    finally:
                        try:
                            ti._db_fingerprint_render_tick = None
                        except Exception:
                            pass
                try:
                    ti._db_fingerprint_render_tick = self.app.after(
                        250, _do_repaint)
                except Exception:
                    _do_repaint()

        self.app.after(0, _apply)

        # Terminal summary so the operator sees the result without
        # switching to Target Intel.
        try:
            if hits:
                kept = [h for h in hits if h[3] != "low"]
                low_n = sum(1 for h in hits if h[3] == "low")
                self.app.terminal.write(
                    f"  [+] DB Fingerprint: {len(kept)} DB(s) "
                    f"identified, {low_n} low-confidence guess(es).",
                    "success")
                for port, svc, ver, conf in kept:
                    self.app.terminal.write(
                        f"      → {target}:{port}  =  {svc}"
                        f"{(' '+ver) if ver else ''}  "
                        f"(conf={conf})",
                        "finding")
            else:
                self.app.terminal.write(
                    "  [+] DB Fingerprint: no databases identified "
                    "on the open ports.", "warn")
        except Exception:
            pass
        return True

    def _parse_enum4linux_to_intel(self, tool, log: list):
        """
        Pull structured info out of enum4linux output:
         - users    (user:[name] rid:[0xXX])
         - groups   (DOMAIN\\name (Domain Group) or Builtin/Local)
         - shares   (table after 'Share Enumeration')
         - domain / workgroup name + SID
         - null-session success
         - NetBIOS computer name + FQDN + DNS domain (enum4linux-ng)
         - SMB dialects supported + SMB signing-required flag
         - NetBIOS role lines (Domain Controller / File Server / Master Browser)
         - MAC address (OUI hint — VMware / VirtualBox / Hyper-V / bare metal)
         - listener-scan reachable services (LDAP/LDAPS/SMB/NetBIOS)
         - "Appears to be root/parent DC" flag from LDAP enumeration
        Saves users/shares/groups into the session and writes a
        rich finding into Target Intel.  Fields are additive and
        conditional: anything enum4linux-ng doesn't emit (typical
        on Samba file servers — no DC role, no LDAP) simply doesn't
        appear in the description.  No field is "required".
        """
        import re
        users          = []
        groups         = []
        shares         = []
        domain_name    = ""
        domain_sid     = ""
        null_session   = False
        samba_version  = ""
        os_info        = ""
        membership     = ""
        # New (enum4linux-ng-only or stronger signals)
        computer_name  = ""    # NetBIOS computer name
        fqdn           = ""
        dns_domain     = ""
        smb_dialects   = []    # list of supported dialect strings
        smb1_enabled   = False
        smb_signing_required = None   # tri-state: None / True / False
        netbios_roles  = []    # list of strings: "Domain Master Browser", ...
        mac_address    = ""
        listener_ports = []    # list of strings: "LDAP 389/tcp", ...
        is_dc          = False

        USER_RE   = re.compile(r'user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]', re.I)
        GROUP_RE  = re.compile(r'S-1-5-[\d\-]+\s+([^\s]+\\[^(]+)\s+\(([^)]+)\)', re.I)
        SHARE_RE  = re.compile(r'^\s*(\w[\w$\-]*)\s+(Disk|IPC|Printer)\s*(.*)', re.I)
        SHARE_NG_RE = re.compile(r'Testing share\s+(\S+)', re.I)
        WORKGROUP_RE = re.compile(r'got domain/workgroup name[:\s]+(\S+)', re.I)
        SID_RE       = re.compile(r'domain sid[:\s]+(S-1-5-[\d\-]+)', re.I)
        SAMBA_RE     = re.compile(r'samba\s+([\d\.]+)', re.I)
        MEMBERSHIP_RE = re.compile(r'Derived membership[:\s]+(.+)', re.I)
        OS_RE         = re.compile(r'^OS[:\s]+(.+)', re.I)
        COMPUTER_RE   = re.compile(r'NetBIOS computer name[:\s]+(\S+)', re.I)
        FQDN_RE       = re.compile(r'^FQDN[:\s]+(\S+)', re.I)
        DNS_DOMAIN_RE = re.compile(r'^DNS domain[:\s]+(\S+)', re.I)
        # SMB dialect lines look like:  "SMB 1.0: true" / "SMB 2.0.2: false"
        DIALECT_RE    = re.compile(
            r'^\s*SMB\s+(\d+\.\d+(?:\.\d+)?)\s*:\s*(true|false)\s*$', re.I)
        SIGNING_RE    = re.compile(
            r'SMB signing required[:\s]+(true|false)', re.I)
        # NetBIOS role lines from "Full NetBIOS names information" block:
        #   "- METASPLOITABLE  <1c> - <GROUP> B <ACTIVE>  Domain Controllers"
        NETBIOS_ROLE_RE = re.compile(
            r'<(?:[0-9a-f]{2})>.*?<ACTIVE>\s+(.+?)\s*$', re.I)
        MAC_RE        = re.compile(
            r'MAC Address\s*=\s*([0-9A-F]{2}(?:[:\-][0-9A-F]{2}){5})', re.I)
        # Listener Scan lines:  "[+] LDAP is accessible on 389/tcp"
        LISTENER_RE   = re.compile(
            r'\[\+\]\s+(\S[^\n]*?)\s+is accessible on\s+(\d+/(?:tcp|udp))',
            re.I)

        for level, line in log:
            s = line.strip()
            if not s:
                continue
            low = s.lower()

            # Users
            m = USER_RE.search(s)
            if m:
                users.append(m.group(1))
                continue

            # Groups
            m = GROUP_RE.search(s)
            if m:
                groups.append(m.group(1).strip())
                continue

            # Shares (ignore header / separator lines)
            if "sharename" not in low and "---" not in s:
                m = SHARE_RE.match(s)
                if m and m.group(1).lower() not in (
                        "reconnecting", "workgroup", "comment", "server", "type"):
                    shares.append((m.group(1), m.group(2), m.group(3).strip()))
            m = SHARE_NG_RE.search(s)
            if m:
                sname = m.group(1)
                if sname.lower() not in [sh[0].lower() for sh in shares]:
                    shares.append((sname, "Disk", ""))

            # OS info (enum4linux-ng)
            m = OS_RE.match(s)
            if m and not os_info:
                os_info = m.group(1).strip()

            # Membership
            m = MEMBERSHIP_RE.search(s)
            if m and not membership:
                membership = m.group(1).strip()

            # Workgroup / domain name
            m = WORKGROUP_RE.search(s)
            if m and not domain_name:
                domain_name = m.group(1)

            # Domain SID
            m = SID_RE.search(s)
            if m:
                sid = m.group(1)
                if sid.upper() != "NULL" and sid != "(NULL":
                    domain_sid = sid

            # Samba version
            m = SAMBA_RE.search(s)
            if m and not samba_version:
                samba_version = m.group(1)

            # Null session
            if "using a null share" in low or "null session" in low:
                null_session = True
            # enum4linux-ng RPC anonymous bind line:
            #   "[+] Server allows authentication via username '' and password ''"
            if ("server allows authentication" in low
                    and "username ''" in low and "password ''" in low):
                null_session = True

            # NetBIOS computer name (enum4linux-ng SMB session block)
            m = COMPUTER_RE.search(s)
            if m and not computer_name:
                computer_name = m.group(1)

            # FQDN
            m = FQDN_RE.match(s)
            if m and not fqdn:
                fqdn = m.group(1)

            # DNS domain
            m = DNS_DOMAIN_RE.match(s)
            if m and not dns_domain:
                dns_domain = m.group(1)

            # SMB dialects + SMB1 enablement signal
            m = DIALECT_RE.match(s)
            if m:
                ver, supported = m.group(1), m.group(2).lower() == "true"
                if supported:
                    smb_dialects.append(ver)
                    if ver.startswith("1."):
                        smb1_enabled = True

            # SMB signing required
            m = SIGNING_RE.search(s)
            if m and smb_signing_required is None:
                smb_signing_required = (m.group(1).lower() == "true")

            # NetBIOS roles (collect interesting ACTIVE lines)
            if s.startswith("-") and "<ACTIVE>" in s.upper():
                m = NETBIOS_ROLE_RE.search(s)
                if m:
                    role = m.group(1).strip()
                    # Skip the most generic ones — keep the diagnostic
                    # roles that actually change attack posture.
                    KEEP = ("domain controller", "domain/workgroup",
                            "domain master browser", "file server",
                            "domain controllers", "master browser")
                    if any(k in role.lower() for k in KEEP):
                        if role not in netbios_roles:
                            netbios_roles.append(role)

            # MAC address
            m = MAC_RE.search(s)
            if m and not mac_address:
                mac_address = m.group(1).upper().replace("-", ":")

            # Listener-scan reachable services
            m = LISTENER_RE.search(s)
            if m:
                svc = m.group(1).strip()
                port = m.group(2)
                listener_ports.append(f"{svc} {port}")

            # DC role flag
            if "appears to be root/parent dc" in low \
                    or "appears to be a domain controller" in low:
                is_dc = True

        # Dedup
        users  = sorted(set(users),  key=str.lower)
        groups = sorted(set(groups), key=str.lower)
        # Shares by (name, type)
        seen_s = set(); uniq_shares = []
        for sh in shares:
            key = (sh[0].lower(), sh[1].lower())
            if key not in seen_s:
                seen_s.add(key); uniq_shares.append(sh)
        shares = uniq_shares

        # Nothing useful — let the generic parser try
        if not any([users, groups, shares, domain_name, null_session,
                    os_info, membership, computer_name, fqdn,
                    smb_dialects, mac_address, listener_ports,
                    is_dc, smb_signing_required is not None]):
            return False

        # Persist to session for later re-use (hydra wordlist, etc.)
        sess = self.app.session_manager.current
        # `rpcclient -c "..."` uses the same parser but the
        # "succeeds against any SMB stack" detected_os = linux nudge
        # is only meaningful for enum4linux's banner-based fingerprint
        # — rpcclient talks to Windows native SMB just as happily, so
        # we keep detected_os alone in that case.
        is_enum4linux = (getattr(tool, "binary", "")
                         in ("enum4linux", "enum4linux-ng"))
        if sess:
            if users:
                sess.add_discovered_users(users)
                # Dump users.txt for hydra/hashcat
                try:
                    import os
                    from utils.config import SESSIONS_DIR
                    users_path = os.path.join(
                        SESSIONS_DIR, f"users_{sess.session_id[:8]}.txt")
                    with open(users_path, "w") as f:
                        f.write("\n".join(users))
                    self.app.terminal.write(
                        f"  [+] Users list saved → {users_path}", "success")
                except Exception as e:
                    print(f"[HAWK] users list save failed: {e}")
            if shares:
                sess.add_discovered_shares([s[0] for s in shares])
            if groups:
                sess.add_discovered_groups(groups)
            if is_enum4linux and sess.detected_os in ("", "unknown"):
                # SMB domain/workgroup → likely Linux/Samba or Windows
                # enum4linux succeeding typically means Samba on Linux
                sess.detected_os = "linux"
            sess.save()

        # Build severity: null session on a real box is HIGH; SMB1
        # enabled escalates to CRITICAL (EternalBlue / MS17-010
        # candidate, plus the relay-attack surface SMB1 brings).
        severity = "high" if null_session or users else "medium"
        if smb1_enabled:
            severity = "critical"

        # Build rich description
        target = self._get_target() or "target"
        parts = []
        if domain_name:
            parts.append(f"Workgroup/Domain     : {domain_name}")
        if domain_sid:
            parts.append(f"Domain SID           : {domain_sid}")
        if computer_name:
            parts.append(f"NetBIOS name         : {computer_name}")
        if fqdn:
            parts.append(f"FQDN                 : {fqdn}")
        if dns_domain:
            parts.append(f"DNS domain           : {dns_domain}")
        if os_info:
            parts.append(f"OS                   : {os_info}")
        if samba_version:
            parts.append(f"Samba version        : {samba_version}")
        if membership:
            parts.append(f"Membership           : {membership}")
        if is_dc:
            parts.append(f"Role                 : Domain Controller")
        if null_session:
            parts.append("Null session         : ALLOWED (no credentials required)")
        if mac_address:
            oui = mac_address[:8]
            # Common pentest-lab MAC OUIs — annotate so the operator
            # immediately spots a virtualised target.
            OUI_HINT = {
                "00:0C:29": "VMware",
                "00:50:56": "VMware",
                "00:05:69": "VMware",
                "00:1C:14": "VMware",
                "08:00:27": "VirtualBox",
                "00:15:5D": "Hyper-V",
                "52:54:00": "QEMU/KVM",
                "00:16:3E": "Xen",
                "FA:16:3E": "OpenStack",
            }
            tag = OUI_HINT.get(oui.upper(), "")
            tag_s = f"  ({tag})" if tag else ""
            parts.append(f"MAC address          : {mac_address}{tag_s}")
        if smb_dialects:
            dl = ", ".join(smb_dialects)
            flag = "  ← SMB1 ENABLED" if smb1_enabled else ""
            parts.append(f"SMB dialects         : {dl}{flag}")
        if smb_signing_required is not None:
            val = "REQUIRED" if smb_signing_required else "NOT required (relay-vulnerable)"
            parts.append(f"SMB signing          : {val}")
        if netbios_roles:
            parts.append(f"NetBIOS roles        : {', '.join(netbios_roles)}")
        if listener_ports:
            # Dedup while preserving order
            seen_lp = set(); uniq_lp = []
            for lp in listener_ports:
                if lp not in seen_lp:
                    seen_lp.add(lp); uniq_lp.append(lp)
            parts.append(f"Reachable services   : {', '.join(uniq_lp)}")

        if users:
            parts.append(f"\nUsers ({len(users)}):")
            parts.append("  " + ", ".join(users[:40]))
            if len(users) > 40:
                parts.append(f"  … and {len(users) - 40} more")

        if shares:
            parts.append(f"\nShares ({len(shares)}):")
            for sn, st, cm in shares[:15]:
                cm_txt = f"  — {cm}" if cm else ""
                parts.append(f"  {sn} ({st}){cm_txt}")

        if groups:
            parts.append(f"\nGroups ({len(groups)}):")
            parts.append("  " + ", ".join(groups[:20]))
            if len(groups) > 20:
                parts.append(f"  … and {len(groups) - 20} more")

        # Attack suggestions
        suggestions = []
        if smb1_enabled:
            suggestions.append(
                f"nmap --script smb-vuln-ms17-010 -p445 {target}    "
                f"# EternalBlue check")
            suggestions.append(
                "msfconsole → use auxiliary/scanner/smb/smb_ms17_010")
        if smb_signing_required is False:
            suggestions.append(
                f"responder -I <iface>  +  ntlmrelayx.py -smb2support "
                f"-t smb://{target}     # signing OFF → relay viable")
        if is_dc:
            suggestions.append(
                f"ldapsearch -x -H ldap://{target} -s base namingcontexts")
            suggestions.append(
                f"bloodhound-python -u <user> -p <pwd> -d "
                f"{(dns_domain or domain_name or 'DOMAIN').lower()} "
                f"-ns {target} -c All")
        if users:
            suggestions.append(
                f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target}")
            suggestions.append(
                f"kerbrute passwordspray -d {domain_name or 'DOMAIN'} users.txt <pwd>")
        if shares:
            anon_try = next((s[0] for s in shares
                             if s[0].lower() not in ("ipc$", "admin$", "c$")), None)
            if anon_try:
                # Carry the module's legacy-Windows compat flags so a copied
                # hint also works on 2008 R2 / NT4 instead of failing with
                # NT_STATUS_RESOURCE_NAME_NOT_FOUND (V3 carry-over; single
                # source is enumeration.SMBCLIENT_COMPAT_FLAGS).
                from modules.enumeration import SMBCLIENT_COMPAT_FLAGS
                compat = SMBCLIENT_COMPAT_FLAGS.format(target=target)
                suggestions.append(
                    f"smbclient //{target}/{anon_try} -N {compat}")
        if samba_version and samba_version.startswith("3."):
            suggestions.append(
                "msfconsole → use exploit/multi/samba/usermap_script  "
                "(CVE-2007-2447 on Samba 3.0.20-3.0.25rc3)")

        if suggestions:
            parts.append("\nNext steps:")
            parts += [f"  $ {c}" for c in suggestions]

        desc = "\n".join(parts)
        # Title — include the most diagnostic flags so the operator
        # sees them at a glance in the Target Intel list without
        # opening the dialog.
        flags = []
        if null_session:
            flags.append("null session")
        if smb1_enabled:
            flags.append("SMB1")
        if smb_signing_required is False:
            flags.append("no signing")
        if is_dc:
            flags.append("DC")
        flag_txt = (" — " + ", ".join(flags)) if flags else ""
        host_txt = computer_name or target
        tool_label = (getattr(tool, "name", "") or "ENUM4LINUX").upper()
        title = (f"{tool_label} — {len(users)} users, "
                 f"{len(shares)} shares on {host_txt}{flag_txt}")

        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description=desc,
            severity=severity, source=tool.name))
        return True

    def _parse_kerbrute_to_intel(self, tool, log: list) -> bool:
        """Parse kerbrute output and:
          - push valid usernames (userenum) to Credential Store as
            'username-only' entries with AD follow-up commands in notes,
          - push valid logins (passwordspray / bruteuser / bruteforce) as
            full cleartext credentials with host + usage hint,
          - emit one Target Intel finding summarizing the run.

        Matches the two key kerbrute success patterns:
          [+] VALID USERNAME: user@REALM
          [+] VALID LOGIN:    user@REALM:pass
        """
        import re
        VALID_USER_RE  = re.compile(
            r"VALID USERNAME[:\s]+([^\s@]+)(?:@(\S+))?", re.I)
        VALID_LOGIN_RE = re.compile(
            r"VALID LOGIN[:\s]+([^\s@]+)(?:@(\S+))?\s*[:]\s*(\S+)", re.I)

        ctx = getattr(self, "_kerbrute_ctx", {}) or {}
        realm_ctx = ctx.get("realm", "")
        dc_ctx    = ctx.get("dc", "")
        mode_ctx  = ctx.get("mode", "")

        valid_users  = []   # (user, realm)
        valid_logins = []   # (user, realm, pass)

        for _, line in log:
            s = line.strip()
            if not s:
                continue
            m = VALID_LOGIN_RE.search(s)
            if m:
                valid_logins.append(
                    (m.group(1), m.group(2) or realm_ctx, m.group(3)))
                continue
            m = VALID_USER_RE.search(s)
            if m:
                valid_users.append(
                    (m.group(1), m.group(2) or realm_ctx))

        # Dedup, preserving first-seen order.
        seen = set()
        valid_users  = [(u, r) for u, r in valid_users
                        if not (u.lower() in seen or seen.add(u.lower()))]
        seen = set()
        valid_logins = [(u, r, p) for u, r, p in valid_logins
                        if not ((u.lower(), p) in seen
                                or seen.add((u.lower(), p)))]

        if not valid_users and not valid_logins:
            return False

        target   = self._get_target() or "target"
        realm    = realm_ctx or (valid_users[0][1] if valid_users
                                 else valid_logins[0][1] if valid_logins else "")
        dc       = dc_ctx or target

        # Persist discovered users in the session for later hydra/spray runs.
        try:
            sess = self.app.session_manager.current
            if sess:
                unames = ([u for u, _ in valid_users]
                          + [u for u, _, _ in valid_logins])
                if unames:
                    sess.add_discovered_users(unames)
                sess.save()
        except Exception:
            pass

        # Push each valid user to the Credential Store. These are
        # "known username, unknown password" entries — still useful as
        # the next step is AS-REP roasting or password spray.
        for user, r in valid_users:
            note = (
                f"Kerbrute — Valid AD user (userenum)\n"
                f"Realm: {r or '<unknown>'}   DC: {dc}\n"
                f"Next steps:\n"
                f"  $ impacket-GetNPUsers {r}/{user} -no-pass -dc-ip {dc}\n"
                f"  $ kerbrute passwordspray -d {r} --dc {dc} users.txt "
                f"'Spring2024!'\n"
                f"  $ nxc smb {target} -u {user} -p ''  # null-bind test"
            )
            cred = Credential(
                username=user, password="",
                cred_type="cleartext",
                services=["KERBEROS"],
                source_phase=self.phase_id,
                host=target, notes=note,
                # userenum proves the account EXISTS.  No password was
                # ever tried, so there is nothing verified about it.
                verified=False)
            self.app.cred_store.add_credential(cred)

        # Valid logins — full cleartext creds.
        for user, r, pwd in valid_logins:
            note = (
                f"Kerbrute — Valid AD login ({mode_ctx or 'spray'})\n"
                f"Realm: {r or '<unknown>'}   DC: {dc}\n"
                f"Use with:\n"
                f"  $ nxc smb {target} -u {user} -p '{pwd}'\n"
                f"  $ evil-winrm -i {target} -u {user} -p '{pwd}'\n"
                f"  $ impacket-psexec {r}/{user}:'{pwd}'@{target}"
            )
            cred = Credential(
                username=user, password=pwd,
                cred_type="cleartext",
                services=["KERBEROS", "SMB", "WINRM"],
                source_phase=self.phase_id,
                host=target, notes=note,
                # VALID LOGIN line: Kerberos pre-auth succeeded with
                # this password.
                verified=True)
            self.app.cred_store.add_credential(cred)

        # Severity: a valid login is HIGH, enumeration-only is MEDIUM.
        severity = "high" if valid_logins else "medium"

        parts = []
        parts.append(f"Realm        : {realm or '<unknown>'}")
        parts.append(f"DC           : {dc}")
        if mode_ctx:
            parts.append(f"Mode         : {mode_ctx}")
        if valid_users:
            parts.append(f"\nValid users ({len(valid_users)}):")
            names = ", ".join(u for u, _ in valid_users[:40])
            parts.append(f"  {names}")
            if len(valid_users) > 40:
                parts.append(f"  … and {len(valid_users) - 40} more")
        if valid_logins:
            parts.append(f"\nValid logins ({len(valid_logins)}):")
            for u, _, p in valid_logins[:20]:
                parts.append(f"  {u} : {p}")

        parts.append("\nNext steps:")
        if valid_users and not valid_logins:
            parts.append("  • AS-REP roast users with DONT_REQ_PREAUTH:")
            parts.append(
                f"      impacket-GetNPUsers {realm}/ -usersfile users.txt "
                f"-no-pass -dc-ip {dc}")
            parts.append("  • Password-spray the enumerated users:")
            parts.append(
                f"      kerbrute passwordspray -d {realm} --dc {dc} "
                f"users.txt 'Spring2024!'")
        if valid_logins:
            u0, _, p0 = valid_logins[0]
            parts.append("  • Authenticate with the first valid login:")
            parts.append(f"      nxc smb {target} -u {u0} -p '{p0}'")
            parts.append(
                f"      impacket-secretsdump {realm}/{u0}:'{p0}'@{target}")

        desc = "\n".join(parts)
        title = (f"KERBRUTE — {len(valid_users)} users, "
                 f"{len(valid_logins)} logins on {target}")

        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description=desc,
            severity=severity, source=tool.name))

        # Terminal summary so the user sees immediate feedback.
        if valid_users:
            self.app.terminal.write(
                f"  [+] Kerbrute — {len(valid_users)} valid AD user"
                f"{'s' if len(valid_users) != 1 else ''} "
                f"added to Credential Store.", "success")
        if valid_logins:
            self.app.terminal.write(
                f"  [+] Kerbrute — {len(valid_logins)} valid login"
                f"{'s' if len(valid_logins) != 1 else ''} "
                f"(user:pass) added to Credential Store.", "success")
        return True

    def _maybe_offer_cred_retry(self, tool, log: list, returncode: int):
        """When a NetExec/Impacket run returns 'access denied' style
        errors on what looks like an anonymous/null-session probe,
        prompt the user to try again with credentials.

        Detection is conservative: we only pop up the dialog when:
          1. The tool's log contains a known access-denied signature
          2. AND the tool either was invoked with empty creds OR failed
             to authenticate at all (no valid login recorded).
        """
        import re
        if not log:
            return

        text = "\n".join(l for _, l in log)
        text_low = text.lower()

        # Known access-denied / auth-failure signatures
        deny_signals = (
            "status_access_denied",
            "error enumerating shares",
            "status_logon_failure",
            "status_network_logon_failure",
            "restrictanonymous",
            "access_denied",
            "authentication failed",
            "unauthorized",
            "smb sessionerror",
            "rpc_s_access_denied",
        )
        if not any(s in text_low for s in deny_signals):
            return

        # Suppress pop-up if a known-good auth was actually recorded —
        # netexec prints "[+] <domain>\<user>:<pass>" on success, we
        # don't want to nag the user when something positive happened.
        if re.search(r"\[\+\]\s+\S+\\\S+:", text):
            # Successful auth recorded somewhere in the log
            return

        target = self._get_target()
        if not target:
            return

        # Open the retry dialog on the UI thread with a small delay so
        # it lands AFTER the terminal has finished flushing the tool's
        # last output (avoids visual clash with the scroll).
        self.after(400, lambda:
                   self._show_cred_retry_dialog(tool, target, text))

    def _show_cred_retry_dialog(self, tool, target, raw_output):
        """Dialog shown after an anonymous run got ACCESS_DENIED.

        Offers 3 paths:
          RETRY W/ CREDS  → re-runs the tool with user/pass/hash typed here
          STORE ONLY      → saves the creds to the Credential Store but
                             doesn't re-run anything (useful if the user
                             is about to try a different tool)
          SKIP            → dismiss, no-op
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        # Session defaults
        sess = self.app.session_manager.current
        default_domain = ""
        try:
            default_domain = getattr(sess, "target_domain", "") or ""
        except Exception:
            pass

        # Is a cred already in the store for this host?  If YES, we
        # still offer the retry but pre-fill from it.
        preset_u = "Administrator"
        preset_p = ""
        preset_h = ""
        try:
            if sess is not None:
                for c in sess.get_credentials():
                    if ((c.host or "").lower() == target.lower()
                            and (c.password or getattr(c, "hash_val", ""))):
                        preset_u = (c.username or preset_u)
                        preset_p = c.password or ""
                        preset_h = getattr(c, "hash_val", "") or ""
                        break
        except Exception:
            pass

        win = _make_win(self,
                        f"{tool.name} — try with credentials?",
                        560, 460)
        _title(win, f"{tool.name} — anonymous denied by the target")

        _note_box(win,
                  "The anonymous / null-session bind was accepted, but "
                  "the target refused to execute the operation "
                  "(RestrictAnonymous / ACL on SMB shares / MS-DS "
                  "policy).\n\nThis is normal on Windows Server 2003+.\n"
                  "Enter them below and HAWK re-runs the tool with auth.",
                  COLORS["text_yellow"])

        def _row(label, var, hint=""):
            f = ctk.CTkFrame(win, fg_color="transparent")
            f.pack(fill="x", padx=24, pady=(4, 0))
            ctk.CTkLabel(f, text=label, width=110, anchor="w",
                         font=_f("sm", True),
                         text_color=COLORS["text_bright"]).pack(side="left")
            e = ctk.CTkEntry(f, textvariable=var, font=_f("sm"),
                             height=30,
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

        user_var   = ctk.StringVar(value=preset_u)
        pass_var   = ctk.StringVar(value=preset_p)
        hash_var   = ctk.StringVar(value=preset_h)
        domain_var = ctk.StringVar(value=default_domain)

        _row("Username",  user_var,   "e.g. Administrator, vagrant, "
                                      "any domain user you compromised")
        _row("Password",  pass_var,   "leave blank if using NTLM hash")
        _row("NTLM hash", hash_var,   "optional — :<NT> or <LM>:<NT>")
        _row("Domain",    domain_var, "optional — pre-filled from session")

        def _build_cmd_with_creds():
            u = user_var.get().strip()
            p = pass_var.get()
            h = hash_var.get().strip()
            d = domain_var.get().strip()
            if not u:
                return None, "username required"
            if not p and not h:
                return None, "password or NTLM hash required"
            user_part = f"{d}/{u}" if d else u

            # Impacket family
            if (tool.binary or "").startswith("impacket-"):
                bin_ = tool.binary
                if h:
                    nt_fmt = h if ":" in h else f":{h}"
                    return (f"{bin_} {_shq(user_part)}@{target} "
                            f"-hashes {_shq(nt_fmt)} -no-pass"), None
                return (f"{bin_} {_shq(user_part)}:{_shq(p)}@{target}"), None

            # NetExec / CME family — use the command that was already
            # run as a template, just swap `-u '' -p ''` for real creds.
            # Fall back to a plain smb shares enum.
            proto_m = re.search(r"(?:netexec|nxc|crackmapexec|cme)\s+"
                                 r"(\w+)", raw_output)
            proto = proto_m.group(1) if proto_m else "smb"
            # Extract the flags (everything after `<proto> <target>`)
            # from the original command so we preserve --shares, --sam,
            # --users, etc.
            flags_m = re.search(
                rf"(?:netexec|nxc|crackmapexec|cme)\s+{proto}\s+\S+\s+(.+)",
                raw_output)
            flags = (flags_m.group(1) if flags_m else "--shares")
            # Strip any existing -u/-p/-H flags the user had before —
            # we're going to inject our own.
            flags = re.sub(r"-u\s+\S+", "", flags)
            flags = re.sub(r"-p\s+\S+", "", flags)
            flags = re.sub(r"-H\s+\S+", "", flags)
            flags = re.sub(r"\s+", " ", flags).strip()

            bin_ = tool.binary
            if h:
                nt_fmt = h if ":" in h else f":{h}"
                cmd = (f"{bin_} {proto} {target} "
                       f"-u {_shq(u)} -H {_shq(nt_fmt)} {flags}")
            else:
                cmd = (f"{bin_} {proto} {target} "
                       f"-u {_shq(u)} -p {_shq(p)} {flags}")
            if d:
                cmd += f" -d {_shq(d)}"
            return cmd.strip(), None

        def _retry():
            cmd, err = _build_cmd_with_creds()
            if err:
                self.app.terminal.write(f"[!] {err}", "warn")
                return
            # Save the creds to the store so next time they're there.
            _save_to_store()
            _safe_destroy(win)
            self._run_raw(tool, cmd)

        def _save_to_store():
            """Save the typed creds.  Returns True only when something
            was actually stored — a username with no password/hash trips
            the guard and stores nothing, so callers must not claim a
            save happened (W-04)."""
            try:
                from utils.session import Credential
                u = user_var.get().strip()
                p = pass_var.get()
                h = hash_var.get().strip()
                if not u or (not p and not h):
                    return False
                svc = ("SMB" if tool.binary in ("netexec", "nxc",
                                                "crackmapexec", "cme")
                       else "AD")
                cred = Credential(
                    username=u,
                    password=p if not h else "",
                    cred_type="hash" if h else "cleartext",
                    hash_val=h,
                    hash_type="NTLM",
                    services=[svc],
                    source_phase=self.phase_id,
                    host=target,
                    notes=f"Added via {tool.name} retry dialog",
                    # Typed by the operator before the retry even
                    # runs — a guess until something authenticates.
                    verified=False)
                self.app.cred_store.add_credential(cred)
                return True
            except Exception as e:
                print(f"[HAWK] cred save failed: {e}")
                return False

        def _store_only():
            if _save_to_store():
                self.app.terminal.write(
                    "  [+] Credentials saved to Credential Store. "
                    "You can re-run any tool now.", "success")
            else:
                self.app.terminal.write(
                    "  [!] Nothing saved — enter a username and a "
                    "password or hash first.", "warn")
            _safe_destroy(win)

        row = _btn_row(win)
        _btn(row, "RETRY W/ CREDS", _retry, primary=True, w=170)
        _btn(row, "STORE ONLY", _store_only, w=130)
        _btn(row, "SKIP", lambda: _safe_destroy(win), w=100)

    def _extract_web_target_label(self, tool):
        """Scope-rich label for Target Intel finding titles.

        Returns a normalised full URL of the form
        ``<scheme>://<host>:<port><path>`` so the finding title is
        unambiguous.  Two normalisations are applied so titles are
        comparable across runs:

          * **Port is ALWAYS present.**  HTTP defaults to ``:80``,
            HTTPS to ``:443`` when the URL didn't carry one
            explicitly.  Without this, ``http://host`` and
            ``http://host:80`` would merge into different finding
            cards.
          * **Path always ends with ``/``.**  When the URL has no
            path we render ``/``; when it has ``/api`` we render
            ``/api/``.  Avoids visual ambiguity ('on http://host'
            vs 'on http://host/').

        Strips ffuf's ``/FUZZ`` marker, query strings, and fragments
        so they don't pollute the title.

        Fallback chain when no URL is in the cmd:
          1. ``host:port`` if only the netloc is parseable.
          2. Bare ``target`` from the session.
          3. ``"target"`` literal as last resort.
        """
        import re
        from urllib.parse import urlparse, urlunparse
        target = self._get_target() or "target"

        def _normalise_url(raw: str) -> str:
            """Apply port + trailing-slash normalisation."""
            raw = raw.split("?", 1)[0].split("#", 1)[0]
            raw = re.sub(r"/FUZZ.*$", "/", raw)
            try:
                pu = urlparse(raw)
                scheme = (pu.scheme or "http").lower()
                host = (pu.hostname or "").lower()
                if not host:
                    return raw
                port = pu.port
                if port is None:
                    port = 443 if scheme == "https" else 80
                netloc = f"{host}:{port}"
                path = pu.path or "/"
                if not path.endswith("/"):
                    path += "/"
                return urlunparse((scheme, netloc, path, "", "", ""))
            except Exception:
                return raw

        try:
            cmd = self._tool_widgets.get(tool.id, {}).get(
                "_last_cmd", "")
            if cmd:
                m = re.search(
                    r"(https?://[^\s'\"]+)", cmd, re.IGNORECASE)
                if m:
                    return _normalise_url(m.group(1))
                # No URL but maybe a bare host:port in the cmd.
                m2 = re.search(
                    r"\b([a-zA-Z][\w\-.]+\.[\w\-.]+:\d+)\b", cmd)
                if m2:
                    return m2.group(1)
        except Exception:
            pass
        return target

