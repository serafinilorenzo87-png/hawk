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

class TargetIntelMsfMixin:
    @staticmethod
    def _auto_generate_finding_info(title: str, description: str,
                                    severity: str = "info") -> dict:
        """Build a structured info dict from any finding, even if it's
        not in the curated FINDING_INFO database.

        Analyses the title and description for:
          - CVE IDs
          - nmap script names → protocol/service hints
          - Common vulnerability keywords → impact guesses
          - Auto-suggested next steps (searchsploit, MSF, manual)

        For low-signal output (info-severity findings that happen to be
        tool progress / download logs / banners) we return an honest
        "this is tool output, not a vulnerability" dict instead of
        fabricating fake nmap / nuclei follow-up commands.
        """
        import re
        combined = (title + " " + description).lower()

        # ── Early bailout: this is clearly NOT a vulnerability ───────
        # Curl progress table, tool banner, or a download action.  The
        # old code happily invented "This vulnerability was confirmed
        # as exploitable by nmap" + "nmap --script vuln" + "nuclei"
        # for these rows, which is garbage and confuses the user.
        is_progress = bool(
            re.search(r'%\s*total\s+%\s*received\s+%\s*xferd', combined) or
            re.search(r'dload\s+upload\s+total\s+spent', combined) or
            re.search(r'\bcurrent\s+speed\b', combined))
        is_action_title = any(t in (title or "").lower() for t in (
            "(download)", "(install)", "(upload)", "(copy)",
            "(fetch)", "(get)", "peas", "pspy"))
        if is_progress or (severity == "info" and is_action_title):
            return {
                "what":    (
                    f"'{title}' is a tool action (download / transfer / "
                    f"exec helper), not a discovered vulnerability.\n\n"
                    f"HAWK logged its terminal output here so you can "
                    f"review what ran, but there's nothing to exploit "
                    f"at this step — the finding exists only as an "
                    f"audit trail."),
                "get":     (
                    "Nothing directly. This entry records that the "
                    "action completed; the real work happens in the "
                    "next step (e.g. host the script, run it on the "
                    "target, review the output)."),
                "how":     (
                    "No exploit needed — this is not a vulnerability.\n"
                    "Continue with the normal post-exploitation flow "
                    "(host the script → run on target → collect output)."),
                "cve":     "N/A",
                "affects": "N/A — informational tool output.",
            }

        # ── Early bailout: EXPOSURE findings ─────────────────────────
        # Web Oracle / nuclei tag reachable services as "EXPOSURE".
        # These are NOT vulnerabilities — just "this port/path is open".
        # The generic IMPACT_MAP below would match stray keywords like
        # "source code" → RCE, producing dangerously misleading advice.
        title_up = (title or "").upper()
        if "EXPOSURE" in title_up:
            port_m = re.search(r':(\d+)', title or "")
            port_hint = f" (port {port_m.group(1)})" if port_m else ""
            path_m = re.search(r'Path\s*:\s*(\S+)', description or "")
            path_hint = path_m.group(1) if path_m else ""
            return {
                "what": (
                    f"A reachable service or path was detected{port_hint}.\n"
                    f"This is an EXPOSURE — the service is accessible from "
                    f"the network, which is not a vulnerability by itself "
                    f"but widens the attack surface."),
                "get": (
                    "Access to the service. Depending on its configuration:\n"
                    "  • Default or weak credentials → unauthorized access\n"
                    "  • Outdated version → known CVE exploits\n"
                    "  • Misconfiguration → information disclosure\n"
                    "  • Sensitive files or admin panels if it's a web path"),
                "how": (
                    f"1. Identify the service version:\n"
                    f"   nmap -sV -p {port_m.group(1) if port_m else '<port>'}"
                    f" <target>\n"
                    f"2. Check for default credentials (admin:admin, etc.)\n"
                    f"3. Search for known vulnerabilities:\n"
                    f"   searchsploit <service name + version>\n"
                    f"4. If it's a web path, open it in a browser and inspect"),
                "cve":     "N/A — exposure, not a specific vulnerability.",
                "affects": f"Exposed service{port_hint} on the target."
                           + (f"\nPath: {path_hint}" if path_hint else ""),
            }

        # ── Extract CVE ──────────────────────────────────────────────
        cve_m = re.search(r'(CVE-\d{4}-\d+)', title + " " + description, re.I)
        cve_id = cve_m.group(1).upper() if cve_m else "N/A"

        # ── Extract script name ──────────────────────────────────────
        script_m = re.search(r'Script:\s*([\w-]+)', description)
        script_name = script_m.group(1) if script_m else ""

        # ── Infer the protocol/service from script name or content ───
        PROTO_HINTS = {
            "http":  ["http-", "web ", "drupal", "apache", "iis",
                      "tomcat", "php", "asp", "nginx", "wordpress"],
            "SSL/TLS": ["ssl-", "tls-", "poodle", "heartbleed",
                        "sslv3", "certificate", "cipher"],
            "SMB":   ["smb-", "ms17", "ms08", "ms10", "eternalblue",
                      "samba", "netbios", "microsoft-ds"],
            "RDP":   ["rdp-", "bluekeep", "ms12-020", "remote desktop"],
            "SSH":   ["ssh-"],
            "FTP":   ["ftp-"],
            "DNS":   ["dns-"],
            "SMTP":  ["smtp-"],
            "LDAP":  ["ldap-"],
        }
        detected_proto = "Unknown service"
        for proto, keywords in PROTO_HINTS.items():
            if any(kw in combined for kw in keywords):
                detected_proto = proto
                break

        # ── Infer what the attacker gets ─────────────────────────────
        IMPACT_MAP = [
            (["remote code", "rce", "arbitrary code", "code execution",
              "buffer overflow", "command injection"],
             "Remote Code Execution — the attacker can run arbitrary "
             "commands on the target system."),
            (["sql injection", "sqli", "sql syntax"],
             "SQL Injection — the attacker can read/write the database, "
             "potentially escalating to full RCE."),
            (["denial of service", "dos", "crash", "bsod"],
             "Denial of Service — the attacker can crash the service "
             "or the entire system."),
            (["information disclosure", "memory leak", "memory disclosure",
              "padding oracle", "decrypt"],
             "Information Disclosure — the attacker can steal sensitive "
             "data (credentials, session tokens, private keys)."),
            (["authentication bypass", "auth bypass", "bypass"],
             "Authentication Bypass — the attacker can access the "
             "service without valid credentials."),
            (["privilege escalation", "priv esc", "escalat"],
             "Privilege Escalation — the attacker can elevate from "
             "a low-privilege user to admin/SYSTEM."),
            (["cross-site", "xss", "script injection"],
             "Cross-Site Scripting (XSS) — the attacker can execute "
             "JavaScript in victims' browsers (steal cookies, redirect)."),
            (["directory traversal", "path traversal", "lfi", "file inclusion"],
             "File Inclusion / Path Traversal — the attacker can read "
             "arbitrary files from the server."),
            (["anonymous", "guest", "no auth", "without credentials",
              "default credentials"],
             "Unauthorized Access — the service is accessible without "
             "credentials or with default passwords."),
        ]
        # Generic default — kept neutral.  Only overridden below if one
        # of the IMPACT_MAP keyword buckets matches.  The previous text
        # ("confirmed as exploitable by nmap") was dishonest for every
        # non-nmap source — e.g. curl downloads, whois output, wafw00f.
        impact = ("Unclear from the description alone.\n"
                  "Read the FULL FINDING above for details on what the "
                  "tool actually reported, then decide the next step.")
        for keywords, desc in IMPACT_MAP:
            if any(kw in combined for kw in keywords):
                impact = desc
                break

        # ── Build "What it is" from description lines ────────────────
        # Take the most meaningful lines from the finding description,
        # skip metadata like "Script:", "CVE:", "References:"
        what_lines = []
        for raw_line in description.split("\n"):
            l = raw_line.strip()
            if not l:
                continue
            if l.startswith(("Script:", "CVE:", "References:", "http://",
                             "https://")):
                continue
            what_lines.append(l)
        # If we still have no lines, fall back to the title itself —
        # more honest than the old "confirmed by nmap" lie for findings
        # that were produced by a completely different tool.
        what_text = "\n".join(what_lines[:4]) if what_lines else (
            f"{title}\n\n"
            f"No detailed description was captured — the source tool "
            f"only produced a short label.")

        # ── Build "How to exploit" with concrete next steps ──────────
        # Only add an nmap vuln-script line when the protocol hint
        # actually matches something nmap can probe (NOT "Unknown").
        # Only add nuclei when the service is web (http / SSL).  For
        # everything else we keep the list short and pointer-based
        # instead of inventing commands that won't run.
        target_placeholder = "<target>"
        how_parts = []
        if cve_id != "N/A":
            how_parts.append(f"searchsploit {cve_id}")
            cve_underscore = cve_id.replace("-", "_").lower()
            how_parts.append(f"msfconsole → search {cve_underscore}")
            if detected_proto != "Unknown service":
                how_parts.append(
                    f"nmap --script vuln -p <port> {target_placeholder}")
        else:
            if script_name:
                how_parts.append(
                    f"searchsploit {script_name.replace('-', ' ')}")
            if detected_proto != "Unknown service":
                how_parts.append(
                    f"nmap --script vuln -p <port> {target_placeholder}")
        # nuclei is a web-CVE scanner — only useful for HTTP/SSL targets.
        if detected_proto in ("http", "SSL/TLS"):
            how_parts.append(
                f"nuclei -t cves/ -u http://{target_placeholder}")
        if not how_parts:
            how_parts = [
                "No automatic exploit path detected for this finding.",
                "Re-read the FULL FINDING, then:",
                "  • searchsploit <keywords from title>",
                "  • Check the source tool's docs for follow-up commands.",
            ]
        how_text = "\n".join(how_parts)

        # ── Affected systems ─────────────────────────────────────────
        # "Unknown service on the target" was a nonsensical fallback —
        # if we couldn't infer the protocol, say so plainly instead.
        if detected_proto == "Unknown service":
            affects = "Unable to infer affected service from the finding."
        else:
            affects = f"Services running {detected_proto} on the target."
        # Extract version hints from description if available
        ver_m = re.search(
            r'(?:version|before|prior to|affected)\s*[:\s]?\s*'
            r'([\d.]+\S*)', combined)
        if ver_m:
            affects += f"\nVulnerable versions: ≤ {ver_m.group(1)}"

        return {
            "what":    what_text,
            "get":     impact,
            "how":     how_text,
            "cve":     cve_id,
            "affects": affects,
        }

    def _rank_modules_for_target(self, modules, finding):
        """Order MSF module suggestions so the best match for THIS target is
        first — it becomes both the picker's pre-selected default and the
        single-module direct-launch choice.  Thin wrapper: pull the target
        OS off self._fp and the finding's port off the shared resolver, then
        delegate to the pure ranker in utils.msf_index (rationale there)."""
        try:
            plat = (getattr(self._fp, "platform", "") or "")
        except Exception:
            plat = ""
        try:
            port = self._extract_port_from_finding(finding)
        except Exception:
            port = None
        try:
            from utils import msf_index as _mi
            return _mi.rank_modules_for_target(
                modules, platform=plat, port=port)
        except Exception as e:
            print(f"[HAWK] msf module ranking failed: {e}")
            return modules

    def _show_msf_module_picker(self, modules: list, finding: dict):
        """Picker dialog shown when a finding has MORE than one MSF
        module that could exploit it (e.g. ms17-010 has eternalblue +
        psexec + scanner).  `modules` is the list of (module_path,
        short_label) tuples returned by _get_exploits_for_vuln.  After
        the user picks, we chain to _show_msf_launch_dialog with the
        selected module so the rest of the flow (LHOST/LPORT/payload)
        is identical to the single-module case."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn

        win = _make_win(self, "MSF — Pick a module", 720, 440)

        ctk.CTkLabel(win, text="MULTIPLE MSF MODULES AVAILABLE",
                     font=_f("xl", True),
                     text_color=COLORS["text_green"]).pack(pady=(16, 4))
        ctk.CTkLabel(win, text=f"Finding: {finding.get('title','')[:72]}",
                     font=_f("sm"),
                     text_color=COLORS["text_dim"],
                     wraplength=660).pack(pady=(0, 10))
        ctk.CTkLabel(win,
                     text=("This vulnerability has several MSF modules — "
                           "pick the one you want to launch.\n"
                           "First option is usually the full-RCE exploit; "
                           "scanners and DoS variants follow."),
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     wraplength=660,
                     justify="left").pack(padx=20, pady=(0, 10))

        # Default selection: first module (most-useful-first convention).
        sel_var = ctk.StringVar(value=modules[0][0])

        # Scrollable list so long sets (ms17-010 has 3+) fit.
        body = ctk.CTkScrollableFrame(
            win, fg_color="transparent", height=220,
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["text_dim"])
        body.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        for mod_path, label in modules:
            row = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                               border_color=COLORS["border_dim"],
                               border_width=1, corner_radius=3)
            row.pack(fill="x", pady=3, padx=2)

            rb = ctk.CTkRadioButton(
                row, text="", variable=sel_var, value=mod_path,
                font=_f("md"),
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                hover_color=COLORS["bg_card_hover"],
                radiobutton_width=16, radiobutton_height=16,
                width=24)
            rb.pack(side="left", padx=(8, 2), pady=8)

            txt_fr = ctk.CTkFrame(row, fg_color="transparent")
            txt_fr.pack(side="left", fill="x", expand=True, pady=4)
            ctk.CTkLabel(txt_fr, text=mod_path,
                         font=_f("md", True),
                         text_color=COLORS["text_bright"],
                         anchor="w").pack(fill="x", padx=4)
            ctk.CTkLabel(txt_fr, text=label,
                         font=_f("sm"),
                         text_color=COLORS["text_dim"],
                         wraplength=520,
                         anchor="w", justify="left").pack(fill="x", padx=4)

            # Clicking anywhere on the row selects the radio — same UX
            # the user gets on the Connect dialog.
            def _select(m=mod_path):
                sel_var.set(m)
            for w in (row, txt_fr):
                w.bind("<Button-1>", lambda e, m=mod_path: sel_var.set(m))

        def _launch():
            chosen = sel_var.get()
            _safe_destroy(win)
            if chosen:
                self._show_msf_launch_dialog(chosen, finding)

        row = _btn_row(win)
        _btn(row, "LAUNCH SELECTED", _launch, primary=True, w=200)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _extract_port_from_finding(self, finding: dict) -> "int | None":
        """Try to figure out which TCP port the finding refers to.

        Search order (first hit wins):
          0.  Explicit ``finding["port"]`` field — set by parsers that
              already know the port (nmap, banner detection, …).
              Highest priority because it's authoritative.
          1.  Direct ``host:port`` pair in title or description
              (e.g. ``192.168.176.138:25``).
          2.  Textual "port N" / "on port N" / "(port N)" / "RPORT N"
              references in title or description.
          3.  ``Script: <name>`` field with a known NSE prefix
              (``smtp-vuln-...`` → 25, ``http-vuln-...`` → 80, …).
          4.  ``via CONNECT / <SVC>`` source token (``via CONNECT / SMB``
              → 445).

        Returns ``None`` when nothing matches — the caller leaves
        RPORT alone (MSF uses the module's own default).
        """
        if not finding:
            return None
        import re as _re

        # 0. Explicit port hint stored on the finding dict.  Authoritative.
        explicit = finding.get("port")
        if isinstance(explicit, int) and 1 <= explicit <= 65535:
            return explicit
        if isinstance(explicit, str) and explicit.isdigit():
            try:
                p = int(explicit)
                if 1 <= p <= 65535:
                    return p
            except ValueError:
                pass

        text = (str(finding.get("title", "")) + " " +
                str(finding.get("description", "")) + " " +
                str(finding.get("source", "")))

        # 1. Direct host:port reference.  Accept both IP and hostname,
        # require the port to be a valid TCP range to avoid matching
        # things like ``CVE-2010-4344`` (the year would be too large).
        for m in _re.finditer(
                r"\b(?:\d+\.\d+\.\d+\.\d+|[A-Za-z][\w.-]+)[:](\d{1,5})\b",
                text):
            try:
                p = int(m.group(1))
                if 1 <= p <= 65535:
                    return p
            except ValueError:
                continue

        # 2. Textual port references — "port 8180" / "(port 8180)" /
        # "on port 8180" / "RPORT 8180" / "port: 8180".  Catches the
        # common HAWK auto-finding wording where the port appears in
        # natural language without a colon-separated host:port.
        for pat in (r"\bRPORT[\s=:]+(\d{1,5})\b",
                    r"\b(?:on|at|via)\s+port[:\s]+(\d{1,5})\b",
                    r"\(\s*port[:\s]+(\d{1,5})\s*\)",
                    r"\bport[:\s]+(\d{1,5})\b"):
            for m in _re.finditer(pat, text, _re.IGNORECASE):
                try:
                    p = int(m.group(1))
                    # Sanity floor — common false-match would be small
                    # numbers in version strings ("Apache 2.2 port 80"
                    # is fine, "PHP 5.2.4-2ubuntu5 port 4" should be
                    # rejected).  We accept 1-65535 since version
                    # numbers like 5.2.4 don't have a leading "port"
                    # word and won't match the regex anyway.
                    if 1 <= p <= 65535:
                        return p
                except ValueError:
                    continue

        # 3. NSE script name → default port via prefix match
        sm = _re.search(r"[Ss]cript:\s*([\w-]+)", text)
        if sm:
            script = sm.group(1).lower()
            # Try longest prefix first so "ms-wbt-" wins over "ms-"
            for prefix in sorted(self._NSE_PREFIX_TO_PORT.keys(),
                                  key=len, reverse=True):
                if script.startswith(prefix):
                    return self._NSE_PREFIX_TO_PORT[prefix]

        # 4. "via CONNECT / SVC" or "source = SVC" hint
        for pat in (r"via\s+CONNECT\s*/\s*(\w+)",
                    r"source[: ]+CONNECT\s*/\s*(\w+)",
                    r"\bvia\s+(\w+)\b"):
            cm = _re.search(pat, text, _re.IGNORECASE)
            if cm:
                svc = cm.group(1).lower()
                if svc in self._SVC_TOKEN_TO_PORT:
                    return self._SVC_TOKEN_TO_PORT[svc]

        return None

    def _show_msf_launch_dialog(self, exploit_module: str, finding: dict):
        """Pre-configured MSF dialog with all fields editable.

        Module classification (auxiliary / DoS / exploit) and payload
        selection both consult the MSF index when available — so the
        dialog can pick a Java payload for ``java_rmi_server``, a
        ``cmd/unix`` payload for TWiki/Samba/distcc, and skip
        Payload/LHOST/LPORT entirely for any ``auxiliary/...`` module.

        Falls back to a path-based heuristic when the index isn't ready
        yet (background build still running on first HAWK launch).
        """
        from utils.runner import lhost_detect, find_free_port
        target     = self.app.get_target() or ""
        lhost      = lhost_detect()
        free_port  = find_free_port(4444)

        # ── Module classification ─────────────────────────────────────────
        # Path-based heuristic (always applies — covers DoS detection
        # which the index doesn't separately flag).
        mod_low = (exploit_module or "").lower()
        is_scanner = ("auxiliary/scanner/" in mod_low or
                      "auxiliary/admin/"   in mod_low or
                      "auxiliary/gather/"  in mod_low)
        is_dos     = "auxiliary/dos/" in mod_low

        # MSF-index lookup — gives the authoritative module_type
        # ("auxiliary", "post", "exploit", …) and a suggested payload
        # picked from `DefaultOptions => PAYLOAD` or platform/arch
        # inference.  Returns None when the index hasn't finished its
        # first-launch build yet — we then fall back to the path
        # heuristic + OS fingerprint, which is what HAWK did before.
        meta = None
        try:
            from utils import msf_index
            meta = msf_index.lookup_module(exploit_module)
        except Exception as _ie:
            print(f"[HAWK] msf_index lookup_module failed: {_ie}")
            meta = None

        if meta is not None:
            module_type = meta.get("module_type", "")
            # Auxiliary / post / encoder / nop / payload / evasion → no
            # payload, no LHOST, no LPORT.  This is the structural answer
            # to the "Invalid LPORT '' — exploit aborted" bug.
            is_payload_free = (
                module_type != "exploit"
                or not meta.get("needs_lhost_lport", True)
                or is_scanner or is_dos
            )
            # Suggested payload from the index — already incorporates
            # DefaultOptions when declared, otherwise inferred from
            # platform+arch (java/php/cmd/unix/linux x64/windows x64…).
            payload = meta.get("suggested_payload", "")

            # Multi-platform exploits → at index level we default to
            # linux/x64 because the index has no target context.  The
            # dialog DOES — refine using the target OS fingerprint.
            plats = [p.lower() for p in (meta.get("platforms") or [])]
            if "multi" in plats and self._fp and self._fp.platform:
                tp = self._fp.platform.lower()
                if "windows" in tp or tp == "win":
                    payload = "windows/x64/meterpreter/reverse_tcp"
                elif "linux" in tp:
                    payload = "linux/x64/meterpreter/reverse_tcp"
                # other OSes (BSD, OSX) — keep the index suggestion
        else:
            # Index not ready or module unknown — keep the previous
            # heuristic as the safety net.  Treat ANY auxiliary/post module
            # as payload-free too (not just scanner/dos): during the brief
            # first-launch index build a generic auxiliary/server or
            # auxiliary/sqli would otherwise be treated as a payload-bearing
            # exploit and emit `set PAYLOAD; exploit` → MSF "Unknown
            # datastore option PAYLOAD".
            is_payload_free = (
                is_scanner or is_dos
                or mod_low.startswith(("auxiliary/", "post/")))
            fp = self._fp
            if fp and fp.platform == "windows":
                payload = "windows/x64/meterpreter/reverse_tcp"
            elif fp and fp.platform == "linux":
                payload = "linux/x64/meterpreter/reverse_tcp"
            else:
                payload = "windows/x64/meterpreter/reverse_tcp"

        # Empty-payload safety net — if everything fell through (rare:
        # exotic platform, no fingerprint, index empty) we still need
        # SOMETHING in the field so the user can edit instead of seeing
        # a blank.  Linux x64 reverse_tcp is the most common default.
        if not is_payload_free and not payload:
            payload = "linux/x64/meterpreter/reverse_tcp"

        from gui.dialogs import _make_win, _safe_destroy
        dlg_h = 400 if is_payload_free else 520
        win = _make_win(self, "MSF — Ready to Launch", 620, dlg_h)

        ctk.CTkLabel(win, text="METASPLOIT  —  Ready to Launch",
                     font=_f("xl", True),
                     text_color=COLORS["text_bright"]).pack(pady=(14,6))
        ctk.CTkLabel(win, text=f"  Vulnerability: {finding['title']}",
                     font=_f("md"), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=24, pady=(0,8))

        # Classification badge — tells the user at-a-glance that this
        # module won't spawn a session.  Prevents the "why did nothing
        # happen?" follow-up after a scanner run.
        if is_scanner:
            ctk.CTkLabel(
                win,
                text=("  ⓘ  This is a SCANNER/AUXILIARY module — it "
                      "reports findings but does NOT open a session."),
                font=_f("sm"), text_color=COLORS["text_cyan"],
                anchor="w", wraplength=560,
            ).pack(fill="x", padx=24, pady=(0, 8))
        elif is_dos:
            ctk.CTkLabel(
                win,
                text=("  ⚠  This is a DoS module — running it will "
                      "likely CRASH the target service (or BSOD the "
                      "host).  Only use on targets you have permission "
                      "to take offline."),
                font=_f("sm"), text_color=COLORS["text_yellow"],
                anchor="w", wraplength=560,
            ).pack(fill="x", padx=24, pady=(0, 8))

        fields = {}
        # Build the field list conditionally: scanners / DoS only need
        # RHOSTS; full exploits need the whole PAYLOAD/LHOST/LPORT set.
        if is_payload_free:
            field_defs = [
                ("Exploit",  exploit_module),
                ("RHOSTS",   target),
            ]
        else:
            field_defs = [
                ("Exploit",  exploit_module),
                ("Payload",  payload),
                ("RHOSTS",   target),
                ("LHOST",    lhost),
                ("LPORT",    str(free_port)),
            ]

        for label, default in field_defs:
            row = ctk.CTkFrame(win, fg_color="transparent")
            row.pack(fill="x", padx=24, pady=3)
            ctk.CTkLabel(row, text=f"{label}:",
                         font=_f("md", True), text_color=COLORS["text_dim"],
                         width=80, anchor="w").pack(side="left")
            var = ctk.StringVar(value=default)
            entry_kw = dict(
                font=_f("md"), height=30,
                fg_color=COLORS["bg_card"],
                text_color=COLORS["text_bright"],
                border_color=COLORS["border_green"], border_width=1,
                corner_radius=3)
            if label == "Payload":
                entry_kw["placeholder_text"] = "leave blank → MSF auto-picks"
            ctk.CTkEntry(row, textvariable=var,
                         **entry_kw).pack(side="left", fill="x", expand=True, padx=(8,0))
            fields[label] = var

        # Extra options — pre-fill `set RPORT N` when the finding gives
        # us a port hint AND the module is an auxiliary scanner/DoS that
        # actually has an RPORT option (most do).  Saves the user a step
        # on the typical workflow: "click an SMTP/SMB-specific finding →
        # MSF dialog already targets the right port".
        rport_hint = self._extract_port_from_finding(finding)
        extra_default = ""
        is_rport_eligible = is_payload_free and rport_hint and (
            "/scanner/" in mod_low
            or "/admin/" in mod_low
            or "/dos/" in mod_low
        )
        if is_rport_eligible:
            extra_default = f"set RPORT {rport_hint}"
        ctk.CTkLabel(win, text="Extra MSF options (optional):",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=24, pady=(8,2))
        if extra_default:
            ctk.CTkLabel(
                win,
                text=(f"  💡  Pre-filled `set RPORT {rport_hint}` "
                      f"based on the finding — edit if wrong"),
                font=_f("xs"), text_color=COLORS["text_cyan"],
                anchor="w").pack(fill="x", padx=24, pady=(0, 2))
        extra_var = ctk.StringVar(value=extra_default)
        ctk.CTkEntry(win, textvariable=extra_var,
                     placeholder_text="e.g. set VERBOSE true",
                     font=_f("md"), height=30,
                     fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
                     border_color=COLORS["border_dim"], border_width=1,
                     corner_radius=3).pack(fill="x", padx=24, pady=(0,8))

        # Preview
        preview_var = ctk.StringVar()
        def _update_preview(*_):
            lines = [f"use {fields['Exploit'].get()}"]
            if not is_payload_free and fields['Payload'].get().strip():
                lines.append(f"set PAYLOAD {fields['Payload'].get().strip()}")
            # Set BOTH RHOSTS and RHOST so older single-target modules
            # (auxiliary/dos/http/slowloris, some legacy scanners) that
            # only declare `RHOST` (singular) get their option populated.
            # MSF prints a benign `[!] Unknown datastore option` warning
            # for whichever variant the module doesn't use — cosmetic.
            _rhost_val = fields['RHOSTS'].get()
            lines.append(f"set RHOSTS {_rhost_val}")
            lines.append(f"set RHOST {_rhost_val}")
            if not is_payload_free:
                lines.append(f"set LHOST {fields['LHOST'].get()}")
                lines.append(f"set LPORT {fields['LPORT'].get()}")
            if extra_var.get().strip():
                lines.append(extra_var.get().strip())
            # Scanners and auxiliary use `run`; exploits use `exploit`.
            # MSF accepts both everywhere but this matches idiomatic
            # output and doesn't confuse scanners that don't have an
            # `exploit` alias.
            lines.append("run" if is_payload_free else "exploit")
            preview_var.set("\n".join(lines))
        for v in list(fields.values()) + [extra_var]:
            v.trace_add("write", _update_preview)
        _update_preview()

        preview_box = ctk.CTkTextbox(
            win, height=120, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_cyan"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3)
        preview_box.pack(fill="x", padx=24, pady=(0,8))

        def _refresh_preview(*_):
            preview_box.configure(state="normal")
            preview_box.delete("1.0", "end")
            preview_box.insert("1.0", preview_var.get())
            preview_box.configure(state="disabled")
        preview_var.trace_add("write", lambda *_: self.after(0, _refresh_preview))
        _refresh_preview()

        def _launch():
            commands = [f"use {fields['Exploit'].get()}"]
            if not is_payload_free and fields['Payload'].get().strip():
                commands.append(f"set PAYLOAD {fields['Payload'].get().strip()}")
            # Mirror the preview generator: set both RHOSTS and RHOST so
            # legacy single-target modules (slowloris DoS, etc.) get
            # populated regardless of which option name they declare.
            _rhost_val = fields['RHOSTS'].get()
            commands.append(f"set RHOSTS {_rhost_val}")
            commands.append(f"set RHOST {_rhost_val}")
            if not is_payload_free:
                commands.append(f"set LHOST {fields['LHOST'].get()}")
                commands.append(f"set LPORT {fields['LPORT'].get()}")
            if extra_var.get().strip():
                commands.append(extra_var.get().strip())
            commands.append("run" if is_payload_free else "exploit")
            _safe_destroy(win)
            self._launch_msf_from_intel(
                commands,
                fields['RHOSTS'].get(),
                fields['LHOST'].get() if not is_payload_free else "",
                fields['LPORT'].get() if not is_payload_free else "")

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(pady=8)
        ctk.CTkButton(btn_row, text="▶ LAUNCH IN XTERM",
                      width=160, height=34, font=_f("md", True),
                      fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
                      border_color=COLORS["border_green"], border_width=1,
                      text_color=COLORS["text_green"], corner_radius=4,
                      command=_launch).pack(side="left", padx=8)
        ctk.CTkButton(btn_row, text="CANCEL",
                      width=100, height=34, font=_f("md"),
                      fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
                      border_color=COLORS["border_dim"], border_width=1,
                      text_color=COLORS["text_dim"], corner_radius=4,
                      command=lambda: _safe_destroy(win)).pack(side="left", padx=8)

    def _launch_msf_from_intel(self, commands, target, lhost, lport):
        from utils.runner import MetasploitRunner, is_port_free, find_free_port
        # LPORT verification — LhostDialog already blocks busy ports, but a
        # port can be grabbed between confirmation and launch. If it happens
        # ABORT instead of silently switching (the user might expect a
        # specific LPORT for firewall/NAT rules).
        #
        # Skip the check entirely when ``lport`` is empty — that's the
        # signal from the launch dialog that this is an auxiliary /
        # payload-free module which doesn't take LPORT at all.  The
        # previous "Invalid LPORT '' — exploit aborted" error broke every
        # auxiliary-scanner run launched from Target Intel.
        if lport != "":
            try:
                port_int = int(lport)
                if not is_port_free(port_int):
                    suggested = find_free_port(port_int + 1)
                    self.app.terminal.write(
                        f"  [!] LPORT {lport} became busy right before launch.\n"
                        f"      Exploit aborted to avoid 'Handler failed to bind'.\n"
                        f"      Re-run with LPORT {suggested} (or another free port).",
                        "error")
                    return
            except ValueError:
                self.app.terminal.write(
                    f"  [!] Invalid LPORT '{lport}' — exploit aborted.", "error")
                return

        # Extract the MSF module path so the pre-flight check can route
        # to the right test (SMBv1 probe, signing check, …).
        exploit_name = ""
        for c in commands:
            cl = c.strip().lower()
            if cl.startswith("use exploit/") or cl.startswith("use auxiliary/"):
                exploit_name = c.split(None, 1)[-1].strip()
                break

        def _actually_launch():
            self.app.terminal.section("MSF EXPLOIT  ·  From Target Intel")
            for c in commands:
                self.app.terminal.write(f"  msf> {c}", "cmd")

            def _shell(t):
                self.app.terminal.write(
                    "  │  SHELL OBTAINED — Check the xterm window!  🦅", "finding")

            MetasploitRunner(
                output_callback=self.app.terminal.output_callback,
                done_callback=lambda n, rc, log:
                    self.app.terminal.write(f"  [+] MSF done.", "success"),
                shell_callback=_shell,
            ).run(commands, target, lhost, lport)

        self.preflight_exploit_launch(exploit_name, target,
                                       on_continue=_actually_launch)

    def preflight_exploit_launch(self, exploit_name: str, target: str,
                                  on_continue, on_cancel=None):
        """Run a pre-flight sanity check before launching an MSF exploit.

        `exploit_name` is the full module path (``exploit/windows/smb/ms17_010_eternalblue``)
        or any string that still contains a recognisable family marker.
        `target`       is the RHOSTS IP we are about to attack.
        `on_continue`  is invoked (UI thread) when the checks pass OR the
                       user clicks RUN ANYWAY.
        `on_cancel`    is invoked (UI thread) if the user aborts — optional.

        All checks are non-blocking: if a family isn't covered, or the probe
        can't run (nmap missing, target unreachable, etc.) we fall through
        to `on_continue` so we never silently block a legitimate exploit.
        """
        name_low = (exploit_name or "").lower()
        check_id = None
        for marker, cid in self._PREFLIGHT_FAMILIES.items():
            if marker in name_low:
                check_id = cid
                break

        if not check_id:
            # Nothing to verify — proceed.
            on_continue()
            return

        if check_id == "smb_signing_off":
            self._preflight_smb_signing(target, exploit_name,
                                         on_continue, on_cancel)
            return

        if check_id == "smbv1":
            self._preflight_smbv1(target, exploit_name,
                                   on_continue, on_cancel)
            return

        # Unknown check id → don't block.
        on_continue()

    def _preflight_smb_signing(self, target, exploit_name,
                                on_continue, on_cancel):
        """SMB relay modules need signing NOT required on the target.
        We already harvested `smb_signing` from smb2-security-mode /
        smb-security-mode into `self._fp`, so this check is instant."""
        signing = (getattr(self._fp, "smb_signing", "") or "").lower()
        if signing == "required":
            self._show_preflight_dialog(
                title="SMB Signing is REQUIRED",
                subtitle=f"Target {target} enforces SMB message signing.",
                reason=(
                    "SMB signing is ENABLED AND REQUIRED on the target.\n\n"
                    "NTLM relay attacks (smb_relay, ntlmrelayx) cannot work\n"
                    "against a target that enforces signing — the relayed\n"
                    "session will be rejected with STATUS_ACCESS_DENIED.\n\n"
                    "This is a hard protocol-level protection, not a\n"
                    "timeout or a rate limit: RUN ANYWAY will not succeed."
                ),
                exploit_name=exploit_name,
                on_continue=on_continue, on_cancel=on_cancel,
                terminal_quick_line=(
                    "  [!] SMB signing is REQUIRED on target — relay will fail"),
            )
            return
        # "supported" (signing enabled but not required) or "disabled" or unknown
        on_continue()

    def _preflight_smbv1(self, target, exploit_name,
                         on_continue, on_cancel):
        """MS17-010 family needs SMBv1 reachable. Run a fast nmap
        --script smb-protocols probe (cached per target)."""
        cached = self._preflight_cache.get(target)
        if cached and (time.time() - cached.get("ts", 0)) < 600:
            # Cache hit (<10 min) — use stored dialect list.
            self._evaluate_smbv1(cached["dialects"], target, exploit_name,
                                 on_continue, on_cancel, from_cache=True)
            return

        self.app.terminal.write(
            f"  [*] Pre-flight: probing SMB dialects on {target}:445 "
            f"(nmap --script smb-protocols, ~5s)…", "info")

        def _worker():
            import subprocess
            dialects = []
            err = None
            try:
                r = subprocess.run(
                    ["nmap", "-Pn", "-p", "445",
                     "--script", "smb-protocols",
                     "-T4", "--max-retries", "1",
                     "--host-timeout", "25s", target],
                    capture_output=True, text=True, timeout=30)
                out = (r.stdout or "") + (r.stderr or "")
                for line in out.splitlines():
                    l = line.strip().lower()
                    # Lines look like:   |     NT LM 0.12 (SMBv1) [dangerous, but default]
                    #                    |     2.0.2
                    #                    |     2.1
                    #                    |     3.0
                    #                    |     3.0.2
                    #                    |     3.1.1
                    if "nt lm 0.12" in l or "smbv1" in l:
                        dialects.append("SMBv1")
                    else:
                        import re as _re
                        m = _re.match(r'^\|?\s*_?\s*(\d\.\d(?:\.\d)?)\s*$', l)
                        if m:
                            dialects.append(f"SMBv{m.group(1)}")
            except FileNotFoundError:
                err = "nmap not installed"
            except subprocess.TimeoutExpired:
                err = "nmap probe timed out"
            except Exception as e:
                err = str(e)

            # Dedup preserving order
            seen = set(); ordered = []
            for d in dialects:
                if d not in seen:
                    seen.add(d); ordered.append(d)
            dialects = ordered

            self._preflight_cache[target] = {
                "dialects": dialects, "ts": time.time(), "err": err,
            }

            def _ui():
                if err and not dialects:
                    # Probe didn't conclude — warn but don't block.
                    self.app.terminal.write(
                        f"  [?] SMB probe inconclusive ({err}) — "
                        f"proceeding without pre-flight.", "warn")
                    on_continue()
                    return
                self._evaluate_smbv1(dialects, target, exploit_name,
                                     on_continue, on_cancel)
            self.after(0, _ui)

        threading.Thread(target=_worker, daemon=True).start()

    def _evaluate_smbv1(self, dialects, target, exploit_name,
                         on_continue, on_cancel, from_cache=False):
        has_v1 = "SMBv1" in dialects
        tag = "(cached)" if from_cache else ""
        if has_v1:
            self.app.terminal.write(
                f"  [✓] SMBv1 available on {target} "
                f"— exploit can proceed {tag}".rstrip(), "success")
            on_continue()
            return
        if not dialects:
            # Probe reached the host but couldn't parse a dialect list.
            # Possible on 445-filtered hosts. Surface it but let the user
            # decide.
            self._show_preflight_dialog(
                title="SMB dialects: inconclusive",
                subtitle=f"No SMB dialects parsed from target {target}.",
                reason=(
                    "nmap --script smb-protocols returned but HAWK could\n"
                    "not extract a dialect list. Common causes:\n"
                    "  • Port 445 is filtered by a host firewall.\n"
                    "  • The SMB service refused the probe (rate limit).\n"
                    "  • NSE script error on this nmap build.\n\n"
                    "If SMBv1 is not actually exposed, this exploit will\n"
                    "hang for ~10s and return Rex::ConnectionTimeout.\n\n"
                    "You can RUN ANYWAY, but expect the same error you saw\n"
                    "before if SMBv1 really is off."
                ),
                exploit_name=exploit_name,
                on_continue=on_continue, on_cancel=on_cancel,
                terminal_quick_line=(
                    "  [?] SMB dialect probe inconclusive — user prompted"),
            )
            return
        # Dialects found but no SMBv1 → hard-fail scenario (the exact
        # situation that produced the user's 'Rex::ConnectionTimeout').
        self._show_preflight_dialog(
            title="SMBv1 is NOT exposed",
            subtitle=f"Target {target} supports: {', '.join(dialects)}",
            reason=(
                "The MS17-010 exploit family (EternalBlue, EternalRomance,\n"
                "EternalSynergy, EternalChampion, DoublePulsar) speaks only\n"
                "the SMBv1 dialect (NT LM 0.12).\n\n"
                f"This target advertises only: {', '.join(dialects)}\n\n"
                "Launching the exploit will succeed in opening a TCP socket\n"
                "to port 445 — nmap confirms the port is reachable — but\n"
                "the initial SMB1_COM_NEGOTIATE will be silently ignored by\n"
                "the target's SMBv2/3-only stack, producing the classic\n"
                "    Rex::ConnectionTimeout: 192.168.x.y:445 timed out.\n\n"
                "Consider a non-SMBv1 exploit vector instead (CVE-2020-0796\n"
                "SMBGhost on SMBv3.1.1, BlueKeep on RDP, service-level RCEs,\n"
                "or credentialed paths via netexec / evil-winrm)."
            ),
            exploit_name=exploit_name,
            on_continue=on_continue, on_cancel=on_cancel,
            terminal_quick_line=(
                f"  [!] Target has no SMBv1 ({', '.join(dialects)}) — "
                f"EternalBlue family will timeout"),
        )

    def _show_preflight_dialog(self, *, title, subtitle, reason,
                                exploit_name, on_continue, on_cancel,
                                terminal_quick_line=""):
        from gui.dialogs import (_make_win, _note_box, _btn_row, _btn,
                                  _safe_destroy)
        if terminal_quick_line:
            self.app.terminal.write(terminal_quick_line, "warn")
        win = _make_win(self, f"Pre-flight: {title}", 620, 460)
        ctk.CTkLabel(win, text=f"⚠  {title}",
                     font=_f("xl", True),
                     text_color=COLORS["text_yellow"]).pack(pady=(14, 4))
        ctk.CTkLabel(win, text=subtitle,
                     font=_f("md", True),
                     text_color=COLORS["text_bright"]).pack(pady=(0, 6))
        if exploit_name:
            ctk.CTkLabel(win, text=f"Module: {exploit_name}",
                         font=_f("sm"),
                         text_color=COLORS["text_dim"]).pack(pady=(0, 6))
        _note_box(win, reason, COLORS["text_yellow"])
        row = _btn_row(win)

        def _cancel():
            _safe_destroy(win)
            self.app.terminal.write(
                "  [·] Exploit launch cancelled by pre-flight check.", "dim")
            if on_cancel:
                on_cancel()
        def _override():
            _safe_destroy(win)
            self.app.terminal.write(
                "  [·] Pre-flight warning overridden — launching anyway.",
                "warn")
            on_continue()

        _btn(row, "CANCEL", _cancel, primary=True, w=140)
        _btn(row, "RUN ANYWAY", _override, warn=True, w=160)

