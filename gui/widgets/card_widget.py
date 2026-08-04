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
import time
import subprocess
import threading

from utils.config import (
    COLORS, STATUS_READY, STATUS_RUNNING, STATUS_DONE, STATUS_ERROR, SZ,
    CACHE_DIR, TMP_DIR,
)
from utils.runner import ToolRunner, MultiRunner, MetasploitRunner, GreenBoneRunner
from utils.session import Credential
from gui.widgets.card_common import (
    STATUS_STYLE, TOOL_STATUS_ICONS, ACCESS_GATED_PHASES, WEB_TOOLS, SMB_TOOLS,
    WINRM_BANNERS, TRUE_HTTP_SERVICES, WORDLIST_DIRS, _f, _shq,
    _find_wordlists, _get_user_wordlists, _get_pass_wordlists,
    _get_dir_wordlists, _get_dns_wordlists, add_context_menu,
    apply_context_menus_recursive,
)
from gui.widgets.card_routes import CardRoutesMixin
from gui.widgets.card_ad_routes import CardADRoutesMixin
from gui.widgets.card_intel_parsers import CardIntelParserMixin
from gui.widgets.card_runtime import CardRuntimeMixin



class KillChainCard(CardRoutesMixin, CardADRoutesMixin, CardIntelParserMixin, CardRuntimeMixin, ctk.CTkFrame):

    def __init__(self, parent, phase_config: dict, module, app, **kwargs):
        super().__init__(
            parent,
            fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=4,
            **kwargs)
        self.phase_config  = phase_config
        self.phase_id      = phase_config["id"]
        self.module        = module
        self.app           = app
        self._status       = STATUS_READY
        self._expanded     = True
        self._tool_runners = {}
        self._tool_widgets = {}
        self._multi_runner = None
        self._raw_log      = []
        # Blink-alert state — set by _notify_activity() when a tool
        # inside this card finishes WHILE the card is collapsed.  Two
        # flavours: yellow for plain "new activity" (tool completed
        # OK), red for "attention needed" (tool errored).  Red wins
        # over yellow.  `_blink_job` holds the after() handle so we
        # can cancel it when the card is expanded again.
        self._blink_state  = None    # None | "activity" | "error"
        self._blink_phase  = 0       # toggle counter for the border
        self._blink_job    = None    # after() handle
        self._build_ui()
        self._restore_collapse_state()

    # ─── Service detection ────────────────────────────────────────────────────

    def _get_fp(self):
        if hasattr(self.app, "target_intel") and self.app.target_intel._fp:
            return self.app.target_intel._fp
        return None

    def _find_service(self, *service_keys) -> tuple:
        fp = self._get_fp()
        if not fp:
            return None, None
        SERVICE_MAP = {
            "http":    ["http","tomcat","jenkins","glassfish","jboss",
                        "weblogic","apache","nginx","iis","lighttpd","httpd"],
            "https":   ["https","ssl/http","https-alt"],
            "ftp":     ["ftp","vsftpd","proftpd","filezilla"],
            "ssh":     ["ssh","openssh"],
            "smb":     ["microsoft-ds","netbios-ssn","smb","netbios",
                        "cifs","samba"],
            "mssql":   ["ms-sql","mssql","microsoft sql"],
            "mysql":   ["mysql"],
            "rdp":     ["ms-wbt-server","rdp","remote desktop"],
            "smtp":    ["smtp","postfix","sendmail","exchange"],
            "winrm":   ["wsman","winrm","httpapi","microsoft-httpapi"],
            "snmp":    ["snmp"],
            "ldap":    ["ldap"],
            "vnc":     ["vnc"],
        }
        # Ports that speak HTTP-ish but are NOT browsable web servers.
        # Excluded from http/https matching so gobuster/ffuf/nikto/wafw00f
        # don't hammer WinRM (5985/5986), RPC-over-HTTP (593), or RPC
        # endpoint mapper (135).
        NON_WEB_HTTP_PORTS = {135, 593, 5985, 5986}
        for port, proto, svc, banner in fp.open_ports:
            svc_low = (svc + " " + (banner or "")).lower()
            for key in service_keys:
                if key in ("http", "https"):
                    # Block known non-web ports even if labelled http
                    if port in NON_WEB_HTTP_PORTS:
                        continue
                    # Use whitelist — only real web servers
                    if any(t == svc.lower().split("/")[0] or t in svc_low
                           for t in TRUE_HTTP_SERVICES):
                        # Extra check: exclude known non-web services
                        if not any(b in svc_low for b in WINRM_BANNERS):
                            return port, banner
                else:
                    patterns = SERVICE_MAP.get(key, [key])
                    if any(p in svc_low for p in patterns):
                        return port, banner
        return None, None

    def _require_service(self, tool_name: str, *service_keys) -> tuple:
        fp = self._get_fp()
        if fp is None:
            self.app.terminal.write(
                f"[!] {tool_name} skipped — no port scan data available.\n"
                f"    Run Port Scanning first.", "warn")
            return None, None
        port, banner = self._find_service(*service_keys)
        if port is None:
            svc_list = " / ".join(service_keys).upper()
            self.app.terminal.write(
                f"[!] {tool_name} skipped — "
                f"{svc_list} not detected on target.\n"
                f"    Run Port Scanning first.", "warn")
        return port, banner

    # ─── Build UI ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self._build_header()
        self._build_content()

    def _build_header(self):
        """Header = toggle button (LEFT) + phase index + phase name +
        status badge (RIGHT).

        RUN ALL / STOP buttons were removed: in practice running every
        tool of a phase concurrently against the same target is noisy,
        racy (hydra + nmap + sqlmap all hitting the same HTTP port
        simultaneously), and the individual per-tool RUN buttons
        already give the user full control.  The bookkeeping methods
        (_run_all / _stop_all / _do_run_all / _on_run_all_done) are
        gone too — dead code.

        Uses PACK geometry (not grid) because CTkFrame + grid +
        grid_propagate(False) had a rendering bug where children
        landed at y=80 (outside the visible 48-px header).  Pack
        dodges the CTk canvas wrapping that causes grid to
        miscalculate child positions.
        """
        self._header_frame = ctk.CTkFrame(
            self, fg_color=COLORS["bg_header"],
            height=52, corner_radius=3)
        self._header_frame.grid(row=0, column=0,
                                 sticky="ew", padx=1, pady=(1, 0))
        # pack_propagate(False) keeps the header a fixed 52 px tall
        # even when every child is smaller — otherwise pack shrinks
        # the frame to the tallest child and the row height jumps
        # around as status badges transition.
        self._header_frame.pack_propagate(False)

        phase = self.phase_config
        color = phase["color"]

        # ── LEFT: big, phase-coloured toggle button ───────────────
        # Previously a 28×26 transparent chevron at the far right —
        # users reported it as invisible / unclickable.  Now 44×40,
        # bordered in the phase colour, first thing on the card.
        self._toggle_btn = ctk.CTkButton(
            self._header_frame, text="▼", width=44, height=40,
            font=_f("xxl", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=color, border_width=1,
            text_color=color, corner_radius=4,
            command=self._toggle_expand)
        self._toggle_btn.pack(side="left", padx=(8, 6), pady=6)

        # ── LEFT: phase index badge ["01"] ────────────────────────
        ctk.CTkLabel(
            self._header_frame, text=f" {phase['icon']} ",
            font=_f("lg", True), text_color=color,
            fg_color=COLORS["bg_card"], corner_radius=3,
            width=42,
        ).pack(side="left", padx=(0, 4), pady=10)

        # ── LEFT: phase name "RECONNAISSANCE" ─────────────────────
        ctk.CTkLabel(
            self._header_frame, text=phase["name"],
            font=_f("xl", True), text_color=color,
            anchor="w",
        ).pack(side="left", padx=4, pady=10)

        # Status badge (READY / RUNNING / DONE / ERROR) removed —
        # kept the card header minimal per user request.  The per-
        # phase state is still persisted to the session and echoed
        # in the bottom status bar via set_status(), so external
        # consumers (status bar, saved sessions, report generator)
        # are unaffected.

    def _build_content(self):
        self._content_frame = ctk.CTkFrame(
            self, fg_color=COLORS["bg_card"], corner_radius=0)
        self._content_frame.grid(row=1, column=0, sticky="ew", padx=1, pady=(0,1))
        self._content_frame.grid_columnconfigure(0, weight=1)

        # Phase description — kept visible but dimmed to the same
        # weight as the per-tool brief lines below.  Was bold + UPPER
        # which made it shout vs the rest of the card text (notably
        # noticeable on WEB ASSAULT where the desc is long).
        ctk.CTkLabel(self._content_frame,
                     text=f"  {self.phase_config['desc']}",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").grid(row=0, column=0, sticky="ew", padx=10, pady=(7,2))

        note = self.phase_config.get("network_note")
        if note:
            short = note.split(".")[0] + "."
            ctk.CTkLabel(self._content_frame,
                         text=f"  ⚠  {short}",
                         font=_f("sm"), text_color=COLORS["text_muted"],
                         anchor="w").grid(row=1, column=0, sticky="ew", padx=10, pady=(0,2))

        # WEB ASSAULT pipeline bar — observes AssaultState and shows
        # per-step status icons.  Read-only: it does not control the
        # workers, just visualizes them.  No-op for other phases.
        if self.phase_id == "web_assault":
            self._build_pipeline_bar(row_index=2)
            sep_row = 3
        else:
            sep_row = 2

        ctk.CTkFrame(self._content_frame, height=1,
                     fg_color=COLORS["border_dim"]).grid(
            row=sep_row, column=0, sticky="ew", padx=10, pady=(0,4))

        tools = self.module.get_tools()
        if not tools:
            self._build_report_content()
            return

        from modules.base import TOOL_BRIEFS, TOOL_ID_BRIEFS

        # ── OS-grouped rendering ──────────────────────────────────────────
        # When a phase mixes Linux and Windows tools (post_exploit, lateral)
        # we split them into visual sections with collapsible headers so
        # the user can focus on the OS they're actually targeting.
        # Phases with only "any" tools fall through to the classic flat list.
        has_os_groups = any(
            getattr(t, "os_hint", "any") != "any" for t in tools)

        if has_os_groups:
            self._build_os_grouped_tools(tools, TOOL_BRIEFS)
            return

        # ── Classic flat list (all phases except post_exploit / lateral) ──
        # Track shown briefs by a key that's normally the binary, but
        # the per-tool ID when an override exists in TOOL_ID_BRIEFS.
        # Without this, two tools sharing a binary (e.g. injection_tester
        # and bloody_crawl both use curl) would only get one header,
        # and tools whose binary has no brief (jwt_analyzer → python3)
        # would never get one at all.
        seen_briefs = set()
        # Tool rows start AFTER the description / pipeline bar / separator.
        # web_assault inserts the pipeline bar at row 2, pushing the
        # separator to row 3 and the first tool to row 4.
        grid_row = (4 if self.phase_id == "web_assault" else 3)
        for tool in tools:
            # Per-tool brief takes precedence; fall back to per-binary.
            tool_brief = TOOL_ID_BRIEFS.get(tool.id)
            if tool_brief:
                brief_key = f"id:{tool.id}"
                brief     = tool_brief
            else:
                brief_key = f"bin:{tool.binary}"
                brief     = TOOL_BRIEFS.get(tool.binary, "")
            if brief and brief_key not in seen_briefs:
                seen_briefs.add(brief_key)
                hdr_fr = ctk.CTkFrame(
                    self._content_frame,
                    fg_color="transparent", height=20)
                hdr_fr.grid(row=grid_row, column=0, sticky="ew",
                            padx=14, pady=(6, 0))
                hdr_fr.grid_propagate(False)
                ctk.CTkLabel(
                    hdr_fr, text=f"  {brief}",
                    font=_f("xs"),
                    text_color=COLORS["text_muted"],
                    anchor="w",
                ).pack(side="left", fill="x")
                grid_row += 1
            self._build_tool_row(tool, row=grid_row)
            grid_row += 1

    # Tools that use the INSTALL-THEN-USE flow: when the binary isn't on PATH,
    # the row stays clickable so the user can launch the install wizard
    # directly. After install, the same binary check re-enables RUN on the
    # next refresh/click.
    _INSTALL_FIRST_IDS = {
        "rustscan", "nuclei", "greenbone",
        "kerbrute", "kerbrute_userenum",
        # enum4linux-ng is a separate package from the legacy Perl
        # enum4linux — on stock Kali it's usually NOT installed.  Route
        # this one through the install wizard so the user gets the
        # apt/pipx/pip cascade automatically instead of a "binary not
        # found" failure when they click RUN.
        "enum4linux",
    }

    # Long-form explanations shown when the user clicks the ⓘ WHAT IT
    # DOES button next to a tool row.  Reserved for tools complex
    # enough that a one-line desc can't cover them — add new entries
    # sparingly, otherwise the button starts to feel like clutter.
    _TOOL_DETAILED_INFO = {
        "web_oracle": (
            "WHAT IS ORACLE\n"
            "──────────────\n"
            "Oracle is HAWK's webapp-profiling engine.  You point it at\n"
            "a URL; it runs a tiered orchestration of open-source web\n"
            "recon binaries in parallel, parses their outputs into a\n"
            "single structured profile, then derives a prioritised list\n"
            "of next-step recommendations based on what the app looks\n"
            "like.\n"
            "\n"
            "WHAT IT DOES, STEP BY STEP\n"
            "──────────────────────────\n"
            "1.  Detects which binaries are installed (whatweb, httpx,\n"
            "    nuclei, katana, ffuf, curl) — missing ones are skipped\n"
            "    gracefully.\n"
            "2.  Creates a working dir under <HAWK>/outputs/ and fires all of\n"
            "    them in parallel against the target URL, streaming\n"
            "    per-binary output to the HAWK terminal in real time.\n"
            "3.  Parses stdout/JSON from every tool + pulls a few key\n"
            "    files via curl:  /robots.txt,  /sitemap.xml,\n"
            "    /.git/HEAD,  /.env,  /.DS_Store,  /server-status,\n"
            "    /phpinfo.php,  /graphql,  /swagger.json,  /admin,\n"
            "    /wp-login.php  ...\n"
            "4.  Builds a unified profile dict with:\n"
            "       tech stack    (frontend framework / CMS / server /\n"
            "                      JS libraries / meta generator)\n"
            "       auth flow     (form-based / basic / JWT / SAML /\n"
            "                      OIDC  — login path + form fields)\n"
            "       API surface   (REST / GraphQL / SOAP / OpenAPI\n"
            "                      endpoints discovered via crawl)\n"
            "       exposures     (.env, .git, robots Disallow, admin\n"
            "                      panels, swagger leaks, JWT in HTML)\n"
            "       CVEs          (from nuclei tags=cve,exposure,misconfig)\n"
            "       regional flags (SPID, DigID, SAP NetWeaver, Shibboleth,\n"
            "                       Keycloak, iDEAL, GDPR cookie walls,\n"
            "                       enterprise CMS like Typo3/Sitecore)\n"
            "       TLS info      (JARM, cert, CDN)\n"
            "5.  Feeds the profile into a recommendation engine that\n"
            "    outputs concrete actions, each with a severity and a\n"
            "    pointer to the right HAWK tool (or an external command\n"
            "    for tools not integrated into HAWK).\n"
            "\n"
            "WHICH BINARIES IT USES + WHY\n"
            "────────────────────────────\n"
            "  whatweb     — tech fingerprint (plugin signatures,\n"
            "                server banner).  Fast, reliable, always\n"
            "                runs first.\n"
            "  httpx       — headers + TLS + JARM + CDN + tech detect\n"
            "                via JSON output.  Modernisation of nmap's\n"
            "                http-* scripts.\n"
            "  nuclei      — template-based vuln/exposure scanner.\n"
            "                Runs with tags=tech,exposure,default-logins,\n"
            "                misconfig — skips heavy CVE fuzzing to keep\n"
            "                the run under 90 s.\n"
            "  katana      — SPA-aware JS crawler.  Executes client-side\n"
            "                JS to discover React/Vue/Next routes that\n"
            "                classic crawlers (gobuster, ffuf) miss.\n"
            "  ffuf        — optional content discovery against top-1k\n"
            "                paths (only when requested).\n"
            "  curl probes — direct HEAD/GET against the ~15 high-value\n"
            "                paths listed above, collected in parallel\n"
            "                with the other tools.\n"
            "\n"
            "POST-SCAN DIALOG\n"
            "────────────────\n"
            "When the orchestrator finishes (typical run: 45-90 s) it\n"
            "opens a summary dialog with sections:\n"
            "    TECH STACK          (with versions + source binary)\n"
            "    EXPOSURES           (paths + status + severity)\n"
            "    API SURFACE         (REST / GraphQL / SOAP / OpenAPI)\n"
            "    AUTH                (type + login path + fields)\n"
            "    KNOWN CVEs          (from nuclei)\n"
            "    STACK / FEDERATION  (regional / enterprise flags)\n"
            "    RECOMMENDED NEXT STEPS — each with a 'RUN IN HAWK'\n"
            "                           button that opens the matching\n"
            "                           tool dialog pre-filled for this\n"
            "                           target, OR a selectable shell\n"
            "                           command for external tools\n"
            "                           (wpscan, graphw00f, jwt_tool,\n"
            "                           git-dumper, typo3scan, …).\n"
            "\n"
            "NOISE / OPSEC NOTE\n"
            "──────────────────\n"
            "Everything Oracle does is ACTIVE recon — every probe hits\n"
            "the target.  WAFs (Cloudflare, Akamai, Imperva) will see\n"
            "most of it.  nuclei especially sends identifiable probes.\n"
            "The session log will usually show:\n"
            "    ~150-300 HTTP requests  (crawl + probes)\n"
            "    1-3  404 Not Found bursts  (exposure probing)\n"
            "    1    TLS handshake per scheme  (via JARM)\n"
            "If you need stealth, run only whatweb + httpx (skip nuclei\n"
            "and katana) — Oracle still builds a partial profile.\n"
            "\n"
            "WHEN NOT TO USE\n"
            "───────────────\n"
            "  · Target is not HTTP/S  — Oracle is web-only.\n"
            "  · You've already run it and have the profile in Target\n"
            "    Intel — no point re-running unless the app changed.\n"
            "  · WAF is known hostile and you're on stealth rules —\n"
            "    use Burp/Caido passively instead.\n"
            "  · Target is in a CSRF-locked OR SPA shell where katana\n"
            "    can't browse unauth — Oracle will still try and report\n"
            "    what it finds, but the SPA routes won't be there."
        ),
        "bloody_crawl": (
            "WHAT IS BLOODY CRAWL\n"
            "────────────────────\n"
            "Bloody Crawl is HAWK's smart endpoint extractor.  Instead of\n"
            "brute-forcing paths like gobuster/ffuf, it READS the HTML the\n"
            "app actually serves and extracts every link, form action,\n"
            "script source, and JS reference.  Then it probes each one.\n"
            "\n"
            "WHY IS THIS BETTER THAN GOBUSTER?\n"
            "─────────────────────────────────\n"
            "Gobuster guesses paths from a wordlist — it will never find\n"
            "/capture or /data/5 unless those words are in the list.\n"
            "Bloody Crawl reads what the app exposes: <a href=\"/capture\">,\n"
            "<form action=\"/login\">, fetch(\"/api/users\") in JS.\n"
            "It finds the REAL attack surface, not random guesses.\n"
            "\n"
            "WHAT IT DOES, STEP BY STEP\n"
            "──────────────────────────\n"
            "1.  Fetches the target page via curl\n"
            "2.  Extracts all href, action, src, JS patterns\n"
            "3.  Normalizes relative URLs to absolute\n"
            "4.  Probes each endpoint (status code, size, redirect)\n"
            "5.  Follows redirect chains (301/302 → final destination)\n"
            "6.  Detects IDOR patterns (numeric IDs → tries variations)\n"
            "7.  Recurses into found pages (configurable depth)\n"
            "\n"
            "USE BOTH TOOLS TOGETHER\n"
            "───────────────────────\n"
            "  1. Run BLOODY CRAWL first → maps the visible surface\n"
            "  2. Run ORACLE → profiles the tech stack + CVEs\n"
            "  3. Run gobuster/ffuf → finds hidden paths NOT linked\n"
            "This gives you the most complete picture possible."
        ),
    }

    # ── WEB ASSAULT pipeline bar ─────────────────────────────────────
    PIPELINE_STEPS = (
        ("oracle", "ORACLE"),
        ("crawl",  "CRAWL"),
        ("inject", "INJECT"),
        ("jwt",    "JWT"),
    )
    _STEP_ICON = {
        "pending": ("○", "text_muted"),
        "ready":   ("◔", "text_dim"),
        "running": ("◍", "text_yellow"),
        "done":    ("●", "text_green"),
        "error":   ("✗", "text_red"),
        "skipped": ("◌", "text_muted"),
    }

    def _build_pipeline_bar(self, row_index: int):
        """Visual ORACLE → CRAWL → INJECT → JWT progress bar.

        Layout v2:
          • Steps + bigger arrows always visible at any card width.
          • Inline summary (counts) removed — was eating ~60 chars and
            forced the user to widen the card to see anything.
          • A `[ DETAILS ]` button on the right opens a dialog with
            the full counters, per-step state, and a global STOP.

        Read-only observer of `app.assault_state`.
        """
        state = getattr(self.app, "assault_state", None)
        bar = ctk.CTkFrame(
            self._content_frame, fg_color=COLORS["bg_secondary"],
            corner_radius=3, border_color=COLORS["border_dim"],
            border_width=1)
        bar.grid(row=row_index, column=0, sticky="ew",
                 padx=10, pady=(2, 4))
        # Two columns: steps grow on the left, [ DETAILS ] pinned right.
        bar.grid_columnconfigure(0, weight=1)
        steps_fr = ctk.CTkFrame(bar, fg_color="transparent")
        steps_fr.grid(row=0, column=0, sticky="w", padx=8, pady=4)

        ctk.CTkLabel(
            steps_fr, text="PIPELINE:", font=_f("md", True),
            text_color=COLORS["text_cyan"]).pack(side="left", padx=(0, 10))

        step_labels = {}
        for i, (key, label) in enumerate(self.PIPELINE_STEPS):
            if i > 0:
                # Bigger, bolder arrow — was `→` at sm, invisible at
                # default card width.  `➜` is wider and `lg` makes it
                # actually readable.
                ctk.CTkLabel(
                    steps_fr, text="➜", font=_f("lg", True),
                    text_color=COLORS["text_cyan"]
                ).pack(side="left", padx=6)
            row_lbl = ctk.CTkLabel(
                steps_fr, text=f"○ {label}", font=_f("md", True),
                text_color=COLORS["text_muted"])
            row_lbl.pack(side="left")
            step_labels[key] = row_lbl

        details_btn = ctk.CTkButton(
            bar, text="DETAILS", width=86, height=24,
            font=_f("xs", True),
            fg_color=COLORS["bg_secondary"],
            hover_color=COLORS["bg_card_hover"],
            text_color=COLORS["text_cyan"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3,
            command=self._show_pipeline_details)
        details_btn.grid(row=0, column=1, sticky="e", padx=8, pady=4)

        self._pipeline_bar    = bar
        self._pipeline_steps  = step_labels
        self._pipeline_details_btn = details_btn

        def _refresh():
            if state is None:
                return
            steps = state.steps()
            for key, lbl in step_labels.items():
                icon, colorkey = self._STEP_ICON.get(
                    steps.get(key, "pending"),
                    self._STEP_ICON["pending"])
                lbl.configure(
                    text=f"{icon} {dict(self.PIPELINE_STEPS)[key]}",
                    text_color=COLORS.get(colorkey,
                                          COLORS["text_muted"]))

        # Initial paint + subscribe to AssaultState mutations.  The
        # subscriber fires on any thread, so we marshal back to Tk.
        _refresh()
        if state is not None:
            state.subscribe(lambda: self.app.after(0, _refresh))

    def _show_pipeline_details(self):
        """WEB ASSAULT pipeline details — control panel + observer.

        Sections:
          1. Header — target + total elapsed wall-clock
          2. Steps — icon, status, duration, error, RE-RUN/START button
          3. Data collected — expandable lists for tech / api / params /
             uploads / jwts (drill-down on click)
          4. Findings (Target Intel) — severity counts + JUMP button
          5. Smart suggestions — contextual NEXT-STEP hints
          6. Footer — STOP PIPELINE / JUMP TO TARGET INTEL / CLOSE
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        state = getattr(self.app, "assault_state", None)
        win = _make_win(self, "WEB ASSAULT — Pipeline details",
                        780, 760)
        _title(win, "PIPELINE DETAILS")

        # Scrollable body — enough room for expanded sections without
        # blowing past the dialog footer.
        body = ctk.CTkScrollableFrame(
            win, fg_color="transparent", height=560,
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["text_dim"])
        body.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        # ── 1. Header — target + timing ──────────────────────────
        target_lbl = ctk.CTkLabel(
            body, text="", font=_f("md", True),
            text_color=COLORS["text_cyan"], anchor="w")
        target_lbl.pack(fill="x", padx=24, pady=(4, 2))

        timing_lbl = ctk.CTkLabel(
            body, text="", font=_f("xs"),
            text_color=COLORS["text_dim"], anchor="w")
        timing_lbl.pack(fill="x", padx=24, pady=(0, 6))

        ctk.CTkFrame(body, height=1, fg_color=COLORS["border_dim"]
                     ).pack(fill="x", padx=24, pady=(0, 8))

        # ── 2. Steps ─────────────────────────────────────────────
        ctk.CTkLabel(
            body, text="STEPS", font=_f("md", True),
            text_color=COLORS["text_cyan"], anchor="w"
        ).pack(fill="x", padx=24, pady=(2, 4))

        steps_fr = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                corner_radius=3,
                                border_color=COLORS["border_dim"],
                                border_width=1)
        steps_fr.pack(fill="x", padx=24, pady=(0, 12))

        STATUS_TEXT = {
            "pending":  "pending — not started",
            "ready":    "ready",
            "running":  "running…",
            "done":     "done",
            "error":    "error",
            "skipped":  "skipped",
        }

        def _fmt_duration(secs: float) -> str:
            if secs <= 0:
                return ""
            secs = int(secs)
            if secs < 60:
                return f"{secs}s"
            m, s = divmod(secs, 60)
            if m < 60:
                return f"{m}m{s:02d}s" if s else f"{m}m"
            h, m = divmod(m, 60)
            return f"{h}h{m:02d}m"

        # Map step → tool_id used by self.module.get_tool().  Drives
        # the RE-RUN button action.
        STEP_TOOL_ID = {
            "oracle": "web_oracle",
            "crawl":  "bloody_crawl",
            "inject": "injection_tester",
            "jwt":    "jwt_analyzer",
        }

        def _rerun_step(step_key: str):
            """Close the dialog and open the tool's config dialog."""
            tid = STEP_TOOL_ID.get(step_key)
            if not tid:
                return
            tool = self.module.get_tool(tid)
            if tool is None:
                return
            _close()
            try:
                self._gate_check(tool)
            except Exception as e:
                try:
                    self.app.terminal.write(
                        f"  [!] could not open {tid} dialog: {e}",
                        "warn")
                except Exception:
                    pass

        step_rows = {}
        for i, (key, label) in enumerate(self.PIPELINE_STEPS):
            row = ctk.CTkFrame(steps_fr, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=4)
            icon = ctk.CTkLabel(row, text="○", font=_f("xl", True),
                                text_color=COLORS["text_muted"],
                                width=24, anchor="w")
            icon.pack(side="left", padx=(0, 6))
            name = ctk.CTkLabel(row, text=label, font=_f("md", True),
                                text_color=COLORS["text_bright"],
                                width=84, anchor="w")
            name.pack(side="left")
            stat = ctk.CTkLabel(row, text="pending",
                                font=_f("sm"),
                                text_color=COLORS["text_dim"],
                                width=90, anchor="w")
            stat.pack(side="left", padx=(0, 4))
            duration = ctk.CTkLabel(row, text="",
                                     font=_f("xs", True),
                                     text_color=COLORS["text_cyan"],
                                     width=70, anchor="w")
            duration.pack(side="left", padx=(0, 6))
            extra = ctk.CTkLabel(row, text="",
                                 font=_f("xs"),
                                 text_color=COLORS["text_muted"],
                                 anchor="w")
            extra.pack(side="left", fill="x", expand=True)

            btn = ctk.CTkButton(
                row, text="RE-RUN", width=78, height=22,
                font=_f("xs", True),
                fg_color=COLORS["bg_secondary"],
                hover_color=COLORS["bg_card_hover"],
                text_color=COLORS["text_green"],
                border_color=COLORS["border_green"], border_width=1,
                corner_radius=3,
                command=lambda k=key: _rerun_step(k))
            btn.pack(side="right", padx=(4, 0))

            # Optional secondary line for the error message — packed
            # only when a step is in error state.
            err_row = ctk.CTkFrame(steps_fr, fg_color="transparent")
            err_lbl = ctk.CTkLabel(err_row, text="",
                                    font=_f("xs"),
                                    text_color=COLORS["text_red"],
                                    anchor="w",
                                    wraplength=680, justify="left")
            err_lbl.pack(fill="x", padx=(40, 10))

            step_rows[key] = {
                "row": row, "icon": icon, "name": name,
                "stat": stat, "duration": duration, "extra": extra,
                "btn": btn, "err_row": err_row, "err_lbl": err_lbl,
            }

        # ── 3. DATA COLLECTED — expandable lists ─────────────────
        ctk.CTkLabel(
            body, text="DATA COLLECTED", font=_f("md", True),
            text_color=COLORS["text_cyan"], anchor="w"
        ).pack(fill="x", padx=24, pady=(2, 4))

        counts_fr = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                 corner_radius=3,
                                 border_color=COLORS["border_dim"],
                                 border_width=1)
        counts_fr.pack(fill="x", padx=24, pady=(0, 12))

        DATA_KEYS = (
            ("tech",    "Tech signatures"),
            ("api",     "API endpoints"),
            ("params",  "Parameters (Crawl)"),
            ("uploads", "Upload forms"),
            ("jwts",    "JWT tokens"),
        )
        # Track which sections the user has expanded (per-dialog).
        is_expanded = {k: False for k, _ in DATA_KEYS}

        data_widgets = {}

        def _toggle_section(key):
            is_expanded[key] = not is_expanded[key]
            _refresh_data_lists()

        for key, label in DATA_KEYS:
            row = ctk.CTkFrame(counts_fr, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=2)
            label_lbl = ctk.CTkLabel(
                row, text=label, font=_f("sm", True),
                text_color=COLORS["text_dim"],
                width=180, anchor="w")
            label_lbl.pack(side="left")
            count_lbl = ctk.CTkLabel(
                row, text="0", font=_f("sm", True),
                text_color=COLORS["text_bright"], width=40,
                anchor="w")
            count_lbl.pack(side="left")
            toggle_btn = ctk.CTkButton(
                row, text="▸", width=22, height=18,
                font=_f("xs", True),
                fg_color="transparent",
                hover_color=COLORS["bg_card_hover"],
                text_color=COLORS["text_dim"],
                border_color=COLORS["border_dim"], border_width=0,
                corner_radius=2,
                command=lambda k=key: _toggle_section(k))
            toggle_btn.pack(side="left", padx=(4, 0))

            expanded = ctk.CTkFrame(counts_fr,
                                     fg_color="transparent")
            # Not packed yet — packed by _refresh_data_lists when
            # is_expanded[key] is True.
            data_widgets[key] = {
                "row": row, "label_lbl": label_lbl,
                "count_lbl": count_lbl, "toggle_btn": toggle_btn,
                "expanded": expanded,
            }

        def _build_list(parent, items: list, formatter, empty: str = ""):
            """Wipe `parent` and rebuild with one CTkLabel per item."""
            for child in parent.winfo_children():
                try:
                    child.destroy()
                except Exception:
                    pass
            if not items:
                if empty:
                    ctk.CTkLabel(parent, text=f"  {empty}",
                                  font=_f("xs"),
                                  text_color=COLORS["text_muted"],
                                  anchor="w").pack(fill="x", padx=20)
                return
            for it in items[:30]:
                ctk.CTkLabel(parent, text=f"  • {formatter(it)}",
                              font=_f("xs"),
                              text_color=COLORS["text_dim"],
                              anchor="w", wraplength=680,
                              justify="left").pack(fill="x", padx=20)
            if len(items) > 30:
                ctk.CTkLabel(parent,
                              text=f"  … and {len(items) - 30} more",
                              font=_f("xs"),
                              text_color=COLORS["text_muted"],
                              anchor="w").pack(fill="x", padx=20)

        # ── 4. Findings summary (Target Intel) ───────────────────
        ctk.CTkLabel(
            body, text="TARGET INTEL", font=_f("md", True),
            text_color=COLORS["text_cyan"], anchor="w"
        ).pack(fill="x", padx=24, pady=(2, 4))

        findings_fr = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                    corner_radius=3,
                                    border_color=COLORS["border_dim"],
                                    border_width=1)
        findings_fr.pack(fill="x", padx=24, pady=(0, 12))

        findings_summary_lbl = ctk.CTkLabel(
            findings_fr, text="", font=_f("sm"),
            text_color=COLORS["text_dim"], anchor="w",
            wraplength=700, justify="left")
        findings_summary_lbl.pack(fill="x", padx=10, pady=(8, 4))

        findings_list_fr = ctk.CTkFrame(findings_fr,
                                         fg_color="transparent")
        findings_list_fr.pack(fill="x", padx=10, pady=(0, 8))

        # ── 5. Smart suggestions ─────────────────────────────────
        ctk.CTkLabel(
            body, text="WHAT TO DO NEXT", font=_f("md", True),
            text_color=COLORS["text_cyan"], anchor="w"
        ).pack(fill="x", padx=24, pady=(2, 4))

        suggestions_fr = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                       corner_radius=3,
                                       border_color=COLORS["border_dim"],
                                       border_width=1)
        suggestions_fr.pack(fill="x", padx=24, pady=(0, 12))

        # ── Top-level cancel banner ──────────────────────────────
        cancel_lbl = ctk.CTkLabel(
            body, text="", font=_f("sm", True),
            text_color=COLORS["text_yellow"], anchor="w")
        cancel_lbl.pack(fill="x", padx=24, pady=(0, 4))

        # ── Refresh ──────────────────────────────────────────────
        def _suggestions(s: dict, findings: list) -> list:
            """Compute contextual NEXT-STEP hints from current state +
            target-intel findings.  Returns list of dicts:
            {icon, color, text}."""
            out = []
            steps = s.get("steps", {})
            cancelled = bool(s.get("cancelled"))

            if cancelled:
                out.append({"icon": "✗", "color": "text_red",
                            "text": ("Pipeline cancelled by user — "
                                     "workers stopped at next "
                                     "checkpoint.")})

            # Per-step error surface.
            for k in self.PIPELINE_STEPS:
                key = k[0] if isinstance(k, tuple) else k
                info = (s.get("step_info") or {}).get(key, {})
                err = info.get("error") or ""
                if err:
                    label = dict(self.PIPELINE_STEPS).get(key, key)
                    out.append({"icon": "✗", "color": "text_red",
                                "text": f"{label} reported an error: {err}"})

            if (steps.get("oracle") == "done" and s.get("api", 0) == 0
                    and s.get("tech", 0) > 0):
                out.append({"icon": "◯", "color": "text_cyan",
                            "text": ("Oracle found 0 API endpoints — "
                                     "directory brute (gobuster / ffuf) "
                                     "might surface unlinked routes.")})

            if (steps.get("crawl") == "done" and s.get("params", 0) == 0
                    and steps.get("oracle") == "done"):
                out.append({"icon": "◯", "color": "text_cyan",
                            "text": ("Crawl found 0 parameters — try "
                                     "ffuf with FUZZ in query string, "
                                     "or feed Inject manual targets.")})

            # Inject heuristic — done with 0 confirmed high+ findings.
            if steps.get("inject") == "done" and s.get("params", 0) > 0:
                inject_high = sum(1 for f in findings
                                  if (f.get("source") == "Injection Tester"
                                      and (f.get("severity") or "")
                                              .lower() in ("critical",
                                                            "high")))
                if inject_high == 0:
                    out.append({"icon": "◯", "color": "text_cyan",
                                "text": (f"INJECT found 0 high+ vulns "
                                         f"in safe mode on "
                                         f"{s['params']} known param(s) "
                                         f"— try AGGRESSIVE (uses "
                                         f"sqlmap / dalfox / commix).")})

            if (steps.get("jwt") in ("pending", "ready")
                    and s.get("jwts", 0) == 0):
                out.append({"icon": "⚠", "color": "text_yellow",
                            "text": ("JWT step pending but 0 tokens "
                                     "captured — paste one manually or "
                                     "skip the step.")})

            if s.get("uploads", 0) > 0:
                upload_findings = [f for f in findings
                                   if "upload"
                                   in (f.get("title", "") or "").lower()]
                if not upload_findings:
                    out.append({"icon": "◯", "color": "text_cyan",
                                "text": (f"{s['uploads']} upload form(s) "
                                         f"detected — INJECT with "
                                         f"'Upload Bypass' enabled "
                                         f"covers webshell-extension "
                                         f"tests.")})

            if all(steps.get(k) == "done"
                    for k in ("oracle", "crawl", "inject", "jwt")):
                out.append({"icon": "✓", "color": "text_green",
                            "text": ("All four steps complete. Review "
                                     "findings in Target Intel and "
                                     "generate the report.")})

            if not out:
                out.append({"icon": "◯", "color": "text_muted",
                            "text": ("No suggestions yet — run more "
                                     "steps to see contextual hints.")})
            return out

        def _findings_for_target() -> list:
            """Return current target_intel auto_findings (already
            scoped to the current target by HAWK's session model —
            target_intel is wiped on target switch)."""
            try:
                ai = getattr(self.app, "target_intel", None)
                if ai is not None:
                    return list(getattr(ai, "_auto_findings", []) or [])
            except Exception:
                pass
            return []

        def _refresh_data_lists():
            if state is None:
                return
            for key, w in data_widgets.items():
                exp = w["expanded"]
                btn = w["toggle_btn"]
                count = int(state.summary().get(key, 0))
                if count == 0:
                    btn.configure(text="—", state="disabled")
                    if is_expanded.get(key):
                        is_expanded[key] = False
                    try:
                        exp.pack_forget()
                    except Exception:
                        pass
                    continue
                btn.configure(state="normal",
                              text="▾" if is_expanded[key] else "▸")
                if is_expanded[key]:
                    if not exp.winfo_ismapped():
                        exp.pack(fill="x", padx=10, pady=(0, 6))
                    if key == "tech":
                        _build_list(exp, state.get_tech() or [],
                                     formatter=lambda x: x)
                    elif key == "api":
                        _build_list(exp, state.get_api_endpoints(),
                                     formatter=lambda e:
                                         f"[{e.kind}] {e.url}"
                                         + (f"  ({e.status})"
                                            if e.status else ""))
                    elif key == "params":
                        _build_list(exp, state.get_parameters(),
                                     formatter=lambda p:
                                         f"{p.method} "
                                         f"{p.url}  "
                                         f"name={p.name}"
                                         + (f"  sample={p.sample}"
                                            if p.sample else ""))
                    elif key == "uploads":
                        _build_list(exp, state.get_upload_forms(),
                                     formatter=lambda u:
                                         f"{u.method} {u.url}  "
                                         f"file={u.file_field}"
                                         + (f"  +fields="
                                            f"{','.join(u.other_fields)}"
                                            if u.other_fields else ""))
                    elif key == "jwts":
                        _build_list(
                            exp, state.get_jwt_tokens(),
                            formatter=lambda t:
                                f"[{t.source}] {t.where or '?'}: "
                                f"{(t.token[:32] + '…') if len(t.token) > 32 else t.token}")
                else:
                    try:
                        exp.pack_forget()
                    except Exception:
                        pass

        # Signatures of the last-rendered content for the two blocks
        # below.  Both _refresh helpers fire every second from the
        # ticker AND on every state change — destroying + recreating
        # widgets each time produced a visible flicker ("lampeggio")
        # because the frame went empty for a beat between destroy()
        # and the new pack().  We now compute a content signature and
        # skip the rebuild when nothing changed; widget identities
        # stay stable, so no flicker.
        findings_sig = [None]
        sugg_sig     = [None]

        def _refresh_findings_block(findings: list):
            SEV_RANK = {"critical": 0, "high": 1, "medium": 2,
                        "low": 3, "info": 4}
            counts = {k: 0 for k in SEV_RANK}
            for f in findings:
                sev = (f.get("severity") or "info").lower()
                if sev in counts:
                    counts[sev] += 1
            sorted_f = sorted(
                findings,
                key=lambda f: (SEV_RANK.get((f.get("severity") or "info")
                                              .lower(), 99),
                                f.get("title", "")))
            top5 = sorted_f[:5]
            sig = (
                len(findings),
                tuple((counts[k] for k in
                       ("critical", "high", "medium", "low", "info"))),
                tuple(((f.get("severity") or "info").lower(),
                       (f.get("title") or "")[:80]) for f in top5),
                len(sorted_f) > 5,
            )
            if sig == findings_sig[0]:
                return
            findings_sig[0] = sig

            for child in findings_list_fr.winfo_children():
                try:
                    child.destroy()
                except Exception:
                    pass
            if not findings:
                findings_summary_lbl.configure(
                    text="No findings on this target yet.")
                return
            parts = []
            for sev in ("critical", "high", "medium", "low", "info"):
                if counts[sev]:
                    parts.append(f"{counts[sev]} {sev}")
            findings_summary_lbl.configure(
                text=f"{len(findings)} finding(s) on this target — "
                     + ", ".join(parts))
            for f in top5:
                sev = (f.get("severity") or "info").upper()
                title = f.get("title", "")[:80]
                ctk.CTkLabel(
                    findings_list_fr,
                    text=f"  [{sev}] {title}",
                    font=_f("xs"),
                    text_color=COLORS["text_dim"],
                    anchor="w", wraplength=700,
                    justify="left").pack(fill="x", padx=4, pady=1)
            if len(sorted_f) > 5:
                ctk.CTkLabel(
                    findings_list_fr,
                    text=f"  … and {len(sorted_f) - 5} more",
                    font=_f("xs"),
                    text_color=COLORS["text_muted"],
                    anchor="w").pack(fill="x", padx=4)

        def _refresh_suggestions_block(s: dict, findings: list):
            sugs = _suggestions(s, findings)
            sig = tuple((x["icon"], x["color"], x["text"]) for x in sugs)
            if sig == sugg_sig[0]:
                return
            sugg_sig[0] = sig

            for child in suggestions_fr.winfo_children():
                try:
                    child.destroy()
                except Exception:
                    pass
            for sug in sugs:
                color = COLORS.get(sug["color"], COLORS["text_dim"])
                ctk.CTkLabel(
                    suggestions_fr,
                    text=f"  {sug['icon']}  {sug['text']}",
                    font=_f("xs"),
                    text_color=color, anchor="w",
                    wraplength=700, justify="left"
                ).pack(fill="x", padx=10, pady=4)

        def _refresh():
            try:
                if not win.winfo_exists():
                    return
            except Exception:
                return
            if state is None:
                target_lbl.configure(text="(no AssaultState bound)")
                timing_lbl.configure(text="")
                cancel_lbl.configure(text="")
                return
            s = state.summary()
            target_lbl.configure(
                text=f"Target:  {s['target'] or '(no target bound)'}")

            # Wall-clock line
            started = s.get("pipeline_started_at") or "—"
            updated = s.get("pipeline_updated_at") or "—"
            total_secs = 0.0
            for info in (s.get("step_info") or {}).values():
                total_secs += info.get("duration_s") or 0.0
            timing_lbl.configure(
                text=(f"Started: {started}    ·    "
                      f"Updated: {updated}    ·    "
                      f"Total: {_fmt_duration(total_secs) or '—'}"))

            steps = s["steps"]
            step_info = s.get("step_info", {}) or {}
            for key, w in step_rows.items():
                st = steps.get(key, "pending")
                ic, colorkey = self._STEP_ICON.get(
                    st, self._STEP_ICON["pending"])
                w["icon"].configure(
                    text=ic,
                    text_color=COLORS.get(colorkey, COLORS["text_muted"]))
                w["stat"].configure(text=STATUS_TEXT.get(st, st))
                info = step_info.get(key, {}) or {}
                w["duration"].configure(
                    text=_fmt_duration(info.get("duration_s") or 0.0))

                # Per-step extra summary.
                if key == "oracle":
                    extra_t = (f"{s['tech']} tech, "
                               f"{s['api']} api endpoint(s)")
                elif key == "crawl":
                    extra_t = (f"{s['params']} params, "
                               f"{s['uploads']} upload(s), "
                               f"{s['jwts']} jwt(s)")
                elif key == "inject":
                    cnt = len([f for f in _findings_for_target()
                                if f.get("source") == "Injection Tester"])
                    extra_t = (f"{cnt} finding(s) pushed"
                               if cnt else "no vulns confirmed yet")
                elif key == "jwt":
                    extra_t = (f"{s['jwts']} token(s) seen"
                               if s['jwts'] else "no tokens")
                else:
                    extra_t = ""
                w["extra"].configure(text=extra_t)

                # Error sub-row visibility.
                err = (info.get("error") or "").strip()
                if err and st == "error":
                    w["err_lbl"].configure(text=f"⚠  {err}")
                    if not w["err_row"].winfo_ismapped():
                        w["err_row"].pack(fill="x", padx=10,
                                            pady=(0, 4))
                else:
                    try:
                        w["err_row"].pack_forget()
                    except Exception:
                        pass

                # RE-RUN/START label depending on state.
                w["btn"].configure(
                    text=("START" if st == "pending" else "RE-RUN"))

            # Counter labels.
            for key, w in data_widgets.items():
                w["count_lbl"].configure(text=str(s.get(key, 0)))

            _refresh_data_lists()
            findings = _findings_for_target()
            _refresh_findings_block(findings)
            _refresh_suggestions_block(s, findings)

            cancel_lbl.configure(
                text=("⚠  Pipeline cancelled — workers stopping at "
                      "next checkpoint." if s.get("cancelled") else ""))

        # Subscribe to state changes; unsubscribe on close.
        sub = (lambda: self.app.after(0, _refresh)) if state else None
        if state and sub:
            state.subscribe(sub)
        # Live timer ticker for "running" duration display — re-runs
        # _refresh every second as long as the dialog is open.
        ticker_id = [None]

        def _tick():
            try:
                if not win.winfo_exists():
                    return
            except Exception:
                return
            _refresh()
            ticker_id[0] = win.after(1000, _tick)

        def _close():
            if state and sub:
                try:
                    state._subscribers.remove(sub)
                except Exception:
                    pass
            try:
                if ticker_id[0] is not None:
                    win.after_cancel(ticker_id[0])
            except Exception:
                pass
            _safe_destroy(win)

        def _stop_pipeline():
            if state is None:
                return
            state.cancel()
            try:
                self.app.terminal.write(
                    "  [!] Pipeline STOP requested — workers will "
                    "abort at next checkpoint.", "warn")
            except Exception:
                pass
            _refresh()

        def _jump_to_intel():
            try:
                if hasattr(self.app, "switch_to_tab"):
                    self.app.switch_to_tab("intel")
            except Exception as e:
                try:
                    self.app.terminal.write(
                        f"  [!] Could not switch to Target Intel tab: {e}",
                        "warn")
                except Exception:
                    pass
            _close()

        row = _btn_row(win)
        _btn(row, "STOP PIPELINE", _stop_pipeline, danger=True, w=170)
        _btn(row, "→ TARGET INTEL", _jump_to_intel, w=170)
        _btn(row, "CLOSE", _close, primary=True, w=120)

        _refresh()
        ticker_id[0] = win.after(1000, _tick)

    def _build_tool_row(self, tool, row: int, parent=None):
        """Build one tool row.

        When *parent* is None the row is placed in self._content_frame via
        grid (legacy path — all non-OS-grouped phases).  When *parent* is
        a CTkFrame (OS section container) the row is packed inside it so
        the section frame can be shown/hidden as a unit for collapse.
        """
        is_greenbone = (tool.id == "greenbone")
        install_first = tool.id in self._INSTALL_FIRST_IDS
        runs_on_target = getattr(tool, "runs_on_target", False)
        installed = tool.is_available()
        # tools that run on the target (Windows built-ins: reg, wmic, netsh…)
        # are always "available" from HAWK's perspective — the command is
        # copied to clipboard and run in the target shell, not locally.
        avail = installed or install_first or runs_on_target

        container = parent if parent is not None else self._content_frame
        row_fr = ctk.CTkFrame(
            container,
            fg_color=COLORS["bg_secondary"] if avail else COLORS["bg_card"],
            height=42, corner_radius=3)
        if parent is not None:
            row_fr.pack(fill="x", padx=10, pady=2)
        else:
            row_fr.grid(row=row, column=0, sticky="ew", padx=10, pady=2)
        row_fr.grid_columnconfigure(2, weight=1)
        row_fr.grid_propagate(False)

        icon_lbl = ctk.CTkLabel(
            row_fr, text="○", font=_f("lg"),
            text_color=COLORS["text_muted"] if avail else COLORS["border_dim"],
            width=18)
        icon_lbl.grid(row=0, column=0, padx=(10,2), pady=5)

        name_lbl = ctk.CTkLabel(
            row_fr, text=tool.name, font=_f("lg",True),
            text_color=COLORS["text_bright"] if avail else COLORS["text_muted"],
            width=190, anchor="w",
        )
        name_lbl.grid(row=0, column=1, padx=(4,8), pady=5, sticky="w")

        desc_first = tool.desc.split("\n")[0] if "\n" in tool.desc else tool.desc
        if install_first and not installed:
            desc_first = "Not installed — click INSTALL to launch the install wizard"
            desc_color = COLORS["text_yellow"]
        elif runs_on_target:
            # NOT `and not installed`.  Several of these Windows
            # built-ins have same-named binaries on Kali (`whoami`,
            # `net`, `netstat`), so gating on local availability sent
            # them down the normal RUN path: HAWK executed them
            # LOCALLY and reported Kali's users, privileges and
            # listening ports as if they were the target's.  A tool
            # declared runs_on_target runs on the target, whatever is
            # installed here.
            desc_first = f"▶ Run on target shell — click SHOW to copy command"
            desc_color = COLORS["text_dim"]
        elif avail:
            desc_color = COLORS["text_dim"]
        else:
            # Show only the first / preferred install strategy inline —
            # the full cascade goes into the install wizard where there's
            # real estate for it.
            try:
                strats = tool.get_install_strategies()
                short = strats[0][1] if strats else f"apt install -y {tool.binary}"
            except Exception:
                short = f"apt install -y {tool.binary}"
            desc_first = f"Not installed — {short}"
            desc_color = COLORS["text_muted"]

        desc_lbl = ctk.CTkLabel(
            row_fr, text=desc_first, font=_f("sm"),
            text_color=desc_color, anchor="w",
        )
        desc_lbl.grid(row=0, column=2, padx=4, pady=5, sticky="w")

        # Button label / color:
        #   "INSTALL" (amber)  → install wizard (tool missing, install-first)
        #   "SHOW"   (cyan)    → runs_on_target: show + copy command dialog
        #   "RUN"    (green)   → normal run locally
        if install_first and not installed:
            btn_label  = "INSTALL"
            btn_border = COLORS["border_amber"]
            btn_text   = COLORS["text_yellow"]
        elif runs_on_target:
            btn_label  = "SHOW"
            btn_border = COLORS.get("text_cyan", "#7EC8E3")
            btn_text   = COLORS.get("text_cyan", "#7EC8E3")
        else:
            btn_label  = "RUN"
            btn_border = COLORS["border_green"]
            btn_text   = COLORS["text_green"]

        def _on_click(t=tool):
            # Re-check binary at click time — if user installed it externally
            # since the card was built, go straight to the real run.
            if t.id in self._INSTALL_FIRST_IDS and not t.is_available():
                self._show_install_dialog(t)
                return
            # netsh portfwd needs its own dialog to collect listen_port,
            # connect_address and connect_port before building the command.
            if t.id == "netsh_portfwd":
                self._route_netsh_portfwd(t)
                return

            # runs_on_target tools: show the command with a copy button
            # so the user can paste it into the target shell (meterpreter,
            # evil-winrm, cmd, PowerShell, etc.) rather than running locally.
            # Local availability is deliberately NOT consulted — see the
            # matching comment in the row builder above.
            if getattr(t, "runs_on_target", False):
                self._show_target_command_dialog(t)
                return
            self._gate_check(t)

        run_btn = ctk.CTkButton(
            row_fr, text=btn_label,
            width=82 if btn_label in ("INSTALL", "SHOW") else 62, height=24,
            font=_f("md",True),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=btn_border, border_width=1,
            text_color=btn_text,
            corner_radius=3, state="normal",
            command=_on_click)
        run_btn.grid(row=0, column=3, padx=(4,10), pady=5)

        # ── Optional "WHAT IT DOES" info button ───────────────────────
        # Surfaced only for tools with an entry in _TOOL_DETAILED_INFO.
        # Opens a scrollable dialog explaining in depth what the tool
        # does, which binaries it orchestrates, how to interpret the
        # output, and when NOT to use it.  Opt-in to keep the row
        # clean for tools whose one-line desc already covers it.
        info_btn = None
        if tool.id in self._TOOL_DETAILED_INFO:
            def _open_info(t=tool):
                self._show_tool_detailed_info(t)
            info_btn = ctk.CTkButton(
                row_fr, text="ⓘ  WHAT IT DOES",
                width=140, height=24,
                font=_f("sm", True),
                fg_color="transparent",
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["text_cyan"], border_width=1,
                text_color=COLORS["text_cyan"],
                corner_radius=3,
                command=_open_info)
            info_btn.grid(row=0, column=4, padx=(0, 10), pady=5)

        # ── Greenbone: extra ACCESS PANEL button next to RUN ──────────
        # RUN should just start the services; the access-panel helper
        # dialog (URL, login helpers, password reset) opens on-demand
        # via this secondary button.  Before this split, the panel
        # auto-opened after RUN — which sometimes triggered the freeze
        # the user reported (two Toplevels + async xterm + webbrowser
        # racing each other on the UI thread).
        access_btn = None
        if tool.id == "greenbone":
            def _open_access_panel(t=tool):
                from gui.dialogs import GreenboneDialog
                # Instantiate dialog WITHOUT calling START — just show
                # the access panel directly.  We reuse the existing
                # dialog's _show_access_panel helper.
                try:
                    dlg = GreenboneDialog.__new__(GreenboneDialog)
                    dlg._callback_run  = lambda *a, **kw: None
                    dlg._callback_skip = lambda *a, **kw: None
                    dlg._show_access_panel(self)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] Access panel error: {e}", "error")

            access_btn = ctk.CTkButton(
                row_fr, text="ACCESS PANEL",
                width=120, height=24,
                font=_f("sm", True),
                # Transparent / muted look — visually distinct from RUN
                # so the user immediately sees it as a secondary/helper
                # action, not the primary launch verb.
                fg_color="transparent",
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["text_muted"], border_width=1,
                text_color=COLORS["text_muted"],
                corner_radius=3,
                command=_open_access_panel)
            access_btn.grid(row=0, column=4, padx=(0, 10), pady=5)

        # ── BloodHound: extra "⚙ CE SETUP" button next to RUN ─────────
        # Offline-friendly setup guide for BloodHound Community Edition
        # (docker + compose + bh-ce stack).  Opens the same dialog
        # reachable from the post-collect summary, but directly on the
        # tool row so first-time users don't have to run bloodhound
        # before seeing the install instructions.
        if tool.id == "bloodhound_python":
            def _open_bhce_setup(t=tool):
                try:
                    from gui.dialogs import \
                        show_bloodhound_ce_setup_dialog
                    show_bloodhound_ce_setup_dialog(self)
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] BH CE setup dialog error: {e}", "error")
            bh_setup_btn = ctk.CTkButton(
                row_fr, text="⚙  CE SETUP",
                width=110, height=24,
                font=_f("sm", True),
                fg_color="transparent",
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["text_muted"], border_width=1,
                text_color=COLORS["text_muted"],
                corner_radius=3,
                command=_open_bhce_setup)
            bh_setup_btn.grid(row=0, column=4, padx=(0, 10), pady=5)

        entry = {
            "row":      row_fr,
            "icon":     icon_lbl,
            "name_lbl": name_lbl,
            "desc_lbl": desc_lbl,
            "run_btn":  run_btn,
            "_status":  "ready",
        }
        if access_btn is not None:
            entry["access_btn"] = access_btn
        if info_btn is not None:
            entry["info_btn"] = info_btn
        self._tool_widgets[tool.id] = entry

    def _show_tool_detailed_info(self, tool):
        """Modal dialog showing the long-form explanation of what a
        tool does.  Text comes from _TOOL_DETAILED_INFO keyed by
        tool id; layout is a scrollable textbox so multi-page
        explanations fit without cramping.
        """
        from gui.dialogs import (_make_win, _title, _sub,
                                  _btn_row, _btn, _safe_destroy)
        text = self._TOOL_DETAILED_INFO.get(tool.id) or ""
        if not text:
            return

        win = _make_win(self,
                        f"{tool.name} — what it does",
                        780, 680)
        _title(win, f"ⓘ  {tool.name}")
        _sub(win, "Detailed explanation of what this tool does, "
                  "how it works, and when to use it.",
             COLORS["text_dim"])

        # Scrollable textbox — content is long, one short dialog
        # wouldn't fit on a 720p laptop display.
        box_frame = ctk.CTkFrame(
            win, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=4)
        box_frame.pack(fill="both", expand=True, padx=14, pady=6)
        tbox = ctk.CTkTextbox(
            box_frame, font=_f("md"),
            fg_color="transparent",
            text_color=COLORS["text_bright"],
            border_width=0, corner_radius=0,
            wrap="word")
        tbox.pack(fill="both", expand=True, padx=8, pady=6)
        tbox.insert("1.0", text)
        tbox.configure(state="disabled")

        row = _btn_row(win)
        _btn(row, "CLOSE", lambda: _safe_destroy(win),
             primary=True, w=140)

    def _build_os_grouped_tools(self, tools: list, tool_briefs: dict):
        """Render tool rows grouped by os_hint into collapsible sections.

        Called only when the phase has at least one tool with os_hint !=
        'any' (currently post_exploit and lateral). Tools tagged 'any' are
        rendered first without a section header; Linux tools go in a 🐧
        LINUX section, Windows tools in a 🪟 WINDOWS section.

        Each section has a toggle button (▼/▶) that shows/hides the
        tool rows by packing/unpacking the section body frame.  Collapse
        state is stored in the session so it survives card rebuilds.
        """
        grid_row = 3  # rows 0-2 are used by _build_header

        any_tools   = [t for t in tools if getattr(t, "os_hint", "any") == "any"]
        linux_tools = [t for t in tools if getattr(t, "os_hint", "any") == "linux"]
        win_tools   = [t for t in tools if getattr(t, "os_hint", "any") == "windows"]

        # ── Collapse-state helpers ────────────────────────────────────────
        # State key pattern: "{phase_id}_os_{hint}" in session.card_collapsed.
        def _get_collapsed(hint: str) -> bool:
            try:
                sess = self.app.session_manager.current
                if sess and hasattr(sess, "card_collapsed"):
                    key = f"{self.phase_id}_os_{hint}"
                    return bool(sess.card_collapsed.get(key, False))
            except Exception:
                pass
            return False

        def _set_collapsed(hint: str, val: bool):
            try:
                sess = self.app.session_manager.current
                if sess and hasattr(sess, "card_collapsed"):
                    key = f"{self.phase_id}_os_{hint}"
                    sess.card_collapsed[key] = val
                    sess.save()
            except Exception:
                pass

        # ── "any" tools — flat list, no section header ───────────────────
        seen_binaries: set = set()
        for tool in any_tools:
            if tool.binary not in seen_binaries:
                seen_binaries.add(tool.binary)
                brief = tool_briefs.get(tool.binary, "")
                if brief:
                    hdr_fr = ctk.CTkFrame(
                        self._content_frame,
                        fg_color="transparent", height=20)
                    hdr_fr.grid(row=grid_row, column=0, sticky="ew",
                                padx=14, pady=(6, 0))
                    hdr_fr.grid_propagate(False)
                    ctk.CTkLabel(
                        hdr_fr, text=f"  {brief}",
                        font=_f("xs"), text_color=COLORS["text_muted"],
                        anchor="w").pack(side="left", fill="x")
                    grid_row += 1
            self._build_tool_row(tool, row=grid_row)
            grid_row += 1

        # ── OS section builder ────────────────────────────────────────────
        def _build_os_section(section_tools, hint, icon, label, color):
            nonlocal grid_row
            if not section_tools:
                return

            collapsed = _get_collapsed(hint)
            n = len(section_tools)

            # Separator + section header row
            sep = ctk.CTkFrame(self._content_frame,
                               fg_color=COLORS["border_dim"], height=1)
            sep.grid(row=grid_row, column=0, sticky="ew",
                     padx=10, pady=(10, 0))
            grid_row += 1

            sec_hdr = ctk.CTkFrame(self._content_frame,
                                   fg_color="transparent", height=28)
            sec_hdr.grid(row=grid_row, column=0, sticky="ew",
                         padx=10, pady=(2, 0))
            sec_hdr.grid_columnconfigure(1, weight=1)
            sec_hdr.grid_propagate(False)
            grid_row += 1

            # Toggle button (▼ / ▶)
            toggle_var = ctk.StringVar(value="▶" if collapsed else "▼")

            # Body frame — contains all tool rows for this section
            body_fr = ctk.CTkFrame(self._content_frame, fg_color="transparent")
            body_fr.grid(row=grid_row, column=0, sticky="ew")
            body_fr.grid_columnconfigure(0, weight=1)
            grid_row += 1

            def _toggle(h=hint, bfr=body_fr, tv=toggle_var):
                now = _get_collapsed(h)
                new_val = not now
                _set_collapsed(h, new_val)
                if new_val:
                    bfr.grid_remove()
                    tv.set("▶")
                else:
                    bfr.grid()
                    tv.set("▼")

            toggle_btn = ctk.CTkButton(
                sec_hdr, textvariable=toggle_var,
                width=28, height=22,
                font=_f("sm", True),
                fg_color="transparent",
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_dim"], border_width=1,
                text_color=color, corner_radius=3,
                command=_toggle)
            toggle_btn.grid(row=0, column=0, padx=(4, 6), pady=3)

            ctk.CTkLabel(
                sec_hdr,
                text=f"{icon}  {label}  —  {n} tool{'s' if n != 1 else ''}",
                font=_f("sm", True), text_color=color, anchor="w",
            ).grid(row=0, column=1, pady=3, sticky="w")

            # If section starts collapsed, hide body immediately
            if collapsed:
                body_fr.grid_remove()

            # Render tool rows inside body_fr (packed, not gridded)
            seen = set()
            for tool in section_tools:
                if tool.binary not in seen:
                    seen.add(tool.binary)
                    brief = tool_briefs.get(tool.binary, "")
                    if brief:
                        bh = ctk.CTkFrame(body_fr, fg_color="transparent",
                                          height=18)
                        bh.pack(fill="x", padx=14, pady=(4, 0))
                        bh.pack_propagate(False)
                        ctk.CTkLabel(
                            bh, text=f"  {brief}",
                            font=_f("xs"), text_color=COLORS["text_muted"],
                            anchor="w").pack(side="left", fill="x")
                self._build_tool_row(tool, row=0, parent=body_fr)

        _build_os_section(
            linux_tools, "linux", "🐧", "LINUX",
            COLORS.get("text_green", "#7EC8A0"))
        _build_os_section(
            win_tools, "windows", "🪟", "WINDOWS",
            COLORS.get("text_cyan", "#7EC8E3"))

    def _build_report_content(self):
        # Everything in the Reporting card is centered on the X axis.
        # Previously the "Generate a full Markdown report of this session."
        # subtitle and the "Session notes:" label rendered left-aligned
        # (sticky="w" / default anchor in a narrow column) while the
        # button sat dead-centre — visually uneven.  Now every label
        # uses `sticky=""` (grid default = center) + `anchor="center"`
        # and the notes box is pinned centrally with a capped width
        # instead of filling edge-to-edge.
        fr = ctk.CTkFrame(self._content_frame, fg_color="transparent")
        fr.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        fr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            fr, text="Generate a full Markdown report of this session.",
            font=_f("md"), text_color=COLORS["text_dim"],
            anchor="center", justify="center",
        ).grid(row=0, column=0, pady=(0, 8))

        ctk.CTkButton(
            fr, text="GENERATE MARKDOWN REPORT",
            width=280, height=34, font=_f("lg", True),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["text_cyan"], border_width=1,
            text_color=COLORS["text_cyan"], corner_radius=3,
            command=self._generate_report,
        ).grid(row=1, column=0, pady=4)

        ctk.CTkLabel(
            fr, text="Session notes:",
            font=_f("sm"), text_color=COLORS["text_muted"],
            anchor="center", justify="center",
        ).grid(row=2, column=0, pady=(10, 2))

        # Notes box — pin a max width + center it so the textbox
        # visually aligns with the button above it instead of
        # stretching to the card edges.
        self._notes_box = ctk.CTkTextbox(
            fr, height=80, width=560,
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            font=_f("md"))
        self._notes_box.grid(row=3, column=0, pady=(0, 6))
        add_context_menu(self._notes_box)

    # ─── Access Gate ──────────────────────────────────────────────────────────













    # ─── Request run — main routing ───────────────────────────────────────────


    # ─── Metasploit launcher (card RUN button) ────────────────────────────────




    # ─── Nmap routing ─────────────────────────────────────────────────────────








    # ─── Ping ─────────────────────────────────────────────────────────────────





    # ─── WEB ASSAULT — webapp profiler + attack planner ────────────────

    # ─── BLOODY CRAWL — smart HTML endpoint extractor ──────────────────────





    # ─── Hydra — port-aware with wordlist selection ───────────────────────────



    # ─── Hydra HTTP-POST-FORM — brute-force HTML login forms ──────────────

    # ─── Hydra SMB: warn when only 139 is open ──────────────────────────

    # ─── Hydra web wizard: pre-flight diagnostic ───────────────────────

    # ─── Hydra alternatives — for cases hydra can't handle ─────────────

    # ─── Universal wordlist picker ───────────────────────────────────────────


    # ─── Responder ────────────────────────────────────────────────────────────




    # ─── Responder — live watcher + status dialog ────────────────────





    # ─── Certipy (AD CS attacks) ──────────────────────────────────────────────


    # ─── Web tools ────────────────────────────────────────────────────────────














    # ─── SMB tools ────────────────────────────────────────────────────────────





    # ─── SNMP ─────────────────────────────────────────────────────────────────



    # ─── Probe UDP 161 then auto-proceed to SNMPWALK ──────────────────


    # ─── SNMP bruteforce with onesixtyone ─────────────────────────────



    # ─── Kerbrute ────────────────────────────────────────────────────────────


    # ─── Kerbrute — mode/fields coherence helpers ──────────────────────



    # ─── LDAPSEARCH ──────────────────────────────────────────────────────────


    # ─── Searchsploit ─────────────────────────────────────────────────────────


    def _run_searchsploit_inner(self, tool, fp):
        """Execution half of searchsploit — runs regardless of fingerprint
        quality.  Only reachable after the user confirms via the warning
        dialog or when the fingerprint is already specific enough."""
        terms = []

        if fp:
            if fp.platform == "windows" and fp.version:
                terms.append(f"Windows Server {fp.version.upper()}")
            elif fp.platform == "windows":
                terms.append("Windows")
            elif fp.platform == "linux":
                terms.append("Linux")

            import re
            for port, proto, svc, banner in fp.open_ports:
                if banner:
                    sw = re.search(r'([A-Za-z][A-Za-z0-9\-]+)[/ ](\d+[\d.]+)', banner)
                    if sw:
                        terms.append(f"{sw.group(1)} {sw.group(2)}")
                svc_clean = svc.lower().split("/")[0]
                if svc_clean == "microsoft-ds":
                    terms.append("MS17-010")
                elif svc_clean not in ("unknown","tcpwrapped","","msrpc","unknown"):
                    if svc_clean not in [t.lower() for t in terms]:
                        terms.append(svc_clean.upper())
        else:
            self.app.terminal.write(
                "[!] SEARCHSPLOIT skipped — no port scan data.\n"
                "    Run Port Scanning first.", "warn")
            return

        if not terms:
            self.app.terminal.write(
                "[!] SEARCHSPLOIT: no search terms from scan data.", "warn")
            return

        # Deduplicate
        seen, unique_terms = set(), []
        for t in terms:
            if t.lower() not in seen:
                seen.add(t.lower())
                unique_terms.append(t)

        self.app.terminal.section("VULNERABILITY ANALYSIS  ·  SEARCHSPLOIT")
        self._set_tool_status(tool.id, "running")
        self.set_status(STATUS_RUNNING)

        def _run_all():
            for term in unique_terms[:4]:
                cmd = f"searchsploit {term}"
                self.app.terminal.write(f"  $ {cmd}", "cmd")
                try:
                    from utils.runner import _hawk_env
                    result = subprocess.run(
                        ["searchsploit", term],
                        capture_output=True, text=True, timeout=30,
                        env=_hawk_env())
                    output = result.stdout + result.stderr
                    for line in output.splitlines():
                        if line.strip() and "Exploit Title" not in line:
                            level = ("finding"
                                     if any(k in line.lower()
                                            for k in ["exploit","remote","rce","exec"])
                                     else "dim")
                            self.app.terminal.write(f"  {line}", level)

                    # Parse exploits — extract title and EDB path
                    exploits = []
                    for l in output.splitlines():
                        if "/" in l and "|" in l and "Exploit Title" not in l:
                            parts = l.split("|")
                            if len(parts) >= 2:
                                title_part = parts[0].strip()
                                path_part  = parts[1].strip()
                                exploits.append((title_part, path_part))

                    if exploits and hasattr(self.app, "target_intel"):
                        # Emit one auto-finding per exploit so each gets its
                        # own INFO + MSF action buttons in Target Intel.
                        for title_part, path_part in exploits[:5]:
                            # Severity heuristic: RCE / remote / exec = high
                            low_title = title_part.lower()
                            if any(k in low_title for k in
                                   ("rce", "remote code", "unauthenticated",
                                    "command execution", "buffer overflow")):
                                sev = "high"
                            elif any(k in low_title
                                     for k in ("local", "dos", "denial")):
                                sev = "medium"
                            else:
                                sev = "medium"
                            desc = (f"{title_part}\n"
                                    f"EDB path: {path_part}\n"
                                    f"Copy: searchsploit -m {path_part}\n"
                                    f"View: searchsploit -x {path_part}")
                            self.app.after(0, lambda t=title_part,
                                           d=desc, s=sev: (
                                self.app.target_intel.add_auto_finding(
                                    title=t[:80],
                                    description=d,
                                    severity=s,
                                    source="searchsploit")
                            ))
                except Exception as e:
                    self.app.terminal.write(
                        f"  [!] searchsploit error: {e}", "error")

            self.app.after(0, lambda: [
                self._set_tool_status(tool.id, "done"),
                self._toggle_run_btn(tool, False),
                self.app.terminal.write("[+] SEARCHSPLOIT completed.", "success"),
            ])

        threading.Thread(target=_run_all, daemon=True).start()

    # ─── Specialized parser: sqlmap ──────────────────────────────────────────


    # ─── Specialized parser: SSH banner ──────────────────────────────────────


    # ─── Specialized parser: enum4linux ──────────────────────────────────────


    # ─── Kerbrute → valid users / logins → Credential Store + Intel ──────────


    # ─── Impacket GetNPUsers — AS-REP Roasting with user wordlist ────────────



    # Usernames that psexec/secretsdump/wmiexec will never
    # authenticate as — filtering them out of auto-fill avoids the
    # "dialog opens pre-filled with Anonymous:Anonymous" bug that
    # made every impacket run fail with STATUS_LOGON_FAILURE.
    _ANON_USERS_IMPACKET = {"anonymous", "anon", "guest",
                             "nobody", "null", ""}







    # Per-tool hints displayed at the top of the AD auth dialog.  Each
    # entry explains WHAT the tool does, WHAT it needs from the user,
    # WHAT output to expect, and TYPICAL extra flags you might want to
    # add.  Keep these concise — the dialog is already busy.  When a
    # tool id isn't in this dict the dialog falls back to the tool's
    # own `desc` field.
    _AD_TOOL_HINTS = {
        "bloodhound_python": {
            "purpose": (
                "Python implementation of SharpHound.  Walks the AD "
                "graph via LDAP + SMB and exports JSON files that "
                "HAWK renders as a native attack graph."),
            "needs":   "Any domain user (read access is enough).",
            "output":  "HAWK parses the ZIP automatically → Target Intel "
                       "(finding with Kerberoastable / AS-REP roastable / "
                       "Unconstrained-delegation computers), discovered "
                       "users → session, AND a post-collect summary "
                       "dialog with a VIEW ATTACK GRAPH button that "
                       "opens a full interactive graph of the domain "
                       "(bright = attackable, dark = rest; click any "
                       "node for details).  Raw .zip kept in the run dir "
                       "so you can still feed it to BloodHound CE for "
                       "Cypher queries.",
            "extras":  [
                "-c DCOnly             — only collect from the DC (faster)",
                "-c All                — full collection (default)",
                "-c Group,ACL          — pick specific methods",
                "--dns-tcp             — force DNS over TCP",
                "--disable-pooling     — if connection errors",
            ],
        },
        "ldapdomaindump": {
            "purpose": (
                "Pure-LDAP dump of the whole domain — users, groups, "
                "computers, GPOs.  Faster than BloodHound for a first "
                "look; output is HTML + JSON + grepable."),
            "needs":   "Any domain user (no admin needed).",
            "output":  "HAWK reads the *.grep files → discovered users & "
                       "computers pushed to the session + Target Intel "
                       "summary finding.  Raw HTML in "
                       "<HAWK>/outputs/ldapdump-<target>/ stays for "
                       "browser review.",
            "extras":  [
                "-at NTLM              — force NTLM auth",
                "--no-json             — skip JSON, HTML only",
                "--no-html             — grep/json only",
                "-r <resolve>          — resolve IPs to hostnames",
            ],
        },
        "nxc_ldap": {
            "purpose": (
                "NetExec LDAP module — one-liner enumeration: users, "
                "groups, admin-count outliers, kerberoastable / AS-REP "
                "roastable / trusted-for-delegation users."),
            "needs":   "Any domain user.  Accepts NTLM hash via -H.",
            "output":  "HAWK parses stdout → admin-count users / SPNs / "
                       "delegation flags surface in Target Intel.  "
                       "Discovered users added to the session.",
            "extras":  [
                "--kerberoasting out.txt   — dump TGS hashes to file",
                "--asreproast out.txt      — dump AS-REP hashes to file",
                "--password-not-required   — accounts with PASSWD_NOTREQD",
                "--dc-ip <ip>              — explicit DC (if target is a client)",
                "-k / --kerberos           — use Kerberos auth",
            ],
        },
        "getuserspns": {
            "purpose": (
                "Impacket GetUserSPNs — request service-ticket hashes "
                "(TGS-REP) for every user with an SPN.  Crack offline "
                "with hashcat mode 13100 → service-account password."),
            "needs":   "ANY domain user (SPN enumeration doesn't need "
                       "privilege).  Domain is required.",
            "output":  "HAWK auto-pushes each TGS hash → Credential Store "
                       "(AD RESULTS box, type 'Kerberos TGS', hashcat -m "
                       "13100 ready) + summary finding in Target Intel.  "
                       "Use CRACK from the store row.",
            "extras":  [
                "-no-preauth <user>       — if you only have pre-auth-disabled user",
                "-hashes :<NT>            — pass-the-hash instead of password",
                "-usersfile users.txt     — target specific users",
                "-target-domain <DOMAIN>  — cross-forest kerberoast",
            ],
        },
        "certipy_find": {
            "purpose": (
                "Certipy AD CS enumeration — lists Enterprise CAs, "
                "certificate templates, and ACLs.  Flags each misconfig "
                "by ESC number (ESC1–ESC11)."),
            "needs":   "Any domain user + the DC reachable.  "
                       "AD CS must be installed on the domain.",
            "output":  "HAWK parses 'Vulnerable to: ESCx' lines → one "
                       "Target Intel finding per vuln template, "
                       "severity=critical, with the certipy-req command "
                       "pre-baked (CA name + template name filled in).",
            "extras":  [
                "-vulnerable              — only show vuln templates",
                "-text                    — text-only output",
                "-json                    — emit machine-readable JSON",
                "-enabled                 — only enabled templates",
                "-stdout                  — default, already set",
            ],
        },
        "certipy_req": {
            "purpose": (
                "Certipy certificate request — abuses an ESC1-style "
                "template (ENROLLEE_SUPPLIES_SUBJECT + enrollable by "
                "domain users) to get a cert for a privileged user "
                "(e.g. Administrator).  The .pfx you get is a TGT "
                "machine for `certipy auth`."),
            "needs":   "Domain user + a vulnerable template + UPN of "
                       "the user you want to impersonate.  Get CA_NAME "
                       "and TEMPLATE from `certipy find` output first.",
            "output":  "<HAWK>/outputs/esc1.pfx on disk — hand it to certipy"
                       "auth (the PFX is binary, not parsed by HAWK).  "
                       "Terminal log shows the path.",
            "extras":  [
                "-upn Administrator@<DOM> — UPN to impersonate (required)",
                "-ca '<CA name>'          — the Enterprise CA name",
                "-template <name>         — the vuln template name",
                "-subject 'CN=foo'        — override subject (ESC6)",
                "-application-policies    — request specific EKUs",
            ],
        },
        "rbcd_attack": {
            "purpose": (
                "Resource-Based Constrained Delegation abuse.  Writes "
                "msDS-AllowedToActOnBehalfOfOtherIdentity on a target "
                "computer via an account that has GenericWrite on it, "
                "then S4U2self/S4U2proxy → any-user ticket for the "
                "target computer."),
            "needs":   "GenericWrite on the target computer + a "
                       "computer account you control (use addcomputer "
                       "tool first if you don't have one).  "
                       "'delegate-from' is YOUR computer, 'delegate-to' "
                       "is the target.",
            "output":  "Updates the RBCD attribute on the target — no "
                       "file produced.  Follow up with impacket-getST "
                       "(or run ticketer_golden) to forge the actual "
                       "ticket.  Terminal log confirms write success.",
            "extras":  [
                "-action read             — check current RBCD state",
                "-action remove           — clean up after the attack",
                "-delegate-from HAWK$     — the computer you control",
                "-delegate-to TARGET$     — the target computer",
                "-hashes :<NT>            — pass-the-hash",
            ],
        },
        "findDelegation": {
            "purpose": (
                "Impacket findDelegation — lists every user and "
                "computer with Unconstrained / Constrained / RBCD "
                "delegation flags set.  Any account with unconstrained "
                "delegation is a privilege-escalation goldmine."),
            "needs":   "Any domain user.  Read-only enumeration.",
            "output":  "Table printed to the HAWK terminal.  Look for "
                       "'Unconstrained' rows first — S4U hijack path.  "
                       "(No structured parser yet — the table is easy "
                       "to read inline.)",
            "extras":  [
                "-hashes :<NT>            — pass-the-hash",
                "-target-domain <DOMAIN>  — cross-forest",
                "-k / -no-pass            — Kerberos only",
            ],
        },
        "secretsdump_dcsync": {
            "purpose": (
                "Impacket secretsdump in remote DCSync mode — uses "
                "the DRSUAPI RPC to replicate hashes of EVERY domain "
                "user including krbtgt.  With krbtgt's hash you can "
                "forge Golden Tickets (see TICKETER)."),
            "needs":   "Account with 'Replicating Directory Changes' "
                       "rights.  By default only Domain Admins and "
                       "Enterprise Admins have it; check via BloodHound "
                       "for less-obvious paths (GenericAll on DC object, "
                       "AdminSDHolder abuse, etc.).",
            "output":  "HAWK parses every NTLM / DCC2 / Kerberos hash "
                       "line → each becomes a Credential Store entry "
                       "(AD RESULTS box) pre-tagged with the right "
                       "hashcat mode (-m 1000 / 2100 / 13100 / 18200).  "
                       "Target Intel summary shows totals + top 5 users. "
                       " Raw .ntds / .sam / .security also written to "
                       "<HAWK>/outputs/ for john/impacket-secretsdump "
                       "dump-tools.",
            "extras":  [
                "-just-dc                 — default, NTDS + krbtgt",
                "-just-dc-ntlm            — NTLM hashes only (skip Kerb keys)",
                "-history                 — include password history",
                "-user-status             — include account status",
                "-hashes :<NT>            — pass-the-hash",
            ],
        },
        "ticketer_golden": {
            "purpose": (
                "Impacket ticketer — forges a Golden Ticket offline.  "
                "Needs krbtgt's NTLM hash (from secretsdump) plus the "
                "domain SID.  Grants domain-wide access until krbtgt "
                "is rotated twice."),
            "needs":   "krbtgt NTLM hash (paste into Password field) + "
                       "domain SID (from `whoami /user` or `wmic useraccount "
                       "get sid` on any joined host).",
            "output":  "Administrator.ccache on disk — use from the "
                       "OPEN SHELL button:\n"
                       "    export KRB5CCNAME=Administrator.ccache\n"
                       "    impacket-psexec -k -no-pass <dom>/admin@<dc>",
            "extras":  [
                "-aesKey <hex>            — AES256 instead of NTLM (safer)",
                "-groups 512,513,518,519  — specific SIDs",
                "-request                 — request TGS after forging",
                "-extra-sid S-1-5-21-...  — add cross-forest SID for SID history",
            ],
        },
        "addcomputer": {
            "purpose": (
                "Impacket addcomputer — any domain user can add up to "
                "10 computer accounts by default (ms-DS-MachineAccount"
                "Quota = 10).  Prerequisite for RBCD chains and "
                "'delegate-from' in rbcd_attack."),
            "needs":   "Any domain user + domain not locked down "
                       "(MAQ > 0).  Check MAQ with "
                       "`ldapsearch ... objectclass=domain ms-DS-Mac"
                       "hineAccountQuota`.",
            "output":  "HAWK parses the 'Successfully added machine "
                       "account X with password Y' line → pushes X:Y "
                       "to the Credential Store (AD RESULTS box, "
                       "service=AD/Computer) + Target Intel finding "
                       "with the cleanup command.  No file on disk — "
                       "the account lives in AD.",
            "extras":  [
                "-computer-name FOO$      — custom name (keep the $)",
                "-computer-pass 'Pass1'   — custom password",
                "-method SAMR             — SAMR instead of LDAP",
                "-delete                  — remove the account you created",
            ],
        },
        "adidnsdump": {
            "purpose": (
                "Dumps ALL DNS records from the AD-integrated DNS zone "
                "(CN=MicrosoftDNS,CN=System,...).  Reveals every "
                "hostname → IP the domain knows about — uncovering "
                "hosts on segments you haven't scanned yet."),
            "needs":   "Any domain user (AD DNS zone is world-readable "
                       "by default).",
            "output":  "HAWK reads records.csv → Target Intel finding "
                       "with the full host → IP table (first 40 rows "
                       "shown inline, rest in the .csv).  Use these "
                       "as new targets for your scan scope.",
            "extras":  [
                "--print-zones            — default, list zones too",
                "-r                       — resolve records HAWK can reach",
                "--zone <name>            — dump a specific zone",
                "--dns-tcp                — force DNS TCP",
            ],
        },
    }

    # ─── Certipy req — prerequisite check + auto-prefill ─────────────



    # ─── RBCD attack — prerequisite check + attacker-computer prefill ─

    # ─── Ticketer — Golden/Silver ticket forge ─────────────────────────

    # ─── Certipy AUTH — PKINIT with a .pfx ────────────────────────────






    # ─── AS-REP single-user (from BloodHound graph button) ──────────────

    # ─── Public: prefilled tool launcher (from BloodHound graph) ────────

    # ─── Gobuster / Dirb → structured directory listing to Target Intel ──────

    # ─── Target-domain candidate detection ────────────────────────────────



    # ─── Linux Capabilities → structured privesc finding ─────────────────────


    # ─── Nuclei → structured Target Intel (per-template findings) ────────────


    # ─── AD-pentesting tool parsers ─────────────────────────────────────
    # Each one generates a single run_id via utils.run_id.new_run_id()
    # and attaches it to every pushed credential + finding, enabling
    # the →INTEL / 🔑 CREDS UI navigation.











    # ─── Traceroute → structured Target Intel finding ─────────────────────────


    # ─── Generic tool output → Intel ──────────────────────────────────────────

    # ANSI CSI escape sequences (colors, cursor moves). Tools like nuclei,
    # wafw00f and ffuf paint their banner in ANSI color which otherwise
    # fools the decoration/alnum ratio check below.
    _ANSI_RE = __import__("re").compile(r"\x1b\[[0-9;]*[A-Za-z]")

    @staticmethod
    def _is_ascii_banner_line(line: str) -> bool:
        """Return True for lines that are mostly ASCII-art / decoration.

        Catches the large FIGlet-style banners that ffuf, wafw00f, nikto,
        nuclei and similar tools print on startup — these lines end up in
        Target Intel descriptions and overwhelm the actual findings.

        Strips ANSI color codes first so lines like '\\x1b[34m___/\\x1b[0m'
        are scored on their visible content, not on the digits inside the
        escape sequence.
        """
        s = KillChainCard._strip_ansi(line).strip()
        if not s:
            return False
        # Separator strips: ===, ---, ___ etc.
        if len(set(s)) <= 2 and s[0] in "=-_*~#":
            return True
        # Known tool-banner signature lines (nuclei, ffuf, wafw00f, sqlmap).
        low = s.lower()
        if "projectdiscovery.io" in low or "sqlmap.org" in low:
            return True
        # Count "decorative" vs alphanumeric characters.
        deco = sum(1 for c in s if c in "/\\|_-=+*<>()[]{}^~`'\"!?.,:;")
        alnum = sum(1 for c in s if c.isalnum())
        total = len(s)
        # Mostly decoration, very little alnum → banner row.
        if total >= 6 and alnum <= 3 and deco / total >= 0.5:
            return True
        # A line that is dominated by slashes/backslashes/underscores/pipes
        # and brackets is banner even if a trailing version string contributes
        # a few alnum chars. Covers:
        #   '/_/ /_/\\__,_/\\___/_/   v3.3.0'          (nuclei/ffuf)
        #   '___ ___[\']_____ ___ ___  {1.7.2#stable}' (sqlmap)
        deco_wide = (s.count("/") + s.count("\\") + s.count("_") +
                     s.count("|") + s.count("[") + s.count("]") +
                     s.count("{") + s.count("}"))
        if total >= 10 and deco_wide / total >= 0.5:
            return True
        # Runs of >=3 backslashes or slashes are a strong ASCII-art signal.
        if "\\\\\\" in s or "////" in s or s.count("\\") >= 4:
            return True
        return False

    def _parse_output_to_intel(self, tool, log: list):
        """
        Generic: any significant output from any tool → Target Intel.
        """
        if not hasattr(self.app, "target_intel"):
            return

        SEV_KEYWORDS = {
            "critical": ["critical","rce","remote code","arbitrary code","ms17-010",
                         "eternalblue","ms08-067","bluekeep"],
            "high":     ["vulnerable","exploit","high","cve-","anonymous login",
                         "anonymous access","writable","default credentials"],
            "medium":   ["medium","found","detected","open","allowed","enabled"],
            "info":     [],
        }

        significant = []
        for level, line in log:
            line_s = line.strip()
            if not line_s:
                continue
            if level in ("error",) and not any(
                    k in line_s.lower() for k in ["found","vulnerable","allowed"]):
                continue
            if len(line_s) < 5:
                continue
            # Skip FIGlet / box-art banner rows so the intel finding isn't
            # dominated by decoration from tools like ffuf, wafw00f, nikto.
            if self._is_ascii_banner_line(line_s):
                continue
            # Skip Certipy / impacket / netexec warning-marker lines —
            # these start with "[-]" and almost always indicate an error
            # or a negative result rather than a finding. Leaving them in
            # causes fake "CERTIPY — <target>" entries in Target Intel when
            # the tool actually failed. Real findings use "[+]" or "[*]".
            if line_s.startswith("[-]"):
                continue
            significant.append(line_s)

        if not significant:
            return

        # Determine severity
        all_text = " ".join(significant).lower()
        severity = "info"
        for sev, keywords in SEV_KEYWORDS.items():
            if any(k in all_text for k in keywords):
                severity = sev
                break

        if severity == "info" and len(significant) <= 2:
            return  # Skip trivial info

        # Build description from first meaningful lines
        desc = "\n".join(significant[:6])
        # Scope-rich title — _extract_web_target_label returns a full
        # URL for web tools (so re-runs on different targets / paths
        # land as distinct findings) and the bare target for non-web
        # tools (smb, kerbrute, ...).  Keeps the merge-by-title
        # semantics in target_intel correct: same scope = merge,
        # different scope = new card.
        try:
            scope = self._extract_web_target_label(tool)
        except Exception:
            scope = self._get_target() or "target"
        title = f"{tool.name} on {scope}"

        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title,
            description=desc,
            severity=severity,
            source=tool.name))

    # ─── OSINT pre-flight (target validation + API keys) ─────────────────────






    # Tools that actually consume API keys from sessions/.apikeys.json. Everything
    # else in _DOMAIN_REQUIRED (dnsrecon, fierce, dnsenum, assetfinder) works
    # entirely offline / against public DNS, so the key dialog is not relevant.
    _KEY_AWARE_OSINT = ("subfinder", "amass", "theharvester")





    # ─── Execution ────────────────────────────────────────────────────────────


    # Tools whose install command is fragile / distro-specific. For these we
    # show instructions only and let the user install manually. They reappear
    # as runnable once `is_available()` becomes True.
    _MANUAL_INSTALL_IDS = {
        "rustscan", "kerbrute", "kerbrute_userenum",
    }











    def _open_peas_workflow(self, tool):
        """After a PEAS-family download completes, open the interactive
        workflow dialog (host via HTTP, transfer commands, exec, exfil,
        review). Handles path/OS detection so the dialog pre-fills the
        right defaults.

        The on-disk filename matches the `-o <name>` argument baked into
        each tool's cmd_template (see modules/post_exploit.py):
          linpeas → linpeas.sh
          winpeas → winpeas.bat
          lse     → lse.sh
          pspy    → pspy64
        """
        import os
        fname_map = {
            "linpeas":       ("linpeas.sh",        "linux"),
            "winpeas":       ("winpeas.bat",       "windows"),
            # Compiled winPEAS — same workflow dialog as the .bat,
            # BUT the script_name is overridden downstream when the
            # user picked a specific variant in the preflight (e.g.
            # Invoke-WinPEAS.ps1 needs the .ps1 execute commands).
            "winpeas_exe":   ("winpeas.exe",       "windows"),
            # PrivescCheck.ps1 — same workflow with PS-specific
            # execute commands (AMSI bypass + Invoke-PrivescCheck).
            "privesc_check":    ("PrivescCheck.ps1",  "windows"),
            # PowerUp.ps1 — PowerSploit privesc script, PS workflow
            # with Invoke-AllChecks.  Output is human-readable text.
            "powerup_download": ("PowerUp.ps1",       "windows"),
            "lse":              ("lse.sh",             "linux"),
            "pspy":             ("pspy64",             "linux"),
        }
        if tool.id not in fname_map:
            return
        script_name, os_type = fname_map[tool.id]

        # ── winpeas.exe preflight override ──────────────────────
        # If the user went through the smart preflight picker and
        # chose a variant (especially the PS1 port), we need to
        # rewrite script_name + local_name so the PEAS Workflow
        # dialog downstream picks the right file and the .ps1 /
        # .exe execute templates in Step 3.
        if tool.id == "winpeas_exe":
            variant = getattr(self,
                              "_winpeas_exe_chosen_variant", None)
            if variant:
                script_name = variant.get("script_name",
                                           script_name)
                # local_name matches what curl saved via -o flag
                local_name = variant.get("local_name",
                                          "winpeas.exe")
            else:
                local_name = "winpeas.exe"
        else:
            local_name = script_name

        # The curl command in post_exploit.py runs from HAWK's CWD,
        # so that's where the file lands.  We look for `local_name`
        # (the name curl saved via -o) rather than `script_name`
        # because the winpeas.exe preflight may have downloaded a
        # .ps1 that we want the workflow dialog to treat AS a ps1
        # while the file on disk is just winpeas.ps1.
        local_path = os.path.join(os.getcwd(), local_name)
        if not os.path.isfile(local_path):
            self.app.terminal.write(
                f"  [!] {local_name} not found at {local_path} — "
                f"skipping workflow dialog.", "warn")
            return

        target = self._get_target() or ""
        try:
            from gui.dialogs import PostExploitGuideDialog
            # stealth_on defaults to False — user toggles it inside
            # the dialog via the per-workflow STEALTH MODE button.
            PostExploitGuideDialog(
                self, script_name=script_name,
                local_path=local_path,
                target=target, os_type=os_type,
                app=self.app,
                stealth_on=False)
            self.app.terminal.write(
                f"  [+] PEAS workflow dialog opened — "
                f"follow the 5 steps to pivot onto the target.",
                "success")
        except Exception as e:
            self.app.terminal.write(
                f"  [!] Could not open workflow dialog: {e}", "error")







    # ── Python-env breakage detector ──────────────────────────────────────────

    # Packages that HAWK knows how to reinstall cleanly. The list maps a
    # tool.binary → pipx package name. Anything not in the map falls back
    # to a generic "upgrade python tooling" hint.
    # Keys here are lowercased tool.binary names. We include ALL impacket
    # entrypoints — the venv publishes ~17 of them on install, and any of
    # them can be reached either from the Exploitation card or from a
    # Target Intel "▶ EXPLOIT WITH" shortcut. If a user hits one that
    # isn't listed, they get a generic "upgrade python tooling" fallback
    # which doesn't know the right pipx package name.
    _PYTHON_TOOL_PIPX = {
        # Impacket suite — one pipx install covers all of these
        "impacket-psexec":           "impacket",
        "impacket-secretsdump":      "impacket",
        "impacket-getnpusers":       "impacket",
        "impacket-getuserspns":      "impacket",
        "impacket-smbclient":        "impacket",
        "impacket-smbserver":        "impacket",
        "impacket-wmiexec":          "impacket",
        "impacket-atexec":           "impacket",
        "impacket-dcomexec":         "impacket",
        "impacket-lookupsid":        "impacket",
        "impacket-samrdump":         "impacket",
        "impacket-rpcdump":          "impacket",
        "impacket-ntlmrelayx":       "impacket",
        "impacket-goldenpac":        "impacket",
        "impacket-ticketer":         "impacket",
        "impacket-get-gpppassword":  "impacket",
        "impacket-mssqlclient":      "impacket",
        "impacket-reg":              "impacket",
        "impacket-services":         "impacket",
        "impacket-mqtt_check":       "impacket",
        # Other Python-env tools
        "certipy-ad":            "certipy-ad",
        "pwncat-cs":             "pwncat-cs",
        "smbmap":                "smbmap",
        "netexec":               "netexec",
        "nxc":                   "netexec",
        "theharvester":          "theHarvester",
    }








    # Run-all flow removed: _run_all / _do_run_all / _stop_all /
    # _on_run_all_done used to orchestrate every tool of a phase
    # concurrently.  In practice this was racy (hydra + sqlmap + nmap
    # hitting the same HTTP port at once produced garbage logs) and
    # the per-tool RUN buttons already give finer control.  The
    # MultiRunner import is preserved because other call sites may
    # still need it.

    # ─── Report ───────────────────────────────────────────────────────────────

    def _generate_report(self):
        if not self.app.session_manager.current:
            self.app.terminal.write("[!] No active session.", "error")
            return
        session = self.app.session_manager.current
        if hasattr(self, "_notes_box"):
            session.notes = self._notes_box.get("1.0", "end").strip()

        # The report reads the SESSION, but the live auto-findings live in
        # the Target Intel panel and only reach the session when somebody
        # saves — and autosave is off by default.  Without this the very
        # normal "run the tools, click REPORT" flow shipped a report with
        # zero findings and no Target Intelligence section, silently.
        from utils.target_intel_sync import sync_target_intel
        sync_target_intel(self.app, session)

        # Pre-export curation: the operator reviews / excludes / overrides
        # findings in a dedicated dialog, then "Generate report" runs the
        # engine on exactly the curated set.  The dialog calls back with
        # the primary deliverable path (the one-path contract is kept).
        def _done(path):
            if not path:
                self.app.terminal.write(
                    "  [!] Report not generated.", "warn")
                return
            self.set_status(STATUS_DONE)
            self.app.terminal.section("REPORT GENERATED")
            self.app.terminal.write(f"  [+] {path}", "success")

        try:
            from gui.widgets.curation_dialog import open_curation_dialog
            open_curation_dialog(self.app, session, on_generated=_done)
        except Exception as e:
            self.app.terminal.write(f"[!] Report failed: {e}", "error")

    # ─── UI helpers ───────────────────────────────────────────────────────────

    def set_status(self, status: str):
        """Record the phase's current status + propagate to session
        and the bottom status bar.  The in-card badge was removed
        (user wanted the header clean) so we just skip the widget
        update — no other callers.
        """
        self._status = status
        if self.app.session_manager.current:
            self.app.session_manager.current.set_phase_status(
                self.phase_id, status.lower())
        self.app.status_bar.set_phase(self.phase_config["name"], status)

    def _set_tool_status(self, tid, status):
        w = self._tool_widgets.get(tid)
        if not w:
            return
        icon, color = TOOL_STATUS_ICONS.get(status, ("○", COLORS["text_muted"]))
        w["icon"].configure(text=icon, text_color=color)
        w["_status"] = status

    def _toggle_run_btn(self, tool, running: bool):
        w = self._tool_widgets.get(tool.id)
        if not w:
            return
        avail = tool.is_available() or (tool.id == "greenbone")
        btn   = w["run_btn"]
        if running:
            btn.configure(text="STOP",
                          border_color=COLORS["text_red"],
                          text_color=COLORS["text_red"],
                          command=lambda t=tool: self._stop_tool(t))
        else:
            btn.configure(text="RUN",
                          border_color=COLORS["border_green"] if avail
                          else COLORS["border_dim"],
                          text_color=COLORS["text_green"] if avail
                          else COLORS["text_muted"],
                          command=lambda t=tool: self._gate_check(t))

    def _stop_tool(self, tool):
        r = self._tool_runners.get(tool.id)
        if r:
            r.kill()
        self._set_tool_status(tool.id, "error")
        self._toggle_run_btn(tool, False)

    def _toggle_expand(self):
        """Collapse / expand the card body.  Persists the new state
        into the current session so re-opening HAWK restores the
        same layout, and cancels any pending blink-alert (if the
        user was expanding a card that had a pending activity flag).
        """
        if self._expanded:
            self._content_frame.grid_remove()
            self._toggle_btn.configure(text="▶")
        else:
            self._content_frame.grid()
            self._toggle_btn.configure(text="▼")
            # Expanding clears the blink flag — user is now looking
            # at the activity, no need to keep nagging the border.
            self._clear_blink()
        self._expanded = not self._expanded
        self._persist_collapse_state()

    def _persist_collapse_state(self):
        """Write this card's collapsed bool into the current session
        so it survives across HAWK restarts.  No-op without a session.
        """
        try:
            sess = self.app.session_manager.current
            if sess is None:
                return
            if not hasattr(sess, "card_collapsed"):
                sess.card_collapsed = {}
            # Store the NEGATION of `_expanded` so the JSON key name
            # matches what it represents (True = card is collapsed).
            sess.card_collapsed[self.phase_id] = (not self._expanded)
            if hasattr(sess, "_touch"):
                sess._touch()
        except Exception as e:
            print(f"[HAWK] persist card collapse state failed: {e}")

    def _restore_collapse_state(self):
        """Called once at the end of __init__ after the header/content
        are built.  If the session remembers this card as collapsed,
        mirror that state visually without going through the toggle
        animation path (so there's no flash of the body)."""
        try:
            sess = self.app.session_manager.current
            if sess is None:
                return
            collapsed = (getattr(sess, "card_collapsed", {}) or
                          {}).get(self.phase_id, False)
            if collapsed and self._expanded:
                # Call the normal toggle so button text flips too,
                # but suppress the immediate re-save (redundant).
                self._content_frame.grid_remove()
                self._toggle_btn.configure(text="▶")
                self._expanded = False
        except Exception as e:
            print(f"[HAWK] restore collapse state failed: {e}")

    # ─── Blink-alert when a tool finishes while collapsed ─────────────
    def _notify_activity(self, is_error: bool = False):
        """Called by _on_done when a tool inside this card transitions
        to done/error.  If the card is CURRENTLY EXPANDED the user is
        already watching — do nothing.  If COLLAPSED, set the blink
        state (error wins over plain activity) and start the border
        pulse loop.
        """
        if self._expanded:
            return
        new_state = "error" if is_error else "activity"
        # Error always wins; once red, a later "activity" doesn't
        # downgrade to yellow.
        if self._blink_state == "error" and new_state == "activity":
            return
        self._blink_state = new_state
        if self._blink_job is None:
            self._blink_loop()

    def _blink_loop(self):
        """Periodic border-colour toggle.  Rescheduled via after(600).
        Cancels itself when `_blink_state` is cleared.
        """
        if self._blink_state is None:
            self._blink_job = None
            # Restore the neutral border.
            try:
                self.configure(border_color=COLORS["border_dim"])
            except Exception:
                pass
            return
        # Pick the "bright" colour for this state.
        hot = (COLORS["text_red"] if self._blink_state == "error"
               else COLORS["border_amber"])
        cold = COLORS["border_dim"]
        self._blink_phase = (self._blink_phase + 1) % 2
        try:
            self.configure(
                border_color=(hot if self._blink_phase else cold))
        except Exception:
            pass
        self._blink_job = self.after(600, self._blink_loop)

    def _clear_blink(self):
        self._blink_state = None
        if self._blink_job is not None:
            try:
                self.after_cancel(self._blink_job)
            except Exception:
                pass
            self._blink_job = None
        try:
            self.configure(border_color=COLORS["border_dim"])
        except Exception:
            pass

    def _get_target(self):
        t = self.app.get_target()
        if not t:
            self.app.terminal.write(
                "[!] No target IP. Start a session first.", "error")
        return t
