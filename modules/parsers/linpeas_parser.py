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
HAWK — linPEAS output parser.

Consumes the ANSI-stripped text produced by linpeas.sh and extracts
actionable findings / credentials into HAWK's Target Intel and
Credential Store.

Mirrors the design of winpeas_parser.py — same public entry point
signature, same section-splitter approach, same push-to-intel+creds
orchestration, same structured-.txt writer.  Differences are only in
what Linux vs Windows considers a privilege-escalation vector.

Sections extracted:
  * Basic system + kernel info (info hint, cross-check with OS fp)
  * Sudo rules (HIGH if NOPASSWD / wildcard / !authenticate)
  * SUID binaries (HIGH if in GTFOBins shortlist)
  * File capabilities (HIGH if cap_setuid / cap_dac_read_search / ...)
  * Cron jobs with writable paths (HIGH)
  * Writable /etc/passwd or shadow (CRITICAL)
  * Docker / LXD group membership (HIGH)
  * NFS exports with no_root_squash (HIGH)
  * SSH private keys readable (HIGH + credentials pushed as key type)
  * Passwords found in files (HIGH + credentials)
  * Writable folders in PATH (HIGH)
  * Installed packages (single info finding)
  * Summary finding with severity tally
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime
from typing import Optional


# ─── GTFOBins shortlist ─────────────────────────────────────────────
# Curated subset of binaries whose SUID (or sudo-able) presence is a
# straight path to root via GTFOBins.  We flag any SUID binary whose
# basename is in this list as HIGH.  Full GTFOBins has ~300 entries;
# we keep the 40 most common/reliable ones to avoid false positives
# from uncommon binaries that only have edge-case escapes.
_GTFOBINS_SUID = {
    "aa-exec", "ash", "awk", "bash", "bundler", "busctl", "busybox",
    "c89", "c99", "cat", "chown", "chroot", "cp", "cpulimit", "csh",
    "curl", "dash", "date", "dd", "dmsetup", "docker", "dstat",
    "emacs", "env", "expand", "expect", "file", "find", "flock",
    "ftp", "gawk", "gcore", "gdb", "gimp", "git", "grep", "gtester",
    "head", "ionice", "iptables", "jjs", "journalctl", "jq", "knife",
    "ksh", "ksshell", "ld.so", "less", "logsave", "lua", "make",
    "man", "mawk", "more", "mount", "multitime", "mv", "nano", "nc",
    "ncdu", "nice", "nl", "nmap", "nohup", "node", "ntpdate",
    "openssl", "openvpn", "parted", "perl", "pg", "php", "pidstat",
    "pip", "posh", "python", "python2", "python3", "rake", "readelf",
    "rlogin", "rlwrap", "rpm", "rsync", "ruby", "run-parts", "rvim",
    "scp", "screen", "script", "sed", "service", "setarch", "sftp",
    "sh", "shuf", "smbclient", "socat", "soelim", "sqlite3", "ss",
    "ssh", "start-stop-daemon", "stdbuf", "strace", "strings", "su",
    "sudo", "systemctl", "systemd-resolve", "tar", "taskset", "tclsh",
    "tcpdump", "tee", "telnet", "tftp", "tic", "time", "timeout",
    "tmux", "top", "ul", "unexpand", "uniq", "unshare", "unsquashfs",
    "unzip", "update-alternatives", "vi", "vigr", "vim", "vipw",
    "wall", "watch", "wget", "whiptail", "xargs", "xxd", "yash",
    "zip", "zsh", "zsoelim",
}


# ─── Dangerous capabilities (getcap output) ─────────────────────────
_DANGEROUS_CAPS = {
    "cap_setuid": (
        "Set arbitrary UID → bin can become root directly.  "
        "Example (Python): "
        "`python3 -c 'import os; os.setuid(0); os.system(\"bash\")'`."),
    "cap_setgid": (
        "Set arbitrary GID → bin can join root's group, often a step "
        "toward file-privilege escalation."),
    "cap_dac_read_search": (
        "Bypass file-read permission checks → can read /etc/shadow, "
        "any user's private keys, etc."),
    "cap_dac_override": (
        "Bypass file-write permission checks → can modify any file "
        "(typically chain with cap_dac_read_search)."),
    "cap_sys_admin": (
        "Essentially root.  Can mount filesystems, change the "
        "hostname, etc."),
    "cap_sys_ptrace": (
        "Inspect/control any process → inject code into a root "
        "process and read its memory."),
    "cap_chown": (
        "Change file ownership without being root → can chown "
        "critical files to yourself."),
    "cap_fowner": (
        "Bypass permission checks on operations requiring ownership "
        "→ chmod arbitrary files."),
    "cap_net_raw": (
        "Raw socket access → ARP/DHCP spoofing, packet sniffing on "
        "interfaces not normally visible."),
    "cap_sys_module": (
        "Load/unload kernel modules → straight path to kernel-mode "
        "code execution."),
}


# ─── Secret-name env detector (shared with winpeas style) ───────────
_SECRET_ENV_RE = re.compile(
    r"(?i)(pass|pwd|secret|token|key|api[_-]?key|auth|credential|"
    r"session|cookie|private[_-]?key|access[_-]?key|bearer)")


_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


# ═════════════════════════════════════════════════════════════════════
#  Public entry point
# ═════════════════════════════════════════════════════════════════════

def parse_linpeas(text: str,
                  app,
                  target: str,
                  source_file: Optional[str] = None) -> dict:
    """Parse the ANSI-stripped linPEAS text output.

    Same contract as parse_winpeas — pushes findings into
    app.target_intel.add_auto_finding and credentials into
    app.cred_store.add_credential, writes a structured `.txt` sibling
    if source_file is given, returns a stats dict."""
    text = _ANSI_RE.sub("", text)

    run_id = _new_run_id()
    sections = _split_into_sections(text)

    findings: list[dict] = []
    creds:    list[dict] = []

    section_reports = []
    section_reports.append(_parse_system_info(sections, target, findings))
    section_reports.append(_parse_sudo_rules(sections, target, findings))
    section_reports.append(_parse_suid_binaries(sections, target, findings))
    section_reports.append(_parse_capabilities(sections, target, findings))
    section_reports.append(_parse_cron_jobs(sections, target, findings))
    section_reports.append(_parse_writable_critical_files(
        sections, target, findings))
    section_reports.append(_parse_group_memberships(
        sections, target, findings))
    section_reports.append(_parse_nfs_exports(sections, target, findings))
    section_reports.append(_parse_ssh_keys(
        sections, target, findings, creds))
    section_reports.append(_parse_passwords_in_files(
        sections, target, findings, creds))
    section_reports.append(_parse_writable_path(
        sections, target, findings))
    section_reports.append(_parse_env_secrets(sections, target, findings))
    section_reports.append(_parse_installed_packages(
        sections, target, findings))

    section_reports = [s for s in section_reports if s]

    sev_counts = {"critical": 0, "high": 0, "medium": 0,
                  "low": 0, "info": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    if source_file:
        try:
            _write_structured_txt(
                source_file, text, section_reports,
                findings, creds, sev_counts, target)
        except Exception as e:
            _term_warn(app,
                        f"  [!] Could not write structured .txt: {e}")

    for f in findings:
        _push_finding(app, f, run_id)
    for c in creds:
        _push_credential(app, c, run_id)

    summary_title = f"linPEAS parsed — {target}"
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
        txt_sibling = os.path.splitext(source_file)[0] + ".txt"
        summary_desc_lines.append("")
        summary_desc_lines.append(f"Readable copy: {txt_sibling}")

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
            source="linpeas parser",
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
#  Section splitter
# ═════════════════════════════════════════════════════════════════════
# linPEAS uses the same box-drawing markers as winPEAS.  Some sections
# are prefixed with extra `╔═══╣` lines and some subsections with
# `═══╣`; we match the first-level and slice between them.
_SECTION_HEADER_RE = re.compile(
    r"^\s*[╔╠][═─]{2,}[╣═─].*$")

_SECTION_TITLE_RE = re.compile(
    r"[╣═─]\s*([^╣═─]+?)\s*$")


def _split_into_sections(text: str) -> dict[str, str]:
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
    kws = [k.lower() for k in keywords]
    for title, body in sections.items():
        if all(k in title for k in kws):
            return body
    return None


# ═════════════════════════════════════════════════════════════════════
#  Individual section parsers
# ═════════════════════════════════════════════════════════════════════

def _parse_system_info(sections, target, findings):
    """Kernel, distro, uptime.  Info-only finding with a hint to
    cross-check with the target's OS fingerprint before trusting any
    CVE suggestion linPEAS emits inline."""
    body = (_find_section(sections, "system", "information")
            or _find_section(sections, "basic", "information")
            or _find_section(sections, "kernel"))
    if not body:
        return None

    # linPEAS dumps `uname -a` and /etc/os-release.
    kernel = _scrape(body, r"Linux\s+\S+\s+([\d\.\-a-zA-Z]+)")
    distro = _scrape(body, r"PRETTY_NAME=\"([^\"]+)\"")
    if not distro:
        distro = _scrape(body, r"Distributor ID:\s*(\S+)")

    desc_lines = []
    if distro: desc_lines.append(f"Distro       : {distro}")
    if kernel: desc_lines.append(f"Kernel       : {kernel}")
    desc_lines.append("")
    desc_lines.append(
        "Hint: this result is safe — cross-check with your OS "
        "fingerprint if you want.  If linPEAS suggests a kernel "
        "exploit inline, verify the CVE applies to the EXACT kernel "
        "version before trying it (many kernel exploit suggester "
        "hits are false positives on patched builds).")

    findings.append({
        "title":       f"linPEAS — system info ({distro or target})",
        "description": "\n".join(desc_lines),
        "severity":    "info",
        "source":      "linpeas parser",
    })
    return {"name": "System Information", "body": body}


def _parse_sudo_rules(sections, target, findings):
    """`sudo -l` output — NOPASSWD, wildcards, !authenticate."""
    body = (_find_section(sections, "sudo", "-l")
            or _find_section(sections, "checking", "sudo")
            or _find_section(sections, "sudo", "version"))
    if not body:
        # linPEAS sometimes puts sudo -l output in an unnamed block
        # immediately after "Sudo version"; fall back to full scan.
        body = "\n".join(sections.values())

    findings_here = []

    # NOPASSWD matches are the strongest signal.
    nopasswd_lines = []
    for line in body.splitlines():
        if "NOPASSWD" in line and ("(" in line or "!" in line):
            nopasswd_lines.append(line.strip())

    if nopasswd_lines:
        findings.append({
            "title":       f"Sudo NOPASSWD rule(s) found ({len(nopasswd_lines)})",
            "description": (
                f"The current user has sudo rules with NOPASSWD on "
                f"{target}.\nCheck each target binary against GTFOBins "
                f"— most NOPASSWD entries are direct root paths.\n\n"
                + "\n".join(f"  • {ln}" for ln in nopasswd_lines[:20])),
            "severity":    "high",
            "source":      "linpeas parser",
        })
        findings_here.append("nopasswd")

    # Wildcards in sudo rules → argument injection / path traversal.
    wild_lines = [ln.strip() for ln in body.splitlines()
                  if re.search(r"\([^)]+\)\s+\S+\s*\*", ln)]
    if wild_lines:
        findings.append({
            "title":       f"Sudo rules with wildcards ({len(wild_lines)})",
            "description": (
                "Wildcards in sudo rules allow argument injection — "
                "if the target binary reads files or executes child "
                "processes, the wildcard can often be abused to run "
                "arbitrary commands.\n\n"
                + "\n".join(f"  • {ln}" for ln in wild_lines[:10])),
            "severity":    "high",
            "source":      "linpeas parser",
        })
        findings_here.append("wildcard")

    # !authenticate bypasses password check entirely.
    if re.search(r"!authenticate", body, re.I):
        findings.append({
            "title":       "Sudo !authenticate flag detected",
            "description": (
                "The sudo config has an `!authenticate` directive — "
                "the current user can sudo without a password for "
                "matching rules.  Often a misconfiguration left over "
                "from automation."),
            "severity":    "high",
            "source":      "linpeas parser",
        })
        findings_here.append("noauth")

    if not findings_here:
        return None
    return {"name": "Sudo Rules", "body": body}


def _parse_suid_binaries(sections, target, findings):
    """SUID root binaries — flag any GTFOBins-known one as HIGH."""
    body = (_find_section(sections, "suid")
            or _find_section(sections, "suid", "files")
            or _find_section(sections, "suid", "gid"))
    if not body:
        return None

    gtfo_hits = []
    all_suids = []
    # SUID lines in linPEAS look like:
    #   -rwsr-xr-x 1 root root 61240 /bin/mount
    for line in body.splitlines():
        m = re.match(
            r"^\s*(-[rwxsSTt-]{9})\s+\d+\s+\S+\s+\S+\s+\d+\s+"
            r"(/\S+)", line)
        if not m:
            continue
        perms, path = m.group(1), m.group(2)
        if "s" not in perms.lower():
            continue
        all_suids.append(path)
        basename = os.path.basename(path).lower()
        if basename in _GTFOBINS_SUID:
            gtfo_hits.append((basename, path))

    if not all_suids:
        return None

    if gtfo_hits:
        lines = [f"  • {b}  →  {p}"
                 for b, p in gtfo_hits[:20]]
        findings.append({
            "title":       f"GTFOBins-exploitable SUID binaries "
                           f"({len(gtfo_hits)})",
            "description": (
                f"SUID binaries on {target} that have known GTFOBins "
                f"escapes to root.  Look each one up on gtfobins.github.io "
                f"and pick the simplest one.\n\n"
                + "\n".join(lines)),
            "severity":    "high",
            "source":      "linpeas parser",
        })

    # Always attach a general SUID info-finding listing ALL SUIDs so
    # the user has the full picture even for binaries we don't flag.
    findings.append({
        "title":       f"All SUID binaries ({len(all_suids)})",
        "description": (
            f"Full list of SUID binaries found on {target}.  Cross-reference "
            f"unusual entries with GTFOBins or check for custom setuid "
            f"binaries left by sysadmins.\n\n"
            + "\n".join(f"  • {p}" for p in all_suids[:80])),
        "severity":    "info",
        "source":      "linpeas parser",
    })
    return {"name": "SUID Binaries", "body": body}


def _parse_capabilities(sections, target, findings):
    """File capabilities (getcap output)."""
    body = (_find_section(sections, "capabilities")
            or _find_section(sections, "cap_"))
    if not body:
        return None

    hits = []
    # linPEAS output:
    #   /usr/bin/python3 = cap_setuid+ep
    for line in body.splitlines():
        m = re.search(r"(/\S+)\s*=\s*([a-z_,+]+)", line)
        if not m:
            continue
        path, caps_str = m.group(1), m.group(2)
        for cap, desc in _DANGEROUS_CAPS.items():
            if cap in caps_str:
                hits.append((path, cap, desc))
                break  # one finding per binary

    if not hits:
        return None

    for path, cap, desc in hits[:15]:
        findings.append({
            "title":       f"Capability {cap} on {os.path.basename(path)}",
            "description": (
                f"Binary: {path}\n"
                f"Capability: {cap}\n\n"
                f"Impact: {desc}"),
            "severity":    "high",
            "source":      "linpeas parser",
        })
    return {"name": "File Capabilities", "body": body}


def _parse_cron_jobs(sections, target, findings):
    """Cron entries with writable script paths or wildcard abuse."""
    body = (_find_section(sections, "cron")
            or _find_section(sections, "analyzing", "cron"))
    if not body:
        return None

    # Look for script paths referenced in /etc/crontab and /etc/cron.*
    # that are either in /tmp, in the user's home, or have ww perms.
    writable_hits = []
    for line in body.splitlines():
        # Simple heuristic: linpeas flags cron lines where the script
        # is writable with a colour → after ANSI strip the path is
        # still parseable.  We look for /tmp/ or /var/tmp/ refs,
        # plus any path marked with [+] or similar linpeas highlight.
        if re.search(r"/tmp/\S+|/var/tmp/\S+", line):
            writable_hits.append(line.strip())

    if not writable_hits:
        return None

    findings.append({
        "title":       f"Cron references to writable paths "
                       f"({len(writable_hits)})",
        "description": (
            f"Cron jobs on {target} reference scripts in /tmp or "
            f"/var/tmp.  These are world-writable by default — if "
            f"the script is truly there and the cron runs as root, "
            f"you have persistent RCE as root on each cron tick.\n\n"
            + "\n".join(f"  • {ln}" for ln in writable_hits[:10])),
        "severity":    "high",
        "source":      "linpeas parser",
    })
    return {"name": "Cron Jobs", "body": body}


def _parse_writable_critical_files(sections, target, findings):
    """Writable /etc/passwd, /etc/shadow, /etc/sudoers → CRITICAL."""
    body = (_find_section(sections, "interesting", "files")
            or _find_section(sections, "/etc")
            or "\n".join(sections.values()))
    if not body:
        return None

    criticals = []
    # linPEAS prints "/etc/passwd" in red if writable; after ANSI strip
    # we still see the line, but can't tell if it was red.  We rely on
    # explicit "[+] /etc/passwd" markers or "(writable)" annotations.
    for critical_file in ("/etc/passwd", "/etc/shadow", "/etc/sudoers",
                           "/etc/sudoers.d"):
        pat = re.compile(
            rf"{re.escape(critical_file)}.*?(writable|ww|w\+)",
            re.I)
        if pat.search(body):
            criticals.append(critical_file)

    if not criticals:
        return None

    for fpath in criticals:
        findings.append({
            "title":       f"{fpath} appears writable",
            "description": (
                f"linPEAS flagged {fpath} as writable on {target}.\n\n"
                f"Exploit path:\n"
                f"  • /etc/passwd: add a root-equivalent user "
                f"(`openssl passwd -1` → append line with uid=0)\n"
                f"  • /etc/shadow: replace root's hash with your own\n"
                f"  • /etc/sudoers: add `<user> ALL=(ALL) NOPASSWD: ALL`\n\n"
                f"Verify: `ls -la {fpath}` then `echo > {fpath}.test`."),
            "severity":    "critical",
            "source":      "linpeas parser",
        })
    return {"name": "Writable Critical Files", "body": body}


def _parse_group_memberships(sections, target, findings):
    """Current user's group memberships — docker, lxd, disk, sudo."""
    body = (_find_section(sections, "groups")
            or _find_section(sections, "users", "information")
            or _find_section(sections, "user")
            or "\n".join(sections.values()))
    if not body:
        return None

    # Find the line that has "uid=N(user) gid=N(group) groups=..."
    groups_match = re.search(
        r"groups=[^(]+\(([^)]+)\)(?:,\d+\(([^)]+)\))*", body)
    if not groups_match:
        # Try a more permissive scan for group names
        groups_match = re.search(
            r"(docker|lxd|lxc|disk|video|adm|sudo|wheel|plugdev)",
            body, re.I)
    if not groups_match:
        return None

    all_text = groups_match.group(0).lower()
    dangerous = {
        "docker": (
            "Member of the `docker` group.  Docker socket grants "
            "root-equivalent access: `docker run -v /:/mnt "
            "--rm -it alpine chroot /mnt sh`."),
        "lxd": (
            "Member of the `lxd` / `lxc` group.  Create a "
            "privileged container mounting /: "
            "`lxc launch alpine priv -c security.privileged=true "
            "&& lxc config device add priv host disk source=/ "
            "path=/mnt && lxc exec priv -- /bin/sh`."),
        "disk": (
            "Member of the `disk` group.  Raw device access — "
            "`debugfs /dev/sda1` lets you read any file including "
            "/etc/shadow."),
    }

    triggered = []
    for grp, desc in dangerous.items():
        if re.search(rf"\b{grp}\b", all_text):
            triggered.append((grp, desc))

    if not triggered:
        return None

    for grp, desc in triggered:
        findings.append({
            "title":       f"Dangerous group membership: {grp}",
            "description": desc,
            "severity":    "high",
            "source":      "linpeas parser",
        })
    return {"name": "Group Memberships", "body": body}


def _parse_nfs_exports(sections, target, findings):
    """`/etc/exports` entries with no_root_squash → remote root file
    access if you can mount from your Kali."""
    body = (_find_section(sections, "nfs")
            or _find_section(sections, "exports"))
    if not body:
        return None

    no_squash_lines = [ln.strip() for ln in body.splitlines()
                       if "no_root_squash" in ln]
    if not no_squash_lines:
        return None

    findings.append({
        "title":       f"NFS exports with no_root_squash "
                       f"({len(no_squash_lines)})",
        "description": (
            f"NFS shares on {target} exported without root squashing. "
            f"From your Kali: mount the share, create a SUID binary "
            f"owned by root inside it, then run the binary back on "
            f"the target for instant root.\n\n"
            f"Commands:\n"
            f"  mkdir -p /tmp/nfs_mount\n"
            f"  sudo mount -t nfs {target}:<exported_path> /tmp/nfs_mount\n"
            f"  echo 'int main() {{ setuid(0); system(\"/bin/sh\"); }}' > "
            f"/tmp/root.c\n"
            f"  gcc /tmp/root.c -o /tmp/nfs_mount/rootshell && "
            f"sudo chown root:root /tmp/nfs_mount/rootshell && "
            f"sudo chmod +s /tmp/nfs_mount/rootshell\n"
            f"  # then on target: /mounted/rootshell\n\n"
            + "\n".join(f"  • {ln}" for ln in no_squash_lines[:10])),
        "severity":    "high",
        "source":      "linpeas parser",
    })
    return {"name": "NFS Exports", "body": body}


def _parse_ssh_keys(sections, target, findings, creds):
    """SSH private keys found readable."""
    body = (_find_section(sections, "ssh", "files")
            or _find_section(sections, "ssh")
            or "\n".join(sections.values()))
    if not body:
        return None

    # linPEAS dumps filenames of readable private keys.
    key_paths = []
    for m in re.finditer(
            r"(/(?:home|root)/[^\s:]+/\.ssh/[^\s:]*id_\w+)", body):
        key_paths.append(m.group(1))

    # Dedup preserve order
    seen = set()
    key_paths = [k for k in key_paths
                 if not (k in seen or seen.add(k))]
    if not key_paths:
        return None

    for key_path in key_paths[:10]:
        # Try to infer username from path (/home/USER/.ssh/...)
        usr = ""
        m = re.match(r"/home/([^/]+)/", key_path)
        if m:
            usr = m.group(1)
        elif key_path.startswith("/root/"):
            usr = "root"
        creds.append({
            "username":  usr,
            "password":  "",
            "host":      target,
            "services":  ["SSH"],
            "cred_type": "key",
            "notes":     f"SSH key readable on target: {key_path}",
        })

    findings.append({
        "title":       f"SSH private keys readable ({len(key_paths)})",
        "description": (
            f"linPEAS found {len(key_paths)} SSH private key(s) on "
            f"{target} that the current user can read.  Copy each "
            f"key to Kali and try `ssh -i <key> <user>@<host>` — "
            f"often gives you a different user (or root) on the same "
            f"or another host.\n\n"
            + "\n".join(f"  • {p}" for p in key_paths[:10])),
        "severity":    "high",
        "source":      "linpeas parser",
    })
    return {"name": "SSH Keys", "body": body}


def _parse_passwords_in_files(sections, target, findings, creds):
    """linPEAS grep for password patterns in common config dirs."""
    body = (_find_section(sections, "password")
            or _find_section(sections, "passwords", "inside")
            or _find_section(sections, "searching", "password"))
    if not body:
        # Also try the "interesting files" section which sometimes
        # contains password leaks.
        body = _find_section(sections, "interesting")
    if not body:
        return None

    # We look for `KEY=VALUE` or `KEY: VALUE` lines where KEY looks
    # like a secret.  Paths preceding the match give context.
    file_hits = []
    current_file = None
    for line in body.splitlines():
        # linPEAS prefixes file paths with the path itself followed
        # by ":" and the match.
        m_file = re.match(
            r"^(/[\w\./\-_]+):\s*(.+)$", line)
        if m_file:
            path, content = m_file.group(1), m_file.group(2)
            if _SECRET_ENV_RE.search(content):
                file_hits.append((path, content.strip()))

    if not file_hits:
        return None

    for path, content in file_hits[:20]:
        # Try to extract a credential pair.
        m = re.search(r"[\"']?(\w+)[\"']?\s*[=:]\s*[\"']?([^\"'\s]+)",
                      content)
        if m:
            key, val = m.group(1), m.group(2)
            # Only push as credential if the value looks non-trivial
            if len(val) >= 4 and val.lower() not in (
                    "null", "none", "false", "true", "undefined",
                    "password", "changeme"):
                creds.append({
                    "username":  "",
                    "password":  val,
                    "host":      target,
                    "services":  ["file-leak"],
                    "cred_type": "cleartext",
                    "notes":     f"Secret '{key}' in {path}",
                })

    lines = [f"  • {p}:  {c[:100]}" for p, c in file_hits[:15]]
    findings.append({
        "title":       f"Passwords/secrets found in files "
                       f"({len(file_hits)})",
        "description": (
            f"linPEAS grep found potential credentials in config "
            f"files on {target}.  Each match was pushed to the "
            f"Credential Store when a value was extractable.\n\n"
            + "\n".join(lines)),
        "severity":    "high",
        "source":      "linpeas parser",
    })
    return {"name": "Passwords in Files", "body": body}


def _parse_writable_path(sections, target, findings):
    """Writable directories in the user's (or root's cron's) PATH."""
    body = (_find_section(sections, "writable", "path")
            or _find_section(sections, "path", "folders")
            or _find_section(sections, "path"))
    if not body:
        return None

    # linPEAS emits lines like "/opt/custom is writable"
    writable = []
    for line in body.splitlines():
        m = re.search(r"(/\S+)\s*(?:is\s+)?writable", line, re.I)
        if m:
            writable.append(m.group(1))

    if not writable:
        return None

    findings.append({
        "title":       f"Writable folders in PATH ({len(writable)})",
        "description": (
            f"Directories in PATH that the current user can write on "
            f"{target}.  If root or another user's cron runs a "
            f"command WITHOUT an absolute path, you can drop a "
            f"same-named binary in one of these dirs for RCE as "
            f"them.\n\n"
            + "\n".join(f"  • {p}" for p in writable[:15])),
        "severity":    "high",
        "source":      "linpeas parser",
    })
    return {"name": "Writable PATH", "body": body}


def _parse_env_secrets(sections, target, findings):
    """Environment variables with secret-looking names."""
    body = (_find_section(sections, "environment")
            or _find_section(sections, "env"))
    if not body:
        return None

    suspicious = []
    for line in body.splitlines():
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]+)=(.+)", line)
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip()
        if _SECRET_ENV_RE.search(name):
            masked = (f"<{len(value)} chars>" if value else "<empty>")
            suspicious.append((name, masked))

    if not suspicious:
        return None

    lines = [f"  • {n}  =  {masked}" for n, masked in suspicious]
    findings.append({
        "title":       f"Env vars with secret-like names "
                       f"({len(suspicious)})",
        "description": (
            f"Environment variables on {target} whose names look "
            f"like they hold secrets.  Values masked here; check the "
            f".txt sibling for raw contents.\n\n"
            + "\n".join(lines)),
        "severity":    "high",
        "source":      "linpeas parser",
    })
    return {"name": "Environment Variables", "body": body}


def _parse_installed_packages(sections, target, findings):
    """Installed packages — single info-finding, no CVE auto-match."""
    body = (_find_section(sections, "packages")
            or _find_section(sections, "installed")
            or _find_section(sections, "useful", "software"))
    if not body:
        return None

    # Collect plausible package-version pairs.  Packaging output is
    # very distro-specific — we just keep lines with a letter+number
    # and cap at 120 entries to avoid flood.
    pkgs = []
    for line in body.splitlines():
        line = line.strip()
        if (len(line) > 3 and len(line) < 200
                and re.search(r"[A-Za-z]", line)
                and re.search(r"\d", line)
                and not line.startswith("╔")
                and not line.startswith("[")):
            pkgs.append(line)

    seen = set()
    unique = []
    for p in pkgs:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    if len(unique) < 3:
        return None

    desc = (
        f"linPEAS enumerated {len(unique)} package/version entries "
        f"on {target}.\n"
        f"No CVE auto-correlation performed (use HAWK → Target Intel "
        f"→ SEARCH CVEs for entries of interest).\n\n"
        + "\n".join(f"  • {p}" for p in unique[:120]))
    if len(unique) > 120:
        desc += f"\n  ... and {len(unique) - 120} more (see .txt)"

    findings.append({
        "title":       f"Installed packages ({len(unique)})",
        "description": desc,
        "severity":    "info",
        "source":      "linpeas parser",
    })
    return {"name": "Installed Packages", "body": body}


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
    """Same layout as winpeas_parser._write_structured_txt — header,
    severity tally, TOC with line numbers, findings/creds preview,
    per-section body, raw dump at the end."""
    txt_path = os.path.splitext(source_file)[0] + ".txt"

    rule = "═" * 67
    dash = "─" * 67

    buffer_lines: list[str] = []

    def _emit(s: str = ""):
        buffer_lines.append(s)

    _emit(rule)
    _emit(f"  HAWK — linPEAS parsed output  —  {target}")
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

    toc_entries_start = len(buffer_lines) + 2
    _emit("  TABLE OF CONTENTS")
    _emit(dash)
    for i, s in enumerate(section_reports, 1):
        _emit(f"    [{i:>2}] {s['name']:<40} line   ???")
    _emit("")

    _emit("  FINDINGS (summary — full details in Target Intel tab)")
    _emit(dash)
    if findings:
        for f in findings:
            _emit(f"    [{f['severity'].upper():<8}] {f['title']}")
    else:
        _emit("    (no findings)")
    _emit("")

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

    section_line_offsets = []
    for i, s in enumerate(section_reports, 1):
        section_line_offsets.append(len(buffer_lines) + 1)
        _emit(f"[{i}] {s['name'].upper()}")
        _emit(dash)
        _emit(s["body"].rstrip())
        _emit("")
        _emit("")

    _emit(rule)
    _emit("  RAW (ANSI-stripped) OUTPUT")
    _emit(rule)
    _emit(clean_text)

    for i, offset in enumerate(section_line_offsets):
        idx = toc_entries_start + i
        section = section_reports[i]
        if 0 <= idx < len(buffer_lines):
            buffer_lines[idx] = (
                f"    [{i + 1:>2}] {section['name']:<40} "
                f"line {offset:>5}")

    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(buffer_lines))


# ═════════════════════════════════════════════════════════════════════
#  Small helpers
# ═════════════════════════════════════════════════════════════════════

def _new_run_id() -> str:
    return f"linpeas-{uuid.uuid4().hex[:10]}"


def _scrape(text: str, pattern: str, flags: int = re.I) -> str:
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else ""


def _push_finding(app, f: dict, run_id: str):
    try:
        app.target_intel.add_auto_finding(
            title=f["title"],
            description=f["description"],
            severity=f["severity"],
            source=f.get("source", "linpeas parser"),
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
            linked_run_id=run_id)
        app.cred_store.add_credential(cred)
    except Exception:
        pass


def _term_warn(app, msg: str):
    try:
        app.terminal.write(msg, "warn")
    except Exception:
        pass
