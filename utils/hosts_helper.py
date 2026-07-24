# HAWK — Hostile Assessment WorKit
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
HAWK — /etc/hosts helper for AD / CTF targets.

Active Directory tools that speak Kerberos (bloodhound-python, certipy,
impacket-getTGT, etc.) need to resolve the DC's FQDN to build valid
SPN tickets.  Kali boxes talking to a lab/HTB/THM target almost never
have that mapping in DNS, so Kerberos silently fails back to NTLM
(or fails entirely on modern strict setups).

This module provides a small, auditable /etc/hosts editor that:

* Adds mappings tagged with a HAWK-specific marker comment so we can
  find and remove them later without touching unrelated entries.
* Removes all HAWK-tagged entries in one shot (on session delete, or
  on explicit user request).
* Executes the write through pkexec (preferred) or sudo-in-xterm
  (fallback) so the user authenticates via a normal graphical prompt.

Tagging format:
    192.168.176.167 vagrant-2008r2.prova.prova.com    # HAWK-ad-dns
    10.10.10.161    forest.htb  forest                # HAWK-ad-dns

A single HAWK session may add multiple entries (e.g. DC + target
computer); we always remove ALL lines with the marker on cleanup.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
from typing import Iterable, Optional, Tuple
from utils.config import TMP_DIR


HOSTS_PATH = "/etc/hosts"
HAWK_MARKER = "# HAWK-ad-dns"


def _mk_hawk_temp(prefix: str) -> Tuple[int, str]:
    os.makedirs(TMP_DIR, exist_ok=True)
    return tempfile.mkstemp(prefix=prefix, suffix=".txt", dir=TMP_DIR)


# ─── Read-side helpers (no privilege required) ─────────────────────────────

def list_hawk_entries() -> list:
    """Return the list of HAWK-tagged lines currently in /etc/hosts.
    Each element is a dict {ip, hostnames, raw}.  Safe to call any time;
    uses only read permissions."""
    out = []
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
            for ln in f:
                if HAWK_MARKER not in ln:
                    continue
                stripped = ln.split("#", 1)[0].strip()
                if not stripped:
                    continue
                parts = stripped.split()
                if len(parts) < 2:
                    continue
                out.append({
                    "ip": parts[0],
                    "hostnames": parts[1:],
                    "raw": ln.rstrip("\n"),
                })
    except OSError:
        pass
    return out


def resolvable(hostname: str, timeout: float = 2.0) -> bool:
    """True when the current resolver can answer a forward lookup for
    `hostname`.  Used to decide whether the DNS helper is actually
    needed — no point offering to add an entry that already resolves."""
    if not hostname:
        return False
    import socket
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(hostname, None)
        return True
    except (socket.gaierror, OSError):
        return False
    finally:
        socket.setdefaulttimeout(None)


# ─── Write-side helpers (need sudo/pkexec) ─────────────────────────────────

def _has_pkexec() -> bool:
    return shutil.which("pkexec") is not None


def _build_append_lines(entries: Iterable[Tuple[str, Iterable[str]]]) -> str:
    """Format a block of hosts lines with the HAWK marker."""
    lines = []
    for ip, hostnames in entries:
        ip = (ip or "").strip()
        hosts_clean = [h.strip() for h in hostnames if h and h.strip()]
        if not ip or not hosts_clean:
            continue
        # /etc/hosts is ASCII-only by convention — drop anything weird.
        hosts_clean = [re.sub(r"[^A-Za-z0-9.\-_]", "", h)
                       for h in hosts_clean]
        hosts_clean = [h for h in hosts_clean if h]
        if not hosts_clean:
            continue
        lines.append(f"{ip}\t{' '.join(hosts_clean)}\t{HAWK_MARKER}")
    return "\n".join(lines) + ("\n" if lines else "")


def add_entries(entries: Iterable[Tuple[str, Iterable[str]]],
                explain: bool = True) -> Tuple[bool, str]:
    """Append HAWK-tagged lines to /etc/hosts.  Returns (ok, message).

    `entries` is an iterable of (ip, [hostname, hostname, …]) tuples.

    Uses pkexec when available (nice graphical prompt), falls back to
    `sudo` via an xterm so the user can type their password.  Never
    touches the file without privilege escalation — safe to call from
    an unprivileged HAWK process.

    This function is synchronous and blocks until the user answers the
    auth prompt or cancels.  That's fine in the context of a small
    dialog triggered by a button click.
    """
    block = _build_append_lines(entries)
    if not block.strip():
        return False, "no valid entries to add"

    # Skip entries that already exist — prevents duplicate accumulation
    # when the user clicks the helper twice.
    existing_ips = {e["ip"]: set(e["hostnames"])
                    for e in list_hawk_entries()}
    filtered = []
    for line in block.splitlines():
        bare = line.split("#", 1)[0].strip()
        if not bare:
            continue
        parts = bare.split()
        ip = parts[0]
        hosts = set(parts[1:])
        if ip in existing_ips and hosts.issubset(existing_ips[ip]):
            continue
        filtered.append(line)
    if not filtered:
        return True, "entry already present — nothing to do"
    block = "\n".join(filtered) + "\n"

    # Write to a tempfile the user can inspect in case things go wrong.
    fd, tmp = _mk_hawk_temp("hawk_hosts_add_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(block)

        if _has_pkexec():
            # pkexec wraps the tee cleanly — one graphical prompt, no
            # terminal flicker.
            cmd = ["pkexec", "sh", "-c",
                   f"cat {shlex.quote(tmp)} >> /etc/hosts"]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=60)
                if r.returncode == 0:
                    return True, (f"added {len(filtered)} entry/entries "
                                  f"via pkexec")
                return False, (f"pkexec failed (rc={r.returncode}): "
                               f"{(r.stderr or '').strip()}")
            except subprocess.TimeoutExpired:
                return False, "pkexec timed out — user didn't authenticate"

        # Fallback: sudo in an xterm.  We invoke the terminal emulator
        # so the user gets a tty for the password prompt.  The command
        # runs `sudo tee -a /etc/hosts` reading from our tempfile.
        from utils.runner import _open_terminal
        sh_cmd = (f"echo -e '\\e[36m[HAWK] Adding {len(filtered)} entry/"
                  f"entries to /etc/hosts\\e[0m'; "
                  f"sudo tee -a {shlex.quote(HOSTS_PATH)} "
                  f"< {shlex.quote(tmp)} >/dev/null && "
                  f"echo -e '\\e[32m[OK] Added.\\e[0m' || "
                  f"echo -e '\\e[31m[FAIL] Not written.\\e[0m'; "
                  f"echo 'Press ENTER to close.'; read")
        ok = _open_terminal("HAWK — /etc/hosts update", sh_cmd)
        if not ok:
            return False, ("no graphical sudo available.  Run manually: "
                           f"sudo tee -a {HOSTS_PATH} < {tmp}")
        return True, (f"launched sudo in xterm — confirm password "
                      f"there; file will be updated on success")
    finally:
        # Don't delete the tmp immediately in the xterm-fallback path —
        # the xterm process reads it asynchronously.  Best-effort delete
        # a few seconds later.
        try:
            if _has_pkexec():
                os.unlink(tmp)
            else:
                import threading, time
                def _cleanup():
                    time.sleep(30)
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                threading.Thread(target=_cleanup, daemon=True).start()
        except Exception:
            pass


def remove_hawk_entries() -> Tuple[bool, str]:
    """Remove every line tagged with the HAWK marker from /etc/hosts.
    Returns (ok, message).  Idempotent — safe to call on clean files."""
    entries = list_hawk_entries()
    if not entries:
        return True, "no HAWK entries to remove"

    # Read full file, strip tagged lines, write the clean version back
    # under sudo/pkexec.
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
            original = f.read()
    except OSError as e:
        return False, f"read failed: {e}"

    cleaned_lines = []
    for ln in original.splitlines(keepends=True):
        if HAWK_MARKER in ln:
            continue
        cleaned_lines.append(ln)
    cleaned = "".join(cleaned_lines)

    fd, tmp = _mk_hawk_temp("hawk_hosts_clean_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(cleaned)

    try:
        if _has_pkexec():
            cmd = ["pkexec", "sh", "-c",
                   f"install -m 644 -o root -g root "
                   f"{shlex.quote(tmp)} {HOSTS_PATH}"]
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=60)
            if r.returncode == 0:
                return True, f"removed {len(entries)} HAWK entry/entries"
            return False, (f"pkexec rc={r.returncode}: "
                           f"{(r.stderr or '').strip()}")
        # Fallback — sudo in xterm
        from utils.runner import _open_terminal
        sh_cmd = (f"echo -e '\\e[36m[HAWK] Removing {len(entries)} entry/"
                  f"entries from /etc/hosts\\e[0m'; "
                  f"sudo install -m 644 -o root -g root "
                  f"{shlex.quote(tmp)} {shlex.quote(HOSTS_PATH)} && "
                  f"echo -e '\\e[32m[OK] Cleaned.\\e[0m' || "
                  f"echo -e '\\e[31m[FAIL] Not written.\\e[0m'; "
                  f"echo 'Press ENTER to close.'; read")
        ok = _open_terminal("HAWK — /etc/hosts cleanup", sh_cmd)
        return ok, ("launched sudo in xterm — confirm password to "
                    "apply removal") if ok else "no graphical sudo available"
    finally:
        try:
            if _has_pkexec():
                os.unlink(tmp)
            else:
                import threading, time

                def _cleanup():
                    time.sleep(30)
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass

                threading.Thread(target=_cleanup, daemon=True).start()
        except OSError:
            pass


def add_entries_async(entries: Iterable[Tuple[str, Iterable[str]]],
                       callback) -> None:
    """Same as add_entries() but runs the pkexec/sudo call in a worker
    thread so the GUI stays responsive. `callback(ok, msg)` is called
    from the worker thread on completion — wrap UI updates in
    `widget.after(0, ...)`."""
    import threading

    # Materialise the iterable in case it's a generator we'd consume
    # twice (we don't here, but the contract is "stable input").
    materialised = [(ip, list(hosts)) for ip, hosts in entries]

    def _worker():
        try:
            ok, msg = add_entries(materialised)
        except Exception as e:
            ok, msg = False, f"async error: {e}"
        try:
            callback(ok, msg)
        except Exception as e:
            import sys as _s
            print(f"[HAWK] add_entries_async callback: {e}",
                  file=_s.stderr)

    threading.Thread(target=_worker, daemon=True).start()


def remove_hawk_entries_async(callback) -> None:
    """Same as remove_hawk_entries() but runs the pkexec/sudo call in a
    background thread so the GUI event loop stays responsive while the
    user authenticates. `callback(ok, msg)` is invoked from the worker
    thread on completion — wrap UI updates in `widget.after(0, ...)`."""
    import threading

    def _worker():
        try:
            ok, msg = remove_hawk_entries()
        except Exception as e:
            ok, msg = False, f"async error: {e}"
        try:
            callback(ok, msg)
        except Exception as e:
            import sys as _s
            print(f"[HAWK] remove_hawk_entries_async callback: {e}",
                  file=_s.stderr)

    threading.Thread(target=_worker, daemon=True).start()


def suggest_dc_hostname(domain: str, target_ip: str = "") -> Optional[str]:
    """Best-effort DC FQDN guess when we don't know it for certain.

    Strategy:
      1. If `target_ip` already has a PTR record, prefer that.
      2. Otherwise synthesise from the domain — many labs follow the
         `<computer>.<domain>` pattern, but we only have the domain at
         this point, so return just the domain itself as a lower-
         confidence fallback.  The user edits it in the dialog.
    """
    if target_ip:
        try:
            import socket
            fqdn, _aliases, _ips = socket.gethostbyaddr(target_ip)
            if fqdn and "." in fqdn:
                return fqdn.lower()
        except (OSError, socket.herror):
            pass
    return (domain or "").strip().lower() or None
