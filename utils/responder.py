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
HAWK — Responder watcher.

Tails Responder's session log + captured-hash files and surfaces the
attack-relevant events through callbacks:

  on_update(counters, unique_names, unique_victims)
      called ~1/sec with fresh aggregates.

  on_hash(hash_entry)
      called exactly once per NEW NTLMv2 hash captured; the entry dict
      is {user, domain, raw, source_file, captured_at} and is what the
      caller should push into the Credential Store.

Usage:
    w = ResponderWatcher(
            app,
            on_update=lambda c,n,v: ...,
            on_hash=lambda e: ...)
    w.start()
    ...
    w.stop()

Design choices:
  * Polls with a 1-second interval.  Tempting to use inotify for exact-
    time delivery, but Responder writes log + hash files on every
    captured event — polling is already within human reaction time
    (the UI update is the bottleneck, not the poll rate).
  * Reads INCREMENTALLY: remembers last-seen file size per file,
    reads only the new suffix.  Handles file truncation by resetting
    the cursor to 0 when the file shrinks.
  * Filters out known IoT mDNS noise (Android TV, AirPlay, HIKVISION
    cameras, smart-home devices) so the counters reflect attack-
    relevant traffic.  The raw count is still tracked as MDNS_noise.
"""

from __future__ import annotations

import os
import re
import glob
import time
import threading
from collections import Counter


_LOG_DIR = "/usr/share/responder/logs"
_SESSION_LOG = os.path.join(_LOG_DIR, "Responder-Session.log")

# Noise patterns — consumer/IoT mDNS broadcasts we see everywhere on
# home LANs (TVs, phones, printers, routers).  Not part of the AD
# attack surface.
_IOT_NOISE = re.compile(
    r"(panasonic|google\s*tv|_androidtvremote2|_airplay|_raop|"
    r"_smart\._tcp|hikvision|android\.local|fritz-box|"
    r"_ipp\._tcp|_smb\._tcp|_services\._dns-sd|_ftp\._tcp|"
    r"computer\s+portatile)",
    re.I)

# Responder "Poisoned answer sent" lines — the most frequent event.
_POISON_RE = re.compile(
    r"\[\*\]\s*\[(MDNS|LLMNR|NBT-NS)\]\s+Poisoned\s+answer\s+sent\s+to\s+"
    r"([^\s]+)\s+for\s+name\s+(.+?)\s*(?:\(service:.*?\))?$",
    re.I)

# NTLMv2 hash line — Responder writes these in both session log AND
# dedicated per-source TXT files.  We only parse the TXT files (cleaner
# format, one hash per line).
_NTLMV2_RE = re.compile(
    r"^[^\s:]{1,64}::[^\s:]{1,64}:[0-9a-f]{16}:[0-9a-f]{32}:"
    r"[0-9a-f]+$", re.I)


class ResponderWatcher:
    def __init__(self, app,
                 on_update=None, on_hash=None):
        """Args:
          app         HAWK app instance (used for `ui_call` marshalling
                      onto the Tk main thread).
          on_update   called ~1/s with (counters_dict, unique_names_dict,
                      unique_victims_list).
          on_hash     called once per fresh NTLMv2 capture with a dict.
        """
        self.app = app
        self.on_update = on_update
        self.on_hash = on_hash

        # Aggregates.
        self.counters = {
            "MDNS":       0,     # all mDNS poison replies
            "MDNS_noise": 0,     # subset that matches _IOT_NOISE
            "LLMNR":      0,
            "NBT-NS":     0,
            "HTTP":       0,     # HTTP auth events in session log
            "SMB":        0,     # SMB auth events in session log
            "wpad":       0,     # WPAD file served
            "NTLMv2":     0,     # full hashes captured
        }
        # Name-frequency Counters scoped per poison protocol.
        self.unique_names = {
            "LLMNR":  Counter(),
            "NBT-NS": Counter(),
            "MDNS":   Counter(),   # filtered: IoT noise excluded
        }
        self.unique_victims = set()
        self.captured_hashes: list = []

        # File-cursor state — we only track NEW content added after
        # watcher.start().
        self._log_pos = 0
        self._hash_offsets: dict = {}
        self._stop = threading.Event()
        self._thread = None

    # ── lifecycle ─────────────────────────────────────────────────────
    def start(self):
        try:
            self._log_pos = (os.path.getsize(_SESSION_LOG)
                             if os.path.isfile(_SESSION_LOG) else 0)
        except Exception:
            self._log_pos = 0
        for hf in glob.glob(
                os.path.join(_LOG_DIR, "*NTLMv2-SSP-*.txt")):
            try:
                self._hash_offsets[hf] = os.path.getsize(hf)
            except Exception:
                self._hash_offsets[hf] = 0

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True,
            name="HAWK-ResponderWatcher")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            try:
                self._thread.join(timeout=2)
            except Exception:
                pass

    # ── core polling ──────────────────────────────────────────────────
    def _poll_loop(self):
        while not self._stop.wait(1.0):
            try:
                self._poll_session_log()
                self._poll_hash_files()
                self._emit_update()
            except Exception as e:
                # Non-fatal: another loop iteration might succeed
                # (file locks, transient read errors).
                print(f"[HAWK] responder watcher poll: {e}")

    def _poll_session_log(self):
        """Read any new bytes at the end of Responder-Session.log and
        classify each line.  Uses the last-seen byte offset as a
        cursor so we don't re-count prior captures on restart."""
        if not os.path.isfile(_SESSION_LOG):
            return
        try:
            sz = os.path.getsize(_SESSION_LOG)
            if sz < self._log_pos:
                # File was truncated / rotated — restart cursor.
                self._log_pos = 0
            if sz == self._log_pos:
                return
            with open(_SESSION_LOG, "rb") as f:
                f.seek(self._log_pos)
                chunk = f.read(sz - self._log_pos).decode(
                    "utf-8", errors="replace")
                self._log_pos = sz
        except Exception:
            return

        for line in chunk.splitlines():
            self._classify_line(line)

    def _classify_line(self, line: str):
        m = _POISON_RE.search(line)
        if m:
            proto = m.group(1).upper()
            victim = m.group(2)
            name   = (m.group(3) or "").strip().strip("()")
            self.counters[proto] += 1
            self.unique_victims.add(victim)
            if proto == "MDNS" and _IOT_NOISE.search(name):
                self.counters["MDNS_noise"] += 1
                return  # don't add IoT noise to unique_names["MDNS"]
            if name:
                self.unique_names[proto][name] += 1
            return

        # Non-poison event classification — substring match, loose by
        # design since Responder's exact wording has changed across
        # versions.
        low = line.lower()
        if "wpad" in low and ("sent" in low or "file" in low):
            self.counters["wpad"] += 1
        if ("[http] ntlmv2" in low
                or "http ntlmv2 client" in low):
            self.counters["HTTP"] += 1
        if ("[smb] ntlmv2" in low
                or "smb ntlmv2 hash" in low
                or "[smbv2] ntlmv2" in low):
            self.counters["SMB"] += 1

    def _poll_hash_files(self):
        """Scan each *NTLMv2-SSP-*.txt file for new hash lines since
        our last read.  Responder writes one hash per unique user the
        first time, then dedup-suffixes subsequent captures — we
        dedup here too on the full hash string."""
        # Add any NEW hash files that appeared after start()
        # (Responder creates them lazily — first SMB capture creates
        # SMB-NTLMv2-SSP-<IP>.txt).
        for hf in glob.glob(
                os.path.join(_LOG_DIR, "*NTLMv2-SSP-*.txt")):
            if hf not in self._hash_offsets:
                self._hash_offsets[hf] = 0

        seen_hashes = {h["raw"] for h in self.captured_hashes}

        for hf, last in list(self._hash_offsets.items()):
            try:
                sz = os.path.getsize(hf)
                if sz < last:
                    last = 0
                if sz == last:
                    continue
                with open(hf, "rb") as f:
                    f.seek(last)
                    chunk = f.read(sz - last).decode(
                        "utf-8", errors="replace")
                    self._hash_offsets[hf] = sz
            except Exception:
                continue

            for line in chunk.splitlines():
                line = line.strip()
                if not _NTLMV2_RE.match(line):
                    continue
                if line in seen_hashes:
                    continue
                seen_hashes.add(line)

                # Parse user::DOMAIN prefix.
                try:
                    head = line.split(":", 2)
                    user = head[0]
                    domain = head[1][1:] if len(head) > 1 and \
                              head[1].startswith(":") else ""
                    # Fallback for the common "user::DOMAIN:..." split
                    parts = line.split("::", 1)
                    if len(parts) == 2:
                        user = parts[0]
                        rest = parts[1]
                        domain = rest.split(":", 1)[0] if ":" in rest \
                                  else ""
                except Exception:
                    user, domain = "?", ""

                entry = {
                    "user":        user,
                    "domain":      domain,
                    "raw":         line,
                    "source_file": hf,
                    "captured_at": time.time(),
                }
                self.captured_hashes.append(entry)
                self.counters["NTLMv2"] += 1
                self._emit_hash(entry)

    # ── callback marshalling onto the Tk main thread ──────────────────
    def _emit_update(self):
        if not self.on_update:
            return
        counters = dict(self.counters)
        # Serialise Counter → list of (name, count) tuples so the UI
        # thread can consume without importing collections.
        unique_names = {
            k: list(v.most_common(20))
            for k, v in self.unique_names.items()
        }
        victims = sorted(self.unique_victims)
        try:
            dispatch = getattr(self.app, "ui_call", None)
            if dispatch:
                dispatch(self.on_update,
                         counters, unique_names, victims)
            else:
                self.on_update(counters, unique_names, victims)
        except Exception as e:
            print(f"[HAWK] responder watcher on_update: {e}")

    def _emit_hash(self, entry):
        if not self.on_hash:
            return
        try:
            dispatch = getattr(self.app, "ui_call", None)
            if dispatch:
                dispatch(self.on_hash, entry)
            else:
                self.on_hash(entry)
        except Exception as e:
            print(f"[HAWK] responder watcher on_hash: {e}")


# ── Control helpers ─────────────────────────────────────────────────

def stop_responder_process() -> bool:
    """Signal Responder to shut down gracefully.

    Responder runs with sudo inside an xterm — we send SIGINT to the
    responder Python process so it flushes state and exits cleanly
    (matches what Ctrl-C inside the xterm would do).  Requires sudo
    privilege; if pkexec is available we prefer it for a passwordless
    prompt.

    Returns True if the signal was delivered, False otherwise.
    """
    import shutil, subprocess
    # Try pkexec first (GUI sudo prompt on most desktops) then sudo -n.
    cmds = []
    if shutil.which("pkexec"):
        cmds.append(["pkexec", "pkill", "-2", "-f",
                     "responder/Responder.py"])
    cmds.append(["sudo", "-n", "pkill", "-2", "-f",
                 "responder/Responder.py"])
    # Fallback: non-sudo pkill (works only if responder was started
    # as the current user, which is rare for responder but possible).
    cmds.append(["pkill", "-2", "-f", "responder/Responder.py"])

    for c in cmds:
        try:
            r = subprocess.run(c, capture_output=True,
                               text=True, timeout=5)
            if r.returncode in (0, 1):
                # 0 = signalled; 1 = no matching process (already
                # stopped — treat as success either way since the
                # caller's intent is satisfied).
                return True
        except Exception:
            continue
    return False
