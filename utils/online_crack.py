# HAWK — Hostile Assessment WorKit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0

"""
HAWK — Online hash-cracking integration.

Two integration levels:

  · API (hashes.com only for now) — submit the hash through the
    official REST API, poll for results in the background, surface
    the cracked password when it arrives.

  · Browser launchers (crackstation, cmd5, onlinehashcrack, custom) —
    copy the hash to the clipboard and open the service URL in the
    user's default browser.  No automation, no scraping: the user
    pastes and drives the rest.

Session-volatile API keys live on the HAWK app instance
(`app._online_crack_keys`) — NOT in a global config file.  See the
dialog in gui/dialogs.py that prompts for the key on first API use.
"""

from __future__ import annotations

import os
import re
import json
import time
import threading
import webbrowser
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional


# ─── Service catalogue ───────────────────────────────────────────────

SERVICES = {
    # id -> (display_name, mode, url_template or None, netntlmv2_ok,
    #        other_algos_supported, short_description)
    "hashes.com": {
        "name":         "hashes.com",
        "mode":         "api",   # "api" or "browser"
        "url":          "https://hashes.com/en/decrypt/hash",
        "supports":     ["NTLM", "NetNTLMv2", "NetNTLMv1",
                          "MD5", "SHA1", "SHA256", "bcrypt",
                          "md5crypt", "sha512crypt"],
        "desc":         ("Huge breach DB + commercial cracking pool. "
                         "Free tier 50 submissions/week."),
        "get_key_url":  "https://hashes.com/en/api/keys",
    },
    "crackstation": {
        "name":         "crackstation.net",
        "mode":         "browser",
        "url":          "https://crackstation.net/",
        "supports":     ["NTLM", "MD5", "SHA1", "SHA256"],
        "desc":         ("Free rainbow tables.  Instant hits for "
                         "MD5/SHA1/NTLM in its DB; no NetNTLMv2."),
        "get_key_url":  None,
    },
    "onlinehashcrack": {
        "name":         "onlinehashcrack.com",
        "mode":         "browser",
        # Root domain — the old /hash-identifier.php path 404s after
        # their 2025 site redesign.  Landing page has the paste-hash
        # form front-and-centre.
        "url":          "https://www.onlinehashcrack.com/",
        "supports":     ["NTLM", "NetNTLMv2", "MD5", "SHA1",
                          "bcrypt"],
        "desc":         ("Free 4 hashes/day, paid unlimited.  "
                         "Decent NetNTLMv2 coverage."),
        "get_key_url":  "https://www.onlinehashcrack.com/api-access",
    },
    "cmd5": {
        "name":         "cmd5.org",
        "mode":         "browser",
        "url":          "https://www.cmd5.org/",
        "supports":     ["NTLM", "MD5", "SHA1", "NetNTLMv2"],
        "desc":         ("Asian breach DB.  Pay-per-hit.  Good "
                         "complement to hashes.com (different pool)."),
        "get_key_url":  None,
    },
}


# ─── Clipboard helper ────────────────────────────────────────────────

def copy_to_clipboard(text: str) -> bool:
    """Cross-platform best-effort clipboard copy.  Returns True on
    success."""
    try:
        from utils.clipboard import clipboard_copy
        return bool(clipboard_copy(text))
    except Exception:
        pass
    # Tk fallback (only works if a Tk root exists).
    try:
        import tkinter as tk
        r = tk.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(text)
        r.update()
        r.destroy()
        return True
    except Exception:
        return False


# ─── Browser launcher ────────────────────────────────────────────────

def open_in_browser(service_id: str, hash_str: str) -> bool:
    """Open the service URL in the default browser AFTER copying the
    hash to the clipboard.  No automation — user pastes and drives."""
    svc = SERVICES.get(service_id)
    if not svc:
        return False
    copy_to_clipboard(hash_str)
    try:
        webbrowser.open(svc["url"], new=2)
        return True
    except Exception:
        return False


# ─── hashes.com API client ───────────────────────────────────────────

class HashesComClient:
    """Minimal REST client for hashes.com.

    Two endpoints matter:

      POST /api/jobs/add
          body: key=<KEY>, currency=BTC (ignored for free submissions),
                algo=<nnn>, hashes=<b64-encoded hash>
      GET  /api/founds?key=<KEY>

    The free tier lets you submit up to 50 hashes / week; after that
    you have to top up with a few bucks via BTC.  For a single AD
    pentest this is more than enough.

    Algo codes (hashes.com's internal numbering, NOT hashcat's):
      · 1000 → NTLM
      · 5600 → NetNTLMv2
      · 0    → MD5
      · 100  → SHA1
      · 1400 → SHA256
      · 3200 → bcrypt
    (they follow hashcat's mapping for convenience).
    """

    _API_BASE = "https://hashes.com/en/api"

    _ALGO = {
        "NTLM":         1000,
        "NetNTLMv2":    5600,
        "NetNTLMv1":    5500,
        "MD5":          0,
        "SHA1":         100,
        "SHA256":       1400,
        "bcrypt":       3200,
        "md5crypt":     500,
        "sha512crypt":  1800,
    }

    def __init__(self, api_key: str):
        self.api_key = api_key

    # ── Request helper ────────────────────────────────────────────────
    def _post(self, path: str, data: dict, timeout: int = 30) -> dict:
        try:
            body = urllib.parse.urlencode(data).encode("utf-8")
            req = urllib.request.Request(
                f"{self._API_BASE}{path}",
                data=body,
                method="POST",
                headers={"User-Agent": "HAWK-Crack/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return {"success": False,
                    "error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        try:
            return json.loads(raw)
        except Exception:
            return {"success": False,
                    "error": f"non-JSON response: {raw[:200]}"}

    def _get(self, path: str, params: dict,
             timeout: int = 30) -> dict:
        try:
            q = urllib.parse.urlencode(params)
            url = f"{self._API_BASE}{path}?{q}"
            req = urllib.request.Request(
                url, headers={"User-Agent": "HAWK-Crack/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return {"success": False,
                    "error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        try:
            return json.loads(raw)
        except Exception:
            return {"success": False,
                    "error": f"non-JSON response: {raw[:200]}"}

    # ── Public ops ────────────────────────────────────────────────────
    def submit(self, hash_str: str, hash_type: str) -> dict:
        """Submit a single hash for cracking.  Returns a dict with
        either {"success": True, "id": <job_id>} or
        {"success": False, "error": "..."}."""
        algo = self._ALGO.get(hash_type)
        if algo is None:
            return {"success": False,
                    "error": f"hashes.com has no algo code for "
                              f"'{hash_type}'"}
        import base64
        hashes_b64 = base64.b64encode(
            hash_str.encode() + b"\n").decode()
        return self._post("/jobs/add", {
            "key":      self.api_key,
            "currency": "BTC",  # required even for free submissions
            "algo":     algo,
            "hashes":   hashes_b64,
        })

    def poll_founds(self) -> dict:
        """List all hashes this key has successfully cracked.  Returns
        a list of {"hash": ..., "plaintext": ..., "algo": ...}
        dicts under key 'founds'."""
        return self._get("/founds", {"key": self.api_key})


# ─── Async submit + poll orchestrator ───────────────────────────────

class HashesComJob:
    """One-shot orchestrator — submit + poll in a daemon thread +
    invoke callbacks on the UI.

    Usage:
        job = HashesComJob(
            api_key=key, hash_str=h, hash_type="NetNTLMv2",
            on_status=lambda msg: terminal.write(msg),
            on_found=lambda cracked: store.mark_cracked(idx, cracked),
            on_done=lambda ok, msg: dialog.close(),
            ui_dispatcher=app.ui_call)
        job.start()
    """

    def __init__(self, api_key: str, hash_str: str, hash_type: str,
                 on_status=None, on_found=None, on_done=None,
                 ui_dispatcher=None,
                 poll_interval_sec: int = 20,
                 max_poll_minutes: int = 30):
        self.api_key = api_key
        self.hash_str = hash_str
        self.hash_type = hash_type
        self.on_status = on_status
        self.on_found = on_found
        self.on_done = on_done
        self.ui_dispatcher = ui_dispatcher
        self.poll_interval_sec = poll_interval_sec
        self.max_poll_minutes = max_poll_minutes

        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True,
            name="HAWK-HashesComJob")
        self._thread.start()

    def stop(self):
        self._stop.set()

    # ── Core flow ─────────────────────────────────────────────────────
    def _run(self):
        client = HashesComClient(self.api_key)

        self._status("Submitting hash to hashes.com API…")
        r = client.submit(self.hash_str, self.hash_type)
        if not r.get("success"):
            err = r.get("error") or r.get("message") or "unknown"
            self._status(f"  [!] submit failed: {err}")
            self._finish(False, err)
            return

        self._status("  [+] submitted — polling for result "
                      f"(every {self.poll_interval_sec}s, up to "
                      f"{self.max_poll_minutes} min).")

        deadline = time.time() + self.max_poll_minutes * 60
        # Short-circuit: first poll immediately in case hashes.com
        # already has this hash in their DB.
        while not self._stop.is_set() and time.time() < deadline:
            r = client.poll_founds()
            if r.get("success"):
                for entry in (r.get("founds") or r.get("list") or []):
                    # hashes.com echoes the full hash back; match by
                    # case-insensitive substring since SSP hashes get
                    # re-normalised.
                    h = (entry.get("hash") or "").lower()
                    if not h:
                        continue
                    if (h == self.hash_str.lower()
                            or self.hash_str.lower() in h
                            or h in self.hash_str.lower()):
                        cracked = (entry.get("plaintext")
                                   or entry.get("plain") or "")
                        if cracked:
                            self._status(
                                f"  [+] cracked: {cracked}")
                            self._found(cracked)
                            self._finish(True, cracked)
                            return
            else:
                err = r.get("error") or ""
                self._status(f"  [poll] {err or 'no match yet…'}")

            if self._stop.wait(self.poll_interval_sec):
                break

        self._status("  [!] poll window expired — no crack within "
                      f"{self.max_poll_minutes} min.  Re-submit later "
                      "or try a different service.")
        self._finish(False, "timeout")

    # ── Callback marshalling ──────────────────────────────────────────
    def _dispatch(self, fn, *args):
        if not fn:
            return
        try:
            if self.ui_dispatcher:
                self.ui_dispatcher(fn, *args)
            else:
                fn(*args)
        except Exception as e:
            print(f"[HAWK] hashes.com job callback: {e}")

    def _status(self, msg):
        self._dispatch(self.on_status, msg)

    def _found(self, cracked):
        self._dispatch(self.on_found, cracked)

    def _finish(self, ok, msg):
        self._dispatch(self.on_done, ok, msg)
