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

"""WEB ASSAULT — UI routes for Injection Tester and JWT Analyzer.

Thin route layer: dialog widgets only.  All scan / crack logic lives
in `utils/injection_tester.py` and `utils/jwt_analyzer.py`.  All
shared state goes through `app.assault_state`.

This file is a sibling to `card_routes_oracle.py` so the two newer
offensive tools (added after the architectural split) don't bloat
the original Oracle/Crawl route file.
"""
import os
import re
import threading
from urllib.parse import urlparse

import customtkinter as ctk

from gui.widgets.card_common import (
    COLORS, _f, add_context_menu, STATUS_RUNNING,
)
# `_selectable_text` lives in gui.dialogs (it's the read-only selectable
# textbox helper used across all configurable dialogs).  Imported lazily
# inside the routes to avoid a hard dependency at module load.


# ───────────────────────────────────────────────────────────────────
# Helpers shared by both routes
# ───────────────────────────────────────────────────────────────────

def _truncate_token(tok: str, head: int = 28) -> str:
    """Display-format a JWT for the picker dropdown.

    Tokens are 200-1000+ chars; we want the user to recognise them
    in a list without dominating the row.  Show the header (helps
    distinguish HS256 vs RS256 from the prefix entropy)."""
    if not tok:
        return ""
    if len(tok) <= head + 12:
        return tok
    return f"{tok[:head]}…{tok[-8:]}  ({len(tok)} chars)"


def _wallarm_status() -> tuple[bool, str]:
    """Return (installed, path_or_empty) for jwt.secrets.list."""
    from utils.jwt_analyzer import find_wallarm_wordlist
    path = find_wallarm_wordlist()
    return (path is not None, path or "")


# ───────────────────────────────────────────────────────────────────
# Mixin
# ───────────────────────────────────────────────────────────────────

class CardAssaultRoutesMixin:

    # ─────────────────────────────────────────────────────────────
    # JWT ANALYZER
    # ─────────────────────────────────────────────────────────────
    def _route_jwt_analyzer(self, tool):
        """Open the JWT Analyzer config dialog.

        Auto-fed: AssaultState.jwt_tokens (from Bloody Crawl).
        Manual:   plain paste field.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy,
                                 _selectable_text)

        state = getattr(self.app, "assault_state", None)
        captured = state.get_jwt_tokens() if state else []

        win = _make_win(self, "JWT Analyzer — configuration", 760, 720)
        _title(win, "JWT ANALYZER")
        _sub(win,
             "Decodes JWTs, tests for weak signing secrets, alg:none "
             "acceptance, and role-escalation paths.  Pure Python — "
             "no external dependencies.",
             COLORS["text_dim"])

        scroll = ctk.CTkScrollableFrame(win, fg_color="transparent",
                                        height=460)
        scroll.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        # ── Token source ────────────────────────────────────────
        ctk.CTkLabel(scroll, text="TOKEN SOURCE",
                     font=_f("md", True),
                     text_color=COLORS["text_cyan"],
                     anchor="w").pack(fill="x", padx=20, pady=(8, 4))

        # Captured tokens (auto-fed) — one radio per token.  Default
        # selection points at the FIRST captured token when at least
        # one exists, so the user can hit START without doing anything.
        # When nothing was captured the default falls back to manual.
        token_var = ctk.StringVar(
            value=("captured:0" if captured else "__manual__"))
        if captured:
            ctk.CTkLabel(
                scroll,
                text=(f"📥  From AssaultState ({len(captured)} captured "
                      f"by Crawl):"),
                font=_f("sm"), text_color=COLORS["text_dim"],
                anchor="w").pack(fill="x", padx=24, pady=(4, 2))
            for i, jt in enumerate(captured):
                lbl = (f"[{jt.source}] {jt.where or '?'}: "
                       f"{_truncate_token(jt.token)}")
                ctk.CTkRadioButton(
                    scroll, text=lbl, variable=token_var,
                    value=f"captured:{i}",
                    font=_f("sm"), text_color=COLORS["text_bright"],
                    fg_color=COLORS["border_green"],
                    border_color=COLORS["border_dim"],
                ).pack(anchor="w", padx=44, pady=1)

        # Manual paste
        ctk.CTkRadioButton(
            scroll, text="📋  Paste token manually:",
            variable=token_var, value="__manual__",
            font=_f("sm"), text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(anchor="w", padx=24, pady=(8, 2))

        manual_box = ctk.CTkTextbox(
            scroll, height=70, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3,
            wrap="char")
        manual_box.pack(fill="x", padx=44, pady=(2, 8))
        add_context_menu(manual_box)

        # ── Tests ───────────────────────────────────────────────
        ctk.CTkLabel(scroll, text="TESTS",
                     font=_f("md", True),
                     text_color=COLORS["text_cyan"],
                     anchor="w").pack(fill="x", padx=20, pady=(12, 4))

        v_decode = ctk.BooleanVar(value=True)
        v_none   = ctk.BooleanVar(value=True)
        v_brute  = ctk.BooleanVar(value=True)
        for var, label, hint in (
            (v_decode, "Decode & analyze",
             "Header, payload, expiry, claims, role detection"),
            (v_none,   "alg:none forgery",
             "Build an unsigned token to verify against the server"),
            (v_brute,  "Weak-secret brute force",
             "HS256 only — try wordlist against the signature"),
        ):
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", padx=24, pady=2)
            ctk.CTkCheckBox(
                row, text=label, variable=var,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                width=16, height=16).pack(side="left")
            ctk.CTkLabel(row, text=f"  — {hint}",
                         font=_f("xs"),
                         text_color=COLORS["text_dim"],
                         anchor="w").pack(side="left")

        # ── Wordlist (only meaningful when brute is enabled) ────
        ctk.CTkLabel(scroll, text="WORDLIST FOR BRUTE-FORCE",
                     font=_f("md", True),
                     text_color=COLORS["text_cyan"],
                     anchor="w").pack(fill="x", padx=20, pady=(12, 4))

        wl_var = ctk.StringVar(value="builtin")
        installed, wallarm_path = _wallarm_status()

        ctk.CTkRadioButton(
            scroll,
            text="Built-in (≈100 framework defaults, ~0.3s)",
            variable=wl_var, value="builtin",
            font=_f("sm"), text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        ).pack(anchor="w", padx=24, pady=2)

        wl_radio_w = ctk.CTkRadioButton(
            scroll,
            text=(f"jwt.secrets.list (wallarm, ~700k entries) "
                  f"{'— detected: ' + wallarm_path if installed else '— ⚠ NOT installed'}"),
            variable=wl_var, value="wallarm",
            font=_f("sm"), text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
        )
        wl_radio_w.pack(anchor="w", padx=24, pady=2)
        if not installed:
            wl_radio_w.configure(state="disabled")

        # ── Wallarm install guide (always shown — user can act on it
        #    later even if they pick built-in for now)
        guide = ctk.CTkFrame(
            scroll, fg_color=COLORS["bg_card"], corner_radius=3,
            border_color=COLORS["border_dim"], border_width=1)
        guide.pack(fill="x", padx=24, pady=(8, 12))
        ctk.CTkLabel(
            guide, text="ABOUT  jwt.secrets.list",
            font=_f("sm", True), text_color=COLORS["text_cyan"],
            anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        _selectable_text(
            guide,
            ("Curated wordlist of ~700k JWT signing secrets harvested "
             "by Wallarm from public leaks, pen-test reports and "
             "SecLists. Best-in-class for HS256 weak-key recovery in "
             "CTFs and lab assessments."),
            color=COLORS["text_dim"], height=44)

        ctk.CTkLabel(
            guide, text="INSTALL",
            font=_f("sm", True), text_color=COLORS["text_cyan"],
            anchor="w").pack(fill="x", padx=10, pady=(6, 2))
        install_cmd = (
            "sudo mkdir -p /usr/share/wordlists/jwt && "
            "sudo wget -O /usr/share/wordlists/jwt/jwt.secrets.list "
            "https://raw.githubusercontent.com/wallarm/jwt-secrets/"
            "master/jwt.secrets.list")
        _selectable_text(
            guide, install_cmd, color=COLORS["text_bright"], height=58)

        cmd_row = ctk.CTkFrame(guide, fg_color="transparent")
        cmd_row.pack(fill="x", padx=10, pady=(0, 6))

        def _copy_install():
            try:
                from utils.clipboard import clipboard_copy
                clipboard_copy(install_cmd)
                self.app.terminal.write(
                    "  [*] Wallarm install command copied to clipboard.",
                    "info")
            except Exception:
                pass

        def _run_install():
            from utils.runner import _open_terminal
            _open_terminal(
                "HAWK — Install wallarm jwt.secrets.list",
                f"echo '=== Installing wallarm/jwt-secrets ==='; "
                f"{install_cmd}; "
                f"echo ''; ls -lh /usr/share/wordlists/jwt/jwt.secrets.list "
                f"2>/dev/null || echo 'install failed'; "
                f"read -p 'Press ENTER to close...'")

        ctk.CTkButton(
            cmd_row, text="COPY", width=80, height=24,
            font=_f("xs", True),
            fg_color=COLORS["bg_secondary"],
            hover_color=COLORS["bg_card_hover"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            command=_copy_install).pack(side="left", padx=2)
        ctk.CTkButton(
            cmd_row, text="RUN (xterm)", width=110, height=24,
            font=_f("xs", True),
            fg_color=COLORS["bg_secondary"],
            hover_color=COLORS["bg_card_hover"],
            text_color=COLORS["text_green"],
            border_color=COLORS["border_green"], border_width=1,
            command=_run_install).pack(side="left", padx=2)

        ctk.CTkLabel(
            guide, text="USAGE",
            font=_f("sm", True), text_color=COLORS["text_cyan"],
            anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        _selectable_text(
            guide,
            ("After install, this radio option auto-detects on next "
             "JWT Analyzer launch. Brute-force time: ~30-90s on a "
             "modern CPU vs ~0.3s for built-in (which catches obvious "
             "cases like 'secret', 'password', 'key')."),
            color=COLORS["text_dim"], height=58)
        ctk.CTkLabel(
            guide, text="WHAT IT FINDS",
            font=_f("sm", True), text_color=COLORS["text_cyan"],
            anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        _selectable_text(
            guide,
            ("HS256 tokens signed with weak/leaked secrets. Catches "
             "everything the built-in misses: framework defaults "
             "(Laravel \"base64:...\" prefixes), CI/CD template secrets, "
             "public Stack Overflow examples, Express/Flask tutorial "
             "secrets."),
            color=COLORS["text_dim"], height=72)

        # Inline validation banner — shown ONLY when the user clicks
        # START without supplying a token.  Without this the dialog
        # used to silently no-op (warning was logged to the terminal,
        # but the user is looking at the open dialog and didn't see it).
        error_lbl = ctk.CTkLabel(
            win, text="", font=_f("sm", True),
            text_color=COLORS["text_red"], anchor="w")
        error_lbl.pack(fill="x", padx=24, pady=(0, 4))

        # ── Launch ──────────────────────────────────────────────
        def _launch():
            sel = token_var.get()
            if sel.startswith("captured:"):
                idx = int(sel.split(":", 1)[1])
                token = captured[idx].token if idx < len(captured) else ""
            else:
                token = manual_box.get("1.0", "end").strip()
            if not token:
                msg = ("⚠ Paste a JWT in the box above (or pick one "
                       "from the captured list) — then press START.")
                error_lbl.configure(text=msg)
                # Mirror to terminal too so it's in the audit trail.
                self.app.terminal.write(
                    f"[!] JWT Analyzer: {msg}", "warn")
                return
            wl_choice = wl_var.get()
            if wl_choice == "wallarm" and installed:
                wordlist_path = wallarm_path
            else:
                wordlist_path = None  # use built-in
            _safe_destroy(win)

            self._set_tool_status(tool.id, "running")
            self.set_status(STATUS_RUNNING)
            self.app.terminal.section(
                f"JWT ANALYZER  ·  {token[:32]}…")

            self._run_jwt_analyzer(
                tool, token,
                do_decode=v_decode.get(),
                do_none=v_none.get(),
                do_brute=v_brute.get(),
                wordlist_path=wordlist_path)

        row = _btn_row(win)
        _btn(row, "START", _launch, primary=True, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _run_jwt_analyzer(self, tool, token, *,
                          do_decode, do_none, do_brute,
                          wordlist_path):
        """Spin up a JwtAnalyzerJob and pipe results into Target Intel."""
        from utils.jwt_analyzer import JwtAnalyzerJob

        state = getattr(self.app, "assault_state", None)
        if state is not None:
            state.set_step("jwt", "running")

        terminal = self.app.terminal
        log_lines = []

        def _on_log(msg, level="info"):
            self.app.after(0, lambda m=msg, l=level:
                           terminal.write(f"  {m}", l))
            log_lines.append((level, msg))

        def _on_progress(checked, hits):
            self.app.after(0, lambda c=checked: terminal.write(
                f"  [brute] tested {c} candidates…", "dim"))

        def _on_done(result):
            self.app.after(0, lambda r=result: self._jwt_finalize(
                tool, r, log_lines))

        cancel_event = (state.cancel_event if state is not None
                        else threading.Event())
        job = JwtAnalyzerJob(
            token=token, do_decode=do_decode, do_none=do_none,
            do_brute=do_brute, wordlist_path=wordlist_path,
            cancel_event=cancel_event,
            on_log=_on_log, on_progress=_on_progress,
            on_done=_on_done)
        # Track the job so the card-level STOP button can cancel it.
        if not hasattr(self, "_tool_runners"):
            self._tool_runners = {}
        self._tool_runners[tool.id] = job
        job.start()

    def _jwt_finalize(self, tool, result, log_lines):
        """Push WebFinding(s) to Target Intel, mark tool done."""
        terminal = self.app.terminal

        # Build description for the index card.
        parts = []
        parts.append(f"Algorithm: {result.algorithm or '?'}")
        if result.expires_at:
            parts.append(
                f"Expires: {result.expires_at} "
                f"({'EXPIRED' if result.expired else 'valid'})")
        if result.priv_claims:
            parts.append(
                f"Privilege claims present: "
                f"{', '.join(result.priv_claims)}")
        if result.cracked_secret:
            masked = (
                result.cracked_secret[:2]
                + "*" * max(0, len(result.cracked_secret) - 4)
                + result.cracked_secret[-2:]
                if len(result.cracked_secret) >= 4 else "***")
            parts.append(f"SECRET RECOVERED: \"{masked}\"  "
                         f"({len(result.cracked_secret)} chars; "
                         f"wordlist: {result.wordlist_used})")
        if result.forged_admin:
            parts.append("Forged admin token (priv claims flipped) "
                         "available in JWT Analyzer result.")
        if result.forged_none:
            parts.append("alg:none forgery built — verify against server.")
        parts.append(f"Elapsed: {result.elapsed_secs:.2f}s")

        SEV_RANK = {"critical": 0, "high": 1, "medium": 2,
                    "low": 3, "info": 4}
        worst = "info"
        for f in result.findings:
            if SEV_RANK.get(f.get("severity", "info"), 99) \
                    < SEV_RANK.get(worst, 99):
                worst = f.get("severity")

        title = ("JWT Analyzer — secret recovered"
                 if result.cracked_secret else
                 ("JWT Analyzer — alg:none accepted"
                  if any("none" in f.get("title","").lower()
                         for f in result.findings)
                  else "JWT Analyzer — token analysis"))

        try:
            self.app.target_intel.add_auto_finding(
                title=title, description="\n".join(parts),
                severity=worst, source="JWT Analyzer")
        except Exception as e:
            terminal.write(f"  [!] Could not push JWT finding: {e}",
                           "warn")

        # Per-finding entries (alg:none, secret recovered, etc.)
        for f in result.findings:
            if f.get("title") == "JWT decoded":
                continue   # the index card already has the decode
            ev = "\n".join(f.get("evidence", []) or [])
            desc = ev
            if f.get("impact"):
                desc += f"\n\nImpact: {f['impact']}"
            if f.get("remediation"):
                desc += f"\n\nRemediation: {f['remediation']}"
            try:
                self.app.target_intel.add_auto_finding(
                    title=f.get("title", "JWT finding"),
                    description=desc,
                    severity=f.get("severity", "info"),
                    source="JWT Analyzer")
            except Exception:
                pass

        state = getattr(self.app, "assault_state", None)
        if state is not None:
            state.set_step("jwt", "done")

        terminal.write(
            f"[+] JWT ANALYZER complete: "
            f"{len(result.findings)} finding(s) — "
            f"{result.elapsed_secs:.2f}s",
            "success")

        try:
            self._on_done(tool, tool.name, 0,
                          [(t, m) for t, m in log_lines])
        except Exception as e:
            terminal.write(f"  [!] _on_done error: {e}", "warn")


    # ─────────────────────────────────────────────────────────────
    # INJECTION TESTER
    # ─────────────────────────────────────────────────────────────
    def _route_injection_tester(self, tool):
        """Open the Injection Tester config dialog.

        Auto-fed: AssaultState.parameters and AssaultState.upload_forms
        Manual:   URL + parameter + method when state is empty.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)

        state = getattr(self.app, "assault_state", None)
        params  = state.get_parameters() if state else []
        uploads = state.get_upload_forms() if state else []

        win = _make_win(self, "Injection Tester — configuration",
                        780, 760)
        _title(win, "INJECTION TESTER")
        _sub(win,
             "Tests parameters for SQL injection, XSS, LFI, command "
             "injection, SSTI, and upload bypass.  Auto-fed from "
             "Bloody Crawl when available.",
             COLORS["text_dim"])

        scroll = ctk.CTkScrollableFrame(win, fg_color="transparent",
                                        height=520)
        scroll.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        # ── Targets ────────────────────────────────────────────
        ctk.CTkLabel(scroll, text="TARGETS",
                     font=_f("md", True),
                     text_color=COLORS["text_cyan"],
                     anchor="w").pack(fill="x", padx=20, pady=(8, 4))

        # Group params by (url, method) for clean display.
        grouped = {}
        for p in params:
            grouped.setdefault((p.url, p.method), []).append(p)
        upload_keys = {(u.url, u.method) for u in uploads}

        target_vars = []   # list of (BoolVar, key_str, label_str)
        if grouped or uploads:
            ctk.CTkLabel(
                scroll,
                text=(f"📥  From AssaultState  "
                      f"({len(grouped)} param-group(s), "
                      f"{len(uploads)} upload form(s)):"),
                font=_f("sm"), text_color=COLORS["text_dim"],
                anchor="w").pack(fill="x", padx=24, pady=(4, 2))
            # Param targets
            for (url, method), plist in sorted(grouped.items()):
                label = (f"{method} {urlparse(url).path or '/'}  "
                         f"({', '.join(p.name for p in plist[:6])}"
                         f"{', …' if len(plist) > 6 else ''})")
                if (url, method) in upload_keys:
                    label += "   📁 upload form"
                v = ctk.BooleanVar(value=True)
                target_vars.append((v, f"params::{url}::{method}",
                                     label))
                ctk.CTkCheckBox(
                    scroll, text=label, variable=v,
                    font=_f("sm"), text_color=COLORS["text_bright"],
                    fg_color=COLORS["border_green"],
                    border_color=COLORS["border_dim"],
                    width=14, height=14,
                ).pack(anchor="w", padx=44, pady=1)
            # Upload-only targets (no associated GET/POST params)
            for u in uploads:
                key = (u.url, u.method)
                if key in grouped:
                    continue
                label = (f"{u.method} {urlparse(u.url).path or '/'}  "
                         f"📁 upload form (file field: {u.file_field})")
                v = ctk.BooleanVar(value=True)
                target_vars.append((v, f"upload::{u.url}::{u.method}",
                                     label))
                ctk.CTkCheckBox(
                    scroll, text=label, variable=v,
                    font=_f("sm"), text_color=COLORS["text_bright"],
                    fg_color=COLORS["border_green"],
                    border_color=COLORS["border_dim"],
                    width=14, height=14,
                ).pack(anchor="w", padx=44, pady=1)
        else:
            _note_box(
                scroll,
                "AssaultState has no parameters yet.\n"
                "Run BLOODY CRAWL first OR use the manual fields below.",
                COLORS["border_dim"])

        # Manual entry (always available — power users / ad-hoc tests)
        ctk.CTkLabel(scroll, text="MANUAL TARGET (optional)",
                     font=_f("md", True),
                     text_color=COLORS["text_cyan"],
                     anchor="w").pack(fill="x", padx=20, pady=(12, 4))

        manual_url = ctk.StringVar(value="")
        manual_par = ctk.StringVar(value="")
        manual_met = ctk.StringVar(value="GET")
        for label, var, width in (
            ("URL:",       manual_url, 540),
            ("Parameter:", manual_par, 240),
        ):
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", padx=24, pady=2)
            ctk.CTkLabel(row, text=label, font=_f("sm", True),
                         text_color=COLORS["text_bright"],
                         width=80, anchor="w").pack(side="left")
            e = ctk.CTkEntry(row, textvariable=var,
                             font=_f("sm"), height=26, width=width,
                             fg_color=COLORS["bg_card"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=3)
            e.pack(side="left")
            add_context_menu(e)
        row = ctk.CTkFrame(scroll, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=2)
        ctk.CTkLabel(row, text="Method:", font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     width=80, anchor="w").pack(side="left")
        for m in ("GET", "POST"):
            ctk.CTkRadioButton(
                row, text=m, variable=manual_met, value=m,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
            ).pack(side="left", padx=8)

        # ── Tests ──────────────────────────────────────────────
        ctk.CTkLabel(scroll, text="TESTS",
                     font=_f("md", True),
                     text_color=COLORS["text_cyan"],
                     anchor="w").pack(fill="x", padx=20, pady=(12, 4))

        v_sqli = ctk.BooleanVar(value=True)
        v_xss  = ctk.BooleanVar(value=True)
        v_lfi  = ctk.BooleanVar(value=True)
        v_cmd  = ctk.BooleanVar(value=True)
        v_ssti = ctk.BooleanVar(value=True)
        v_up   = ctk.BooleanVar(value=bool(uploads))
        for var, label in (
            (v_sqli, "SQL Injection"),
            (v_xss,  "XSS (Reflected)"),
            (v_lfi,  "LFI / Path Traversal"),
            (v_cmd,  "Command Injection"),
            (v_ssti, "SSTI (Template Injection)"),
            (v_up,   "Upload Bypass (only meaningful on file forms)"),
        ):
            ctk.CTkCheckBox(
                scroll, text=label, variable=var,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                width=14, height=14,
            ).pack(anchor="w", padx=24, pady=1)

        # ── Mode ───────────────────────────────────────────────
        ctk.CTkLabel(scroll, text="MODE",
                     font=_f("md", True),
                     text_color=COLORS["text_cyan"],
                     anchor="w").pack(fill="x", padx=20, pady=(12, 4))
        mode_var = ctk.StringVar(value="safe")
        for val, label, hint in (
            ("safe", "SAFE — pure curl, light payloads, 1 req/s",
             "Detects errors and behavior diffs without external tools."),
            ("aggressive",
             "AGGRESSIVE — invokes sqlmap / dalfox / commix if installed",
             "Higher coverage, MUCH more traffic, may trigger WAF/IDS."),
        ):
            ctk.CTkRadioButton(
                scroll, text=label, variable=mode_var, value=val,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
            ).pack(anchor="w", padx=24, pady=2)
            ctk.CTkLabel(scroll, text=f"      {hint}",
                         font=_f("xs"),
                         text_color=COLORS["text_dim"],
                         anchor="w").pack(fill="x", padx=24)

        _note_box(
            scroll,
            "⚠ AGGRESSIVE MODE generates high traffic and may trigger "
            "WAFs/IDS.  Use only on authorised targets.",
            COLORS["text_yellow"])

        # ── Launch ─────────────────────────────────────────────
        def _launch():
            chosen_keys = [k for v, k, _ in target_vars if v.get()]
            manual = {
                "url":    manual_url.get().strip(),
                "param":  manual_par.get().strip(),
                "method": manual_met.get(),
            }
            if not chosen_keys and not (manual["url"] and manual["param"]):
                self.app.terminal.write(
                    "[!] Injection Tester cancelled — pick at least "
                    "one target or fill the manual fields.", "warn")
                return
            tests = {
                "sqli": v_sqli.get(),
                "xss":  v_xss.get(),
                "lfi":  v_lfi.get(),
                "cmd":  v_cmd.get(),
                "ssti": v_ssti.get(),
                "upload": v_up.get(),
            }
            mode = mode_var.get()
            _safe_destroy(win)

            self._set_tool_status(tool.id, "running")
            self.set_status(STATUS_RUNNING)
            self.app.terminal.section(
                f"INJECTION TESTER  ·  mode={mode}")

            self._run_injection_tester(
                tool, chosen_keys=chosen_keys, manual=manual,
                tests=tests, mode=mode,
                grouped=grouped, uploads=uploads)

        row = _btn_row(win)
        _btn(row, "START", _launch, primary=True, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _run_injection_tester(self, tool, *, chosen_keys, manual,
                                tests, mode, grouped, uploads):
        """Build the target list and dispatch to InjectionTesterJob."""
        from utils.injection_tester import (InjectionTesterJob,
                                             InjectTarget)

        state = getattr(self.app, "assault_state", None)
        if state is not None:
            state.set_step("inject", "running")

        targets = []
        # AssaultState-fed targets
        for key in chosen_keys:
            if key.startswith("params::"):
                _, url, method = key.split("::", 2)
                plist = grouped.get((url, method), [])
                targets.append(InjectTarget(
                    url=url, method=method,
                    params=[p.name for p in plist],
                    upload_field=None))
            elif key.startswith("upload::"):
                _, url, method = key.split("::", 2)
                u = next((u for u in uploads
                          if u.url == url and u.method == method), None)
                if u is not None:
                    targets.append(InjectTarget(
                        url=u.url, method=u.method or "POST",
                        params=list(u.other_fields),
                        upload_field=u.file_field))

        # Manual target
        if manual["url"] and manual["param"]:
            targets.append(InjectTarget(
                url=manual["url"], method=manual["method"],
                params=[manual["param"]], upload_field=None))

        terminal = self.app.terminal
        log_lines = []

        def _on_log(msg, level="info"):
            self.app.after(0, lambda m=msg, l=level:
                           terminal.write(f"  {m}", l))
            log_lines.append((level, msg))

        def _on_finding(finding):
            """A confirmed vulnerability — push to Target Intel
            immediately (don't wait for completion)."""
            self.app.after(0, lambda f=finding:
                           self._push_inject_finding(f))

        def _on_done(stats):
            self.app.after(0, lambda s=stats:
                           self._inject_finalize(tool, s, log_lines))

        cancel_event = (state.cancel_event if state is not None
                        else threading.Event())
        job = InjectionTesterJob(
            targets=targets, tests=tests, mode=mode,
            target_host=(state.target_host if state else ""),
            cancel_event=cancel_event,
            on_log=_on_log, on_finding=_on_finding,
            on_done=_on_done)
        if not hasattr(self, "_tool_runners"):
            self._tool_runners = {}
        self._tool_runners[tool.id] = job
        job.start()

    def _push_inject_finding(self, finding: dict):
        try:
            self.app.target_intel.add_auto_finding(
                title=finding.get("title", "Injection finding"),
                description=finding.get("description", ""),
                severity=finding.get("severity", "info"),
                source="Injection Tester")
        except Exception as e:
            self.app.terminal.write(
                f"  [!] could not push injection finding: {e}", "warn")

    def _inject_finalize(self, tool, stats, log_lines):
        terminal = self.app.terminal
        confirmed = stats.get("confirmed", 0)
        probable  = stats.get("probable", 0)
        elapsed   = stats.get("elapsed", 0.0)
        terminal.write(
            f"[+] INJECTION complete: {confirmed} confirmed, "
            f"{probable} probable — {elapsed:.1f}s", "success")
        state = getattr(self.app, "assault_state", None)
        if state is not None:
            state.set_step("inject", "done")
        try:
            self._on_done(tool, tool.name, 0,
                          [(t, m) for t, m in log_lines])
        except Exception as e:
            terminal.write(f"  [!] _on_done error: {e}", "warn")
