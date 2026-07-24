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
HAWK - Target Intel Widget v1.0
- Nmap vuln scripts findings → auto-populate intel
- Per-finding MSF launch button with pre-configured editable dialog
- OS Detection merge (don't overwrite existing ports)
- Single nonstandard port popup (flag)
- Spinner on all operations
"""

import customtkinter as ctk
import tkinter as tk
import os
import re
import time
import threading
import subprocess
import shlex
import json
import socket
import tempfile
import shutil
from datetime import datetime

from gui.widgets.target_intel_common import *

class TargetIntelConnectDialogMixin:
    def _show_connect_dialog(self, target, port, svc, svc_key, creds):
        """Profile-driven CONNECT dialog.

        Shows:
          • service card (icon, name, description)
          • ACTION selector (what the user actually wants to do)
          • extra per-action parameter fields (share name, URL path, DB, …)
          • auth block sized to the action's mode (anon/auth/hash/key)
          • live command preview
          • 'What this does' plain-English explanation
          • 'Expected result' block
          • 'If it fails' common-error cheat-sheet
          • pre-flight TCP reachability before launch
        """
        from gui.dialogs import (_make_win, _title, _note_box, _btn_row,
                                  _btn, _safe_destroy)
        from utils.clipboard import add_context_menu

        profile = self._get_profile(svc_key)

        # ── Fallback path: no profile → old generic dialog ──
        if not profile:
            return self._show_generic_connect(
                target, port, svc, svc_key, creds)

        # Static actions from the profile…
        actions  = list(profile["actions"])
        extras   = dict(profile.get("extras", {}))
        # …augmented with synthesized brute-force actions when the
        # service has a _BRUTE_PRESETS entry.  The `_build_brute_*`
        # helpers return [] / {} for services without a preset, so the
        # augment is a no-op when no brute makes sense (e.g. SMTP).
        try:
            actions.extend(self._build_brute_actions(svc_key))
            extras.update(self._build_brute_extras(svc_key))
        except Exception as _be:
            print(f"[HAWK] brute action injection failed: {_be}")
        icon     = profile.get("icon", "💻")
        title    = profile.get("title", svc_key.upper())

        win = _make_win(self, f"Connect — {title} :{port}", 720, 680)
        _title(win, f"{icon}  {title}   on   {target}:{port}")

        # Make main content scrollable — some services have a lot of text
        body = ctk.CTkScrollableFrame(
            win, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["text_dim"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 4))

        # ── Service description card ──
        desc_frame = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                  border_color=COLORS["border_dim"],
                                  border_width=1, corner_radius=4)
        desc_frame.pack(fill="x", padx=20, pady=(8, 10))
        ctk.CTkLabel(desc_frame, text=profile["desc"],
                     font=_f("sm"), text_color=COLORS["text_dim"],
                     wraplength=640, justify="left", anchor="w"
                     ).pack(fill="x", padx=12, pady=8)

        # ── TARGET GENERATION badge + override ──
        # Shows whether HAWK is emitting clean (modern) or compat (legacy/
        # unknown) commands.  The three radios let the user force the
        # classification when auto-detection was wrong.  The PROBE OS
        # button fires an async `nmap -O -sV` to refresh the fingerprint
        # without leaving the dialog.  Only rendered for services where
        # compat flags actually matter — others skip it to reduce noise.
        fp = self._get_fingerprint()
        svc_has_compat = (svc_key in self._COMPAT_FLAGS or
                          self._COMPAT_ALIASES.get(svc_key) in self._COMPAT_FLAGS)
        if fp is not None and svc_has_compat:
            gen_frame = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                     border_color=COLORS["border_dim"],
                                     border_width=1, corner_radius=4)
            gen_frame.pack(fill="x", padx=20, pady=(0, 10))

            # Badge line — port-scoped so the user sees what classification
            # applies to THIS port specifically (may differ from target-wide
            # when a per-port override is set).
            badge_row = ctk.CTkFrame(gen_frame, fg_color="transparent")
            badge_row.pack(fill="x", padx=12, pady=(8, 4))
            icon, label, hint = fp.generation_badge(port=port)
            gen_color_map = {
                "modern":  COLORS["text_green"],
                "legacy":  COLORS["text_yellow"],
                "unknown": COLORS["text_muted"],
            }
            badge_icon_var  = ctk.StringVar(value=f"{icon}  {label}")
            badge_hint_var  = ctk.StringVar(value=hint)
            _cur_gen = self._current_generation(port)
            badge_icon_lbl = ctk.CTkLabel(
                badge_row, textvariable=badge_icon_var,
                font=_f("md", True),
                text_color=gen_color_map.get(_cur_gen,
                                             COLORS["text_muted"]),
                anchor="w")
            badge_icon_lbl.pack(side="left")
            ctk.CTkLabel(badge_row, textvariable=badge_hint_var,
                         font=_f("sm"), text_color=COLORS["text_dim"],
                         anchor="w").pack(side="left", padx=(8, 0))

            # Scope label — makes explicit that the radio below applies
            # to THIS port only.  Clicking on the Connect dialog for a
            # different port opens an independent generation context.
            ctk.CTkLabel(gen_frame,
                         text=f"This override applies only to port {port}. "
                              f"Target-wide generation is unaffected.",
                         font=_f("sm"), text_color=COLORS["text_muted"],
                         anchor="w").pack(fill="x", padx=12, pady=(0, 2))

            # Radio + probe row — radio writes to fp._per_port_overrides[port]
            ctrl_row = ctk.CTkFrame(gen_frame, fg_color="transparent")
            ctrl_row.pack(fill="x", padx=12, pady=(0, 8))
            override_var = ctk.StringVar(
                value=fp.get_port_override(port))

            def _on_override_change(*_):
                try:
                    fp.set_port_override(port, override_var.get())
                    # No need to call classify_generation — per-port
                    # override takes precedence directly.
                    ic, lb, hn = fp.generation_badge(port=port)
                    badge_icon_var.set(f"{ic}  {lb}")
                    badge_hint_var.set(hn)
                    badge_icon_lbl.configure(
                        text_color=gen_color_map.get(
                            self._current_generation(port),
                            COLORS["text_muted"]))
                    # Persist to session so the port override survives reload
                    try:
                        sess = self.app.session_manager.current
                        if sess and hasattr(sess, "save"):
                            sess.save()
                    except Exception:
                        pass
                    _refresh_preview()
                except Exception:
                    pass

            for rv, rl in (("auto",   "Auto"),
                           ("modern", "Force modern"),
                           ("legacy", "Force legacy")):
                ctk.CTkRadioButton(
                    ctrl_row, text=rl, variable=override_var, value=rv,
                    font=_f("sm"), text_color=COLORS["text_bright"],
                    fg_color=COLORS["border_green"],
                    border_color=COLORS["border_dim"],
                    hover_color=COLORS["bg_card_hover"],
                    command=_on_override_change,
                    radiobutton_width=16, radiobutton_height=16,
                ).pack(side="left", padx=(0, 16))

            # PROBE OS — async nmap -O -sV refresh
            def _probe_os():
                """Fire nmap -O -sV on the current target in a worker
                thread.  On completion, merge the new fingerprint into
                the widget's _fp and refresh the badge + preview.  Uses
                ToolRunner so the user gets terminal output for free."""
                _safe_destroy_probe_btn = False
                try:
                    probe_btn.configure(state="disabled", text="PROBING…")
                except Exception:
                    pass
                import threading, subprocess as _sp
                def _worker():
                    try:
                        # -Pn to skip host discovery (target is known reachable)
                        # --top-ports 20 keeps it fast; -sV gives us banners
                        # for banner-based classification even when -O fails
                        # (requires root).  When run without root, nmap drops
                        # -O silently and still yields useful -sV data.
                        cmd = ["nmap", "-Pn", "-O", "-sV",
                               "--top-ports", "20",
                               "--max-retries", "1",
                               "--host-timeout", "45s",
                               target]
                        r = _sp.run(cmd, capture_output=True, text=True,
                                    timeout=60)
                        lines = (r.stdout or "").splitlines()
                    except Exception as e:
                        lines = [f"# probe failed: {e}"]
                    # Back to the UI thread for fingerprint merge
                    def _apply():
                        try:
                            from modules.exploit_suggester import OSFingerprint
                            new_fp = OSFingerprint.from_nmap_output(lines)
                            if new_fp.platform:
                                fp.platform   = new_fp.platform
                                fp.version    = new_fp.version
                                fp.confidence = max(fp.confidence,
                                                     new_fp.confidence)
                                fp.os_raw     = new_fp.os_raw or fp.os_raw
                            # Let _has_legacy_banner see any new banners
                            if new_fp.open_ports:
                                existing = {p for p,_,_,_ in fp.open_ports}
                                for tup in new_fp.open_ports:
                                    if tup[0] not in existing:
                                        fp.open_ports.append(tup)
                            fp.classify_generation()
                            ic, lb, hn = fp.generation_badge(port=port)
                            badge_icon_var.set(f"{ic}  {lb}")
                            badge_hint_var.set(hn)
                            badge_icon_lbl.configure(
                                text_color=gen_color_map.get(
                                    self._current_generation(port),
                                    COLORS["text_muted"]))
                            _refresh_preview()
                            try:
                                self.app.terminal.write(
                                    f"  [+] OS probe done: {fp.summary()}",
                                    "success")
                            except Exception:
                                pass
                        finally:
                            try:
                                probe_btn.configure(state="normal",
                                                    text="PROBE OS")
                            except Exception:
                                pass
                    try:
                        win.after(0, _apply)
                    except Exception:
                        pass
                threading.Thread(target=_worker, daemon=True).start()

            probe_btn = ctk.CTkButton(
                ctrl_row, text="PROBE OS",
                width=110, height=28, font=_f("sm", True),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_amber"],
                border_width=1, corner_radius=3,
                text_color=COLORS["text_yellow"],
                command=_probe_os,
            )
            probe_btn.pack(side="right")

        # ── ACTION selector ──
        ctk.CTkLabel(body, text="1.  CHOOSE WHAT TO DO",
                     font=_f("md", True),
                     text_color=COLORS["text_green"], anchor="w"
                     ).pack(fill="x", padx=20, pady=(4, 2))
        action_labels = [f"{a['label']}" for a in actions]
        action_var    = ctk.StringVar(value=action_labels[0])
        ctk.CTkOptionMenu(
            body, values=action_labels, variable=action_var,
            width=640, height=32, font=_f("sm"),
            fg_color=COLORS["bg_card"],
            button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_bright"], corner_radius=3,
        ).pack(fill="x", padx=20)

        # 'What this does' explanation (updates with action)
        what_var = ctk.StringVar(value=actions[0]["what"])
        ctk.CTkLabel(body, textvariable=what_var,
                     font=_f("sm"), text_color=COLORS["text_cyan"],
                     wraplength=640, justify="left", anchor="w"
                     ).pack(fill="x", padx=20, pady=(4, 8))

        # ────────────────────────────────────────────────────────────
        # Layout containers — packed NOW in the correct visual order
        # so that dynamically-rebuilt sections (extras, auth) always
        # appear ABOVE the command preview and reference material.
        # Each container is a transparent frame; its children are
        # populated by _build_extras() / _build_auth() on action change.
        # ────────────────────────────────────────────────────────────

        # 2. PARAMETERS (dynamic extras like share name, URL path…)
        extras_container = ctk.CTkFrame(body, fg_color="transparent")
        extras_container.pack(fill="x")
        extras_label = ctk.CTkLabel(
            extras_container, text="2.  PARAMETERS",
            font=_f("md", True),
            text_color=COLORS["text_green"], anchor="w")
        extras_frame = ctk.CTkFrame(extras_container, fg_color="transparent")
        extra_vars   = {}  # id → StringVar, rebuilt on action change

        # 3. AUTHENTICATION (username / password / hash — dynamic)
        auth_container = ctk.CTkFrame(body, fg_color="transparent")
        auth_container.pack(fill="x")
        auth_label = ctk.CTkLabel(
            auth_container, text="3.  AUTHENTICATION",
            font=_f("md", True),
            text_color=COLORS["text_green"], anchor="w")
        auth_frame = ctk.CTkFrame(auth_container, fg_color="transparent")

        user_var = ctk.StringVar(value="")
        pass_var = ctk.StringVar(value="")
        hash_var = ctk.StringVar(value="")
        store_var = ctk.StringVar(value="")
        use_store_var = ctk.BooleanVar(value=bool(creds))

        # 4. COMMAND PREVIEW (always visible)
        preview_container = ctk.CTkFrame(body, fg_color="transparent")
        preview_container.pack(fill="x")
        preview_label = ctk.CTkLabel(
            preview_container, text="4.  COMMAND PREVIEW",
            font=_f("md", True),
            text_color=COLORS["text_green"], anchor="w")
        preview_label.pack(fill="x", padx=20, pady=(6, 2))
        preview_var = ctk.StringVar(value="")
        preview_box = ctk.CTkFrame(
            preview_container, fg_color=COLORS["bg_primary"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3)
        preview_box.pack(fill="x", padx=20, pady=(0, 6))
        ctk.CTkLabel(preview_box, textvariable=preview_var,
                     font=_f("sm"), text_color=COLORS["text_cyan"],
                     wraplength=640, justify="left", anchor="w"
                     ).pack(fill="x", padx=10, pady=8)

        # 5. Reference material (static — packed once, stays at bottom)
        ref_container = ctk.CTkFrame(body, fg_color="transparent")
        ref_container.pack(fill="x")

        if profile.get("errors"):
            ctk.CTkLabel(ref_container, text="IF IT FAILS",
                         font=_f("sm", True),
                         text_color=COLORS["text_yellow"], anchor="w"
                         ).pack(fill="x", padx=20, pady=(4, 2))
            errs = profile["errors"]
            err_text = "\n".join(f"  • {k} → {v}" for k, v in errs.items())
            ctk.CTkLabel(ref_container, text=err_text,
                         font=_f("sm"), text_color=COLORS["text_dim"],
                         wraplength=640, justify="left", anchor="w"
                         ).pack(fill="x", padx=20, pady=(0, 6))

        if profile.get("flags"):
            ctk.CTkLabel(ref_container, text="FLAG REFERENCE",
                         font=_f("sm", True),
                         text_color=COLORS["text_green"], anchor="w"
                         ).pack(fill="x", padx=20, pady=(4, 2))
            flag_text = "\n".join(
                f"  {k:<18} {v}" for k, v in profile["flags"].items())
            ctk.CTkLabel(ref_container, text=flag_text,
                         font=_f("sm"), text_color=COLORS["text_dim"],
                         wraplength=640, justify="left", anchor="w"
                         ).pack(fill="x", padx=20, pady=(0, 8))

        if profile.get("expect"):
            ctk.CTkLabel(ref_container, text="EXPECTED RESULT",
                         font=_f("sm", True),
                         text_color=COLORS["text_green"], anchor="w"
                         ).pack(fill="x", padx=20, pady=(4, 2))
            ctk.CTkLabel(ref_container, text=profile["expect"],
                         font=_f("sm"), text_color=COLORS["text_dim"],
                         wraplength=640, justify="left", anchor="w"
                         ).pack(fill="x", padx=20, pady=(0, 6))

        # ═════════════════════════════════════════════════════════════
        # Dynamic UI builders
        # ═════════════════════════════════════════════════════════════

        def _clear(container):
            for w in container.winfo_children():
                w.destroy()

        def _build_extras(action):
            """Rebuild the extras section for the current action."""
            _clear(extras_frame)
            extra_vars.clear()
            needs = action.get("needs", [])
            # Always re-pack label+frame so the section is always visible
            extras_label.pack_forget()
            extras_frame.pack_forget()
            extras_label.pack(fill="x", padx=20, pady=(6, 2))
            extras_frame.pack(fill="x", padx=20, pady=(0, 4))
            if not needs:
                ctk.CTkLabel(extras_frame,
                             text="(no extra parameters needed)",
                             font=_f("sm"), text_color=COLORS["text_dim"]
                             ).pack(anchor="w", padx=4, pady=2)
                return
            for eid in needs:
                meta = extras.get(eid, {"label": eid.upper(),
                                        "default": "",
                                        "hint": ""})
                row = ctk.CTkFrame(extras_frame, fg_color="transparent")
                row.pack(fill="x", pady=3)
                ctk.CTkLabel(row, text=meta["label"] + ":",
                             width=120, anchor="w", font=_f("sm", True),
                             text_color=COLORS["text_bright"]
                             ).pack(side="left")
                v = ctk.StringVar(value=meta.get("default", ""))
                extra_vars[eid] = v
                e = ctk.CTkEntry(row, textvariable=v, font=_f("sm"),
                                 height=28,
                                 fg_color=COLORS["bg_card"],
                                 text_color=COLORS["text_bright"],
                                 border_color=COLORS["border_green"],
                                 border_width=1, corner_radius=3)
                e.pack(side="left", fill="x", expand=True, padx=(0, 8))
                add_context_menu(e)
                v.trace_add("write", lambda *_: _refresh_preview())
                if meta.get("hint"):
                    ctk.CTkLabel(extras_frame, text="      " + meta["hint"],
                                 font=_f("sm"),
                                 text_color=COLORS["text_dim"], anchor="w"
                                 ).pack(fill="x", padx=4, pady=(0, 4))

        def _build_auth(action):
            """Rebuild the auth section for the current action mode."""
            _clear(auth_frame)
            mode = action.get("mode", "anon")
            # Always re-pack label+frame so the section is always visible
            auth_label.pack_forget()
            auth_frame.pack_forget()
            auth_label.pack(fill="x", padx=20, pady=(6, 2))
            auth_frame.pack(fill="x", padx=20, pady=(0, 4))

            if mode == "anon":
                ctk.CTkLabel(auth_frame,
                             text="(no authentication needed for this action)",
                             font=_f("sm"), text_color=COLORS["text_dim"]
                             ).pack(anchor="w", padx=4, pady=2)
                return

            # ── Source-selector: cred store vs manual ────────────────────
            # When the store has applicable creds we render the full
            # picker (checkbox + dropdown).  When the store is empty for
            # this service (either nothing at all, or the available creds
            # were filtered out by _NO_ANON_CONNECT_SERVICES) we STILL
            # render a single-entry dropdown showing the manual-entry
            # sentinel — UX stays consistent, and a hint banner makes
            # explicit that the user should type the creds below.
            src_row = ctk.CTkFrame(auth_frame, fg_color="transparent")
            src_row.pack(fill="x", pady=2)

            if creds:
                ctk.CTkCheckBox(
                    src_row, text="Use credential from Store",
                    variable=use_store_var,
                    font=_f("sm"),
                    text_color=COLORS["text_bright"],
                    fg_color=COLORS["text_green"],
                    command=lambda: _toggle_src(action)
                ).pack(anchor="w")

                # Cred picker — first entry is the manual-entry sentinel
                # so the user can always opt out of auto-fill.
                cred_labels = [_MANUAL_ENTRY_LABEL]
                for i, c in enumerate(creds):
                    if c.cred_type == "cleartext":
                        v = c.password or c.cracked_pass or "(empty)"
                        cred_labels.append(
                            f"{i+1}. [CLEAR] {c.username} : {v}")
                    else:
                        if getattr(c, "cracked", False) and c.cracked_pass:
                            cred_labels.append(
                                f"{i+1}. [HASH·cracked] {c.username} → "
                                f"{c.cracked_pass}")
                        else:
                            hv = (c.hash_val or "")[-10:]
                            cred_labels.append(
                                f"{i+1}. [HASH] {c.username} … {hv}")
                # Auto-pick the best applicable credential at open so
                # the operator doesn't have to dig through the dropdown
                # for a credential HAWK already knows about.  Strategy:
                #   1. Ask _pick_best_cred for the most relevant one
                #      (service-tag match preferred, cleartext over hash).
                #   2. Find its index in `creds` to map to its dropdown
                #      label.
                #   3. Fall back to the first real cred in the list if
                #      _pick_best_cred returned None or the cred isn't
                #      in `creds` (it can be filtered out by anon-rules
                #      between picker and resolver).
                #   4. If nothing usable is found, default to the manual
                #      sentinel so the user can still type fresh creds.
                if not store_var.get() or store_var.get() not in cred_labels:
                    chosen_label = _MANUAL_ENTRY_LABEL
                    try:
                        best = self._pick_best_cred(svc_key, port)
                    except Exception:
                        best = None
                    if best is not None:
                        for i, c in enumerate(creds):
                            if (c.username == best.username
                                    and c.cred_type == best.cred_type
                                    and (c.password or c.hash_val)
                                        == (best.password or best.hash_val)):
                                # cred_labels[0] is _MANUAL_ENTRY_LABEL,
                                # so real cred i lives at cred_labels[i+1].
                                if i + 1 < len(cred_labels):
                                    chosen_label = cred_labels[i + 1]
                                break
                    if chosen_label == _MANUAL_ENTRY_LABEL and len(cred_labels) > 1:
                        chosen_label = cred_labels[1]
                    store_var.set(chosen_label)
                store_menu = ctk.CTkOptionMenu(
                    auth_frame, values=cred_labels, variable=store_var,
                    width=640, height=30, font=_f("sm"),
                    fg_color=COLORS["bg_card"],
                    button_color=COLORS["border_dim"],
                    dropdown_fg_color=COLORS["bg_secondary"],
                    dropdown_text_color=COLORS["text_bright"],
                    text_color=COLORS["text_bright"], corner_radius=3,
                )
                store_menu.pack(fill="x", pady=(2, 6))
            else:
                # No applicable creds in store → still show a dropdown
                # with just the manual-entry sentinel + an explicit hint
                # so the user understands the manual fields below are
                # the way to provide credentials.
                ctk.CTkLabel(
                    src_row,
                    text=("💡  No credentials in store for this service — "
                          "type them in the fields below"),
                    font=_f("sm"),
                    text_color=COLORS["text_yellow"],
                    anchor="w").pack(anchor="w", padx=2)
                store_var.set(_MANUAL_ENTRY_LABEL)
                store_menu = ctk.CTkOptionMenu(
                    auth_frame, values=[_MANUAL_ENTRY_LABEL],
                    variable=store_var,
                    width=640, height=30, font=_f("sm"),
                    state="disabled",       # nothing else to pick
                    fg_color=COLORS["bg_card"],
                    button_color=COLORS["border_dim"],
                    dropdown_fg_color=COLORS["bg_secondary"],
                    dropdown_text_color=COLORS["text_bright"],
                    text_color=COLORS["text_dim"], corner_radius=3,
                )
                store_menu.pack(fill="x", pady=(2, 6))

            # ── Manual fields ────────────────────────────────────────────
            # Bright cyan border on these entries makes them visually
            # stand out as "type here" — the cred-picker dropdown above
            # uses the dim border, so the eye naturally falls down to
            # the typing area.
            def _row(lbl, var, show="", placeholder=""):
                r = ctk.CTkFrame(auth_frame, fg_color="transparent")
                r.pack(fill="x", pady=2)
                ctk.CTkLabel(r, text=lbl + ":", width=160, anchor="w",
                             font=_f("sm", True),
                             text_color=COLORS["text_bright"]
                             ).pack(side="left")
                e = ctk.CTkEntry(
                    r, textvariable=var, show=show,
                    placeholder_text=placeholder,
                    font=_f("sm"), height=28,
                    fg_color=COLORS["bg_card"],
                    text_color=COLORS["text_bright"],
                    border_color=COLORS["text_cyan"],
                    border_width=2, corner_radius=3)
                e.pack(side="left", fill="x", expand=True)
                add_context_menu(e)
                return e

            # Pre-fill a sensible default username ONLY where the
            # default is the protocol-defined / vendor-shipped account
            # name (anonymous on FTP, root on Linux SSH, root on MySQL,
            # postgres on PostgreSQL).  Windows / AD services get NO
            # pre-fill — in real engagements the operator already knows
            # the target username (htb-student, mario.rossi, svc_backup,
            # CORP\\sa, …) and a hard-coded "administrator" just costs a
            # backspace+retype on every Connect.  When credentials ARE
            # in the store, the cred-picker auto-select takes care of
            # filling the field anyway.
            if not user_var.get():
                if svc_key == "ssh":
                    user_var.set("root")
                elif svc_key == "ftp":
                    user_var.set("anonymous")
                elif svc_key == "mysql":
                    user_var.set("root")
                elif svc_key == "postgresql":
                    user_var.set("postgres")

            _row("Username (type or paste)", user_var, show="",
                 placeholder="username")
            if mode == "auth":
                _row("Password (type or paste)", pass_var, show="*",
                     placeholder="password")
            elif mode == "hash":
                _row("NTLM hash (type or paste)", hash_var, show="",
                     placeholder="32-char NTLM hash")
            elif mode == "key":
                # keyfile is an extra field already — user still needed
                pass

        def _toggle_src(action):
            _build_auth(action)   # re-render (shows/hides manual entries)
            _refresh_preview()

        # ═════════════════════════════════════════════════════════════
        # Command builder
        # ═════════════════════════════════════════════════════════════

        def _current_action():
            lbl = action_var.get()
            for a in actions:
                if a["label"] == lbl:
                    return a
            return actions[0]

        def _fill_from_store(*_):
            """Pre-fill user/pass/hash fields from the selected store cred.

            When the manual-entry sentinel is selected, this is a no-op —
            we leave whatever the user has typed alone (don't even clear
            it, because that would erase their typing every time the
            dropdown event fires)."""
            if not creds or not use_store_var.get():
                return
            sel = store_var.get()
            if sel == _MANUAL_ENTRY_LABEL:
                # Explicit "type below" choice — don't touch the fields.
                return
            try:
                idx = int(sel.split(".", 1)[0]) - 1
                c   = creds[idx]
            except Exception:
                return
            user_var.set(c.username or "")
            if c.cred_type == "cleartext":
                pass_var.set(c.password or c.cracked_pass or "")
                hash_var.set("")
            else:
                pass_var.set(c.cracked_pass if getattr(c, "cracked", False) else "")
                hash_var.set(c.hash_val or "")

        def _resolve_creds(action):
            """Return (user, password, hash) for the current mode.
            Always reads from the UI fields — the store picker only
            pre-fills those fields, so manual edits are never lost."""
            mode = action.get("mode", "anon")
            if mode == "anon":
                return "", "", ""
            return (user_var.get().strip(),
                    pass_var.get().strip(),
                    hash_var.get().strip())

        def _build_cmd():
            action = _current_action()
            tpl = action["tpl"]
            u, pw, hv = _resolve_creds(action)

            # Resolve xfreerdp → xfreerdp3/xfreerdp2 (whichever is installed)
            # and substitute version-aware TLS/security flags
            if "xfreerdp" in tpl:
                from modules.base import _resolve_freerdp, _rdp_compat_flags
                tpl = tpl.replace("xfreerdp", _resolve_freerdp(), 1)
                tpl = tpl.replace("{rdp_flags}", _rdp_compat_flags())

            # Resolve {compat} → per-protocol compat flags based on the
            # target generation ("modern" → "", "legacy"/"unknown" → flags).
            # Uses self._apply_compat which also collapses double spaces
            # left by an empty expansion.  Done BEFORE the standard-token
            # substitution because the compat string for SMB contains
            # "{host}" which needs to flow through.  Port-scoped so the
            # per-port override radio takes effect.
            if "{compat}" in tpl:
                tpl = self._apply_compat(tpl, svc_key, host=target, port=port)

            # Substitute standard tokens
            out = (tpl.replace("{host}", target)
                      .replace("{port}", str(port))
                      .replace("{user}", u or "")
                      .replace("{pass}", pw or "")
                      .replace("{hash}", hv or ""))

            # Substitute extra-param tokens
            for eid, v in extra_vars.items():
                out = out.replace("{" + eid + "}", v.get())

            # Warn about unfilled required placeholders
            import re as _re
            unfilled = _re.findall(r"\{([a-z_]+)\}", out)
            if unfilled:
                out = f"# missing: {', '.join(unfilled)}\n" + out
            # Empty-password sanity check for auth modes
            mode = action.get("mode", "anon")
            if mode == "auth" and not pw:
                out = ("# WARNING: password is empty — command will likely "
                       "fail auth\n" + out)
            if mode == "hash" and not hv:
                out = ("# WARNING: hash is empty — pass-the-hash requires "
                       "a hash\n" + out)
            return out

        def _refresh_preview(*_):
            preview_var.set(_build_cmd())

        def _on_action_change(*_):
            action = _current_action()
            what_var.set(action["what"])
            _build_extras(action)
            _build_auth(action)
            _fill_from_store()        # pre-fill fields from selected cred
            _refresh_preview()

        action_var.trace_add("write", _on_action_change)
        user_var.trace_add("write",  _refresh_preview)
        pass_var.trace_add("write",  _refresh_preview)
        hash_var.trace_add("write",  _refresh_preview)
        # When the store dropdown changes or checkbox turns on → fill fields
        store_var.trace_add("write",
                            lambda *_: (_fill_from_store(), _refresh_preview()))
        use_store_var.trace_add("write",
                                lambda *_: (_fill_from_store(), _refresh_preview()))

        # Initial render
        _on_action_change()

        # ═════════════════════════════════════════════════════════════
        # Bottom bar (fixed)
        # ═════════════════════════════════════════════════════════════
        def _launch():
            cmd = preview_var.get().strip()
            # Strip leading comment lines (warnings) — run the last line only
            lines = [ln for ln in cmd.splitlines() if not ln.startswith("#")]
            cmd = "\n".join(lines).strip()
            if not cmd:
                self.app.terminal.write(
                    "  [!] Fill in the required fields first.", "warn")
                return

            # Active guard: empty-password sanity.  The preview-build
            # above drops a "# WARNING: password is empty" comment that
            # _launch silently strips, so the user never actually saw
            # the warning and the command ran with `/p:` empty anyway
            # (RDP/SSH/SMB → 99% auth failure).  Block here and require
            # an explicit override.
            #
            # EXCEPTION: when the username is a canonical anonymous
            # account for a protocol that ACCEPTS an empty password by
            # design (RFC 1635 FTP anonymous, SMB null session / guest),
            # the empty password is NOT a mistake — it's the protocol-
            # correct invocation.  Repeatedly nagging the user with the
            # "RUN ANYWAY" dialog on every retry is pure friction and
            # was the root cause of the user-reported "FTP anonymous
            # validate keeps asking for run anyway, Connect launches
            # multiple times" loop (last2_linux.json #553-#571).
            def _empty_pwd_is_protocol_normal(svc, uname):
                svc = (svc or "").lower()
                u   = (uname or "").strip().lower()
                # FTP RFC 1635: 'anonymous' and 'ftp' accept any
                # password (including empty / email-like dummies).
                if svc == "ftp":
                    return u in ("anonymous", "ftp")
                # SMB null session / guest auth: empty password is
                # the unauthenticated-enumeration idiom.
                if svc in ("smb", "microsoft-ds", "netbios-ssn"):
                    return u in ("", "guest")
                # MySQL / MariaDB on legacy / vanilla lab targets:
                # the canonical 'root' account often has NO password
                # set (Metasploitable2 vanilla, HTB starter boxes,
                # old shared-hosting MySQL).  An empty password here
                # is intentional and routinely correct, not a
                # mistake — same goes for the maintenance accounts
                # 'mysql' and 'admin'.
                if svc in ("mysql", "mariadb"):
                    return u in ("root", "mysql", "admin")
                # PostgreSQL: the bootstrap superuser 'postgres' is
                # frequently created with no / trust auth on local
                # listeners.  Empty password is the protocol-correct
                # invocation for that account.
                if svc in ("postgresql", "postgres"):
                    return u in ("postgres", "")
                return False

            action = _current_action()
            mode   = action.get("mode", "anon")
            # Combined guard: short-circuit on the override flag set
            # by a prior "RUN ANYWAY" click.  The earlier version
            # built the dialog FIRST and then checked the override —
            # which on re-entry instantiated a SECOND Toplevel dialog
            # before falling through to launch, so the user saw the
            # warning re-appear "on the background" every time they
            # clicked RUN ANYWAY (last2_linux.json: MySQL connect
            # repeat warn loop).  Checking the override at the TOP
            # of the condition means re-entry skips the entire
            # dialog branch — single warn, single click, clean
            # launch.  Cf. issue #16 in the bug tracker.
            if (mode == "auth"
                    and not pass_var.get()
                    and not _empty_pwd_is_protocol_normal(
                        svc_key, user_var.get())
                    and not getattr(_launch, "_override", False)):
                from gui.dialogs import (_make_win as _mw, _title as _t,
                                         _note_box as _nb, _btn_row as _br,
                                         _btn as _b, _safe_destroy as _sd)
                confirm = _mw(self, "Empty password", 520, 280)
                _t(confirm, "⚠  Password field is empty")
                _nb(confirm,
                    f"You picked 'auth' mode for {svc_key.upper()} but "
                    f"left the password blank.  This usually fails with "
                    f"LOGON_FAILURE / Permission denied.\n\n"
                    f"Run the command anyway only if:\n"
                    f"  • You're testing whether the account has NO "
                    f"password set (rare, lab-only).\n"
                    f"  • The service accepts anonymous where you meant "
                    f"'anonymous' — in which case switch the action "
                    f"selector to 'Anonymous login' instead.",
                    COLORS["text_yellow"])
                r = _br(confirm)
                def _go_anyway():
                    _sd(confirm)
                    # Mark this dialog instance as overridden and
                    # recurse; the top-of-conditional override check
                    # above will then short-circuit the warn rebuild.
                    _launch._override = True
                    _launch()
                _b(r, "RUN ANYWAY", _go_anyway, warn=True, w=160)
                _b(r, "CANCEL", lambda: _sd(confirm))
                # Block this launch — caller has to wait for the
                # user's choice (RUN ANYWAY recurses, CANCEL is no-op).
                return
            # If we reach here on a re-entry after RUN ANYWAY, reset
            # the override so a future Connect with a real empty-pwd
            # situation gets a fresh warn.
            if getattr(_launch, "_override", False):
                _launch._override = False
            # Block hash mode with empty hash the same way
            if mode == "hash" and not hash_var.get():
                self.app.terminal.write(
                    f"  [!] Pass-the-hash cancelled — NTLM hash field "
                    f"is empty.", "warn")
                return

            # Pre-flight TCP reachability check
            import socket
            reach = False
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((target, int(port)))
                s.close()
                reach = True
            except Exception:
                reach = False

            if not reach:
                self._show_unreachable_warning(target, port, cmd, win)
                return

            action = _current_action()

            # Credentials are NEVER saved at launch time.  They are only
            # added to the Credential Store when a captured parser
            # confirms a successful login (see _mark_creds_verified
            # in target_intel_parsers.py).  This eliminates the old
            # "[unverified]" entries that cluttered the store with
            # guesses the user typed into the dialog.

            # Snapshot user-typed creds BEFORE destroying the dialog —
            # widgets get torn down by _safe_destroy, so reading the
            # StringVars afterwards can return empty on some Tk backends.
            _u_typed  = user_var.get().strip()
            _pw_typed = pass_var.get().strip()
            _h_typed  = hash_var.get().strip()
            used_creds = (_u_typed, _pw_typed, _h_typed)

            _safe_destroy(win)
            # Captured actions run inline in HAWK terminal so we can parse the
            # output and push findings to Target Intel.  Interactive actions
            # (shells, binary protocols, auth prompts) still spawn an xterm.
            #
            # Pass the credentials the user actually typed so per-service
            # parsers can save a [verified] entry to the Credential Store
            # when they detect login success in the captured output.
            try:
                if self._action_is_captured(svc_key, action.get("id", "")):
                    # Lockout intercept: when the user picks a brute-force
                    # action on an AD-attached service (SMB/WinRM/RDP/LDAP/
                    # MSSQL), route through the lockout-aware popup so they
                    # can choose Spray / Kerberos / Slow / Patator / Policy
                    # check, or proceed with the original brute knowing the
                    # risk.  Non-AD services and non-brute actions skip the
                    # popup entirely.
                    aid = (action.get("id") or "").lower()
                    if (aid.startswith("brute")
                            and self._service_is_lockout_aware(svc_key)):
                        self._show_lockout_warning(
                            target, port, svc_key, cmd,
                            action, used_creds=used_creds)
                    else:
                        self._run_captured_connect(
                            cmd, target, port, svc, svc_key, action,
                            used_creds=used_creds)
                else:
                    aid = (action.get("id") or "").lower()
                    if aid == "browser" and "xdg-open" in cmd:
                        import subprocess as _sp
                        try:
                            _sp.Popen(["xdg-open", cmd.split("xdg-open ")[-1].strip()],
                                      stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
                            self.app.terminal.write(
                                f"  [*] Opening browser → {cmd.split('xdg-open ')[-1].strip()}",
                                "info")
                        except Exception as _e:
                            self.app.terminal.write(
                                f"  [!] Failed to open browser: {_e}", "error")
                        return

                    canon = self._canonical_profile_key(svc_key)
                    if _pw_typed and canon == "ssh" and "sshpass" not in cmd:
                        from shlex import quote as _shq
                        cmd = f"sshpass -p {_shq(_pw_typed)} {cmd}"
                    elif _pw_typed and canon == "ftp" and "printf" not in cmd:
                        from shlex import quote as _shq
                        cmd = (f"{{ printf 'user {_u_typed or 'anonymous'} "
                               f"{_pw_typed}\\npassive\\n'; cat; }} | "
                               f"ftp -nv {target} {port}")
                    elif _pw_typed and canon == "telnet":
                        from shlex import quote as _shq
                        cmd = (f"{{ sleep 1; printf '{_u_typed or 'root'}\\n'; "
                               f"sleep 1; printf '{_pw_typed}\\n'; cat; }} | "
                               f"telnet {target} {port}")
                    elif canon in ("mysql", "mariadb"):
                        # mysql / mariadb client -p flag handling:
                        # • -p with NO value → prompts for password.
                        #   Pressing Enter on empty sends an EMPTY
                        #   password attempt, which the server logs
                        #   as "using password: YES" and the user
                        #   root@'%' with NULL hash rejects (this is
                        #   the auth model on MySQL 5.x / MariaDB
                        #   10.x — Metasploitable2 reproduces it
                        #   exactly: ERROR 1045 (28000) "using
                        #   password: YES").
                        # • OMITTING -p entirely → "using password:
                        #   NO" attempt, which the server matches
                        #   against a user with NULL hash → success.
                        # • -p<value> inline (no space) → password
                        #   sent without prompt, "using password:
                        #   YES".  mysql client emits a security
                        #   warning about cleartext on cmdline, but
                        #   the auth succeeds.
                        # Strategy: when the field is empty, strip
                        # the trailing -p; when it carries a value,
                        # inline it as -p<value>.
                        if _pw_typed:
                            from shlex import quote as _shq
                            # Replace the bare ` -p` with ` -p<pwd>`.
                            # The template puts -p at the END of the
                            # mysql cmd so a simple suffix replace
                            # is safe; we also handle a trailing
                            # newline / extra whitespace.
                            cmd = cmd.replace(
                                " -p",
                                f" -p{_shq(_pw_typed)}", 1)
                        else:
                            # Drop the trailing ` -p` so the client
                            # sends NO password attempt at all.
                            cmd = cmd.replace(" -p", "", 1).rstrip()
                    # Surface the dispatch in the HAWK terminal so the
                    # user sees the launch even when the spawned xterm
                    # window pops up off-screen, behind another window,
                    # or fails silently — _open_connect_terminal will
                    # follow up with [+] Opened terminal: ... or [!].
                    try:
                        self.app.terminal.write(
                            f"  [*] Launching terminal for "
                            f"{(svc or svc_key).upper()} → {target}:{port} "
                            f"({action.get('label', action.get('id', '?'))})",
                            "info")
                    except Exception:
                        pass
                    self._open_connect_terminal(
                        cmd, target, port, svc,
                        action=action, used_creds=used_creds)
            except Exception as _le:
                # Surface any silent exception in the launch chain so the
                # user knows why nothing seemed to happen.
                import traceback as _tb
                try:
                    self.app.terminal.write(
                        f"  [!] Connect launch failed: {_le}", "error")
                    self.app.terminal.write(_tb.format_exc(), "dim")
                except Exception:
                    print(f"[HAWK] Connect launch failed: {_le}")
                    print(_tb.format_exc())

        row = _btn_row(win)
        # Build primary button inline so we can mutate its label based on
        # whether the selected action will be captured or interactive.
        launch_btn = ctk.CTkButton(
            row, text="OPEN TERMINAL", width=180, height=34,
            font=_f("md", True),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"],
            corner_radius=4, command=_launch,
        )
        launch_btn.pack(side="left", padx=6)
        _btn(row, "COPY CMD",
             lambda: self._copy_preview(preview_var.get()), w=110)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

        def _refresh_launch_btn(*_):
            a = _current_action()
            if self._action_is_captured(svc_key, a.get("id", "")):
                launch_btn.configure(text="CAPTURE & PARSE")
            else:
                launch_btn.configure(text="OPEN TERMINAL")

        action_var.trace_add("write", _refresh_launch_btn)
        _refresh_launch_btn()

    def _copy_preview(self, text):
        from utils.clipboard import clipboard_copy
        lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
        clipboard_copy("\n".join(lines).strip())
        self.app.terminal.write("  [*] Command copied to clipboard.", "dim")

    def _show_generic_connect(self, target, port, svc, svc_key, creds):
        """Fallback dialog when we don't have a profile for this service.
        Minimal UI — mode selector + preview + launch."""
        from gui.dialogs import (_make_win, _title, _note_box, _btn_row,
                                  _btn, _safe_destroy)
        from utils.clipboard import add_context_menu
        svc_label = (svc or svc_key).upper()
        win = _make_win(self, f"Connect — {svc_label} :{port}", 600, 420)
        _title(win, f"💻  CONNECT  —  {svc_label} on {target}:{port}")
        _note_box(win,
                  f"No detailed profile for '{svc_key}'. Generic mode.\n"
                  "Pick mode, then OPEN TERMINAL.",
                  COLORS["text_yellow"])

        user_var = ctk.StringVar(value="root")
        pass_var = ctk.StringVar(value="")
        mode_var = ctk.StringVar(value="manual")

        def _row(lbl, var, show=""):
            r = ctk.CTkFrame(win, fg_color="transparent")
            r.pack(fill="x", padx=24, pady=3)
            ctk.CTkLabel(r, text=lbl + ":", width=100, anchor="w",
                         font=_f("sm", True),
                         text_color=COLORS["text_bright"]).pack(side="left")
            e = ctk.CTkEntry(r, textvariable=var, show=show, font=_f("sm"),
                             height=28,
                             fg_color=COLORS["bg_card"],
                             text_color=COLORS["text_bright"],
                             border_color=COLORS["border_green"],
                             border_width=1, corner_radius=3)
            e.pack(side="left", fill="x", expand=True)
            add_context_menu(e)

        _row("Username", user_var)
        _row("Password", pass_var, show="*")

        preview = ctk.StringVar(value="")
        ctk.CTkLabel(win, textvariable=preview, font=_f("sm"),
                     text_color=COLORS["text_cyan"], wraplength=540,
                     justify="left", anchor="w"
                     ).pack(fill="x", padx=24, pady=(8, 4))

        def _refresh(*_):
            tpl = self._terminal_cmd_for(svc_key, port) or ""
            # Substitute {compat} first — its expansion itself contains
            # {host} (for SMB), which needs to flow through to the next
            # replace() pass.  Port-scoped so per-port overrides apply.
            if "{compat}" in tpl:
                tpl = self._apply_compat(tpl, svc_key, host=target, port=port)
            out = (tpl.replace("{host}", target)
                      .replace("{port}", str(port))
                      .replace("{user}", user_var.get() or "root")
                      .replace("{pass}", pass_var.get())
                      .replace("{hash}", ""))
            preview.set(out or "# no template available")
        user_var.trace_add("write", _refresh)
        pass_var.trace_add("write", _refresh)
        _refresh()

        def _launch():
            cmd = preview.get().strip()
            if not cmd or cmd.startswith("#"):
                return
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((target, int(port))); s.close()
                ok = True
            except Exception:
                ok = False
            if not ok:
                self._show_unreachable_warning(target, port, cmd, win)
                return
            _safe_destroy(win)
            self._open_connect_terminal(cmd, target, port, svc)

        row = _btn_row(win)
        _btn(row, "OPEN TERMINAL", _launch, primary=True, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _show_unreachable_warning(self, target, port, cmd, parent_win):
        """Host didn't answer TCP on <port>. Ask the user if they still
        want to launch the command — and explain why it will probably
        fail with NT_STATUS_IO_TIMEOUT / No route to host / etc."""
        from gui.dialogs import (_make_win, _title, _note_box, _btn_row,
                                  _btn, _safe_destroy)
        win = _make_win(parent_win, f"Host unreachable :{port}", 560, 420)
        _title(win, f"⚠  {target}:{port} did not answer")
        _note_box(win,
                  f"HAWK tried a 2-second TCP connect to {target}:{port}\n"
                  f"and got no response.\n\n"
                  f"Likely causes:\n"
                  f"  • The VM was paused / rebooted since last scan.\n"
                  f"  • A host firewall is dropping new sessions now.\n"
                  f"  • Routing changed (VPN flap, tun0 down).\n"
                  f"  • Port is filtered and only answers to specific\n"
                  f"    source IPs (HTB/THM lab restrictions).\n\n"
                  f"Launching the command now will almost certainly fail\n"
                  f"with NT_STATUS_IO_TIMEOUT (SMB) or 'No route to\n"
                  f"host' (WinRM/SSH).",
                  COLORS["text_red"])
        _note_box(win,
                  "Quick checks:\n"
                  f"  ping {target}\n"
                  f"  nmap -Pn -p {port} {target}\n"
                  f"  ip route get {target}",
                  COLORS["border_dim"])

        def _go_anyway():
            _safe_destroy(win)
            _safe_destroy(parent_win)
            self._open_connect_terminal(cmd, target, port, "")

        row = _btn_row(win)
        _btn(row, "RUN ANYWAY", _go_anyway, warn=True, w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

