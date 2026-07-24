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
HAWK - Target Bar Widget
Top area: IP input, platform selector, session controls.
"""

import os
import re
import customtkinter as ctk
from utils.config import COLORS, WINDOW


# Keys we store on finding dicts to hold live Tk widget references —
# used by target_intel_widget.TargetIntelWidget._apply_read_style to
# repaint a single finding card in place instead of rerendering the
# whole auto_findings section.  These MUST be stripped before the
# session is serialised to JSON — Tk widgets are not JSON-serialisable.
#
# `_raw_description` carries the un-masked counterpart of a finding's
# description (Bloody Crawl JS-secret values).  It's deliberately kept
# in memory only — writing real tokens / emails / endpoints to a
# session JSON on disk would defeat the masking design (`mask_secret`
# in utils/web_findings.py).  After SAVE/LOAD the SHOW RAW toggle is
# disabled until the parser re-runs.
_FINDING_NON_PERSISTED_KEYS = (
    "_frame_ref", "_badge_ref", "_mark_btn_ref",
    "_raw_description",
    # AI-OPS finding side-data captured at probe time.  Re-detected
    # on the next probe run so it doesn't need to survive save/load.
    "_aiops_detected_version",
)
# Backward-compat alias — older code paths might still import the
# original name.  Same value, same semantics.
_FINDING_WIDGET_REF_KEYS = _FINDING_NON_PERSISTED_KEYS


def _strip_finding_widget_refs(findings):
    """Return a list of shallow-cloned finding dicts with widget
    references and other in-memory-only keys removed so the session
    serialiser doesn't trip on tkinter widget objects and doesn't leak
    un-masked secrets to disk."""
    out = []
    for f in findings or []:
        if not isinstance(f, dict):
            out.append(f)
            continue
        clean = {k: v for k, v in f.items()
                 if k not in _FINDING_NON_PERSISTED_KEYS}
        out.append(clean)
    return out


class TargetBar(ctk.CTkFrame):
    """
    Top input bar with:
    - Target IP entry
    - Platform selector (HTB / THM / Custom)
    - New Session / Save / Load buttons
    """

    def __init__(self, parent, app, **kwargs):
        super().__init__(
            parent,
            fg_color     = COLORS["bg_header"],
            border_width = 0,
            **kwargs
        )
        self.app = app
        # Autosave state — off by default. When enabled, a 5-minute timer
        # silently overwrites the current session file so long pentests
        # don't lose progress if HAWK crashes or the box reboots.
        self._autosave_on:       bool = False
        self._autosave_after_id: str  = None
        self._autosave_interval_ms: int = 5 * 60 * 1000   # 5 minutes
        self._build_ui()

    def _build_ui(self):
        # Compacted vs. v1.0 — entry/button heights 34→28, pady 8→3 per
        # row, row-3 NetHealth pady (4,8)→(2,3).  Saves ~25 px per row ×
        # 3 rows ≈ 75 px of vertical space that the operational panels
        # below gain.  Fonts intentionally untouched at 13-15 px so the
        # bar stays readable on a 1080p display.
        self.grid_columnconfigure(4, weight=1)

        # ── TARGET IP label ──
        ctk.CTkLabel(
            self,
            text="  TARGET IP:",
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            text_color=COLORS["text_dim"],
            width=110,
        ).grid(row=0, column=0, padx=(10, 4), pady=3, sticky="w")

        # ── IP Entry ──
        self._ip_entry = ctk.CTkEntry(
            self,
            width=210, height=28,
            placeholder_text="e.g. 10.10.10.1",
            font=ctk.CTkFont(family="Courier New", size=15),
            fg_color    = "#050505",
            text_color  = COLORS["text_bright"],
            border_color = COLORS["border_green"],
            border_width = 1,
            placeholder_text_color = COLORS["text_muted"],
            corner_radius = 3,
        )
        self._ip_entry.grid(row=0, column=1, padx=4, pady=3)
        self._ip_entry.bind("<Return>", lambda e: self._new_session())
        # Auto-insert dots while the user types an IPv4 address (skipped
        # when they are typing letters — e.g. a hostname).
        self._ip_entry.bind("<KeyRelease>", self._auto_dot_ip)

        # ── Platform selector ──
        ctk.CTkLabel(
            self,
            text="PLATFORM:",
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            text_color=COLORS["text_dim"],
        ).grid(row=0, column=2, padx=(12, 4), pady=3)

        self._platform_var = ctk.StringVar(value="HTB")
        # Propagate platform changes into the active session so SAVE /
        # AUTOSAVE persist the correct value even if the user flips
        # HTB ↔ THM ↔ Custom mid-session.  The guard flag prevents
        # this from firing when WE set the value programmatically
        # during session LOAD (which would mark the session dirty for
        # no reason).
        self._platform_suppress_trace = False

        def _on_platform_change(*_):
            if self._platform_suppress_trace:
                return
            try:
                sess = self.app.session_manager.current
                if sess is not None:
                    sess.platform = self._platform_var.get()
                    sess._touch()
                    # Update the header / status bar / terminal label
                    # so the change is visible immediately.
                    self._update_session_label(sess)
                    if hasattr(self.app, "status_bar"):
                        self.app.status_bar.set_session(
                            sess.target_ip, sess.platform)
                    self.app.title(
                        f"HAWK — {sess.target_ip} [{sess.platform}]")
                    self.app.terminal.write(
                        f"[*] Platform changed to {sess.platform}.  "
                        f"Saved on next SAVE / AUTOSAVE tick.", "dim")
            except Exception as e:
                print(f"[HAWK] platform trace error: {e}")
        self._platform_var.trace_add("write", _on_platform_change)

        # PLATFORM + VHOST live in a shared sub-frame so they stay
        # visually glued together regardless of how wide column 3 gets
        # (row 1's domain buttons widen column 3 far beyond the dropdown).
        plat_frame = ctk.CTkFrame(self, fg_color="transparent")
        plat_frame.grid(row=0, column=3, padx=(4, 0), pady=3, sticky="w")

        self._platform_menu = ctk.CTkOptionMenu(
            plat_frame,
            values=["HTB", "THM", "Custom"],
            variable=self._platform_var,
            width=110, height=28,
            font=ctk.CTkFont(family="Courier New", size=14),
            fg_color     = "#050505",
            button_color = COLORS["border_dim"],
            button_hover_color = "#1A3A1A",
            dropdown_fg_color  = "#0A0A0A",
            dropdown_text_color = COLORS["text_green"],
            text_color   = COLORS["text_green"],
            corner_radius = 3,
        )
        self._platform_menu.pack(side="left")

        self._vhost_btn = ctk.CTkButton(
            plat_frame,
            text="🌐 VHOST",
            width=90, height=22,
            font=ctk.CTkFont(family="Courier New", size=11),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"],
            border_width=1,
            text_color=COLORS["text_dim"],
            corner_radius=3,
            command=self._open_vhost_dialog,
        )
        self._vhost_btn.pack(side="left", padx=(4, 0))

        # ── Spacer (pushes action buttons to the right) ──
        ctk.CTkFrame(self, fg_color="transparent", width=1).grid(row=0, column=4, sticky="ew")

        # ── Action Buttons ──
        btn_cfg = [
            ("▶  NEW SESSION", self._new_session, COLORS["border_green"], COLORS["text_green"],  "#001500"),
            ("💾  SAVE",        self._save_session, COLORS["border_dim"],  COLORS["text_dim"],   COLORS["bg_card"]),
            ("⟳  AUTOSAVE",    self._toggle_autosave, COLORS["border_dim"], COLORS["text_dim"],  COLORS["bg_card"]),
            ("📂  LOAD",        self._load_session, COLORS["border_dim"],  COLORS["text_dim"],   COLORS["bg_card"]),
            ("🗑  DELETE SESSION", self._delete_session, COLORS["text_red"],     COLORS["text_red"],    "#1A0000"),
        ]

        for idx, (label, cmd, border, fg, bg) in enumerate(btn_cfg):
            btn = ctk.CTkButton(
                self,
                text=label,
                width=160 if idx == 0 else 120,
                height=28,
                font=ctk.CTkFont(family="Courier New", size=13, weight="bold" if idx == 0 else "normal"),
                fg_color     = bg,
                hover_color  = "#003000" if idx == 0 else "#1A1A1A",
                border_color = border,
                border_width = 1,
                text_color   = fg,
                corner_radius = 3,
                command=cmd,
            )
            btn.grid(row=0, column=5 + idx, padx=4, pady=3)
            # Keep a handle on the AUTOSAVE button so _toggle_autosave
            # can repaint it green/gray on state change.
            if "AUTOSAVE" in label:
                self._autosave_btn = btn

        # ── Row 1: TARGET DOMAIN (optional) ──
        ctk.CTkLabel(
            self,
            text="  TARGET DOMAIN:",
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            text_color=COLORS["text_dim"],
            width=110,
        ).grid(row=1, column=0, padx=(10, 4), pady=(0, 3), sticky="w")

        self._domain_entry = ctk.CTkEntry(
            self,
            width=320, height=28,
            placeholder_text="optional — e.g. example.com  (for subfinder/amass)",
            font=ctk.CTkFont(family="Courier New", size=14),
            fg_color    = "#050505",
            text_color  = COLORS["text_bright"],
            border_color = COLORS["border_dim"],
            border_width = 1,
            placeholder_text_color = COLORS["text_muted"],
            corner_radius = 3,
        )
        self._domain_entry.grid(row=1, column=1, columnspan=2, padx=4, pady=(0, 3), sticky="w")
        self._domain_entry.bind("<Return>", lambda e: self._save_domain())

        # SAVE/CHANGE + DELETE buttons live in a shared sub-frame so they
        # stay glued together regardless of column 3's weight=1 stretching.
        domain_btns = ctk.CTkFrame(self, fg_color="transparent")
        domain_btns.grid(row=1, column=3, padx=4, pady=(0, 3), sticky="w")

        # SAVE/CHANGE button — label switches to "CHANGE" once a domain has
        # been persisted on the current session.
        self._save_domain_btn = ctk.CTkButton(
            domain_btns,
            text="💾  SAVE DOMAIN",
            width=160, height=28,
            font=ctk.CTkFont(family="Courier New", size=13),
            fg_color     = COLORS["bg_card"],
            hover_color  = "#1A1A1A",
            border_color = COLORS["border_dim"],
            border_width = 1,
            text_color   = COLORS["text_dim"],
            corner_radius = 3,
            command=self._save_domain,
        )
        self._save_domain_btn.pack(side="left", padx=(0, 4))

        # DELETE DOMAIN button — clears both the entry and the saved value.
        self._delete_domain_btn = ctk.CTkButton(
            domain_btns,
            text="🗑  DELETE",
            width=120, height=28,
            font=ctk.CTkFont(family="Courier New", size=13),
            fg_color     = "#1A0000",
            hover_color  = "#2A0505",
            border_color = COLORS["text_red"],
            border_width = 1,
            text_color   = COLORS["text_red"],
            corner_radius = 3,
            command=self._delete_domain,
        )
        self._delete_domain_btn.pack(side="left")

        # Status label — "✓ Saved — example.com" / "⚠ invalid" / etc.
        # Previously gridded at column 4 which left a huge empty gap
        # between DELETE and the status text.  Packed here inside the
        # same sub-frame as the buttons so it stays visually glued to
        # the right edge of DELETE no matter how the parent columns
        # stretch.
        self._domain_status_lbl = ctk.CTkLabel(
            domain_btns,
            text="",
            font=ctk.CTkFont(family="Courier New", size=13),
            text_color=COLORS["text_muted"],
        )
        self._domain_status_lbl.pack(side="left", padx=(12, 0))

        # ── Row 2: Session info label ──
        self._session_label = ctk.CTkLabel(
            self,
            text="  No active session",
            font=ctk.CTkFont(family="Courier New", size=13),
            text_color=COLORS["text_muted"],
        )
        self._session_label.grid(row=2, column=0, columnspan=10, sticky="w", padx=10, pady=(0, 2))

        # ── Row 3: Network health + PROXYCHAINS button + "Coming Soon" ──
        # NetHealth on the left, PROXYCHAINS config button in the middle,
        # ARGUS plugin teaser button on the right.
        row3 = ctk.CTkFrame(self, fg_color="transparent")
        row3.grid(row=3, column=0, columnspan=10,
                  sticky="ew", padx=(4, 4), pady=(2, 4))

        from gui.widgets.net_health import NetHealthIndicator
        self._net_health = NetHealthIndicator(row3, app=self.app)
        self._net_health.pack(side="left")

        self._proxy_btn = ctk.CTkButton(
            row3,
            text="🔗  PROXY: reading...",
            width=220, height=26,
            font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"],
            border_width=1,
            text_color=COLORS["text_dim"],
            corner_radius=3,
            command=self._open_proxychains_dialog,
        )
        self._proxy_btn.pack(side="left", padx=(16, 0))
        self.after(200, self._refresh_proxy_button)

        cta_frame = ctk.CTkFrame(row3, fg_color="transparent")
        cta_frame.pack(side="right")
        self._build_coming_soon_buttons(cta_frame)

        # Reflect initial button state (no domain saved yet).
        self._refresh_domain_button_state(saved=False)

    # ─── Actions ───────────────────────────────────────────────────────────────

    # ─── IP input auto-formatting ──────────────────────────────────────────────

    def _auto_dot_ip(self, event):
        """Insert dots automatically while typing an IPv4 address.

        Triggers ONLY when the buffer is purely numeric (so hostnames like
        'target.htb' are untouched). When a dot is missing between octets
        that are already 3 digits long, one is inserted.
        """
        # Ignore navigation / modifier keys
        if event.keysym in ("Left", "Right", "Up", "Down", "Home", "End",
                             "Tab", "Shift_L", "Shift_R", "Control_L",
                             "Control_R", "Alt_L", "Alt_R", "BackSpace",
                             "Delete", "Return"):
            return
        raw = self._ip_entry.get()
        # If there's ANY letter, the user is typing a hostname → bail out
        if re.search(r"[A-Za-z]", raw):
            return
        # Strip anything that isn't digit or dot
        cleaned = re.sub(r"[^0-9.]", "", raw)
        # Collapse repeated dots
        cleaned = re.sub(r"\.{2,}", ".", cleaned)
        # Split into octets
        parts = cleaned.split(".")
        # Enforce max 3 digits per octet
        parts = [p[:3] for p in parts]
        # Auto-insert a dot after a full 3-digit octet if we're below 4 octets
        # and the user just typed a digit (not a dot).
        if (event.keysym not in ("period",) and
                len(parts) < 4 and
                len(parts[-1]) == 3):
            parts.append("")
        # Cap at 4 octets
        parts = parts[:4]
        new_val = ".".join(parts)
        if new_val != raw:
            # Preserve caret at the end (natural for typing)
            self._ip_entry.delete(0, "end")
            self._ip_entry.insert(0, new_val)

    def _new_session(self):
        target = self._ip_entry.get().strip()
        if not self._validate_ip(target):
            self.app.terminal.write(
                "[!] Invalid IP address. Enter a valid IPv4 (e.g. 10.10.10.1) or hostname.",
                "error"
            )
            self._ip_entry.configure(border_color=COLORS["text_red"])
            return

        self._ip_entry.configure(border_color=COLORS["border_green"])
        platform = self._platform_var.get()

        session = self.app.session_manager.new_session(target, platform)
        # New sessions start with stealth OFF (transparent mode is
        # the didactic default); the operator can flip the toggle
        # any time and it persists from that point on.
        # Reset domain field for the new session (keep it blank until user saves one)
        self._domain_entry.delete(0, "end")
        self._domain_entry.configure(border_color=COLORS["border_dim"])
        self._domain_status_lbl.configure(text="", text_color=COLORS["text_muted"])
        self._refresh_domain_button_state(saved=False)

        # Full reset of all panels
        self._reset_all_panels()

        self.app.terminal.section(f"NEW SESSION — {platform}  |  {target}")
        self.app.terminal.write(f"[+] Session started: {target}", "success")
        self.app.terminal.write(f"    Platform : {platform}", "info")
        self.app.terminal.write(f"    Session  : {session.session_id[:8]}", "info")

        self._update_session_label(session)
        self.app.kill_chain_panel.reset_all_statuses()
        self.app.status_bar.set_session(target, platform)
        self.app.title(f"HAWK — {target} [{platform}]")
        self._refresh_vhost_button()

        if platform in ("HTB", "THM"):
            self._show_vhost_info_dialog(platform)

    def _show_vhost_info_dialog(self, platform):
        from gui.dialogs import (_make_win, _title, _sub,
                                  _btn_row, _btn, _safe_destroy)

        win = _make_win(self, "VHOST — Auto-Detection", 520, 300)
        _title(win, "🌐  VHOST AUTO-DETECTION")
        _sub(win, f"Platform: {platform}", COLORS["text_green"])

        ctk.CTkLabel(
            win,
            text=(f"{platform} machines often redirect to hostnames "
                  f"(e.g. target.htb) that your system can't resolve.\n\n"
                  f"HAWK will automatically detect these hostnames "
                  f"after you run a port scan (NMAP Quick or NMAP Full) "
                  f"and add them to /etc/hosts so your browser "
                  f"and tools can reach the target.\n\n"
                  f"When you close HAWK, a dialog will ask whether "
                  f"to clean up these entries."),
            font=ctk.CTkFont(family="Courier New", size=13),
            text_color=COLORS["text_bright"],
            wraplength=480, justify="left", anchor="w",
        ).pack(fill="x", padx=16, pady=(8, 12))

        row = _btn_row(win)
        _btn(row, "GOT IT", lambda: _safe_destroy(win), primary=True, w=140)

    def _save_domain(self):
        """Persist target_domain on the current session so tools that need
        a domain (subfinder / amass) can auto-consume it without prompting.
        Also acts as CHANGE when a domain is already saved — the button label
        reflects which operation is being performed."""
        # Diagnostic terminal log — user-reported "CHANGE DOMAIN doesn't
        # work", this makes it obvious whether the click reached us and
        # why the operation might have bailed early (no session, invalid
        # domain string, unchanged value, etc.).
        try:
            self.app.terminal.write(
                f"  [*] SAVE/CHANGE DOMAIN clicked — "
                f"entry='{self._domain_entry.get()}'", "dim")
        except Exception:
            pass
        if not self.app.session_manager.current:
            self._domain_status_lbl.configure(
                text="  ⚠  Start a session first.",
                text_color=COLORS["text_yellow"])
            try:
                self.app.terminal.write(
                    "  [!] Can't save domain — no active session.  "
                    "Create one via NEW SESSION first.", "warn")
            except Exception:
                pass
            return
        raw = self._domain_entry.get().strip().rstrip(".")
        if not raw:
            # Empty entry → treat as an implicit clear. Use DELETE button for
            # an explicit clear with confirmation.
            self.app.session_manager.current.target_domain = ""
            # Clearing the domain also releases the pin — auto-
            # detection resumes normally on the next tool output.
            self.app.session_manager.current.target_domain_pinned = False
            try:
                self.app.session_manager.current.save()
            except Exception as e:
                print(f"[HAWK] clear-domain save failed: {e}")
            self._domain_entry.configure(border_color=COLORS["border_dim"])
            self._domain_status_lbl.configure(
                text="  ✖  Domain cleared.",
                text_color=COLORS["text_dim"])
            self._refresh_domain_button_state(saved=False)
            try:
                self.app.terminal.write(
                    "  [*] Domain field was empty — cleared saved value.",
                    "dim")
            except Exception:
                pass
            return
        try:
            from utils.target_validator import is_domain
        except Exception:
            is_domain = lambda s: True  # fallback
        if not is_domain(raw):
            self._domain_entry.configure(border_color=COLORS["text_red"])
            self._domain_status_lbl.configure(
                text="  ⚠  Not a valid domain.",
                text_color=COLORS["text_red"])
            return

        prev = (self.app.session_manager.current.target_domain or "").strip()
        is_change = bool(prev) and prev != raw
        self.app.session_manager.current.target_domain = raw
        # Mark the domain as USER-PINNED so subsequent auto-detection
        # from tool output (LDAP namingContexts, NTLM challenges,
        # reverse-DNS PTRs, nmap ssl-cert CN, …) never prompts to
        # override it.  Previously a high-confidence LDAP hit would
        # pop the override dialog even though the user had clearly
        # typed their intended value — now those candidates are just
        # logged to the terminal and surfaced as info findings.
        self.app.session_manager.current.target_domain_pinned = True
        self.app.session_manager.current.save()
        self._domain_entry.configure(border_color=COLORS["border_green"])

        if is_change:
            self._domain_status_lbl.configure(
                text=f"  ✓  Changed — {prev} → {raw}",
                text_color=COLORS["text_green"])
            log_msg = f"[+] Target domain changed: {prev} → {raw}"
        else:
            self._domain_status_lbl.configure(
                text=f"  ✓  Saved — {raw}",
                text_color=COLORS["text_green"])
            log_msg = f"[+] Target domain saved to session: {raw}"

        try:
            self.app.terminal.write(log_msg, "success")
        except Exception:
            pass
        self._refresh_domain_button_state(saved=True)

    def _delete_domain(self):
        """Explicit DELETE button — confirms, then wipes the domain from
        both the entry and the session."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn
        if not self.app.session_manager.current:
            self._domain_status_lbl.configure(
                text="  ⚠  Start a session first.",
                text_color=COLORS["text_yellow"])
            return
        current = (self.app.session_manager.current.target_domain or "").strip()
        entry_val = self._domain_entry.get().strip().rstrip(".")
        if not current and not entry_val:
            self._domain_status_lbl.configure(
                text="  —  No domain to delete.",
                text_color=COLORS["text_dim"])
            return

        win = _make_win(self, "Delete Target Domain", 440, 220)
        ctk.CTkLabel(win, text="Delete Target Domain?",
                     font=ctk.CTkFont(family="Courier New", size=15, weight="bold"),
                     text_color=COLORS["text_red"]).pack(pady=(20, 8))
        ctk.CTkLabel(
            win,
            text=f"Domain: {current or entry_val}\n"
                 "Subfinder / Amass will prompt again next time they run.",
            font=ctk.CTkFont(family="Courier New", size=12),
            text_color=COLORS["text_muted"], justify="center").pack(pady=4)

        def _confirm():
            _safe_destroy(win)
            try:
                self.app.session_manager.current.target_domain = ""
                # Release the pin too — auto-detection resumes.
                self.app.session_manager.current.target_domain_pinned = False
                self.app.session_manager.current.save()
            except Exception as e:
                print(f"[HAWK] delete domain failed: {e}")
            self._domain_entry.delete(0, "end")
            self._domain_entry.configure(border_color=COLORS["border_dim"])
            self._domain_status_lbl.configure(
                text="  ✖  Domain deleted.",
                text_color=COLORS["text_dim"])
            try:
                self.app.terminal.write(
                    "[*] Target domain removed from session.", "dim")
            except Exception:
                pass
            self._refresh_domain_button_state(saved=False)

        row = _btn_row(win)
        _btn(row, "DELETE", _confirm, danger=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    # ═══════════════════════════════════════════════════════════════
    #  "Coming Soon" teaser buttons (ARGUS)
    # ═══════════════════════════════════════════════════════════════
    #
    # These are hype buttons that live on the NetHealth row, right
    # side.  They do NOT launch real functionality yet — v2.0.0 of
    # HAWK will ship the features.  Click feedback is a small dialog
    # with a short pitch of what's coming.
    #
    # Visual spec (user-requested):
    #   * Dimmed border + text so they look unfinished but present
    #   * hand2 cursor + hover border glow so they clearly invite click
    #   * "only in v.2.0.0" neon-cyan label under the main text
    #   * Slow-pulsing dot (~3s cycle) on the left as a teaser cue
    #   * Hover tooltip with the full feature pitch
    #   * Click → _show_coming_soon_dialog with tagline + description

    def _build_coming_soon_buttons(self, parent):
        """Build the teaser button(s) inside `parent` (a frame).
        Called once from __init__ during row3 layout.

        CTAs auto-size their title label to the natural text width,
        then we normalise across all of them so the longest one
        dictates the width of every other (user requirement: "stessa
        dimensione, larghezza data in base a lunghezza testo").
        Height matches NEW SESSION (28 px) via the Courier-13-bold
        font + 3 px vertical padding."""
        self._teaser_title_labels: list = []

        # ARGUS — state-aware button (M1.5).  The plugin loader
        # resolves one of six PluginState values at HAWK boot; the
        # button visual + click handler are picked from that state.
        # See argus/docs/plugin-contract.md and hawkC/utils/plugin_loader.py.
        self._make_argus_button(parent)

        # ── Width normaliser ─────────────────────────────────────
        # After both buttons render once, measure their title labels
        # and resize the shorter one UP to the longest's width so the
        # two CTAs end up visually identical.  We queue the
        # normalisation twice (50 ms + 250 ms) because CTk's own
        # asynchronous layout sometimes reports a stale width on the
        # first pass.
        def _normalise_teaser_widths():
            try:
                labels = self._teaser_title_labels
                if not labels:
                    return
                widths = []
                for lbl in labels:
                    try:
                        lbl.update_idletasks()
                        widths.append(lbl.winfo_reqwidth())
                    except Exception:
                        continue
                if not widths:
                    return
                max_w = max(widths)
                for lbl in labels:
                    try:
                        lbl.configure(width=max_w)
                    except Exception:
                        pass
            except Exception as e:
                print(f"[HAWK] teaser width normalise failed: {e}")
        try:
            parent.after(50,  _normalise_teaser_widths)
            parent.after(250, _normalise_teaser_widths)
        except Exception:
            pass

    def _make_coming_soon_button(self, parent, *,
                                   title: str,
                                   tagline: str,
                                   description: str,
                                   tooltip: str = "",
                                   accent_color: str = None,
                                   lock_icon: str = "🔒",
                                   on_click=None) -> None:
        """Create one teaser button inside `parent`.

        The `tooltip` parameter is kept in the signature for call-site
        compatibility but no longer used — we previously rendered a
        custom hover tooltip via tk.Toplevel, but that combo fought
        with Kali's Xfce WM (override-redirect + deiconify stuck the
        window in withdrawn state) and the debug cycles dragged on.
        All the hype info is surfaced in the click-dialog instead,
        which is the native HAWK interaction everywhere else in the
        app.  Keeping the file noise-free.

        Optional extras (added in M1.5 for ARGUS state-aware buttons —
        defaults preserve the generic coming-soon teaser behaviour):
          accent_color  override border/title/lock colour (e.g. amber for
                        "license expired", red for plugin error)
          lock_icon     override the trailing icon ("🔒" by default;
                        "⏰" for expired, "⚠" for error, "" to drop)
          on_click      override the click handler (default is the
                        coming-soon dialog with the supplied texts)."""
        _ = tooltip  # silence unused-arg warnings

        # Colours — keep them const here so the pulse code stays
        # self-contained.
        dim_col    = accent_color if accent_color else COLORS["text_dim"]
        hover_col  = COLORS["text_cyan"]   # subtle border glow
        pulse_on   = "#FFFFFF"             # white heartbeat — neutral
        pulse_off  = COLORS["bg_card"]     # almost invisible on dark bg
        # Text sizes: title at 14 pt, padlock at 16 pt.  The 2-point
        # bump makes the lock visibly taller than the title line
        # while still fitting inside a ~28 px button, so the CTAs
        # stay the same height as NEW SESSION.  (Earlier tried
        # 18 pt — fit the glyph but grew the button to ~32 px and
        # broke the visual alignment with the action-button row.)
        title_size = 14
        lock_size  = 16
        # Lock icon — shared font/size/colour used BOTH on the
        # right side of the button AND at the start of the tooltip
        # first line, so the "locked" signal is visually consistent
        # across every place the button surface touches.
        lock_char  = lock_icon
        lock_font  = ctk.CTkFont(
            family="Courier New", size=lock_size)
        lock_color = dim_col

        # Outer shell — same style family as NEW SESSION (Courier 13
        # bold, 3 px corner radius, 1 px border).  Height is driven
        # by the single-line content: 13 pt font + 3 px padding on
        # top/bottom lands at ~28 px, matching NEW SESSION.  Width is
        # NOT fixed — the frame auto-sizes to its children, then
        # `_normalise_teaser_widths` (called from the caller) widens
        # the shorter button's title label so both end up identical.
        shell = ctk.CTkFrame(
            parent,
            fg_color=COLORS["bg_card"],
            border_color=dim_col,
            border_width=1,
            corner_radius=3,
            cursor="hand2",
        )
        shell.pack(side="left", padx=(6, 0))

        # Main row (single line, NO sublabel).  Horizontal layout:
        #   ●          TITLE          🔒
        # Dot is packed left, lock is packed right, title fills the
        # space in between with anchor="center" — this produces a
        # visually centred title regardless of its text length.
        # Pack order matters: dot + lock first grab their edges, then
        # title's fill=x+expand=True takes everything that remains.
        inner = ctk.CTkFrame(shell, fg_color="transparent")
        inner.pack(fill="x", padx=8, pady=3)

        dot = ctk.CTkLabel(
            inner, text="●",
            font=ctk.CTkFont(
                family="Courier New", size=title_size, weight="bold"),
            text_color=pulse_off,
        )
        dot.pack(side="left", padx=(0, 6))
        # Lock first (packed right) so title can expand into the
        # middle on its own fill=x pass.
        lock_lbl = ctk.CTkLabel(
            inner, text=lock_char,
            font=lock_font,
            text_color=lock_color,
        )
        lock_lbl.pack(side="right", padx=(6, 0))
        title_lbl = ctk.CTkLabel(
            inner, text=title,
            font=ctk.CTkFont(
                family="Courier New", size=title_size, weight="bold"),
            text_color=dim_col,
            anchor="center",
        )
        # NOTE: NO fill="x", NO expand=True.  Those pack options force
        # the label to grow to fill any leftover horizontal space,
        # which overrides the width= attribute and breaks the width
        # normaliser across multiple teaser buttons.  By packing with
        # plain side="left" the label honours its `width` attribute,
        # so the normaliser can resize every title label to the same
        # pixel width after initial render.  The `anchor="center"`
        # still centres the text inside that allocated width.
        title_lbl.pack(side="left")
        # Track this label so the width normaliser can resize it
        # later (both CTAs end up matching the longer title).
        try:
            self._teaser_title_labels.append(title_lbl)
        except Exception:
            pass

        # ── Pulsing dot animation ─────────────────────────────────
        # Toggle every 3500 ms → full on/off cycle ≈ 7 s, the "slow
        # ambient heartbeat" the user asked for.  Faster cycles read
        # as status LEDs / error indicators; 7 s is unambiguously
        # decorative.
        _pulse_state = {"on": False}
        def _pulse():
            try:
                if not dot.winfo_exists():
                    return
            except Exception:
                return
            _pulse_state["on"] = not _pulse_state["on"]
            try:
                dot.configure(
                    text_color=pulse_on if _pulse_state["on"]
                                else pulse_off)
            except Exception:
                pass
            try:
                dot.after(3500, _pulse)
            except Exception:
                pass
        dot.after(1000, _pulse)

        # ── Click handler → teaser dialog ────────────────────────
        # customtkinter's CTkLabel delegates .bind() to its internal
        # tk.Label, and that same internal tk.Label ALSO shows up as
        # a child of CTkLabel when we walk winfo_children().  Naive
        # recursive bind therefore hits the handler TWICE on every
        # click — which is the "dialog opens on top of itself, need
        # two OKs" bug the user reported.  Fix below: we bind click
        # only on CTk* container widgets and rely on CTk's own bind
        # delegation to reach the underlying tk.Label.
        _click_fired = {"ts": 0.0}
        def _on_click(_event=None):
            import time as _t
            now = _t.time()
            # Guard against double-fire within 250 ms even if the
            # defensive recursion rules above ever drift.
            if now - _click_fired["ts"] < 0.25:
                return
            _click_fired["ts"] = now
            try:
                if on_click is not None:
                    on_click()
                else:
                    self._show_coming_soon_dialog(
                        title=title,
                        tagline=tagline,
                        description=description)
            except Exception as e:
                print(f"[HAWK] coming-soon dialog error: {e}")

        # ── Hover border glow (polled once per 150 ms) ───────────
        # Cheap in-place poll just to toggle the border between
        # dimmed and cyan on hover.  Uses pure bbox math (no
        # winfo_containing, no Enter/Leave bindings) so it's
        # immune to Tk / customtkinter event-propagation quirks.
        def _hover_poll():
            try:
                if not shell.winfo_exists():
                    return
                sx = shell.winfo_rootx()
                sy = shell.winfo_rooty()
                sw = shell.winfo_width()
                sh = shell.winfo_height()
                if sw > 1 and sh > 1:
                    px = shell.winfo_pointerx()
                    py = shell.winfo_pointery()
                    inside = (sx <= px < sx + sw
                              and sy <= py < sy + sh)
                    shell.configure(
                        border_color=hover_col if inside
                                     else dim_col)
            except Exception:
                pass
            try:
                shell.after(150, _hover_poll)
            except Exception:
                pass
        try:
            shell.after(400, _hover_poll)
        except Exception:
            pass

        # ── Click binding — CTk containers only ──────────────────
        # Bind <Button-1> on the shell + inner + the 3 CTkLabels.
        # CRITICAL: we do NOT recurse into each CTkLabel because
        # customtkinter already delegates the bind to the internal
        # tk.Label — walking winfo_children() would bind the same
        # internal label a second time and the click handler would
        # fire twice (→ two stacked dialogs, double-OK bug).
        for _w in (shell, inner, dot, title_lbl, lock_lbl):
            try:
                _w.bind("<Button-1>", _on_click, add="+")
                _w.configure(cursor="hand2")
            except Exception:
                pass

    # ═══════════════════════════════════════════════════════════════
    #  ARGUS — state-aware button + plugin window (M1.5)
    # ═══════════════════════════════════════════════════════════════

    def _make_argus_button(self, parent) -> None:
        """Build the ARGUS button matched to the current plugin state.

        Six logical states from the plugin loader collapse into four
        visual buckets:
          NOT_INSTALLED / IMPORT_ERROR / INCOMPATIBLE → grey lock teaser
          NO_LICENSE                                  → amber lock teaser
          EXPIRED                                     → amber clock teaser
          ACTIVE                                      → cyan functional button

        The dialog text is state-specific so the operator gets a
        precise next step (install, license, renew, error detail).
        """
        from utils.plugin_loader import discover_argus, PluginState

        loader = discover_argus()
        # Stash on `self` so _open_argus_window and shutdown can reach it.
        self._argus_loader = loader

        if loader.state is PluginState.ACTIVE:
            self._make_argus_active_button(parent)
            return

        # ── state-specific teaser content ──────────────────────────
        amber = COLORS["text_yellow"]
        red   = COLORS["text_red"]
        if loader.state is PluginState.NOT_INSTALLED:
            cfg = dict(
                title="ARGUS",
                accent_color=None,        # default grey
                lock_icon="🔒",
                tagline="ARGUS plugin is not installed.",
                description=(
                    "ARGUS is a paid plugin for HAWK that maps the "
                    "defensive controls of an authorised target — "
                    "outside-in (network blackbox) and inside-out "
                    "(host snapshot).\n\n"
                    "Categories detected: Network Filtering, Service "
                    "Exposure, HTTP/TLS Mediation, Response Anomalies, "
                    "Deception Likelihood.\n\n"
                    "Install:  pip install hawk-argus\n"
                    "License:  obtain at the ARGUS landing page."),
            )
        elif loader.state is PluginState.NO_LICENSE:
            cfg = dict(
                title="ARGUS — license required",
                accent_color=amber,
                lock_icon="🔒",
                tagline="ARGUS is installed but no valid license was found.",
                description=(
                    f"Reason: {loader.error}\n\n"
                    "Drop your license file at:\n"
                    "  ~/.hawk/argus_license.bin\n\n"
                    "If you don't have one, get a license at the "
                    "ARGUS landing page (Trial: 30 days free)."),
            )
        elif loader.state is PluginState.EXPIRED:
            cfg = dict(
                title="ARGUS — license expired",
                accent_color=amber,
                lock_icon="⏰",
                tagline="Your ARGUS license has expired.",
                description=(
                    f"Details: {loader.error}\n\n"
                    "Renew to continue receiving Vendor Evidence "
                    "Pack updates and to unlock the ARGUS tab."),
            )
        elif loader.state is PluginState.INCOMPATIBLE:
            cfg = dict(
                title="ARGUS — incompatible plugin",
                accent_color=red,
                lock_icon="⚠",
                tagline="ARGUS plugin requires a different HAWK API version.",
                description=(
                    f"Details: {loader.error}\n\n"
                    "Update HAWK to a matching minor release or "
                    "downgrade the ARGUS plugin to a compatible "
                    "version."),
            )
        else:  # IMPORT_ERROR or any unexpected future state
            cfg = dict(
                title="ARGUS — plugin error",
                accent_color=red,
                lock_icon="⚠",
                tagline="ARGUS plugin failed to load.",
                description=(
                    f"Details: {loader.error}\n\n"
                    "Reinstall the ARGUS plugin or check the HAWK "
                    "console for the underlying traceback."),
            )

        self._make_coming_soon_button(parent, tooltip="", **cfg)

    def _make_argus_active_button(self, parent) -> None:
        """Active ARGUS button — cyan accent, no lock, opens plugin window."""
        cyan = COLORS["text_cyan"]
        shell = ctk.CTkFrame(
            parent,
            fg_color=COLORS["bg_card"],
            border_color=cyan,
            border_width=1,
            corner_radius=3,
            cursor="hand2",
        )
        shell.pack(side="left", padx=(6, 0))

        inner = ctk.CTkFrame(shell, fg_color="transparent")
        inner.pack(fill="x", padx=8, pady=3)

        # Heartbeat dot stays — same visual language as the teasers,
        # but coloured cyan to mark "live" instead of grey "locked".
        dot = ctk.CTkLabel(
            inner, text="●",
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            text_color=cyan,
        )
        dot.pack(side="left", padx=(0, 6))

        title_lbl = ctk.CTkLabel(
            inner, text="ARGUS",
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            text_color=cyan,
            anchor="center",
        )
        title_lbl.pack(side="left")
        try:
            self._teaser_title_labels.append(title_lbl)
        except Exception:
            pass

        # Click handler — same double-fire guard pattern as the teaser.
        _click_fired = {"ts": 0.0}
        def _on_click(_event=None):
            import time as _t
            now = _t.time()
            if now - _click_fired["ts"] < 0.25:
                return
            _click_fired["ts"] = now
            try:
                self._open_argus_window()
            except Exception as e:
                print(f"[HAWK] ARGUS open failed: {e}")

        for _w in (shell, inner, dot, title_lbl):
            try:
                _w.bind("<Button-1>", _on_click, add="+")
                _w.configure(cursor="hand2")
            except Exception:
                pass

    def _open_argus_window(self) -> None:
        """Mount the ARGUS plugin in a Toplevel CTk window.

        First click creates the window and mounts the plugin.
        Subsequent clicks raise the existing window.
        Closing the window unmounts and destroys; the next click will
        re-mount cleanly (the contract's "once per session" is honoured
        within each window lifetime; the v0.1 plugin is idempotent
        across cycles)."""
        loader = getattr(self, "_argus_loader", None)
        if loader is None:
            return
        from utils.plugin_loader import PluginState
        if loader.state is not PluginState.ACTIVE:
            return

        # Reuse an existing window if still alive.
        existing = getattr(self, "_argus_win", None)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.deiconify()
                    existing.lift()
                    existing.focus_force()
                    return
            except Exception:
                pass

        win = ctk.CTkToplevel(self.app)
        win.title("ARGUS — security validation and evidence correlation")
        win.geometry("1100x700")
        win.minsize(880, 560)

        container = ctk.CTkFrame(win, fg_color=COLORS["bg_primary"])
        container.pack(fill="both", expand=True)

        api = self._build_hawk_api()
        if not loader.mount(container, api):
            ctk.CTkLabel(
                container,
                text=f"ARGUS failed to mount: {loader.error}",
                text_color=COLORS["text_red"],
            ).pack(expand=True)

        self._argus_win = win

        def _on_close():
            try:
                loader.unmount()
            except Exception as e:
                print(f"[HAWK] ARGUS unmount on close raised: {e}")
            try:
                win.destroy()
            except Exception:
                pass
            self._argus_win = None

        win.protocol("WM_DELETE_WINDOW", _on_close)

    def _build_hawk_api(self):
        """Build a HawkAPI-compatible callback handle for the plugin.

        See argus/docs/plugin-contract.md §2 (HawkAPI surface).  This
        is the only legal way for the plugin to reach back into HAWK.
        """
        from utils.config import APP_VERSION, HAWK_API_VERSION, BASE_DIR
        from pathlib import Path
        bar = self

        class _HawkAPI:
            def hawk_version(self): return APP_VERSION
            def hawk_api_version(self): return HAWK_API_VERSION

            def session_dir(self):
                d = Path(BASE_DIR) / "sessions" / "argus_scratch"
                d.mkdir(parents=True, exist_ok=True)
                return d

            def log(self, level, message):
                # v1: print to stdout with HAWK marker.  Wired to the
                # main HAWK log panel in a follow-up pass when ARGUS
                # actually has logs to surface (M2 onwards).
                print(f"[HAWK<-ARGUS][{level}] {message}")

            def get_target(self):
                try:
                    val = bar._ip_entry.get()
                    return val if val else None
                except Exception:
                    return None

            def show_modal(self, title, body, kind="info"):
                try:
                    from tkinter import messagebox
                    if kind == "error":
                        messagebox.showerror(title, body)
                    elif kind == "warning":
                        messagebox.showwarning(title, body)
                    else:
                        messagebox.showinfo(title, body)
                except Exception as e:
                    print(f"[HAWK<-ARGUS] show_modal failed: {e}")

        return _HawkAPI()

    def _show_coming_soon_dialog(self, *, title: str,
                                   tagline: str,
                                   description: str) -> None:
        """Tiny modal that pops up when a teaser button is clicked.
        Sells the upcoming v2.0.0 feature with a one-liner tagline
        and a short description."""
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                   _btn_row, _btn, _safe_destroy)
        # Bigger dialog + bigger fonts — the old defaults were built
        # for the whole-app font scale but hit as undersized in this
        # single-purpose teaser modal where the user briefly stops
        # to read a pitch.  720×520 gives breathing room, and the
        # text-size bumps (15pt tagline, 13pt body) make every line
        # readable without leaning in.
        win = _make_win(
            self, f"Coming in v2.0.0 — {title}", 720, 520)
        _title(win, f"🔒  {title}")
        _sub(win,
             "Not available yet — shipping in HAWK v2.0.0.",
             COLORS["text_yellow"])
        ctk.CTkLabel(
            win,
            text=f"  {tagline}",
            font=ctk.CTkFont(
                family="Courier New", size=15, weight="bold"),
            text_color=COLORS["text_cyan"],
            anchor="w", justify="left", wraplength=660,
        ).pack(fill="x", padx=20, pady=(8, 12))
        ctk.CTkLabel(
            win,
            text=description,
            font=ctk.CTkFont(family="Courier New", size=13),
            text_color=COLORS["text_bright"],
            anchor="w", justify="left", wraplength=660,
        ).pack(fill="x", padx=20, pady=(0, 12))
        _note_box(
            win,
            "★ Stay tuned — follow HAWK updates to know when "
            "v2.0.0 drops.",
            COLORS["text_green"])
        row = _btn_row(win)
        _btn(row, "OK", lambda: _safe_destroy(win),
             primary=True, w=160)

    # ═══════════════════════════════════════════════════════════════
    #  Stealth Mode toggle — read / write / persist
    # ═══════════════════════════════════════════════════════════════

    # ── Proxychains helpers ────────────────────────────────────────────────

    def _read_proxychains_state(self) -> tuple:
        """Return (is_active: bool, label: str) from /etc/proxychains4.conf.

        is_active=True only when a non-Tor proxy is configured.
        label is a short human string for the button text."""
        for conf_path in ("/etc/proxychains4.conf", "/etc/proxychains.conf"):
            try:
                with open(conf_path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    in_list = False
                    for line in fh:
                        s = line.strip()
                        if s == "[ProxyList]":
                            in_list = True
                            continue
                        if in_list and s and not s.startswith("#"):
                            parts = s.split()
                            if (len(parts) >= 3
                                    and parts[0] in
                                    ("socks4", "socks5", "http")):
                                ip, port = parts[1], parts[2]
                                if port == "9050":
                                    # Still pointing at Tor default
                                    return (False, "PROXY: TOR (default)")
                                return (True, f"PROXY  {ip}:{port}")
                return (False, "PROXY: OFF")
            except FileNotFoundError:
                continue
            except Exception:
                return (False, "PROXY: OFF")
        return (False, "PROXY: OFF")

    def _refresh_proxy_button(self) -> None:
        """Update the PROXY button label + colour to reflect /etc/proxychains4.conf."""
        try:
            is_active, label = self._read_proxychains_state()
            color = (COLORS["text_cyan"] if is_active
                     else COLORS["text_dim"])
            border = (COLORS["text_cyan"] if is_active
                      else COLORS["border_dim"])
            self._proxy_btn.configure(
                text=f"🔗  {label}",
                text_color=color,
                border_color=border,
            )
        except Exception:
            pass

    def _open_proxychains_dialog(self) -> None:
        """Open the proxychains config dialog and refresh the button after."""
        try:
            from gui.dialogs import show_proxychains_config_dialog
            show_proxychains_config_dialog(
                self, app=self.app,
                on_save=self._refresh_proxy_button)
        except Exception as e:
            try:
                self.app.terminal.write(
                    f"  [!] Could not open proxychains config dialog: {e}",
                    "error")
            except Exception:
                pass

    # ─── VHOST / /etc/hosts management ─────────────────────────────────────

    def _open_vhost_dialog(self):
        from gui.dialogs import (_make_win, _title, _sub,
                                  _btn_row, _btn, _safe_destroy)
        from utils.hosts_helper import list_hawk_entries, add_entries

        sess = None
        target = ""
        try:
            sess = self.app.session_manager.current
            target = sess.target_ip if sess else ""
        except Exception:
            pass
        if not target:
            try:
                self.app.terminal.write(
                    "  [!] No active session — start a session first.",
                    "warn")
            except Exception:
                pass
            return

        win = _make_win(self, "VHOST — /etc/hosts Manager", 560, 420)
        _title(win, "VHOST  —  /etc/hosts Manager")
        _sub(win, f"Target: {target}", COLORS["text_dim"])

        current_entries = list_hawk_entries()
        target_entries = [e for e in current_entries
                         if e["ip"] == target]

        if target_entries:
            ctk.CTkLabel(
                win, text="Current HAWK entries for this target:",
                font=ctk.CTkFont(family="Courier New", size=13, weight="bold"),
                text_color=COLORS["text_green"],
                anchor="w",
            ).pack(fill="x", padx=14, pady=(8, 2))
            for e in target_entries:
                ctk.CTkLabel(
                    win,
                    text=f"  {e['ip']}  →  {' '.join(e['hostnames'])}",
                    font=ctk.CTkFont(family="Courier New", size=12),
                    text_color=COLORS["text_bright"],
                    anchor="w",
                ).pack(fill="x", padx=14, pady=0)

        ctk.CTkLabel(
            win, text="Hostname to add:",
            font=ctk.CTkFont(family="Courier New", size=13, weight="bold"),
            text_color=COLORS["text_bright"],
            anchor="w",
        ).pack(fill="x", padx=14, pady=(12, 2))

        host_entry = ctk.CTkEntry(
            win, width=500, height=28,
            placeholder_text="e.g. target.htb  (space-separated for multiple)",
            font=ctk.CTkFont(family="Courier New", size=14),
            fg_color="#050505",
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"],
            border_width=1,
            corner_radius=3,
        )
        host_entry.pack(fill="x", padx=14, pady=(0, 6))

        status_lbl = ctk.CTkLabel(
            win, text="", font=ctk.CTkFont(family="Courier New", size=12),
            text_color=COLORS["text_yellow"], anchor="w")
        status_lbl.pack(fill="x", padx=14, pady=(0, 4))

        def _add():
            raw = host_entry.get().strip()
            if not raw:
                status_lbl.configure(text="⚠  Enter a hostname first")
                return
            hostnames = raw.split()
            ok, msg = add_entries([(target, hostnames)])
            if ok:
                status_lbl.configure(
                    text=f"✓  {msg}",
                    text_color=COLORS["text_green"])
                if sess:
                    for h in hostnames:
                        entry = {"ip": target, "hostname": h}
                        if entry not in getattr(sess, "hawk_hosts_entries", []):
                            sess.hawk_hosts_entries.append(entry)
                    sess._touch()
                self._refresh_vhost_button()
            else:
                status_lbl.configure(
                    text=f"✗  {msg}",
                    text_color=COLORS["text_red"])

        def _remove_all():
            from utils.hosts_helper import remove_hawk_entries_async
            status_lbl.configure(
                text="…  waiting for sudo/polkit",
                text_color=COLORS["text_yellow"])

            def _on_done(ok, msg):
                def _apply():
                    if ok:
                        status_lbl.configure(
                            text=f"✓  {msg}",
                            text_color=COLORS["text_green"])
                        if sess:
                            sess.hawk_hosts_entries = []
                            sess._touch()
                        self._refresh_vhost_button()
                    else:
                        status_lbl.configure(
                            text=f"✗  {msg}",
                            text_color=COLORS["text_red"])
                try:
                    self.after(0, _apply)
                except Exception:
                    _apply()

            remove_hawk_entries_async(_on_done)

        row = _btn_row(win)
        _btn(row, "ADD TO /etc/hosts", _add, primary=True, w=200)
        _btn(row, "REMOVE ALL HAWK", _remove_all, w=180)
        _btn(row, "CLOSE", lambda: _safe_destroy(win))

    def _refresh_vhost_button(self):
        try:
            from utils.hosts_helper import list_hawk_entries
            entries = list_hawk_entries()
            if entries:
                hosts = []
                for e in entries:
                    hosts.extend(e["hostnames"])
                short = ", ".join(hosts[:2])
                if len(hosts) > 2:
                    short += f" +{len(hosts)-2}"
                n = len(hosts)
                label = f"🌐 VHOST ({n})" if n > 1 else f"🌐 {hosts[0]}"
                self._vhost_btn.configure(
                    text=label,
                    border_color=COLORS["text_bright"],
                    text_color=COLORS["text_bright"])
            else:
                self._vhost_btn.configure(
                    text="🌐 VHOST",
                    border_color=COLORS["border_dim"],
                    text_color=COLORS["text_dim"])
        except Exception:
            pass

    def auto_detect_vhost(self, target_ip: str):
        """Called after port scan — probe HTTP ports for hostname redirects."""
        import threading
        threading.Thread(
            target=self._detect_vhost_worker,
            args=(target_ip,),
            daemon=True).start()

    def _detect_vhost_worker(self, target_ip: str):
        import subprocess
        import re

        sess = None
        try:
            sess = self.app.session_manager.current
        except Exception:
            pass
        if not sess:
            return

        fp = None
        try:
            if hasattr(self.app, "target_intel") and self.app.target_intel._fp:
                fp = self.app.target_intel._fp
        except Exception:
            pass
        if not fp:
            return

        http_ports = []
        for p, _pr, svc, bann in fp.open_ports:
            token = ((svc or "") + " " + (bann or "")).lower()
            if any(t in token for t in ("http", "apache", "nginx",
                                        "iis", "lighttpd", "tomcat")):
                if p not in (5985, 5986, 135, 593):
                    http_ports.append(p)

        if not http_ports:
            return

        detected_hosts = set()
        host_re = re.compile(
            r"(?:Location|location):\s*https?://([A-Za-z0-9._-]+\.(?:htb|thm|local|lan|box))",
            re.IGNORECASE)
        title_re = re.compile(
            r"https?://([A-Za-z0-9._-]+\.(?:htb|thm|local|lan|box))",
            re.IGNORECASE)

        for port in http_ports[:4]:
            for scheme in ("http", "https"):
                try:
                    r = subprocess.run(
                        ["curl", "-sIkL", "--max-time", "5",
                         "--max-redirs", "2",
                         f"{scheme}://{target_ip}:{port}/"],
                        capture_output=True, text=True, timeout=8,
                        errors="replace")
                    output = (r.stdout or "") + (r.stderr or "")
                    for m in host_re.finditer(output):
                        h = m.group(1).lower()
                        if h != target_ip:
                            detected_hosts.add(h)
                    for m in title_re.finditer(output):
                        h = m.group(1).lower()
                        if h != target_ip:
                            detected_hosts.add(h)
                except Exception:
                    pass

        if not detected_hosts:
            return

        from utils.hosts_helper import list_hawk_entries
        existing = set()
        for e in list_hawk_entries():
            if e["ip"] == target_ip:
                existing.update(e["hostnames"])

        new_hosts = sorted(detected_hosts - existing)
        if not new_hosts:
            return

        # WHY THIS IS NOT auto-add anymore
        # ─────────────────────────────────
        # The previous behaviour called `add_entries` directly here
        # (synchronous), which pops the pkexec/sudo password prompt
        # IMMEDIATELY — before the operator has any chance to consent
        # to the change.  /etc/hosts is a system file: HAWK shouldn't
        # touch it without an explicit confirmation, even when the
        # detection is high-confidence.
        #
        # The fix: marshal back to the UI thread (this worker runs in
        # a daemon thread spawned by auto_detect_vhost) and pop a
        # small confirmation dialog.  On ADD → async pkexec via
        # add_entries_async (so the UI doesn't block waiting for
        # the password).  On DISMISS → terminal note only.
        host_list = ", ".join(new_hosts)
        try:
            self.app.terminal.write(
                f"  [*] Auto-detected hostname(s) from HTTP probes: "
                f"{host_list} — asking before adding to /etc/hosts.",
                "info")
        except Exception:
            pass

        try:
            self.after(0,
                       lambda: self._prompt_add_detected_vhosts(
                           target_ip, new_hosts, sess))
        except Exception:
            pass

    def _prompt_add_detected_vhosts(self, target_ip: str,
                                     new_hosts: list,
                                     sess) -> None:
        """Confirmation modal for the auto-detected vhost-add flow.

        Runs on the UI thread (marshaled from _detect_vhost_worker
        via after()).  Two-button: ADD → async pkexec; DISMISS → no-op
        with a terminal note so the operator can spot the missed
        opportunity if they care.

        IMPORTANT: pkexec is fired ONLY on the ADD click.  This
        replaces the previous behaviour where the password prompt
        appeared as soon as nmap completed, before any consent UI.
        """
        from gui.dialogs import (_make_win, _title, _note_box,
                                  _btn_row, _btn, _safe_destroy)
        from utils.hosts_helper import add_entries_async

        win = _make_win(
            self,
            "Auto-detected hostnames — add to /etc/hosts?",
            580, 380)
        _title(win, "🌐  AUTO-DETECTED HOSTNAMES FROM HTTP PROBES")

        host_block = "\n".join(f"    • {h}" for h in new_hosts)
        _note_box(
            win,
            f"HAWK probed the open HTTP/HTTPS ports of "
            f"{target_ip} and the responses (Location: redirects, "
            f"page <title>, …) reference these hostnames:\n\n"
            f"{host_block}\n\n"
            f"Adding them to /etc/hosts (HAWK-tagged, removed on "
            f"session delete or HAWK shutdown) lets web tools "
            f"target the vhosts directly by name — usually "
            f"required for any apex/subdomain that returns a "
            f"placeholder when hit by IP.\n\n"
            f"A pkexec password prompt will appear ONLY if you "
            f"click ADD below.",
            COLORS.get("text_yellow", "#FFCC00"))

        status_lbl = ctk.CTkLabel(
            win, text="", font=ctk.CTkFont(family="Courier New",
                                            size=12),
            text_color=COLORS.get("text_dim", "#808080"))
        status_lbl.pack(fill="x", padx=24, pady=(0, 4))

        def _on_add():
            status_lbl.configure(
                text="…  waiting for sudo/polkit",
                text_color=COLORS.get("text_yellow", "#FFCC00"))

            def _done(ok, msg):
                def _post():
                    if ok:
                        try:
                            self.app.terminal.write(
                                f"  [+] /etc/hosts updated: "
                                f"{', '.join(new_hosts)} → {target_ip}",
                                "success")
                            if sess:
                                for h in new_hosts:
                                    entry = {"ip": target_ip,
                                             "hostname": h}
                                    if entry not in getattr(
                                            sess, "hawk_hosts_entries",
                                            []):
                                        sess.hawk_hosts_entries.append(
                                            entry)
                                # Pin target_domain on first add — the
                                # vhost-aware helpers in target_intel
                                # (ADD HOSTS, ATTACK NEW VHOSTS,
                                # _extract_discovered_hostnames) all
                                # need a target_domain to validate
                                # which FQDNs belong to the target.
                                # Without this, the user adds
                                # silentium.htb to /etc/hosts and the
                                # ffuf-vhost finding still has no
                                # button.  Pick the SHORTEST hostname
                                # (= apex when one is present).  Don't
                                # overwrite an existing pin — the user
                                # may have set it manually.
                                if not (getattr(sess, "target_domain",
                                                "") or "").strip():
                                    apex = sorted(new_hosts,
                                                   key=len)[0]
                                    sess.target_domain = apex
                                    try:
                                        self.set_target_domain(apex)
                                    except Exception:
                                        pass
                                    self.app.terminal.write(
                                        f"  [+] Target domain auto-"
                                        f"set to {apex}  (vhost-aware "
                                        f"buttons now active on "
                                        f"Target Intel)", "success")
                                sess._touch()
                        except Exception:
                            pass
                        try:
                            self._refresh_vhost_button()
                        except Exception:
                            pass
                        _safe_destroy(win)
                    else:
                        status_lbl.configure(
                            text=f"✗  {msg}",
                            text_color=COLORS.get("text_red",
                                                  "#FF5555"))
                        try:
                            self.app.terminal.write(
                                f"  [!] /etc/hosts update failed: "
                                f"{msg}", "warn")
                        except Exception:
                            pass
                try:
                    self.app.after(0, _post)
                except Exception:
                    _post()

            add_entries_async([(target_ip, new_hosts)], _done)

        def _on_dismiss():
            try:
                self.app.terminal.write(
                    f"  [*] Auto-detected hostnames dismissed.  "
                    f"Use the VHOST manager on the target bar "
                    f"to add them later if you change your mind.",
                    "dim")
            except Exception:
                pass
            _safe_destroy(win)

        r = _btn_row(win)
        _btn(r, "ADD TO /etc/hosts", _on_add, primary=True, w=180)
        _btn(r, "DISMISS", _on_dismiss, w=120)

    def is_stealth_mode(self) -> bool:
        """Kept for backward compatibility — stealth mode is now toggled
        inside each PEAS workflow dialog, not here.  Always returns False."""
        return False

    def _refresh_domain_button_state(self, saved: bool):
        """Toggle the primary domain button between SAVE and CHANGE modes,
        and enable/disable DELETE based on whether a domain is persisted."""
        try:
            if saved:
                self._save_domain_btn.configure(
                    text="✎  CHANGE DOMAIN",
                    border_color=COLORS["text_yellow"],
                    text_color=COLORS["text_yellow"])
                self._delete_domain_btn.configure(state="normal")
            else:
                self._save_domain_btn.configure(
                    text="💾  SAVE DOMAIN",
                    border_color=COLORS["border_dim"],
                    text_color=COLORS["text_dim"])
                self._delete_domain_btn.configure(state="disabled")
        except Exception as e:
            print(f"[HAWK] refresh domain button failed: {e}")

    def get_target_domain(self) -> str:
        return self._domain_entry.get().strip().rstrip(".")

    def set_target_domain(self, domain: str):
        """Programmatic setter — used when a tool captures a domain dynamically
        or when a saved session is loaded."""
        self._domain_entry.delete(0, "end")
        if domain:
            self._domain_entry.insert(0, domain)
            self._domain_entry.configure(border_color=COLORS["border_green"])
            self._domain_status_lbl.configure(
                text=f"  ✓  Saved — {domain}",
                text_color=COLORS["text_green"])
            self._refresh_domain_button_state(saved=True)
        else:
            self._domain_entry.configure(border_color=COLORS["border_dim"])
            self._domain_status_lbl.configure(text="", text_color=COLORS["text_muted"])
            self._refresh_domain_button_state(saved=False)

    def _save_session(self):
        if not self.app.session_manager.current:
            self.app.terminal.write("[!] No active session to save.", "warn")
            return

        # Check for running background jobs — their output is streaming
        # and hasn't been captured into session.executed_tools yet, so
        # the user should be warned that those results won't be in the
        # snapshot.
        bg_jobs = []
        try:
            bg_jobs = list(self.app.bg_jobs_bar._jobs.values())
        except Exception:
            bg_jobs = []

        if bg_jobs:
            self._show_bg_save_warning(bg_jobs)
            return
        self._do_save_current()

    def _show_bg_save_warning(self, bg_jobs: list):
        """Modal warning that bg jobs are still running and their output
        will NOT be included in the snapshot. User can SAVE ANYWAY or CANCEL."""
        from gui.dialogs import _make_win, _title, _note_box, _btn_row, _btn, _safe_destroy

        win = _make_win(self, "Background jobs running", 560, 360)
        _title(win, "⚠  BACKGROUND JOBS STILL RUNNING")

        jobs_txt = "\n".join(
            f"  • {j.label}  (started {j.start_time.strftime('%H:%M:%S')})"
            for j in bg_jobs)
        _note_box(win,
                  f"HAWK has {len(bg_jobs)} background job(s) in progress:\n\n"
                  f"{jobs_txt}\n\n"
                  "Their final output has NOT been captured yet. The\n"
                  "snapshot you are about to save WILL contain everything\n"
                  "that is already in the terminal, plus every tool that\n"
                  "has already finished — but the in-progress jobs above\n"
                  "will NOT be included.\n\n"
                  "When they finish you can SAVE again to capture their\n"
                  "output in a new snapshot.",
                  COLORS["text_yellow"])

        def _save_anyway():
            _safe_destroy(win)
            self._do_save_current()

        row = _btn_row(win)
        _btn(row, "SAVE ANYWAY", _save_anyway, warn=True, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _do_save_current(self):
        """Perform the actual save. Called either directly (no bg jobs)
        or from the bg-job warning dialog after the user confirms."""
        sess = self.app.session_manager.current

        # Capture a snapshot of the Target Intel panel so it can be
        # restored on reload. The panel holds live Python objects
        # (OSFingerprint, ExploitEntry dataclass) that the JSON encoder
        # can't serialise directly — call their explicit to_dict() helpers
        # so the save doesn't fail with "Object of type X is not JSON
        # serializable".
        try:
            intel = self.app.target_intel
            fp = getattr(intel, "_fp", None)
            exploits = getattr(intel, "_exploits", []) or []
            sess.set_target_intel({
                "fingerprint":    (fp.to_dict() if fp is not None and
                                    hasattr(fp, "to_dict") else None),
                "exploits":       [(e.to_dict() if hasattr(e, "to_dict")
                                    else e)
                                   for e in exploits],
                "auto_findings":  _strip_finding_widget_refs(
                                      getattr(intel, "_auto_findings",
                                              []) or []),
            })
        except Exception as e:
            print(f"[HAWK] target_intel snapshot failed: {e}")

        try:
            path = sess.save(new_file=True)
            import os as _os
            fname = _os.path.basename(path)
        except Exception as e:
            self.app.terminal.write(f"[!] Save failed: {e}", "error")
            return

        self.app.terminal.write(
            f"[+] Session saved → {fname}", "success")
        self.app.terminal.write(
            f"    Tools recorded   : {len(sess.executed_tools)}", "dim")
        self.app.terminal.write(
            f"    Terminal lines   : {len(sess.terminal_lines)}", "dim")
        self.app.terminal.write(
            f"    Credentials      : {len(sess.credentials)}", "dim")

    # ── Autosave ───────────────────────────────────────────────────────────

    def _toggle_autosave(self):
        """Flip autosave state. First activation pops a small explainer."""
        if not self._autosave_on:
            # Going OFF → ON. Show the explainer on the very first enable
            # of this HAWK run; subsequent toggles skip it to avoid nagging.
            if not getattr(self, "_autosave_explained", False):
                self._show_autosave_info(on_confirm=self._autosave_enable)
                self._autosave_explained = True
            else:
                self._autosave_enable()
        else:
            self._autosave_disable()

    def _show_autosave_info(self, on_confirm):
        """Small modal explaining what autosave does before first enable."""
        from gui.dialogs import _make_win, _title, _note_box, _btn_row, _btn, _safe_destroy

        win = _make_win(self, "Autosave", 520, 320)
        _title(win, "⟳  AUTOSAVE")
        _note_box(win,
                  "Autosave silently writes the current session to disk\n"
                  f"every {self._autosave_interval_ms // 60000} minutes,\n"
                  "overwriting the SAME file each time (like Word does).\n\n"
                  "Useful during long pentests: if HAWK crashes, the box\n"
                  "reboots, or you close the window, the latest snapshot\n"
                  "is already on disk.\n\n"
                  "• Green button  =  autosave ON\n"
                  "• Gray button   =  autosave OFF\n\n"
                  "Click the button again to turn it off. Manual SAVE\n"
                  "still works normally and creates a new snapshot.",
                  COLORS["text_green"])

        def _ok():
            _safe_destroy(win)
            on_confirm()

        row = _btn_row(win)
        _btn(row, "ENABLE AUTOSAVE", _ok, primary=True, w=180)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _autosave_enable(self):
        """Turn autosave on: repaint button green and start the timer."""
        self._autosave_on = True
        try:
            self._autosave_btn.configure(
                fg_color     = "#001500",
                border_color = COLORS["border_green"],
                text_color   = COLORS["text_green"],
            )
        except Exception as e:
            print(f"[HAWK] autosave btn repaint failed: {e}")
        # Schedule first tick.
        self._autosave_after_id = self.after(
            self._autosave_interval_ms, self._autosave_tick)
        mins = self._autosave_interval_ms // 60000
        self.app.terminal.write(
            f"[AUTO] Autosave ON — overwrites session every {mins} min.",
            "success")

    def _autosave_disable(self):
        """Turn autosave off: repaint button gray and cancel timer."""
        self._autosave_on = False
        if self._autosave_after_id is not None:
            try:
                self.after_cancel(self._autosave_after_id)
            except Exception:
                pass
            self._autosave_after_id = None
        try:
            self._autosave_btn.configure(
                fg_color     = COLORS["bg_card"],
                border_color = COLORS["border_dim"],
                text_color   = COLORS["text_dim"],
            )
        except Exception as e:
            print(f"[HAWK] autosave btn repaint failed: {e}")
        self.app.terminal.write("[AUTO] Autosave OFF.", "dim")

    def _autosave_tick(self):
        """Timer callback — overwrite the current session file."""
        # If autosave got disabled between schedule and fire, bail.
        if not self._autosave_on:
            return
        sess = self.app.session_manager.current
        if sess is None:
            # No active session → nothing to save. Reschedule so the
            # user can start a session without having to re-toggle.
            self._autosave_after_id = self.after(
                self._autosave_interval_ms, self._autosave_tick)
            return

        # Snapshot the Target Intel panel the same way _do_save_current
        # does — otherwise reload would lose fingerprint/exploits/findings.
        try:
            intel = self.app.target_intel
            fp = getattr(intel, "_fp", None)
            exploits = getattr(intel, "_exploits", []) or []
            sess.set_target_intel({
                "fingerprint":    (fp.to_dict() if fp is not None and
                                    hasattr(fp, "to_dict") else None),
                "exploits":       [(e.to_dict() if hasattr(e, "to_dict")
                                    else e)
                                   for e in exploits],
                "auto_findings":  _strip_finding_widget_refs(
                                      getattr(intel, "_auto_findings",
                                              []) or []),
            })
        except Exception as e:
            print(f"[HAWK] autosave intel snapshot failed: {e}")

        try:
            # new_file=False → overwrite the same file. If this session
            # has never been saved before, Session.save() will create the
            # file on first call and reuse it thereafter.
            path = sess.save(new_file=False)
            import os as _os
            fname = _os.path.basename(path)
            self.app.terminal.write(
                f"[AUTO] Session saved → {fname}", "dim")
        except Exception as e:
            self.app.terminal.write(
                f"[AUTO] Autosave failed: {e}", "warn")

        # Reschedule next tick.
        self._autosave_after_id = self.after(
            self._autosave_interval_ms, self._autosave_tick)

    def _load_session(self):
        """Open a simple session picker dialog."""
        sessions = self.app.session_manager.load_all()
        if not sessions:
            self.app.terminal.write("[!] No saved sessions found.", "warn")
            return
        _SessionPickerDialog(self, self.app, sessions)

    def _update_session_label(self, session):
        if session is None:
            self._session_label.configure(
                text="  No active session",
                text_color=COLORS["text_muted"],
            )
            return
        s = session.summary()
        self._session_label.configure(
            text=(
                f"  ● SESSION: {s['target_ip']}  |  {s['platform'] or 'N/A'}  |  "
                f"ID: {s['session_id']}  |  Started: {s['created_at']}"
            ),
            text_color=COLORS["text_green"],
        )


    def _delete_session(self):
        """Delete current session with confirmation dialog."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn
        if not self.app.session_manager.current:
            self.app.terminal.write("[!] No active session to delete.", "error")
            return
        target = self.app.session_manager.current.target_ip
        win = _make_win(self, "Delete Session", 440, 220)
        import customtkinter as ctk
        ctk.CTkLabel(win, text="Delete Session?",
                     font=ctk.CTkFont(family="Courier New", size=15, weight="bold"),
                     text_color=COLORS["text_red"]).pack(pady=(20,8))
        ctk.CTkLabel(win,
                     text=f"Session: {target}\nThis will reset ALL data. Cannot be undone.",
                     font=ctk.CTkFont(family="Courier New", size=13),
                     text_color=COLORS["text_muted"], justify="center").pack(pady=4)

        def _confirm():
            _safe_destroy(win)
            # Stop autosave FIRST — otherwise the timer fires mid-delete
            # and writes a fresh snapshot right after we wiped the old
            # ones (resurrection bug).
            try:
                if getattr(self, "_autosave_on", False):
                    self._autosave_disable()
            except Exception:
                pass
            # Clean HAWK-tagged /etc/hosts entries left behind by the
            # AD DNS helper during this session.  No-op when the user
            # never used the helper, so we don't spam pkexec prompts
            # on every DELETE SESSION.
            try:
                from utils.hosts_helper import (list_hawk_entries,
                                                 remove_hawk_entries)
                if list_hawk_entries():
                    ok, msg = remove_hawk_entries()
                    if ok:
                        self.app.terminal.write(
                            f"  [*] /etc/hosts: {msg}", "dim")
                    else:
                        self.app.terminal.write(
                            f"  [!] /etc/hosts cleanup failed: {msg}",
                            "warn")
            except Exception as e:
                print(f"[HAWK] hosts cleanup failed: {e}")
            # Hard-delete the JSON snapshots on disk BEFORE detaching
            # the in-memory object — otherwise we lose the file_path
            # reference and can't find the files.
            deleted_paths = []
            try:
                deleted_paths = self.app.session_manager.delete()
            except Exception as e:
                print(f"[HAWK] session delete failed: {e}")
            # Now reset the UI panels.
            self._reset_all_panels()
            self.app.session_manager.current = None
            self._update_session_label(None)
            # Clear the domain field as well
            try:
                self._domain_entry.delete(0, "end")
                self._domain_entry.configure(border_color=COLORS["border_dim"])
                self._domain_status_lbl.configure(text="", text_color=COLORS["text_muted"])
                self._refresh_domain_button_state(saved=False)
            except Exception:
                pass
            # Clear the IP field too so the user isn't tricked into
            # thinking the (now-empty) session still knows the target.
            try:
                self._ip_entry.delete(0, "end")
            except Exception:
                pass
            self.app.title(WINDOW["title"])
            n = len(deleted_paths)
            if n == 0:
                self.app.terminal.write(
                    "  [*] Session cleared (no files on disk to remove).",
                    "dim")
            elif n == 1:
                self.app.terminal.write(
                    f"  [*] Session deleted — removed {os.path.basename(deleted_paths[0])}",
                    "success")
            else:
                self.app.terminal.write(
                    f"  [*] Session deleted — removed {n} snapshot files.",
                    "success")
                for p in deleted_paths:
                    self.app.terminal.write(
                        f"      • {os.path.basename(p)}", "dim")

        row = _btn_row(win)
        _btn(row, "DELETE", _confirm, danger=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win))

    def _reset_all_panels(self):
        """Reset all panels on new session."""
        try:
            self.app.terminal.clear()
        except Exception as e:
            print(f"[HAWK] reset terminal failed: {e}")
        try:
            self.app.target_intel._fp = None
            self.app.target_intel._exploits = []
            self.app.target_intel._auto_findings = []
            self.app.target_intel._nonstandard_checked = False
            # Forget ports the user dismissed via the NonStandardPort
            # IGNORE button on the previous session — the new session
            # should be free to re-prompt if it hits the same ports.
            self.app.target_intel._dismissed_nonstandard_ports = set()
            # Clear cached section-rows; a fresh _render_all will
            # rebuild them from scratch.
            if hasattr(self.app.target_intel, "_section_rows"):
                self.app.target_intel._section_rows = {}
            self.app.target_intel._render_all()
        except Exception as e:
            print(f"[HAWK] reset target intel failed: {e}")
        # Reset the per-tool status dots on every kill-chain card — the
        # previous session's green "done" indicators must NOT leak into
        # the new session (otherwise the user thinks a tool already ran
        # against the new target, which may be a totally different box).
        try:
            kc = getattr(self.app, "kill_chain_panel", None)
            cards = list(getattr(kc, "_cards", {}).values()) if kc else []
            for card in cards:
                for tid in list(getattr(card, "_tool_widgets", {}).keys()):
                    try:
                        # "ready" → ○ grey dot (see TOOL_STATUS_ICONS
                        # in card_widget.py).  That's the "never run
                        # this session" state we want to restore.
                        card._set_tool_status(tid, "ready")
                    except Exception:
                        pass
        except Exception as e:
            print(f"[HAWK] reset tool status dots failed: {e}")
        try:
            for w in self.app.cred_store._scroll.winfo_children():
                w.destroy()
        except Exception as e:
            print(f"[HAWK] reset cred store failed: {e}")
        try:
            self.app._findings_box.configure(state="normal")
            self.app._findings_box.delete("1.0", "end")
            self.app._findings_box.configure(state="disabled")
        except Exception as e:
            print(f"[HAWK] reset findings box failed: {e}")

    @staticmethod
    def _validate_ip(value: str) -> bool:
        if not value:
            return False
        # Strict IP validation (each octet 0-255)
        ip_match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", value)
        if ip_match:
            return all(0 <= int(o) <= 255 for o in ip_match.groups())
        # Hostname validation
        host_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
        return bool(re.match(host_pattern, value))

    def get_target(self) -> str:
        return self._ip_entry.get().strip()


class _SessionPickerDialog(ctk.CTkToplevel):
    """Small dialog to pick a saved session."""

    def __init__(self, parent, app, sessions):
        super().__init__(parent)
        # Hide until layout settles (see comment in gui/dialogs._make_win)
        self.withdraw()
        self.app      = app
        self.sessions = sessions
        self.title("Load Session")
        # Bumped from 500x400 — the old default cut the LOAD button
        # off on the right of each session row (long target_domain +
        # metadata pushed it outside the viewport).  Bigger baseline
        # means "just works" on first open, no resize required.
        self.geometry("820x580")
        self.configure(fg_color=COLORS["bg_primary"])
        self.resizable(True, True)
        self._build()
        self.after(80, self._autosize)
        self.after(250, self._autosize)

        def _reveal():
            try:
                if not self.winfo_exists():
                    return
                self.deiconify(); self.lift(); self.focus_force()
            except Exception:
                pass
        self.after(280, _reveal)

    def _autosize(self):
        try:
            self.update_idletasks()
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            # Minimums bumped to 820x580 — same rationale as the
            # initial geometry: narrow windows truncate the right-side
            # LOAD / 🗑 buttons on each session row.  Padding bumped
            # from 40 to 60 so reqwidth/reqheight estimates don't
            # undershoot on Kali's GTK theme which reports slightly
            # smaller than the actual rendered size.
            w = min(max(self.winfo_reqwidth() + 60, 820),
                    int(sw * 0.92))
            h = min(max(self.winfo_reqheight() + 60, 580),
                    int(sh * 0.92))
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _build(self):
        ctk.CTkLabel(
            self,
            text="SAVED SESSIONS",
            font=ctk.CTkFont(family="Courier New", size=13, weight="bold"),
            text_color=COLORS["text_green"],
        ).pack(pady=(14, 4))
        ctk.CTkLabel(
            self,
            text=f"  {len(self.sessions)} snapshot(s) — newest first",
            font=ctk.CTkFont(family="Courier New", size=9),
            text_color=COLORS["text_muted"],
        ).pack(pady=(0, 6))

        scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=COLORS["bg_secondary"],
            border_color=COLORS["border_dim"],
            border_width=1,
        )
        scroll.pack(fill="both", expand=True, padx=16, pady=8)

        for session in self.sessions:
            s = session.summary()
            row = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=4)
            row.pack(fill="x", padx=4, pady=3)

            # Left column: name + metadata
            left = ctk.CTkFrame(row, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True, padx=8, pady=6)

            header = (f"  {s['target_ip']}"
                      + (f"  ({s['target_domain']})" if s.get('target_domain') else "")
                      + f"   [{s['platform'] or 'N/A'}]")
            ctk.CTkLabel(
                left, text=header,
                font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
                text_color=COLORS["text_green"], anchor="w",
            ).pack(fill="x")

            meta_bits = []
            if s.get("last_saved"):
                meta_bits.append(f"saved {s['last_saved']}")
            if s.get("tools_run"):
                meta_bits.append(f"{s['tools_run']} tools")
            if s.get("terminal_lines"):
                meta_bits.append(f"{s['terminal_lines']} terminal lines")
            if s.get("creds_found"):
                meta_bits.append(f"{s['creds_found']} creds")
            if s.get("total_findings"):
                meta_bits.append(f"{s['total_findings']} findings")
            ctk.CTkLabel(
                left, text="  " + "  ·  ".join(meta_bits) if meta_bits
                     else "  (empty — nothing recorded yet)",
                font=ctk.CTkFont(family="Courier New", size=9),
                text_color=COLORS["text_muted"], anchor="w",
            ).pack(fill="x", pady=(2, 0))

            if s.get("file_name"):
                ctk.CTkLabel(
                    left, text=f"  {s['file_name']}",
                    font=ctk.CTkFont(family="Courier New", size=8),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(fill="x")

            # Right column: LOAD + DELETE buttons
            btns = ctk.CTkFrame(row, fg_color="transparent")
            btns.pack(side="right", padx=8, pady=6)
            ctk.CTkButton(
                btns, text="LOAD", width=70, height=26,
                font=ctk.CTkFont(family="Courier New", size=9, weight="bold"),
                fg_color=COLORS["bg_primary"],
                hover_color="#003000",
                border_color=COLORS["border_green"],
                border_width=1,
                text_color=COLORS["text_green"],
                corner_radius=3,
                command=lambda s=session: self._load(s),
            ).pack(side="left", padx=2)
            ctk.CTkButton(
                btns, text="🗑", width=30, height=26,
                font=ctk.CTkFont(family="Courier New", size=10),
                fg_color=COLORS["bg_primary"],
                hover_color="#2A0505",
                border_color=COLORS["text_red"],
                border_width=1,
                text_color=COLORS["text_red"],
                corner_radius=3,
                command=lambda s=session, r=row: self._delete_snapshot(s, r),
            ).pack(side="left", padx=2)

        ctk.CTkButton(
            self,
            text="CLOSE",
            width=80,
            fg_color="transparent",
            border_color=COLORS["border_dim"],
            border_width=1,
            text_color=COLORS["text_dim"],
            font=ctk.CTkFont(family="Courier New", size=10),
            command=self.destroy,
        ).pack(pady=8)

    def _delete_snapshot(self, session, row_widget):
        """Delete a single snapshot file from disk."""
        import os as _os
        path = session.file_path
        if path and _os.path.exists(path):
            try:
                _os.remove(path)
                self.app.terminal.write(
                    f"  [*] Deleted snapshot: {_os.path.basename(path)}",
                    "dim")
            except Exception as e:
                self.app.terminal.write(
                    f"  [!] Delete failed: {e}", "error")
                return
        try:
            row_widget.destroy()
        except Exception:
            pass

    def _load(self, session):
        import os as _os
        # Pause AUTOSAVE for the duration of the restore so a
        # half-restored state can't be written over the source file
        # (user-reported hypothesis: "new session + autosave + load =
        # saved data disappears").  We disable the timer before any
        # UI repopulation and re-enable it at the end ONLY if it was
        # on when we started.
        tb = self.app.target_bar
        autosave_was_on = getattr(tb, "_autosave_on", False)
        if autosave_was_on:
            try:
                tb._autosave_disable()
                self.app.terminal.write(
                    "  [*] AUTOSAVE paused for LOAD — will re-enable "
                    "after restore completes.", "dim")
            except Exception as e:
                print(f"[HAWK] load: autosave pause failed: {e}")

        self.app.session_manager.set_current(session)

        # Target + domain
        self.app.target_bar._ip_entry.delete(0, "end")
        self.app.target_bar._ip_entry.insert(0, session.target_ip)
        self.app.target_bar.set_target_domain(
            getattr(session, "target_domain", "") or "")

        # Platform dropdown — suppress the trace so setting the value
        # programmatically doesn't mark the session dirty / re-fire
        # the "Platform changed to X" terminal line.
        try:
            tb = self.app.target_bar
            plat = (getattr(session, "platform", "") or "HTB").strip()
            if plat not in ("HTB", "THM", "Custom"):
                plat = "Custom"
            tb._platform_suppress_trace = True
            tb._platform_var.set(plat)
            tb._platform_suppress_trace = False
        except Exception as e:
            print(f"[HAWK] platform restore failed: {e}")

        # Restore terminal history BEFORE writing any new lines — so the
        # new "session loaded" banner appears at the end of the replay.
        try:
            self.app.terminal.restore_lines(session.terminal_lines)
        except Exception as e:
            print(f"[HAWK] terminal restore failed: {e}")

        # Restore tool status icons across all kill-chain cards
        try:
            status_by_tool = session.last_status_per_tool()
            kc = getattr(self.app, "kill_chain_panel", None)
            cards = list(getattr(kc, "_cards", {}).values()) if kc else []
            for card in cards:
                for tid in list(getattr(card, "_tool_widgets", {}).keys()):
                    if tid in status_by_tool:
                        card._set_tool_status(tid, status_by_tool[tid])
        except Exception as e:
            print(f"[HAWK] tool-status restore failed: {e}")

        # Restore Target Intel snapshot.
        # The snapshot stores fingerprint/exploits as plain dicts (JSON
        # round-trip); rehydrate them back into OSFingerprint / ExploitEntry
        # so the rest of the widget (which expects live objects with
        # .platform / .rank_color() / …) keeps working. Still tolerate
        # already-live objects in case we ever load an unsaved in-memory
        # snapshot.
        try:
            from modules.exploit_suggester import OSFingerprint, ExploitEntry
            intel_state = session.target_intel or {}
            if intel_state:
                fp_raw = intel_state.get("fingerprint")
                if isinstance(fp_raw, dict):
                    fp_obj = OSFingerprint.from_dict(fp_raw)
                else:
                    fp_obj = fp_raw   # already an OSFingerprint (or None)
                self.app.target_intel._fp = fp_obj

                exps_raw = intel_state.get("exploits", []) or []
                rebuilt = []
                for e in exps_raw:
                    if isinstance(e, dict):
                        rebuilt.append(ExploitEntry.from_dict(e))
                    else:
                        rebuilt.append(e)
                self.app.target_intel._exploits = rebuilt

                self.app.target_intel._auto_findings = (
                    list(intel_state.get("auto_findings", []) or []))
                self.app.target_intel._render_all()
        except Exception as e:
            print(f"[HAWK] target_intel restore failed: {e}")

        # Status bar + window title
        self.app.status_bar.set_session(session.target_ip, session.platform)
        self.app.target_bar._update_session_label(session)
        self.app.title(f"HAWK — {session.target_ip} [{session.platform}]")
        # Restore the STEALTH MODE checkbox to match the session's
        # Banner in terminal (appended AFTER the replay)
        s = session.summary()
        self.app.terminal.section(f"SESSION RESUMED — {session.target_ip}")
        self.app.terminal.write(
            f"[+] Loaded {_os.path.basename(session.file_path or '?')}",
            "success")
        if s.get("last_saved"):
            self.app.terminal.write(
                f"    Snapshot time  : {s['last_saved']}", "dim")

        # Comprehensive post-load audit — every category that might
        # have come out of the file is logged with its count so the
        # user can immediately tell whether the file HAS data (and the
        # widgets failed to render it) or whether the file is basically
        # empty (and the "no data" feeling is correct from the file's
        # contents).  User-reported confusion "ho caricato ma non ha
        # salvato nessun dato" is almost always file-was-empty.
        intel = getattr(session, "target_intel", {}) or {}
        fp_present   = bool(intel.get("fingerprint"))
        n_exploits   = len(intel.get("exploits") or [])
        n_findings   = len(intel.get("auto_findings") or [])
        self.app.terminal.write(
            f"    Tools recorded     : {s.get('tools_run', 0)}", "dim")
        self.app.terminal.write(
            f"    Terminal lines     : {s.get('terminal_lines', 0)}", "dim")
        self.app.terminal.write(
            f"    Credentials        : {s.get('creds_found', 0)}", "dim")
        self.app.terminal.write(
            f"    Target Intel — OS  : "
            f"{'✓ fingerprint saved' if fp_present else '✗ no fingerprint'}",
            "dim")
        self.app.terminal.write(
            f"    Target Intel — findings : {n_findings}", "dim")
        self.app.terminal.write(
            f"    Target Intel — exploits : {n_exploits}", "dim")
        self.app.terminal.write(
            f"    Discovered users   : "
            f"{len(getattr(session, 'discovered_users', []) or [])}", "dim")
        self.app.terminal.write(
            f"    Discovered shares  : "
            f"{len(getattr(session, 'discovered_shares', []) or [])}", "dim")
        total = (s.get('tools_run', 0) + s.get('terminal_lines', 0)
                 + s.get('creds_found', 0) + n_findings
                 + (1 if fp_present else 0))
        if total == 0:
            self.app.terminal.write(
                "[!] The snapshot contained NO recoverable state "
                "(the file was saved before any tool produced output).  "
                "Nothing to restore — start running tools to populate "
                "Target Intel / Credential Store.",
                "warn")
        else:
            self.app.terminal.write(
                "[*] Pick up where you left off — previous output is "
                "restored above.", "info")

        # Restore /etc/hosts entries from session
        try:
            saved_hosts = getattr(session, "hawk_hosts_entries", [])
            if saved_hosts:
                from utils.hosts_helper import list_hawk_entries, add_entries
                existing = set()
                for e in list_hawk_entries():
                    for h in e["hostnames"]:
                        existing.add((e["ip"], h))
                to_add = {}
                for entry in saved_hosts:
                    ip = entry.get("ip", "")
                    hostname = entry.get("hostname", "")
                    if ip and hostname and (ip, hostname) not in existing:
                        to_add.setdefault(ip, []).append(hostname)
                if to_add:
                    add_entries(list(to_add.items()))
                    self.app.terminal.write(
                        f"  [+] Restored {sum(len(v) for v in to_add.values())} "
                        f"/etc/hosts entry/entries from session", "success")
            self.app.target_bar._refresh_vhost_button()
        except Exception as e:
            print(f"[HAWK] vhost restore failed: {e}")

        # Re-enable autosave if it was on before the load — now that
        # the UI has the restored data, it's safe for the timer to
        # start writing the session file again.
        if autosave_was_on:
            try:
                tb._autosave_enable()
                self.app.terminal.write(
                    "  [*] AUTOSAVE resumed.", "dim")
            except Exception as e:
                print(f"[HAWK] load: autosave resume failed: {e}")

        self.destroy()
