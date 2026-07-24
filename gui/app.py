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
HAWK - Main Application Window
Bottom panel: Findings | Credential Store | Target Intel (blinking)
"""

import tkinter as tk
import customtkinter as ctk
from utils.config import COLORS, BANNER, BANNER_SUBTITLE, WINDOW, APP_VERSION, SZ
from utils.session import SessionManager


def _f(key="md", bold=False):
    return ctk.CTkFont(family="Courier New", size=SZ.get(key, 14),
                       weight="bold" if bold else "normal")


class HawkApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        # Hide the window the instant Tk creates it.  Without this, X11
        # makes the window briefly visible during __init__ — long enough
        # for the user to see HAWK flash on screen for ~3 s before the
        # splash / api-key dialog takes over.  main() will deiconify
        # later via app.show() when the splash is done.
        self.withdraw()
        self.title(WINDOW["title"])
        # Start maximized
        try:
            self.state("zoomed")
        except Exception:
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            self.geometry(f"{sw}x{sh}+0+0")
        self.minsize(WINDOW["min_width"], WINDOW["min_height"])
        self.configure(fg_color=COLORS["bg_primary"])

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.session_manager = SessionManager()

        # Shared state for the WEB ASSAULT pipeline (Oracle → Crawl →
        # Inject → JWT).  Any widget that needs read/write access uses
        # `self.app.assault_state` — there is exactly one per app.
        from utils.assault_state import AssaultState
        self.assault_state = AssaultState()

        self._build_header()
        self._build_main_area()
        self._build_bg_jobs_bar()
        self._build_status_bar()
        # Apply right-click context menus to all text widgets
        self.after(200, self._apply_context_menus)
        # Install global mouse-wheel scrolling (routes to the scrollable
        # container under the pointer — works across all panels, popups
        # and scrollable frames).
        try:
            from utils.mousewheel import install_global_mousewheel
            install_global_mousewheel(self)
        except Exception as e:
            print(f"[!] mouse-wheel install failed: {e}")

        # MSF module index — build CVE→module map in background so the
        # RUN WITH MSF button appears automatically for any CVE that has
        # a Metasploit module, without the user doing anything.
        # Non-blocking: daemon thread, never touches the UI.
        try:
            from utils import msf_index
            msf_index.start_background_build()
        except Exception as _msfex:
            print(f"[!] MSF index start failed: {_msfex}")

        # /etc/hosts cleanup wiring — the AD DNS Helper writes temporary
        # HAWK-tagged entries.  Their lifecycle is "until HAWK exits OR
        # the user clicks DELETE SESSION", whichever comes first.  We
        # hook both the graceful-close path (WM_DELETE_WINDOW) and the
        # startup path (to clean stale entries left by a previous crash
        # / kill -9 that never got to run the exit handler).
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._hosts_cleanup_done = False
        self.after(600, self._startup_hosts_cleanup_check)

        # SIGINT (Ctrl-C from launching shell) + SIGTERM (systemd stop
        # / kill default) — route them through the same cleanup path
        # as the X button so /etc/hosts is always restored, no matter
        # how the user ends the HAWK process.  SIGKILL (-9) can't be
        # trapped — that's what the startup stale-entry check covers.
        try:
            import signal
            def _sig_handler(signum, _frame):
                import sys as _s
                print(f"[HAWK] Received signal {signum} — "
                      f"running cleanup then exiting.", file=_s.stderr)
                try:
                    self.after(0, self._on_close)
                except Exception:
                    # Event loop already dead — skip dialog, just clean up.
                    self._finish_close()
            signal.signal(signal.SIGINT,  _sig_handler)
            signal.signal(signal.SIGTERM, _sig_handler)
        except (ValueError, OSError):
            # Non-main thread on some platforms — fall back silently,
            # WM_DELETE_WINDOW still catches the normal close path.
            pass

    # ─── Shutdown / /etc/hosts cleanup ───────────────────────────────────────
    def _on_close(self):
        """Graceful close handler — if HAWK-tagged /etc/hosts entries
        exist, show a dialog asking whether to remove them.  Then
        destroy the window regardless of the answer."""
        import sys as _sys
        try:
            from utils.hosts_helper import list_hawk_entries
            entries = list_hawk_entries()
            if entries and not self._hosts_cleanup_done:
                self._show_hosts_cleanup_dialog(entries)
                return
        except Exception as e:
            print(f"[HAWK] on_close outer error: {e}", file=_sys.stderr)
        self._finish_close()

    def _show_hosts_cleanup_dialog(self, entries):
        """Ask the user whether to remove HAWK /etc/hosts entries."""
        import customtkinter as ctk
        from utils.config import COLORS

        win = ctk.CTkToplevel(self)
        win.title("HAWK — /etc/hosts Cleanup")
        win.geometry("520x320")
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()
        win.protocol("WM_DELETE_WINDOW", lambda: None)

        ctk.CTkLabel(
            win,
            text="🌐  /etc/hosts — Clean up entries?",
            font=ctk.CTkFont(family="Courier New", size=16, weight="bold"),
            text_color=COLORS.get("text_green", "#00FF41"),
        ).pack(padx=16, pady=(16, 4))

        ctk.CTkLabel(
            win,
            text=(f"HAWK added {len(entries)} entry/entries to /etc/hosts "
                  f"during this session.\n"
                  f"Do you want to remove them before closing?"),
            font=ctk.CTkFont(family="Courier New", size=13),
            text_color=COLORS.get("text_bright", "#E0E0E0"),
            wraplength=480, justify="left",
        ).pack(padx=16, pady=(0, 8))

        entry_frame = ctk.CTkFrame(
            win, fg_color=COLORS.get("bg_card", "#0A0A0A"),
            corner_radius=4)
        entry_frame.pack(fill="x", padx=16, pady=(0, 12))
        for e in entries[:8]:
            ctk.CTkLabel(
                entry_frame,
                text=f"  {e['ip']}  →  {' '.join(e['hostnames'])}",
                font=ctk.CTkFont(family="Courier New", size=12),
                text_color=COLORS.get("text_dim", "#808080"),
                anchor="w",
            ).pack(fill="x", padx=8, pady=1)
        if len(entries) > 8:
            ctk.CTkLabel(
                entry_frame,
                text=f"  … and {len(entries) - 8} more",
                font=ctk.CTkFont(family="Courier New", size=12),
                text_color=COLORS.get("text_muted", "#555555"),
                anchor="w",
            ).pack(fill="x", padx=8, pady=1)

        btn_frame = ctk.CTkFrame(win, fg_color="transparent")
        btn_frame.pack(pady=(4, 12))

        def _yes():
            import sys as _sys
            from utils.hosts_helper import remove_hawk_entries_async

            # Disable buttons + show waiting state. The pkexec/sudo
            # prompt blocks for as long as it takes the user to type
            # the password — running it on the Tk thread froze the
            # whole app. Spawn it on a worker and only then destroy.
            for child in btn_frame.winfo_children():
                try:
                    child.configure(state="disabled")
                except Exception:
                    pass
            try:
                waiting_lbl = ctk.CTkLabel(
                    win,
                    text="Waiting for sudo/polkit authentication...",
                    font=ctk.CTkFont(family="Courier New", size=12),
                    text_color=COLORS.get("text_yellow", "#FFCC00"))
                waiting_lbl.pack(pady=(0, 8))
            except Exception:
                pass

            def _on_done(ok, msg):
                def _finish():
                    self._hosts_cleanup_done = True
                    print(f"[HAWK] /etc/hosts cleanup: "
                          f"{'OK' if ok else 'FAILED'} — {msg}",
                          file=_sys.stderr)
                    try:
                        win.destroy()
                    except Exception:
                        pass
                    self._finish_close()
                try:
                    self.after(0, _finish)
                except Exception:
                    _finish()

            remove_hawk_entries_async(_on_done)

        def _no():
            win.destroy()
            self._finish_close()

        ctk.CTkButton(
            btn_frame, text="YES — Remove entries",
            width=200, height=32,
            font=ctk.CTkFont(family="Courier New", size=13, weight="bold"),
            fg_color="#002200",
            hover_color="#003300",
            border_color=COLORS.get("text_green", "#00FF41"),
            border_width=1,
            text_color=COLORS.get("text_green", "#00FF41"),
            corner_radius=3,
            command=_yes,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_frame, text="NO — Keep them",
            width=200, height=32,
            font=ctk.CTkFont(family="Courier New", size=13),
            fg_color=COLORS.get("bg_card", "#0A0A0A"),
            hover_color="#1A1A1A",
            border_color=COLORS.get("border_dim", "#333333"),
            border_width=1,
            text_color=COLORS.get("text_dim", "#808080"),
            corner_radius=3,
            command=_no,
        ).pack(side="left", padx=8)

    def _finish_close(self):
        """Final shutdown — kill crack processes and destroy."""
        import sys as _sys
        try:
            cs = getattr(self, "cred_store", None)
            if cs is not None and hasattr(cs, "stop_all_active_cracks"):
                cs.stop_all_active_cracks()
        except Exception as e:
            print(f"[HAWK] crack teardown error: {e}", file=_sys.stderr)
        try:
            self.destroy()
        except Exception:
            pass

    def _startup_hosts_cleanup_check(self):
        """On startup, check /etc/hosts for stale HAWK-tagged entries.
        They can only exist if a previous HAWK instance crashed / was
        killed before _on_close ran.  We surface a non-modal notice in
        the terminal + offer one-click cleanup via a small dialog."""
        try:
            from utils.hosts_helper import list_hawk_entries
            stale = list_hawk_entries()
            if not stale:
                return
            self.terminal.write(
                f"  [!] Found {len(stale)} stale HAWK /etc/hosts "
                f"entry/entries from a previous session — they should "
                f"have been cleaned on exit but weren't (likely a "
                f"HAWK crash or force-kill).", "warn")
            for e in stale:
                self.terminal.write(
                    f"      {e['ip']}  →  {' '.join(e['hostnames'])}",
                    "dim")
            self.terminal.write(
                "  [*] Use the DNS HELPER → REMOVE ALL HAWK ENTRIES "
                "button (any AD tool auth dialog) to clean them up.",
                "dim")
        except Exception as e:
            print(f"[HAWK] startup hosts check error: {e}")

    # ─── Header ────────────────────────────────────────────────────────────────

    def _build_header(self):
        # Header is INTENTIONALLY compact — every pixel we save up here
        # is a pixel the operational area (kill chain left, terminal +
        # intel tabs right) gets to spend on scrolling output and port
        # rows.  Changes vs. the v1.0 layout:
        #   • banner pady 10→4 top, 4→2 bottom
        #   • subtitle font 14→13 (still bold so it reads)
        #   • version line font 13→11, muted color
        #   • bottom divider row REMOVED (unnecessary visual clutter)
        #   • hdr grid pady 8→4 top, 4→2 bottom
        # Net effect: ~35 % fewer pixels spent on chrome, same readability.
        from gui.widgets.target_bar import TargetBar
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_header"],
                           border_color=COLORS["border_dim"],
                           border_width=1, corner_radius=4)
        hdr.grid(row=0, column=0, sticky="ew", padx=8, pady=(4, 2))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkFrame(hdr, fg_color=COLORS["border_green"],
                     height=2, corner_radius=0).grid(
            row=0, column=0, columnspan=2, sticky="ew")

        # Banner + subtitle live in a vertical sub-frame so each can carry
        # its own font size: ASCII banner stays at the tight figlet size
        # (resizing it breaks the art), subtitle is promoted to a readable
        # body font.
        banner_box = ctk.CTkFrame(hdr, fg_color="transparent")
        banner_box.grid(row=1, column=0, padx=20, pady=(4, 2), sticky="w")
        ctk.CTkLabel(banner_box, text=BANNER.strip("\n"),
                     font=_f("banner", True),
                     text_color=COLORS["text_green"],
                     justify="left", anchor="w").pack(anchor="w")
        ctk.CTkLabel(banner_box, text=BANNER_SUBTITLE.strip(),
                     font=ctk.CTkFont(family="Courier New", size=13,
                                       weight="bold"),
                     text_color=COLORS["text_green"],
                     justify="left", anchor="w").pack(anchor="w", pady=(1, 0))

        # Watermark — two-line layout: version info (dim) + author (bright)
        wm_box = ctk.CTkFrame(hdr, fg_color="transparent")
        wm_box.grid(row=1, column=1, padx=20, pady=(4, 2), sticky="e")
        ctk.CTkLabel(wm_box,
                     text=f"v{APP_VERSION}  ·  Open Source  ·  Authorized use only",
                     font=ctk.CTkFont(family="Courier New", size=12),
                     text_color=COLORS["text_muted"],
                     anchor="e").pack(anchor="e")
        ctk.CTkLabel(wm_box,
                     text="Created by Lorenzo Serafini",
                     font=ctk.CTkFont(family="Courier New", size=13,
                                      weight="bold"),
                     text_color=COLORS["text_dim"],
                     anchor="e").pack(anchor="e")

        # Bottom divider removed — the TargetBar's own green top stripe
        # already provides enough visual separation.

        self.target_bar = TargetBar(hdr, self)
        self.target_bar.grid(row=2, column=0, columnspan=2,
                             sticky="ew", padx=4, pady=(0, 3))

    # ─── Main Area with resizable splitter ────────────────────────────────────

    def _build_main_area(self):
        from gui.widgets.kill_chain_panel import KillChainPanel
        from gui.widgets.terminal_widget  import TerminalWidget

        self._paned = tk.PanedWindow(
            self, orient=tk.HORIZONTAL,
            bg=COLORS["border_dim"],
            sashwidth=8, sashrelief=tk.RAISED,
            sashpad=0, handlesize=0, showhandle=False)
        self._paned.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)

        # Left: kill chain cards
        left = ctk.CTkFrame(self._paned, fg_color=COLORS["bg_primary"],
                            corner_radius=0)
        left.grid_rowconfigure(0, weight=1)
        left.grid_columnconfigure(0, weight=1)
        self.kill_chain_panel = KillChainPanel(left, app=self)
        self.kill_chain_panel.grid(row=0, column=0, sticky="nsew")

        # Right: vertical paned — terminal (top) + bottom tabs
        right = ctk.CTkFrame(self._paned, fg_color=COLORS["bg_primary"],
                             corner_radius=0)
        right.grid_rowconfigure(0, weight=1)
        right.grid_columnconfigure(0, weight=1)

        self._vpaned = tk.PanedWindow(
            right, orient=tk.VERTICAL,
            bg=COLORS["border_dim"],
            sashwidth=8, sashrelief=tk.RAISED,
            sashpad=0, handlesize=0, showhandle=False)
        self._vpaned.grid(row=0, column=0, sticky="nsew")

        self.terminal = TerminalWidget(self._vpaned, app=self)
        self._bottom_frame = ctk.CTkFrame(self._vpaned,
                                           fg_color=COLORS["bg_primary"],
                                           corner_radius=0)
        self._build_bottom_panel(self._bottom_frame)

        self._vpaned.add(self.terminal, minsize=100, height=400)
        self._vpaned.add(self._bottom_frame, minsize=80)

        # Sash highlight on vertical paned
        self._vpaned.bind("<Enter>", lambda e: self._vpaned.configure(
            bg=COLORS["border_green"]))
        self._vpaned.bind("<Leave>", lambda e: self._vpaned.configure(
            bg=COLORS["bg_primary"]))

        self._paned.add(left,  minsize=0, width=620)
        self._paned.add(right, minsize=0)

        # Sash highlight on horizontal paned
        self._paned.bind("<Enter>", lambda e: self._paned.configure(
            bg=COLORS["border_green"]))
        self._paned.bind("<Leave>", lambda e: self._paned.configure(
            bg=COLORS["bg_primary"]))

    def _build_bottom_panel(self, parent):
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        bottom = ctk.CTkFrame(
            parent, fg_color=COLORS["bg_secondary"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=4)
        bottom.grid(row=0, column=0, sticky="nsew")
        bottom.grid_rowconfigure(1, weight=1)
        bottom.grid_columnconfigure(0, weight=1)

        # Tab header
        tab_hdr = ctk.CTkFrame(bottom, fg_color=COLORS["bg_header"],
                               height=30, corner_radius=0)
        tab_hdr.grid(row=0, column=0, sticky="ew", padx=1, pady=(1, 0))
        tab_hdr.grid_propagate(False)
        # Last column (where the EXPAND/COMPACT button sits) takes the
        # remaining horizontal space so the button is pushed to the far right.
        tab_hdr.grid_columnconfigure(99, weight=1)

        self._tab_var = ctk.StringVar(value="findings")

        # Tab labels stored so we can blink TARGET INTEL
        self._tab_labels = {}

        for col, (label, val) in enumerate([
            ("FINDINGS",          "findings"),
            ("CREDENTIAL STORE",  "creds"),
            ("TARGET INTEL",      "intel"),
        ]):
            rb = ctk.CTkRadioButton(
                tab_hdr, text=label,
                variable=self._tab_var, value=val,
                font=_f("sm", True),
                text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                hover_color=COLORS["bg_card_hover"],
                command=self._switch_tab)
            rb.grid(row=0, column=col, padx=14, pady=4, sticky="w")
            self._tab_labels[val] = rb

        # Cross-tab SEARCH — opens a modal dialog that queries all
        # three data sources (Findings, Credentials, Target Intel)
        # at once.  Sits RIGHT OF the EXPAND button to fit the
        # user's mental model (both are "panel tools").  Same
        # compact format.
        self._search_btn = ctk.CTkButton(
            tab_hdr, text="🔍  SEARCH",
            width=110, height=22,
            font=_f("xs", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=3,
            command=self._open_cross_tab_search)
        self._search_btn.grid(row=0, column=98,
                              padx=(8, 2), pady=3, sticky="e")

        # Layout toggle — click once to give the intel/creds/findings
        # panel 80 % of the vertical space (terminal shrinks to 20 %);
        # click again to revert.  Tkinter's PanedWindow sashes are
        # draggable but people miss them, so this is the explicit path.
        self._bottom_expanded = False
        self._expand_btn = ctk.CTkButton(
            tab_hdr, text="⇕  EXPAND",
            width=110, height=22,
            font=_f("xs", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=3,
            command=self._toggle_bottom_expand)
        self._expand_btn.grid(row=0, column=99, padx=8, pady=3, sticky="e")

        # Content frames
        self._findings_frame = self._build_findings_panel(bottom)
        self._findings_frame.grid(row=1, column=0, sticky="nsew",
                                  padx=1, pady=(0, 1))

        from gui.widgets.credential_store_widget import CredentialStoreWidget
        self.cred_store = CredentialStoreWidget(bottom, app=self)

        self.cred_store.set_tab_label(self._tab_labels["creds"])

        from gui.widgets.target_intel_widget import TargetIntelWidget
        self.target_intel = TargetIntelWidget(bottom, app=self)
        self.target_intel.set_tab_label(self._tab_labels["intel"])

        self._tab_var.set("findings")

    def _toggle_bottom_expand(self):
        """Swap the vertical paned-window between two presets:

          compact  →  terminal ~70 % / tabs ~30 %   (default)
          expanded →  terminal ~20 % / tabs ~80 %

        Handy when TARGET INTEL or FINDINGS has accumulated dozens of
        entries and scrolling inside a cramped panel is miserable.
        """
        try:
            self.update_idletasks()
            total_h = self._vpaned.winfo_height()
            if total_h <= 50:
                return
            if self._bottom_expanded:
                # Back to compact — terminal gets most of the space.
                new_y = int(total_h * 0.65)
                self._expand_btn.configure(text="⇕  EXPAND",
                                           text_color=COLORS["text_green"])
                self._bottom_expanded = False
            else:
                # Give the bottom tabs 80 % of the room.
                new_y = int(total_h * 0.20)
                self._expand_btn.configure(text="⇔  COMPACT",
                                           text_color=COLORS["text_yellow"])
                self._bottom_expanded = True
            try:
                self._vpaned.sash_place(0, 0, new_y)
            except Exception:
                # Older Tk: fall back to sash_coord / sash_dragto.
                self._vpaned.sash_coord(0)
                self._vpaned.sash_dragto(0, 0, new_y)
        except Exception as e:
            print(f"[HAWK] toggle-expand failed: {e}")

    def _open_cross_tab_search(self):
        """Modal dialog that queries all three bottom-panel data
        sources (Findings / Credential Store / Target Intel) for a
        user-typed term.  Each hit shows its origin badge + snippet
        + a GOTO button that switches to the right tab and scrolls
        / highlights the underlying entry.

        Live filter: re-runs the query on every keystroke with a
        ~150 ms debounce so typing feels instant without hammering
        the builder on every key.
        """
        from gui.dialogs import (_make_win, _title, _sub,
                                  _btn_row, _btn, _safe_destroy)
        import re as _re

        win = _make_win(self, "Search — Findings / Creds / Intel",
                         820, 640)
        _title(win, "🔍  Cross-tab search")
        _sub(win,
             "Type anything — matches across manual findings, "
             "credentials, and Target Intel.",
             COLORS["text_dim"])

        query_var = ctk.StringVar(value="")

        # Search bar at the top.
        fr = ctk.CTkFrame(win, fg_color="transparent")
        fr.pack(fill="x", padx=14, pady=(6, 4))
        entry = ctk.CTkEntry(
            fr, textvariable=query_var, font=_f("lg"), height=36,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=4,
            placeholder_text="e.g. ldap, administrator, smb, "
                              "cve-2020, 192.168.1.10")
        entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        try:
            entry.focus_set()
        except Exception:
            pass

        # Counter.
        counter_var = ctk.StringVar(value="  (type to search)")
        ctk.CTkLabel(
            fr, textvariable=counter_var,
            font=_f("sm"), text_color=COLORS["text_dim"],
            width=160,
        ).pack(side="right")

        # Scrollable results body.
        body = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=4,
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=14, pady=(0, 6))

        def _clear_body():
            for w in body.winfo_children():
                try:
                    w.destroy()
                except Exception:
                    pass

        def _add_section(title_text, color, rows):
            if not rows:
                return
            ctk.CTkLabel(
                body, text=f"  ◇  {title_text}  ({len(rows)})",
                font=_f("md", True), text_color=color,
                anchor="w",
            ).pack(fill="x", padx=8, pady=(8, 2))
            for text, on_goto in rows[:30]:
                rf = ctk.CTkFrame(
                    body, fg_color=COLORS["bg_secondary"],
                    border_color=COLORS["border_dim"],
                    border_width=1, corner_radius=3)
                rf.pack(fill="x", padx=8, pady=2)
                ctk.CTkLabel(
                    rf, text=text, font=_f("sm"),
                    text_color=COLORS["text_bright"],
                    anchor="w", justify="left", wraplength=620,
                ).pack(side="left", fill="x", expand=True,
                       padx=6, pady=4)
                _btn(rf, "→ GOTO", on_goto, w=90)

        def _do_search(*_):
            q = (query_var.get() or "").strip().lower()
            _clear_body()
            if len(q) < 2:
                counter_var.set("  (type 2+ chars)")
                return

            # ── Target Intel findings ──────────────────────────────
            intel_hits = []
            try:
                intel = getattr(self, "target_intel", None)
                findings = (getattr(intel, "_auto_findings", []) or
                             []) if intel else []

                # Pre-build alias expansion: canonical vuln key →
                # all alias names + exploit labels.  This lets the
                # user search "eternalblue" and match a finding
                # whose title is "ms17-010".
                _alias_extra = {}
                try:
                    from gui.widgets.target_intel_widget import (
                        VULN_EXPLOIT_MAP as _vmap)
                    # First pass: collect labels for canonical keys
                    for _k, _v in _vmap.items():
                        if isinstance(_v, list):
                            parts = [_k]
                            for _mp, _lbl in _v:
                                parts.append(_lbl)
                                parts.append(_mp)
                            _alias_extra[_k] = " ".join(parts).lower()
                    # Second pass: pull alias names into their canonical
                    for _k, _v in _vmap.items():
                        if (isinstance(_v, str)
                                and _v.startswith("__alias__")):
                            _canon = _v[len("__alias__"):]
                            if _canon in _alias_extra:
                                _alias_extra[_canon] += " " + _k
                except Exception:
                    pass

                for f in findings:
                    _title_l = f.get("title", "").lower()
                    blob = (_title_l + " "
                             + f.get("description", "").lower() + " "
                             + f.get("source", "").lower()
                             + " " + _alias_extra.get(_title_l, ""))
                    if q in blob:
                        rid = f.get("linked_run_id", "")
                        title = f.get("title", "(no title)")
                        snippet = (f.get("description", "") or "")
                        snippet = _re.sub(r"\s+", " ",
                                           snippet)[:120]
                        text = f"{title}\n  {snippet}"
                        def _goto(r=rid, t=title):
                            _safe_destroy(win)
                            if r:
                                self.navigate_to_run_id(r, "intel")
                            else:
                                self.switch_to_tab("intel")
                        intel_hits.append((text, _goto))
            except Exception as e:
                print(f"[HAWK] cross-search intel: {e}")

            # ── Credential Store ───────────────────────────────────
            cred_hits = []
            try:
                sess = self.session_manager.current
                if sess is not None:
                    for c in (sess.get_credentials() or []):
                        blob = (f"{c.username} {c.host} "
                                f"{' '.join(c.services or [])} "
                                f"{c.cred_type} {c.hash_type} "
                                f"{c.notes} "
                                f"{c.password or ''} "
                                f"{c.hash_val or ''}").lower()
                        if q in blob:
                            rid = c.linked_run_id or ""
                            secret = (c.password or
                                       c.hash_val or "")
                            if len(secret) > 24:
                                secret = secret[:20] + "…"
                            svcs = (", ".join(c.services) or "—")
                            text = (f"{c.username or '(no user)'}  :  "
                                    f"{secret or '(no secret)'}\n"
                                    f"  {c.host or '(no host)'}  ·  "
                                    f"{svcs}  ·  {c.cred_type}")
                            def _goto(r=rid):
                                _safe_destroy(win)
                                if r:
                                    self.navigate_to_run_id(r, "creds")
                                else:
                                    self.switch_to_tab("creds")
                            cred_hits.append((text, _goto))
            except Exception as e:
                print(f"[HAWK] cross-search creds: {e}")

            # ── Manual findings (bottom-left panel) ────────────────
            manual_hits = []
            try:
                sess = self.session_manager.current
                if sess is not None:
                    for phase_id, pdata in (
                            (sess.phases or {}).items()):
                        for f in (pdata.get("findings") or []):
                            if not isinstance(f, dict):
                                continue
                            note = (f.get("title") or
                                     f.get("text") or "")
                            if q in note.lower() \
                                    or q in phase_id.lower():
                                sev = f.get("severity", "info")
                                text = (f"[{phase_id}  ·  "
                                        f"{sev}]\n  {note[:180]}")
                                def _goto():
                                    _safe_destroy(win)
                                    self.switch_to_tab("findings")
                                manual_hits.append((text, _goto))
            except Exception as e:
                print(f"[HAWK] cross-search manual: {e}")

            # Render.
            _add_section("TARGET INTEL",
                          COLORS["text_cyan"],    intel_hits)
            _add_section("CREDENTIAL STORE",
                          COLORS["text_green"],   cred_hits)
            _add_section("FINDINGS (manual)",
                          COLORS["text_yellow"],  manual_hits)

            total = len(intel_hits) + len(cred_hits) + len(manual_hits)
            counter_var.set(
                f"  {total} match"
                + ("es" if total != 1 else "")
                + f"  ·  intel={len(intel_hits)}"
                + f"  creds={len(cred_hits)}"
                + f"  findings={len(manual_hits)}")
            if total == 0:
                ctk.CTkLabel(
                    body,
                    text=f"\n  No matches for “{query_var.get()}”\n",
                    font=_f("md"),
                    text_color=COLORS["text_dim"],
                    anchor="center", justify="center",
                ).pack(fill="x", padx=8, pady=16)

        # Debounced live-search: schedule _do_search 150 ms after the
        # last keystroke so the builder doesn't re-run on every char.
        _pending = {"after_id": None}

        def _on_key(*_):
            if _pending["after_id"] is not None:
                try:
                    win.after_cancel(_pending["after_id"])
                except Exception:
                    pass
            _pending["after_id"] = win.after(150, _do_search)

        query_var.trace_add("write", _on_key)
        entry.bind("<Return>", lambda e: _do_search())

        row = _btn_row(win)
        _btn(row, "CLOSE", lambda: _safe_destroy(win),
             primary=True, w=120)

    def _switch_tab(self):
        val = self._tab_var.get()
        # Hide all
        for frame in [self._findings_frame,
                      self.cred_store, self.target_intel]:
            try:
                frame.grid_remove()
            except Exception:
                pass

        if val == "findings":
            self._findings_frame.grid(row=1, column=0, sticky="nsew",
                                      padx=1, pady=(0, 1))
        elif val == "creds":
            self.cred_store.grid(row=1, column=0, sticky="nsew",
                                 padx=1, pady=(0, 1))
            self.cred_store.refresh()
        elif val == "intel":
            self.target_intel.grid(row=1, column=0, sticky="nsew",
                                   padx=1, pady=(0, 1))

        # Stop blink on that tab
        if val == "intel":
            self.target_intel._blink_stop()
        elif val == "creds":
            self.cred_store._blink_stop()

    def switch_to_tab(self, tab_name: str) -> None:
        """Public helper for widgets that want to jump to a sibling
        panel — used by the cred↔intel run-id navigation buttons.
        Valid tab names: 'findings' | 'creds' | 'intel'."""
        if tab_name not in ("findings", "creds", "intel"):
            return
        try:
            self._tab_var.set(tab_name)
            self._switch_tab()
        except Exception as e:
            print(f"[HAWK] switch_to_tab({tab_name}) failed: {e}")

    def navigate_to_run_id(self, run_id: str, side: str) -> None:
        """Cross-navigation entrypoint — called by the "→ intel" /
        "🔑 creds" buttons.  `side` is the DESTINATION panel:
          "intel" → switch to Target Intel + scroll+highlight the
                    first finding whose linked_run_id matches
          "creds" → switch to Credential Store + scroll+highlight
                    the first credential whose linked_run_id matches

        No-op when run_id is empty."""
        if not run_id:
            return
        self.switch_to_tab(side)
        try:
            if side == "intel":
                self.target_intel.scroll_to_run_id(run_id)
            elif side == "creds":
                self.cred_store.scroll_to_run_id(run_id)
        except Exception as e:
            print(f"[HAWK] navigate_to_run_id({run_id}, {side}) failed: {e}")

    def _build_findings_panel(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"],
                             corner_radius=0)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Input row
        inp = ctk.CTkFrame(frame, fg_color="transparent")
        inp.grid(row=0, column=0, sticky="ew", padx=6, pady=4)
        inp.grid_columnconfigure(0, weight=1)

        self._finding_entry = ctk.CTkEntry(
            inp, height=26,
            placeholder_text="Add finding... (Enter to save)",
            font=_f("md"),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            placeholder_text_color=COLORS["text_muted"],
            corner_radius=3)
        self._finding_entry.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self._finding_entry.bind("<Return>", lambda e: self._add_finding())

        self._sev_var = ctk.StringVar(value="info")
        ctk.CTkOptionMenu(
            inp, values=["info", "low", "medium", "high", "critical"],
            variable=self._sev_var,
            width=90, height=26, font=_f("sm"),
            fg_color=COLORS["bg_secondary"],
            button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_dim"], corner_radius=3,
        ).grid(row=0, column=1, padx=(0, 4))

        ctk.CTkButton(
            inp, text="ADD", width=50, height=26,
            font=_f("sm", True),
            fg_color=COLORS["bg_secondary"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=3,
            command=self._add_finding,
        ).grid(row=0, column=2)

        # Findings textbox
        self._findings_box = ctk.CTkTextbox(
            frame, fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_width=0, corner_radius=0,
            font=_f("md"), wrap="word", state="disabled")
        self._findings_box.grid(row=1, column=0, sticky="nsew",
                                padx=4, pady=(0, 4))

        inner = self._findings_box._textbox
        for sev, col in [
            ("info",     COLORS["text_dim"]),
            ("low",      "#40A060"),
            ("medium",   COLORS["text_yellow"]),
            ("high",     COLORS["text_orange"]),
            ("critical", COLORS["text_red"]),
        ]:
            inner.tag_config(sev, foreground=col)

        return frame

    def _add_finding(self):
        text = self._finding_entry.get().strip()
        if not text:
            return
        sev = self._sev_var.get()
        if self.session_manager.current:
            self.session_manager.current.add_finding("recon", text, sev)
            self.session_manager.current.save()

        prefix = {
            "info":     "[INFO]    ", "low":      "[LOW]     ",
            "medium":   "[MEDIUM]  ", "high":     "[HIGH]    ",
            "critical": "[CRITICAL]",
        }.get(sev, "[INFO]    ")

        self._findings_box.configure(state="normal")
        self._findings_box._textbox.insert(
            "end", f"{prefix}  {text}\n", sev)
        self._findings_box.configure(state="disabled")
        self._findings_box._textbox.see("end")
        self._finding_entry.delete(0, "end")

    # ─── BG Jobs Bar ───────────────────────────────────────────────────────────

    def _build_bg_jobs_bar(self):
        from gui.widgets.bg_jobs_bar import BgJobsBar
        self.bg_jobs_bar = BgJobsBar(self, app=self)
        self.bg_jobs_bar.grid(row=2, column=0, sticky="ew",
                              padx=8, pady=0)

    # ─── Status Bar ────────────────────────────────────────────────────────────

    def _build_status_bar(self):
        from gui.widgets.status_bar import StatusBar
        # Network-health indicator lives in the TargetBar now, so the status
        # bar is back to its original three-field layout (session | phase | clock).
        self.status_bar = StatusBar(self)
        self.status_bar.grid(row=3, column=0, sticky="ew",
                             padx=8, pady=(0, 6))


    def _apply_context_menus(self):
        """Apply right-click Copy/Paste to all text widgets using xclip."""
        from utils.clipboard import apply_context_menus_recursive
        apply_context_menus_recursive(self)

    # ─── Public API ────────────────────────────────────────────────────────────

    def get_target(self) -> str:
        return self.target_bar.get_target()

    def get_completed_tools(self) -> set:
        """Return set of tool_ids that have completed across all kill chain cards."""
        try:
            return self.kill_chain_panel.get_completed_tool_ids()
        except Exception:
            return set()

    def has_run_tool(self, *tool_ids) -> bool:
        """True if ANY of the given tool_ids is in 'done' state."""
        done = self.get_completed_tools()
        return any(t in done for t in tool_ids)

    def ui_call(self, fn, *args, **kwargs):
        """Run a callback safely on the tkinter main loop."""
        if fn is None:
            return

        def _wrapped():
            try:
                fn(*args, **kwargs)
            except Exception as e:
                try:
                    self.terminal.write(f"[!] UI callback error: {e}", "error")
                except Exception:
                    pass

        try:
            self.after(0, _wrapped)
        except Exception:
            _wrapped()

    def ui_wrap(self, fn):
        """Return a callback that is always marshalled onto the UI thread."""
        if fn is None:
            return None
        return lambda *a, **k: self.ui_call(fn, *a, **k)

    def show(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    # ─── Target domain auto-suggestion ───────────────────────────────────────

    def suggest_target_domain(self, domain: str, source: str,
                              confidence: int, evidence: str = ""):
        """Offer a just-discovered target domain to the user.

        Called by tool parsers whenever they spot something that looks
        like a DNS/AD domain in a scan's output (enum4linux, ldapsearch,
        nmap ssl-cert, reverse DNS, NTLM challenge, ...).

        Behaviour:
          • If the session already holds this exact domain → silent no-op.
          • If the user already dismissed the same (source, domain) pair
            during this session → silent no-op.
          • Otherwise queue a DomainSuggestionDialog on the UI thread
            (via after(100) so it doesn't race with the tool's own
            done-callback side-effects).
        """
        if not domain:
            return
        domain = domain.strip().rstrip(".").lower()
        if not domain or "." not in domain:
            # We only promote proper FQDNs.  NetBIOS-only names
            # (WORKGROUP, COMPANY) are surfaced elsewhere and would
            # false-positive against IPs.
            return
        sess = self.session_manager.current
        if sess is None:
            return
        current = (getattr(sess, "target_domain", "") or "").lower()
        if current == domain:
            return    # already accepted

        # USER-PINNED domain — when the user typed the domain
        # manually in the target bar, HAWK never prompts to replace
        # it.  Auto-detected candidates are just logged + surfaced
        # as info findings (visible in Target Intel) so the user
        # knows the network self-reports a different name, without
        # being nagged to override their deliberate choice.
        pinned = bool(getattr(sess, "target_domain_pinned", False))
        if current and pinned:
            try:
                self.terminal.write(
                    f"  [i] Detected domain '{domain}' from {source} "
                    f"({confidence}% confidence) — target_domain is "
                    f"USER-PINNED to '{current}', not overriding.  "
                    f"Clear the domain field manually if you want to "
                    f"accept a detected one.",
                    "info")
            except Exception:
                pass
            try:
                if hasattr(self, "target_intel"):
                    self.target_intel.add_auto_finding(
                        title=f"Domain candidate (not applied): "
                              f"{domain}",
                        description=(
                            f"HAWK detected a domain name in tool "
                            f"output that does NOT match your manual "
                            f"target_domain setting.\n"
                            f"\n"
                            f"Detected : {domain}\n"
                            f"Source   : {source}\n"
                            f"Confidence: {confidence}%\n"
                            f"\n"
                            f"Evidence:\n{evidence or '(none)'}\n"
                            f"\n"
                            f"Because you've pinned the target "
                            f"domain, HAWK did not prompt to replace "
                            f"it.  If this candidate is the real "
                            f"AD/DNS name, clear your manual entry "
                            f"and re-run the tool."),
                        severity="info",
                        source=f"domain-detect / {source}")
            except Exception as e:
                print(f"[HAWK] pinned-domain finding failed: {e}")
            return

        # Respect a previously-accepted (non-pinned) target_domain
        # against weak sources.  Reverse DNS (PTR), HTTP redirects,
        # and nikto/whatweb "Target Hostname" all report the box's
        # FQDN — semantically different from the AD domain.  For
        # a non-pinned current value, only prompt on high-confidence
        # sources (LDAP namingContexts / NTLM challenge / SMB
        # DnsDomainName / SSL cert CN / enum4linux Domain Name).
        _HIGH_CONFIDENCE_FOR_OVERRIDE = 80
        if current and (int(confidence or 0) < _HIGH_CONFIDENCE_FOR_OVERRIDE):
            try:
                self.terminal.write(
                    f"  [*] Ignored low-confidence domain candidate "
                    f"'{domain}' from {source} ({confidence}%) — "
                    f"target_domain is already set to '{current}'.  "
                    f"Edit it manually if you want to change it.",
                    "dim")
            except Exception:
                pass
            return

        # Dismissed tracker — (source, domain) lower-case.
        if not hasattr(self, "_dismissed_domain_suggestions"):
            self._dismissed_domain_suggestions = set()
        key = ((source or "").lower(), domain)
        if key in self._dismissed_domain_suggestions:
            return

        def _on_accept(final_domain):
            s = self.session_manager.current
            if s is None:
                return
            s.target_domain = final_domain
            try:
                s.save()
            except Exception as e:
                print(f"[HAWK] failed to persist target_domain: {e}")
            if hasattr(self, "target_bar"):
                try:
                    self.target_bar.set_target_domain(final_domain)
                except Exception:
                    pass
            self.terminal.write(
                f"  [+] Target domain set: {final_domain}  "
                f"(via {source}, {confidence}% confidence)", "success")
            # Mirror into Target Intel as an info finding so it's visible
            # next to the rest of the target data.
            if hasattr(self, "target_intel"):
                try:
                    self.target_intel.add_auto_finding(
                        title=f"Domain identified: {final_domain}",
                        description=(
                            f"Source:     {source}\n"
                            f"Confidence: {confidence}%\n"
                            f"\nEvidence:\n{evidence or '(none)'}"),
                        severity="info",
                        source=source)
                except Exception:
                    pass

        def _on_dismiss():
            self._dismissed_domain_suggestions.add(key)
            self.terminal.write(
                f"  [*] Domain suggestion dismissed: {domain} "
                f"(via {source}) — won't ask again for this pair.",
                "dim")

        from gui.dialogs import DomainSuggestionDialog
        self.after(150, lambda: DomainSuggestionDialog(
            self, domain, source, int(confidence), evidence,
            on_accept=_on_accept, on_dismiss=_on_dismiss))
