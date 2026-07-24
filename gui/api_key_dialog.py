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
HAWK - API Key Setup Dialog v1.0
Shown at startup. User enters NVD API key or skips.
Key saved to .env — never committed to git.
"""

import customtkinter as ctk
from utils.config import COLORS, SZ


def _f(key="md", bold=False):
    return ctk.CTkFont(family="Courier New", size=SZ.get(key, 14),
                       weight="bold" if bold else "normal")


class ApiKeyDialog(ctk.CTkToplevel):
    """
    Modal dialog shown at startup for NVD API key setup.
    Calls on_done(key) when confirmed, on_done("") if skipped.
    """

    def __init__(self, parent, on_done, existing_key: str = ""):
        super().__init__(parent)
        # Hide until the build is complete — otherwise CTkToplevel flashes
        # the window at its default tiny size before _autosize settles it.
        self.withdraw()
        self._on_done   = on_done
        self._existing  = existing_key.strip()

        self.title("HAWK — CVE Lookup Setup")
        self.geometry("620x560")
        self.resizable(True, True)
        self.configure(fg_color=COLORS["bg_primary"])

        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"620x560+{(sw-620)//2}+{(sh-560)//2}")

        self._build()
        self.after(80, self._autosize)
        self.after(250, self._autosize)

        # Reveal once the layout has settled.
        def _reveal():
            try:
                if not self.winfo_exists():
                    return
                self.deiconify()
                self.lift()
                self.focus_force()
                self.grab_set()
            except Exception:
                pass
        self.after(280, _reveal)

    def _autosize(self):
        try:
            self.update_idletasks()
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            w = min(max(self.winfo_reqwidth() + 40, 620), int(sw * 0.92))
            h = min(max(self.winfo_reqheight() + 40, 560), int(sh * 0.92))
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _build(self):
        # Top accent
        ctk.CTkFrame(self, fg_color=COLORS["border_green"],
                     height=2, corner_radius=0).pack(fill="x")

        # Title
        ctk.CTkLabel(self,
                     text="HAWK  —  CVE Lookup Setup",
                     font=_f("xl", True),
                     text_color=COLORS["text_green"]).pack(pady=(20, 4))

        ctk.CTkLabel(self,
                     text="Real-time vulnerability data from NVD / NIST",
                     font=_f("sm"),
                     text_color=COLORS["text_muted"]).pack(pady=(0, 14))

        # Info box
        info = ctk.CTkFrame(self,
                            fg_color=COLORS["bg_card"],
                            border_color=COLORS["border_dim"],
                            border_width=1, corner_radius=4)
        info.pack(fill="x", padx=24, pady=4)

        ctk.CTkLabel(info,
                     text=(
                         "HAWK queries the National Vulnerability Database (NVD) "
                         "to find CVEs for services detected during scanning.\n\n"
                         "Without API key:  5 requests / 30 seconds\n"
                         "With free API key: 50 requests / 30 seconds  ★ recommended\n\n"
                         "Get your free key at:\n"
                         "  nvd.nist.gov/developers/request-an-api-key\n\n"
                         "Your key is saved locally in .env — "
                         "never uploaded to GitHub."
                     ),
                     font=_f("md"),
                     text_color=COLORS["text_dim"],
                     justify="left",
                     anchor="w").pack(padx=14, pady=12, anchor="w")

        # Current status
        has_key = bool(self._existing)
        if has_key:
            masked = f"{self._existing[:8]}...{self._existing[-4:]}"
            status_text  = f"  ✓  Key already configured: {masked}"
            status_color = COLORS["text_green"]
        else:
            status_text  = "  ✗  No key configured — limited rate mode"
            status_color = COLORS["text_yellow"]

        self._status_lbl = ctk.CTkLabel(self,
                     text=status_text, font=_f("md"),
                     text_color=status_color)
        self._status_lbl.pack(pady=(8, 2))

        # Entry
        ctk.CTkLabel(self,
                     text="Paste your NVD API key:",
                     font=_f("md"), text_color=COLORS["text_dim"],
                     anchor="w").pack(fill="x", padx=24, pady=(12, 4))

        self._key_entry = ctk.CTkEntry(
            self,
            height=38,
            placeholder_text="e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            font=_f("md"),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"],
            border_width=1,
            placeholder_text_color=COLORS["text_muted"],
            corner_radius=4)
        self._key_entry.pack(fill="x", padx=24, pady=(0, 4))

        # Pre-fill if existing
        if self._existing:
            self._key_entry.insert(0, self._existing)

        # Validate hint
        self._hint_lbl = ctk.CTkLabel(self,
                     text="",
                     font=_f("sm"),
                     text_color=COLORS["text_muted"])
        self._hint_lbl.pack(pady=2)

        self._key_entry.bind("<KeyRelease>", self._validate)
        # Enter on the key entry should act as "SAVE KEY & START" — one
        # keystroke instead of tabbing to the button.  If the entry is
        # empty, fall through to _skip() so pressing Enter on a blank
        # field still dismisses the dialog in limited mode (keeps
        # keyboard-only users moving).
        def _submit(_e=None):
            if self._key_entry.get().strip():
                self._confirm()
            else:
                self._skip()
        self._key_entry.bind("<Return>",    _submit)
        self._key_entry.bind("<KP_Enter>",  _submit)   # numpad Enter too
        # Put focus on the entry so the user can type / paste + Enter
        # without clicking first.
        self._key_entry.focus_set()

        # Buttons
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(pady=20)

        ctk.CTkButton(
            btn_row, text="SAVE KEY & START",
            width=180, height=36,
            font=_f("md", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=4,
            command=self._confirm,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_row, text="SKIP — use limited mode",
            width=200, height=36,
            font=_f("md"),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=4,
            command=self._skip,
        ).pack(side="left", padx=8)

        ctk.CTkLabel(self,
                     text="You can change this later in Settings → API Keys",
                     font=_f("sm"),
                     text_color=COLORS["text_muted"]).pack(pady=4)

    def _validate(self, event=None):
        key = self._key_entry.get().strip()
        import re
        uuid_re = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.I)
        if not key:
            self._hint_lbl.configure(text="", text_color=COLORS["text_muted"])
        elif uuid_re.match(key):
            self._hint_lbl.configure(
                text="  ✓  Valid key format",
                text_color=COLORS["text_green"])
        else:
            self._hint_lbl.configure(
                text="  ✗  Invalid format — NVD keys are UUID format",
                text_color=COLORS["text_yellow"])

    def _confirm(self):
        key = self._key_entry.get().strip()
        # Empty field → SAVE is meaningless; force user to either type a
        # key or explicitly click SKIP.
        if not key:
            self._hint_lbl.configure(
                text="  ✗  Field is empty — type your key or click "
                     "\"SKIP — use limited mode\"",
                text_color=COLORS.get("text_red", COLORS["text_yellow"]))
            self._key_entry.focus_set()
            return
        # Sanity-check UUID format; a typo here would silently save
        # garbage and every CVE lookup would fail later.
        import re
        uuid_re = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.I)
        if not uuid_re.match(key):
            self._hint_lbl.configure(
                text="  ✗  Not a valid UUID — check the key and paste again",
                text_color=COLORS.get("text_red", COLORS["text_yellow"]))
            self._key_entry.focus_set()
            return
        self.grab_release()
        self.destroy()
        from utils.cve_lookup import set_api_key
        set_api_key(key)
        self._on_done(key)

    def _skip(self):
        self.grab_release()
        self.destroy()
        self._on_done("")
