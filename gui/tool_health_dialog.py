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
HAWK - Tool health dialog.

Shown shortly after startup when the health check (utils.tool_health) finds a
known-problem tool that is installed but broken — e.g. netexec crashing on
import under Kali 2025's Python 3.13. Lists each broken tool, what breaks, and
offers to run its one-command fix in an external terminal (the operator types
any password there; HAWK never handles it).

Non-blocking by construction: nothing is shown when everything is fine — the
caller only builds this dialog when tool_health.check() returned entries.
"""

import customtkinter as ctk
from utils.config import COLORS, SZ


def _f(key="md", bold=False):
    return ctk.CTkFont(family="Courier New", size=SZ.get(key, 14),
                       weight="bold" if bold else "normal")


class ToolHealthDialog(ctk.CTkToplevel):
    """Modal dialog listing installed-but-broken tools with a one-click fix.
    `broken` is the list returned by utils.tool_health.check()."""

    def __init__(self, parent, broken, on_done=None):
        super().__init__(parent)
        self.withdraw()
        self._on_done = on_done or (lambda: None)
        self._broken = broken or []

        self.title("HAWK — Tool health")
        self.geometry("680x560")
        self.resizable(True, True)
        self.configure(fg_color=COLORS["bg_primary"])

        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"680x560+{(sw-680)//2}+{(sh-560)//2}")
        self.protocol("WM_DELETE_WINDOW", self._close)

        self._build()
        self.after(80, self._autosize)
        self.after(250, self._autosize)

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
            w = min(max(self.winfo_reqwidth() + 40, 680), int(sw * 0.92))
            h = min(max(self.winfo_reqheight() + 40, 560), int(sh * 0.92))
            self.geometry(f"{w}x{h}+{max(0, (sw-w)//2)}+{max(0, (sh-h)//2)}")
        except Exception:
            pass

    def _build(self):
        ctk.CTkFrame(self, fg_color=COLORS["border_green"], height=2,
                     corner_radius=0).pack(fill="x")
        ctk.CTkLabel(self, text="HAWK  —  Tool health",
                     font=_f("xl", True),
                     text_color=COLORS["text_green"]).pack(pady=(20, 4))
        n = len(self._broken)
        ctk.CTkLabel(
            self,
            text=(f"{n} installed tool(s) are present but broken — "
                  "they will fail until fixed"),
            font=_f("sm"), text_color=COLORS["text_muted"]).pack(pady=(0, 12))

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=16, pady=4)
        for entry in self._broken:
            self._tool_block(scroll, entry)

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(pady=14)
        ctk.CTkButton(
            btn_row, text="CONTINUE", width=150, height=36, font=_f("md"),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=4,
            command=self._close).pack(side="left", padx=8)

    def _tool_block(self, parent, entry):
        box = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"],
                           border_color=COLORS["border_amber"],
                           border_width=1, corner_radius=4)
        box.pack(fill="x", pady=6)
        ctk.CTkLabel(box, text=f"  ✗  {entry['name']} — installed but "
                               f"broken",
                     font=_f("md", True), text_color=COLORS["text_yellow"],
                     anchor="w").pack(fill="x", padx=12, pady=(10, 2))
        ctk.CTkLabel(box, text=entry.get("why", ""), font=_f("sm"),
                     text_color=COLORS["text_dim"], justify="left",
                     anchor="w", wraplength=580).pack(fill="x", padx=12, pady=2)
        ctk.CTkLabel(box, text=f"fix:  {entry.get('fix_cmd', '')}",
                     font=_f("sm"), text_color=COLORS["text_green"],
                     justify="left", anchor="w",
                     wraplength=580).pack(fill="x", padx=12, pady=(2, 4))

        hint = ctk.CTkLabel(box, text="", font=_f("sm"),
                            text_color=COLORS["text_muted"],
                            wraplength=580, justify="left", anchor="w")
        hint.pack(fill="x", padx=12, pady=(0, 2))

        def _run():
            cmd = entry.get("fix_cmd")
            if not cmd:
                return
            opened = False
            try:
                from utils.runner import open_native_shell
                opened = open_native_shell(
                    title=f"HAWK — fix {entry['name']}",
                    initial_cmd=cmd, auto_close=False)
            except Exception:
                opened = False
            if opened:
                hint.configure(
                    text="  A terminal opened — type your password if asked. "
                         "When it finishes, restart HAWK.",
                    text_color=COLORS["text_green"])
            else:
                hint.configure(
                    text=f"  ✗  Could not open a terminal. Run manually:  "
                         f"{cmd}",
                    text_color=COLORS["text_yellow"])

        ctk.CTkButton(
            box, text="RUN FIX IN TERMINAL", width=200, height=32,
            font=_f("sm", True), fg_color=COLORS["bg_card_hover"],
            hover_color=COLORS["bg_card"], border_color=COLORS["border_green"],
            border_width=1, text_color=COLORS["text_green"], corner_radius=4,
            command=_run).pack(anchor="w", padx=12, pady=(2, 10))

    def _close(self):
        try:
            self.grab_release()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass
        try:
            self._on_done()
        except Exception:
            pass
