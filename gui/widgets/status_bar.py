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
HAWK - Status Bar Widget
Bottom bar: session info, current phase, clock.

The network-health indicator used to live here but was moved to the
TargetBar (gui.widgets.net_health.NetHealthIndicator) so it sits right
under the NEW SESSION / RESUME / SAVE buttons where the user actually
looks during a test, instead of being a dim label in the far corner.
"""

import customtkinter as ctk
from datetime import datetime
from utils.config import COLORS


class StatusBar(ctk.CTkFrame):

    def __init__(self, parent, **kwargs):
        super().__init__(
            parent,
            fg_color     = COLORS["bg_header"],
            border_color = COLORS["border_dim"],
            border_width = 1,
            height       = 26,
            corner_radius = 0,
            **kwargs
        )
        self.grid_propagate(False)
        self._build_ui()
        self._tick()

    # ─── UI layout ─────────────────────────────────────────────────────────
    def _build_ui(self):
        # col 2 stretches, everything else is fixed.
        self.grid_columnconfigure(2, weight=1)

        # Left: session info
        self._session_lbl = ctk.CTkLabel(
            self,
            text="  ● No session",
            font=ctk.CTkFont(family="Courier New", size=9),
            text_color=COLORS["text_dim"],
            anchor="w",
        )
        self._session_lbl.grid(row=0, column=0, padx=(8, 16), pady=2, sticky="w")

        # Mid-left: phase info
        self._phase_lbl = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont(family="Courier New", size=9),
            text_color=COLORS["text_dim"],
            anchor="w",
        )
        self._phase_lbl.grid(row=0, column=1, padx=8, pady=2, sticky="w")

        # Spacer
        ctk.CTkFrame(self, fg_color="transparent").grid(row=0, column=2, sticky="ew")

        # Right: clock
        self._clock_lbl = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont(family="Courier New", size=9),
            text_color=COLORS["text_dim"],
            anchor="e",
        )
        self._clock_lbl.grid(row=0, column=3, padx=(4, 12), pady=2, sticky="e")

    # ─── Public API ────────────────────────────────────────────────────────
    def set_session(self, target: str, platform: str):
        self._session_lbl.configure(
            text=f"  ● {target}  [{platform}]",
            text_color=COLORS["text_green"],
        )

    def set_phase(self, phase_name: str, status: str):
        color_map = {
            "READY":   COLORS["text_dim"],
            "RUNNING": "#FFB600",
            "DONE":    "#39FF14",
            "ERROR":   COLORS["text_red"],
        }
        color = color_map.get(status.upper(), COLORS["text_dim"])
        self._phase_lbl.configure(
            text=f"  {phase_name}  [{status}]",
            text_color=color,
        )

    def set_message(self, msg: str):
        self._phase_lbl.configure(
            text=f"  {msg}",
            text_color=COLORS["text_green"],
        )

    # ─── Clock tick ────────────────────────────────────────────────────────
    def _tick(self):
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self._clock_lbl.configure(text=f"{now}  ")
        self._tick_id = self.after(1000, self._tick)

    # ─── Teardown ──────────────────────────────────────────────────────────
    def destroy(self):
        try:
            tid = getattr(self, "_tick_id", None)
            if tid is not None:
                self.after_cancel(tid)
        except Exception:
            pass
        super().destroy()
