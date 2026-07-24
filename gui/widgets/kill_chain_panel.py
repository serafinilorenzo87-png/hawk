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
HAWK - Kill Chain Panel
Scrollable left panel containing all 8 kill chain cards.
"""

import customtkinter as ctk
from utils.config import COLORS, KILL_CHAIN_PHASES
from modules import MODULE_MAP
from gui.widgets.card_widget import KillChainCard


class KillChainPanel(ctk.CTkFrame):
    """
    Left panel: scrollable list of KillChainCard widgets.
    """

    def __init__(self, parent, app, **kwargs):
        super().__init__(
            parent,
            fg_color     = COLORS["bg_primary"],
            border_width = 0,
            **kwargs
        )
        self.app   = app
        self._cards: dict[str, KillChainCard] = {}
        self._build_ui()

    def _build_ui(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Scrollable container for the cards
        self._scroll = ctk.CTkScrollableFrame(
            self,
            fg_color            = COLORS["bg_primary"],
            scrollbar_button_color       = COLORS["border_dim"],
            scrollbar_button_hover_color = COLORS["border_green"],
            corner_radius = 0,
            border_width  = 0,
        )
        self._scroll.grid(row=0, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)

        # Build one card per kill chain phase
        for idx, phase_cfg in enumerate(KILL_CHAIN_PHASES):
            module_cls = MODULE_MAP.get(phase_cfg["id"])
            if module_cls is None:
                continue
            module_instance = module_cls()

            card = KillChainCard(
                self._scroll,
                phase_config=phase_cfg,
                module=module_instance,
                app=self.app,
            )
            card.grid(row=idx, column=0, sticky="ew", padx=6, pady=4)

            self._cards[phase_cfg["id"]] = card

    # ─── Public API ────────────────────────────────────────────────────────────

    @property
    def cards(self) -> dict:
        """Expose cards dict (read-only view)."""
        return self._cards

    def get_card(self, phase_id: str) -> KillChainCard:
        return self._cards.get(phase_id)

    def get_completed_tool_ids(self) -> set:
        """
        Return ids of every tool that has completed successfully
        (green-dot status == 'done') across all cards.
        """
        done = set()
        for card in self._cards.values():
            for tid, tw in getattr(card, "_tool_widgets", {}).items():
                if isinstance(tw, dict) and tw.get("_status") == "done":
                    done.add(tid)
        return done

    def get_tool_statuses(self) -> dict:
        """Return {tool_id: status} for every tool across all cards."""
        out = {}
        for card in self._cards.values():
            for tid, tw in getattr(card, "_tool_widgets", {}).items():
                if isinstance(tw, dict):
                    out[tid] = tw.get("_status", "ready")
        return out

    def reset_all_statuses(self):
        """Reset all cards to READY (when a new session starts)."""
        from utils.config import STATUS_READY
        for card in self._cards.values():
            card.set_status(STATUS_READY)
            for tool_id in card._tool_widgets:
                card._set_tool_status(tool_id, "ready")

    def run_autopilot(self, phase_ids: list = None):
        """
        Hybrid autopilot: run all phases (or a subset) sequentially.
        Each phase waits for the previous to finish before starting.
        """
        if phase_ids is None:
            phase_ids = list(self._cards.keys())

        from utils.runner import MultiRunner

        sequence = []
        for phase_id in phase_ids:
            card = self._cards.get(phase_id)
            if card:
                sequence.append(card)

        self._run_sequence(sequence)

    def _run_sequence(self, cards: list, idx: int = 0):
        if idx >= len(cards):
            self.app.terminal.write(
                "[+] Autopilot complete — all phases executed.", "success"
            )
            return
        card = cards[idx]
        self.app.terminal.section(
            f"AUTOPILOT → {card.phase_config['name']}"
        )
        # After run_all completes, trigger next
        orig_cb = None

        def _next_on_done(results):
            if orig_cb:
                orig_cb(results)
            self.after(500, lambda: self._run_sequence(cards, idx + 1))

        if card._multi_runner is None:
            from utils.runner import MultiRunner
            card._multi_runner = MultiRunner(
                output_callback=self.app.terminal.output_callback,
                all_done_callback=_next_on_done,
                ui_dispatcher=getattr(self.app, "ui_call", None),
            )
        else:
            orig_cb = card._multi_runner.all_done_callback
            card._multi_runner.all_done_callback = _next_on_done

        card._run_all()
