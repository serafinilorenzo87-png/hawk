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

"""Network-health pill: the state machine must never paint GREEN unless
the gateway AND the target are BOTH reachable.

The bug: with the target VM down (or with no target set at all) the pill
stayed green, because green was granted on gateway reachability alone
(`gw_ok and (not has_tg or tg_ok)`).  A dead target hid behind a
healthy-looking pill — the same class of dishonest signal as "LAUNCH ==
RCE".  These tests pin the honest contract on the pure decision so no Tk
or display is needed.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# ─── headless customtkinter stub (module level, not conftest) ──────────────
class _DummyCtk:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, _n):
        return _DummyCtk

    def __call__(self, *a, **k):
        return _DummyCtk()


def _install_ctk_stub():
    m = types.ModuleType("customtkinter")
    for name in ("CTk", "CTkFrame", "CTkFont", "CTkButton", "CTkLabel",
                 "CTkEntry", "CTkToplevel"):
        setattr(m, name, _DummyCtk)
    m.set_appearance_mode = lambda *a, **k: None
    m.set_default_color_theme = lambda *a, **k: None
    sys.modules["customtkinter"] = m


_install_ctk_stub()

from gui.widgets.net_health import _net_pill_state          # noqa: E402
from utils.config import COLORS                             # noqa: E402

GREEN = COLORS["text_green"]
RED = COLORS["text_red"]
DIM = COLORS["text_dim"]
AMBER = "#FFB600"


class PillStateTruthTable(unittest.TestCase):

    # ── the reported symptom, pinned ────────────────────────────────────
    def test_target_down_is_amber_never_green(self):
        state, text, color = _net_pill_state(gw_ok=True, has_tg=True,
                                             tg_ok=False)
        self.assertEqual(state, "degraded")
        self.assertEqual(color, AMBER)
        self.assertNotEqual(color, GREEN)

    def test_no_target_set_is_neutral_never_green(self):
        """Gateway up, no target: link is fine but nothing is verified
        reachable, so the pill must NOT be green."""
        state, text, color = _net_pill_state(gw_ok=True, has_tg=False,
                                             tg_ok=None)
        self.assertEqual(state, "link")
        self.assertEqual(color, DIM)
        self.assertNotEqual(color, GREEN)

    # ── the one and only green ──────────────────────────────────────────
    def test_both_reachable_is_green(self):
        state, text, color = _net_pill_state(gw_ok=True, has_tg=True,
                                             tg_ok=True)
        self.assertEqual(state, "ok")
        self.assertEqual(color, GREEN)

    # ── link/gateway down dominates everything ──────────────────────────
    def test_gateway_down_is_red_regardless_of_target(self):
        for tg_ok in (True, False, None):
            for has_tg in (True, False):
                for gw in (False, None):
                    _s, _t, color = _net_pill_state(gw, has_tg, tg_ok)
                    self.assertEqual(color, RED,
                                     f"gw={gw} has_tg={has_tg} tg={tg_ok}")

    # ── drift escalates a down target from amber to red ─────────────────
    def test_drift_is_red_ip_marker(self):
        state, text, color = _net_pill_state(gw_ok=True, has_tg=True,
                                             tg_ok=False, drift_suspected=True)
        self.assertEqual(state, "drift")
        self.assertIn("IP?", text)
        self.assertNotEqual(color, AMBER)

    def test_target_probe_pending_is_dim_not_green(self):
        state, text, color = _net_pill_state(gw_ok=True, has_tg=True,
                                             tg_ok=None)
        self.assertEqual(state, "unknown")
        self.assertEqual(color, DIM)

    # ── the invariant across the WHOLE state space ──────────────────────
    def test_green_iff_gateway_and_target_both_reachable(self):
        for gw in (True, False, None):
            for has_tg in (True, False):
                for tg_ok in (True, False, None):
                    for drift in (False, True):
                        _s, _t, color = _net_pill_state(gw, has_tg, tg_ok,
                                                        drift)
                        is_green = (color == GREEN)
                        should = bool(gw) and has_tg and (tg_ok is True)
                        self.assertEqual(
                            is_green, should,
                            f"green={is_green} but expected {should} for "
                            f"gw={gw} has_tg={has_tg} tg={tg_ok} drift={drift}")


if __name__ == "__main__":
    unittest.main()
