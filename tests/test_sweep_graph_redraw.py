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

"""Sweep-graph redraw on promotion (carry-over V4a).

The graph window is a snapshot: after a host is promoted (its session is
materialised) the cyan has_session ring only appeared on a reopen.  The fix
repaints the ring in place.  target_bar drives it through
``_mark_sweep_graph_session``, which must call the window's
``mark_session_ring`` when present and otherwise fall back to closing the
(older / unrepaintable) window so nothing stale is left up.

The matplotlib repaint itself needs a display + matplotlib/networkx and is
not unit-tested here; this pins the wiring/fallback contract headlessly.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class _DummyCtk:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, _n):
        return _DummyCtk

    def __call__(self, *a, **k):
        return _DummyCtk()


def _install_customtkinter_stub():
    module = types.ModuleType("customtkinter")
    for name in (
        "CTkFrame", "CTkFont", "CTkButton", "CTkLabel", "CTkEntry",
        "CTkTextbox", "CTkToplevel", "CTkScrollableFrame", "CTkOptionMenu",
        "CTkCheckBox", "CTkRadioButton", "CTkProgressBar", "CTkTabview",
        "CTkSwitch", "StringVar", "BooleanVar", "IntVar",
    ):
        setattr(module, name, _DummyCtk)
    sys.modules["customtkinter"] = module


class MarkSweepGraphSessionTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        from gui.widgets.target_bar import TargetBar
        self._TargetBar = TargetBar

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _bar(self):
        tb = self._TargetBar.__new__(self._TargetBar)
        tb._closed = 0

        def _close():
            tb._closed += 1
            tb._sweep_graph_win = None
        tb._close_sweep_graph = _close
        return tb

    def test_repaintable_window_gets_the_ring_and_stays_open(self):
        tb = self._bar()
        marked = []

        class _Win:
            def mark_session_ring(self, ip):
                marked.append(ip)

        tb._sweep_graph_win = _Win()
        tb._mark_sweep_graph_session("10.0.0.7")
        self.assertEqual(marked, ["10.0.0.7"])
        self.assertEqual(tb._closed, 0)                # not closed

    def test_old_window_without_repaint_falls_back_to_close(self):
        tb = self._bar()
        tb._sweep_graph_win = object()                 # no mark_session_ring
        tb._mark_sweep_graph_session("10.0.0.7")
        self.assertEqual(tb._closed, 1)

    def test_mark_that_raises_falls_back_to_close(self):
        tb = self._bar()

        class _Win:
            def mark_session_ring(self, ip):
                raise RuntimeError("canvas gone")

        tb._sweep_graph_win = _Win()
        tb._mark_sweep_graph_session("10.0.0.7")
        self.assertEqual(tb._closed, 1)

    def test_no_open_window_is_harmless(self):
        tb = self._bar()
        tb._sweep_graph_win = None
        tb._mark_sweep_graph_session("10.0.0.7")
        self.assertEqual(tb._closed, 1)                # close is a no-op-safe


if __name__ == "__main__":
    unittest.main()
