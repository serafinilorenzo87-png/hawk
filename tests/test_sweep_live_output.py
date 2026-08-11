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

"""Network-sweep live output (finding F-26).

A sweep is a discovery run: the operator watches hosts appear to decide
whether to abort.  In smart mode the terminal buffers every tool line
until the run is done, so a long sweep shows nothing and the operator
aborts blind.  ``output_callback(mirror_live=True)`` must stream every
non-progress line to the terminal as it arrives instead of buffering it.

Runs headless with a customtkinter stub + a bare __new__ instance so no
Tk root / display is required.
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


class SweepLiveOutputTests(unittest.TestCase):
    # A plain nmap-sn discovery line — matches none of the progress regexes,
    # so it takes the buffer-or-append tail of output_callback.
    _HOST_LINE = "Nmap scan report for 192.168.1.42"

    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        from gui.widgets.terminal_widget import TerminalWidget
        self._TerminalWidget = TerminalWidget

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _term(self):
        """A bare TerminalWidget in smart mode, with only the attributes
        output_callback touches and a synchronous ``after``."""
        term = self._TerminalWidget.__new__(self._TerminalWidget)
        term._smart_mode = True
        term._pending = {}
        term._port_scan_seen = {}
        term.appended = []
        term._append = lambda line, level="info": term.appended.append(
            (line, level))
        term.after = lambda _delay, cb=None, *a: (cb() if callable(cb)
                                                  else None)
        return term

    def test_live_mirror_shows_the_line_immediately(self):
        term = self._term()
        term.output_callback(self._HOST_LINE, "sweep-nmap-sn", "info",
                             mirror_live=True)
        # Shown live...
        self.assertIn((self._HOST_LINE, "info"), term.appended)
        # ...and NOT left sitting in the buffer.
        self.assertEqual(term._pending.get("sweep-nmap-sn", []), [])

    def test_smart_mode_without_mirror_buffers_the_line(self):
        term = self._term()
        term.output_callback(self._HOST_LINE, "sweep-nmap-sn", "info")
        # The unfixed behaviour: nothing shown, everything buffered.
        self.assertEqual(term.appended, [])
        self.assertEqual(term._pending.get("sweep-nmap-sn"),
                         [self._HOST_LINE])


if __name__ == "__main__":
    unittest.main()
