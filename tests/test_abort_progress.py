"""_abort_progress stops a scan's progress bar in a distinct 'ran, but
no service' state instead of leaving it frozen at its last percentage.

The SNMP UDP-161 probe drives nmap's --stats-every bar through
ToolRunner and never reaches flush_tool_output, so on a closed port the
bar used to freeze at ~50%.  The probe now calls _abort_progress, which
must (a) drop the tool from every progress-tracking dict so nothing
lingers, and (b) render an amber bar carrying the reason -- NOT the green
'100% Complete' check that _finish_progress paints (that would sell a
dead port as a successful scan).
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


class _Var:
    def __init__(self):
        self.value = None

    def set(self, v):
        self.value = v


class _Lbl:
    def __init__(self):
        self.fg = None
        self.destroyed = False

    def winfo_exists(self):
        return True

    def configure(self, **k):
        if "fg" in k:
            self.fg = k["fg"]

    def destroy(self):
        self.destroyed = True


PROBE = "NMAP UDP 161 probe"


class AbortProgressTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _stub_with_bar(self):
        lbl, var = _Lbl(), _Var()
        stub = types.SimpleNamespace(
            _progress_labels={PROBE: (lbl, var)},
            _progress_max={PROBE: 100},
            _port_scan_seen={PROBE: True})
        return stub, lbl, var

    def test_abort_removes_bar_from_all_tracking(self):
        from gui.widgets.terminal_widget import TerminalWidget
        stub, lbl, var = self._stub_with_bar()
        TerminalWidget._abort_progress(stub, PROBE, "161/udp closed (no service)")
        # No lingering entry in any progress dict -> the bar can't freeze.
        self.assertNotIn(PROBE, stub._progress_labels)
        self.assertNotIn(PROBE, stub._progress_max)
        self.assertNotIn(PROBE, stub._port_scan_seen)

    def test_abort_shows_reason_and_is_not_the_green_complete(self):
        from gui.widgets.terminal_widget import TerminalWidget
        stub, lbl, var = self._stub_with_bar()
        TerminalWidget._abort_progress(stub, PROBE, "161/udp closed (no service)")
        self.assertIn("161/udp closed (no service)", var.value)
        # _finish_progress paints "100.0%  — Complete" green (#40A060);
        # abort must do neither.
        self.assertNotIn("Complete", var.value)
        self.assertNotEqual(lbl.fg, "#40A060")
        self.assertEqual(lbl.fg, "#C08040")

    def test_abort_on_unknown_tool_is_a_noop(self):
        from gui.widgets.terminal_widget import TerminalWidget
        stub, _, _ = self._stub_with_bar()
        # Different name -> nothing to abort, must not raise.
        TerminalWidget._abort_progress(stub, "some other scan", "x")
        self.assertIn(PROBE, stub._progress_labels)


if __name__ == "__main__":
    unittest.main()
