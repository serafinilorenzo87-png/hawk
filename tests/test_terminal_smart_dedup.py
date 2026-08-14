"""Smart-output hints must not repeat within one tool run.

The (opt-in) Smart output feature annotates lines that contain a keyword
(e.g. /phpmyadmin -> "Database admin panel exposed ...").  A verbose tool
like dirb prints "--> Testing: .../phpMyAdmin/setup/<word>" for every
wordlist entry, so the hint fired on every attempt (404s included) —
dozens of times, faking many exposed panels.  _explain() now dedups per
run via a `seen` set the parsers thread through.
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


class SmartDedupTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_explain_dedups_with_seen(self):
        from gui.widgets.terminal_widget import _explain
        seen = set()
        first = _explain("GET /phpMyAdmin/setup/openejb", seen)
        self.assertIn("admin panel", first.lower())
        second = _explain("GET /phpMyAdmin/setup/openfile", seen)
        self.assertEqual(second, "")   # same hint, suppressed

    def test_explain_without_seen_is_unchanged(self):
        from gui.widgets.terminal_widget import _explain
        a = _explain("GET /phpMyAdmin/x")
        b = _explain("GET /phpMyAdmin/y")
        self.assertTrue(a and a == b)   # no dedup without a set (back-compat)

    def test_parse_generic_emits_the_hint_once(self):
        from gui.widgets.terminal_widget import _parse_generic
        lines = [
            "--> Testing: http://t/phpMyAdmin/setup/openejb",
            "--> Testing: http://t/phpMyAdmin/setup/openfile",
            "--> Testing: http://t/phpMyAdmin/setup/opensearch",
        ]
        out = _parse_generic(lines)
        hints = [txt for _, txt in out if "admin panel" in txt.lower()]
        self.assertEqual(len(hints), 1, out)


if __name__ == "__main__":
    unittest.main()
