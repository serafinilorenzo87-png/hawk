"""The Target Intel "(N new)" badge must equal the number of unread rows.

The badge used to be an incrementing counter that only reset when the
tab was opened; marking a finding read or removing one cleared its cyan
row highlight but NOT the badge, so the user saw "(2 new)" over a single
live row.  It is now recomputed from the actual number of ``_fresh``
findings, so it can never drift from the highlighted rows.
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


class _Label:
    def __init__(self):
        self.text = None

    def configure(self, **k):
        if "text" in k:
            self.text = k["text"]

    def winfo_exists(self):
        return True


def _host():
    from gui.widgets.target_intel_admin import TargetIntelAdminMixin

    class Host(TargetIntelAdminMixin):
        def __init__(self):
            self._auto_findings = []
            self._new_findings = 0
            self._tab_label = _Label()
            self._tab_base_text = "TARGET INTEL"
            self._blink_active = False
            self._blink_count = 0

    return Host()


class NewBadgeTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_badge_equals_unread_count(self):
        h = _host()
        h._auto_findings = [
            {"_fresh": True}, {"_fresh": True}, {"_fresh": None}, {}]
        h._refresh_new_badge()
        self.assertEqual(h._new_findings, 2)
        self.assertEqual(h._tab_label.text, "TARGET INTEL  (2 new)")

    def test_badge_clears_when_none_unread(self):
        h = _host()
        h._auto_findings = [{"_fresh": None}, {}]
        h._new_findings = 5   # stale inflated value
        h._refresh_new_badge()
        self.assertEqual(h._new_findings, 0)
        self.assertEqual(h._tab_label.text, "TARGET INTEL")

    def test_marking_one_read_drops_the_badge(self):
        h = _host()
        h._auto_findings = [{"_fresh": True}, {"_fresh": True}]
        h._refresh_new_badge()
        self.assertEqual(h._new_findings, 2)
        h._auto_findings[0].pop("_fresh")     # one marked read
        h._refresh_new_badge()
        self.assertEqual(h._new_findings, 1)  # badge follows the rows

    def test_removing_a_fresh_finding_drops_the_badge(self):
        h = _host()
        h._auto_findings = [{"_fresh": True}, {"_fresh": True}]
        h._refresh_new_badge()
        h._auto_findings.pop(0)               # a removed fresh finding
        h._refresh_new_badge()
        self.assertEqual(h._new_findings, 1)


if __name__ == "__main__":
    unittest.main()
