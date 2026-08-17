r"""ORACLE's summary finding must use a STABLE title so re-running Oracle
on the same URL updates one card instead of stacking a new one.

The summary title used to embed the live counts:
    f"ORACLE - {url} ({n} CVEs, {m} exposures)"
so a first run that reported "1 exposures" and a later run that reported
"20 exposures" produced TWO different titles -> add_auto_finding (which
merges by title+port) treated them as separate findings and the operator
saw two ORACLE cards for the same scan.  The title is now stable
(f"ORACLE - {url}") with the counts in the description + replace=True, so
reruns collapse into one card that reflects the latest profile -- the
same fix shape already used for the dir-buster and enum4linux findings.

These tests exercise the REAL add_auto_finding merge engine with the two
title strategies (counts-in-title vs stable) to lock the contract in.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

URL = "http://192.168.177.134:80/"


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


class _Terminal:
    def __init__(self):
        self.messages = []

    def write(self, msg, style=None):
        self.messages.append((msg, style))

    def section(self, title):
        self.messages.append((title, "section"))


def _build_intel():
    from gui.widgets.target_intel_render import TargetIntelRenderMixin

    class DummyIntel(TargetIntelRenderMixin):
        def __init__(self):
            self._auto_findings = []
            self._collapsed = {"vulns": True}
            self._fp = None
            self._nonstandard_checked = True
            self.app = types.SimpleNamespace(
                terminal=_Terminal(),
                session_manager=types.SimpleNamespace(current=None))

        def _render_auto_findings(self):
            pass

        def _render_all(self):
            pass

        def _blink_start(self, count_as_new: bool = True):
            pass

        def _kb_correlate(self, *a, **kw):
            return None

        def _aiops_correlate(self, *a, **kw):
            return None

    return DummyIntel()


class OracleSummaryTitleTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_stable_title_merges_reruns_and_reflects_latest(self):
        # What card_routes_oracle now emits: stable title + replace.
        intel = _build_intel()
        intel.add_auto_finding(
            f"ORACLE — {URL}",
            "  Exposures     : 1\n  CVEs          : 0",
            severity="high", source="Web Oracle", replace=True)
        intel.add_auto_finding(
            f"ORACLE — {URL}",
            "  Exposures     : 20\n  CVEs          : 0",
            severity="high", source="Web Oracle", replace=True)

        oracle = [f for f in intel._auto_findings
                  if f["title"].startswith("ORACLE —")]
        self.assertEqual(len(oracle), 1,
                         [f["title"] for f in intel._auto_findings])
        self.assertIn("Exposures     : 20", oracle[0]["description"])
        self.assertNotIn("Exposures     : 1\n", oracle[0]["description"])
        self.assertEqual(oracle[0].get("run_count"), 2)

    def test_counts_in_title_would_have_duplicated(self):
        # The bug the stable title fixes: counts embedded in the title
        # made a rerun with different counts land as a SECOND card.
        intel = _build_intel()
        intel.add_auto_finding(
            f"ORACLE — {URL} (0 CVEs, 1 exposures)",
            "d1", severity="high", source="Web Oracle")
        intel.add_auto_finding(
            f"ORACLE — {URL} (0 CVEs, 20 exposures)",
            "d2", severity="high", source="Web Oracle")

        oracle = [f for f in intel._auto_findings
                  if f["title"].startswith("ORACLE —")]
        self.assertEqual(len(oracle), 2)


if __name__ == "__main__":
    unittest.main()
