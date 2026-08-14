"""Dir-buster findings (gobuster/dirb/ffuf) refresh instead of accumulate.

These tools report the COMPLETE current path list every run, so a rerun's
finding must SUPERSEDE the previous one.  The old merge appended the new
description to the old, which stacked contradictory summaries in a single
card — e.g. a stale "0 paths found" (from an earlier failed/empty run)
sitting on top of a fresh "Discovered 22 paths".  `add_auto_finding(...,
replace=True)` overwrites description + severity while keeping the per-run
occurrence history; the dir-buster parser opts in.
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


class _Terminal:
    def __init__(self):
        self.messages = []

    def write(self, msg, style=None):
        self.messages.append((msg, style))

    def section(self, title):
        self.messages.append((title, "section"))


def _build_intel():
    """A real TargetIntelRenderMixin host (real add_auto_finding)."""
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


class ReplaceMergeTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_replace_overwrites_description_and_severity(self):
        intel = _build_intel()
        title = "GOBUSTER Dir on http://192.168.177.134:80/"
        intel.add_auto_finding(
            title, "0 paths found.\ntarget really has no content",
            severity="info", source="GOBUSTER Dir")
        intel.add_auto_finding(
            title, "Discovered 22 paths/files:\n  /phpMyAdmin",
            severity="high", source="GOBUSTER Dir", replace=True)

        self.assertEqual(len(intel._auto_findings), 1,
                         "should merge into one row, not duplicate")
        f = intel._auto_findings[0]
        self.assertNotIn("0 paths found", f["description"],
                         "stale description must be gone")
        self.assertIn("Discovered 22 paths", f["description"])
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f.get("run_count"), 2,
                         "per-run history must be kept")

    def test_default_merge_still_appends(self):
        """Regression: without replace, evidence still accumulates."""
        intel = _build_intel()
        intel.add_auto_finding("T", "alpha-line", severity="info", source="s")
        intel.add_auto_finding("T", "beta-line", severity="info", source="s")
        f = intel._auto_findings[0]
        self.assertIn("alpha-line", f["description"])
        self.assertIn("beta-line", f["description"])


class ParserWiringTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _run_parser(self, log, rc):
        from gui.widgets.card_parsers_web import CardWebParserMixin
        calls = []

        class Intel:
            def add_auto_finding(self, **kw):
                calls.append(kw)

        class Host(CardWebParserMixin):
            def __init__(self):
                self.app = types.SimpleNamespace(
                    terminal=_Terminal(),
                    target_intel=Intel(),
                    session_manager=types.SimpleNamespace(current=None),
                    after=lambda _d, fn: fn())

            def _get_target(self):
                return "192.168.177.134"

            def _strip_ansi(self, s):
                return s

            def _extract_web_target_label(self, tool):
                return "http://192.168.177.134:80/"

        host = Host()
        tool = types.SimpleNamespace(
            name="GOBUSTER Dir", binary="gobuster", id="gobuster_dir")
        host._parse_gobuster_to_intel(tool, log, rc)
        return calls

    def test_has_hits_emit_uses_replace(self):
        calls = self._run_parser(
            [("info", "/phpMyAdmin  (Status: 301) [Size: 328]"),
             ("info", "/index.php  (Status: 200) [Size: 891]")], 0)
        self.assertTrue(calls, "parser emitted no finding")
        self.assertTrue(all(c.get("replace") for c in calls), calls)

    def test_empty_success_emit_uses_replace(self):
        calls = self._run_parser([("info", "Finished")], 0)
        self.assertTrue(calls, "parser emitted no finding")
        self.assertTrue(all(c.get("replace") for c in calls), calls)


class ParserEndToEndTests(unittest.TestCase):
    """Two real parser runs against a real Target Intel: empty then hits.

    Mirrors the reported sequence (a "0 paths found" card followed by a
    successful run) end-to-end, so a title-mismatch or a non-merging
    emit would surface here, not just in the isolated unit checks.
    """

    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _host(self, intel):
        from gui.widgets.card_parsers_web import CardWebParserMixin

        class Host(CardWebParserMixin):
            def __init__(self):
                self.app = types.SimpleNamespace(
                    terminal=_Terminal(), target_intel=intel,
                    session_manager=types.SimpleNamespace(current=None),
                    after=lambda _d, fn: fn())

            def _get_target(self):
                return "192.168.177.134"

            def _strip_ansi(self, s):
                return s

            def _extract_web_target_label(self, tool):
                return "http://192.168.177.134:80/"

        return Host()

    def test_empty_then_hits_leaves_one_clean_card(self):
        intel = _build_intel()
        host = self._host(intel)
        tool = types.SimpleNamespace(
            name="GOBUSTER Dir", binary="gobuster", id="gobuster_dir")
        host._parse_gobuster_to_intel(tool, [("info", "Finished")], 0)
        host._parse_gobuster_to_intel(
            tool,
            [("info", "/phpMyAdmin  (Status: 301) [Size: 328]"),
             ("info", "/index.php  (Status: 200) [Size: 891]")], 0)

        gob = [f for f in intel._auto_findings
               if "gobuster dir on" in f["title"].lower()]
        self.assertEqual(len(gob), 1,
                         [f["title"] for f in intel._auto_findings])
        self.assertNotIn("0 paths found", gob[0]["description"])
        self.assertIn("Discovered", gob[0]["description"])
        self.assertEqual(gob[0].get("run_count"), 2)


if __name__ == "__main__":
    unittest.main()
