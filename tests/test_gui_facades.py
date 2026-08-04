import os
import sys
import types
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class _DummyCtk:
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, _name):
        return _DummyCtk

    def __call__(self, *args, **kwargs):
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


def _build_dummy_intel():
    """Minimal TargetIntelRenderMixin host: no Tk, no session, no KB.

    customtkinter must already be stubbed by the caller.
    """
    from gui.widgets.target_intel_render import TargetIntelRenderMixin

    class Terminal:
        def __init__(self):
            self.messages = []

        def write(self, message, style=None):
            self.messages.append((message, style))

    class DummyIntel(TargetIntelRenderMixin):
        def __init__(self):
            self._auto_findings = []
            self._collapsed = {"vulns": True}
            self.render_count = 0
            self.blink_count = 0
            self.app = types.SimpleNamespace(terminal=Terminal())

        def _render_auto_findings(self):
            self.render_count += 1

        def _blink_start(self, count_as_new: bool = True):
            self.blink_count += 1
            self.last_count_as_new = count_as_new

        # The two correlation hooks fire on every push; they are not
        # under test here and would otherwise raise AttributeError
        # into the caller's try/except and spam stderr.
        def _kb_correlate(self, *a, **kw):
            return None

        def _aiops_correlate(self, *a, **kw):
            return None

    return DummyIntel()


class GuiFacadeTests(unittest.TestCase):
    def test_public_gui_facades_still_import(self):
        old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        try:
            from gui.widgets.card_widget import KillChainCard
            from gui.widgets.target_intel_widget import TargetIntelWidget
            from gui.dialogs import (
                LhostDialog,
                PostExploitGuideDialog,
                show_proxychains_config_dialog,
                _make_win,
            )

            self.assertTrue(hasattr(KillChainCard, "_request_run"))
            self.assertTrue(hasattr(TargetIntelWidget, "_show_connect_dialog"))
            self.assertTrue(callable(_make_win))
            self.assertTrue(LhostDialog)
            self.assertTrue(PostExploitGuideDialog)
            self.assertTrue(show_proxychains_config_dialog)
        finally:
            if old_ctk is None:
                sys.modules.pop("customtkinter", None)
            else:
                sys.modules["customtkinter"] = old_ctk

    def test_auto_findings_track_repeated_runs(self):
        old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        try:
            intel = _build_dummy_intel()
            intel.add_auto_finding(
                "FTP anonymous login",
                "Anonymous FTP is enabled",
                severity="high",
                source="Nmap",
                linked_run_id="run-a",
            )
            intel.add_auto_finding(
                "ftp anonymous login",
                "Anonymous FTP is enabled",
                severity="high",
                source="Nmap",
                linked_run_id="run-b",
            )

            self.assertEqual(len(intel._auto_findings), 1)
            finding = intel._auto_findings[0]
            self.assertEqual(finding["run_count"], 2)
            self.assertEqual(
                [o["n"] for o in finding["occurrences"]],
                [1, 2],
            )
            # Same evidence pushed twice: the FIRST add tagged it
            # NEW #1 + _fresh=True; the SECOND add is a "seen again"
            # with nothing new to show, so it does NOT overwrite the
            # NEW #1 badge nor bump the "(N new)" badge counter.
            # Without this guard the user would see "(2 new)" but
            # only one row glowed green (re-trigger of the same
            # finding wasn't actually new).
            self.assertEqual(finding["_update_note"], "NEW #1")
            self.assertTrue(finding.get("_fresh"))
            # New badge format: empty for 1 run, just the latest count
            # for 2+ runs.  See `_format_finding_runs`.
            self.assertEqual(intel._format_finding_runs(finding), "2")
            self.assertEqual(intel.render_count, 2)
            self.assertEqual(intel.blink_count, 2)
            # First blink counted as new, second one didn't.
            self.assertFalse(intel.last_count_as_new)
            self.assertFalse(intel._collapsed["vulns"])
        finally:
            if old_ctk is None:
                sys.modules.pop("customtkinter", None)
            else:
                sys.modules["customtkinter"] = old_ctk

    def test_auto_findings_are_keyed_on_title_and_port(self):
        """Same title on two ports = two findings (M18).

        Real emitter this reproduces: `_kb_correlate` builds its title
        from the KB entry alone (`▶ <id>  ·  <title>`) and passes the
        triggering finding's port.  A host running Apache 2.4.49 on
        both 80 and 8080 hits the same KB entry twice, so before this
        fix the two services collapsed into ONE card and ONE report
        row — the operator never saw the second listener.
        """
        old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        try:
            kb_title = ("▶ CVE-2021-41773  ·  Apache httpd 2.4.49 "
                        "path traversal / RCE")
            intel = _build_dummy_intel()
            intel.add_auto_finding(
                title=kb_title,
                description="http://10.10.10.5:80/ — Apache/2.4.49 (Unix)",
                severity="critical",
                source="CVE KB (CVE-2021-41773)",
                port=80,
            )
            intel.add_auto_finding(
                title=kb_title,
                description="http://10.10.10.5:8080/ — Apache/2.4.49 (Unix)",
                severity="critical",
                source="CVE KB (CVE-2021-41773)",
                port=8080,
            )

            self.assertEqual(len(intel._auto_findings), 2)
            self.assertEqual(
                sorted(f.get("port") for f in intel._auto_findings),
                [80, 8080],
            )
            for f in intel._auto_findings:
                self.assertEqual(f["run_count"], 1)
            # Each card keeps only its own evidence.
            by_port = {f["port"]: f for f in intel._auto_findings}
            self.assertIn(":80/", by_port[80]["description"])
            self.assertNotIn(":8080/", by_port[80]["description"])
            self.assertIn(":8080/", by_port[8080]["description"])

            # Same title AND same port -> still merges, run_count bumps.
            intel.add_auto_finding(
                title=kb_title,
                description="http://10.10.10.5:80/ — confirmed via curl",
                severity="critical",
                source="CVE KB (CVE-2021-41773)",
                port=80,
            )
            self.assertEqual(len(intel._auto_findings), 2)
            self.assertEqual(by_port[80]["run_count"], 2)
            self.assertEqual(by_port[8080]["run_count"], 1)
            self.assertIn("confirmed via curl", by_port[80]["description"])
            self.assertNotIn("confirmed via curl",
                             by_port[8080]["description"])
        finally:
            if old_ctk is None:
                sys.modules.pop("customtkinter", None)
            else:
                sys.modules["customtkinter"] = old_ctk

    def test_auto_findings_without_port_still_merge(self):
        """The documented rerun case: no port on either side -> merge.

        gobuster's parser pushes no port hint, so both runs carry
        `port=None` and must land in the same card.
        """
        old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        try:
            intel = _build_dummy_intel()
            intel.add_auto_finding(
                "Gobuster — 3 path(s) on http://10.10.10.5/",
                "/admin (Status: 301)",
                severity="info", source="gobuster",
            )
            intel.add_auto_finding(
                "Gobuster — 3 path(s) on http://10.10.10.5/",
                "/backup (Status: 200)",
                severity="info", source="gobuster",
            )

            self.assertEqual(len(intel._auto_findings), 1)
            finding = intel._auto_findings[0]
            self.assertEqual(finding["run_count"], 2)
            self.assertIsNone(finding.get("port"))
            self.assertIn("/admin", finding["description"])
            self.assertIn("/backup", finding["description"])
        finally:
            if old_ctk is None:
                sys.modules.pop("customtkinter", None)
            else:
                sys.modules["customtkinter"] = old_ctk


if __name__ == "__main__":
    unittest.main()
