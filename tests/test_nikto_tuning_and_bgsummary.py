r"""Two NIKTO-review fixes:

1. Custom -Tuning: the dialog only offered fixed presets (one class, or
   [common]/[default]); the operator could not run an arbitrary subset
   like 2,3,4.  A free-form field now overrides the preset, sanitised to
   valid nikto tuning chars (0-9 a b c x).

2. Background-job summary: nikto (and other non-dir-buster bg tools:
   nuclei/sqlmap/wpscan) push findings to Target Intel via their own
   parser, so the path-counting summary reported "No paths found" on a
   clean nikto run even though the NIKTO card held 26 items.  The summary
   now only talks about paths for the dir-busters.
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


class NiktoTuningSanitizeTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_sanitize_accepts_any_combo_and_drops_junk(self):
        from gui.widgets.card_routes_web import _sanitize_nikto_tuning
        self.assertEqual(_sanitize_nikto_tuning("234"), "234")
        # commas / spaces the operator might type are stripped
        self.assertEqual(_sanitize_nikto_tuning("2,3,4"), "234")
        self.assertEqual(_sanitize_nikto_tuning("  2 3 4 "), "234")
        # exclude + software-id combos survive
        self.assertEqual(_sanitize_nikto_tuning("x06"), "x06")
        self.assertEqual(_sanitize_nikto_tuning("1289b"), "1289b")
        # uppercase lowered, invalid chars dropped
        self.assertEqual(_sanitize_nikto_tuning("A;B;C"), "abc")
        self.assertEqual(_sanitize_nikto_tuning("9!!!"), "9")
        self.assertEqual(_sanitize_nikto_tuning(""), "")


class _Terminal:
    def write(self, *a, **k):
        pass

    def section(self, *a, **k):
        pass


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


_NIKTO_RUN1 = [
    ("info", "+ Server: Apache/2.2.8 (Ubuntu) DAV/2"),
    ("info", "+ [750510] /phpinfo.php: Output from the phpinfo() "
             "function was found."),
    ("info", "+ [001213] /doc/: The /doc/ directory is browsable."),
]
_NIKTO_RUN2 = [
    ("info", "+ Server: Apache/2.2.8 (Ubuntu) DAV/2"),
    ("info", "+ [001795] /phpMyAdmin/changelog.php: phpMyAdmin is for "
             "managing MySQL databases and should be protected."),
]


class NiktoReplaceOnRerunTests(unittest.TestCase):
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

    def test_rerun_replaces_not_stacks(self):
        intel = _build_intel()
        host = self._host(intel)
        tool = types.SimpleNamespace(name="NIKTO", binary="nikto", id="nikto")
        host._parse_nikto_to_intel(tool, _NIKTO_RUN1)
        host._parse_nikto_to_intel(tool, _NIKTO_RUN2)

        cards = [f for f in intel._auto_findings
                 if f["title"].lower().startswith("nikto on")]
        self.assertEqual(len(cards), 1, [f["title"] for f in intel._auto_findings])
        desc = cards[0]["description"]
        self.assertIn("phpMyAdmin", desc)          # latest run present
        self.assertNotIn("phpinfo", desc)          # first run superseded
        self.assertNotIn("/doc/", desc)
        self.assertEqual(cards[0].get("run_count"), 2)


_NUCLEI_RUN1 = [
    ("info", "[CVE-2012-1823] [http] [high] "
             "http://192.168.177.134:80/index.php"),
    ("info", "[ssh-weak-algo-supported] [javascript] [medium] "
             "192.168.177.134:22"),
]
_NUCLEI_RUN2 = [
    ("info", "[CVE-2020-1938] [tcp] [critical] 192.168.177.134:8009"),
]


class NucleiReplaceOnRerunTests(unittest.TestCase):
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

            def _is_ascii_banner_line(self, line):
                return False

        return Host()

    def test_rerun_replaces_not_stacks(self):
        intel = _build_intel()
        host = self._host(intel)
        tool = types.SimpleNamespace(name="NUCLEI", binary="nuclei", id="nuclei")
        host._parse_nuclei_to_intel(tool, _NUCLEI_RUN1)
        host._parse_nuclei_to_intel(tool, _NUCLEI_RUN2)

        cards = [f for f in intel._auto_findings
                 if f["title"].lower().startswith("nuclei on")]
        self.assertEqual(len(cards), 1, [f["title"] for f in intel._auto_findings])
        desc = cards[0]["description"]
        self.assertIn("CVE-2020-1938", desc)       # latest run present
        self.assertNotIn("CVE-2012-1823", desc)     # first run superseded
        self.assertEqual(cards[0].get("run_count"), 2)


class WiringTests(unittest.TestCase):
    def _src(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()

    def test_nikto_dialog_has_custom_tuning_field(self):
        src = self._src("gui/widgets/card_routes_web.py")
        self.assertIn("tuning_custom_var", src)
        self.assertIn("_sanitize_nikto_tuning(custom_t)", src)

    def test_bg_summary_gates_paths_to_dir_busters(self):
        src = self._src("gui/widgets/card_runtime.py")
        self.assertIn("_is_path_tool", src)
        # non-path tools no longer get "No paths found"
        self.assertIn("Scan complete", src)

    def test_nuclei_runs_as_background_job(self):
        # A full nuclei run is long and can hang on its tail; it must go
        # through the bg-jobs bar (STOP handle), not the foreground runner.
        src = self._src("gui/widgets/card_routes_web.py")
        start = src.index("def _route_nuclei")
        end = src.index("\n    def ", start + 1)
        body = src[start:end]
        self.assertIn("_run_in_background(tool, cmd", body)
        self.assertNotIn("_run_raw(tool, cmd)", body)


if __name__ == "__main__":
    unittest.main()
