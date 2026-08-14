"""enum4linux-ng users must land in discovered_users.

HAWK runs ``enum4linux-ng`` (see modules/enumeration).  Its user output
is one account per line as ``username: <name>`` — NOT the classic
``user:[name] rid:[0x..]`` form the parser's USER_RE matches.  So every
account (system + real: root / msfadmin / user / service / postgres / …)
was seen and dropped, leaving discovered_users empty and users.txt
unwritten on a box that clearly exposes 35 users.
"""

import os
import sys
import shutil
import tempfile
import types
import unittest
from unittest.mock import patch

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


class _Sess:
    def __init__(self):
        self.users = None
        self.shares = None
        self.groups = None
        self.detected_os = ""
        self.session_id = "testsess0"

    def add_discovered_users(self, u):
        self.users = list(u)

    def add_discovered_shares(self, s):
        self.shares = list(s)

    def add_discovered_groups(self, g):
        self.groups = list(g)

    def save(self):
        pass


# Real Metasploitable2 enum4linux-ng "Users via RPC" shape.
_E4L_NG = [
    ("info", "[+] Enumerating users via 'enumdomusers'"),
    ("info", "[+] After merging user results we have 3 user(s) total:"),
    ("info", "username: root"),
    ("info", "name: (null)"),
    ("info", "username: msfadmin"),
    ("info", "username: user"),
    ("info", "name: just a user,111,,"),
    # These look user-ish but must NOT be captured:
    ("info", "[*] Username ......... ''"),
    ("info", "[+] Server allows authentication via username '' and password ''"),
]


class Enum4LinuxNgUserTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        # users.txt is written under SESSIONS_DIR — redirect to a temp.
        import utils.config as cfg
        self.cfg = cfg
        self._real_sessions = cfg.SESSIONS_DIR
        self.tmp = tempfile.mkdtemp(prefix="hawk_e4l_")
        cfg.SESSIONS_DIR = self.tmp

    def tearDown(self):
        self.cfg.SESSIONS_DIR = self._real_sessions
        shutil.rmtree(self.tmp, ignore_errors=True)
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _run(self):
        from gui.widgets.card_parsers_service import CardServiceParserMixin

        sess = _Sess()

        class Host(CardServiceParserMixin):
            def __init__(self):
                self.app = types.SimpleNamespace(
                    session_manager=types.SimpleNamespace(current=sess),
                    terminal=_Terminal(),
                    target_intel=types.SimpleNamespace(
                        add_auto_finding=lambda **k: None,
                        remove_auto_findings_by_source=lambda *a, **k: 0),
                    after=lambda _d, fn: fn())

            def _get_target(self):
                return "192.168.177.134"

        host = Host()
        tool = types.SimpleNamespace(
            name="ENUM4LINUX", binary="enum4linux-ng", id="enum4linux")
        host._parse_enum4linux_to_intel(tool, _E4L_NG)
        return sess

    def test_ng_usernames_are_captured(self):
        sess = self._run()
        # order is an implementation detail (parser dedups/sorts)
        self.assertCountEqual(sess.users, ["root", "msfadmin", "user"])

    def test_config_and_anon_lines_are_not_users(self):
        sess = self._run()
        self.assertNotIn("", sess.users or [])
        self.assertNotIn("just", sess.users or [])


def _build_intel():
    """A real TargetIntelRenderMixin host (real add/remove finding)."""
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


class Enum4LinuxSingleCardTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        import utils.config as cfg
        self.cfg = cfg
        self._real_sessions = cfg.SESSIONS_DIR
        self.tmp = tempfile.mkdtemp(prefix="hawk_e4l2_")
        cfg.SESSIONS_DIR = self.tmp

    def tearDown(self):
        self.cfg.SESSIONS_DIR = self._real_sessions
        shutil.rmtree(self.tmp, ignore_errors=True)
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _run_parser(self, intel):
        from gui.widgets.card_parsers_service import CardServiceParserMixin

        class Host(CardServiceParserMixin):
            def __init__(self):
                self.app = types.SimpleNamespace(
                    session_manager=types.SimpleNamespace(current=_Sess()),
                    terminal=_Terminal(),
                    target_intel=intel,
                    after=lambda _d, fn: fn())

            def _get_target(self):
                return "192.168.177.134"

        Host()._parse_enum4linux_to_intel(
            types.SimpleNamespace(
                name="ENUM4LINUX", binary="enum4linux-ng", id="enum4linux"),
            _E4L_NG)

    def test_remove_by_source_is_case_insensitive(self):
        intel = _build_intel()
        intel.add_auto_finding("A on h", "x", source="ENUM4LINUX")
        intel.add_auto_finding("B on h", "y", source="RPCCLIENT")
        removed = intel.remove_auto_findings_by_source("enum4linux")
        self.assertEqual(removed, 1)
        self.assertEqual(
            [f["source"] for f in intel._auto_findings], ["RPCCLIENT"])

    def test_rerun_collapses_to_one_stable_card(self):
        intel = _build_intel()
        # stale pre-fix card that carried the count in its title
        intel.add_auto_finding(
            "ENUM4LINUX — 0 users, 5 shares on METASPLOITABLE — null session",
            "old", severity="critical", source="ENUM4LINUX")
        self._run_parser(intel)   # run 1
        self._run_parser(intel)   # run 2
        e4l = [f for f in intel._auto_findings
               if (f.get("source") or "") == "ENUM4LINUX"]
        self.assertEqual(len(e4l), 1,
                         [f["title"] for f in intel._auto_findings])
        self.assertNotIn(" users,", e4l[0]["title"])   # count gone
        self.assertIn(" on ", e4l[0]["title"])         # stable "<TOOL> on host"


if __name__ == "__main__":
    unittest.main()
