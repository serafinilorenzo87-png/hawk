r"""Tools launched outside the standard _run_raw path (background jobs,
ORACLE, Bloody Crawl) must still be recorded in session.executed_tools.

executed_tools is the log that drives (a) the per-tool status-dot restore
when a session is reloaded (target_bar.apply_session reads
last_status_per_tool()) and (b) the session tool-history / reports.  The
custom routes never called start_tool_execution, so web_oracle /
gobuster_dir / ffuf / bloody_crawl were absent from the log: their green
dot vanished on restart and they were missing from the history.

_record_tool_start now opens the record and stashes the exec_id where the
shared _on_done (which every one of these paths already calls) applies the
finish.  These tests cover the helper end-to-end against a REAL Session and
assert the three launch points are wired to it.
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


def _host(sess, tool_id):
    return types.SimpleNamespace(
        app=types.SimpleNamespace(
            session_manager=types.SimpleNamespace(current=sess)),
        phase_id="web_assault",
        _tool_widgets={tool_id: {}})


class RecordToolStartTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_start_lands_in_executed_tools_and_stashes_exec_id(self):
        from gui.widgets.card_runtime import CardRuntimeMixin
        from utils.session import Session

        sess = Session("192.168.177.134")
        tool = types.SimpleNamespace(
            id="web_oracle", name="ORACLE", binary="web_oracle")
        host = _host(sess, "web_oracle")

        exec_id = CardRuntimeMixin._record_tool_start(
            host, tool, "web_oracle http://192.168.177.134:80/")

        self.assertTrue(exec_id)
        self.assertEqual(
            host._tool_widgets["web_oracle"]["_exec_id"], exec_id)
        self.assertEqual(len(sess.executed_tools), 1)
        e = sess.executed_tools[0]
        self.assertEqual(e["tool_id"], "web_oracle")
        self.assertEqual(e["status"], "running")
        # This is exactly what the reload restore reads.
        self.assertEqual(
            sess.last_status_per_tool().get("web_oracle"), "running")

    def test_exec_id_lets_on_done_finish_the_record(self):
        # The stashed exec_id must be the handle _on_done finishes with,
        # flipping the tool to a restorable "done" status.
        from gui.widgets.card_runtime import CardRuntimeMixin
        from utils.session import Session

        sess = Session("192.168.177.134")
        tool = types.SimpleNamespace(
            id="gobuster_dir", name="GOBUSTER Dir", binary="gobuster")
        host = _host(sess, "gobuster_dir")

        eid = CardRuntimeMixin._record_tool_start(
            host, tool, "gobuster dir -u http://t/")
        # _on_done does exactly this with the stashed exec_id:
        sess.finish_tool_execution(
            host._tool_widgets["gobuster_dir"]["_exec_id"],
            0, ["/admin (Status: 200)"], "done")

        self.assertEqual(
            sess.last_status_per_tool().get("gobuster_dir"), "done")
        self.assertEqual(sess.executed_tools[0]["status"], "done")

    def test_missing_session_is_a_safe_noop(self):
        from gui.widgets.card_runtime import CardRuntimeMixin
        tool = types.SimpleNamespace(
            id="ffuf", name="FFUF", binary="ffuf")
        host = types.SimpleNamespace(
            app=types.SimpleNamespace(
                session_manager=types.SimpleNamespace(current=None)),
            phase_id="web_assault",
            _tool_widgets={"ffuf": {}})
        # No session -> no record, no crash, exec_id None stashed.
        self.assertIsNone(CardRuntimeMixin._record_tool_start(
            host, tool, "ffuf -u http://t/FUZZ"))
        self.assertIsNone(host._tool_widgets["ffuf"]["_exec_id"])


class LaunchPointWiringTests(unittest.TestCase):
    """Static guard: the three custom launch points must call the helper,
    else their runs silently vanish from executed_tools again."""

    def _src(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()

    def test_background_jobs_record(self):
        src = self._src("gui/widgets/card_runtime.py")
        self.assertIn("self._record_tool_start(tool, cmd)", src)

    def test_oracle_records(self):
        src = self._src("gui/widgets/card_routes_oracle.py")
        self.assertIn('self._record_tool_start(tool, f"web_oracle', src)

    def test_bloody_crawl_records(self):
        src = self._src("gui/widgets/card_routes_oracle.py")
        self.assertIn('self._record_tool_start(tool, f"bloody_crawl', src)

    def test_injection_records(self):
        src = self._src("gui/widgets/card_routes_assault.py")
        self.assertIn('self._record_tool_start(tool, f"injection_tester', src)

    def test_jwt_records(self):
        src = self._src("gui/widgets/card_routes_assault.py")
        self.assertIn('self._record_tool_start(tool, "jwt_analyzer")', src)


if __name__ == "__main__":
    unittest.main()
