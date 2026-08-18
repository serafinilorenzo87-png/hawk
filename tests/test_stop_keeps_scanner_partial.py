r"""STOP on a streaming scanner (nuclei/nikto) must KEEP its partial
results, not discard them.

The F-03 abort guard in _on_done discards a STOPped run's output so an
inference-based parser (nmap "No open ports") can't emit phantom findings
off a partial buffer.  But nuclei/nikto stream ALREADY-CONFIRMED match
lines, so aborting a long scan at 99% used to throw away real findings.
Those two now parse their partial log on STOP; every other tool keeps the
discard.  The execution record is finalized either way (STOP used to
leave it "running" forever).
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
    def write(self, *a, **k):
        pass

    def section(self, *a, **k):
        pass


class _Sess:
    def __init__(self):
        self.finished = []

    def finish_tool_execution(self, exec_id, rc, lines, status):
        self.finished.append((exec_id, status))


def _run_stop(tool_id, binary):
    from gui.widgets.card_runtime import CardRuntimeMixin

    sess = _Sess()

    class Host(CardRuntimeMixin):
        def __init__(self):
            self.parsed = []
            self.status = []
            self._tool_runners = {
                tool_id: types.SimpleNamespace(_kill_requested=True)}
            self._tool_widgets = {tool_id: {"_exec_id": "e1"}}
            self._raw_logs = {tool_id: []}
            self.after = lambda _d, fn: fn()
            self.app = types.SimpleNamespace(
                terminal=_Terminal(),
                session_manager=types.SimpleNamespace(current=sess))

        def _parse_nuclei_to_intel(self, tool, log):
            self.parsed.append("nuclei")
            return True

        def _parse_nikto_to_intel(self, tool, log):
            self.parsed.append("nikto")
            return True

        def _set_tool_status(self, tid, status):
            self.status.append(status)

        def _toggle_run_btn(self, tool, running):
            pass

    host = Host()
    tool = types.SimpleNamespace(id=tool_id, binary=binary, name=binary.upper())
    host._on_done(tool, binary.upper(), 1,
                  [("info", "[some-template] [http] [high] http://t/")])
    return host, sess


class StopKeepsPartialTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_nuclei_stop_keeps_partial(self):
        host, sess = _run_stop("nuclei", "nuclei")
        self.assertEqual(host.parsed, ["nuclei"], "parser must run on stop")
        self.assertIn("done", host.status)
        self.assertEqual(sess.finished, [("e1", "done")])

    def test_nikto_stop_keeps_partial(self):
        host, sess = _run_stop("nikto", "nikto")
        self.assertEqual(host.parsed, ["nikto"])
        self.assertIn("done", host.status)
        self.assertEqual(sess.finished, [("e1", "done")])

    def test_other_tool_stop_still_discards(self):
        host, sess = _run_stop("gobuster_dir", "gobuster")
        self.assertEqual(host.parsed, [], "non-streaming tool must discard")
        self.assertIn("error", host.status)
        self.assertEqual(sess.finished, [("e1", "aborted")])


if __name__ == "__main__":
    unittest.main()
