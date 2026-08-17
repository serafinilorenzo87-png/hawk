r"""Pushing several findings at once must trigger ONE panel render, not N.

add_auto_finding re-renders the whole Target Intel panel on every push.
JWT Analyzer's finalize pushes an index card + per-finding cards in one
main-thread burst, so on a large panel that meant N full rebuilds
back-to-back — the app froze for several seconds ("can't click").  A
batch guard (_suspend_finding_render / _resume_finding_render) now holds
the render until the end so the burst costs a single rebuild.
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


def _intel():
    from gui.widgets.target_intel_render import TargetIntelRenderMixin

    class DummyIntel(TargetIntelRenderMixin):
        def __init__(self):
            self._auto_findings = []
            self._collapsed = {"vulns": True}
            self._fp = None
            self._nonstandard_checked = True
            self.render_calls = 0
            self.app = types.SimpleNamespace(
                terminal=_Terminal(),
                session_manager=types.SimpleNamespace(current=None))

        def _render_auto_findings(self):
            self.render_calls += 1

        def _render_all(self):
            pass

        def _blink_start(self, count_as_new: bool = True):
            pass

        def _kb_correlate(self, *a, **kw):
            return None

        def _aiops_correlate(self, *a, **kw):
            return None

    return DummyIntel()


class BatchRenderTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_batch_renders_once(self):
        intel = _intel()
        intel._suspend_finding_render()
        intel.add_auto_finding("A", "d", source="s")
        intel.add_auto_finding("B", "d", source="s")
        intel.add_auto_finding("C", "d", source="s")
        self.assertEqual(intel.render_calls, 0,
                         "no render while a batch is open")
        intel._resume_finding_render()
        self.assertEqual(intel.render_calls, 1,
                         "exactly one render on resume")
        self.assertEqual(len(intel._auto_findings), 3,
                         "all findings still added")

    def test_default_still_renders_each_push(self):
        # Single pushes (no batch) keep rendering per call — unchanged.
        intel = _intel()
        intel.add_auto_finding("A", "d", source="s")
        intel.add_auto_finding("B", "d", source="s")
        self.assertEqual(intel.render_calls, 2)


if __name__ == "__main__":
    unittest.main()
