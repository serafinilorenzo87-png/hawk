r"""LOAD must not freeze while the Target Intel panel renders.

Bug (user-reported): after clicking LOAD the dialog stayed open — frozen —
for 20-30 s.  apply_session() rebuilt the Target Intel panel inline, and a
session with dozens of findings is a multi-second customtkinter widget
build (each finding is ~a dozen widgets).  Because the restore ran that
render synchronously before _load() destroyed the dialog, the dialog
lingered for the whole render.

Fix:
  1. apply_session() defers _render_all off the LOAD critical path
     (self.after(0, ...)) so the restore returns at once and the dialog
     closes immediately.
  2. _render_auto_findings_section() flushes the idle queue every few
     cards so findings paint progressively instead of the panel freezing
     blank until the last one is built.

(These widgets subclass customtkinter and can't be imported headless, so
this is a static check on the two methods' shapes.)
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _method(src, name):
    i = src.index(f"def {name}")
    j = len(src)
    for pat in ("\n    def ", "\nclass "):
        k = src.find(pat, i + 1)
        if k != -1:
            j = min(j, k)
    return src[i:j]


class LoadDefersRenderTests(unittest.TestCase):
    def setUp(self):
        self.body = _method(
            _src("gui/widgets/target_bar.py"), "apply_session")

    def test_render_is_deferred_not_synchronous(self):
        # The Target Intel repaint is scheduled, not run inline...
        self.assertIn(".after(", self.body)
        self.assertIn("_render_all", self.body)

    def test_no_synchronous_render_all_call(self):
        # ...so no bare _render_all() call survives on the restore path
        # (the deferred form passes the bound method by reference).
        code = "\n".join(l for l in self.body.splitlines()
                         if not l.lstrip().startswith("#"))
        self.assertNotIn("_render_all()", code)

    def test_no_leftover_profiling(self):
        # The timing probe used to diagnose this must not ship.
        self.assertNotIn("LOADPROF", self.body)
        self.assertNotIn("_lpp(", self.body)


class ProgressivePaintTests(unittest.TestCase):
    def test_findings_loop_flushes_idle_queue(self):
        body = _method(
            _src("gui/widgets/target_intel_render.py"),
            "_render_auto_findings_section")
        # Cards paint in batches: the loop drains pending redraws every
        # few findings instead of freezing until the last one is built.
        self.assertIn("update_idletasks", body)


if __name__ == "__main__":
    unittest.main()
