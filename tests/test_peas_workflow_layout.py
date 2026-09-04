r"""PEAS Workflow Step-3 tab bodies must stay anchored under the toggle.

Bug (found live on MS2): the Step-3 "RUN + SAVE TO FILE" / "RUN + STREAM LIVE"
toggle re-packed its command body with a bare .pack() (no `after=`).  On first
render that was fine (Steps 4/5 didn't exist yet), but a LATER toggle appended
the body to the END of the scroll frame, so the run/monitor commands jumped
below Step 5.

Fix: every pack of redirect_body / stream_body carries `after=tab_row`, pinning
the body immediately under the toggle buttons regardless of build order.

dialogs_privesc subclasses customtkinter and can't import headless, so this is
a static source-shape guard.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class PeasTabAnchorTests(unittest.TestCase):
    def setUp(self):
        self.src = _src("gui/dialogs_privesc.py")

    def test_every_body_pack_is_anchored(self):
        # Any pack of redirect_body / stream_body must pin after=tab_row.
        for m in re.finditer(r"(redirect_body|stream_body)\.pack\(([^)]*)\)",
                             self.src):
            with self.subTest(call=m.group(0)):
                self.assertIn(
                    "after=tab_row", m.group(2),
                    f"{m.group(1)}.pack() must anchor after=tab_row so the "
                    f"exec body can't drift to the bottom of the dialog")

    def test_pack_forget_still_used_for_the_hidden_tab(self):
        # The toggle hides the other body — that half must still be there.
        self.assertIn("stream_body.pack_forget()", self.src)
        self.assertIn("redirect_body.pack_forget()", self.src)


class PeasOpenOutputGuardTests(unittest.TestCase):
    r"""OPEN OUTPUT's empty-guard must reject only EMPTY files, by SIZE — never
    by linpeas-specific box markers.  Live bug: the marker check keyed on ╔/╠,
    which LSE / pspy / PowerUp / PrivescCheck output does NOT contain, so a
    valid 265 KB LSE capture was rejected as "not PEAS output" and the "redo
    Step 4" advice made the operator re-listen and truncate the good file.
    """

    def setUp(self):
        self.src = _src("gui/dialogs_privesc.py")

    def test_guard_is_size_based(self):
        self.assertIn("len(_raw) < 256", self.src)

    def test_guard_does_not_reject_on_box_markers(self):
        # the old marker-rejection must be gone (it false-rejected LSE).
        self.assertNotIn(
            'if not any(m in content for m in ("╔", "╠")):',
            self.src)

    def test_done_check_row_is_present(self):
        # a prominent "is it finished?" check sits by the RUN command.
        self.assertIn('"done?"', self.src)
        self.assertIn("pgrep -fl", self.src)


if __name__ == "__main__":
    unittest.main()
