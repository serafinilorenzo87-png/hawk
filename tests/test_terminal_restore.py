r"""LOAD must not freeze re-inserting terminal history line by line.

Bug (user-reported): clicking LOAD took 20-30 s before the UI came back.
TerminalWidget.restore_lines() re-rendered the session's terminal history
with one textbox insert() PER LINE; each insert forces a Text-widget
relayout, so a session with a few thousand lines (a single nuclei/sqlmap
run) meant thousands of relayouts.

Fix: one insert for the whole history, then colour lines via tag ranges.
(TerminalWidget subclasses customtkinter and can't be imported headless,
so this is a static check on the method's shape.)
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


class RestoreLinesShapeTests(unittest.TestCase):
    def setUp(self):
        self.body = _method(
            _src("gui/widgets/terminal_widget.py"), "restore_lines")

    def test_history_inserted_in_one_call(self):
        # The whole history is joined and inserted once...
        self.assertIn('"".join(', self.body)

    def test_lines_coloured_via_tag_ranges(self):
        # ...then each line is coloured with a tag range (cheap, no
        # relayout) instead of a tag on a per-line insert.
        self.assertIn("tag_add", self.body)

    def test_no_per_line_insert(self):
        # The old hot loop did insert("end", text + "\n", lvl) once per
        # line; that exact per-line insert must be gone.
        code = "\n".join(l for l in self.body.splitlines()
                         if not l.lstrip().startswith("#"))
        self.assertNotIn('insert("end", text + ', code)


if __name__ == "__main__":
    unittest.main()
