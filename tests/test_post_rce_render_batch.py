r"""POST-RCE RECON: ANALYZE must batch its Target Intel pushes.

Bug (found live on MS2): clicking ANALYZE froze HAWK.  The handler pushed
each parsed finding with add_auto_finding() in a loop, and every call
re-renders the WHOLE Target Intel panel — so a recon's worth of findings,
on top of the findings already collected, meant N full re-renders on the UI
thread.

Fix: wrap the push loop in _suspend_finding_render()/_resume_finding_render()
(try/finally) so the whole burst costs one redraw instead of N.

card_routes_access subclasses customtkinter and can't import headless, so
this is a static source-shape check of the dialog handler.
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


class PostRceRenderBatchTests(unittest.TestCase):
    def setUp(self):
        self.body = _method(
            _src("gui/widgets/card_routes_access.py"),
            "_show_post_rce_recon_dialog")

    def test_pushes_are_batched(self):
        self.assertIn("_suspend_finding_render", self.body)
        self.assertIn("_resume_finding_render", self.body)

    def test_resume_is_in_a_finally(self):
        # resume must run even if the push loop errors, else rendering
        # stays suspended forever.
        self.assertIn("finally:", self.body)
        # suspend opens the batch, resume closes it.
        self.assertLess(self.body.index("_suspend_finding_render"),
                        self.body.index("_resume_finding_render"))


if __name__ == "__main__":
    unittest.main()
