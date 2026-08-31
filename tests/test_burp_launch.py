r"""BURP SUITE must launch detached, not through the streaming ToolRunner.

Bug (confirmed live on MS2): BURP had no dedicated route, so it fell through
to the generic path and ran `burpsuite &` via the pty ToolRunner.  The
backgrounded java kept the pty slave open, so the runner never saw EOF —
the card stayed stuck on "running" for Burp's whole lifetime, and pressing
STOP killpg'd the group, killing Burp.  It also refused to launch without a
session target.

Fix: a dedicated _route_burpsuite that launches Burp in its own session
(start_new_session=True) with detached stdio (DEVNULL), so the card stays
ready, STOP can't touch it, and no target is required.

(card_routes_scan subclasses customtkinter and can't import headless, so
these are static source-shape checks.)
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


class BurpDetachedLaunchTests(unittest.TestCase):
    def test_burpsuite_has_dedicated_route(self):
        src = _src("gui/widgets/card_routes_scan.py")
        self.assertIn('tool.id == "burpsuite"', src)
        self.assertIn("_route_burpsuite", src)

    def test_burp_route_launches_detached_not_via_runner(self):
        body = _method(_src("gui/widgets/card_routes_scan.py"),
                       "_route_burpsuite")
        self.assertIn("start_new_session=True", body)   # own session
        self.assertIn("DEVNULL", body)                   # no pty tether
        # Must NOT go through the streaming ToolRunner path that caused the
        # stuck-running / STOP-kills-Burp bug — check for the actual calls,
        # not prose in the docstring.
        self.assertNotIn("_run_raw(", body)
        self.assertNotIn("_run_tool(", body)
        self.assertNotIn("ToolRunner(", body)


if __name__ == "__main__":
    unittest.main()
