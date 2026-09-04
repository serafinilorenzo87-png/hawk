r"""LSE / pspy are funnel-only: registered (the LINPEAS picker resolves them
with get_tool) but not rendered as their own cards.

Lorenzo's call: the post-exploit list had a "double" — a LINPEAS card that
opens a Choose-Approach picker (linpeas.sh / LSE / pspy / Manual) AND separate
LSE / pspy cards.  We keep the single LINPEAS funnel and hide the LSE / pspy
cards via Tool.hidden, WITHOUT unregistering the tools (the picker still needs
get_tool() to fetch their download command).  LINPEAS stays a visible card.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.post_exploit import PostExploitModule          # noqa: E402


class FunnelConsolidationTests(unittest.TestCase):
    def setUp(self):
        self.mod = PostExploitModule()
        self.byid = {t.id: t for t in self.mod.get_tools()}

    def test_lse_and_pspy_are_hidden(self):
        for tid in ("lse", "pspy"):
            self.assertTrue(getattr(self.byid[tid], "hidden", False),
                            f"{tid} must be hidden (funnel-only)")

    def test_linpeas_stays_a_visible_card(self):
        self.assertFalse(getattr(self.byid["linpeas"], "hidden", False),
                         "the LINPEAS funnel card must stay visible")

    def test_hidden_tools_are_still_registered(self):
        # the picker resolves them via module.get_tool — they must exist.
        for tid in ("lse", "pspy"):
            self.assertIsNotNone(self.mod.get_tool(tid),
                                 f"{tid} must stay resolvable via get_tool")

    def test_pspy_downloads_both_architectures(self):
        # pspy64 fails on 32-bit targets (Metasploitable i686) — grab both so
        # the transfer step can offer pspy32 as well.
        cmd = self.byid["pspy"].cmd_template
        self.assertIn("pspy32", cmd)
        self.assertIn("pspy64", cmd)

    def test_card_widget_filters_hidden_from_display(self):
        # static guard: the row builder must drop hidden tools before render.
        with open(os.path.join(ROOT, "gui/widgets/card_widget.py"),
                  encoding="utf-8") as f:
            src = f.read()
        self.assertIn('getattr(t, "hidden", False)', src)


if __name__ == "__main__":
    unittest.main()
