r"""winPEAS.exe / PowerUp / PrivescCheck are funnel-only: registered (the
Windows "Choose Approach" picker resolves them with get_tool) but not rendered
as their own cards.

Windows mirror of test_linpeas_funnel.  The post-exploit list had the same
"double" on the Windows side that LINPEAS had on Linux: a WINPEAS card that
opens the Choose-Approach picker (winpeas.bat / winpeas.exe / PrivescCheck /
PowerUp / Manual) AND separate winpeas.exe / PowerUp / PrivescCheck cards.  We
keep the single WINPEAS funnel and hide the three secondary cards via
Tool.hidden, WITHOUT unregistering the tools (the picker still needs
get_tool() to fetch their download command).  WINPEAS stays a visible card.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.post_exploit import PostExploitModule          # noqa: E402


# The three winPEAS-funnel secondary approaches, in module-tool-id form.
_HIDDEN_IDS = ("winpeas_exe", "powerup_download", "privesc_check")


class WinpeasFunnelConsolidationTests(unittest.TestCase):
    def setUp(self):
        self.mod = PostExploitModule()
        self.byid = {t.id: t for t in self.mod.get_tools()}

    def test_secondary_approaches_are_hidden(self):
        for tid in _HIDDEN_IDS:
            self.assertTrue(getattr(self.byid[tid], "hidden", False),
                            f"{tid} must be hidden (funnel-only)")

    def test_winpeas_stays_a_visible_card(self):
        self.assertFalse(getattr(self.byid["winpeas"], "hidden", False),
                         "the WINPEAS funnel card must stay visible")

    def test_hidden_tools_are_still_registered(self):
        # the picker resolves them via module.get_tool — they must exist.
        for tid in _HIDDEN_IDS:
            self.assertIsNotNone(self.mod.get_tool(tid),
                                 f"{tid} must stay resolvable via get_tool")

    def test_card_widget_filters_hidden_from_display(self):
        # static guard: the row builder must drop hidden tools before render.
        with open(os.path.join(ROOT, "gui/widgets/card_widget.py"),
                  encoding="utf-8") as f:
            src = f.read()
        self.assertIn('getattr(t, "hidden", False)', src)

    def test_picker_resolves_every_funnel_id_to_a_real_tool(self):
        # The Windows picker maps its dialog tool_ids to module tool ids in
        # card_routes_access.py.  Every mapped module id must resolve via
        # get_tool, or a picked approach dead-ends.
        with open(os.path.join(ROOT, "gui/widgets/card_routes_access.py"),
                  encoding="utf-8") as f:
            src = f.read()
        # winpeas.bat maps to the visible "winpeas" funnel card; the three
        # secondary approaches map to the now-hidden tools.
        for module_id in ("winpeas", "winpeas_exe",
                          "privesc_check", "powerup_download"):
            self.assertIsNotNone(
                self.mod.get_tool(module_id),
                f"picker target {module_id!r} must resolve via get_tool")
        self.assertIn('"powerup":       "powerup_download"', src,
                      "the picker must map PowerUp to the hidden module tool")

    def test_picker_dialog_offers_powerup(self):
        # PowerUp had no picker card before this consolidation, so hiding
        # its standalone card would have stranded it.  Assert the dialog
        # now carries a PowerUp entry.
        with open(os.path.join(ROOT, "gui/dialogs_privesc.py"),
                  encoding="utf-8") as f:
            src = f.read()
        self.assertIn('"id":       "powerup"', src)
        self.assertIn("PowerUp.ps1", src)


if __name__ == "__main__":
    unittest.main()
