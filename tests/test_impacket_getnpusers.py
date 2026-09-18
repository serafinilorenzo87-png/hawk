r"""IMPACKET GetNPUsers — one home, one dispatch entry.

History (kept for context so future reviewers don't add the second
id back):
  The Exploitation-phase card used to run GetNPUsers under tool.id
  "impacket_getnpusers", while the AD PENTESTING card used
  "getnpusers".  Two ids for the same tool caused a per-target-id
  parser dispatch drift: the AS-REP parser (AD_PARSER_BY_TOOL_ID)
  originally mapped only "getnpusers", so hashes from the
  Exploitation card were silently dropped on save.

Coherence fix: one tool, one home — the duplicate Exploitation
Tool has been removed and the dispatch entry deduplicated.  This
test locks the new invariant:

  * "getnpusers" is present in the dispatch and routes to
    _parse_asrep_to_intel;
  * "impacket_getnpusers" is NOT present anywhere — no duplicate
    Tool in modules/exploitation.py, no dispatch entry in
    card_runtime.py, no routing branch in card_routes_scan.py.

card_runtime subclasses customtkinter and can't import headless,
so the dispatch check is a static source-shape scan of the block.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class GetNPUsersOneHomeTests(unittest.TestCase):

    def test_getnpusers_dispatch_still_routes_to_asrep(self):
        src = _src("gui/widgets/card_runtime.py")
        i = src.index("AD_PARSER_BY_TOOL_ID = {")
        j = src.index("}", i)
        block = src[i:j]
        self.assertIn('"getnpusers"', block)
        self.assertIn("_parse_asrep_to_intel", block)

    def test_no_duplicate_impacket_getnpusers_dispatch(self):
        """The old Exploitation-phase id must not linger in the
        parser map — a stray entry would resurrect the two-ids
        drift the coherence fix removed."""
        src = _src("gui/widgets/card_runtime.py")
        i = src.index("AD_PARSER_BY_TOOL_ID = {")
        j = src.index("}", i)
        block = src[i:j]
        self.assertNotIn('"impacket_getnpusers"', block,
                         "impacket_getnpusers must not be a dispatch "
                         "entry any more — one tool, one home.")

    def test_no_duplicate_tool_definition(self):
        """No Tool(id="impacket_getnpusers") anywhere in modules/."""
        for rel in ("modules/exploitation.py",
                     "modules/ad_pentesting.py",
                     "modules/lateral.py",
                     "modules/base.py"):
            src = _src(rel)
            self.assertNotIn(
                'id="impacket_getnpusers"', src,
                f"{rel} still exposes the duplicate "
                "impacket_getnpusers Tool.")

    def test_routing_branch_uses_single_id(self):
        """card_routes_scan.py used to accept both ids
        ('impacket_getnpusers', 'getnpusers'); it must now accept
        only 'getnpusers'."""
        src = _src("gui/widgets/card_routes_scan.py")
        self.assertNotIn("(\"impacket_getnpusers\", \"getnpusers\")",
                          src)
        self.assertNotIn("(\"getnpusers\", \"impacket_getnpusers\")",
                          src)
        # The single-id branch must still be there.
        self.assertIn('tool.id == "getnpusers"', src)


if __name__ == "__main__":
    unittest.main()
