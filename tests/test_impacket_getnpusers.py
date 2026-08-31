r"""IMPACKET GetNPUsers (Exploitation card) must parse AS-REP output.

Bug (from the per-tool review; bites on an AD target — deferred live
validation to MS3, N/A on MS2): the Exploitation-phase card runs GetNPUsers
under tool.id "impacket_getnpusers", but the AS-REP parser dispatch
(AD_PARSER_BY_TOOL_ID) only mapped "getnpusers" (the AD-phase id).  So on a
real AD target the Exploitation card's $krb5asrep$ hashes were never parsed
— no Credential Store push, no finding — silently lost on save.
(secretsdump doesn't have this: it is binary-keyed, so both ids work.)

Fix: map both spellings to _parse_asrep_to_intel.

card_runtime subclasses customtkinter and can't import headless, so this
is a static source-shape check of the dispatch table.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class ImpacketGetNPUsersDispatchTests(unittest.TestCase):
    def setUp(self):
        src = _src("gui/widgets/card_runtime.py")
        i = src.index("AD_PARSER_BY_TOOL_ID = {")
        j = src.index("}", i)
        self.block = src[i:j]

    def test_both_getnpusers_ids_present(self):
        # AD-phase id and Exploitation-phase id both in the dispatch.
        self.assertIn('"getnpusers"', self.block)
        self.assertIn('"impacket_getnpusers"', self.block)

    def test_both_map_to_asrep_parser(self):
        # both entries route to the AS-REP parser.
        self.assertEqual(self.block.count("_parse_asrep_to_intel"), 2)


if __name__ == "__main__":
    unittest.main()
