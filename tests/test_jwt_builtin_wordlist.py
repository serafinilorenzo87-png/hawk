r"""Picking the "built-in" JWT wordlist must actually use the built-in
list, not silently fall back to auto-detecting the 700k wallarm list.

The JWT dialog offered "Built-in (~100 defaults, ~0.3s)" vs "wallarm
(~700k)".  For "built-in" the route passed wordlist_path=None, but
analyze_token treats None as "auto-detect wallarm if installed" — so on
a box with jwt.secrets.list present, the built-in choice was ignored and
the operator got a 700k brute (slow, and it drives the UI-freeze on the
JWT run).  The route now passes a non-file sentinel ("<builtin>") that
routes straight to the built-in fallback.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# HS256, secret "secret", payload {"user":"admin","role":"admin"}
TOKEN = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
         "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9."
         "y5LxbX5na7V60gpc1_fSsdRrDe5PDtboHXDaLHbNMDg")


class JwtBuiltinWordlistTests(unittest.TestCase):
    def test_none_autodetects_wallarm_but_sentinel_forces_builtin(self):
        from utils import jwt_analyzer

        orig = jwt_analyzer.find_wallarm_wordlist
        # Simulate a box where the 700k wallarm list IS installed.
        jwt_analyzer.find_wallarm_wordlist = lambda: "/fake/jwt.secrets.list"
        try:
            r_none = jwt_analyzer.analyze_token(
                TOKEN, do_decode=True, do_none=False, do_brute=True,
                wordlist_path=None)
            r_builtin = jwt_analyzer.analyze_token(
                TOKEN, do_decode=True, do_none=False, do_brute=True,
                wordlist_path="<builtin>")
        finally:
            jwt_analyzer.find_wallarm_wordlist = orig

        # None → the old, surprising behaviour: auto-detect wallarm.
        self.assertEqual(r_none.wordlist_used, "/fake/jwt.secrets.list")
        # The sentinel the route now passes → real built-in list.
        self.assertEqual(r_builtin.wordlist_used, "<builtin>")

    def test_builtin_still_cracks_the_obvious_secret(self):
        from utils import jwt_analyzer
        # "secret" is in the built-in list, so built-in must still crack it.
        r = jwt_analyzer.analyze_token(
            TOKEN, do_decode=True, do_none=False, do_brute=True,
            wordlist_path="<builtin>")
        self.assertEqual(r.wordlist_used, "<builtin>")
        self.assertEqual(r.cracked_secret, "secret")


class JwtRouteWiringTests(unittest.TestCase):
    def test_route_passes_builtin_sentinel_not_none(self):
        with open(os.path.join(ROOT, "gui/widgets/card_routes_assault.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('wordlist_path = "<builtin>"', src)
        self.assertNotIn("wordlist_path = None  # use built-in", src)


if __name__ == "__main__":
    unittest.main()
