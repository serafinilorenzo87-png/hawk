r"""PRIVESC CHEAT SHEET must not raise a bogus "writable /etc/passwd".

Bug (found live on MS2): the writable_passwd pattern matched
`{"desc_substr": ["/etc/passwd"]}` — a bare substring — so ANY finding that
merely NAMES /etc/passwd (an LFI that can READ it, a linpeas line, etc.)
fired a CRITICAL "Writable /etc/passwd -> add root user", even when the file
is not writable at all.

Fix: a new desc_all matcher (AND across substrings) requires the finding to
actually indicate WRITABILITY ("/etc/passwd" AND "writable" together), and
the title matcher is tightened.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from utils import privesc_patterns as pp  # noqa: E402  (pure module)


class WritablePasswdFalsePositiveTests(unittest.TestCase):
    def _ids(self, findings):
        return {m["id"] for m in pp.match(findings)}

    def test_mere_mention_does_not_fire(self):
        # An LFI/readable finding names /etc/passwd but says nothing about
        # writability — must NOT trigger the writable_passwd pattern.
        f = [{"title": "LFI on /index.php",
              "description": "LFI allows reading /etc/passwd and /etc/shadow"}]
        self.assertNotIn("writable_passwd", self._ids(f))

    def test_real_writable_desc_fires(self):
        f = [{"title": "Interesting writable files",
              "description": "/etc/passwd is writable by all (-rw-rw-rw-)"}]
        self.assertIn("writable_passwd", self._ids(f))

    def test_writable_title_fires(self):
        f = [{"title": "Writable /etc/passwd", "description": "perms rw"}]
        self.assertIn("writable_passwd", self._ids(f))


class DescAllMatcherTests(unittest.TestCase):
    """The new desc_all matcher is AND across its substrings."""

    def test_desc_all_requires_all_terms(self):
        from utils.privesc_patterns import _matcher_hits
        m = {"desc_all": ["/etc/passwd", "writable"]}
        hit, _ = _matcher_hits(
            m, [{"title": "", "description": "/etc/passwd writable"}], None)
        self.assertTrue(hit)
        miss, _ = _matcher_hits(
            m, [{"title": "", "description": "can read /etc/passwd"}], None)
        self.assertFalse(miss)


if __name__ == "__main__":
    unittest.main()
